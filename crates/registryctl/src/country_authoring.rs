// SPDX-License-Identifier: Apache-2.0
//! Deterministic country configuration authoring for Relay and Notary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use registry_relay::source_plan::{
    authoring::{
        compile_consultation_contract, compile_integration_pack, compile_private_binding,
        AuthoredArtifact, AuthoredConsultationContract,
    },
    EvidenceClass, PinnedEvidenceArtifact, PinnedSourcePlanArtifact, SourcePlanArtifactBundle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

static COUNTRY_STARTERS: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/assets/country-starters");
static DHIS2_TRACKER_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/dhis2-tracker");
static OPENCRVS_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/opencrvs");
static OPENSPP_STARTER: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/tests/fixtures/country-authoring/openspp-exact");

const PROJECT_FILE: &str = "registry-stack.yaml";
const BUILD_ROOT: &str = ".registry-stack/build";
const REVIEW_SCHEMA: &str = "registry.country.review.v1";
const MAX_AUTHORED_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LIVE_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURES: usize = 128;
const MAX_OPERATIONS: usize = 5;
const MAX_FACTS: usize = 64;
const MAX_CLAIMS: usize = 64;
const MAX_BOUNDED_INPUT_BYTES: u16 = 256;
const RHAI_RELEASE_CAPABILITIES: &[(&str, &str)] = &[("dhis2", "2.41.9")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CountryStarter {
    BoundedHttp,
    Dhis2Tracker,
    Opencrvs,
    Openspp,
}

impl CountryStarter {
    const fn directory(self) -> &'static str {
        match self {
            Self::BoundedHttp => "bounded-http",
            Self::Dhis2Tracker => "dhis2-tracker",
            Self::Opencrvs => "opencrvs",
            Self::Openspp => "openspp",
        }
    }

    fn embedded(self) -> Result<&'static include_dir::Dir<'static>> {
        match self {
            Self::BoundedHttp => COUNTRY_STARTERS
                .get_dir(self.directory())
                .ok_or_else(|| anyhow!("country starter is unavailable")),
            Self::Dhis2Tracker => Ok(&DHIS2_TRACKER_STARTER),
            Self::Opencrvs => Ok(&OPENCRVS_STARTER),
            Self::Openspp => Ok(&OPENSPP_STARTER),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CountryInitOptions {
    pub starter: CountryStarter,
    pub directory: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CountryTestOptions {
    pub project_directory: PathBuf,
    pub environment: Option<String>,
    pub live: bool,
}

#[derive(Debug, Clone)]
pub struct CountryCheckOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub explain: bool,
    pub against: Option<PathBuf>,
    pub anchor: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CountryBuildOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub against: Option<PathBuf>,
    pub anchor: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CountryCommandReport {
    pub status: &'static str,
    pub project: String,
    pub environment: Option<String>,
    pub fixtures: Vec<FixtureReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub semantic_changes: Vec<SemanticChange>,
    pub required_reviews: BTreeSet<ReviewClass>,
    pub baseline: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureReport {
    pub integration: String,
    pub fixture: String,
    pub inputs: Vec<String>,
    pub calls: Vec<String>,
    pub facts: Vec<String>,
    pub claims: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_access: Option<bool>,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticChange {
    pub dimension: &'static str,
    pub previous_digest: Option<String>,
    pub current_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClass {
    Claim,
    Integration,
    CountryPolicy,
    OperatorSecurity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CountryProject {
    version: u8,
    registry: RegistryDeclaration,
    integrations: BTreeMap<String, IntegrationReference>,
    services: BTreeMap<String, ServiceDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryDeclaration {
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationReference {
    file: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceDeclaration {
    kind: ServiceKind,
    #[serde(default)]
    version: u32,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    legal_basis: String,
    #[serde(default = "default_consent")]
    consent: ConsentDeclaration,
    #[serde(default)]
    access: AccessDeclaration,
    #[serde(default)]
    variables: BTreeMap<String, RequestVariable>,
    #[serde(default)]
    consultations: BTreeMap<String, ConsultationDeclaration>,
    #[serde(default)]
    claims: BTreeMap<String, ClaimDeclaration>,
    #[serde(default)]
    credentials: BTreeMap<String, CredentialDeclaration>,
    #[serde(default)]
    definition: Option<PathBuf>,
    #[serde(default)]
    entity: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ServiceKind {
    Evidence,
    RecordsApi,
}

fn default_consent() -> ConsentDeclaration {
    ConsentDeclaration::NotRequired
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentDeclaration {
    NotRequired,
    Required,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessDeclaration {
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordsDefinition {
    version: u8,
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    sensitivity: Option<RecordSensitivity>,
    #[serde(default)]
    access_rights: Option<RecordAccessRights>,
    #[serde(default)]
    update_frequency: Option<RecordUpdateFrequency>,
    #[serde(default)]
    conforms_to: Vec<String>,
    primary_key: String,
    fields: BTreeMap<String, RecordField>,
    api: RecordsApiDeclaration,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecordSensitivity {
    Public,
    Internal,
    Personal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordAccessRights {
    Public,
    Restricted,
    NonPublic,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordUpdateFrequency {
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordField {
    #[serde(rename = "type")]
    field_type: RecordFieldType,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    sensitive: bool,
    #[serde(default)]
    concept_uri: Option<String>,
    #[serde(default)]
    codelist: Option<String>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecordFieldType {
    String,
    Number,
    Integer,
    Boolean,
    Date,
    Timestamp,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordsApiDeclaration {
    scopes: RecordScopes,
    #[serde(default)]
    purposes: Vec<String>,
    pagination: RecordPagination,
    #[serde(default)]
    filters: BTreeMap<String, Vec<RecordFilterOperator>>,
    #[serde(default)]
    required_principal_filters: Vec<String>,
    #[serde(default)]
    relationships: BTreeMap<String, RecordRelationship>,
    #[serde(default)]
    aggregates: BTreeMap<String, RecordAggregate>,
    standards: RecordStandards,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordScopes {
    metadata: String,
    rows: String,
    #[serde(default)]
    aggregate: Option<String>,
    #[serde(default)]
    evidence_verification: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordPagination {
    default_limit: u32,
    max_limit: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum RecordFilterOperator {
    Eq,
    In,
    Gte,
    Lte,
    Between,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordRelationship {
    kind: RecordRelationshipKind,
    target: String,
    foreign_key: String,
    #[serde(default)]
    concept_uri: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordRelationshipKind {
    BelongsTo,
    HasMany,
    HasOne,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregate {
    description: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    default_group_by: Vec<String>,
    #[serde(default)]
    dimensions: Vec<RecordAggregateDimension>,
    #[serde(default)]
    indicators: Vec<RecordAggregateIndicator>,
    #[serde(default)]
    allowed_filters: BTreeMap<String, Vec<RecordFilterOperator>>,
    #[serde(default)]
    required_principal_filters: Vec<String>,
    #[serde(default)]
    temporal_field: Option<String>,
    #[serde(default)]
    access: Option<RecordAggregateAccess>,
    #[serde(default)]
    spatial: Option<RecordAggregateSpatial>,
    #[serde(default)]
    joins: Vec<String>,
    #[serde(default)]
    group_by: Vec<String>,
    #[serde(default)]
    measures: Vec<RecordAggregateMeasure>,
    disclosure_control: RecordDisclosureControl,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateDimension {
    id: String,
    label: String,
    field: String,
    #[serde(default)]
    codelist: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateIndicator {
    id: String,
    label: String,
    function: RecordAggregateFunction,
    column: String,
    unit_measure: String,
    #[serde(default)]
    unit_mult: Option<i32>,
    #[serde(default)]
    decimals: Option<u32>,
    #[serde(default)]
    frequency: Option<String>,
    #[serde(default)]
    definition_uri: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateAccess {
    #[serde(default)]
    metadata_scope: Option<String>,
    #[serde(default)]
    aggregate_scope: Option<String>,
    #[serde(default)]
    aggregate_only_execution: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum RecordAggregateSpatial {
    AdminArea {
        #[serde(default)]
        collection_id: Option<String>,
        dimension: String,
        geometry_entity: String,
        geometry_id_field: String,
        geometry_field: String,
        #[serde(default)]
        bbox_fields: Option<RecordSpatialBbox>,
        #[serde(default = "default_record_max_geometry_vertices")]
        max_geometry_vertices: u32,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateMeasure {
    name: String,
    function: RecordAggregateFunction,
    column: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordAggregateFunction {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    Median,
    CountDistinct,
    Stddev,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordDisclosureControl {
    #[serde(default = "default_record_min_group_size")]
    min_group_size: u32,
    #[serde(default)]
    suppression: RecordSuppression,
}

fn default_record_min_group_size() -> u32 {
    5
}

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordSuppression {
    #[default]
    Omit,
    Mask,
    Null,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordStandards {
    ogc_features: RecordStandard<RecordSpatial>,
    sp_dci: RecordStandard<RecordSpdci>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum RecordStandard<T> {
    Enabled(T),
    Disabled(bool),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordSpatial {
    #[serde(default)]
    collection_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    geometry: RecordSpatialGeometry,
    #[serde(default)]
    bbox_fields: Option<RecordSpatialBbox>,
    #[serde(default)]
    datetime_field: Option<String>,
    #[serde(default = "default_record_max_bbox_degrees")]
    max_bbox_degrees: f64,
    #[serde(default = "default_record_max_geometry_vertices")]
    max_geometry_vertices: u32,
}

fn default_record_max_bbox_degrees() -> f64 {
    5.0
}

fn default_record_max_geometry_vertices() -> u32 {
    10_000
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecordSpatialGeometry {
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordSpatialBbox {
    min_x: String,
    min_y: String,
    max_x: String,
    max_y: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordSpdci {
    registry: String,
    registry_type: String,
    record_type: String,
    identifiers: BTreeMap<String, String>,
    expression_fields: BTreeMap<String, String>,
    #[serde(default)]
    response_fields: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestVariable {
    from: String,
    #[serde(rename = "type")]
    value_type: FactType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConsultationDeclaration {
    integration: String,
    input: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimDeclaration {
    #[serde(default)]
    fact: Option<String>,
    #[serde(default)]
    cel: Option<String>,
    disclosure: DisclosureDeclaration,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum DisclosureDeclaration {
    Mode(DisclosureMode),
    Policy {
        default: DisclosureMode,
        allowed: Vec<DisclosureMode>,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum DisclosureMode {
    Value,
    Predicate,
    Redacted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialDeclaration {
    format: String,
    #[serde(rename = "type")]
    credential_type: String,
    validity: String,
    claims: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationDocument {
    version: u8,
    id: String,
    source: SourceDeclaration,
    input: BTreeMap<String, InputDeclaration>,
    capability: CapabilityDeclaration,
    facts: BTreeMap<String, FactDeclaration>,
    bounds: BoundsDeclaration,
    fixtures: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDeclaration {
    product: String,
    versions: SourceVersions,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceVersions {
    #[serde(default)]
    tested: Vec<String>,
    #[serde(default)]
    supported: Vec<String>,
    #[serde(default)]
    unverified: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputDeclaration {
    #[serde(rename = "type")]
    input_type: InputType,
    bytes: u16,
    pattern: String,
    canonicalization: Canonicalization,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputType {
    String,
    FullDate,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Canonicalization {
    Identity,
    AsciiLowercase,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CredentialType {
    None,
    Basic,
    StaticBearer,
    Oauth2ClientCredentials,
    ApiKeyHeader,
    ApiKeyQuery,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialInterface {
    #[serde(rename = "type")]
    credential_type: CredentialType,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    max_value_bytes: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum CapabilityDeclaration {
    BoundedHttp {
        bounded_http: BoundedHttpDeclaration,
    },
    SnapshotExact {
        snapshot_exact: SnapshotExactDeclaration,
    },
    SandboxedRhai {
        sandboxed_rhai: SandboxedRhaiDeclaration,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundedHttpDeclaration {
    credential: CredentialInterface,
    operations: BTreeMap<String, OperationDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxedRhaiDeclaration {
    credential: CredentialInterface,
    operations: BTreeMap<String, OperationDeclaration>,
    script: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotExactDeclaration {
    entity: String,
    cardinality: CardinalityMode,
    freshness: String,
    materialization: SnapshotFootprint,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFootprint {
    max_source_records: u64,
    max_source_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationDeclaration {
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    role: OperationRole,
    #[serde(default)]
    primitive: Option<String>,
    request: RequestDeclaration,
    response: ResponseDeclaration,
    #[serde(default)]
    verification: Option<VerificationDeclaration>,
    #[serde(default)]
    when: Option<ConditionDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationDeclaration {
    primitive: String,
    jwks: String,
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OperationRole {
    #[default]
    Data,
    Credential,
    Verification,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestDeclaration {
    method: ReadMethod,
    destination: String,
    path: String,
    #[serde(default)]
    path_parameters: BTreeMap<String, ValueSource>,
    #[serde(default)]
    query: BTreeMap<String, ValueSource>,
    #[serde(default)]
    headers: BTreeMap<String, ValueSource>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default)]
    primitive: Option<String>,
    #[serde(default)]
    codec: Option<String>,
    #[serde(default)]
    authorization: Option<ValueSource>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum ReadMethod {
    Get,
    Post,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum ValueSource {
    Input { input: String },
    Value { value: Value },
    Prior { prior: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConditionDeclaration {
    prior: String,
    equals: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseDeclaration {
    statuses: Vec<u16>,
    max_bytes: u32,
    schema: SchemaNode,
    #[serde(default)]
    codec: Option<String>,
    #[serde(default)]
    cardinality: Option<CardinalityDeclaration>,
    #[serde(default)]
    status_semantics: Option<StatusSemanticsDeclaration>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusSemanticsDeclaration {
    #[serde(default)]
    no_match: Vec<u16>,
    #[serde(default)]
    ambiguous: Vec<u16>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CardinalityDeclaration {
    #[serde(default)]
    records: Option<String>,
    mode: CardinalityMode,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CardinalityMode {
    Singleton,
    ProbeTwo,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SchemaNode {
    Object {
        #[serde(default = "reject_additional")]
        additional_fields: AdditionalFields,
        fields: BTreeMap<String, SchemaField>,
    },
    Array {
        max_items: u16,
        items: Box<SchemaNode>,
    },
    String {
        max_bytes: u32,
    },
    Integer {
        min: i64,
        max: i64,
    },
    Boolean,
    Date,
}

fn reject_additional() -> AdditionalFields {
    AdditionalFields::Reject
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AdditionalFields {
    Reject,
}

#[derive(Debug)]
struct SchemaField {
    required: bool,
    schema: SchemaNode,
}

impl<'de> Deserialize<'de> for SchemaField {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("schema field must be an object"))?;
        let required = match object.remove("required") {
            None => false,
            Some(Value::Bool(required)) => required,
            Some(_) => {
                return Err(serde::de::Error::custom(
                    "schema field required must be Boolean",
                ))
            }
        };
        let schema = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self { required, schema })
    }
}

impl Serialize for SchemaField {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut value = serde_json::to_value(&self.schema).map_err(serde::ser::Error::custom)?;
        value
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("schema field did not serialize as object"))?
            .insert("required".to_string(), Value::Bool(self.required));
        value.serialize(serializer)
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FactType {
    Boolean,
    Integer,
    String,
    Date,
    Presence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FactDeclaration {
    #[serde(rename = "type")]
    fact_type: FactType,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    max_bytes: Option<u32>,
    from: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundsDeclaration {
    calls: u8,
    source_bytes: u64,
    request_bytes: u32,
    deadline: String,
    concurrency: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDocument {
    version: u8,
    integrations: BTreeMap<String, EnvironmentIntegration>,
    #[serde(default)]
    entities: BTreeMap<String, EnvironmentEntityBinding>,
    issuance: IssuanceBinding,
    callers: BTreeMap<String, CallerBinding>,
    relay_trust: RelayTrustBinding,
    deployment: DeploymentBinding,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentIntegration {
    source_version: String,
    #[serde(default)]
    data_destination: Option<DestinationBinding>,
    #[serde(default)]
    credential_destination: Option<DestinationBinding>,
    #[serde(default)]
    credential: Option<EnvironmentCredential>,
    #[serde(default)]
    advanced_capabilities: Option<IntegrationAdvancedCapabilities>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DestinationBinding {
    origin: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentCredential {
    #[serde(rename = "type")]
    credential_type: CredentialType,
    #[serde(default)]
    username: Option<SecretReference>,
    #[serde(default)]
    password: Option<SecretReference>,
    #[serde(default)]
    token: Option<SecretReference>,
    #[serde(default)]
    client_id: Option<SecretReference>,
    #[serde(default)]
    client_secret: Option<SecretReference>,
    #[serde(default)]
    value: Option<SecretReference>,
    #[serde(default)]
    review: Option<ReviewClassInput>,
    generation: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretReference {
    secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntityBinding {
    provider: RecordProvider,
    columns: BTreeMap<String, String>,
    source_revision: String,
    generation: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RecordProvider {
    Csv {
        path: PathBuf,
        #[serde(default)]
        header_row: Option<u32>,
        #[serde(default)]
        delimiter: Option<u8>,
        #[serde(default)]
        quote: Option<u8>,
    },
    Xlsx {
        path: PathBuf,
        sheet: String,
        #[serde(default)]
        header_row: Option<u32>,
        #[serde(default)]
        data_range: Option<String>,
    },
    Parquet {
        path: PathBuf,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceBinding {
    issuer: String,
    signing_key: SecretReference,
    signing_kid: String,
    generation: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CallerBinding {
    api_key_fingerprint: SecretReference,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayTrustBinding {
    origin: String,
    issuer: String,
    jwks_url: String,
    audience: String,
    notary_client_id: String,
    notary_token_file: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBinding {
    profile: CountryDeploymentProfile,
    relay: ServiceBinding,
    notary: ServiceBinding,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CountryDeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

impl CountryDeploymentProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::HostedLab => "hosted_lab",
            Self::Production => "production",
            Self::EvidenceGrade => "evidence_grade",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceBinding {
    service: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationAdvancedCapabilities {
    sandboxed_rhai: SandboxedRhaiEnablement,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SandboxedRhaiEnablement {
    enabled: bool,
    review: ReviewClassInput,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReviewClassInput {
    OperatorSecurity,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureDocument {
    name: String,
    input: BTreeMap<String, Value>,
    #[serde(default)]
    variables: BTreeMap<String, Value>,
    #[serde(default)]
    request_context: Option<FixtureRequestContext>,
    #[serde(default)]
    request_overrides: Option<Value>,
    source: BTreeMap<String, FixtureSourceResponse>,
    expect: FixtureExpectation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
enum FixtureSourceResponse {
    Http {
        status: u16,
        #[serde(default)]
        body: Value,
    },
    Timeout {
        timeout: String,
    },
    RawBody {
        status: u16,
        raw_body: String,
    },
    BodyBytes {
        status: u16,
        body_bytes: u64,
    },
    Outcome {
        outcome: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureRequestContext {
    caller: String,
    #[serde(default)]
    scopes: Vec<String>,
    purpose: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureExpectation {
    #[serde(default)]
    facts: BTreeMap<String, Value>,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    source_access: Option<bool>,
    #[serde(default)]
    disclosed_claims: Vec<String>,
    #[serde(default)]
    calls: Vec<String>,
    #[serde(default)]
    fresh_worker: Option<bool>,
}

struct LoadedCountryProject {
    root: PathBuf,
    project: CountryProject,
    environment_name: Option<String>,
    environment: Option<EnvironmentDocument>,
    integrations: BTreeMap<String, LoadedIntegration>,
    records: BTreeMap<String, LoadedRecordsDefinition>,
    authored_hash: String,
    semantic_digests: SemanticDigests,
}

struct LoadedRecordsDefinition {
    document: RecordsDefinition,
}

struct LoadedIntegration {
    document: IntegrationDocument,
    fixtures: Vec<(PathBuf, FixtureDocument)>,
    script: Option<(PathBuf, Box<[u8]>)>,
}

struct CompiledCountry {
    reviewable: BTreeMap<PathBuf, Box<[u8]>>,
    relay_private: BTreeMap<PathBuf, Box<[u8]>>,
    notary_private: BTreeMap<PathBuf, Box<[u8]>>,
    review: Value,
    explanation: Value,
    fixture_profiles: Vec<FixtureProfile>,
    semantic_changes: Vec<SemanticChange>,
    required_reviews: BTreeSet<ReviewClass>,
}

struct FixtureProfile {
    service_id: String,
    integration_alias: String,
    id: String,
    version: String,
    contract_hash: String,
}

struct VerifiedBaseline {
    review: Value,
    verified_manifest: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticDigests {
    claim: String,
    integration: String,
    country_policy: String,
    operator_security: String,
}

struct GeneratedPack {
    alias: String,
    id: String,
    version: String,
    artifact: AuthoredArtifact,
    evidence: Vec<GeneratedEvidence>,
}

struct GeneratedEvidence {
    class: EvidenceClass,
    path: PathBuf,
    bytes: Box<[u8]>,
    sha256: String,
}

struct GeneratedProfile {
    service_id: String,
    consultation_name: String,
    integration_alias: String,
    id: String,
    version: String,
    contract: AuthoredConsultationContract,
    binding: AuthoredArtifact,
}

pub fn init_country_project(options: &CountryInitOptions) -> Result<CountryCommandReport> {
    if options.directory.exists() {
        let metadata = fs::symlink_metadata(&options.directory)
            .context("failed to inspect country project destination")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::read_dir(&options.directory)
                .context("failed to inspect country project destination")?
                .next()
                .is_some()
        {
            bail!("country project destination must be absent or an empty real directory");
        }
    }
    let starter = options.starter.embedded()?;
    if !options.directory.exists() {
        create_dir_owner_only(&options.directory)?;
    }
    copy_embedded_dir(starter, &options.directory)?;
    let project = load_country_project(&options.directory, None)?;
    Ok(CountryCommandReport {
        status: "initialized",
        project: project.project.registry.id,
        environment: None,
        fixtures: Vec::new(),
        semantic_changes: Vec::new(),
        required_reviews: BTreeSet::from([
            ReviewClass::Claim,
            ReviewClass::Integration,
            ReviewClass::CountryPolicy,
            ReviewClass::OperatorSecurity,
        ]),
        baseline: "initial_without_baseline",
        output: Some(options.directory.display().to_string()),
        explanation: None,
    })
}

pub fn test_country_project(options: &CountryTestOptions) -> Result<CountryCommandReport> {
    if options.live && options.environment.is_none() {
        bail!("live country tests require an explicit non-production --environment");
    }
    let loaded = load_country_project(&options.project_directory, options.environment.as_deref())?;
    let offline_environment = offline_fixture_environment(&loaded)?;
    validate_environment(&loaded.integrations, &loaded.records, &offline_environment)?;
    let compiled =
        compile_country_for_environment(&loaded, "offline-fixture", &offline_environment, None)?;
    validate_generated_product_configs(&compiled)?;
    let mut reports = execute_all_fixtures(&loaded, &compiled)?;
    require_passing_fixtures(&reports)?;
    if options.live {
        reports.push(execute_governed_live_test(&loaded)?);
    }
    Ok(CountryCommandReport {
        status: "passed",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures: reports,
        semantic_changes: Vec::new(),
        required_reviews: required_reviews(&loaded, None),
        baseline: "initial_without_baseline",
        output: None,
        explanation: None,
    })
}

fn offline_fixture_environment(loaded: &LoadedCountryProject) -> Result<EnvironmentDocument> {
    let mut integrations = BTreeMap::new();
    for (alias, integration) in &loaded.integrations {
        let source_version = integration
            .document
            .source
            .versions
            .tested
            .first()
            .or_else(|| integration.document.source.versions.supported.first())
            .or_else(|| integration.document.source.versions.unverified.first())
            .ok_or_else(|| anyhow!("offline fixture integration has no reviewed source version"))?
            .clone();
        let credential_type = credential_interface(&integration.document).credential_type;
        let credential = match credential_type {
            CredentialType::None => None,
            CredentialType::Basic => Some(EnvironmentCredential {
                credential_type,
                username: Some(SecretReference {
                    secret: "REGISTRY_COUNTRY_FIXTURE_USERNAME".to_string(),
                }),
                password: Some(SecretReference {
                    secret: "REGISTRY_COUNTRY_FIXTURE_PASSWORD".to_string(),
                }),
                token: None,
                client_id: None,
                client_secret: None,
                value: None,
                review: None,
                generation: 1,
            }),
            CredentialType::StaticBearer => Some(EnvironmentCredential {
                credential_type,
                username: None,
                password: None,
                token: Some(SecretReference {
                    secret: "REGISTRY_COUNTRY_FIXTURE_TOKEN".to_string(),
                }),
                client_id: None,
                client_secret: None,
                value: None,
                review: None,
                generation: 1,
            }),
            CredentialType::Oauth2ClientCredentials => Some(EnvironmentCredential {
                credential_type,
                username: None,
                password: None,
                token: None,
                client_id: Some(SecretReference {
                    secret: "REGISTRY_COUNTRY_FIXTURE_CLIENT_ID".to_string(),
                }),
                client_secret: Some(SecretReference {
                    secret: "REGISTRY_COUNTRY_FIXTURE_CLIENT_SECRET".to_string(),
                }),
                value: None,
                review: None,
                generation: 1,
            }),
            CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
                Some(EnvironmentCredential {
                    credential_type,
                    username: None,
                    password: None,
                    token: None,
                    client_id: None,
                    client_secret: None,
                    value: Some(SecretReference {
                        secret: "REGISTRY_COUNTRY_FIXTURE_API_KEY".to_string(),
                    }),
                    review: (credential_type == CredentialType::ApiKeyQuery)
                        .then_some(ReviewClassInput::OperatorSecurity),
                    generation: 1,
                })
            }
        };
        let operations = integration_operations(&integration.document);
        let has_http = !matches!(
            integration.document.capability,
            CapabilityDeclaration::SnapshotExact { .. }
        );
        let has_credential_destination = operations
            .values()
            .any(|operation| operation.role == OperationRole::Credential);
        let advanced_capabilities = matches!(
            integration.document.capability,
            CapabilityDeclaration::SandboxedRhai { .. }
        )
        .then_some(IntegrationAdvancedCapabilities {
            sandboxed_rhai: SandboxedRhaiEnablement {
                enabled: true,
                review: ReviewClassInput::OperatorSecurity,
            },
        });
        integrations.insert(
            alias.clone(),
            EnvironmentIntegration {
                source_version,
                data_destination: has_http.then(|| DestinationBinding {
                    origin: format!("https://{alias}.fixture.invalid"),
                }),
                credential_destination: has_credential_destination.then(|| DestinationBinding {
                    origin: format!("https://{alias}-credential.fixture.invalid"),
                }),
                credential,
                advanced_capabilities,
            },
        );
    }
    let entities = loaded
        .records
        .iter()
        .map(|(id, definition)| {
            (
                id.clone(),
                EnvironmentEntityBinding {
                    provider: RecordProvider::Csv {
                        path: PathBuf::from(format!("/var/lib/registry-fixtures/{id}.csv")),
                        header_row: Some(1),
                        delimiter: None,
                        quote: None,
                    },
                    columns: definition
                        .document
                        .fields
                        .keys()
                        .map(|field| (field.clone(), field.clone()))
                        .collect(),
                    source_revision: "offline-fixture".to_string(),
                    generation: "offline-fixture-1".to_string(),
                },
            )
        })
        .collect();
    let callers = loaded
        .project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::Evidence)
        .map(|(service_id, service)| {
            (
                service_id.clone(),
                CallerBinding {
                    api_key_fingerprint: SecretReference {
                        secret: "REGISTRY_COUNTRY_FIXTURE_API_KEY_HASH".to_string(),
                    },
                    scopes: service.access.scopes.clone(),
                },
            )
        })
        .collect();
    Ok(EnvironmentDocument {
        version: 1,
        integrations,
        entities,
        issuance: IssuanceBinding {
            issuer: "did:web:notary.fixture.invalid".to_string(),
            signing_key: SecretReference {
                secret: "REGISTRY_COUNTRY_FIXTURE_ISSUER_JWK".to_string(),
            },
            signing_kid: "offline-fixture-key".to_string(),
            generation: 1,
        },
        callers,
        relay_trust: RelayTrustBinding {
            origin: "https://relay.fixture.invalid".to_string(),
            issuer: "https://workload.fixture.invalid".to_string(),
            jwks_url: "https://workload.fixture.invalid/.well-known/jwks.json".to_string(),
            audience: "registry-relay".to_string(),
            notary_client_id: "registry-country-fixture-notary".to_string(),
            notary_token_file: PathBuf::from("/run/secrets/offline-fixture-token"),
        },
        deployment: DeploymentBinding {
            profile: CountryDeploymentProfile::Local,
            relay: ServiceBinding {
                service: "registry-country-fixture-relay".to_string(),
            },
            notary: ServiceBinding {
                service: "registry-country-fixture-notary".to_string(),
            },
        },
    })
}

fn execute_governed_live_test(loaded: &LoadedCountryProject) -> Result<FixtureReport> {
    let environment = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("live country tests require an environment"))?;
    if matches!(environment, "prod" | "production")
        || environment.starts_with("prod-")
        || environment.ends_with("-prod")
        || loaded.environment.as_ref().is_some_and(|environment| {
            matches!(
                environment.deployment.profile,
                CountryDeploymentProfile::Production | CountryDeploymentProfile::EvidenceGrade
            )
        })
    {
        bail!("live country tests refuse production environments");
    }
    let origin = std::env::var("REGISTRY_STACK_LIVE_NOTARY_ORIGIN")
        .context("live Notary origin is absent from the process environment")?;
    let origin = validate_live_notary_origin(&origin)?;
    let api_key = std::env::var("REGISTRY_STACK_LIVE_NOTARY_API_KEY")
        .context("live Notary API key is absent from the process environment")?;
    if api_key.len() < 32 || api_key.len() > 4096 || api_key.chars().any(char::is_control) {
        bail!("live Notary API key has an invalid bounded shape");
    }
    let request_path = std::env::var_os("REGISTRY_STACK_LIVE_REQUEST_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("live request file is absent from the process environment"))?;
    let request_bytes = read_bounded_external_request(&request_path)?;
    let request = parse_json_strict(&request_bytes).context("live request is not strict JSON")?;
    let claims = validate_live_request(loaded, &request)?;
    validate_live_relay_readiness(&origin)?;
    let expected_path = std::env::var_os("REGISTRY_STACK_LIVE_EXPECTED_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow!("live expected-result file is absent from the process environment")
        })?;
    let expected_bytes = read_bounded_external_request(&expected_path)?;
    let expected = parse_json_strict(&expected_bytes)
        .context("live expected-result file is not strict JSON")?;
    let endpoint = origin
        .join("v1/evaluations")
        .map_err(|_| anyhow!("failed to construct the governed Notary endpoint"))?;
    let response = ureq::post(endpoint.as_str())
        .set("content-type", "application/json")
        .set("accept", "application/json")
        .set("x-api-key", &api_key)
        .send_bytes(&request_bytes)
        .map_err(|_| anyhow!("governed Notary evaluation failed"))?;
    let mut response_bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LIVE_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_bytes)
        .context("failed to read the governed Notary response")?;
    if response_bytes.len() as u64 > MAX_LIVE_RESPONSE_BYTES {
        bail!("governed Notary response exceeded the configured bound");
    }
    let response = parse_json_strict(&response_bytes)
        .context("governed Notary response was not strict JSON")?;
    let returned_claims = validate_live_response(&response, &claims, &expected)?;
    Ok(FixtureReport {
        integration: "governed-notary-relay".to_string(),
        fixture: "live-evaluation".to_string(),
        inputs: Vec::new(),
        calls: vec!["notary-evaluation".to_string()],
        facts: Vec::new(),
        claims: returned_claims,
        outcome: Some("match".to_string()),
        expected_error: None,
        source_access: None,
        passed: true,
        failure: None,
    })
}

fn validate_live_relay_readiness(origin: &url::Url) -> Result<()> {
    let endpoint = origin
        .join("ready")
        .map_err(|_| anyhow!("failed to construct the Notary readiness endpoint"))?;
    let response = ureq::get(endpoint.as_str())
        .set("accept", "application/json")
        .call()
        .map_err(|_| anyhow!("governed Notary readiness check failed"))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LIVE_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read governed Notary readiness")?;
    if bytes.len() as u64 > MAX_LIVE_RESPONSE_BYTES {
        bail!("governed Notary readiness response exceeded the configured bound");
    }
    let readiness = parse_json_strict(&bytes)
        .context("governed Notary readiness response was not strict JSON")?;
    let relay = readiness
        .pointer("/checks/relay")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("governed Notary readiness lacks the Relay dependency check"))?;
    let total = relay
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("governed Notary Relay readiness total is invalid"))?;
    let ok = relay
        .get("ok")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("governed Notary Relay readiness result is invalid"))?;
    if total == 0 || ok != total {
        bail!("governed Notary has no fully ready Relay-backed consultation dependency");
    }
    Ok(())
}

fn validate_live_response(
    response: &Value,
    requested_claims: &[String],
    expected: &Value,
) -> Result<Vec<String>> {
    let object = response
        .as_object()
        .ok_or_else(|| anyhow!("governed Notary response must be an object"))?;
    if object.len() != 1 || !object.contains_key("results") {
        bail!("governed Notary response has an unexpected top-level field");
    }
    let results = object["results"]
        .as_array()
        .ok_or_else(|| anyhow!("governed Notary response results must be an array"))?;
    if results.len() != requested_claims.len() {
        bail!("governed Notary response did not return every requested claim exactly once");
    }
    let requested = requested_claims
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("claims"))
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("live expected-result file must contain only a claims object"))?;
    if expected.keys().map(String::as_str).collect::<BTreeSet<_>>() != requested {
        bail!("live expected-result claims do not exactly match the governed request");
    }
    let mut returned = BTreeSet::new();
    for result in results {
        let result = result
            .as_object()
            .ok_or_else(|| anyhow!("governed Notary result must be an object"))?;
        let claim_id = result
            .get("claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("governed Notary result lacks a claim_id"))?;
        if !requested.contains(claim_id) || !returned.insert(claim_id.to_string()) {
            bail!("governed Notary response contains an unknown or duplicate claim result");
        }
        let expected_result = expected[claim_id]
            .as_object()
            .ok_or_else(|| anyhow!("live expected claim result must be an object"))?;
        if expected_result
            .keys()
            .any(|key| !matches!(key.as_str(), "value" | "satisfied" | "disclosure"))
            || expected_result.is_empty()
        {
            bail!("live expected claim result has an unsupported field");
        }
        for field in expected_result.keys() {
            if result.get(field) != expected_result.get(field) {
                bail!("governed Notary disclosed claim result did not match the expected fixture");
            }
        }
        if result
            .get("provenance")
            .and_then(|value| value.pointer("/used/source_count"))
            .and_then(Value::as_u64)
            .is_none_or(|count| count == 0)
        {
            bail!("governed Notary result lacks source-backed provenance");
        }
    }
    Ok(returned.into_iter().collect())
}

fn validate_live_notary_origin(value: &str) -> Result<url::Url> {
    if value.len() > 2048 || value.trim() != value {
        bail!("live Notary origin has an invalid bounded shape");
    }
    let origin = url::Url::parse(value).context("live Notary origin is not a URL")?;
    let loopback_http = origin.scheme() == "http"
        && match origin.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(_)) | None => false,
        };
    if (origin.scheme() != "https" && !loopback_http)
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("live Notary origin must be an HTTPS origin or an HTTP loopback origin");
    }
    Ok(origin)
}

fn read_bounded_external_request(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("failed to inspect the live request file")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_AUTHORED_FILE_BYTES
    {
        bail!("live request must be a bounded regular file, not a symlink");
    }
    fs::read(path).context("failed to read the live request file")
}

fn validate_live_request(loaded: &LoadedCountryProject, request: &Value) -> Result<Vec<String>> {
    let object = request
        .as_object()
        .ok_or_else(|| anyhow!("live request must be a JSON object"))?;
    if contains_sensitive_request_key(request) {
        bail!("live request contains a forbidden credential-like field");
    }
    let purpose = object
        .get("purpose")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("live request must declare one project purpose"))?;
    let service = loaded
        .project
        .services
        .values()
        .find(|service| service.purpose == purpose)
        .ok_or_else(|| anyhow!("live request purpose is not declared by this project"))?;
    let claims = object
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("live request must contain a claims array"))?;
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        bail!("live request claim count is outside the project bound");
    }
    let mut ids = Vec::with_capacity(claims.len());
    let mut unique = BTreeSet::new();
    for claim in claims {
        let id = match claim {
            Value::String(id) => id.as_str(),
            Value::Object(object) => object
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("live request claim reference is invalid"))?,
            _ => bail!("live request claim reference is invalid"),
        };
        if !service.claims.contains_key(id) || !unique.insert(id) {
            bail!("live request contains an unknown or duplicate project claim");
        }
        ids.push(id.to_string());
    }
    Ok(ids)
}

fn contains_sensitive_request_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "credential" | "credentials" | "password" | "secret" | "token" | "api_key"
            ) || contains_sensitive_request_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_sensitive_request_key),
        _ => false,
    }
}

pub fn check_country_project(options: &CountryCheckOptions) -> Result<CountryCommandReport> {
    validate_baseline_pair(options.against.as_deref(), options.anchor.as_deref())?;
    let loaded = load_country_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    let baseline = load_verified_baseline(
        options.against.as_deref(),
        options.anchor.as_deref(),
        &loaded,
    )?;
    let compiled = compile_country(&loaded, baseline.as_ref())?;
    validate_generated_product_configs(&compiled)?;
    let fixtures = execute_all_fixtures(&loaded, &compiled)?;
    require_passing_fixtures(&fixtures)?;
    Ok(CountryCommandReport {
        status: "valid",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        required_reviews: compiled.required_reviews.clone(),
        baseline: if baseline.is_some() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: None,
        explanation: options.explain.then_some(compiled.explanation),
    })
}

pub fn build_country_project(options: &CountryBuildOptions) -> Result<CountryCommandReport> {
    validate_baseline_pair(options.against.as_deref(), options.anchor.as_deref())?;
    let loaded = load_country_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    let baseline = load_verified_baseline(
        options.against.as_deref(),
        options.anchor.as_deref(),
        &loaded,
    )?;
    let compiled = compile_country(&loaded, baseline.as_ref())?;
    validate_generated_product_configs(&compiled)?;
    let fixtures = execute_all_fixtures(&loaded, &compiled)?;
    require_passing_fixtures(&fixtures)?;
    let output = loaded
        .root
        .join(BUILD_ROOT)
        .join(options.environment.as_str());
    write_compiled_country(&loaded.root, &output, &compiled)?;
    Ok(CountryCommandReport {
        status: "built",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        required_reviews: compiled.required_reviews.clone(),
        baseline: if baseline.is_some() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: Some(output.display().to_string()),
        explanation: None,
    })
}

fn require_passing_fixtures(fixtures: &[FixtureReport]) -> Result<()> {
    let failing = fixtures
        .iter()
        .filter(|fixture| !fixture.passed)
        .map(|fixture| {
            format!(
                "{}.{} ({})",
                fixture.integration,
                fixture.fixture,
                fixture.failure.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>();
    if !failing.is_empty() {
        bail!(
            "country integration fixtures failed: {}",
            failing.join(", ")
        );
    }
    Ok(())
}

fn compile_country(
    loaded: &LoadedCountryProject,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledCountry> {
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("country build requires an explicit environment"))?;
    let environment_name = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("country build requires an explicit environment"))?;
    compile_country_for_environment(loaded, environment_name, environment, baseline)
}

fn compile_country_for_environment(
    loaded: &LoadedCountryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<CompiledCountry> {
    validate_entity_generation_changes(loaded, environment, baseline)?;
    let mut reviewable = BTreeMap::new();
    let mut relay_private = BTreeMap::new();
    let mut packs = BTreeMap::new();

    for (id, records) in &loaded.records {
        reviewable.insert(
            PathBuf::from(format!("records/{id}.json")),
            canonical_json_line(&serde_json::to_value(&records.document)?)?.into_boxed_slice(),
        );
    }

    for (alias, integration) in &loaded.integrations {
        let evidence = generate_evidence(alias, integration)?;
        let pack_document =
            integration_pack_document(loaded, environment, alias, integration, &evidence)?;
        let authored =
            compile_integration_pack(&canonical_json_line(&pack_document)?).map_err(|error| {
                anyhow!("generated integration pack {alias} did not compile: {error:?}")
            })?;
        let path = PathBuf::from(format!("config/artifacts/integration-packs/{alias}.json"));
        let review_path = PathBuf::from(format!("integration-packs/{alias}.json"));
        reviewable.insert(review_path, authored.canonical_json().into());
        relay_private.insert(path, authored.canonical_json().into());
        for artifact in &evidence {
            relay_private.insert(
                PathBuf::from("config").join(&artifact.path),
                artifact.bytes.clone(),
            );
        }
        if let Some((_, script)) = &integration.script {
            relay_private.insert(
                PathBuf::from(format!("config/artifacts/rhai/{alias}.rhai")),
                script.clone(),
            );
        }
        let id = pack_document["id"]
            .as_str()
            .ok_or_else(|| anyhow!("generated integration pack id is absent"))?
            .to_string();
        let version = pack_document["version"]
            .as_str()
            .ok_or_else(|| anyhow!("generated integration pack version is absent"))?
            .to_string();
        packs.insert(
            alias.clone(),
            GeneratedPack {
                alias: alias.clone(),
                id,
                version,
                artifact: authored,
                evidence,
            },
        );
    }

    let mut profiles = Vec::new();
    for (service_id, service) in &loaded.project.services {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        for (consultation_name, consultation) in &service.consultations {
            let pack = packs
                .get(&consultation.integration)
                .ok_or_else(|| anyhow!("generated consultation lacks its integration pack"))?;
            let (profile_id, profile_version) =
                generated_profile_identity(loaded, service_id, consultation_name, pack)?;
            let contract_document = consultation_contract_document(
                loaded,
                environment,
                (service_id, service),
                (consultation_name, consultation),
                pack,
                (&profile_id, &profile_version),
            )?;
            let contract = compile_consultation_contract(&canonical_json_line(&contract_document)?)
                .map_err(|error| anyhow!(
                    "generated consultation contract {service_id}.{consultation_name} did not compile: {error:?}"
                ))?;
            let binding_document = private_binding_document(
                loaded,
                environment,
                consultation,
                pack,
                &profile_id,
                &profile_version,
            )?;
            let binding = compile_private_binding(&canonical_json_line(&binding_document)?)
                .map_err(|error| anyhow!(
                    "generated private binding {service_id}.{consultation_name} did not compile: {error:?}"
                ))?;
            let contract_path = PathBuf::from(format!(
                "config/artifacts/consultation-contracts/{service_id}-{consultation_name}.json"
            ));
            let review_path = PathBuf::from(format!(
                "consultation-contracts/{service_id}-{consultation_name}.json"
            ));
            let binding_path = PathBuf::from(format!(
                "config/artifacts/private-bindings/{service_id}-{consultation_name}.json"
            ));
            reviewable.insert(review_path, contract.artifact().canonical_json().into());
            relay_private.insert(contract_path, contract.artifact().canonical_json().into());
            relay_private.insert(binding_path, binding.canonical_json().into());
            profiles.push(GeneratedProfile {
                service_id: service_id.clone(),
                consultation_name: consultation_name.clone(),
                integration_alias: consultation.integration.clone(),
                id: profile_id,
                version: profile_version,
                contract,
                binding,
            });
        }
    }

    let relay_config =
        generated_relay_config(loaded, environment_name, environment, &packs, &profiles)?;
    relay_private.insert(
        PathBuf::from("config/relay.yaml"),
        serde_yaml::to_string(&relay_config)?
            .into_bytes()
            .into_boxed_slice(),
    );
    let notary_config = generated_notary_config(loaded, environment_name, environment, &profiles)?;
    relay_private.insert(
        PathBuf::from("descriptors/operations.json"),
        canonical_json_line(&operational_descriptor(
            "registry-relay",
            &environment.deployment.relay.service,
            environment.deployment.profile,
            profiles.len(),
        ))?
        .into_boxed_slice(),
    );
    relay_private.insert(
        PathBuf::from("descriptors/secret-consumers.json"),
        canonical_json_line(&secret_consumer_descriptor("registry-relay", &relay_config))?
            .into_boxed_slice(),
    );
    let mut notary_private = BTreeMap::from([(
        PathBuf::from("config/notary.yaml"),
        serde_yaml::to_string(&notary_config)?
            .into_bytes()
            .into_boxed_slice(),
    )]);
    notary_private.insert(
        PathBuf::from("descriptors/operations.json"),
        canonical_json_line(&operational_descriptor(
            "registry-notary",
            &environment.deployment.notary.service,
            environment.deployment.profile,
            profiles.len(),
        ))?
        .into_boxed_slice(),
    );
    notary_private.insert(
        PathBuf::from("descriptors/secret-consumers.json"),
        canonical_json_line(&secret_consumer_descriptor(
            "registry-notary",
            &notary_config,
        ))?
        .into_boxed_slice(),
    );

    let reviewable_digest = closure_digest(&reviewable)?;
    let relay_digest = closure_digest(&relay_private)?;
    let notary_digest = closure_digest(&notary_private)?;
    let closure_digests = json!({
        "reviewable": reviewable_digest,
        "relay": relay_digest,
        "notary": notary_digest,
    });
    let semantic_changes =
        semantic_change_records(loaded, baseline.map(|baseline| &baseline.review));
    let reviews = required_reviews(loaded, baseline.map(|baseline| &baseline.review));
    let semantic_unchanged = reviews.is_empty();
    let mut reviews = reviews;
    if let Some(baseline) = baseline {
        let compiler_changed = baseline
            .review
            .get("compiler_version")
            .and_then(Value::as_str)
            != Some(env!("CARGO_PKG_VERSION"));
        let generated_changed =
            baseline.review.get("generated_closure_digests") != Some(&closure_digests);
        if semantic_unchanged && (compiler_changed || generated_changed) {
            reviews.extend([
                ReviewClass::Claim,
                ReviewClass::Integration,
                ReviewClass::CountryPolicy,
                ReviewClass::OperatorSecurity,
            ]);
        }
    }
    let baseline_record = baseline
        .map(|baseline| {
            Ok::<Value, anyhow::Error>(json!({
                "review_digest": digest_json(&baseline.review)?,
                "authored_input_digest": baseline.review.get("authored_input_digest"),
                "verified_manifest": baseline.verified_manifest,
            }))
        })
        .transpose()?;
    let review = json!({
        "schema": REVIEW_SCHEMA,
        "registry": loaded.project.registry.id,
        "source_revision": loaded.authored_hash,
        "compiler_version": env!("CARGO_PKG_VERSION"),
        "baseline": baseline_record,
        "authored_input_digest": loaded.authored_hash,
        "semantic_digests": loaded.semantic_digests,
        "generated_closure_digests": closure_digests,
        "semantic_changes": semantic_changes,
        "required_reviews": reviews,
        "environment": environment_name,
        "entity_materializations": generated_entity_materialization_review(loaded, environment)?,
    });
    let explanation = generated_explanation(loaded, environment_name, &packs, &profiles);
    let fixture_profiles = profiles
        .iter()
        .map(|profile| FixtureProfile {
            service_id: profile.service_id.clone(),
            integration_alias: profile.integration_alias.clone(),
            id: profile.id.clone(),
            version: profile.version.clone(),
            contract_hash: profile.contract.artifact().typed_hash().to_string(),
        })
        .collect();
    // The review record itself is deliberately excluded from the digests above.
    // It becomes a signed payload member only when the existing bundle command runs.
    Ok(CompiledCountry {
        reviewable,
        relay_private,
        notary_private,
        review,
        explanation,
        fixture_profiles,
        semantic_changes,
        required_reviews: reviews,
    })
}

fn operational_descriptor(
    product: &str,
    service: &str,
    profile: CountryDeploymentProfile,
    consultation_profiles: usize,
) -> Value {
    let config = match product {
        "registry-relay" => "config/relay.yaml",
        "registry-notary" => "config/notary.yaml",
        _ => "config.yaml",
    };
    json!({
        "schema": "registry.country.operations.v1",
        "product": product,
        "service": service,
        "deployment_profile": profile,
        "config": config,
        "health": "/healthz",
        "readiness": "/ready",
        "restart_required": true,
        "consultation_profiles": consultation_profiles,
    })
}

fn secret_consumer_descriptor(product: &str, config: &Value) -> Value {
    let mut consumers = Vec::new();
    collect_secret_consumers(config, "", &mut consumers);
    consumers.sort_by(|left, right| {
        left.get("config_pointer")
            .and_then(Value::as_str)
            .cmp(&right.get("config_pointer").and_then(Value::as_str))
            .then_with(|| {
                left.get("kind")
                    .and_then(Value::as_str)
                    .cmp(&right.get("kind").and_then(Value::as_str))
            })
    });
    json!({
        "schema": "registry.country.secret-consumers.v1",
        "product": product,
        "consumers": consumers,
    })
}

fn collect_secret_consumers(value: &Value, pointer: &str, output: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if object
                .get("provider")
                .and_then(Value::as_str)
                .is_some_and(|provider| matches!(provider, "env" | "environment"))
            {
                if let Some(locator) = object.get("name").and_then(Value::as_str) {
                    output.push(json!({
                        "kind": "environment",
                        "locator": locator,
                        "config_pointer": format!("{pointer}/name"),
                    }));
                }
            }
            for (name, value) in object {
                let next = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                let kind = if name.ends_with("_env") {
                    Some("environment")
                } else if matches!(
                    name.as_str(),
                    "token_file" | "notary_token_file" | "private_key_file" | "secret_file"
                ) {
                    Some("file")
                } else {
                    None
                };
                if let (Some(kind), Some(locator)) = (kind, value.as_str()) {
                    output.push(json!({
                        "kind": kind,
                        "locator": locator,
                        "config_pointer": next,
                    }));
                }
                collect_secret_consumers(value, &next, output);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_secret_consumers(value, &format!("{pointer}/{index}"), output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn closure_digest(files: &BTreeMap<PathBuf, Box<[u8]>>) -> Result<String> {
    let entries = files
        .iter()
        .map(|(path, bytes)| {
            Ok(json!({
                "path": path
                    .to_str()
                    .ok_or_else(|| anyhow!("generated path is not Unicode"))?,
                "sha256": sha256_uri(bytes),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    digest_json(&Value::Array(entries))
}

fn generate_evidence(
    alias: &str,
    integration: &LoadedIntegration,
) -> Result<Vec<GeneratedEvidence>> {
    let conformance = integration
        .fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.error.is_none())
        .map(|(_, fixture)| fixture)
        .collect::<Vec<_>>();
    let negative_security = integration
        .fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.error.is_some())
        .map(|(_, fixture)| fixture)
        .collect::<Vec<_>>();
    let classes = [
        (
            EvidenceClass::Conformance,
            "conformance",
            json!({
                "schema": "registry.country.integration-evidence.v1",
                "class": "conformance",
                "integration": integration.document.id,
                "fixtures": conformance,
            }),
        ),
        (
            EvidenceClass::NegativeSecurity,
            "negative-security",
            json!({
                "schema": "registry.country.integration-evidence.v1",
                "class": "negative_security",
                "integration": integration.document.id,
                "fixtures": negative_security,
            }),
        ),
        (
            EvidenceClass::Minimization,
            "minimization",
            json!({
                "schema": "registry.country.integration-evidence.v1",
                "class": "minimization",
                "integration": integration.document.id,
                "facts": integration.document.facts,
                "operations": integration_operations(&integration.document)
                    .iter()
                    .map(|(id, operation)| (id, json!({
                        "request": operation.request,
                        "response_schema": operation.response.schema,
                    })))
                    .collect::<BTreeMap<_, _>>(),
            }),
        ),
    ];
    classes
        .into_iter()
        .map(|(class, name, value)| {
            let bytes = canonical_json_line(&value)?.into_boxed_slice();
            Ok(GeneratedEvidence {
                class,
                path: PathBuf::from(format!("artifacts/evidence/{alias}/{name}.json")),
                sha256: sha256_uri(&bytes),
                bytes,
            })
        })
        .collect()
}

fn integration_pack_document(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let binding = environment
        .integrations
        .get(alias)
        .ok_or_else(|| anyhow!("integration environment binding is absent"))?;
    let pack_id = bounded_join_id(&[
        loaded.project.registry.id.as_str(),
        integration.document.id.as_str(),
    ])?;
    let version_seed = json!({
        "integration": integration.document,
        "fixtures": integration.fixtures.iter().map(|(_, fixture)| fixture).collect::<Vec<_>>(),
        "script": integration.script.as_ref().map(|(_, bytes)| sha256_uri(bytes)),
        "source_version": binding.source_version,
    });
    let version = numeric_artifact_version(&digest_json(&version_seed)?)?;
    let input_slots = integration
        .document
        .input
        .iter()
        .map(|(name, input)| {
            Ok((
                name.clone(),
                json!({
                    "type": match input.input_type {
                        InputType::String => "string",
                        InputType::FullDate => "full_date",
                    },
                    "max_bytes": input.bytes,
                    "pattern": relay_input_pattern(&input.pattern)?,
                    "canonicalization": match input.canonicalization {
                        Canonicalization::Identity => "identity",
                        Canonicalization::AsciiLowercase => "ascii_lowercase",
                    },
                }),
            ))
        })
        .collect::<Result<Map<String, Value>>>()?;
    let (acquisition, reviewed, output, plan, limits, _materialization) =
        generated_pack_semantics(alias, integration, evidence)?;
    let evidence_manifest = evidence_manifest(evidence);
    let specification = json!({
        "product_family": integration.document.source.product,
        "supported_version_evidence": [format!("{}:{}", source_version_class(&integration.document, &binding.source_version), binding.source_version)],
        "logical_operation": integration.document.id,
        "input_slots": input_slots,
        "acquisition": acquisition,
        "source_provenance": {
            "source_observed_at": { "type": "absent" },
            "source_revision": { "type": "absent" },
        },
        "reviewed_acquisition": reviewed,
        "output": output,
        "plan": plan,
        "bounds": limits,
        "deployment_parameters": {},
        "evidence": evidence_manifest,
    });
    Ok(json!({
        "schema": "registry.relay.integration-pack.v1",
        "id": pack_id,
        "version": version,
        "spec": specification,
    }))
}

fn source_version_class(integration: &IntegrationDocument, version: &str) -> &'static str {
    if integration
        .source
        .versions
        .tested
        .iter()
        .any(|item| item == version)
    {
        "tested"
    } else if integration
        .source
        .versions
        .supported
        .iter()
        .any(|item| item == version)
    {
        "supported"
    } else {
        "unverified"
    }
}

fn relay_input_pattern(pattern: &str) -> Result<String> {
    let bytes = pattern.as_bytes();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            if bytes[index] == b'{' || bytes[index] == b'}' {
                bail!("input pattern uses an unsupported repetition shape");
            }
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() && bytes[index] != b']' {
            index += 1;
        }
        if index == bytes.len() {
            bail!("input pattern contains an unterminated character class");
        }
        index += 1;
        let atom = &pattern[start..index];
        let repetitions = if bytes.get(index) == Some(&b'{') {
            let count_start = index + 1;
            let Some(relative_end) = bytes[count_start..].iter().position(|byte| *byte == b'}')
            else {
                bail!("input pattern contains an unterminated repetition");
            };
            let count_end = count_start + relative_end;
            let count = pattern[count_start..count_end].parse::<usize>()?;
            if count == 0 || count > 64 {
                bail!("input pattern fixed repetition is outside the supported bound");
            }
            index = count_end + 1;
            count
        } else {
            1
        };
        for _ in 0..repetitions {
            output.push_str(atom);
        }
    }
    Ok(output)
}

fn evidence_manifest(evidence: &[GeneratedEvidence]) -> Value {
    let hashes = |class| {
        evidence
            .iter()
            .filter(|artifact| artifact.class == class)
            .map(|artifact| Value::String(artifact.sha256.clone()))
            .collect::<Vec<_>>()
    };
    json!({
        "conformance": hashes(EvidenceClass::Conformance),
        "negative_security": hashes(EvidenceClass::NegativeSecurity),
        "minimization": hashes(EvidenceClass::Minimization),
    })
}

fn bounded_join_id(parts: &[&str]) -> Result<String> {
    let id = parts.join(".");
    validate_stable_id(&id, "generated artifact id")?;
    Ok(id)
}

fn bounded_scope(parts: &[&str]) -> Result<String> {
    let scope = parts.join(":");
    validate_token(&scope, "generated scope", 256)?;
    Ok(scope)
}

fn numeric_artifact_version(digest: &str) -> Result<String> {
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("semantic digest has an invalid shape"))?;
    let value = u64::from_str_radix(&hexadecimal[..12], 16)? % 9_000_000_000;
    Ok((value + 1_000_000_000).to_string())
}

type PackSemantics = (Value, Value, Value, Value, Value, Option<Value>);

fn generated_pack_semantics(
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<PackSemantics> {
    match &integration.document.capability {
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SandboxedRhai { .. } => {
            generated_http_pack_semantics(alias, integration, evidence)
        }
        CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
            generated_snapshot_pack_semantics(alias, integration, snapshot_exact)
        }
    }
}

fn generated_http_pack_semantics(
    alias: &str,
    integration: &LoadedIntegration,
    evidence: &[GeneratedEvidence],
) -> Result<PackSemantics> {
    let ordered = ordered_operations(integration_operations(&integration.document))?;
    let data_operations = ordered
        .iter()
        .copied()
        .filter(|(_, operation)| operation.role == OperationRole::Data)
        .collect::<Vec<_>>();
    if data_operations.is_empty() {
        bail!("HTTP integration must declare at least one data operation");
    }
    let mut acquired_fields = Map::new();
    let mut reviewed_fields = Map::new();
    let mut reviewed_controls = Map::new();
    let control_fields = referenced_prior_fields(&integration.document)?;
    for (operation_id, operation) in &data_operations {
        let record = operation_record_schema(operation)?;
        if operation.primitive.as_deref() == Some("dci_search_v1") {
            let SchemaNode::Object { .. } = record else {
                bail!("DCI post-codec record schema must be an object");
            };
            let compiled = relay_schema_node(record, false);
            acquired_fields.insert("record".to_string(), compiled.clone());
            reviewed_fields.insert("record".to_string(), compiled);
            continue;
        }
        let SchemaNode::Object { fields, .. } = record else {
            bail!("operation normalized record schema must be an object");
        };
        for (field, schema) in fields {
            let compiled = relay_schema_node(&schema.schema, false);
            if acquired_fields
                .insert(field.clone(), compiled.clone())
                .is_some_and(|prior| prior != compiled)
            {
                bail!("duplicate acquired field has conflicting closed schemas");
            }
            if control_fields
                .get(operation_id.as_str())
                .is_some_and(|controls| controls.contains(field))
            {
                reviewed_controls.insert(field.clone(), compiled);
            } else {
                reviewed_fields.insert(field.clone(), compiled);
            }
        }
    }
    let output = integration
        .document
        .facts
        .iter()
        .map(|(name, fact)| {
            let output_type = if fact.from.ends_with(".presence") {
                "presence"
            } else {
                match fact.fact_type {
                    FactType::Boolean | FactType::Presence => "boolean",
                    FactType::Integer => "integer",
                    FactType::String => "string",
                    FactType::Date => "date",
                }
            };
            (
                name.clone(),
                json!({ "type": output_type, "nullable": fact.nullable }),
            )
        })
        .collect::<Map<String, Value>>();
    let root_operation_id = data_operations[0].0;
    let operations = data_operations
        .iter()
        .map(|(id, operation)| {
            generated_http_operation(
                alias,
                &integration.document,
                id,
                operation,
                *id == root_operation_id,
                &control_fields,
                evidence,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let step_conditions = if matches!(
        integration.document.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    ) {
        Map::new()
    } else {
        generated_step_conditions(&integration.document)?
    };
    let verification_operations = generated_verification_operations(alias, &integration.document)?;
    let first = data_operations[0];
    let selector = exact_selector(&integration.document.input, first.0, first.1)?;
    let any_probe_two = data_operations.iter().any(|(_, operation)| {
        operation
            .response
            .cardinality
            .as_ref()
            .is_some_and(|cardinality| cardinality.mode == CardinalityMode::ProbeTwo)
            || operation
                .response
                .status_semantics
                .as_ref()
                .is_some_and(|semantics| !semantics.ambiguous.is_empty())
    });
    let acquisition = json!({
        "class": "bounded_full_record",
        "fields": acquired_fields,
    });
    let reviewed = json!({
        "class": "bounded_full_record",
        "fields": reviewed_fields,
        "control_fields": reviewed_controls,
        "selector": selector,
        "cardinality": if any_probe_two { "probe_two" } else { "source_enforced_singleton" },
        "reject_unknown_fields": true,
    });
    let plan_kind = match integration.document.capability {
        CapabilityDeclaration::BoundedHttp { .. } => "bounded_http",
        CapabilityDeclaration::SandboxedRhai { .. } => "sandboxed_rhai",
        CapabilityDeclaration::SnapshotExact { .. } => unreachable!(),
    };
    let credential_operation = generated_credential_operation(alias, &integration.document)?;
    let credential_slot = credential_operation
        .as_ref()
        .map(|_| format!("{alias}-credential"));
    let rhai = generated_rhai_template(alias, integration)?;
    let plan = json!({
        "kind": plan_kind,
        "data_destination_slot": format!("{alias}-data"),
        "credential_destination_slot": credential_slot,
        "operations": operations,
        "verification_operations": verification_operations,
        "steps": data_operations.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        "step_conditions": step_conditions,
        "credential_operation": credential_operation,
        "snapshot": null,
        "rhai": rhai,
    });
    let credential_exchanges = usize::from(credential_operation.is_some());
    let limits = json!({
        "max_source_matches": if any_probe_two { 2 } else { 1 },
        "max_disclosed_records": 1,
        "max_data_exchanges": data_operations.len() + verification_operations.len(),
        "max_credential_exchanges": credential_exchanges,
        "max_data_destinations": 1,
        "max_source_bytes": integration.document.bounds.source_bytes,
        "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
        "max_in_flight": integration.document.bounds.concurrency,
        "quota_per_minute": 60,
        "quota_burst": integration.document.bounds.concurrency.min(60),
    });
    Ok((
        acquisition,
        reviewed,
        Value::Object(output),
        plan,
        limits,
        None,
    ))
}

fn generated_snapshot_pack_semantics(
    _alias: &str,
    integration: &LoadedIntegration,
    snapshot: &SnapshotExactDeclaration,
) -> Result<PackSemantics> {
    let mut fields = Map::new();
    let mut output = Map::new();
    for (fact_name, fact) in &integration.document.facts {
        let (_, path) = fact
            .from
            .split_once('.')
            .ok_or_else(|| anyhow!("snapshot fact path is invalid"))?;
        let field = path.strip_prefix("record.").unwrap_or(path);
        if field == "presence" {
            output.insert(
                fact_name.clone(),
                json!({ "type": "presence", "nullable": false }),
            );
            continue;
        }
        let schema = match fact.fact_type {
            FactType::Boolean | FactType::Presence => {
                json!({ "type": "boolean", "nullable": fact.nullable })
            }
            FactType::Integer => json!({
                "type": "integer",
                "nullable": fact.nullable,
                "minimum": -((1_i64 << 53) - 1),
                "maximum": (1_i64 << 53) - 1,
            }),
            FactType::String => json!({
                "type": "string",
                "nullable": fact.nullable,
                "max_bytes": fact.max_bytes.ok_or_else(|| anyhow!("snapshot string fact bound is absent"))?,
            }),
            FactType::Date => {
                json!({ "type": "string", "nullable": fact.nullable, "max_bytes": 10 })
            }
        };
        fields.insert(field.to_string(), schema);
        output.insert(
            fact_name.clone(),
            json!({
                "type": match fact.fact_type {
                    FactType::Boolean | FactType::Presence => "boolean",
                    FactType::Integer => "integer",
                    FactType::String => "string",
                    FactType::Date => "date",
                },
                "nullable": fact.nullable,
            }),
        );
    }
    let max_matches = match snapshot.cardinality {
        CardinalityMode::Singleton => 1,
        CardinalityMode::ProbeTwo => 2,
    };
    let freshness = u64::from(parse_duration_ms_with_max(
        &snapshot.freshness,
        31 * 24 * 60 * 60 * 1_000,
        "snapshot freshness",
    )?);
    let acquisition = json!({
        "class": "materialized_snapshot",
        "fields": fields,
    });
    let reviewed = json!({
        "class": "materialized_snapshot",
        "fields": fields,
        "control_fields": {},
        "selector": {
            "type": "snapshot_exact_and",
            "components": integration.document.input.keys().map(|input| {
                (input.clone(), json!("snapshot_key"))
            }).collect::<Map<String, Value>>(),
        },
        "cardinality": if max_matches == 2 { "probe_two" } else { "source_enforced_singleton" },
        "reject_unknown_fields": true,
    });
    let plan = json!({
        "kind": "snapshot_exact",
        "data_destination_slot": null,
        "credential_destination_slot": null,
        "operations": [],
        "steps": [],
        "credential_operation": null,
        "snapshot": {
            "max_snapshot_age_ms": freshness,
            "unavailable": "unavailable",
            "immutable_generation": true,
        },
        "rhai": null,
    });
    let limits = json!({
        "max_source_matches": max_matches,
        "max_disclosed_records": 1,
        "max_data_exchanges": 0,
        "max_credential_exchanges": 0,
        "max_data_destinations": 0,
        "max_source_bytes": integration.document.bounds.source_bytes,
        "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
        "max_in_flight": integration.document.bounds.concurrency,
        "quota_per_minute": 60,
        "quota_burst": integration.document.bounds.concurrency.min(60),
    });
    let materialization = json!({
        "max_snapshot_age_ms": freshness,
        "stale_behavior": "unavailable",
        "footprint": {
            "fields": fields.keys().collect::<Vec<_>>(),
            "max_source_records": snapshot.materialization.max_source_records,
            "max_source_bytes": snapshot.materialization.max_source_bytes,
            "max_data_exchanges": 1,
            "max_credential_exchanges": 0,
            "max_data_destinations": 1,
        },
        "refresh_class": "operator_triggered",
        "snapshot_retention_generations": 2,
        "immutable_generation": true,
        "digest_bound_active_pointer": true,
    });
    Ok((
        acquisition,
        reviewed,
        Value::Object(output),
        plan,
        limits,
        Some(materialization),
    ))
}

fn operation_record_schema(operation: &OperationDeclaration) -> Result<&SchemaNode> {
    if operation.primitive.as_deref() == Some("fhir_r4_search_get") {
        return Ok(&operation.response.schema);
    }
    let Some(cardinality) = &operation.response.cardinality else {
        return Ok(&operation.response.schema);
    };
    let Some(path) = cardinality.records.as_deref() else {
        return Ok(&operation.response.schema);
    };
    let mut current = &operation.response.schema;
    for segment in path.split('.') {
        current = match current {
            SchemaNode::Object { fields, .. } => fields
                .get(segment)
                .map(|field| &field.schema)
                .ok_or_else(|| anyhow!("cardinality record path is not in the response schema"))?,
            _ => bail!("cardinality record path traverses a non-object schema"),
        };
    }
    match current {
        SchemaNode::Array { items, .. } => Ok(items),
        _ => bail!("cardinality record path must resolve to an array"),
    }
}

fn relay_schema_node(schema: &SchemaNode, nullable: bool) -> Value {
    match schema {
        SchemaNode::Object { fields, .. } => json!({
            "type": "object",
            "nullable": nullable,
            "reject_unknown_fields": true,
            "fields": fields.iter().map(|(name, field)| (name.clone(), json!({
                "required": field.required,
                "schema": relay_schema_node(&field.schema, false),
            }))).collect::<Map<String, Value>>(),
        }),
        SchemaNode::Array { max_items, items } => json!({
            "type": "array",
            "nullable": nullable,
            "max_items": max_items,
            "items": relay_schema_node(items, false),
        }),
        SchemaNode::String { max_bytes } => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": max_bytes })
        }
        SchemaNode::Integer { min, max } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({ "type": "boolean", "nullable": nullable }),
        SchemaNode::Date => {
            json!({ "type": "string", "nullable": nullable, "max_bytes": 10 })
        }
    }
}

fn referenced_prior_fields(
    integration: &IntegrationDocument,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut fields = BTreeMap::<String, BTreeSet<String>>::new();
    for operation in integration_operations(integration).values() {
        for source in operation
            .request
            .query
            .values()
            .chain(operation.request.headers.values())
            .chain(operation.request.path_parameters.values())
        {
            if let ValueSource::Prior { prior: output } = source {
                record_prior_field(output, &mut fields)?;
            }
        }
        if let Some(body) = &operation.request.body {
            collect_body_prior_fields(body, &mut fields)?;
        }
    }
    Ok(fields)
}

fn record_prior_field(path: &str, fields: &mut BTreeMap<String, BTreeSet<String>>) -> Result<()> {
    let (operation, path) = path
        .split_once('.')
        .ok_or_else(|| anyhow!("prior field path is invalid"))?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    let field = path
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("prior field path is empty"))?;
    if field != "presence" {
        fields
            .entry(operation.to_string())
            .or_default()
            .insert(field.to_string());
    }
    Ok(())
}

fn collect_body_prior_fields(
    value: &Value,
    fields: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(path) = object.get("prior").and_then(Value::as_str) {
                record_prior_field(path, fields)?;
            }
            for value in object.values() {
                collect_body_prior_fields(value, fields)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_body_prior_fields(value, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn generated_http_operation(
    alias: &str,
    integration: &IntegrationDocument,
    operation_id: &str,
    operation: &OperationDeclaration,
    is_root: bool,
    control_fields: &BTreeMap<String, BTreeSet<String>>,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let is_dci = operation.primitive.as_deref() == Some("dci_search_v1");
    let is_fhir = operation.primitive.as_deref() == Some("fhir_r4_search_get");
    let is_rhai = matches!(
        integration.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    );
    let record = operation_record_schema(operation)?;
    let SchemaNode::Object { fields, .. } = record else {
        bail!("normalized operation record must be an object");
    };
    let operation_facts = integration
        .facts
        .iter()
        .filter_map(|(name, fact)| {
            fact.from
                .split_once('.')
                .is_some_and(|(source, _)| source == operation_id)
                .then_some((name, fact))
        })
        .collect::<Vec<_>>();
    let acquisition_fields = if is_dci {
        BTreeSet::from(["record"])
    } else {
        operation_facts
            .iter()
            .filter_map(|(_, fact)| {
                let (_, path) = fact.from.split_once('.')?;
                (!path.ends_with("presence"))
                    .then(|| path.strip_prefix("record.").unwrap_or(path))
                    .and_then(|path| path.split('.').next())
            })
            .collect::<BTreeSet<_>>()
    };
    let controls = control_fields
        .get(operation_id)
        .cloned()
        .unwrap_or_default();
    let output_mapping = if is_rhai {
        Map::new()
    } else {
        operation_facts
            .iter()
            .filter_map(|(name, fact)| {
                let (_, path) = fact.from.split_once('.')?;
                if path == "presence" {
                    None
                } else {
                    let path = path.strip_prefix("record.").unwrap_or(path);
                    let pointer = if is_dci {
                        format!("record.{path}")
                    } else {
                        path.to_string()
                    };
                    Some(((*name).clone(), static_json_pointer(&pointer)))
                }
            })
            .collect::<Map<String, Value>>()
    };
    let presence_outputs = if is_rhai {
        Vec::new()
    } else {
        operation_facts
            .iter()
            .filter_map(|(name, fact)| fact.from.ends_with(".presence").then_some((*name).clone()))
            .collect::<Vec<_>>()
    };
    let prior_fields = if matches!(
        integration.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    ) {
        fields.keys().cloned().collect::<BTreeSet<_>>()
    } else {
        controls.clone()
    };
    let prior_outputs = prior_fields
        .iter()
        .map(|field| {
            let schema = fields
                .get(field)
                .ok_or_else(|| anyhow!("prior output field is absent from its response schema"))?;
            Ok((
                field.clone(),
                prior_output_document(&schema.schema, &format!("/{field}"))?,
            ))
        })
        .collect::<Result<Map<String, Value>>>()?;
    let response_cardinality = if is_dci {
        json!({ "mechanism": "dci_probe_two" })
    } else {
        generated_cardinality(operation, evidence)?
    };
    let cardinality = operation.response.cardinality.as_ref();
    let (normalization, records_field, max_records) = if is_dci || is_fhir {
        ("json_array_probe_two", None, 2)
    } else {
        match cardinality {
            Some(CardinalityDeclaration {
                records: Some(path),
                mode: CardinalityMode::ProbeTwo,
            }) => ("json_object_array_probe_two", Some(path.clone()), 2),
            Some(CardinalityDeclaration {
                records: None,
                mode: CardinalityMode::Singleton,
            })
            | None => ("json_object", None, 1),
            Some(CardinalityDeclaration {
                records: Some(_),
                mode: CardinalityMode::Singleton,
            }) => (
                "json_object_array_singleton",
                cardinality.and_then(|item| item.records.clone()),
                1,
            ),
            Some(CardinalityDeclaration {
                records: None,
                mode: CardinalityMode::ProbeTwo,
            }) => bail!(
                "probe-two response requires a reviewed record collection or status semantics"
            ),
        }
    };
    let response_schema = if is_dci {
        json!({
            "type": "array",
            "nullable": false,
            "max_items": 2,
            "items": {
                "type": "object",
                "nullable": false,
                "reject_unknown_fields": true,
                "fields": {
                    "record": {
                        "required": true,
                        "schema": relay_schema_node(record, false),
                    },
                },
            },
        })
    } else if is_fhir {
        json!({
            "type": "array",
            "nullable": false,
            "max_items": 2,
            "items": relay_schema_node(record, false),
        })
    } else {
        relay_schema_node(&operation.response.schema, false)
    };
    let mut response = json!({
        "max_bytes": operation.response.max_bytes,
        "max_records": max_records,
        "normalization": normalization,
        "cardinality": response_cardinality,
        "schema": response_schema,
        "output_mapping": output_mapping,
        "presence_outputs": presence_outputs,
        "prior_outputs": prior_outputs,
        "accepted_statuses": operation.response.statuses,
    });
    if let Some(records_field) = records_field {
        response["records_field"] = Value::String(records_field);
    }
    if let Some(statuses) = &operation.response.status_semantics {
        response["status_outcomes"] = json!({
            "no_match": statuses.no_match,
            "ambiguous": statuses.ambiguous,
        });
    }
    let request_codec = match operation.request.codec.as_deref() {
        None => "none",
        Some("strict_json_v1") => "json",
        Some("dci_search_v1") => "dci_exact_v1",
        Some("fhir_r4_search_get") => "fhir_r4_search",
        Some(other) => bail!("unsupported reviewed request codec {other}"),
    };
    let request_signer: Option<&str> = None;
    let relation_selector = relation_selector(operation)?;
    let input_selector = if !is_root && relation_selector.is_none() {
        let input = integration
            .input
            .first_key_value()
            .map(|(input, _)| input.as_str())
            .ok_or_else(|| anyhow!("integration input is absent"))?;
        selector_location(operation, input).transpose()?
    } else {
        None
    };
    let query = operation
        .request
        .query
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let headers = operation
        .request
        .headers
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let path_parameters = operation
        .request
        .path_parameters
        .iter()
        .map(|(name, source)| Ok((name.clone(), relay_value_expression(source)?)))
        .collect::<Result<Map<String, Value>>>()?;
    let body = if is_dci {
        None
    } else {
        operation
            .request
            .body
            .as_ref()
            .map(relay_body_template)
            .transpose()?
    };
    let mut document = json!({
        "id": operation_id,
        "method": match operation.request.method { ReadMethod::Get => "GET", ReadMethod::Post => "READ_ONLY_POST" },
        "destination_slot": match operation.request.destination.as_str() {
            "data" => format!("{alias}-data"),
            "credential" => format!("{alias}-credential"),
            _ => bail!("operation destination must be data or credential"),
        },
        "path": operation.request.path,
        "query": query,
        "headers": headers,
        "body": body,
        "relation_selector": relation_selector,
        "input_selector": input_selector,
        "request_codec": request_codec,
        "request_signer": request_signer,
        "step_limits": {
            "max_request_bytes": integration.bounds.request_bytes,
            "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
            "max_in_flight": 1,
        },
        "auth": relay_source_auth(credential_interface(integration)),
        "acquisition_fields": acquisition_fields,
        "control_fields": controls,
        "projection": { "mechanism": "bounded_full_record" },
        "response": response,
    });
    if is_dci {
        document["dci"] = generated_dci_document(operation)?;
    }
    if is_fhir {
        let resource_type = operation
            .request
            .path
            .rsplit('/')
            .next()
            .filter(|resource| !resource.is_empty())
            .ok_or_else(|| anyhow!("FHIR operation path must end with its resource type"))?;
        document["fhir"] = json!({ "resource_type": resource_type });
    }
    if !path_parameters.is_empty() {
        document["path_parameters"] = Value::Object(path_parameters);
    }
    Ok(document)
}

fn prior_output_document(schema: &SchemaNode, pointer: &str) -> Result<Value> {
    let value = match schema {
        SchemaNode::String { max_bytes } => json!({
            "pointer": pointer,
            "type": "string",
            "nullable": false,
            "max_bytes": u16::try_from(*max_bytes).context("prior string output is too large")?,
        }),
        SchemaNode::Integer { min, max } => json!({
            "pointer": pointer,
            "type": "integer",
            "nullable": false,
            "minimum": min,
            "maximum": max,
        }),
        SchemaNode::Boolean => json!({
            "pointer": pointer,
            "type": "boolean",
            "nullable": false,
        }),
        SchemaNode::Date => json!({
            "pointer": pointer,
            "type": "date",
            "nullable": false,
            "max_bytes": 10,
        }),
        SchemaNode::Object { .. } | SchemaNode::Array { .. } => {
            bail!("prior step outputs must be bounded string, integer, or Boolean scalars")
        }
    };
    Ok(value)
}

fn static_json_pointer(path: &str) -> Value {
    Value::String(format!(
        "/{}",
        path.split('.')
            .map(|token| token.replace('~', "~0").replace('/', "~1"))
            .collect::<Vec<_>>()
            .join("/")
    ))
}

fn relay_value_expression(source: &ValueSource) -> Result<Value> {
    Ok(match source {
        ValueSource::Input { input } => {
            json!({ "source": "consultation_input", "name": input })
        }
        ValueSource::Value { value } => {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                Value::Null | Value::Array(_) | Value::Object(_) => {
                    bail!("query, header, and path literals must be bounded scalars")
                }
            };
            json!({ "source": "literal", "value": value })
        }
        ValueSource::Prior { prior: output } => {
            let (step, output) = split_prior_output(output)?;
            json!({ "source": "prior_step_output", "step": step, "output": output })
        }
    })
}

fn split_prior_output(value: &str) -> Result<(&str, &str)> {
    let (step, path) = value
        .split_once('.')
        .ok_or_else(|| anyhow!("prior output path is invalid"))?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    let output = path
        .split('.')
        .next()
        .ok_or_else(|| anyhow!("prior output path is empty"))?;
    Ok((step, output))
}

fn relay_body_template(value: &Value) -> Result<Value> {
    match value {
        Value::Null => Ok(json!({ "kind": "null" })),
        Value::Bool(value) => Ok(json!({ "kind": "boolean", "value": value })),
        Value::Number(value) => value
            .as_i64()
            .map(|value| json!({ "kind": "integer", "value": value }))
            .ok_or_else(|| anyhow!("request body numbers must be exact integers")),
        Value::String(value) => Ok(json!({ "kind": "string_literal", "value": value })),
        Value::Array(values) => Ok(json!({
            "kind": "array",
            "items": values.iter().map(relay_body_template).collect::<Result<Vec<_>>>()?,
        })),
        Value::Object(object) if object.len() == 1 && object.contains_key("input") => {
            let input = object["input"]
                .as_str()
                .ok_or_else(|| anyhow!("request input expression is invalid"))?;
            Ok(json!({
                "kind": "expression",
                "value": { "source": "consultation_input", "name": input },
            }))
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("prior") => {
            let prior = object["prior"]
                .as_str()
                .ok_or_else(|| anyhow!("request prior expression is invalid"))?;
            let (step, output) = split_prior_output(prior)?;
            Ok(json!({
                "kind": "expression",
                "value": { "source": "prior_step_output", "step": step, "output": output },
            }))
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("value") => {
            relay_body_template(&object["value"])
        }
        Value::Object(object) => Ok(json!({
            "kind": "object",
            "fields": object.iter().map(|(name, value)| Ok((name.clone(), relay_body_template(value)?))).collect::<Result<Map<String, Value>>>()?,
        })),
    }
}

fn generated_cardinality(
    operation: &OperationDeclaration,
    evidence: &[GeneratedEvidence],
) -> Result<Value> {
    let conformance = evidence
        .iter()
        .find(|artifact| artifact.class == EvidenceClass::Conformance)
        .map(|artifact| artifact.sha256.as_str())
        .ok_or_else(|| anyhow!("conformance evidence is absent"))?;
    match operation.response.cardinality.as_ref() {
        Some(CardinalityDeclaration {
            mode: CardinalityMode::ProbeTwo,
            ..
        }) => {
            if let Some(parameter) = operation.request.query.iter().find_map(|(name, source)| {
                matches!(source, ValueSource::Value { value }
                    if value.as_u64() == Some(2) || value.as_str() == Some("2"))
                .then_some(name)
            }) {
                return Ok(json!({
                    "mechanism": "probe_query_parameter",
                    "parameter": parameter,
                }));
            }
            if let Some(body) = &operation.request.body {
                if let Some(pointer) = find_body_literal_pointer(body, 2, "") {
                    return Ok(json!({
                        "mechanism": "probe_body_integer",
                        "pointer": pointer,
                    }));
                }
            }
            bail!("probe-two operation must carry a fixed reviewed limit of two")
        }
        Some(CardinalityDeclaration {
            mode: CardinalityMode::Singleton,
            ..
        })
        | None => Ok(json!({
            "mechanism": "source_enforced_singleton",
            "conformance_evidence": conformance,
        })),
    }
}

fn find_body_literal_pointer(value: &Value, expected: i64, pointer: &str) -> Option<String> {
    match value {
        Value::Object(object)
            if object.len() == 1
                && object
                    .get("value")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value == expected) =>
        {
            Some(pointer.to_string())
        }
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_literal_pointer(
                value,
                expected,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_literal_pointer(value, expected, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn exact_selector(
    inputs: &BTreeMap<String, InputDeclaration>,
    operation_id: &str,
    operation: &OperationDeclaration,
) -> Result<Value> {
    let components = inputs
        .keys()
        .map(|input| {
            let location = if operation.primitive.as_deref() == Some("dci_search_v1")
                && operation.request.body.as_ref().is_some_and(|body| {
                    body.get("exact_and")
                        .and_then(Value::as_object)
                        .is_some_and(|components| components.contains_key(input))
                }) {
                json!({ "type": "codec", "role": "dci_exact_predicate" })
            } else {
                selector_location(operation, input)
                    .transpose()?
                    .ok_or_else(|| {
                        anyhow!("root operation must bind every exact consultation input")
                    })?
            };
            Ok((input.clone(), location))
        })
        .collect::<Result<Map<String, Value>>>()?;
    Ok(json!({
        "type": "http_exact_and",
        "operation": operation_id,
        "components": components,
    }))
}

fn selector_location(operation: &OperationDeclaration, input: &str) -> Option<Result<Value>> {
    if let Some(parameter) = operation.request.query.iter().find_map(|(name, source)| {
        matches!(source, ValueSource::Input { input: candidate } if candidate == input)
            .then_some(name)
    }) {
        return Some(Ok(json!({ "type": "query", "parameter": parameter })));
    }
    if let Some(parameter) = operation
        .request
        .path_parameters
        .iter()
        .find_map(|(name, source)| {
            matches!(source, ValueSource::Input { input: candidate } if candidate == input)
                .then_some(name)
        })
    {
        return Some(Ok(json!({ "type": "path", "parameter": parameter })));
    }
    operation.request.body.as_ref().and_then(|body| {
        find_body_input_pointer(body, input, "")
            .map(|pointer| Ok(json!({ "type": "body", "pointer": pointer })))
    })
}

fn find_body_input_pointer(value: &Value, input: &str, pointer: &str) -> Option<String> {
    match value {
        Value::Object(object)
            if object.len() == 1 && object.get("input").and_then(Value::as_str) == Some(input) =>
        {
            Some(pointer.to_string())
        }
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_input_pointer(
                value,
                input,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_input_pointer(value, input, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn relation_selector(operation: &OperationDeclaration) -> Result<Option<Value>> {
    for (parameter, source) in &operation.request.query {
        if let ValueSource::Prior { prior: output } = source {
            let (step, output) = split_prior_output(output)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "query", "parameter": parameter },
            })));
        }
    }
    for (parameter, source) in &operation.request.path_parameters {
        if let ValueSource::Prior { prior: output } = source {
            let (step, output) = split_prior_output(output)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "path", "parameter": parameter },
            })));
        }
    }
    if let Some(body) = &operation.request.body {
        if let Some((pointer, prior)) = find_body_prior_pointer(body, "") {
            let (step, output) = split_prior_output(prior)?;
            return Ok(Some(json!({
                "step": step,
                "output": output,
                "location": { "type": "body", "pointer": pointer },
            })));
        }
    }
    Ok(None)
}

fn find_body_prior_pointer<'a>(value: &'a Value, pointer: &str) -> Option<(String, &'a str)> {
    match value {
        Value::Object(object) if object.len() == 1 => object
            .get("prior")
            .and_then(Value::as_str)
            .map(|prior| (pointer.to_string(), prior)),
        Value::Object(object) => object.iter().find_map(|(name, value)| {
            find_body_prior_pointer(
                value,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
            )
        }),
        Value::Array(values) => values.iter().enumerate().find_map(|(index, value)| {
            find_body_prior_pointer(value, &format!("{pointer}/{index}"))
        }),
        _ => None,
    }
}

fn generated_step_conditions(integration: &IntegrationDocument) -> Result<Map<String, Value>> {
    integration_operations(integration)
        .iter()
        .filter_map(|(operation_id, operation)| {
            operation.when.as_ref().map(|condition| {
                let (step, path) = condition
                    .prior
                    .split_once('.')
                    .ok_or_else(|| anyhow!("step condition path is invalid"))?;
                let condition = if path == "presence" {
                    let output = integration
                        .facts
                        .iter()
                        .find_map(|(name, fact)| {
                            (fact.from == format!("{step}.presence")).then_some(name)
                        })
                        .ok_or_else(|| anyhow!("presence condition requires a declared presence fact"))?;
                    json!({ "predicate": "exists", "step": step, "output": output })
                } else {
                    let output = path.strip_prefix("record.").unwrap_or(path);
                    let output = output.split('.').next().unwrap_or(output);
                    match &condition.equals {
                        Value::String(value) => json!({ "predicate": "string_equals", "step": step, "output": output, "value": value }),
                        Value::Bool(value) => json!({ "predicate": "boolean_equals", "step": step, "output": output, "value": value }),
                        Value::Number(value) if value.as_i64().is_some() => json!({ "predicate": "integer_equals", "step": step, "output": output, "value": value }),
                        _ => bail!("step condition value must be a bounded scalar"),
                    }
                };
                Ok((operation_id.clone(), condition))
            })
        })
        .collect()
}

fn relay_source_auth(interface: &CredentialInterface) -> Value {
    match interface.credential_type {
        CredentialType::None => json!({ "mode": "none" }),
        CredentialType::Basic => json!({ "mode": "basic", "max_value_bytes": 1024 }),
        CredentialType::StaticBearer => {
            json!({ "mode": "static_bearer", "max_value_bytes": 1024 })
        }
        CredentialType::Oauth2ClientCredentials => {
            json!({ "mode": "oauth_client_credentials" })
        }
        CredentialType::ApiKeyHeader => json!({
            "mode": "api_key_header",
            "name": interface.name.as_deref().unwrap_or_default(),
            "max_value_bytes": interface.max_value_bytes.unwrap_or_default(),
        }),
        CredentialType::ApiKeyQuery => json!({
            "mode": "api_key_query",
            "name": interface.name.as_deref().unwrap_or_default(),
            "max_value_bytes": interface.max_value_bytes.unwrap_or_default(),
        }),
    }
}

fn generated_credential_operation(
    alias: &str,
    integration: &IntegrationDocument,
) -> Result<Option<Value>> {
    let operation = integration_operations(integration)
        .iter()
        .find(|(_, operation)| operation.role == OperationRole::Credential);
    let Some((id, operation)) = operation else {
        return Ok(None);
    };
    if operation.primitive.as_deref() != Some("oauth2_client_credentials") {
        bail!("unsupported credential operation primitive");
    }
    let SchemaNode::Object { fields, .. } = &operation.response.schema else {
        bail!("OAuth response schema must be a closed object");
    };
    let access_token_max_bytes = match fields.get("access_token").map(|field| &field.schema) {
        Some(SchemaNode::String { max_bytes }) => *max_bytes,
        _ => bail!("OAuth response schema must bound access_token"),
    };
    Ok(Some(json!({
        "id": id,
        "kind": "oauth2_client_credentials",
        "destination_slot": format!("{alias}-credential"),
        "path": operation.request.path,
        "request": {
            "format": "json_client_secret_body",
            "max_client_id_bytes": 256,
            "max_client_secret_bytes": 512,
            "max_body_bytes": integration.bounds.request_bytes.min(8192),
            "max_request_bytes": integration.bounds.request_bytes,
            "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
        },
        "response": {
            "max_bytes": operation.response.max_bytes,
            "accepted_statuses": operation.response.statuses,
            "schema": "strict_access_token_bearer_no_expiry",
            "access_token_max_bytes": access_token_max_bytes,
            "token_type": "Bearer",
            "cache_mode": "disabled",
        },
        "failure_policy": "fail_closed_source_unavailable_no_retry_no_stale_no_data_dispatch",
    })))
}

fn generated_verification_operations(
    alias: &str,
    integration: &IntegrationDocument,
) -> Result<Vec<Value>> {
    integration_operations(integration)
        .iter()
        .filter(|(_, operation)| operation.role == OperationRole::Verification)
        .map(|(id, operation)| {
            if operation.primitive.as_deref() != Some("jwks_json_v1")
                || operation.request.method != ReadMethod::Get
                || operation.response.statuses != [200]
            {
                bail!("verification operation must use the closed JWKS GET primitive");
            }
            Ok(json!({
                "id": id,
                "primitive": "jwks_v1",
                "destination_slot": format!("{alias}-data"),
                "method": "GET",
                "path": operation.request.path,
                "step_limits": {
                    "max_request_bytes": integration.bounds.request_bytes,
                    "timeout_ms": parse_duration_ms(&integration.bounds.deadline)?.min(10_000),
                    "max_in_flight": 1,
                },
                "max_response_bytes": operation.response.max_bytes,
                "accepted_statuses": operation.response.statuses,
            }))
        })
        .collect()
}

fn generated_dci_document(operation: &OperationDeclaration) -> Result<Value> {
    let body = operation
        .request
        .body
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI authored parameters must be one fixed body object"))?;
    let literal_string = |name: &str| -> Result<String> {
        body.get(name)
            .and_then(Value::as_object)
            .and_then(|value| value.get("value"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("DCI authored parameter {name} must be one fixed string"))
    };
    let page_number = body
        .get("page_number")
        .and_then(Value::as_object)
        .and_then(|value| value.get("value"))
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("DCI page_number must be one fixed positive integer"))?;
    if page_number == 0 || page_number > u64::from(u16::MAX) {
        bail!("DCI page_number is outside its fixed bound");
    }
    let verification = operation
        .verification
        .as_ref()
        .ok_or_else(|| anyhow!("DCI verification binding is absent"))?;
    let jwks_operation = verification
        .jwks
        .split_once('.')
        .map(|(operation, _)| operation)
        .ok_or_else(|| anyhow!("DCI JWKS binding is invalid"))?;
    let exact_and = body
        .get("exact_and")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI exact selector map is absent"))?;
    let mut document = json!({
        "protocol_version": literal_string("protocol_version")?,
        "sender_id": literal_string("sender")?,
        "receiver_id": literal_string("receiver")?,
        "registry_type": literal_string("registry_type")?,
        "registry_event_type": literal_string("registry_event_type")?,
        "record_type": literal_string("record_type")?,
        "exact_and": exact_and,
        "locale": literal_string("locale")?,
        "page_number": page_number,
        "jwks_operation": jwks_operation,
        "response_verifier": verification.primitive,
    });
    if body.contains_key("identifier_type") {
        document["identifier_type"] = Value::String(literal_string("identifier_type")?);
    }
    Ok(document)
}

fn generated_rhai_template(_alias: &str, integration: &LoadedIntegration) -> Result<Option<Value>> {
    let CapabilityDeclaration::SandboxedRhai { .. } = integration.document.capability else {
        return Ok(None);
    };
    let (_, script) = integration
        .script
        .as_ref()
        .ok_or_else(|| anyhow!("sandboxed Rhai script is absent"))?;
    let source = std::str::from_utf8(script).context("sandboxed Rhai script is not UTF-8")?;
    Ok(Some(json!({
        "script": source,
        "script_hash": sha256_uri(script),
        "entrypoint": "consult",
        "memory_bytes": 64 * 1024 * 1024,
        "cpu_ms": 250,
        "ipc_frame_bytes": 256 * 1024,
        "instructions": 100_000,
        "call_depth": 16,
        "string_bytes": 64 * 1024,
        "array_items": 1024,
        "map_entries": 1024,
        "output_bytes": 64 * 1024,
        "concurrency": 1,
    })))
}

fn generated_profile_identity(
    loaded: &LoadedCountryProject,
    service_id: &str,
    consultation_name: &str,
    pack: &GeneratedPack,
) -> Result<(String, String)> {
    let id = bounded_join_id(&[
        loaded.project.registry.id.as_str(),
        service_id,
        consultation_name,
    ])?;
    let service = &loaded.project.services[service_id];
    let version = numeric_artifact_version(&digest_json(&json!({
        "service": service,
        "consultation": consultation_name,
        "pack_hash": pack.artifact.typed_hash(),
    }))?)?;
    Ok((id, version))
}

fn consultation_contract_document(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    service: (&str, &ServiceDeclaration),
    consultation: (&str, &ConsultationDeclaration),
    pack: &GeneratedPack,
    profile: (&str, &str),
) -> Result<Value> {
    let (service_id, service) = service;
    let (consultation_name, consultation) = consultation;
    let (profile_id, profile_version) = profile;
    let pack_value = parse_json_strict(pack.artifact.canonical_json())
        .context("generated integration pack is not strict JSON")?;
    let pack_spec = pack_value
        .get("spec")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("generated integration pack spec is absent"))?;
    let input = pack_spec
        .get("input_slots")
        .cloned()
        .ok_or_else(|| anyhow!("generated integration pack input is absent"))?;
    let bounds = pack_spec
        .get("bounds")
        .cloned()
        .ok_or_else(|| anyhow!("generated integration pack bounds are absent"))?;
    let max_matches = bounds
        .get("max_source_matches")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("generated integration pack cardinality is absent"))?;
    let policy_id = bounded_join_id(&["relay", service_id, consultation_name])?;
    let mut specification = json!({
        "subject": {
            "mode": "single_subject",
            "selector_provenance": { "type": "workload_selected" },
        },
        "inputs": input,
        "integration_pack": {
            "id": pack.id,
            "version": pack.version,
            "hash": pack.artifact.typed_hash(),
        },
        "acquisition": pack_spec.get("acquisition"),
        "source_provenance": pack_spec.get("source_provenance"),
        "output": pack_spec.get("output"),
        "authorization": {
            "workload": environment.relay_trust.notary_client_id,
            "required_scope": bounded_scope(&["registry", "consult", service_id])?,
            "purposes": [service.purpose.as_str()],
            "legal_basis": service.legal_basis,
            "policy": {
                "id": policy_id,
                "hash": format!("sha256:{}", "0".repeat(64)),
                "decision_cache": "disabled",
                "max_decision_age_ms": 1000,
                "unavailable": "deny",
            },
            "consent": { "required": false },
            "mandatory_obligations": [],
        },
        "bounds": bounds,
        "public_behavior": {
            "outcomes": if max_matches == 2 { vec!["match", "no_match", "ambiguous"] } else { vec!["match", "no_match"] },
            "denial_code": "consultation.denied",
            "denial_timing_profile": "measured-uniform-v1",
        },
    });
    let integration = loaded
        .integrations
        .get(&consultation.integration)
        .ok_or_else(|| anyhow!("consultation integration is absent"))?;
    let (_, _, _, _, _, materialization) =
        generated_pack_semantics(&consultation.integration, integration, &pack.evidence)?;
    if let Some(materialization) = materialization {
        specification["materialization"] = materialization;
    }
    Ok(json!({
        "schema": "registry.relay.consultation-contract.v1",
        "id": profile_id,
        "version": profile_version,
        "spec": specification,
    }))
}

fn private_binding_document(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    consultation: &ConsultationDeclaration,
    pack: &GeneratedPack,
    profile_id: &str,
    profile_version: &str,
) -> Result<Value> {
    let integration = &loaded.integrations[&consultation.integration];
    let binding = &environment.integrations[&consultation.integration];
    let data_destination = binding.data_destination.as_ref().map(|destination| {
        json!({
            "id": format!("{}-data", consultation.integration),
            "origin": destination.origin,
            "allowed_private_cidrs": [],
        })
    });
    let credential_destination = binding.credential_destination.as_ref().map(|destination| {
        json!({
            "id": format!("{}-credential", consultation.integration),
            "origin": destination.origin,
            "allowed_private_cidrs": [],
        })
    });
    let credential = binding.credential.as_ref().map(|credential| {
        json!({
            "ref": format!("{}-credential", consultation.integration),
            "generation": credential.generation,
        })
    });
    let allow_rhai = matches!(
        integration.document.capability,
        CapabilityDeclaration::SandboxedRhai { .. }
    );
    let rhai = allow_rhai.then(|| {
        json!({
            "callable_operations": integration_operations(&integration.document).keys().collect::<Vec<_>>(),
            "max_calls": integration.document.bounds.calls,
            "memory_bytes": 64 * 1024 * 1024,
            "cpu_ms": 250,
            "ipc_frame_bytes": 256 * 1024,
            "instructions": 100_000,
            "call_depth": 16,
            "string_bytes": 64 * 1024,
            "array_items": 1024,
            "map_entries": 1024,
            "output_bytes": 64 * 1024,
            "concurrency": 1,
            "isolation": "one_shot_worker_v1",
        })
    });
    let materialization =
        match &integration.document.capability {
            CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
                let records = &loaded
                    .records
                    .get(&snapshot_exact.entity)
                    .ok_or_else(|| anyhow!("snapshot records definition is absent"))?
                    .document;
                let entity = environment
                    .entities
                    .get(&snapshot_exact.entity)
                    .ok_or_else(|| anyhow!("snapshot environment entity is absent"))?;
                let keys = integration
                    .document
                    .input
                    .keys()
                    .map(|input| {
                        let physical = entity.columns.get(input).ok_or_else(|| {
                            anyhow!("snapshot input has no private physical mapping")
                        })?;
                        Ok((
                            input.clone(),
                            json!({
                                "input": input,
                                "physical_field": physical,
                                "physical_type": "utf8",
                                "comparison": "binary_equality",
                            }),
                        ))
                    })
                    .collect::<Result<Map<String, Value>>>()?;
                let projection = integration
                    .document
                    .facts
                    .values()
                    .filter_map(|fact| {
                        let (_, path) = fact.from.split_once('.')?;
                        let field = path.strip_prefix("record.").unwrap_or(path);
                        (field != "presence").then_some(field)
                    })
                    .map(|field| {
                        let physical = entity
                            .columns
                            .get(field)
                            .ok_or_else(|| anyhow!("environment entity omits a logical field"))?;
                        Ok((field.to_string(), Value::String(physical.clone())))
                    })
                    .collect::<Result<Map<String, Value>>>()?;
                Some(json!({
                    "table_provider": records_table_provider(records, entity)?,
                    "mapping": {
                        "keys": keys,
                        "projection": projection,
                    },
                }))
            }
            CapabilityDeclaration::BoundedHttp { .. }
            | CapabilityDeclaration::SandboxedRhai { .. } => None,
        };
    let source_instance = match &integration.document.capability {
        CapabilityDeclaration::SnapshotExact { snapshot_exact } => {
            let records = &loaded.records[&snapshot_exact.entity].document;
            let entity = &environment.entities[&snapshot_exact.entity];
            records_materialization_resource_id(records, entity)?
        }
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SandboxedRhai { .. } => {
            format!("{}-source", consultation.integration)
        }
    };
    Ok(json!({
        "profile": { "id": profile_id, "version": profile_version },
        "integration_pack": {
            "id": pack.id,
            "version": pack.version,
            "hash": pack.artifact.typed_hash(),
        },
        "tenant": loaded.project.registry.id,
        "registry_instance": loaded.project.registry.id,
        "source_instance": source_instance,
        "data_destination": data_destination,
        "credential_destination": credential_destination,
        "credential": credential,
        "deployment_parameters": {},
        "limits": {
            "max_source_bytes": integration.document.bounds.source_bytes,
            "timeout_ms": parse_duration_ms(&integration.document.bounds.deadline)?,
            "max_in_flight": integration.document.bounds.concurrency,
            "quota_per_minute": 60,
            "quota_burst": integration.document.bounds.concurrency.min(60),
            "max_public_response_bytes": 64 * 1024,
        },
        "capabilities": {
            "allow_sandboxed_rhai": allow_rhai,
            "sandboxed_rhai": rhai,
        },
        "materialization": materialization,
    }))
}

fn generated_relay_config(
    loaded: &LoadedCountryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    packs: &BTreeMap<String, GeneratedPack>,
    profiles: &[GeneratedProfile],
) -> Result<Value> {
    let public_contracts = profiles
        .iter()
        .map(|profile| {
            json!({
                "path": format!("artifacts/consultation-contracts/{}-{}.json", profile.service_id, profile.consultation_name),
                "hash": profile.contract.artifact().typed_hash(),
                "sha256": profile.contract.artifact().raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let integration_packs = packs
        .values()
        .map(|pack| {
            json!({
                "path": format!("artifacts/integration-packs/{}.json", pack.alias),
                "hash": pack.artifact.typed_hash(),
                "sha256": pack.artifact.raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let private_bindings = profiles
        .iter()
        .map(|profile| {
            json!({
                "path": format!("artifacts/private-bindings/{}-{}.json", profile.service_id, profile.consultation_name),
                "hash": profile.binding.typed_hash(),
                "sha256": profile.binding.raw_sha256(),
            })
        })
        .collect::<Vec<_>>();
    let evidence = packs
        .values()
        .flat_map(|pack| &pack.evidence)
        .map(|artifact| {
            json!({
                "class": match artifact.class {
                    EvidenceClass::Conformance => "conformance",
                    EvidenceClass::NegativeSecurity => "negative_security",
                    EvidenceClass::Minimization => "minimization",
                },
                "path": artifact.path,
                "sha256": artifact.sha256,
            })
        })
        .collect::<Vec<_>>();
    let rhai_scripts = loaded
        .integrations
        .iter()
        .filter_map(|(alias, integration)| {
            integration.script.as_ref().map(|(_, script)| {
                json!({
                    "path": format!("artifacts/rhai/{alias}.rhai"),
                    "sha256": sha256_uri(script),
                })
            })
        })
        .collect::<Vec<_>>();
    let source_credentials = environment
        .integrations
        .iter()
        .filter(|(_, binding)| binding.credential.is_some())
        .map(|(alias, binding)| {
            let credential = binding
                .credential
                .as_ref()
                .ok_or_else(|| anyhow!("credential binding disappeared"))?;
            let reference = format!("{alias}-credential");
            match credential.credential_type {
                CredentialType::None => bail!("none credential must not have an environment binding"),
                CredentialType::Basic => Ok(json!({
                    "type": "basic",
                    "ref": reference,
                    "generation": credential.generation,
                    "username_env": required_secret_name(credential.username.as_ref(), "basic username")?,
                    "password_env": required_secret_name(credential.password.as_ref(), "basic password")?,
                })),
                CredentialType::StaticBearer => Ok(json!({
                    "type": "static_bearer",
                    "ref": reference,
                    "generation": credential.generation,
                    "token_env": required_secret_name(credential.token.as_ref(), "bearer token")?,
                })),
                CredentialType::Oauth2ClientCredentials => Ok(json!({
                    "type": "oauth_client_credentials",
                    "ref": reference,
                    "generation": credential.generation,
                    "client_id_env": required_secret_name(credential.client_id.as_ref(), "OAuth client id")?,
                    "client_secret_env": required_secret_name(credential.client_secret.as_ref(), "OAuth client secret")?,
                })),
                CredentialType::ApiKeyHeader => Ok(json!({
                    "type": "api_key_header",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                })),
                CredentialType::ApiKeyQuery => Ok(json!({
                    "type": "api_key_query",
                    "ref": reference,
                    "generation": credential.generation,
                    "value_env": required_secret_name(credential.value.as_ref(), "API-key value")?,
                })),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let datasets = generated_records_datasets(loaded, environment)?;
    let standards = generated_records_standards(loaded)?;
    Ok(json!({
        "instance": {
            "id": environment.deployment.relay.service,
            "environment": environment_name,
        },
        "server": { "bind": "127.0.0.1:8080" },
        "catalog": {
            "title": format!("{} governed consultation Relay", loaded.project.registry.id),
            "base_url": environment.relay_trust.origin,
            "publisher": loaded.project.registry.id,
        },
        "auth": {
            "mode": "oidc",
            "oidc": {
                "issuer": environment.relay_trust.issuer,
                "audiences": [environment.relay_trust.audience.as_str()],
                "jwks_url": environment.relay_trust.jwks_url,
                "allowed_clients": [environment.relay_trust.notary_client_id.as_str()],
            },
        },
        "audit": {
            "sink": "stdout",
            "hash_secret_env": "REGISTRY_RELAY_AUDIT_HASH_SECRET",
        },
        "consultation": {
            "notary_workload": {
                "audience": environment.relay_trust.audience,
                "client_claim_selector": "azp",
                "client_value": environment.relay_trust.notary_client_id,
                "principal_id": environment.relay_trust.notary_client_id,
            },
            "state_plane": {
                "database_url_env": "REGISTRY_RELAY_CONSULTATION_DATABASE_URL",
                "chain_key_epoch_id": "country-consultation-chain-1",
                "serving_fence_lock_key": deterministic_lock_key(&loaded.project.registry.id, 0),
                "audit_pseudonym_keyring_lock_key": deterministic_lock_key(&loaded.project.registry.id, 1),
            },
            "audit_pseudonym_materials": [{
                "key_id": "epoch-1",
                "source": { "provider": "environment", "name": "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1" },
            }],
            "source_credentials": source_credentials,
            "artifacts": {
                "public_contracts": public_contracts,
                "integration_packs": integration_packs,
                "private_bindings": private_bindings,
                "evidence": evidence,
                "rhai_scripts": rhai_scripts,
            },
        },
        "datasets": datasets,
        "standards": standards,
        "deployment": { "profile": environment.deployment.profile.as_str() },
    }))
}

fn generated_records_datasets(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
) -> Result<Vec<Value>> {
    loaded
        .records
        .values()
        .map(|loaded_records| {
            let records = &loaded_records.document;
            let binding = environment
                .entities
                .get(&records.id)
                .ok_or_else(|| anyhow!("generated records entity binding is absent"))?;
            let resource_id = records_materialization_resource_id(records, binding)?;
            let source = match &binding.provider {
                RecordProvider::Csv {
                    path,
                    header_row,
                    delimiter,
                    quote,
                } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "csv": {
                        "header_row": header_row,
                        "delimiter": delimiter,
                        "quote": quote,
                    }},
                }),
                RecordProvider::Xlsx {
                    path,
                    sheet,
                    header_row,
                    data_range,
                } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "xlsx": {
                        "sheet": sheet,
                        "header_row": header_row,
                        "data_range": data_range,
                    }},
                }),
                RecordProvider::Parquet { path } => json!({
                    "type": "file",
                    "path": path,
                    "format": { "parquet": {} },
                }),
            };
            let fields = records
                .fields
                .iter()
                .map(|(logical, field)| {
                    json!({
                        "name": binding.columns[logical],
                        "type": field.field_type,
                        "nullable": field.nullable,
                        "sensitive": field.sensitive,
                        "concept_uri": field.concept_uri,
                        "codelist": field.codelist,
                        "unit": field.unit,
                        "language": field.language,
                    })
                })
                .collect::<Vec<_>>();
            let public_fields = records
                .fields
                .iter()
                .map(|(logical, field)| {
                    json!({
                        "name": logical,
                        "from": binding.columns[logical],
                        "sensitive": field.sensitive,
                        "concept_uri": field.concept_uri,
                        "codelist": field.codelist,
                        "unit": field.unit,
                        "language": field.language,
                    })
                })
                .collect::<Vec<_>>();
            let allowed_filters = records
                .api
                .filters
                .iter()
                .map(|(field, ops)| json!({ "field": field, "ops": ops }))
                .collect::<Vec<_>>();
            let required_filter_bindings = records
                .api
                .required_principal_filters
                .iter()
                .map(|field| json!({ "field": field, "source": "principal_id" }))
                .collect::<Vec<_>>();
            let relationships = records
                .api
                .relationships
                .iter()
                .map(|(name, relationship)| {
                    json!({
                        "name": name,
                        "kind": relationship.kind,
                        "target": relationship.target,
                        "foreign_key": binding.columns[&relationship.foreign_key],
                        "concept_uri": relationship.concept_uri,
                    })
                })
                .collect::<Vec<_>>();
            let aggregates = records
                .api
                .aggregates
                .iter()
                .map(|(id, aggregate)| {
                    let allowed_filters = aggregate
                        .allowed_filters
                        .iter()
                        .map(|(field, ops)| json!({ "field": field, "ops": ops }))
                        .collect::<Vec<_>>();
                    let required_filter_bindings = aggregate
                        .required_principal_filters
                        .iter()
                        .map(|field| json!({ "field": field, "source": "principal_id" }))
                        .collect::<Vec<_>>();
                    json!({
                        "id": id,
                        "title": aggregate.title,
                        "description": aggregate.description,
                        "source_entity": records.id,
                        "default_group_by": aggregate.default_group_by,
                        "dimensions": aggregate.dimensions,
                        "indicators": aggregate.indicators,
                        "allowed_filters": allowed_filters,
                        "required_filters": aggregate.required_principal_filters,
                        "required_filter_bindings": required_filter_bindings,
                        "temporal_field": aggregate.temporal_field,
                        "access": aggregate.access,
                        "spatial": aggregate.spatial,
                        "joins": aggregate.joins.iter().map(|relationship| json!({ "relationship": relationship })).collect::<Vec<_>>(),
                        "group_by": aggregate.group_by,
                        "measures": aggregate.measures,
                        "disclosure_control": {
                            "min_group_size": aggregate.disclosure_control.min_group_size,
                            "suppression": aggregate.disclosure_control.suppression,
                        },
                    })
                })
                .collect::<Vec<_>>();
            let aggregate_scope = records
                .api
                .scopes
                .aggregate
                .clone()
                .unwrap_or_else(|| format!("{}:aggregate", records.id));
            let governed_policy = (!records.api.purposes.is_empty()).then(|| {
                json!({
                    "permitted_purposes": records.api.purposes,
                    "permitted_jurisdictions": [],
                    "allowed_assurance": [],
                    "require_legal_basis": false,
                    "require_consent": false,
                    "redaction_fields": [],
                    "trusted_context": {},
                })
            });
            let spatial = match &records.api.standards.ogc_features {
                RecordStandard::Enabled(spatial) => Some(serde_json::to_value(spatial)?),
                RecordStandard::Disabled(_) => None,
            };
            Ok(json!({
                "id": records.id,
                "title": records.title.clone().unwrap_or_else(|| records.id.clone()),
                "description": records.description.clone().unwrap_or_else(|| format!("Governed {} records", records.id)),
                "owner": records.owner.clone().unwrap_or_else(|| loaded.project.registry.id.clone()),
                "sensitivity": records.sensitivity.unwrap_or(RecordSensitivity::Personal),
                "access_rights": records.access_rights.unwrap_or(RecordAccessRights::Restricted),
                "update_frequency": records.update_frequency.unwrap_or(RecordUpdateFrequency::AsNeeded),
                "conforms_to": records.conforms_to,
                "defaults": { "refresh": { "mode": "manual" }, "materialization": "snapshot" },
                "tables": [{
                    "id": resource_id,
                    "source": source,
                    "refresh": { "mode": "manual" },
                    "materialization": "snapshot",
                    "primary_key": binding.columns[&records.primary_key],
                    "schema": { "strict": true, "fields": fields },
                    "access": {
                        "metadata_scope": records.api.scopes.metadata,
                        "aggregate_scope": aggregate_scope,
                    },
                    "api": {
                        "default_limit": records.api.pagination.default_limit,
                        "max_limit": records.api.pagination.max_limit,
                        "require_purpose_header": !records.api.purposes.is_empty(),
                        "allowed_filters": [],
                    },
                    "aggregates": [],
                }],
                "entities": [{
                    "name": records.id,
                    "title": records.title,
                    "description": records.description,
                    "table": resource_id,
                    "fields": public_fields,
                    "relationships": relationships,
                    "access": {
                        "metadata_scope": records.api.scopes.metadata,
                        "aggregate_scope": aggregate_scope,
                        "read_scope": records.api.scopes.rows,
                        "evidence_verification_scope": records.api.scopes.evidence_verification.clone().unwrap_or_default(),
                    },
                    "api": {
                        "default_limit": records.api.pagination.default_limit,
                        "max_limit": records.api.pagination.max_limit,
                        "require_purpose_header": !records.api.purposes.is_empty(),
                        "governed_policy": governed_policy,
                        "required_filters": records.api.required_principal_filters,
                        "required_filter_bindings": required_filter_bindings,
                        "allowed_filters": allowed_filters,
                        "allowed_expansions": records.api.relationships.keys().collect::<Vec<_>>(),
                    },
                    "aggregates": aggregates,
                    "spatial": spatial,
                }],
                "aggregates": [],
            }))
        })
        .collect()
}

fn generated_records_standards(loaded: &LoadedCountryProject) -> Result<Value> {
    let mut registries = Map::new();
    for records in loaded.records.values().map(|loaded| &loaded.document) {
        let RecordStandard::Enabled(spdci) = &records.api.standards.sp_dci else {
            continue;
        };
        if registries
            .insert(
                spdci.registry.clone(),
                json!({
                    "dataset": records.id,
                    "entity": records.id,
                    "registry_type": spdci.registry_type,
                    "record_type": spdci.record_type,
                    "identifiers": spdci.identifiers,
                    "expression_fields": spdci.expression_fields,
                    "response_fields": spdci.response_fields,
                }),
            )
            .is_some()
        {
            bail!("SP DCI registry ids must be unique across records definitions");
        }
    }
    Ok(if registries.is_empty() {
        json!({})
    } else {
        json!({ "spdci": { "registries": registries } })
    })
}

fn required_secret_name<'a>(
    reference: Option<&'a SecretReference>,
    label: &str,
) -> Result<&'a str> {
    reference
        .map(|reference| reference.secret.as_str())
        .ok_or_else(|| anyhow!("environment is missing the required {label} secret reference"))
}

fn deterministic_lock_key(registry: &str, lane: u8) -> i64 {
    let digest = Sha256::digest([registry.as_bytes(), &[lane]].concat());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(bytes) & i64::MAX
}

fn records_materialization_resource_id(
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    let digest = digest_json(&json!({
        "entity_definition": records,
        "provider": binding.provider,
        "columns": binding.columns,
        "source_revision": binding.source_revision,
        "generation": binding.generation,
    }))?;
    let hexadecimal = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("materialization identity digest is invalid"))?;
    Ok(format!("materialization_{hexadecimal}"))
}

fn records_table_provider(
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<String> {
    Ok(format!(
        "{}__{}",
        records.id,
        records_materialization_resource_id(records, binding)?
    ))
}

fn generated_entity_materialization_review(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
) -> Result<Map<String, Value>> {
    loaded
        .records
        .iter()
        .map(|(id, loaded_records)| {
            let binding = &environment.entities[id];
            let provider_digest = digest_json(&json!({
                "provider": binding.provider,
                "columns": binding.columns,
            }))?;
            Ok((
                id.clone(),
                json!({
                    "provider_digest": provider_digest,
                    "source_revision": binding.source_revision,
                    "generation": binding.generation,
                    "materialization_identity": records_materialization_resource_id(&loaded_records.document, binding)?,
                    "table_provider": records_table_provider(&loaded_records.document, binding)?,
                }),
            ))
        })
        .collect()
}

fn validate_entity_generation_changes(
    loaded: &LoadedCountryProject,
    environment: &EnvironmentDocument,
    baseline: Option<&VerifiedBaseline>,
) -> Result<()> {
    let Some(previous) = baseline
        .and_then(|baseline| baseline.review.get("entity_materializations"))
        .and_then(Value::as_object)
    else {
        return Ok(());
    };
    let current = generated_entity_materialization_review(loaded, environment)?;
    for (id, materialization) in &current {
        let Some(prior) = previous.get(id) else {
            continue;
        };
        if prior.get("provider_digest") != materialization.get("provider_digest")
            && prior.get("generation") == materialization.get("generation")
        {
            bail!("records provider or physical mapping changed without a new generation");
        }
    }
    Ok(())
}

fn generated_notary_config(
    loaded: &LoadedCountryProject,
    environment_name: &str,
    environment: &EnvironmentDocument,
    profiles: &[GeneratedProfile],
) -> Result<Value> {
    let mut variables = Map::new();
    let mut claims = Vec::new();
    let mut credential_profiles = Map::new();
    let mut allowed_purposes = BTreeSet::new();
    let mut seen_claims = BTreeSet::new();
    let mut max_validity_seconds = 600_u64;
    for (service_id, service) in &loaded.project.services {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        allowed_purposes.insert(service.purpose.clone());
        for (name, variable) in &service.variables {
            let declaration = json!({ "from": variable.from, "type": "date" });
            if variables
                .insert(name.clone(), declaration.clone())
                .is_some_and(|prior| prior != declaration)
            {
                bail!("request variable has conflicting service declarations");
            }
        }
        for (credential_id, credential) in &service.credentials {
            let profile_id = bounded_join_id(&[service_id, credential_id])?;
            let validity_seconds = parse_validity_seconds(&credential.validity)?;
            max_validity_seconds = max_validity_seconds.max(validity_seconds);
            credential_profiles.insert(
                profile_id,
                json!({
                    "format": normalize_credential_format(&credential.format),
                    "issuer": environment.issuance.issuer,
                    "signing_key": "country-issuer",
                    "vct": credential.credential_type,
                    "validity_seconds": validity_seconds,
                    "allowed_claims": credential.claims,
                    "disclosure": { "allowed": ["value", "predicate", "redacted"] },
                }),
            );
        }
        for (claim_id, claim) in &service.claims {
            if !seen_claims.insert(claim_id) {
                bail!("Notary claim ids must be unique across country services");
            }
            let consultation_name = claim_consultation_name(service, claim)?;
            let consultation = &service.consultations[consultation_name];
            let integration = &loaded.integrations[&consultation.integration];
            let profile = profiles
                .iter()
                .find(|profile| {
                    profile.service_id == *service_id
                        && profile.consultation_name == consultation_name
                })
                .ok_or_else(|| anyhow!("claim consultation profile is absent"))?;
            let facts = generated_notary_fact_contracts(&integration.document)?;
            let (value_type, nullable, rule) = generated_notary_claim_rule(
                claim_id,
                claim,
                consultation_name,
                &integration.document,
                integration,
            )?;
            let claim_credential_profiles = service
                .credentials
                .iter()
                .filter(|(_, credential)| credential.claims.iter().any(|id| id == claim_id))
                .map(|(credential, _)| bounded_join_id(&[service_id, credential]))
                .collect::<Result<Vec<_>>>()?;
            let mut formats = vec!["application/vnd.registry-notary.claim-result+json".to_string()];
            formats.extend(
                service
                    .credentials
                    .values()
                    .filter(|credential| credential.claims.iter().any(|id| id == claim_id))
                    .map(|credential| normalize_credential_format(&credential.format)),
            );
            formats.sort();
            formats.dedup();
            let (default_disclosure, allowed_disclosures) = expanded_disclosure(&claim.disclosure);
            let inputs = consultation
                .input
                .iter()
                .map(|(name, source)| {
                    (
                        name.clone(),
                        Value::String(if source == "request.target.id" {
                            "target.id".to_string()
                        } else {
                            source.clone()
                        }),
                    )
                })
                .collect::<Map<String, Value>>();
            let consultation_config = json!({
                "profile": {
                    "id": profile.id,
                    "version": profile.version,
                    "contract_hash": profile.contract.artifact().typed_hash(),
                },
                "inputs": inputs,
                "facts": facts,
            });
            let consultation_configs =
                Map::from_iter([(consultation_name.to_string(), consultation_config)]);
            claims.push(json!({
                "id": claim_id,
                "title": claim_id.replace('-', " "),
                "version": service.version.to_string(),
                "subject_type": "person",
                "evidence_mode": {
                    "type": "registry_backed",
                    "consultations": consultation_configs,
                },
                "value": { "type": value_type, "nullable": nullable },
                "purpose": service.purpose,
                "required_scopes": service.access.scopes,
                "rule": rule,
                "disclosure": {
                    "default": default_disclosure,
                    "allowed": allowed_disclosures,
                    "downgrade": "deny",
                },
                "formats": formats,
                "credential_profiles": claim_credential_profiles,
            }));
        }
    }
    let api_keys = environment
        .callers
        .iter()
        .map(|(id, caller)| {
            json!({
                "id": id,
                "fingerprint": {
                    "provider": "env",
                    "name": caller.api_key_fingerprint.secret,
                },
                "scopes": caller.scopes,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "instance": {
            "id": environment.deployment.notary.service,
            "environment": environment_name,
        },
        "server": { "bind": "127.0.0.1:8081", "request_timeout": "30s" },
        "auth": { "mode": "api_key", "api_keys": api_keys },
        "audit": {
            "sink": "stdout",
            "hash_secret_env": "REGISTRY_NOTARY_AUDIT_HASH_SECRET",
        },
        "evidence": {
            "enabled": true,
            "service_id": environment.deployment.notary.service,
            "max_credential_validity_seconds": max_validity_seconds,
            "allowed_purposes": allowed_purposes,
            "variables": variables,
            "relay": {
                "base_url": environment.relay_trust.origin,
                "token_file": environment.relay_trust.notary_token_file,
                "allowed_private_cidrs": [],
            },
            "claims": claims,
            "signing_keys": {
                "country-issuer": {
                    "provider": "local_jwk_env",
                    "private_jwk_env": environment.issuance.signing_key.secret,
                    "alg": "EdDSA",
                    "kid": environment.issuance.signing_kid,
                    "status": "active",
                },
            },
            "credential_profiles": credential_profiles,
        },
        "deployment": { "profile": environment.deployment.profile.as_str() },
    }))
}

fn generated_notary_fact_contracts(integration: &IntegrationDocument) -> Result<Value> {
    let facts = integration
        .facts
        .iter()
        .map(|(name, fact)| {
            let contract = if fact.from.ends_with(".presence") {
                json!({ "type": "presence" })
            } else {
                match fact.fact_type {
                    FactType::Boolean | FactType::Presence => {
                        json!({ "type": "boolean", "nullable": fact.nullable })
                    }
                    FactType::Integer => {
                        if matches!(
                            integration.capability,
                            CapabilityDeclaration::SnapshotExact { .. }
                        ) {
                            json!({
                                "type": "integer",
                                "nullable": fact.nullable,
                                "minimum": -((1_i64 << 53) - 1),
                                "maximum": (1_i64 << 53) - 1,
                            })
                        } else {
                            let schema = fact_source_schema(integration, fact)?;
                            let SchemaNode::Integer { min, max } = schema else {
                                bail!("integer fact must resolve to an integer response field");
                            };
                            json!({ "type": "integer", "nullable": fact.nullable, "minimum": min, "maximum": max })
                        }
                    }
                    FactType::String => json!({
                        "type": "string",
                        "nullable": fact.nullable,
                        "max_bytes": fact.max_bytes.ok_or_else(|| anyhow!("string fact bound is absent"))?,
                    }),
                    FactType::Date => {
                        json!({ "type": "date", "nullable": fact.nullable })
                    }
                }
            };
            Ok((name.clone(), contract))
        })
        .collect::<Result<Map<String, Value>>>()?;
    Ok(Value::Object(facts))
}

fn fact_source_schema<'a>(
    integration: &'a IntegrationDocument,
    fact: &FactDeclaration,
) -> Result<&'a SchemaNode> {
    let (operation, path) = fact
        .from
        .split_once('.')
        .ok_or_else(|| anyhow!("fact path is invalid"))?;
    let operation = integration_operations(integration)
        .get(operation)
        .ok_or_else(|| anyhow!("fact operation is absent"))?;
    let mut schema = operation_record_schema(operation)?;
    let path = path.strip_prefix("record.").unwrap_or(path);
    for segment in path.split('.') {
        schema = match schema {
            SchemaNode::Object { fields, .. } => fields
                .get(segment)
                .map(|field| &field.schema)
                .ok_or_else(|| anyhow!("fact path is absent from the response schema"))?,
            _ => bail!("fact path traverses a non-object response schema"),
        };
    }
    Ok(schema)
}

fn generated_notary_claim_rule(
    claim_id: &str,
    claim: &ClaimDeclaration,
    consultation_name: &str,
    integration: &IntegrationDocument,
    loaded: &LoadedIntegration,
) -> Result<(String, bool, Value)> {
    if let Some(fact_path) = &claim.fact {
        let (consultation, fact_name) = fact_path
            .split_once('.')
            .ok_or_else(|| anyhow!("direct claim fact path is invalid"))?;
        if consultation != consultation_name {
            bail!("direct claim fact path names the wrong consultation");
        }
        let fact = integration
            .facts
            .get(fact_name)
            .ok_or_else(|| anyhow!("direct claim references an unknown fact"))?;
        let (value_type, nullable) = if fact.from.ends_with(".presence") {
            ("boolean", false)
        } else {
            (
                match fact.fact_type {
                    FactType::Boolean | FactType::Presence => "boolean",
                    FactType::Integer => "integer",
                    FactType::String => "string",
                    FactType::Date => "date",
                },
                fact.nullable,
            )
        };
        let rule = if fact.from.ends_with(".presence") {
            json!({ "type": "exists", "source": consultation_name })
        } else {
            json!({ "type": "extract", "source": consultation_name, "field": fact_name })
        };
        return Ok((value_type.to_string(), nullable, rule));
    }
    let expression = claim
        .cel
        .as_ref()
        .ok_or_else(|| anyhow!("claim source is absent"))?;
    let (value_type, nullable) = infer_fixture_claim_type(claim_id, loaded)?;
    Ok((
        value_type,
        nullable,
        json!({ "type": "cel", "expression": expression, "bindings": {} }),
    ))
}

fn infer_fixture_claim_type(
    claim_id: &str,
    integration: &LoadedIntegration,
) -> Result<(String, bool)> {
    let mut value_type = None;
    let mut nullable = false;
    for (_, fixture) in &integration.fixtures {
        let Some(value) = fixture.expect.claims.get(claim_id) else {
            continue;
        };
        if value.is_null() {
            nullable = true;
            continue;
        }
        let candidate = if value.is_boolean() {
            "boolean"
        } else if value.as_i64().is_some() {
            "integer"
        } else if value
            .as_str()
            .is_some_and(|value| validate_full_date(value).is_ok())
        {
            "date"
        } else if value.is_string() {
            "string"
        } else {
            bail!("CEL fixture claim must be a scalar v1 value");
        };
        match value_type {
            Some(previous) if previous != candidate => {
                bail!("CEL fixture claim has inconsistent result types")
            }
            None => value_type = Some(candidate),
            Some(_) => {}
        }
    }
    Ok((
        value_type
            .ok_or_else(|| anyhow!("CEL claim lacks a typed fixture result"))?
            .to_string(),
        nullable,
    ))
}

fn claim_consultation_name<'a>(
    service: &'a ServiceDeclaration,
    claim: &'a ClaimDeclaration,
) -> Result<&'a str> {
    if let Some(fact) = &claim.fact {
        let (consultation, _) = fact
            .split_once('.')
            .ok_or_else(|| anyhow!("direct claim fact path is invalid"))?;
        if service.consultations.contains_key(consultation) {
            return Ok(consultation);
        }
    }
    let roots = claim
        .cel
        .as_deref()
        .map(cel_member_roots)
        .transpose()?
        .unwrap_or_default();
    let referenced = service
        .consultations
        .keys()
        .filter(|name| roots.contains(name.as_str()))
        .map(String::as_str)
        .collect::<Vec<_>>();
    match referenced.as_slice() {
        [name] => Ok(name),
        [] if service.consultations.len() == 1 => Ok(service
            .consultations
            .first_key_value()
            .expect("one consultation was checked")
            .0),
        _ => bail!("v1 claim must depend on exactly one consultation"),
    }
}

fn cel_member_roots(expression: &str) -> Result<BTreeSet<String>> {
    let bytes = expression.as_bytes();
    let mut roots = BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            index += 1;
            let mut escaped = false;
            let mut closed = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    closed = true;
                    break;
                }
            }
            if !closed {
                bail!("CEL expression contains an unterminated string literal");
            }
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            if bytes.get(index) == Some(&b'.') {
                roots.insert(expression[start..index].to_string());
            }
            continue;
        }
        index += 1;
    }
    Ok(roots)
}

fn expanded_disclosure(disclosure: &DisclosureDeclaration) -> (&str, Vec<&str>) {
    match disclosure {
        DisclosureDeclaration::Mode(DisclosureMode::Value) => ("value", vec!["value", "redacted"]),
        DisclosureDeclaration::Mode(DisclosureMode::Predicate) => {
            ("predicate", vec!["predicate", "redacted"])
        }
        DisclosureDeclaration::Mode(DisclosureMode::Redacted) => ("redacted", vec!["redacted"]),
        DisclosureDeclaration::Policy { default, allowed } => (
            match default {
                DisclosureMode::Value => "value",
                DisclosureMode::Predicate => "predicate",
                DisclosureMode::Redacted => "redacted",
            },
            allowed
                .iter()
                .map(|mode| match mode {
                    DisclosureMode::Value => "value",
                    DisclosureMode::Predicate => "predicate",
                    DisclosureMode::Redacted => "redacted",
                })
                .collect(),
        ),
    }
}

fn normalize_credential_format(format: &str) -> String {
    match format {
        "dc+sd-jwt" => "application/dc+sd-jwt".to_string(),
        value => value.to_string(),
    }
}

fn parse_validity_seconds(value: &str) -> Result<u64> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix('s') {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3600)
    } else {
        bail!("credential validity must use s, m, or h")
    };
    number
        .parse::<u64>()?
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("credential validity overflows"))
}

fn generated_explanation(
    loaded: &LoadedCountryProject,
    environment_name: &str,
    packs: &BTreeMap<String, GeneratedPack>,
    profiles: &[GeneratedProfile],
) -> Value {
    json!({
        "schema": "registry.country.explanation.v1",
        "registry": loaded.project.registry.id,
        "environment": environment_name,
        "integrations": loaded.integrations.iter().map(|(alias, integration)| {
            (alias.clone(), json!({
                "source_product": integration.document.source.product,
                "source_versions": integration.document.source.versions,
                "input": integration.document.input,
                "capability": match integration.document.capability {
                    CapabilityDeclaration::BoundedHttp { .. } => "bounded_http",
                    CapabilityDeclaration::SnapshotExact { .. } => "snapshot_exact",
                    CapabilityDeclaration::SandboxedRhai { .. } => "sandboxed_rhai",
                },
                "operations": integration_operations(&integration.document).iter().map(|(id, operation)| {
                    json!({
                        "id": id,
                        "role": match operation.role {
                            OperationRole::Data => "data",
                            OperationRole::Credential => "credential",
                            OperationRole::Verification => "verification",
                        },
                        "method": match operation.request.method { ReadMethod::Get => "GET", ReadMethod::Post => "READ_ONLY_POST" },
                        "primitive": operation.primitive,
                        "depends_on": operation.depends_on,
                        "when": operation.when,
                        "destination": operation.request.destination,
                        "path": operation.request.path,
                        "path_parameters": operation.request.path_parameters,
                        "query": operation.request.query,
                        "headers": operation.request.headers,
                        "body": operation.request.body,
                        "request_codec": operation.request.codec,
                        "authorization": operation.request.authorization,
                        "response_bytes": operation.response.max_bytes,
                        "response_codec": operation.response.codec,
                        "response_statuses": operation.response.statuses,
                        "response_schema": operation.response.schema,
                        "cardinality": operation.response.cardinality,
                    })
                }).collect::<Vec<_>>(),
                "facts": integration.document.facts,
                "bounds": integration.document.bounds,
                "generated_pack": packs.get(alias).map(|pack| json!({
                    "id": pack.id,
                    "version": pack.version,
                    "hash": pack.artifact.typed_hash(),
                })),
            }))
        }).collect::<Map<String, Value>>(),
        "services": loaded.project.services.iter().map(|(id, service)| {
            (id.clone(), json!({
                "kind": service.kind,
                "definition": service.definition,
                "entity": service.entity,
                "purpose": service.purpose,
                "legal_basis": service.legal_basis,
                "consent": service.consent,
                "required_scopes": service.access.scopes,
                "variables": service.variables,
                "consultations": service.consultations,
                "claims": service.claims.iter().map(|(claim, declaration)| (claim, json!({
                    "fact": declaration.fact,
                    "cel": declaration.cel,
                    "disclosure": declaration.disclosure,
                }))).collect::<BTreeMap<_, _>>(),
                "credentials": service.credentials,
                "profiles": profiles.iter().filter(|profile| profile.service_id == *id).map(|profile| json!({
                    "consultation": profile.consultation_name,
                    "integration": profile.integration_alias,
                    "id": profile.id,
                    "version": profile.version,
                    "contract_hash": profile.contract.artifact().typed_hash(),
                    "policy_hash": profile.contract.policy_hash(),
                })).collect::<Vec<_>>(),
            }))
        }).collect::<Map<String, Value>>(),
        "environment_binding": loaded.environment.as_ref().map(|environment| json!({
            "deployment_profile": environment.deployment.profile,
            "integrations": environment.integrations.iter().map(|(alias, binding)| (alias.clone(), json!({
                "source_version": binding.source_version,
                "data_origin": binding.data_destination.as_ref().map(|destination| &destination.origin),
                "credential_origin": binding.credential_destination.as_ref().map(|destination| &destination.origin),
                "credential_interface": binding.credential.as_ref().map(|credential| credential.credential_type),
                "snapshot_entity": match &loaded.integrations[alias].document.capability {
                    CapabilityDeclaration::SnapshotExact { snapshot_exact } => Some(snapshot_exact.entity.as_str()),
                    CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SandboxedRhai { .. } => None,
                },
                "rhai_enabled": binding.advanced_capabilities.as_ref().is_some_and(|advanced| advanced.sandboxed_rhai.enabled),
            }))).collect::<Map<String, Value>>(),
            "entities": environment.entities.iter().map(|(id, binding)| (id.clone(), json!({
                "source_revision": binding.source_revision,
                "generation": binding.generation,
                "materialization_identity": loaded.records.get(id).and_then(|records| records_materialization_resource_id(&records.document, binding).ok()),
            }))).collect::<Map<String, Value>>(),
            "callers": environment.callers.iter().map(|(caller, binding)| (caller.clone(), json!({
                "scopes": binding.scopes,
            }))).collect::<Map<String, Value>>(),
            "relay_workload": {
                "client_id": environment.relay_trust.notary_client_id,
                "audience": environment.relay_trust.audience,
            },
        })),
    })
}

fn load_country_project(root: &Path, environment: Option<&str>) -> Result<LoadedCountryProject> {
    let root = canonical_root(root)?;
    let project_path = root.join(PROJECT_FILE);
    let project_bytes = read_authored_file(&root, &project_path)?;
    let project: CountryProject = parse_yaml(&project_bytes, PROJECT_FILE)?;
    validate_project_shape(&project)?;

    let mut hasher = Sha256::new();
    hash_authored_file(&mut hasher, PROJECT_FILE, &project_bytes);
    let mut records = BTreeMap::new();
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::RecordsApi)
    {
        let relative = service
            .definition
            .as_ref()
            .ok_or_else(|| anyhow!("records_api definition is absent"))?;
        let path = resolve_authored_path(&root, relative)?;
        let bytes = read_authored_file(&root, &path)?;
        hash_authored_file(
            &mut hasher,
            relative
                .to_str()
                .ok_or_else(|| anyhow!("records definition path is not Unicode"))?,
            &bytes,
        );
        let document: RecordsDefinition = parse_yaml(&bytes, &relative.display().to_string())?;
        validate_records_definition(&document)?;
        if service.entity.as_deref() != Some(document.id.as_str()) {
            bail!("records_api entity must match its records definition id");
        }
        if records
            .insert(document.id.clone(), LoadedRecordsDefinition { document })
            .is_some()
        {
            bail!("one records entity cannot be declared by multiple services");
        }
    }
    let mut integrations = BTreeMap::new();
    for (alias, reference) in &project.integrations {
        let path = resolve_authored_path(&root, &reference.file)?;
        let bytes = read_authored_file(&root, &path)?;
        hash_authored_file(
            &mut hasher,
            reference
                .file
                .to_str()
                .ok_or_else(|| anyhow!("integration path is not Unicode"))?,
            &bytes,
        );
        let document: IntegrationDocument =
            parse_yaml(&bytes, &reference.file.display().to_string())?;
        validate_integration(alias, &document).with_context(|| {
            format!("invalid authored integration {}", reference.file.display())
        })?;
        let fixture_dir = path
            .parent()
            .ok_or_else(|| anyhow!("integration file has no parent"))?
            .join(&document.fixtures);
        let fixtures = load_fixtures(&root, &fixture_dir, &mut hasher)?;
        validate_fixture_inputs(alias, &document, &fixtures)?;
        let script = integration_script(&document)
            .map(|script| {
                let script_path = resolve_relative_to_file(&root, &path, script)?;
                let script_bytes = read_authored_file(&root, &script_path)?;
                let relative = script_path
                    .strip_prefix(&root)
                    .map_err(|_| anyhow!("script path escapes project root"))?;
                hash_authored_file(
                    &mut hasher,
                    relative
                        .to_str()
                        .ok_or_else(|| anyhow!("script path is not Unicode"))?,
                    &script_bytes,
                );
                Ok::<(PathBuf, Box<[u8]>), anyhow::Error>((
                    script_path,
                    script_bytes.into_boxed_slice(),
                ))
            })
            .transpose()?;
        integrations.insert(
            alias.clone(),
            LoadedIntegration {
                document,
                fixtures,
                script,
            },
        );
    }
    validate_service_integration_links(&project, &integrations)?;
    validate_country_records_links(&integrations, &records)?;

    let (environment_name, environment) = match environment {
        Some(name) => {
            validate_stable_id(name, "environment")?;
            let relative = PathBuf::from("environments").join(format!("{name}.yaml"));
            let path = resolve_authored_path(&root, &relative)?;
            let bytes = read_authored_file(&root, &path)?;
            hash_authored_file(
                &mut hasher,
                relative
                    .to_str()
                    .ok_or_else(|| anyhow!("environment path is not Unicode"))?,
                &bytes,
            );
            let document: EnvironmentDocument =
                parse_yaml(&bytes, &relative.display().to_string())?;
            validate_environment(&integrations, &records, &document)?;
            (Some(name.to_owned()), Some(document))
        }
        None => (None, None),
    };
    let semantic_digests =
        semantic_digests(&project, &integrations, &records, environment.as_ref())?;
    Ok(LoadedCountryProject {
        root,
        project,
        environment_name,
        environment,
        integrations,
        records,
        authored_hash: format!("sha256:{}", hex::encode(hasher.finalize())),
        semantic_digests,
    })
}

fn semantic_digests(
    project: &CountryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    records: &BTreeMap<String, LoadedRecordsDefinition>,
    environment: Option<&EnvironmentDocument>,
) -> Result<SemanticDigests> {
    let claims = project
        .services
        .iter()
        .map(|(id, service)| {
            (
                id,
                json!({
                    "variables": service.variables,
                    "claims": service.claims,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let policy = project
        .services
        .iter()
        .map(|(id, service)| {
            (
                id,
                json!({
                    "purpose": service.purpose,
                    "legal_basis": service.legal_basis,
                    "consent": service.consent,
                    "access": service.access,
                    "disclosure": service.claims.iter().map(|(claim, declaration)|
                        (claim, &declaration.disclosure)).collect::<BTreeMap<_, _>>(),
                    "credentials": service.credentials,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_policy = records
        .iter()
        .map(|(id, loaded)| {
            (
                id,
                json!({
                    "scopes": loaded.document.api.scopes,
                    "purposes": loaded.document.api.purposes,
                    "required_principal_filters": loaded.document.api.required_principal_filters,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_model = records
        .iter()
        .map(|(id, loaded)| {
            let definition = &loaded.document;
            (
                id,
                json!({
                    "version": definition.version,
                    "id": definition.id,
                    "title": definition.title,
                    "description": definition.description,
                    "owner": definition.owner,
                    "sensitivity": definition.sensitivity,
                    "access_rights": definition.access_rights,
                    "update_frequency": definition.update_frequency,
                    "conforms_to": definition.conforms_to,
                    "primary_key": definition.primary_key,
                    "fields": definition.fields,
                    "pagination": definition.api.pagination,
                    "filters": definition.api.filters,
                    "relationships": definition.api.relationships,
                    "aggregates": definition.api.aggregates,
                    "standards": definition.api.standards,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let integration = integrations
        .iter()
        .map(|(alias, loaded)| {
            let fixture_digests = loaded
                .fixtures
                .iter()
                .map(|(path, fixture)| {
                    let name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| anyhow!("fixture path is not Unicode"))?;
                    Ok((name, fixture))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let script_digest = loaded.script.as_ref().map(|(_, script)| sha256_uri(script));
            let source_version = environment
                .and_then(|environment| environment.integrations.get(alias))
                .map(|binding| binding.source_version.as_str());
            let snapshot_mapping = match &loaded.document.capability {
                CapabilityDeclaration::SnapshotExact { snapshot_exact } => environment
                    .and_then(|environment| environment.entities.get(&snapshot_exact.entity))
                    .map(|binding| json!({ "columns": binding.columns })),
                CapabilityDeclaration::BoundedHttp { .. }
                | CapabilityDeclaration::SandboxedRhai { .. } => None,
            };
            Ok((
                alias,
                json!({
                    "document": loaded.document,
                    "fixtures": fixture_digests,
                    "script_digest": script_digest,
                    "source_version": source_version,
                    "snapshot_mapping": snapshot_mapping,
                }),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let service_consultations = project
        .services
        .iter()
        .map(|(service, declaration)| (service, &declaration.consultations))
        .collect::<BTreeMap<_, _>>();
    let callers = environment.map(|environment| {
        environment
            .callers
            .iter()
            .map(|(id, caller)| (id, &caller.scopes))
            .collect::<BTreeMap<_, _>>()
    });
    let operator = environment.map(|environment| {
        let integrations = environment
            .integrations
            .iter()
            .map(|(alias, binding)| {
                (
                    alias,
                    json!({
                        "data_destination": binding.data_destination,
                        "credential_destination": binding.credential_destination,
                        "credential": binding.credential,
                        "advanced_capabilities": binding.advanced_capabilities,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let caller_credentials = environment
            .callers
            .iter()
            .map(|(id, caller)| (id, &caller.api_key_fingerprint))
            .collect::<BTreeMap<_, _>>();
        json!({
            "integrations": integrations,
            "entities": environment.entities,
            "caller_credentials": caller_credentials,
            "issuance": environment.issuance,
            "relay_trust": environment.relay_trust,
            "deployment": environment.deployment,
        })
    });
    Ok(SemanticDigests {
        claim: digest_json(&json!({ "services": claims }))?,
        integration: digest_json(&json!({
            "integrations": integration,
            "service_consultations": service_consultations,
            "records": records_model,
        }))?,
        country_policy: digest_json(
            &json!({ "services": policy, "records": records_policy, "callers": callers }),
        )?,
        operator_security: digest_json(&json!({ "operator": operator }))?,
    })
}

fn digest_json(value: &Value) -> Result<String> {
    Ok(sha256_uri(
        &canonicalize_json(value).context("failed to canonicalize semantic review input")?,
    ))
}

fn validate_project_shape(project: &CountryProject) -> Result<()> {
    if project.version != 1 {
        bail!("registry-stack.yaml version must be 1");
    }
    validate_stable_id(&project.registry.id, "registry.id")?;
    if project.integrations.is_empty() || project.integrations.len() > 16 {
        bail!("project must declare between one and 16 integrations");
    }
    if project.services.is_empty() || project.services.len() > 32 {
        bail!("project must declare between one and 32 services");
    }
    for (alias, reference) in &project.integrations {
        validate_stable_id(alias, "integration alias")?;
        validate_relative_authored_path(&reference.file)?;
    }
    for (service_id, service) in &project.services {
        validate_stable_id(service_id, "service id")?;
        match service.kind {
            ServiceKind::RecordsApi => {
                if service.version != 0
                    || !service.purpose.is_empty()
                    || !service.legal_basis.is_empty()
                    || !service.access.scopes.is_empty()
                    || !service.variables.is_empty()
                    || !service.consultations.is_empty()
                    || !service.claims.is_empty()
                    || !service.credentials.is_empty()
                {
                    bail!("records_api service may declare only kind, definition, and entity");
                }
                let definition = service
                    .definition
                    .as_ref()
                    .ok_or_else(|| anyhow!("records_api service requires a definition"))?;
                validate_relative_authored_path(definition)?;
                validate_stable_id(
                    service
                        .entity
                        .as_deref()
                        .ok_or_else(|| anyhow!("records_api service requires an entity"))?,
                    "records_api entity",
                )?;
                continue;
            }
            ServiceKind::Evidence => {
                if service.definition.is_some() || service.entity.is_some() {
                    bail!("evidence service cannot declare records_api fields");
                }
            }
        }
        if service.version == 0 {
            bail!("service version must be positive");
        }
        validate_token(&service.purpose, "service purpose", 256)?;
        validate_token(&service.legal_basis, "service legal_basis", 128)?;
        if service.consent == ConsentDeclaration::Required {
            bail!("consent: required is unavailable until sealed consent verification lands");
        }
        validate_scopes(&service.access.scopes)?;
        if service.consultations.is_empty() || service.consultations.len() > 16 {
            bail!("service consultations must contain between one and 16 entries");
        }
        if service.claims.is_empty() || service.claims.len() > MAX_CLAIMS {
            bail!("service claims must contain between one and 64 entries");
        }
        for (name, consultation) in &service.consultations {
            validate_stable_id(name, "consultation name")?;
            if !project.integrations.contains_key(&consultation.integration) {
                bail!("consultation references an unknown integration");
            }
            if !(1..=4).contains(&consultation.input.len()) {
                bail!(
                    "consultation input must contain between one and four typed subject mappings"
                );
            }
            for mapping in consultation.input.values() {
                validate_request_mapping(mapping)?;
            }
        }
        for (variable, declaration) in &service.variables {
            validate_stable_id(variable, "request variable")?;
            if declaration.from != format!("request.variables.{variable}")
                || declaration.value_type != FactType::Date
            {
                bail!("v1 request variables must be exact declared full-date mappings");
            }
        }
        for (claim_id, claim) in &service.claims {
            validate_stable_id(claim_id, "claim id")?;
            if claim.fact.is_some() == claim.cel.is_some() {
                bail!("each claim must declare exactly one of fact or cel");
            }
            validate_disclosure(&claim.disclosure)?;
        }
        for credential in service.credentials.values() {
            if credential.claims.is_empty() {
                bail!("credential claim allow-list must not be empty");
            }
            for claim in &credential.claims {
                if !service.claims.contains_key(claim) {
                    bail!("credential references an unknown claim");
                }
            }
        }
    }
    Ok(())
}

fn validate_records_definition(records: &RecordsDefinition) -> Result<()> {
    if records.version != 1 {
        bail!("records definition version must be 1");
    }
    validate_stable_id(&records.id, "records id")?;
    if records.id.len() > 45 || !is_lower_snake_id(&records.id) {
        bail!("records id exceeds the shared materialization provider bound");
    }
    validate_stable_id(&records.primary_key, "records primary_key")?;
    if records.fields.is_empty() || records.fields.len() > 256 {
        bail!("records fields must contain between one and 256 entries");
    }
    if !records.fields.contains_key(&records.primary_key) {
        bail!("records primary_key must reference a declared logical field");
    }
    for (name, field) in &records.fields {
        validate_stable_id(name, "records field")?;
        if !is_lower_snake_id(name) {
            bail!("records fields must use Relay lower-snake ids");
        }
        if name == &records.primary_key && field.nullable {
            bail!("records primary_key must be non-nullable");
        }
    }
    validate_scopes(&[
        records.api.scopes.metadata.clone(),
        records.api.scopes.rows.clone(),
    ])?;
    for scope in [
        Some(&records.api.scopes.metadata),
        Some(&records.api.scopes.rows),
        records.api.scopes.aggregate.as_ref(),
        records.api.scopes.evidence_verification.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_token(scope, "records scope", 128)?;
        if scope.split_once(':').map(|(dataset, _)| dataset) != Some(records.id.as_str()) {
            bail!("records scopes must use their records id namespace");
        }
    }
    if records.api.pagination.default_limit == 0
        || records.api.pagination.max_limit == 0
        || records.api.pagination.default_limit > records.api.pagination.max_limit
        || records.api.pagination.max_limit > 10_000
    {
        bail!("records pagination limits are invalid");
    }
    for purpose in &records.api.purposes {
        validate_token(purpose, "records purpose", 256)?;
    }
    let field_names = records
        .fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (field, operators) in &records.api.filters {
        if !field_names.contains(field.as_str()) || operators.is_empty() {
            bail!("records filters must name declared fields and at least one operator");
        }
        if operators.iter().collect::<BTreeSet<_>>().len() != operators.len() {
            bail!("records filter operators must be unique");
        }
    }
    for field in &records.api.required_principal_filters {
        if !field_names.contains(field.as_str()) || !records.api.filters.contains_key(field) {
            bail!("required principal filters must be allow-listed records fields");
        }
    }
    for (name, relationship) in &records.api.relationships {
        validate_stable_id(name, "records relationship")?;
        if !is_lower_snake_id(name) {
            bail!("records relationships must use Relay lower-snake ids");
        }
        validate_stable_id(&relationship.target, "records relationship target")?;
        if !field_names.contains(relationship.foreign_key.as_str()) {
            bail!("records relationship foreign_key must be a declared field");
        }
    }
    for (id, aggregate) in &records.api.aggregates {
        validate_stable_id(id, "records aggregate")?;
        if !is_lower_snake_id(id) {
            bail!("records aggregates must use Relay lower-snake ids");
        }
        if (aggregate.measures.is_empty() && aggregate.indicators.is_empty())
            || aggregate.disclosure_control.min_group_size == 0
        {
            bail!(
                "records aggregate requires measures or indicators and positive disclosure control"
            );
        }
        for field in aggregate
            .group_by
            .iter()
            .chain(&aggregate.default_group_by)
            .chain(aggregate.temporal_field.iter())
        {
            if !field_names.contains(field.as_str()) {
                bail!("records aggregate fields must name declared fields");
            }
        }
        for dimension in &aggregate.dimensions {
            validate_stable_id(&dimension.id, "records aggregate dimension")?;
            if !is_lower_snake_id(&dimension.id) {
                bail!("records aggregate dimensions must use Relay lower-snake ids");
            }
            if !field_names.contains(dimension.field.as_str()) {
                bail!("records aggregate dimension must name a declared field");
            }
        }
        for indicator in &aggregate.indicators {
            validate_stable_id(&indicator.id, "records aggregate indicator")?;
            if !is_lower_snake_id(&indicator.id) {
                bail!("records aggregate indicators must use Relay lower-snake ids");
            }
            if !field_names.contains(indicator.column.as_str()) {
                bail!("records aggregate indicator must name a declared field");
            }
        }
        for measure in &aggregate.measures {
            validate_stable_id(&measure.name, "records aggregate measure")?;
            if !is_lower_snake_id(&measure.name) {
                bail!("records aggregate measures must use Relay lower-snake ids");
            }
            if !field_names.contains(measure.column.as_str()) {
                bail!("records aggregate measure must name a declared field");
            }
        }
        for (field, operators) in &aggregate.allowed_filters {
            if !field_names.contains(field.as_str()) || operators.is_empty() {
                bail!("records aggregate filters must name declared fields");
            }
        }
        for field in &aggregate.required_principal_filters {
            if !aggregate.allowed_filters.contains_key(field) {
                bail!("records aggregate principal filters must be allow-listed");
            }
        }
        if aggregate
            .joins
            .iter()
            .any(|join| !records.api.relationships.contains_key(join))
        {
            bail!("records aggregate joins must name declared relationships");
        }
    }
    validate_record_standards(records, &field_names)?;
    Ok(())
}

fn is_lower_snake_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn validate_record_standards(records: &RecordsDefinition, fields: &BTreeSet<&str>) -> Result<()> {
    match &records.api.standards.ogc_features {
        RecordStandard::Disabled(false) => {}
        RecordStandard::Disabled(true) => {
            bail!("ogc_features: true requires an explicit spatial configuration")
        }
        RecordStandard::Enabled(spatial) => {
            let mut referenced = Vec::new();
            match &spatial.geometry {
                RecordSpatialGeometry::Point {
                    longitude_field,
                    latitude_field,
                    ..
                } => referenced.extend([longitude_field.as_str(), latitude_field.as_str()]),
                RecordSpatialGeometry::Geojson { field, .. }
                | RecordSpatialGeometry::Wkt { field, .. }
                | RecordSpatialGeometry::Wkb { field, .. } => referenced.push(field),
            }
            if let Some(bbox) = &spatial.bbox_fields {
                referenced.extend([
                    bbox.min_x.as_str(),
                    bbox.min_y.as_str(),
                    bbox.max_x.as_str(),
                    bbox.max_y.as_str(),
                ]);
            }
            if let Some(datetime) = &spatial.datetime_field {
                referenced.push(datetime);
            }
            if referenced.into_iter().any(|field| !fields.contains(field)) {
                bail!("OGC spatial configuration must use declared logical fields");
            }
        }
    }
    match &records.api.standards.sp_dci {
        RecordStandard::Disabled(false) => {}
        RecordStandard::Disabled(true) => {
            bail!("sp_dci: true requires an explicit registry mapping")
        }
        RecordStandard::Enabled(spdci) => {
            validate_stable_id(&spdci.registry, "SP DCI registry id")?;
            if spdci
                .identifiers
                .values()
                .chain(spdci.expression_fields.values())
                .chain(spdci.response_fields.values())
                .any(|field| !fields.contains(field.as_str()))
            {
                bail!("SP DCI mapping must use declared logical fields");
            }
        }
    }
    Ok(())
}

fn validate_country_records_links(
    integrations: &BTreeMap<String, LoadedIntegration>,
    records: &BTreeMap<String, LoadedRecordsDefinition>,
) -> Result<()> {
    for loaded in integrations.values() {
        let CapabilityDeclaration::SnapshotExact { snapshot_exact } = &loaded.document.capability
        else {
            continue;
        };
        let definition = records.get(&snapshot_exact.entity).ok_or_else(|| {
            anyhow!("snapshot_exact references an unknown governed records entity")
        })?;
        if loaded
            .document
            .input
            .keys()
            .any(|input| !definition.document.fields.contains_key(input))
        {
            bail!("snapshot_exact inputs must name declared logical records fields");
        }
        let projected = loaded
            .document
            .facts
            .values()
            .filter_map(snapshot_fact_field)
            .collect::<BTreeSet<_>>();
        if projected.is_empty()
            || projected
                .iter()
                .any(|field| loaded.document.input.contains_key(*field))
            || projected
                .iter()
                .any(|field| !definition.document.fields.contains_key(*field))
        {
            bail!("snapshot_exact projection must be a non-empty logical records subset distinct from its selector key");
        }
        for name in projected {
            let field = &definition.document.fields[name];
            let fact = loaded
                .document
                .facts
                .get(name)
                .ok_or_else(|| anyhow!("snapshot_exact logical field is absent"))?;
            let compatible = matches!(
                (field.field_type, fact.fact_type),
                (RecordFieldType::String, FactType::String)
                    | (RecordFieldType::Integer, FactType::Integer)
                    | (RecordFieldType::Boolean, FactType::Boolean)
                    | (RecordFieldType::Date, FactType::Date)
            );
            if !compatible || field.nullable != fact.nullable {
                bail!("snapshot_exact facts must preserve records field type and nullability");
            }
        }
    }
    for definition in records.values() {
        for relationship in definition.document.api.relationships.values() {
            if !records.contains_key(&relationship.target) {
                bail!("records relationship references an unknown entity");
            }
        }
    }
    Ok(())
}

fn validate_service_integration_links(
    project: &CountryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
) -> Result<()> {
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::Evidence)
    {
        for consultation in service.consultations.values() {
            let integration = &integrations[&consultation.integration].document;
            if consultation.input.keys().ne(integration.input.keys()) {
                bail!("consultation input must bind the integration input set exactly");
            }
            if consultation.input.values().collect::<BTreeSet<_>>().len()
                != consultation.input.len()
            {
                bail!("consultation target mappings must be injective");
            }
        }
    }
    Ok(())
}

fn validate_fixture_inputs(
    alias: &str,
    integration: &IntegrationDocument,
    fixtures: &[(PathBuf, FixtureDocument)],
) -> Result<()> {
    for (_, fixture) in fixtures {
        if fixture.input.keys().ne(integration.input.keys()) {
            bail!(
                "fixture {} must bind every {alias} input exactly once",
                fixture.name
            );
        }
        for (name, declaration) in &integration.input {
            let value = fixture.input[name]
                .as_str()
                .ok_or_else(|| anyhow!("fixture input must be a string"))?;
            if declaration.input_type == InputType::FullDate
                && time::Date::parse(
                    value,
                    &time::macros::format_description!("[year]-[month]-[day]"),
                )
                .is_err()
            {
                bail!("fixture full_date input is not canonical");
            }
        }
    }
    Ok(())
}

fn snapshot_fact_field(fact: &FactDeclaration) -> Option<&str> {
    let (_, path) = fact.from.split_once('.')?;
    let field = path.strip_prefix("record.").unwrap_or(path);
    (field != "presence").then_some(field)
}

fn validate_integration(alias: &str, integration: &IntegrationDocument) -> Result<()> {
    if integration.version != 1 {
        bail!("integration {alias} version must be 1");
    }
    validate_stable_id(&integration.id, "integration id")?;
    validate_stable_id(&integration.source.product, "source.product")?;
    let versions = integration
        .source
        .versions
        .tested
        .iter()
        .chain(&integration.source.versions.supported)
        .chain(&integration.source.versions.unverified);
    let mut unique_versions = BTreeSet::new();
    for version in versions {
        validate_token(version, "source version", 256)?;
        if !unique_versions.insert(version) {
            bail!("source version evidence classes contain a duplicate");
        }
    }
    if unique_versions.is_empty() || unique_versions.len() > 32 {
        bail!("source versions must contain between one and 32 unique entries");
    }
    if !(1..=4).contains(&integration.input.len()) {
        bail!("integration {alias} must declare between one and four typed subject inputs");
    }
    for (name, input) in &integration.input {
        validate_input_name(name).with_context(|| format!("input.{name}.name"))?;
        if input.bytes == 0 || input.bytes > MAX_BOUNDED_INPUT_BYTES {
            bail!("input.{name}.bytes must be between 1 and {MAX_BOUNDED_INPUT_BYTES}");
        }
        if input.pattern.is_empty() || input.pattern.len() > 1024 {
            bail!("input.{name}.pattern must be between 1 and 1024 bytes");
        }
        if input.input_type == InputType::FullDate
            && (input.bytes != 10
                || input.pattern != "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
                || !matches!(input.canonicalization, Canonicalization::Identity))
        {
            bail!("full_date input requires the exact RFC 3339 full-date contract");
        }
    }
    validate_credential_interface(integration)?;
    if integration.facts.is_empty() || integration.facts.len() > MAX_FACTS {
        bail!("integration facts must contain between one and 64 entries");
    }
    let operations = integration_operations(integration);
    let snapshot = matches!(
        integration.capability,
        CapabilityDeclaration::SnapshotExact { .. }
    );
    if (!snapshot && operations.is_empty()) || operations.len() > MAX_OPERATIONS {
        bail!("bounded integration must contain between one and five operations");
    }
    if usize::from(integration.bounds.calls) != operations.len()
        || (!snapshot && integration.bounds.calls == 0)
        || integration.bounds.source_bytes == 0
        || integration.bounds.source_bytes > 1024 * 1024
        || integration.bounds.request_bytes == 0
        || integration.bounds.concurrency == 0
        || integration.bounds.concurrency > 16
    {
        bail!("integration bounds are inconsistent with its fixed operation graph");
    }
    parse_duration_ms(&integration.bounds.deadline)?;
    let ordered = ordered_operations(operations)?;
    let mut prior = BTreeSet::new();
    for (operation_id, operation) in ordered {
        validate_stable_id(operation_id, "operation id")?;
        validate_operation(operation, &integration.input, &prior)?;
        prior.insert(operation_id.as_str());
    }
    for (fact, declaration) in &integration.facts {
        validate_stable_id(fact, "fact id")?;
        if snapshot {
            validate_snapshot_fact(fact, declaration)?;
        } else {
            validate_fact(declaration, operations)?;
        }
    }
    validate_relative_authored_path(&integration.fixtures)?;
    Ok(())
}

fn validate_environment(
    integrations: &BTreeMap<String, LoadedIntegration>,
    records: &BTreeMap<String, LoadedRecordsDefinition>,
    environment: &EnvironmentDocument,
) -> Result<()> {
    if environment.version != 1 || environment.integrations.len() != integrations.len() {
        bail!("environment must bind every integration exactly once");
    }
    for (alias, loaded) in integrations {
        let binding = environment
            .integrations
            .get(alias)
            .ok_or_else(|| anyhow!("environment is missing integration binding {alias}"))?;
        if !loaded
            .document
            .source
            .versions
            .tested
            .contains(&binding.source_version)
            && !loaded
                .document
                .source
                .versions
                .supported
                .contains(&binding.source_version)
            && !loaded
                .document
                .source
                .versions
                .unverified
                .contains(&binding.source_version)
        {
            bail!("environment source_version is not declared by the integration");
        }
        match &loaded.document.capability {
            CapabilityDeclaration::SnapshotExact { .. } => {
                if binding.data_destination.is_some() || binding.credential_destination.is_some() {
                    bail!("snapshot_exact uses only its governed records entity binding");
                }
            }
            CapabilityDeclaration::BoundedHttp { .. }
            | CapabilityDeclaration::SandboxedRhai { .. } => {
                if binding.data_destination.is_none() {
                    bail!("HTTP integrations require a fixed data destination");
                }
                validate_https_origin(
                    &binding
                        .data_destination
                        .as_ref()
                        .expect("presence was checked")
                        .origin,
                    "data destination",
                )?;
            }
        }
        validate_environment_credential(credential_interface(&loaded.document), binding)?;
    }
    if environment
        .integrations
        .keys()
        .any(|key| !integrations.contains_key(key))
    {
        bail!("environment contains an unknown integration binding");
    }
    if environment.entities.len() != records.len() {
        bail!("environment must bind every governed records entity exactly once");
    }
    for (id, loaded) in records {
        let binding = environment
            .entities
            .get(id)
            .ok_or_else(|| anyhow!("environment is missing governed records entity {id}"))?;
        validate_environment_entity(&loaded.document, binding)?;
    }
    if environment
        .entities
        .keys()
        .any(|entity| !records.contains_key(entity))
    {
        bail!("environment contains an unknown governed records entity");
    }
    if environment.callers.is_empty() {
        bail!("environment must bind at least one authenticated caller");
    }
    if environment.callers.len() > 64 {
        bail!("environment callers exceed the supported bound");
    }
    for (caller_id, caller) in &environment.callers {
        validate_stable_id(caller_id, "caller id")?;
        validate_secret_reference(&caller.api_key_fingerprint)?;
        validate_scopes(&caller.scopes)?;
    }
    validate_secret_reference(&environment.issuance.signing_key)?;
    validate_token(&environment.issuance.issuer, "issuance issuer", 2048)?;
    validate_stable_id(&environment.issuance.signing_kid, "issuance signing_kid")?;
    if environment.issuance.generation == 0 {
        bail!("issuance generation must be positive");
    }
    validate_https_origin(&environment.relay_trust.origin, "Relay trust origin")?;
    validate_https_origin(&environment.relay_trust.issuer, "Relay workload issuer")?;
    validate_token(
        &environment.relay_trust.audience,
        "Relay workload audience",
        256,
    )?;
    validate_token(
        &environment.relay_trust.notary_client_id,
        "Relay Notary client id",
        256,
    )?;
    validate_absolute_runtime_path(
        &environment.relay_trust.notary_token_file,
        "Relay workload token file",
    )?;
    let jwks = url::Url::parse(&environment.relay_trust.jwks_url)
        .context("Relay workload JWKS URL is invalid")?;
    if jwks.scheme() != "https"
        || jwks.host().is_none()
        || !jwks.username().is_empty()
        || jwks.password().is_some()
        || jwks.path() == "/"
        || jwks.query().is_some()
        || jwks.fragment().is_some()
    {
        bail!("Relay workload JWKS URL must be one exact HTTPS resource");
    }
    validate_stable_id(&environment.deployment.relay.service, "Relay service id")?;
    validate_stable_id(&environment.deployment.notary.service, "Notary service id")?;
    for (alias, loaded) in integrations {
        let enablement = environment.integrations[alias]
            .advanced_capabilities
            .as_ref()
            .map(|advanced| &advanced.sandboxed_rhai);
        match (&loaded.document.capability, enablement) {
            (CapabilityDeclaration::SandboxedRhai { .. }, Some(enablement))
                if enablement.enabled
                    && enablement.review == ReviewClassInput::OperatorSecurity
                    && RHAI_RELEASE_CAPABILITIES.contains(&(
                        loaded.document.source.product.as_str(),
                        environment.integrations[alias].source_version.as_str(),
                    )) => {}
            (CapabilityDeclaration::SandboxedRhai { .. }, _) => {
                bail!("sandboxed_rhai requires release allow-list and explicit operator-security enablement")
            }
            (_, None) => {}
            (_, Some(_)) => bail!("advanced capability enablement is unused"),
        }
    }
    Ok(())
}

fn validate_credential_interface(integration: &IntegrationDocument) -> Result<()> {
    let interface = credential_interface(integration);
    match interface.credential_type {
        CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
            let name = interface
                .name
                .as_deref()
                .ok_or_else(|| anyhow!("API-key credential interface requires a fixed name"))?;
            let max_value_bytes = interface
                .max_value_bytes
                .filter(|bound| *bound > 0 && *bound <= 4096)
                .ok_or_else(|| anyhow!("API-key credential interface requires a bounded value"))?;
            let _ = max_value_bytes;
            let mut bytes = name.bytes();
            match interface.credential_type {
                CredentialType::ApiKeyHeader => {
                    if name.len() > 64
                        || !matches!(bytes.next(), Some(b'a'..=b'z'))
                        || !bytes
                            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
                    {
                        bail!("API-key header name must be one fixed lower-case HTTP token");
                    }
                    if is_forbidden_api_key_header(name) {
                        bail!("API-key header name is security-sensitive or hop-by-hop");
                    }
                }
                CredentialType::ApiKeyQuery => {
                    if name.len() > 96
                        || !matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
                        || !bytes.all(|byte| {
                            matches!(
                                byte,
                                b'a'..=b'z'
                                    | b'A'..=b'Z'
                                    | b'0'..=b'9'
                                    | b'.'
                                    | b'_'
                                    | b':'
                                    | b'~'
                                    | b'-'
                            )
                        })
                    {
                        bail!("API-key query name is outside the closed reviewed grammar");
                    }
                    if integration_operations(integration)
                        .values()
                        .any(|operation| operation.request.query.contains_key(name))
                    {
                        bail!("API-key query name collides with an authored request parameter");
                    }
                }
                _ => unreachable!(),
            }
        }
        CredentialType::None
        | CredentialType::Basic
        | CredentialType::StaticBearer
        | CredentialType::Oauth2ClientCredentials => {
            if interface.name.is_some() || interface.max_value_bytes.is_some() {
                bail!("non-API-key credential interfaces cannot declare API-key fields");
            }
        }
    }
    Ok(())
}

fn is_forbidden_api_key_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "host"
            | "connection"
            | "content-length"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

fn validate_environment_entity(
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<()> {
    let expected = records
        .fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if binding
        .columns
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        bail!("environment entity columns must bind every logical field exactly once");
    }
    let mut physical = BTreeSet::new();
    for column in binding.columns.values() {
        validate_stable_id(column, "records physical column")?;
        if !physical.insert(column) {
            bail!("environment entity physical column mapping must be injective");
        }
    }
    validate_token(&binding.source_revision, "records source revision", 256)?;
    validate_token(&binding.generation, "records generation", 256)?;
    let path = match &binding.provider {
        RecordProvider::Csv { path, .. }
        | RecordProvider::Xlsx { path, .. }
        | RecordProvider::Parquet { path } => path,
    };
    validate_absolute_runtime_path(path, "records provider path")?;
    if let RecordProvider::Xlsx { sheet, .. } = &binding.provider {
        validate_token(sheet, "records provider sheet", 256)?;
    }
    Ok(())
}

fn execute_all_fixtures(
    loaded: &LoadedCountryProject,
    compiled: &CompiledCountry,
) -> Result<Vec<FixtureReport>> {
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    let relay_fixture = compile_generated_relay_fixture(relay_config, &compiled.relay_private)?;
    let mut reports = Vec::new();
    for (alias, integration) in &loaded.integrations {
        for (fixture_path, fixture) in &integration.fixtures {
            let preflight = fixture_preflight(loaded, alias, fixture);
            let mut actual_calls = Vec::new();
            let (result, evaluated_claims) = match preflight {
                Err(error) => (Err(error), None),
                Ok(()) if fixture_requires_product_pre_relay_denial(loaded, alias, fixture) => {
                    match evaluate_product_claims(loaded, compiled, alias, fixture, None)
                        .with_context(|| {
                            format!(
                                "failed the product Notary pre-Relay denial for fixture {}.{}",
                                alias, fixture.name
                            )
                        })? {
                        Ok(claims) => (Ok((BTreeMap::new(), "no_match")), Some(claims)),
                        Err(error) => (Err(error), None),
                    }
                }
                Ok(()) => {
                    let relay = execute_fixture(
                        compiled,
                        &relay_fixture,
                        alias,
                        fixture,
                        &mut actual_calls,
                    );
                    match relay {
                        Ok((facts, outcome)) if matches!(outcome, "match" | "no_match") => {
                            match evaluate_product_claims(
                                loaded,
                                compiled,
                                alias,
                                fixture,
                                Some((&facts, outcome)),
                            )
                            .with_context(|| {
                                format!(
                                    "failed to evaluate product claims for fixture {}.{}",
                                    alias, fixture.name
                                )
                            })? {
                                Ok(claims) => (Ok((facts, outcome)), Some(claims)),
                                Err(error) => (Err(error), None),
                            }
                        }
                        Ok(result) => (Ok(result), None),
                        Err(error) => (Err(error), None),
                    }
                }
            };
            let passed = match (&result, &fixture.expect.error) {
                (Ok((facts, _)), None) => {
                    let outcome_matches =
                        fixture.expect.outcome.as_deref().is_none_or(|expected| {
                            result
                                .as_ref()
                                .is_ok_and(|(_, outcome)| *outcome == expected)
                        });
                    let claims_match = if result
                        .as_ref()
                        .is_ok_and(|(_, outcome)| *outcome == "ambiguous")
                    {
                        fixture.expect.claims.is_empty()
                            && fixture.expect.disclosed_claims.is_empty()
                    } else {
                        evaluated_claims.as_ref() == Some(&fixture.expect.claims)
                    };
                    facts == &fixture.expect.facts
                        && claims_match
                        && outcome_matches
                        && (fixture.expect.calls.is_empty() || fixture.expect.calls == actual_calls)
                        && fixture.expect.source_access.is_none_or(|expected| expected)
                }
                (Err(code), Some(expected)) => {
                    code == expected
                        && (fixture.expect.calls.is_empty() || fixture.expect.calls == actual_calls)
                        && fixture.expect.disclosed_claims.is_empty()
                        && fixture
                            .expect
                            .source_access
                            .is_none_or(|expected| expected == error_implies_source_access(code))
                }
                _ => false,
            };
            let failure = (!passed).then(|| match (&result, &fixture.expect.error) {
                (Ok((facts, _)), None) if facts != &fixture.expect.facts => format!(
                    "facts_mismatch: fields={}",
                    mismatched_map_keys(facts, &fixture.expect.facts).join("|")
                ),
                (Ok((_, outcome)), None)
                    if fixture
                        .expect
                        .outcome
                        .as_deref()
                        .is_some_and(|expected| expected != *outcome) =>
                {
                    format!(
                        "outcome_mismatch: expected={}, actual={outcome}",
                        fixture.expect.outcome.as_deref().unwrap_or("unspecified")
                    )
                }
                (Ok(_), None) if evaluated_claims.as_ref() != Some(&fixture.expect.claims) => {
                    format!(
                        "claims_mismatch: claims={}",
                        mismatched_optional_map_keys(
                            evaluated_claims.as_ref(),
                            &fixture.expect.claims,
                        )
                        .join("|")
                    )
                }
                (Ok(_), None) | (Err(_), Some(_))
                    if !fixture.expect.calls.is_empty() && fixture.expect.calls != actual_calls =>
                {
                    format!(
                        "calls_mismatch: expected={}, actual={}",
                        fixture.expect.calls.join("|"),
                        actual_calls.join("|")
                    )
                }
                (Err(actual), Some(expected)) if actual != expected => {
                    format!("error_mismatch: expected={expected}, actual={actual}")
                }
                (Err(actual), None) => format!("unexpected_error: actual={actual}"),
                (Ok(_), Some(expected)) => {
                    format!("expected_error_missing: expected={expected}")
                }
                _ => "expectation_mismatch".to_string(),
            });
            let failure = failure.map(|failure| {
                let relative = fixture_path
                    .strip_prefix(&loaded.root)
                    .unwrap_or(fixture_path)
                    .display();
                let field = result
                    .as_ref()
                    .err()
                    .filter(|code| code.as_str() == "input.pattern_mismatch")
                    .and_then(|_| invalid_fixture_input_field(&integration.document, fixture))
                    .map(|field| format!(" field=input.{field}"))
                    .unwrap_or_default();
                format!("file={relative}{field} {failure}")
            });
            let facts = result
                .as_ref()
                .ok()
                .map(|(facts, _)| facts.keys().cloned().collect())
                .unwrap_or_default();
            reports.push(FixtureReport {
                integration: alias.clone(),
                fixture: fixture.name.clone(),
                inputs: fixture.input.keys().cloned().collect(),
                calls: actual_calls,
                facts,
                claims: evaluated_claims
                    .as_ref()
                    .map(|claims| claims.keys().cloned().collect())
                    .unwrap_or_default(),
                outcome: result
                    .as_ref()
                    .ok()
                    .map(|(_, outcome)| (*outcome).to_string()),
                expected_error: fixture.expect.error.clone(),
                source_access: result
                    .as_ref()
                    .err()
                    .map(|code| error_implies_source_access(code)),
                passed,
                failure,
            });
        }
    }
    Ok(reports)
}

fn invalid_fixture_input_field<'a>(
    integration: &'a IntegrationDocument,
    fixture: &FixtureDocument,
) -> Option<&'a str> {
    integration.input.iter().find_map(|(name, declaration)| {
        let Some(value) = fixture.input.get(name).and_then(Value::as_str) else {
            return Some(name.as_str());
        };
        if value.len() > usize::from(declaration.bytes) {
            return Some(name.as_str());
        }
        if declaration.input_type == InputType::FullDate && validate_full_date(value).is_err() {
            return Some(name.as_str());
        }
        let canonical = match declaration.canonicalization {
            Canonicalization::Identity => std::borrow::Cow::Borrowed(value),
            Canonicalization::AsciiLowercase => std::borrow::Cow::Owned(value.to_ascii_lowercase()),
        };
        let pattern = relay_input_pattern(&declaration.pattern).ok()?;
        (!regex::Regex::new(&pattern).ok()?.is_match(&canonical)).then_some(name.as_str())
    })
}

fn mismatched_map_keys<T: PartialEq>(
    actual: &BTreeMap<String, T>,
    expected: &BTreeMap<String, T>,
) -> Vec<String> {
    actual
        .keys()
        .chain(expected.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| actual.get(*key) != expected.get(*key))
        .cloned()
        .collect()
}

fn mismatched_optional_map_keys<T: PartialEq>(
    actual: Option<&BTreeMap<String, T>>,
    expected: &BTreeMap<String, T>,
) -> Vec<String> {
    actual.map_or_else(
        || expected.keys().cloned().collect(),
        |actual| mismatched_map_keys(actual, expected),
    )
}

fn error_implies_source_access(code: &str) -> bool {
    code.starts_with("source.")
}

fn fixture_preflight(
    _loaded: &LoadedCountryProject,
    _integration_alias: &str,
    fixture: &FixtureDocument,
) -> std::result::Result<(), String> {
    if fixture.request_overrides.is_some() {
        return Err("fixture.request_override_forbidden".to_string());
    }
    Ok(())
}

fn fixture_requires_product_pre_relay_denial(
    loaded: &LoadedCountryProject,
    integration_alias: &str,
    fixture: &FixtureDocument,
) -> bool {
    fixture.request_context.as_ref().is_some_and(|context| {
        context.caller.starts_with("unauthorized")
            || !context.scopes.is_empty()
            || !loaded.project.services.values().any(|service| {
                service.kind == ServiceKind::Evidence
                    && service.purpose == context.purpose
                    && service
                        .consultations
                        .values()
                        .any(|consultation| consultation.integration == integration_alias)
            })
    })
}

fn evaluate_product_claims(
    loaded: &LoadedCountryProject,
    compiled: &CompiledCountry,
    integration_alias: &str,
    fixture: &FixtureDocument,
    relay_result: Option<(&BTreeMap<String, Value>, &str)>,
) -> Result<std::result::Result<BTreeMap<String, Value>, String>> {
    use registry_notary_core::{
        ClaimRef, EvaluateRequest, EvidenceEntity, EvidenceIdentifier, RequestVariables,
        FORMAT_CLAIM_RESULT_JSON,
    };
    use registry_notary_server::standalone::{
        OfflineAuthentication, OfflineNotaryHarness, OfflineNotaryRequest,
        OfflineRelayConsultation, OfflineRelayOutcome,
    };

    let empty_facts = BTreeMap::new();
    let (facts, outcome) = relay_result.unwrap_or((&empty_facts, "no_match"));
    let relay_outcome = match outcome {
        "match" => OfflineRelayOutcome::Match,
        "no_match" => OfflineRelayOutcome::NoMatch,
        "ambiguous" => OfflineRelayOutcome::Ambiguous,
        _ => bail!("offline Relay returned an unknown product outcome"),
    };
    let relay_inputs = fixture
        .input
        .iter()
        .map(|(name, value)| {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow!("fixture input is not a bounded string"))?;
            Ok((name.clone(), value.to_string()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let relay_evidence = compiled
        .fixture_profiles
        .iter()
        .filter(|profile| profile.integration_alias == integration_alias)
        .map(|profile| {
            let purpose = &loaded.project.services[&profile.service_id].purpose;
            OfflineRelayConsultation::decoded_inputs(
                profile.id.clone(),
                profile.version.clone(),
                profile.contract_hash.clone(),
                purpose.clone(),
                relay_inputs.clone(),
                relay_outcome,
                if relay_outcome == OfflineRelayOutcome::Match {
                    facts.clone()
                } else {
                    BTreeMap::new()
                },
            )
        })
        .collect::<Vec<_>>();
    if relay_evidence.is_empty() {
        bail!("offline Notary fixture has no exact Relay consultation profile");
    }
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary_config: StandaloneRegistryNotaryConfig = serde_yaml::from_slice(notary_config)
        .context("generated Notary config did not parse for offline evaluation")?;
    let harness =
        OfflineNotaryHarness::compile(notary_config, relay_evidence, country_cel_worker_config()?)
            .context("production Notary offline harness did not compile")?;
    let authentication =
        fixture
            .request_context
            .as_ref()
            .map_or(OfflineAuthentication::Valid, |context| {
                if context.caller.starts_with("unauthorized") {
                    OfflineAuthentication::WrongCredential
                } else if !context.scopes.is_empty() {
                    OfflineAuthentication::InsufficientScope
                } else {
                    OfflineAuthentication::Valid
                }
            });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the offline Notary evaluation runtime")?;
    let mut claims = BTreeMap::new();
    let mut evaluated_any = false;
    for service in loaded.project.services.values() {
        if service.kind != ServiceKind::Evidence {
            continue;
        }
        let mut claim_groups = BTreeMap::<DisclosureMode, Vec<String>>::new();
        for (claim_id, claim) in &service.claims {
            let consultation = claim_consultation_name(service, claim)?;
            if service.consultations[consultation].integration != integration_alias {
                continue;
            }
            let disclosure = match &claim.disclosure {
                DisclosureDeclaration::Mode(mode) => *mode,
                DisclosureDeclaration::Policy { default, .. } => *default,
            };
            claim_groups
                .entry(disclosure)
                .or_default()
                .push(claim_id.clone());
        }
        if claim_groups.is_empty() {
            continue;
        }
        evaluated_any = true;
        let mut target = EvidenceEntity::new("person");
        let mut identifiers = BTreeMap::new();
        for consultation in service
            .consultations
            .values()
            .filter(|consultation| consultation.integration == integration_alias)
        {
            for (name, request_path) in &consultation.input {
                let value = fixture
                    .input
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("fixture omitted a compiled consultation input"))?;
                if request_path == "request.target.id" {
                    target.id = Some(value.to_string());
                } else if let Some(scheme) =
                    request_path.strip_prefix("request.target.identifiers.")
                {
                    identifiers.insert(scheme.to_string(), value.to_string());
                } else {
                    bail!("compiled consultation input uses an unsupported target path");
                }
            }
        }
        target.identifiers = identifiers
            .into_iter()
            .map(|(scheme, value)| EvidenceIdentifier {
                scheme,
                value,
                issuer: None,
                country: None,
            })
            .collect();
        let variables = fixture
            .variables
            .iter()
            .map(|(name, value)| {
                value
                    .as_str()
                    .map(|value| (name.clone(), value.to_string()))
                    .ok_or_else(|| anyhow!("fixture variable is not a full-date string"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let purpose = fixture
            .request_context
            .as_ref()
            .map_or(service.purpose.as_str(), |context| context.purpose.as_str());
        let variables = RequestVariables::try_new(variables).map_err(|error| anyhow!(error))?;
        for (disclosure, claim_ids) in claim_groups {
            let request = EvaluateRequest {
                requester: None,
                target: Some(target.clone()),
                relationship: None,
                on_behalf_of: None,
                variables: variables.clone(),
                claims: claim_ids
                    .iter()
                    .map(|claim| ClaimRef::from(claim.as_str()))
                    .collect(),
                disclosure: Some(
                    match disclosure {
                        DisclosureMode::Value => "value",
                        DisclosureMode::Predicate => "predicate",
                        DisclosureMode::Redacted => "redacted",
                    }
                    .to_string(),
                ),
                format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                purpose: Some(purpose.to_string()),
            };
            let evidence = runtime.block_on(harness.evaluate(
                OfflineNotaryRequest::new(authentication, request).with_header_purpose(purpose),
            ));
            if evidence.direct_source_calls() != 0 {
                bail!("offline Notary attempted a forbidden direct source read");
            }
            if let Some(error) = evidence.error_class() {
                if fixture_requires_product_pre_relay_denial(loaded, integration_alias, fixture)
                    && evidence.relay_calls() != 0
                {
                    bail!("offline Notary authorization denial occurred after Relay access");
                }
                if !fixture_requires_product_pre_relay_denial(loaded, integration_alias, fixture) {
                    if let Some(product_error_code) = evidence.product_error_code() {
                        bail!("offline Notary product evaluation failed: {product_error_code}");
                    }
                }
                return Ok(Err(error.as_str().to_string()));
            }
            if evidence.relay_calls() != evidence.consultation_count() as u64 {
                bail!("offline Notary did not reuse each request-scoped consultation exactly once");
            }
            for claim in evidence.claims() {
                let value = if claim.disclosure() == "redacted" {
                    Value::String("redacted".to_string())
                } else if claim.disclosure() == "predicate" {
                    claim.satisfied().map_or(Value::Null, Value::Bool)
                } else if let Some(value) = claim.value() {
                    value.clone()
                } else {
                    Value::Null
                };
                if claims.insert(claim.claim_id().to_string(), value).is_some() {
                    bail!("offline Notary returned a duplicate country claim id");
                }
            }
        }
    }
    if !evaluated_any {
        bail!("offline fixture does not select a country Notary service");
    }
    Ok(Ok(claims))
}

fn country_cel_worker_config() -> Result<registry_notary_server::cel_worker::CelWorkerConfig> {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = country_registryctl_program()?;
    config.command_args = vec![std::ffi::OsString::from("__registryctl-cel-worker-v1")];
    config.command_envs.clear();
    config.current_dir = None;
    // Debug and sanitizer builds can take longer than the production worker's
    // evaluation deadline to cold-start the isolated subprocess. Country
    // conformance remains bounded, but must measure the rule rather than the
    // test binary's startup latency.
    config.request_timeout = std::time::Duration::from_secs(10);
    Ok(config)
}

fn country_registryctl_program() -> Result<PathBuf> {
    let current = std::env::current_exe().context("current executable is unavailable")?;
    if current
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "deps")
    {
        let mut candidate = current
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| anyhow!("registryctl worker path is unavailable"))?
            .join("registryctl");
        candidate.set_extension(std::env::consts::EXE_EXTENSION);
        if !candidate.is_file() {
            bail!("registryctl worker executable is unavailable");
        }
        Ok(candidate)
    } else {
        Ok(current)
    }
}

fn execute_fixture<'a>(
    compiled: &CompiledCountry,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    execute_compiled_relay_fixture(compiled, relay_fixture, integration_alias, fixture, calls)
}

fn execute_compiled_relay_fixture<'a>(
    compiled: &CompiledCountry,
    relay_fixture: &registry_relay::offline_fixture::OfflineRelayFixture,
    integration_alias: &str,
    fixture: &'a FixtureDocument,
    calls: &mut Vec<String>,
) -> std::result::Result<(BTreeMap<String, Value>, &'a str), String> {
    use registry_relay::offline_fixture::{
        OfflineFixtureError, OfflineFixtureOutcome, OfflineFixtureRequest, OfflineProfilePin,
        OfflineSourceResponse,
    };

    let source = fixture
        .source
        .iter()
        .map(|(operation, response)| {
            let response = match response {
                FixtureSourceResponse::Http { status, body } => OfflineSourceResponse::Http {
                    status: *status,
                    body: serde_json::to_vec(body)
                        .map_err(|_| "source.response_malformed".to_string())?,
                },
                FixtureSourceResponse::Timeout { timeout } => {
                    parse_duration_ms(timeout)
                        .map_err(|_| "source.deadline_exceeded".to_string())?;
                    OfflineSourceResponse::Timeout
                }
                FixtureSourceResponse::RawBody { status, raw_body } => {
                    OfflineSourceResponse::Http {
                        status: *status,
                        body: raw_body.as_bytes().to_vec(),
                    }
                }
                FixtureSourceResponse::BodyBytes { status, body_bytes } => {
                    OfflineSourceResponse::DeclaredBodyBytes {
                        status: *status,
                        body_bytes: *body_bytes,
                    }
                }
                FixtureSourceResponse::Outcome { outcome }
                    if matches!(
                        outcome.as_str(),
                        "credential_success" | "credential-operation-succeeded"
                    ) =>
                {
                    OfflineSourceResponse::CredentialSuccess
                }
                FixtureSourceResponse::Outcome { outcome } if outcome == "no_match" => {
                    OfflineSourceResponse::NoMatch
                }
                FixtureSourceResponse::Outcome { outcome } if outcome == "unavailable" => {
                    OfflineSourceResponse::Unavailable
                }
                FixtureSourceResponse::Outcome { .. } => {
                    return Err("source.response_malformed".to_string())
                }
            };
            Ok((operation.clone(), response))
        })
        .collect::<std::result::Result<BTreeMap<_, _>, String>>()?;
    let input = fixture
        .input
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_string()))
                .ok_or_else(|| "invalid_input".to_string())
        })
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
    let mut selected = compiled
        .fixture_profiles
        .iter()
        .filter(|profile| profile.integration_alias == integration_alias);
    let first = selected
        .next()
        .ok_or_else(|| "fixture.product_contract_invalid".to_string())?;
    let execute = |profile: &FixtureProfile| {
        relay_fixture.execute(OfflineFixtureRequest {
            profile: OfflineProfilePin {
                id: profile.id.clone(),
                version: profile
                    .version
                    .parse()
                    .map_err(|_| OfflineFixtureError::ProfileNotFound)?,
                contract_hash: profile.contract_hash.clone(),
            },
            input: input.clone(),
            source: source.clone(),
        })
    };
    let observation = execute(first).map_err(map_offline_relay_error)?;
    for profile in selected {
        let sibling = execute(profile).map_err(map_offline_relay_error)?;
        if sibling != observation {
            return Err("fixture.product_contract_invalid".to_string());
        }
    }
    calls.extend(observation.calls);
    let outcome = match observation.outcome {
        OfflineFixtureOutcome::Match => "match",
        OfflineFixtureOutcome::NoMatch => "no_match",
        OfflineFixtureOutcome::Ambiguous => "ambiguous",
    };
    Ok((observation.facts, outcome))
}

fn map_offline_relay_error(error: registry_relay::offline_fixture::OfflineFixtureError) -> String {
    use registry_relay::offline_fixture::OfflineFixtureError;
    match error {
        OfflineFixtureError::InvalidInput => "input.pattern_mismatch",
        OfflineFixtureError::UnknownSourceOperation => "fixture.source_operation_unknown",
        OfflineFixtureError::MissingSourceObservation => "source_unavailable",
        OfflineFixtureError::SourceDeadlineExceeded => "source.deadline_exceeded",
        OfflineFixtureError::SourceUnavailable => "source.unavailable",
        OfflineFixtureError::SourceStatusRejected => "source.status_rejected",
        OfflineFixtureError::SourceResponseTooLarge => "source.response_too_large",
        OfflineFixtureError::SourceResponseMalformed => "source.response_malformed",
        OfflineFixtureError::SourceCardinalityViolation => "source.cardinality_violation",
        OfflineFixtureError::ProfileNotFound => "fixture.profile_not_found",
        OfflineFixtureError::ExecutionContractViolation => "fixture.execution_contract_invalid",
    }
    .to_string()
}

fn validate_operation(
    operation: &OperationDeclaration,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
) -> Result<()> {
    if operation.request.path.is_empty()
        || !operation.request.path.starts_with('/')
        || operation.request.path.contains("..")
        || operation.request.path.contains(['?', '#'])
    {
        bail!("operation path must be a fixed canonical absolute path");
    }
    let closed_credential_post = operation.role == OperationRole::Credential
        && operation.primitive.as_deref() == Some("oauth2_client_credentials")
        && operation.request.codec.as_deref() == Some("oauth2_client_credentials_json_v1");
    if operation.request.method == ReadMethod::Get && operation.request.body.is_some() {
        bail!("reviewed GET operations cannot carry a request body");
    }
    if operation.request.method == ReadMethod::Post
        && operation.request.body.is_none()
        && !closed_credential_post
    {
        bail!("reviewed read-only POST requires a fixed bounded body template");
    }
    match operation.role {
        OperationRole::Credential
            if operation.primitive.as_deref() == Some("oauth2_client_credentials")
                && operation.request.destination == "credential"
                && operation.request.codec.as_deref()
                    == Some("oauth2_client_credentials_json_v1")
                && operation.response.codec.as_deref() == Some("oauth2_token_v1")
                && operation.verification.is_none() => {}
        OperationRole::Verification
            if operation.primitive.as_deref() == Some("jwks_json_v1")
                && operation.request.method == ReadMethod::Get
                && operation.request.destination == "data"
                && operation.request.codec.is_none()
                && operation.request.authorization.is_none()
                && operation.response.codec.as_deref() == Some("jwks_json_v1")
                && operation.verification.is_none() => {}
        OperationRole::Data if operation.primitive.as_deref() == Some("dci_search_v1") => {
            let verification = operation
                .verification
                .as_ref()
                .ok_or_else(|| anyhow!("DCI search requires a closed JWS verification binding"))?;
            let (jwks_operation, jwks_output) = verification
                .jwks
                .split_once('.')
                .ok_or_else(|| anyhow!("DCI JWS verification must name a prior JWKS output"))?;
            let authorization = match operation.request.authorization.as_ref() {
                Some(ValueSource::Prior { prior }) => Some(prior.as_str()),
                _ => None,
            };
            let authorization_is_anchored = authorization
                .and_then(|authorization| authorization.split_once('.'))
                .is_some_and(|(operation, field)| {
                    field == "access_token" && prior.contains(operation)
                });
            if verification.primitive != "dci_jws_v1"
                || jwks_output != "keys"
                || !prior.contains(jwks_operation)
                || operation.request.codec.as_deref() != Some("dci_search_v1")
                || operation.request.destination != "data"
                || operation.response.codec.as_deref() != Some("dci_search_response_v1")
                || !authorization_is_anchored
            {
                bail!("DCI search uses an unsupported or unanchored verification shape");
            }
            validate_dci_exact_and(operation, inputs)?;
        }
        OperationRole::Data
            if operation.primitive.as_deref() == Some("fhir_r4_search_get")
                && operation.request.method == ReadMethod::Get
                && operation.request.destination == "data"
                && operation.request.codec.as_deref() == Some("fhir_r4_search_get")
                && operation.request.authorization.is_none()
                && operation.response.codec.as_deref() == Some("fhir_r4_searchset")
                && operation.verification.is_none()
                && operation
                    .response
                    .cardinality
                    .as_ref()
                    .is_some_and(|cardinality| {
                        cardinality.mode == CardinalityMode::ProbeTwo
                            && cardinality.records.is_none()
                    }) => {}
        OperationRole::Data
            if operation.primitive.is_none()
                && operation.verification.is_none()
                && operation.request.destination == "data"
                && operation.request.authorization.is_none()
                && operation.response.codec.is_none()
                && matches!(
                    (operation.request.method, operation.request.codec.as_deref()),
                    (ReadMethod::Get, None) | (ReadMethod::Post, Some("strict_json_v1"))
                ) => {}
        _ => bail!("operation role and reviewed primitive do not form a supported closed shape"),
    }
    if operation.request.path_parameters.len() > 1 {
        bail!("operation path supports at most one reviewed path parameter");
    }
    let mut fixed_path = operation.request.path.clone();
    for (parameter, source) in &operation.request.path_parameters {
        validate_stable_id(parameter, "path parameter")?;
        if is_sensitive_authored_name(parameter) {
            bail!("request path parameter names cannot carry credential material");
        }
        let marker = format!("{{{parameter}}}");
        if !operation.request.path.contains(&marker)
            || operation.request.path.matches(&marker).count() != 1
            || !operation.request.path.ends_with(&format!("/{marker}"))
        {
            bail!("path parameter must be the single final operation path segment");
        }
        fixed_path = fixed_path.replace(&marker, "");
        validate_operation_value_source(source, inputs, prior)?;
    }
    if fixed_path.contains(['{', '}']) {
        bail!("operation path contains an undeclared path parameter");
    }
    for (name, source) in &operation.request.query {
        if is_sensitive_authored_name(name) {
            bail!("request query names cannot carry credential material");
        }
        validate_operation_value_source(source, inputs, prior)?;
    }
    for (name, source) in &operation.request.headers {
        if !is_safe_authored_header_name(name) {
            bail!("request header is outside the closed non-credential allow-list");
        }
        if !matches!(
            source,
            ValueSource::Value {
                value: Value::String(_)
            }
        ) {
            bail!("request headers must use fixed bounded string values");
        }
        validate_operation_value_source(source, inputs, prior)?;
    }
    if let Some(authorization) = &operation.request.authorization {
        validate_operation_value_source(authorization, inputs, prior)?;
    }
    if let Some(body) = &operation.request.body {
        let mut nodes = 0_usize;
        validate_body_template_sources(body, inputs, prior, 1, &mut nodes)?;
    }
    if operation
        .depends_on
        .iter()
        .any(|dependency| !prior.contains(dependency.as_str()))
    {
        bail!("operation dependency is not an earlier operation");
    }
    if operation.response.statuses.is_empty()
        || operation.response.statuses.iter().any(|status| {
            !(200..300).contains(status)
                && operation
                    .response
                    .status_semantics
                    .as_ref()
                    .is_none_or(|semantics| {
                        !semantics.no_match.contains(status)
                            && !semantics.ambiguous.contains(status)
                    })
        })
        || operation.response.max_bytes == 0
        || operation.response.max_bytes > 256 * 1024
    {
        bail!("operation response bounds are invalid");
    }
    if let Some(semantics) = &operation.response.status_semantics {
        if semantics.no_match.is_empty() && semantics.ambiguous.is_empty() {
            bail!("status semantics must declare at least one non-success outcome");
        }
        let mut statuses = BTreeSet::new();
        for status in semantics.no_match.iter().chain(&semantics.ambiguous) {
            if (200..300).contains(status)
                || !operation.response.statuses.contains(status)
                || !statuses.insert(status)
            {
                bail!("status semantics must partition declared non-success statuses");
            }
        }
    }
    Ok(())
}

fn validate_dci_exact_and(
    operation: &OperationDeclaration,
    inputs: &BTreeMap<String, InputDeclaration>,
) -> Result<()> {
    let components = operation
        .request
        .body
        .as_ref()
        .and_then(|body| body.get("exact_and"))
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("DCI request must declare one exact_and selector map"))?;
    if components.keys().ne(inputs.keys()) {
        bail!("DCI exact_and keys must equal the integration input keys");
    }
    if operation
        .request
        .body
        .as_ref()
        .is_some_and(|body| body.get("identifier_type").is_some())
        && components.len() != 1
    {
        bail!("DCI identifier_type wire compatibility is limited to one exact component");
    }
    let record = operation_record_schema(operation)?;
    let mut fields = BTreeSet::new();
    let mut pointers = BTreeSet::new();
    for (input, component) in components {
        let component = component
            .as_object()
            .filter(|component| {
                component.len() == 2
                    && component.contains_key("field")
                    && component.contains_key("response_pointer")
            })
            .ok_or_else(|| {
                anyhow!("DCI exact_and component must contain only field and response_pointer")
            })?;
        let field = component["field"]
            .as_str()
            .ok_or_else(|| anyhow!("DCI exact_and field must be a string"))?;
        validate_stable_id(field, "DCI exact predicate field")?;
        let pointer = component["response_pointer"]
            .as_str()
            .ok_or_else(|| anyhow!("DCI exact_and response_pointer must be a string"))?;
        let response = resolve_schema_pointer(record, pointer)?;
        if !fields.insert(field) || !pointers.insert(pointer) {
            bail!("DCI exact_and fields and response pointers must be injective");
        }
        let same_type = matches!(
            (&inputs[input].input_type, response),
            (InputType::String, SchemaNode::String { .. })
                | (InputType::FullDate, SchemaNode::Date)
        );
        if !same_type {
            bail!("DCI exact_and response pointer type must match its consultation input");
        }
    }
    Ok(())
}

fn resolve_schema_pointer<'a>(mut schema: &'a SchemaNode, pointer: &str) -> Result<&'a SchemaNode> {
    if !pointer.starts_with('/') || pointer.len() > 1024 || pointer.contains('~') {
        bail!("DCI exact_and response pointer must be canonical and bounded");
    }
    for token in pointer[1..].split('/') {
        if token.is_empty() {
            bail!("DCI exact_and response pointer contains an empty token");
        }
        if matches!(schema, SchemaNode::Array { .. })
            && (!token.bytes().all(|byte| byte.is_ascii_digit())
                || (token != "0" && token.starts_with('0')))
        {
            bail!("DCI exact_and response pointer contains a noncanonical array index");
        }
        schema = match schema {
            SchemaNode::Object { fields, .. } => {
                let field = fields.get(token).ok_or_else(|| {
                    anyhow!("DCI exact_and response pointer is outside the signed record schema")
                })?;
                if !field.required {
                    bail!("DCI exact_and response pointer must traverse required fields");
                }
                &field.schema
            }
            SchemaNode::Array { items, .. }
                if token.bytes().all(|byte| byte.is_ascii_digit())
                    && (token == "0" || !token.starts_with('0')) =>
            {
                items
            }
            _ => bail!("DCI exact_and response pointer does not resolve to a scalar"),
        };
    }
    match schema {
        SchemaNode::String { .. } | SchemaNode::Date => Ok(schema),
        _ => bail!("DCI exact_and response pointer must resolve to a string or full-date scalar"),
    }
}

fn validate_operation_value_source(
    source: &ValueSource,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
) -> Result<()> {
    if let ValueSource::Input { input } = source {
        if !inputs.contains_key(input) {
            bail!("operation references an undeclared consultation input");
        }
    }
    if let ValueSource::Value { value } = source {
        let valid = match value {
            Value::String(value) => {
                value.len() <= 4096
                    && !value.chars().any(char::is_control)
                    && !looks_like_credential_literal(value)
            }
            Value::Bool(_) => true,
            Value::Number(value) => value
                .as_i64()
                .is_some_and(|value| value.unsigned_abs() <= ((1_u64 << 53) - 1)),
            Value::Null | Value::Array(_) | Value::Object(_) => false,
        };
        if !valid {
            bail!("operation literal must be one bounded JSON-safe scalar");
        }
    }
    if let ValueSource::Prior { prior: output } = source {
        let operation = output
            .split_once('.')
            .map(|(operation, _)| operation)
            .ok_or_else(|| anyhow!("prior output must name operation.field"))?;
        if !prior.contains(operation) {
            bail!("operation references a non-prior output");
        }
    }
    Ok(())
}

fn validate_body_template_sources(
    value: &Value,
    inputs: &BTreeMap<String, InputDeclaration>,
    prior: &BTreeSet<&str>,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| anyhow!("request body template node count overflowed"))?;
    if depth > 8 || *nodes > 256 {
        bail!("request body template exceeds its structural bound");
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(value)
            if value
                .as_i64()
                .is_some_and(|value| value.unsigned_abs() <= ((1_u64 << 53) - 1)) =>
        {
            Ok(())
        }
        Value::Number(_) => bail!("request body numbers must be exact JSON-safe integers"),
        Value::String(value)
            if value.len() <= 4096
                && !value.chars().any(char::is_control)
                && !looks_like_credential_literal(value) =>
        {
            Ok(())
        }
        Value::String(_) => bail!("request body string exceeds its bound"),
        Value::Array(items) => {
            if items.len() > 32 {
                bail!("request body array exceeds its static bound");
            }
            for item in items {
                validate_body_template_sources(item, inputs, prior, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("input") => {
            let input = object["input"]
                .as_str()
                .ok_or_else(|| anyhow!("request body input expression is invalid"))?;
            if !inputs.contains_key(input) {
                bail!("request body references an undeclared consultation input");
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("prior") => {
            let prior_output = object["prior"]
                .as_str()
                .ok_or_else(|| anyhow!("request body prior expression is invalid"))?;
            let operation = prior_output
                .split_once('.')
                .map(|(operation, _)| operation)
                .ok_or_else(|| anyhow!("request body prior output is invalid"))?;
            if !prior.contains(operation) {
                bail!("request body references a non-prior output");
            }
            Ok(())
        }
        Value::Object(object) if object.len() == 1 && object.contains_key("value") => {
            validate_body_template_sources(&object["value"], inputs, prior, depth + 1, nodes)
        }
        Value::Object(object) => {
            if object.is_empty() || object.len() > 32 {
                bail!("request body object exceeds its static bound");
            }
            for (name, value) in object {
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    bail!("request body field name is invalid");
                }
                if is_sensitive_authored_name(name) {
                    bail!("request body field names cannot carry credential material");
                }
                validate_body_template_sources(value, inputs, prior, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn is_sensitive_authored_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "authorization",
        "apikey",
        "password",
        "passwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "credential",
        "clientsecret",
        "privatekey",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

fn is_safe_authored_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "accept"
            | "accept-language"
            | "content-type"
            | "data-purpose"
            | "x-locale"
            | "x-projection"
    )
}

fn looks_like_credential_literal(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed.len() > 8192
        || trimmed.starts_with("Bearer ")
        || trimmed.starts_with("Basic ")
        || trimmed.contains("-----BEGIN PRIVATE KEY-----")
        || trimmed.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
}

fn validate_fact(
    declaration: &FactDeclaration,
    operations: &BTreeMap<String, OperationDeclaration>,
) -> Result<()> {
    let (operation, path) = declaration.from.split_once('.').ok_or_else(|| {
        anyhow!("fact mapping must name operation.presence or operation.record.path")
    })?;
    if !operations.contains_key(operation) {
        bail!("fact mapping references an unknown operation");
    }
    if path == "presence" {
        if !matches!(
            declaration.fact_type,
            FactType::Presence | FactType::Boolean
        ) || declaration.nullable
        {
            bail!("presence mapping must use a non-null Boolean or presence type");
        }
    } else if path.split('.').any(|segment| {
        segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-'))
    }) {
        bail!("fact mapping must use a static record path");
    }
    if declaration.fact_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("string fact requires a positive bounded max_bytes");
    }
    if declaration.fact_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only string facts may declare max_bytes");
    }
    if declaration.fact_type == FactType::Presence && path != "presence" {
        bail!("presence facts must map an operation presence outcome");
    }
    if path != "presence" {
        let operation = operations
            .get(operation)
            .expect("fact operation presence was checked");
        let mut schema = operation_record_schema(operation)?;
        let path = path.strip_prefix("record.").unwrap_or(path);
        for segment in path.split('.') {
            schema = match schema {
                SchemaNode::Object { fields, .. } => {
                    let field = fields
                        .get(segment)
                        .ok_or_else(|| anyhow!("fact path is absent from the response schema"))?;
                    if !field.required {
                        bail!("fact paths must traverse required response fields");
                    }
                    &field.schema
                }
                _ => bail!("fact path traverses a non-object response schema"),
            };
        }
        let matches = match (declaration.fact_type, schema) {
            (FactType::Boolean, SchemaNode::Boolean) => true,
            (FactType::Integer, SchemaNode::Integer { .. }) => true,
            (FactType::String, SchemaNode::String { max_bytes }) => {
                declaration.max_bytes == Some(*max_bytes)
            }
            (FactType::Date, SchemaNode::Date) => true,
            (FactType::Presence, _) | (_, _) => false,
        };
        if !matches {
            bail!("fact type or bound does not exactly match its response schema field");
        }
    }
    Ok(())
}

fn validate_snapshot_fact(name: &str, declaration: &FactDeclaration) -> Result<()> {
    let (source, field) = declaration
        .from
        .split_once('.')
        .ok_or_else(|| anyhow!("snapshot fact mapping must name snapshot.field"))?;
    let field = field.strip_prefix("record.").unwrap_or(field);
    if source != "snapshot" || field.contains('.') {
        bail!("snapshot facts must use one flat logical snapshot field");
    }
    if field == "presence" {
        if name != "exists"
            || !matches!(
                declaration.fact_type,
                FactType::Boolean | FactType::Presence
            )
            || declaration.nullable
            || declaration.max_bytes.is_some()
        {
            bail!("snapshot presence must be the non-null exists fact");
        }
        return Ok(());
    }
    validate_stable_id(field, "snapshot logical field")?;
    if name != field {
        bail!("snapshot fact ids must equal their logical projected field names");
    }
    if declaration.fact_type == FactType::Presence {
        bail!("presence facts must map snapshot.presence");
    }
    if declaration.fact_type == FactType::String
        && declaration
            .max_bytes
            .is_none_or(|bound| bound == 0 || bound > 64 * 1024)
    {
        bail!("snapshot string fact requires a positive bounded max_bytes");
    }
    if declaration.fact_type != FactType::String && declaration.max_bytes.is_some() {
        bail!("only snapshot string facts may declare max_bytes");
    }
    Ok(())
}

fn integration_operations(
    integration: &IntegrationDocument,
) -> &BTreeMap<String, OperationDeclaration> {
    match &integration.capability {
        CapabilityDeclaration::BoundedHttp { bounded_http } => &bounded_http.operations,
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => &sandboxed_rhai.operations,
        CapabilityDeclaration::SnapshotExact { .. } => {
            static EMPTY: std::sync::LazyLock<BTreeMap<String, OperationDeclaration>> =
                std::sync::LazyLock::new(BTreeMap::new);
            &EMPTY
        }
    }
}

fn ordered_operations(
    operations: &BTreeMap<String, OperationDeclaration>,
) -> Result<Vec<(&String, &OperationDeclaration)>> {
    let mut ordered = Vec::with_capacity(operations.len());
    let mut emitted = BTreeSet::new();
    while ordered.len() < operations.len() {
        let before = ordered.len();
        for (id, operation) in operations {
            if emitted.contains(id)
                || !operation
                    .depends_on
                    .iter()
                    .all(|dependency| emitted.contains(dependency))
            {
                continue;
            }
            if operation
                .depends_on
                .iter()
                .any(|dependency| !operations.contains_key(dependency))
            {
                bail!("operation dependency references an unknown operation");
            }
            emitted.insert(id.clone());
            ordered.push((id, operation));
        }
        if ordered.len() == before {
            bail!("operation dependency graph contains a cycle");
        }
    }
    Ok(ordered)
}

fn credential_interface(integration: &IntegrationDocument) -> &CredentialInterface {
    match &integration.capability {
        CapabilityDeclaration::BoundedHttp { bounded_http } => &bounded_http.credential,
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => &sandboxed_rhai.credential,
        CapabilityDeclaration::SnapshotExact { .. } => {
            static NONE: CredentialInterface = CredentialInterface {
                credential_type: CredentialType::None,
                name: None,
                max_value_bytes: None,
            };
            &NONE
        }
    }
}

fn integration_script(integration: &IntegrationDocument) -> Option<&Path> {
    match &integration.capability {
        CapabilityDeclaration::SandboxedRhai { sandboxed_rhai } => {
            Some(sandboxed_rhai.script.as_path())
        }
        CapabilityDeclaration::BoundedHttp { .. } | CapabilityDeclaration::SnapshotExact { .. } => {
            None
        }
    }
}

fn validate_generated_product_configs(compiled: &CompiledCountry) -> Result<()> {
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    validate_generated_relay(relay_config, &compiled.relay_private)?;
    validate_generated_notary(compiled)
}

fn validate_generated_notary(compiled: &CompiledCountry) -> Result<()> {
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary: StandaloneRegistryNotaryConfig =
        serde_yaml::from_slice(notary_config).context("generated Notary config did not parse")?;
    notary
        .validate()
        .context("generated Notary config failed the production validator")?;
    Ok(())
}

fn validate_generated_relay(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<()> {
    compile_generated_relay_fixture(relay_config, files).map(drop)?;
    validate_generated_relay_activation(relay_config, files)
}

fn validate_generated_relay_activation(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<()> {
    let validation_root = GeneratedValidationDirectory::create()?;
    write_file_map(&validation_root.path, files)?;
    let config_path = validation_root.path.join("config/relay.yaml");
    let mut local_config: Value = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse for activation validation")?;
    local_config["deployment"]["profile"] = Value::String("local".to_string());
    fs::remove_file(&config_path)
        .context("failed to stage generated Relay activation validation")?;
    write_private_file(
        &config_path,
        serde_yaml::to_string(&local_config)?.as_bytes(),
    )?;
    let mut loaded = registry_relay::config::load_with_metadata(&config_path)
        .map_err(|_| anyhow!("generated Relay config failed production loading"))?;
    let artifacts = loaded
        .consultation_artifacts
        .take()
        .ok_or_else(|| anyhow!("generated Relay consultation artifacts were not loaded"))?;
    registry_relay::consultation::ConsultationService::validate_configuration(
        &loaded.runtime,
        artifacts,
    )
    .context("generated Relay config failed production consultation activation validation")
}

struct GeneratedValidationDirectory {
    path: PathBuf,
}

impl GeneratedValidationDirectory {
    fn create() -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .context("failed to create generated validation directory identity")?;
            let path = std::env::temp_dir().join(format!(
                "registryctl-country-validation-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("failed to create generated validation directory")
                }
            }
        }
        bail!("failed to allocate a unique generated validation directory")
    }
}

impl Drop for GeneratedValidationDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn compile_generated_relay_fixture(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<registry_relay::offline_fixture::OfflineRelayFixture> {
    let runtime: registry_relay::config::Config = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse with the production model")?;
    registry_relay::config::validate::run(&runtime).map_err(|error| {
        anyhow!("generated Relay config failed the production startup validator: {error:?}")
    })?;
    let config: Value = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse as strict YAML")?;
    let artifacts = config
        .pointer("/consultation/artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("generated Relay consultation artifact closure is absent"))?;
    let public = generated_pinned_artifacts(files, artifacts, "public_contracts")?;
    let packs = generated_pinned_artifacts(files, artifacts, "integration_packs")?;
    let bindings = generated_binding_artifacts(files, artifacts)?;
    let evidence = generated_evidence(files, artifacts)?;
    let public_refs = public
        .iter()
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let pack_refs = packs
        .iter()
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let binding_refs = bindings.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence_refs = evidence
        .iter()
        .map(|(class, bytes, hash)| PinnedEvidenceArtifact::new(*class, bytes, hash))
        .collect::<Vec<_>>();
    let bundle = SourcePlanArtifactBundle::new(&public_refs, &pack_refs, &binding_refs)
        .with_evidence(&evidence_refs);
    registry_relay::offline_fixture::OfflineRelayFixture::compile(&bundle)
        .context("generated Relay artifacts failed the production source-plan compiler")
}

fn generated_pinned_artifacts(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
    field: &str,
) -> Result<Vec<(Vec<u8>, String)>> {
    closure
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay artifact list {field} is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated artifact path is invalid"))?;
            let hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated typed artifact hash is invalid"))?;
            let raw_hash = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated raw artifact hash is invalid"))?;
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated artifact is not vendored in Relay input"))?;
            if sha256_uri(bytes) != raw_hash {
                bail!("generated artifact raw digest does not match its vendored bytes");
            }
            Ok((bytes.to_vec(), hash.to_owned()))
        })
        .collect()
}

fn generated_binding_artifacts(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
) -> Result<Vec<Vec<u8>>> {
    closure
        .get("private_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay private binding closure is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated artifact path is invalid"))?;
            let expected_hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated private binding typed hash is invalid"))?;
            let expected_raw = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated private binding raw hash is invalid"))?;
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated artifact is not vendored in Relay input"))?;
            if sha256_uri(bytes) != expected_raw {
                bail!("generated private binding raw digest does not match its vendored bytes");
            }
            let binding = compile_private_binding(bytes)
                .context("generated private binding failed exact typed revalidation")?;
            if binding.typed_hash() != expected_hash {
                bail!(
                    "generated private binding typed hash does not match its normalized identity"
                );
            }
            Ok(bytes.to_vec())
        })
        .collect()
}

fn generated_evidence(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
) -> Result<Vec<(EvidenceClass, Vec<u8>, String)>> {
    closure
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay evidence closure is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated evidence path is invalid"))?;
            let class = match entry.get("class").and_then(Value::as_str) {
                Some("conformance") => EvidenceClass::Conformance,
                Some("negative_security") => EvidenceClass::NegativeSecurity,
                Some("minimization") => EvidenceClass::Minimization,
                _ => bail!("generated evidence class is invalid"),
            };
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated evidence is not vendored in Relay input"))?;
            let hash = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated evidence hash is invalid"))?
                .to_string();
            if sha256_uri(bytes) != hash {
                bail!("generated evidence digest does not match its vendored bytes");
            }
            Ok((class, bytes.to_vec(), hash))
        })
        .collect()
}

fn write_compiled_country(root: &Path, output: &Path, compiled: &CompiledCountry) -> Result<()> {
    let expected_parent = root.join(BUILD_ROOT);
    let parent = output
        .parent()
        .ok_or_else(|| anyhow!("generated output has no parent"))?;
    if parent != expected_parent || output.file_name().is_none() {
        bail!("generated output must remain under the selected environment build root");
    }
    reject_symlink_components(root, &expected_parent)?;
    fs::create_dir_all(&expected_parent)
        .with_context(|| format!("failed to create {}", expected_parent.display()))?;
    reject_symlink_components(root, &expected_parent)?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("generated output name is invalid"))?;
    let temporary = expected_parent.join(format!(".{name}.tmp-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .with_context(|| format!("failed to remove stale {}", temporary.display()))?;
    }
    create_dir_owner_only(&temporary)?;
    let reviewable_root = temporary.join("reviewable");
    let relay_root = temporary.join("private/relay");
    let notary_root = temporary.join("private/notary");
    create_dir_owner_only(&reviewable_root)?;
    create_dir_owner_only(&relay_root)?;
    create_dir_owner_only(&notary_root)?;
    write_file_map(&reviewable_root, &compiled.reviewable)?;
    write_file_map(&relay_root, &compiled.relay_private)?;
    write_file_map(&notary_root, &compiled.notary_private)?;
    let review_bytes = canonical_json_line(&compiled.review)?;
    write_private_file(&reviewable_root.join("review.json"), &review_bytes)?;
    write_private_file(&relay_root.join("approval/review.json"), &review_bytes)?;
    write_private_file(&notary_root.join("approval/review.json"), &review_bytes)?;

    let backup = expected_parent.join(format!(".{name}.previous-{}", std::process::id()));
    if backup.exists() {
        fs::remove_dir_all(&backup)
            .with_context(|| format!("failed to remove stale {}", backup.display()))?;
    }
    if output.exists() {
        reject_symlink(output)?;
        fs::rename(output, &backup)
            .with_context(|| format!("failed to stage prior build {}", output.display()))?;
    }
    if let Err(error) = fs::rename(&temporary, output) {
        if backup.exists() {
            let _ = fs::rename(&backup, output);
        }
        return Err(error).with_context(|| format!("failed to publish {}", output.display()));
    }
    if backup.exists() {
        fs::remove_dir_all(&backup)
            .with_context(|| format!("failed to remove prior build {}", backup.display()))?;
    }
    Ok(())
}

fn write_file_map(root: &Path, files: &BTreeMap<PathBuf, Box<[u8]>>) -> Result<()> {
    for (relative, bytes) in files {
        validate_relative_authored_path(relative)?;
        write_private_file(&root.join(relative), bytes)?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("generated file has no parent"))?;
    create_dir_owner_only(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

fn copy_embedded_dir(source: &include_dir::Dir<'_>, destination: &Path) -> Result<()> {
    for entry in source.entries() {
        match entry {
            include_dir::DirEntry::Dir(directory) => {
                let target = destination.join(
                    directory
                        .path()
                        .file_name()
                        .ok_or_else(|| anyhow!("embedded starter directory has no file name"))?,
                );
                create_dir_owner_only(&target)?;
                copy_embedded_dir(directory, &target)?;
            }
            include_dir::DirEntry::File(file) => {
                let target = destination.join(
                    file.path()
                        .file_name()
                        .ok_or_else(|| anyhow!("embedded starter file has no file name"))?,
                );
                write_private_file(&target, file.contents())?;
            }
        }
    }
    Ok(())
}

fn validate_baseline_pair(against: Option<&Path>, anchor: Option<&Path>) -> Result<()> {
    if against.is_some() != anchor.is_some() {
        bail!("--against and --anchor must be supplied together");
    }
    Ok(())
}

fn load_verified_baseline(
    against: Option<&Path>,
    anchor: Option<&Path>,
    loaded: &LoadedCountryProject,
) -> Result<Option<VerifiedBaseline>> {
    let (Some(bundle), Some(anchor)) = (against, anchor) else {
        return Ok(None);
    };
    let verified = super::verify_config_bundle_cli(bundle, anchor)?;
    let environment = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("verified baseline requires an explicit environment"))?;
    if !matches!(
        verified.product.as_str(),
        "registry-relay" | "registry-notary"
    ) || verified.environment != environment
    {
        bail!("verified baseline manifest is not bound to this product environment");
    }
    let review_path = bundle.join("approval/review.json");
    let bytes = fs::read(&review_path)
        .with_context(|| format!("verified baseline lacks {}", review_path.display()))?;
    let value = parse_json_strict(&bytes).context("baseline review record is not strict JSON")?;
    if value.get("schema").and_then(Value::as_str) != Some(REVIEW_SCHEMA) {
        bail!("baseline review record has the wrong schema");
    }
    if value.get("registry").and_then(Value::as_str) != Some(loaded.project.registry.id.as_str())
        || value.get("environment").and_then(Value::as_str) != Some(environment)
    {
        bail!("verified baseline review is not bound to this registry and environment");
    }
    Ok(Some(VerifiedBaseline {
        review: value,
        verified_manifest: serde_json::to_value(verified)
            .context("failed to retain verified baseline manifest identity")?,
    }))
}

fn required_reviews(
    loaded: &LoadedCountryProject,
    baseline: Option<&Value>,
) -> BTreeSet<ReviewClass> {
    let Some(baseline) = baseline else {
        return BTreeSet::from([
            ReviewClass::Claim,
            ReviewClass::Integration,
            ReviewClass::CountryPolicy,
            ReviewClass::OperatorSecurity,
        ]);
    };
    let mut reviews = BTreeSet::new();
    for (class, field, current) in [
        (
            ReviewClass::Claim,
            "claim",
            loaded.semantic_digests.claim.as_str(),
        ),
        (
            ReviewClass::Integration,
            "integration",
            loaded.semantic_digests.integration.as_str(),
        ),
        (
            ReviewClass::CountryPolicy,
            "country_policy",
            loaded.semantic_digests.country_policy.as_str(),
        ),
        (
            ReviewClass::OperatorSecurity,
            "operator_security",
            loaded.semantic_digests.operator_security.as_str(),
        ),
    ] {
        if baseline
            .get("semantic_digests")
            .and_then(|digests| digests.get(field))
            .and_then(Value::as_str)
            != Some(current)
        {
            reviews.insert(class);
        }
    }
    reviews
}

fn semantic_change_records(
    loaded: &LoadedCountryProject,
    baseline: Option<&Value>,
) -> Vec<SemanticChange> {
    [
        ("claim", loaded.semantic_digests.claim.as_str()),
        ("integration", loaded.semantic_digests.integration.as_str()),
        (
            "country_policy",
            loaded.semantic_digests.country_policy.as_str(),
        ),
        (
            "operator_security",
            loaded.semantic_digests.operator_security.as_str(),
        ),
    ]
    .into_iter()
    .filter_map(|(dimension, current)| {
        let previous = baseline
            .and_then(|review| review.get("semantic_digests"))
            .and_then(|digests| digests.get(dimension))
            .and_then(Value::as_str);
        (previous != Some(current)).then(|| SemanticChange {
            dimension,
            previous_digest: previous.map(str::to_string),
            current_digest: current.to_string(),
        })
    })
    .collect()
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to stat country project {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("country project root must be a real directory");
    }
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))
}

fn resolve_authored_path(root: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_authored_path(relative)?;
    let path = root.join(relative);
    reject_symlink_components(root, &path)?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve authored file {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("authored file escapes the country project root");
    }
    Ok(canonical)
}

fn resolve_relative_to_file(root: &Path, file: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_authored_path(relative)?;
    let parent = file
        .parent()
        .ok_or_else(|| anyhow!("authored file has no parent"))?;
    let path = parent.join(relative);
    reject_symlink_components(root, &path)?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("authored reference escapes the country project root");
    }
    Ok(canonical)
}

fn validate_relative_authored_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("authored paths must be non-empty and relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                bail!("authored paths must be normalized and cannot traverse")
            }
            Component::Normal(_) => bail!("authored path component is empty"),
        }
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path is outside country project root"))?;
    let mut current = root.to_path_buf();
    reject_symlink(&current)?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("path is not normalized");
        };
        current.push(component);
        if current.exists() {
            reject_symlink(&current)?;
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("symlinks are forbidden at the country authoring boundary");
    }
    Ok(())
}

fn read_authored_file(root: &Path, path: &Path) -> Result<Vec<u8>> {
    reject_symlink_components(root, path)?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_AUTHORED_FILE_BYTES {
        bail!("authored file must be a bounded regular file");
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > MAX_AUTHORED_FILE_BYTES {
        bail!("authored file exceeds the size bound");
    }
    Ok(bytes)
}

fn load_fixtures(
    root: &Path,
    directory: &Path,
    hasher: &mut Sha256,
) -> Result<Vec<(PathBuf, FixtureDocument)>> {
    reject_symlink_components(root, directory)?;
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("failed to stat fixture directory {}", directory.display()))?;
    if !metadata.is_dir() {
        bail!("fixture path must be a directory");
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read fixture directory {}", directory.display()))?
    {
        let entry = entry.context("failed to read fixture directory entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat fixture {}", path.display()))?;
        if metadata.file_type().is_symlink() || metadata.is_dir() {
            bail!("fixture directories may contain only direct regular YAML files");
        }
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            bail!("fixture directory contains an unsupported file");
        }
        paths.push(path);
    }
    paths.sort_by(|left, right| {
        left.file_name()
            .map(std::ffi::OsStr::as_encoded_bytes)
            .cmp(&right.file_name().map(std::ffi::OsStr::as_encoded_bytes))
    });
    if paths.is_empty() || paths.len() > MAX_FIXTURES {
        bail!("integration must contain between one and 128 fixtures");
    }
    paths
        .into_iter()
        .map(|path| {
            let bytes = read_authored_file(root, &path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("fixture escapes country project root"))?;
            hash_authored_file(
                hasher,
                relative
                    .to_str()
                    .ok_or_else(|| anyhow!("fixture path is not Unicode"))?,
                &bytes,
            );
            let fixture = parse_yaml(&bytes, &relative.display().to_string())?;
            Ok((path, fixture))
        })
        .collect()
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_yaml::from_slice(bytes).with_context(|| format!("invalid authored YAML in {label}"))
}

fn hash_authored_file(hasher: &mut Sha256, relative: &str, bytes: &[u8]) {
    hasher.update((relative.len() as u64).to_be_bytes());
    hasher.update(relative.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn create_dir_owner_only(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    Ok(())
}

fn validate_stable_id(value: &str, field: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 96
        || !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        bail!("{field} must match the bounded stable-id grammar");
    }
    Ok(())
}

fn validate_input_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 64
        || !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    {
        bail!("integration input name must match [a-z][a-z0-9_]{{0,63}}");
    }
    Ok(())
}

fn validate_token(value: &str, field: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains(',')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("{field} must be one bounded token");
    }
    Ok(())
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() || scopes.len() > 16 {
        bail!("caller scopes must contain between one and 16 entries");
    }
    let mut unique = BTreeSet::new();
    for scope in scopes {
        validate_token(scope, "scope", 128)?;
        if !unique.insert(scope) {
            bail!("caller scopes contain a duplicate");
        }
    }
    Ok(())
}

fn validate_request_mapping(mapping: &str) -> Result<()> {
    if mapping == "request.target.id" {
        return Ok(());
    }
    let identifier = mapping
        .strip_prefix("request.target.identifiers.")
        .ok_or_else(|| anyhow!("consultation input must use the closed target grammar"))?;
    let mut bytes = identifier.bytes();
    if identifier.is_empty()
        || identifier.len() > 96
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        || !bytes.all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
    {
        bail!("target identifier must match the bounded identifier grammar");
    }
    Ok(())
}

fn validate_disclosure(disclosure: &DisclosureDeclaration) -> Result<()> {
    match disclosure {
        DisclosureDeclaration::Mode(_) => Ok(()),
        DisclosureDeclaration::Policy { default, allowed } => {
            if allowed.is_empty() || !allowed.contains(default) {
                bail!("disclosure policy must allow its default mode");
            }
            let unique = allowed.iter().copied().collect::<BTreeSet<_>>();
            if unique.len() != allowed.len() {
                bail!("disclosure allowed modes contain duplicates");
            }
            Ok(())
        }
    }
}

fn validate_secret_reference(reference: &SecretReference) -> Result<()> {
    let value = reference.secret.as_str();
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 128
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        || !bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
    {
        bail!("secret references must be bounded environment identifiers");
    }
    Ok(())
}

fn validate_environment_credential(
    interface: &CredentialInterface,
    binding: &EnvironmentIntegration,
) -> Result<()> {
    match (&interface.credential_type, &binding.credential) {
        (CredentialType::None, None) => Ok(()),
        (expected, Some(credential))
            if std::mem::discriminant(expected)
                == std::mem::discriminant(&credential.credential_type)
                && credential.generation > 0 =>
        {
            for reference in [
                credential.username.as_ref(),
                credential.password.as_ref(),
                credential.token.as_ref(),
                credential.client_id.as_ref(),
                credential.client_secret.as_ref(),
                credential.value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_secret_reference(reference)?;
            }
            let exact = match credential.credential_type {
                CredentialType::None => false,
                CredentialType::Basic => {
                    credential.username.is_some()
                        && credential.password.is_some()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::StaticBearer => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_some()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::Oauth2ClientCredentials => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_some()
                        && credential.client_secret.is_some()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_some()
                }
                CredentialType::ApiKeyHeader => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_some()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::ApiKeyQuery => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_some()
                        && credential.review == Some(ReviewClassInput::OperatorSecurity)
                        && binding.credential_destination.is_none()
                }
            };
            if !exact {
                bail!("environment credential fields do not match the closed credential type");
            }
            if let Some(destination) = &binding.credential_destination {
                validate_https_origin(&destination.origin, "credential destination")?;
            }
            Ok(())
        }
        _ => bail!("environment credential does not match the reviewed integration interface"),
    }
}

fn validate_https_origin(value: &str, field: &str) -> Result<()> {
    let origin = url::Url::parse(value).with_context(|| format!("{field} is not a URL"))?;
    if origin.scheme() != "https"
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("{field} must be an exact HTTPS origin");
    }
    Ok(())
}

fn validate_absolute_runtime_path(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().as_encoded_bytes().len() > 4096 || !path.is_absolute() {
        bail!("{field} must be one bounded absolute path");
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                bail!("{field} must be normalized and cannot traverse")
            }
        }
    }
    Ok(())
}

fn parse_duration_ms(value: &str) -> Result<u32> {
    parse_duration_ms_with_max(value, 20_000, "deadline")
}

fn parse_duration_ms_with_max(value: &str, maximum: u32, label: &str) -> Result<u32> {
    let milliseconds = if let Some(seconds) = value.strip_suffix('s') {
        seconds.parse::<u32>()?.checked_mul(1000)
    } else if let Some(milliseconds) = value.strip_suffix("ms") {
        Some(milliseconds.parse::<u32>()?)
    } else {
        None
    }
    .ok_or_else(|| anyhow!("{label} must be a bounded positive duration"))?;
    if milliseconds == 0 || milliseconds > maximum {
        bail!("{label} is outside its reviewed bound");
    }
    Ok(milliseconds)
}

fn validate_full_date(value: &str) -> Result<()> {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        bail!("date must use RFC 3339 full-date syntax");
    }
    let year = value[0..4].parse::<i32>()?;
    let month = value[5..7].parse::<u8>()?;
    let day = value[8..10].parse::<u8>()?;
    time::Date::from_calendar_date(
        year,
        time::Month::try_from(month).map_err(|_| anyhow!("date month is invalid"))?,
        day,
    )
    .context("date is invalid")?;
    Ok(())
}

fn canonical_json_line(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonicalize_json(value).context("failed to canonicalize generated JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_code_owned_country_conformance(project: &Path) -> Result<Vec<FixtureReport>> {
        let loaded = load_country_project(project, None)?;
        let offline_environment = offline_fixture_environment(&loaded)?;
        let compiled = compile_country_for_environment(
            &loaded,
            "offline-fixture",
            &offline_environment,
            None,
        )?;
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        // This structural compiler bypass is selected only by this cfg(test)
        // harness. No authored field, CLI flag, environment variable, startup
        // path, or runtime API can request it.
        compile_generated_relay_fixture(relay_config, &compiled.relay_private).map(drop)?;
        validate_generated_notary(&compiled)?;
        let reports = execute_all_fixtures(&loaded, &compiled)?;
        require_passing_fixtures(&reports)?;
        Ok(reports)
    }

    fn country_golden(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/country-authoring")
            .join(name)
    }

    #[test]
    fn code_owned_rhai_conformance_matches_bounded_http_and_is_deterministic() {
        let bounded = run_code_owned_country_conformance(&country_golden("dhis2-tracker"))
            .expect("bounded DHIS2 conformance passes");
        let rhai_project = country_golden("dhis2-sandboxed-rhai");
        let rhai = run_code_owned_country_conformance(&rhai_project)
            .expect("Rhai DHIS2 conformance passes");
        let repeated = run_code_owned_country_conformance(&rhai_project)
            .expect("repeated Rhai DHIS2 conformance passes");
        assert_eq!(
            serde_json::to_value(&rhai).expect("first Rhai report serializes"),
            serde_json::to_value(&repeated).expect("repeated Rhai report serializes"),
            "fresh one-shot workers must produce deterministic fixture reports"
        );

        let rhai_by_name = rhai
            .iter()
            .map(|fixture| (fixture.fixture.as_str(), fixture))
            .collect::<BTreeMap<_, _>>();
        for expected in &bounded {
            let actual = rhai_by_name
                .get(expected.fixture.as_str())
                .unwrap_or_else(|| panic!("Rhai omitted fixture {}", expected.fixture));
            assert_eq!(
                actual.inputs, expected.inputs,
                "{} inputs",
                expected.fixture
            );
            assert_eq!(actual.calls, expected.calls, "{} calls", expected.fixture);
            assert_eq!(actual.facts, expected.facts, "{} facts", expected.fixture);
            assert_eq!(
                actual.claims, expected.claims,
                "{} claims",
                expected.fixture
            );
            assert_eq!(
                actual.outcome, expected.outcome,
                "{} outcome",
                expected.fixture
            );
            assert_eq!(
                actual.passed, expected.passed,
                "{} result",
                expected.fixture
            );
        }
    }

    #[test]
    fn generated_relay_rejects_independent_raw_and_typed_binding_tampering() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/country-authoring/custom-system");
        let loaded = load_country_project(&project, Some("local")).expect("golden project loads");
        let compiled = compile_country(&loaded, None).expect("golden project compiles");
        let relay = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .expect("Relay config exists");
        let original: Value = serde_yaml::from_slice(relay).expect("Relay config parses");

        for field in ["sha256", "hash"] {
            let mut tampered = original.clone();
            tampered["consultation"]["artifacts"]["private_bindings"][0][field] =
                Value::String(format!("sha256:{}", "0".repeat(64)));
            let bytes = serde_yaml::to_string(&tampered).expect("tampered config serializes");
            let error = validate_generated_relay(bytes.as_bytes(), &compiled.relay_private)
                .expect_err("tampered binding pin must fail closed");
            assert!(
                format!("{error:#}").contains("binding"),
                "unexpected {field} diagnostic: {error:#}"
            );
        }
    }

    #[test]
    fn governed_live_result_requires_exact_disclosure_and_source_provenance() {
        let claims = vec!["eligible".to_string()];
        let expected = json!({ "claims": { "eligible": { "satisfied": true } } });
        let response = json!({
            "results": [{
                "claim_id": "eligible",
                "satisfied": true,
                "provenance": { "used": { "source_count": 1 } },
            }],
        });
        assert_eq!(
            validate_live_response(&response, &claims, &expected).expect("exact result passes"),
            claims
        );

        let mut missing_provenance = response;
        missing_provenance["results"][0]["provenance"]["used"]["source_count"] = json!(0);
        assert!(
            validate_live_response(&missing_provenance, &claims, &expected)
                .expect_err("source-free result must fail")
                .to_string()
                .contains("source-backed provenance")
        );
    }

    #[test]
    fn cel_consultation_roots_ignore_string_literals() {
        assert_eq!(
            cel_member_roots("'decoy.exists' == 'x' && person.exists").expect("CEL roots parse"),
            BTreeSet::from(["person".to_string()])
        );
        assert!(cel_member_roots("person.exists && 'unterminated").is_err());
    }

    #[test]
    fn secret_descriptor_includes_named_environment_providers() {
        let descriptor = secret_consumer_descriptor(
            "registry-notary",
            &json!({
                "authentication": {
                    "fingerprint": { "provider": "env", "name": "CALLER_TOKEN_HASH" },
                },
                "audit": {
                    "source": {
                        "provider": "environment",
                        "name": "AUDIT_PSEUDONYM_EPOCH_1",
                    },
                },
            }),
        );
        let consumers = descriptor["consumers"]
            .as_array()
            .expect("descriptor consumers are present");
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "CALLER_TOKEN_HASH"
                && consumer["config_pointer"] == "/authentication/fingerprint/name"
        }));
        assert!(consumers.iter().any(|consumer| {
            consumer["locator"] == "AUDIT_PSEUDONYM_EPOCH_1"
                && consumer["config_pointer"] == "/audit/source/name"
        }));
    }
}
