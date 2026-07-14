// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProjectStarter {
    Http,
    Dhis2Tracker,
    OpencrvsDci,
    FhirR4,
    Snapshot,
}

impl ProjectStarter {
    const fn directory(self) -> &'static str {
        match self {
            Self::Http => "bounded-http",
            Self::Dhis2Tracker => "dhis2-tracker",
            Self::OpencrvsDci => "opencrvs-dci",
            Self::FhirR4 => "fhir-r4",
            Self::Snapshot => "snapshot",
        }
    }

    fn embedded(self) -> Result<&'static include_dir::Dir<'static>> {
        match self {
            Self::Http => PROJECT_STARTERS
                .get_dir(self.directory())
                .ok_or_else(|| anyhow!("project starter is unavailable")),
            Self::Dhis2Tracker => Ok(&DHIS2_TRACKER_STARTER),
            Self::OpencrvsDci => Ok(&OPENCRVS_DCI_STARTER),
            Self::FhirR4 => Ok(&FHIR_R4_STARTER),
            Self::Snapshot => Ok(&SNAPSHOT_STARTER),
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Dhis2Tracker => "dhis2-tracker",
            Self::OpencrvsDci => "opencrvs-dci",
            Self::FhirR4 => "fhir-r4",
            Self::Snapshot => "snapshot",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProjectInitOptions {
    pub starter: ProjectStarter,
    pub directory: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ProjectTestOptions {
    pub project_directory: PathBuf,
    pub environment: Option<String>,
    pub live: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectTestSelection {
    pub integration: Option<String>,
    pub fixture: Option<String>,
    pub trace: bool,
}

#[derive(Debug, Clone)]
pub struct ProjectCheckOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub explain: bool,
    pub against: Option<PathBuf>,
    pub anchor: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProjectBuildOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub against: Option<PathBuf>,
    pub anchor: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCommandReport {
    pub status: &'static str,
    pub project: String,
    pub environment: Option<String>,
    pub fixtures: Vec<FixtureReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub semantic_changes: Vec<SemanticChange>,
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
    pub outputs: Vec<String>,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryProject {
    version: u8,
    #[serde(default)]
    starter: Option<StarterProvenance>,
    registry: RegistryDeclaration,
    #[serde(default)]
    integrations: BTreeMap<String, IntegrationReference>,
    #[serde(default)]
    entities: BTreeMap<String, EntityReference>,
    services: BTreeMap<String, ServiceDeclaration>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StarterProvenance {
    id: String,
    release: String,
    content_digest: String,
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
struct EntityReference {
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
    credential_profiles: BTreeMap<String, CredentialProfileDeclaration>,
    #[serde(default)]
    entity: Option<String>,
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
    #[serde(default)]
    api: Option<RecordsApiDeclaration>,
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessDeclaration {
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityDefinition {
    version: u8,
    id: String,
    revision: u32,
    primary_key: String,
    schema: EntityObjectSchema,
    materialization: EntityMaterialization,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityObjectSchema {
    #[serde(rename = "type")]
    schema_type: EntityObjectType,
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
    required: Vec<String>,
    properties: BTreeMap<String, EntityFieldSchema>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EntityObjectType {
    Object,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityFieldSchema {
    #[serde(rename = "type")]
    field_type: AuthoredSchemaType,
    #[serde(default)]
    format: Option<AuthoredStringFormat>,
    #[serde(default, rename = "enum")]
    enum_values: Option<Vec<Value>>,
    #[serde(default, rename = "const")]
    const_value: Option<Value>,
    #[serde(default, rename = "minLength")]
    min_length: Option<u32>,
    #[serde(default, rename = "maxLength")]
    max_length: Option<u32>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityMaterialization {
    max_records: u64,
    max_bytes: AuthoredByteSize,
    refresh: String,
    retain_generations: u8,
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
    projection: Vec<String>,
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
    value_type: OutputType,
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
    output: Option<String>,
    #[serde(default)]
    cel: Option<String>,
    #[serde(default)]
    value: Option<ClaimValueDeclaration>,
    disclosure: DisclosureDeclaration,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClaimEvidence {
    RegistryBacked,
    SelfAttested,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimValueDeclaration {
    #[serde(rename = "type")]
    value_type: OutputType,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    max_bytes: Option<u32>,
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
struct CredentialProfileDeclaration {
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
    #[serde(default = "default_integration_revision")]
    revision: u32,
    source: SourceDeclaration,
    input: BTreeMap<String, InputDeclaration>,
    capability: CapabilityDeclaration,
    outputs: BTreeMap<String, OutputDeclaration>,
    #[serde(default)]
    not_applicable: NotApplicableDeclaration,
    bounds: BoundsDeclaration,
    fixtures: PathBuf,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotApplicableDeclaration {
    #[serde(default)]
    ambiguity: Option<NotApplicableReason>,
    #[serde(default)]
    subject_mismatch: Option<NotApplicableReason>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotApplicableReason {
    rationale: String,
    request_fixture: String,
}

fn default_integration_revision() -> u32 {
    1
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDeclaration {
    product: Option<String>,
    versions: SourceVersions,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceVersions {
    #[serde(default)]
    tested: Vec<String>,
    #[serde(default)]
    unverified: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputDeclaration {
    role: AuthoredInputRole,
    #[serde(rename = "type")]
    input_type: InputType,
    nullable: bool,
    #[serde(default, rename = "maxLength")]
    max_length: Option<u16>,
    #[serde(default, rename = "minLength")]
    min_length: Option<u16>,
    bytes: u16,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default, rename = "enum")]
    enum_values: Option<Vec<Value>>,
    #[serde(default, rename = "const")]
    const_value: Option<Value>,
    canonicalization: Canonicalization,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputType {
    String,
    FullDate,
    Boolean,
    Integer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialInterface {
    #[serde(rename = "type")]
    credential_type: CredentialType,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    max_value_bytes: Option<u16>,
    #[serde(default)]
    request: Option<OAuthRequestFormat>,
    #[serde(default)]
    response_profile: Option<OAuthResponseProfile>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    refresh_skew: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OAuthRequestFormat {
    Form,
    Json,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OAuthResponseProfile {
    Oauth2Bearer,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum CapabilityDeclaration {
    Http { http: HttpDeclaration },
    Snapshot { snapshot: SnapshotDeclaration },
    Script { script: Box<ScriptDeclaration> },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpDeclaration {
    credential: CredentialInterface,
    operations: BTreeMap<String, OperationDeclaration>,
    #[serde(skip)]
    response_max_bytes_authored: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptDeclaration {
    runtime: ScriptRuntime,
    credential: CredentialInterface,
    allow: Vec<ScriptAllowRule>,
    request_headers: Vec<String>,
    response_headers: Vec<String>,
    response: ScriptResponseDeclaration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signed_dci: Option<AuthoredSignedDciDeclaration>,
    script: PathBuf,
    modules: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptAllowRule {
    method: ReadMethod,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantics: Option<AuthoredRequestSemantics>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptResponseDeclaration {
    format: AuthoredResponseFormat,
    max_bytes: u32,
    #[serde(skip)]
    max_bytes_authored: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ScriptRuntime {
    RhaiV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDeclaration {
    entity: String,
    exact: BTreeMap<String, String>,
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
    Ignore,
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
enum OutputType {
    Boolean,
    Integer,
    String,
    Date,
    Presence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutputDeclaration {
    #[serde(rename = "type")]
    output_type: OutputType,
    #[serde(default)]
    nullable: bool,
    #[serde(default)]
    max_bytes: Option<u32>,
    #[serde(default)]
    minimum: Option<i64>,
    #[serde(default)]
    maximum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_pointer: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundsDeclaration {
    calls: u8,
    #[serde(skip)]
    calls_authored: bool,
    source_bytes: u64,
    #[serde(skip)]
    source_bytes_authored: bool,
    request_bytes: u32,
    #[serde(skip)]
    request_bytes_authored: bool,
    deadline: String,
    #[serde(skip)]
    deadline_authored: bool,
    concurrency: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDocument {
    version: u8,
    #[serde(default)]
    integrations: BTreeMap<String, EnvironmentIntegration>,
    #[serde(default)]
    entities: BTreeMap<String, EnvironmentEntityBinding>,
    #[serde(default)]
    issuance: Option<IssuanceBinding>,
    #[serde(default)]
    callers: BTreeMap<String, CallerBinding>,
    #[serde(default)]
    relay: Option<RelayBinding>,
    #[serde(default)]
    notary_relay: Option<NotaryRelayBinding>,
    #[serde(default)]
    notary_state: Option<NotaryStateBinding>,
    deployment: DeploymentBinding,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentIntegration {
    source: EnvironmentSourceBinding,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentSourceBinding {
    origin: String,
    #[serde(default)]
    allowed_private_cidrs: Vec<String>,
    #[serde(default)]
    ca: Option<CertificateAuthorityBinding>,
    #[serde(default)]
    mtls: Option<MutualTlsBinding>,
    #[serde(default)]
    credential: Option<EnvironmentCredential>,
    #[serde(default)]
    oauth: Option<PrivateEndpointBinding>,
    #[serde(default)]
    jwks: Option<PrivateEndpointBinding>,
    #[serde(default)]
    rate: Option<SourceRateBinding>,
    #[serde(default)]
    concurrency: Option<u16>,
    #[serde(default)]
    timeout: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateAuthorityBinding {
    file: PathBuf,
    generation: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MutualTlsBinding {
    certificate_file: PathBuf,
    private_key: SecretReference,
    generation: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateEndpointBinding {
    origin: String,
    path: String,
    #[serde(default)]
    allowed_private_cidrs: Vec<String>,
    #[serde(default)]
    ca: Option<CertificateAuthorityBinding>,
    #[serde(default)]
    mtls: Option<MutualTlsBinding>,
    generation: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceRateBinding {
    per_minute: u32,
    burst: u16,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentCredential {
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
    Postgres {
        connection: SecretReference,
        schema: String,
        table: String,
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
struct RelayBinding {
    origin: String,
    issuer: String,
    jwks_url: String,
    audience: String,
    allowed_clients: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryRelayBinding {
    workload_client_id: String,
    token_file: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryStateBinding {
    postgresql: NotaryPostgresqlBinding,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryPostgresqlBinding {
    root_certificate_path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBinding {
    profile: DeploymentProfile,
    #[serde(default)]
    relay: Option<ServiceBinding>,
    #[serde(default)]
    notary: Option<ServiceBinding>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeploymentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

impl DeploymentProfile {
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

#[derive(Debug, Serialize)]
struct FixtureDocument {
    name: String,
    classification: AuthoredFixtureClassification,
    input: BTreeMap<String, Value>,
    #[serde(default)]
    variables: BTreeMap<String, Value>,
    interactions: Vec<FixtureInteraction>,
    expect: FixtureExpectation,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureInteraction {
    expect: FixtureRequestExpectation,
    respond: FixtureSourceResponse,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureRequestExpectation {
    method: ReadMethod,
    path: String,
    query: BTreeMap<String, Value>,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
enum FixtureSourceResponse {
    Http {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Value,
    },
    Timeout {
        timeout: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureExpectation {
    #[serde(default)]
    outputs: BTreeMap<String, Value>,
    #[serde(default)]
    claims: BTreeMap<String, Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
}

struct LoadedRegistryProject {
    root: PathBuf,
    project: RegistryProject,
    environment_name: Option<String>,
    environment: Option<EnvironmentDocument>,
    integrations: BTreeMap<String, LoadedIntegration>,
    entities: BTreeMap<String, LoadedEntityDefinition>,
    authored_hash: String,
    project_content_digest: String,
    semantic_digests: SemanticDigests,
}

struct LoadedEntityDefinition {
    document: EntityDefinition,
}

struct LoadedIntegration {
    document: IntegrationDocument,
    fixtures: Vec<(PathBuf, FixtureDocument)>,
    script: Option<(PathBuf, Box<[u8]>)>,
    script_modules: Vec<(PathBuf, Box<[u8]>)>,
}

struct CompiledProject {
    reviewable: BTreeMap<PathBuf, Box<[u8]>>,
    relay_private: BTreeMap<PathBuf, Box<[u8]>>,
    notary_private: BTreeMap<PathBuf, Box<[u8]>>,
    review: Value,
    approval_state: Value,
    explanation: Value,
    fixture_profiles: Vec<FixtureProfile>,
    semantic_changes: Vec<SemanticChange>,
}

struct FixtureProfile {
    service_id: String,
    integration_alias: String,
    id: String,
    version: String,
    contract_hash: String,
}

struct VerifiedBaseline {
    approval_state: Value,
    verified_manifest: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticDigests {
    claim: String,
    integration: String,
    service_policy: String,
    operator_security: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DisclosureReviewProfile {
    default: DisclosureMode,
    allowed: BTreeSet<DisclosureMode>,
}

type DisclosureReviewProfiles = BTreeMap<String, BTreeMap<String, DisclosureReviewProfile>>;

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
