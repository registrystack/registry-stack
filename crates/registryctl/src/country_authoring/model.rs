// SPDX-License-Identifier: Apache-2.0

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
