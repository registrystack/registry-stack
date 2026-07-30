// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectStarter {
    Http,
    Spreadsheet,
    Dhis2Tracker,
    OpencrvsDci,
    FhirR4,
    Snapshot,
}

impl ProjectStarter {
    const fn directory(self) -> &'static str {
        match self {
            Self::Http => "bounded-http",
            Self::Spreadsheet => "spreadsheet",
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
            Self::Spreadsheet => PROJECT_STARTERS
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
            Self::Spreadsheet => "spreadsheet",
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

/// The result of an explicitly requested trusted-local check.
///
/// This type deliberately does not implement `Serialize` or `Debug`.
/// `authored_values` may contain project-sensitive metadata and is only for
/// direct, human-readable terminal review. It must not enter portable reports,
/// logs, generated artifacts, comparison output, or promotion evidence.
pub struct ProjectTrustedLocalCheck {
    pub report: ProjectCommandReport,
    pub authored_values: Vec<ProjectTrustedLocalAuthoredValue>,
}

/// One directly authored, non-secret scalar for trusted-local human review.
///
/// Values classified as secret references, secret values, or redacted fixture
/// data are never constructible through this surface. Runtime secret-file
/// locators, raw parser text, and derived and defaulted values are also
/// excluded.
pub struct ProjectTrustedLocalAuthoredValue {
    address: ProjectFieldAddress,
    source: FieldSourceKind,
    sensitivity: FieldSensitivity,
    value: Value,
}

impl ProjectTrustedLocalAuthoredValue {
    /// Render one bounded, single-line terminal entry.
    ///
    /// No raw value accessor is exposed because this surface is not a
    /// machine-report or export contract.
    pub fn terminal_line(&self) -> Result<String> {
        if !matches!(
            self.source,
            FieldSourceKind::Authored | FieldSourceKind::EnvironmentBound
        ) {
            bail!("only authored values can enter trusted-local authored output");
        }
        if !matches!(
            self.sensitivity,
            FieldSensitivity::Public
                | FieldSensitivity::Internal
                | FieldSensitivity::Structural
                | FieldSensitivity::Sensitive
        ) {
            bail!("secret or fixture data cannot enter trusted-local authored output");
        }
        if matches!(&self.address, ProjectFieldAddress::Fixture { .. }) {
            bail!("fixture data cannot enter trusted-local authored output");
        }
        if trusted_local_value_path_is_prohibited(&self.address) {
            bail!("secret locator or parser input cannot enter trusted-local authored output");
        }
        let address = match &self.address {
            ProjectFieldAddress::Project { path } => {
                format!("project:{}", trusted_local_terminal_escape(path.as_str()))
            }
            ProjectFieldAddress::Integration { integration, path } => format!(
                "integration {}:{}",
                trusted_local_terminal_escape(integration),
                trusted_local_terminal_escape(path.as_str())
            ),
            ProjectFieldAddress::Entity { entity, path } => format!(
                "entity {}:{}",
                trusted_local_terminal_escape(entity),
                trusted_local_terminal_escape(path.as_str())
            ),
            ProjectFieldAddress::Environment { environment, path } => format!(
                "environment {}:{}",
                trusted_local_terminal_escape(environment),
                trusted_local_terminal_escape(path.as_str())
            ),
            // Constructors exclude fixtures. Fail closed if a future internal
            // change violates that invariant.
            ProjectFieldAddress::Fixture { .. } => {
                bail!("fixture data cannot enter trusted-local authored output")
            }
        };
        let value = serde_json::to_string(&self.value)
            .context("trusted-local authored scalar could not be rendered")?;
        Ok(format!(
            "{address} = {} ({}, {})",
            trusted_local_terminal_escape(&value),
            match self.source {
                FieldSourceKind::Authored => "authored",
                FieldSourceKind::EnvironmentBound => "environment-bound",
                FieldSourceKind::Defaulted => "defaulted",
                FieldSourceKind::Detected => "detected",
                FieldSourceKind::Derived => "derived",
                FieldSourceKind::Generated => "generated",
                FieldSourceKind::Runtime => "runtime",
                FieldSourceKind::Absent => "absent",
            },
            match self.sensitivity {
                FieldSensitivity::Public => "public",
                FieldSensitivity::Internal => "internal",
                FieldSensitivity::Sensitive => "sensitive",
                FieldSensitivity::SecretReference => "secret-reference",
                FieldSensitivity::SecretValue => "secret-value",
                FieldSensitivity::RedactedFixture => "redacted-fixture",
                FieldSensitivity::Structural => "structural",
            }
        ))
    }
}

fn trusted_local_terminal_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn trusted_local_value_path_is_prohibited(address: &ProjectFieldAddress) -> bool {
    let path = match address {
        ProjectFieldAddress::Project { path }
        | ProjectFieldAddress::Integration { path, .. }
        | ProjectFieldAddress::Entity { path, .. }
        | ProjectFieldAddress::Environment { path, .. }
        | ProjectFieldAddress::Fixture { path, .. } => path.as_str(),
    };
    let field_name = path.rsplit('/').next().unwrap_or_default();
    matches!(
        field_name,
        "token_file"
            | "workload_token_file"
            | "secret_file"
            | "private_key_file"
            | "cel"
            | "x-registry-source"
    ) || path == "/starter/content_digest"
}

#[derive(Debug, Clone)]
pub struct ProjectBuildOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    pub against: Option<PathBuf>,
    pub anchor: Option<PathBuf>,
}

/// Product-labelled approved baselines for a project build.
///
/// Public Relay, consultation Relay, and Notary are independently signed
/// inputs. A consultation project supplies both Relay pairs, plus Notary when
/// that product is projected. The `against` and `anchor` fields on
/// [`ProjectBuildOptions`] remain available for single-lane callers.
#[derive(Debug, Clone, Default)]
pub struct ProjectBuildBaselineSetOptions {
    pub relay_against: Option<PathBuf>,
    pub relay_anchor: Option<PathBuf>,
    pub relay_consultation_against: Option<PathBuf>,
    pub relay_consultation_anchor: Option<PathBuf>,
    pub notary_against: Option<PathBuf>,
    pub notary_anchor: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProjectPreflightOptions {
    pub project_directory: PathBuf,
    pub environment: String,
}

#[derive(Debug, Clone)]
pub struct ProjectCapabilityOptions {
    pub project_directory: PathBuf,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCommandReport {
    pub schema_version: &'static str,
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
    pub semantic_impact: Option<ProjectSemanticImpactReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_manifest: Option<ProjectArtifactManifestRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixture_coverage: Option<ProjectFixtureCoverageReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<ProjectExplanationReportV1>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectAuthoringDiagnostics {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub diagnostics: Vec<ProjectAuthoringDiagnostic>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectAuthoringDiagnostic {
    pub code: &'static str,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_hint: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<&'static str>,
    /// Machine-readable project-relative locations. `file` and `field` stay
    /// available as the stable compatibility projection used by existing CLI
    /// renderers and integrations.
    pub addresses: Vec<ProjectAuthoringDiagnosticAddress>,
    pub phase: &'static str,
    pub rule: &'static str,
    pub accepted: &'static str,
    pub safe_summary_policy: &'static str,
    pub received_summary: &'static str,
    pub documentation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_behavior: Option<&'static str>,
    pub cause: &'static str,
    pub remediation: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectAuthoringDiagnosticAddress {
    pub file: String,
    /// An RFC 6901 JSON Pointer. The empty pointer identifies the document.
    pub pointer: String,
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StarterProvenance {
    id: String,
    release: String,
    content_digest: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryDeclaration {
    id: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntegrationReference {
    file: PathBuf,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityReference {
    file: PathBuf,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceDeclaration {
    kind: ServiceKind,
    #[serde(default)]
    version: u32,
    /// Subject category evaluated by an evidence service. Omission is
    /// normalized to `person` without erasing whether the field was authored,
    /// so records services cannot silently accept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_type: Option<EvidenceSubjectType>,
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum EvidenceSubjectType {
    #[default]
    Person,
    Project,
}

impl EvidenceSubjectType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Project => "project",
        }
    }
}

impl ServiceDeclaration {
    const fn effective_subject_type(&self) -> EvidenceSubjectType {
        match self.subject_type {
            Some(subject_type) => subject_type,
            None => EvidenceSubjectType::Person,
        }
    }
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ServiceKind {
    Evidence,
    RecordsApi,
}

fn default_consent() -> ConsentDeclaration {
    ConsentDeclaration::NotRequired
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentDeclaration {
    NotRequired,
    Required,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessDeclaration {
    #[serde(default)]
    scopes: Vec<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EntityObjectType {
    Object,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityMaterialization {
    max_records: u64,
    max_bytes: AuthoredByteSize,
    refresh: String,
    retain_generations: u8,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecordSensitivity {
    Public,
    Internal,
    Personal,
    Confidential,
    Secret,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordAccessRights {
    Public,
    Restricted,
    NonPublic,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[serde(default)]
    attribute_release_profiles: BTreeMap<String, RecordAttributeReleaseProfile>,
    standards: RecordStandards,
}

/// A project-authored, entity-bound identity release. The project compiler
/// deliberately exposes only the minimizing subset used by Registry Relay:
/// exact-one subject resolution, purpose binding, and typed claim selection.
/// Source metadata disclosure and response caching are not authoring options.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAttributeReleaseProfile {
    version: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    purpose: String,
    release_scope: String,
    subject: RecordAttributeReleaseSubject,
    release_conditions: RecordAttributeReleaseConditions,
    claims: BTreeMap<String, RecordAttributeReleaseClaim>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAttributeReleaseSubject {
    source_field: String,
    id_type: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAttributeReleaseConditions {
    expression: RecordAttributeReleaseExpression,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAttributeReleaseExpression {
    cel: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAttributeReleaseClaim {
    #[serde(default)]
    source_field: Option<String>,
    #[serde(default)]
    expression: Option<RecordAttributeReleaseExpression>,
    required: bool,
    sensitivity: RecordAttributeReleaseSensitivity,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordAttributeReleaseSensitivity {
    DirectIdentifier,
    Personal,
    Public,
    Pseudonymous,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordPagination {
    default_limit: u32,
    max_limit: u32,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum RecordFilterOperator {
    Eq,
    In,
    Gte,
    Lte,
    Between,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordRelationship {
    kind: RecordRelationshipKind,
    target: String,
    foreign_key: String,
    #[serde(default)]
    concept_uri: Option<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordRelationshipKind {
    BelongsTo,
    HasMany,
    HasOne,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateDimension {
    id: String,
    label: String,
    field: String,
    #[serde(default)]
    codelist: Option<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordAggregateMeasure {
    name: String,
    function: RecordAggregateFunction,
    column: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordSuppression {
    #[default]
    Omit,
    Mask,
    Null,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordStandards {
    ogc_features: RecordStandard<RecordSpatial>,
    sp_dci: RecordStandard<RecordSpdci>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum RecordStandard<T> {
    Enabled(T),
    Disabled(bool),
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordSpatialBbox {
    min_x: String,
    min_y: String,
    max_x: String,
    max_y: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestVariable {
    from: String,
    #[serde(rename = "type")]
    value_type: OutputType,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConsultationDeclaration {
    integration: String,
    input: BTreeMap<String, String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClaimEvidence {
    RegistryBacked,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum DisclosureDeclaration {
    Mode(DisclosureMode),
    Policy {
        default: DisclosureMode,
        allowed: Vec<DisclosureMode>,
    },
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum DisclosureMode {
    Value,
    Predicate,
    Redacted,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialProfileDeclaration {
    format: String,
    #[serde(rename = "type")]
    credential_type: String,
    validity: String,
    claims: Vec<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotApplicableDeclaration {
    #[serde(default)]
    ambiguity: Option<NotApplicableReason>,
    #[serde(default)]
    subject_mismatch: Option<NotApplicableReason>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotApplicableReason {
    rationale: String,
    request_fixture: String,
}

fn default_integration_revision() -> u32 {
    1
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDeclaration {
    product: Option<String>,
    versions: SourceVersions,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceVersions {
    #[serde(default)]
    tested: Vec<String>,
    #[serde(default)]
    unverified: Vec<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InputType {
    String,
    FullDate,
    Boolean,
    Integer,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Canonicalization {
    Identity,
    AsciiLowercase,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OAuthRequestFormat {
    Form,
    Json,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OAuthResponseProfile {
    Oauth2Bearer,
    Oauth2BearerNoExpiry,
}

impl OAuthResponseProfile {
    const fn uses_expiry_bound_cache(self) -> bool {
        match self {
            Self::Oauth2Bearer => true,
            Self::Oauth2BearerNoExpiry => false,
        }
    }
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum CapabilityDeclaration {
    Http { http: HttpDeclaration },
    Snapshot { snapshot: SnapshotDeclaration },
    Script { script: Box<ScriptDeclaration> },
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpDeclaration {
    credential: CredentialInterface,
    operations: BTreeMap<String, OperationDeclaration>,
    #[serde(skip)]
    response_max_bytes_authored: bool,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptAllowRule {
    method: ReadMethod,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    semantics: Option<AuthoredRequestSemantics>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScriptResponseDeclaration {
    format: AuthoredResponseFormat,
    max_bytes: u32,
    #[serde(skip)]
    max_bytes_authored: bool,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ScriptRuntime {
    RhaiV1,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDeclaration {
    entity: String,
    exact: BTreeMap<String, String>,
    cardinality: CardinalityMode,
    freshness: String,
    materialization: SnapshotFootprint,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFootprint {
    max_source_records: u64,
    max_source_bytes: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationDeclaration {
    primitive: String,
    jwks: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OperationRole {
    #[default]
    Data,
    Credential,
    Verification,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum ReadMethod {
    Get,
    Post,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum ValueSource {
    Input { input: String },
    Value { value: Value },
    Prior { prior: String },
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConditionDeclaration {
    prior: String,
    equals: Value,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusSemanticsDeclaration {
    #[serde(default)]
    no_match: Vec<u16>,
    #[serde(default)]
    ambiguous: Vec<u16>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CardinalityDeclaration {
    #[serde(default)]
    records: Option<String>,
    mode: CardinalityMode,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CardinalityMode {
    Singleton,
    ProbeTwo,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

// `SchemaField` has a deliberate hand-written deserializer because `required`
// is flattened into each tagged `SchemaNode` object. Keep its mechanically
// derived structural schema tied to that exact wire shape instead of allowing
// schemars to infer the private storage shape above.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "schema-only wire variants describe a custom deserializer and are never constructed"
)]
#[derive(schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SchemaFieldWireShape {
    Object {
        #[serde(default)]
        required: bool,
        #[serde(default = "reject_additional")]
        additional_fields: AdditionalFields,
        fields: BTreeMap<String, SchemaFieldWireShape>,
    },
    Array {
        #[serde(default)]
        required: bool,
        max_items: u16,
        items: Box<SchemaNode>,
    },
    String {
        #[serde(default)]
        required: bool,
        max_bytes: u32,
    },
    Integer {
        #[serde(default)]
        required: bool,
        min: i64,
        max: i64,
    },
    Boolean {
        #[serde(default)]
        required: bool,
    },
    Date {
        #[serde(default)]
        required: bool,
    },
}

#[cfg(test)]
impl schemars::JsonSchema for SchemaField {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SchemaField".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <SchemaFieldWireShape as schemars::JsonSchema>::json_schema(generator)
    }
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OutputType {
    Boolean,
    Integer,
    String,
    Date,
    Object,
    Array,
    Presence,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StructuredOutputObjectField {
    required: bool,
    schema: Box<StructuredOutputSchema>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum StructuredOutputSchema {
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Date {
        nullable: bool,
    },
    Object {
        nullable: bool,
        max_bytes: u32,
        fields: BTreeMap<String, StructuredOutputObjectField>,
    },
    Array {
        nullable: bool,
        max_bytes: u32,
        max_items: u16,
        items: Box<StructuredOutputSchema>,
    },
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    structured_schema: Option<StructuredOutputSchema>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_pointer: Option<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentDocument {
    version: u8,
    #[serde(default)]
    development: Option<DevelopmentDeclaration>,
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
    relay_state: Option<RelayStateBinding>,
    #[serde(default)]
    notary_state: Option<NotaryStateBinding>,
    #[serde(default)]
    notary_cel: Option<NotaryCelBinding>,
    #[serde(default)]
    oid4vci: Option<Oid4vciBinding>,
    deployment: DeploymentBinding,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevelopmentDeclaration {
    #[cfg_attr(test, schemars(required))]
    #[serde(default)]
    source_mode: Option<DevelopmentSourceMode>,
    #[cfg_attr(test, schemars(required))]
    #[serde(default)]
    default_integration: Option<String>,
    #[cfg_attr(test, schemars(required))]
    #[serde(default)]
    default_fixture: Option<String>,
    #[serde(default)]
    relay_port: Option<u16>,
    #[serde(default)]
    notary_port: Option<u16>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DevelopmentSourceMode {
    Synthetic,
    OperatorBound,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentIntegration {
    source: EnvironmentSourceBinding,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateAuthorityBinding {
    file: PathBuf,
    generation: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MutualTlsBinding {
    certificate_file: PathBuf,
    private_key: SecretReference,
    generation: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceRateBinding {
    per_minute: u32,
    burst: u16,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecretReference {
    secret: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntityBinding {
    provider: RecordProvider,
    columns: BTreeMap<String, String>,
    source_revision: String,
    generation: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
        project_file: PathBuf,
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceBinding {
    issuer: String,
    signing_key: SecretReference,
    signing_kid: String,
    #[serde(default)]
    algorithm: IssuanceSigningAlgorithm,
    generation: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
enum IssuanceSigningAlgorithm {
    #[default]
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
}

impl IssuanceSigningAlgorithm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CallerBinding {
    api_key_fingerprint: SecretReference,
    scopes: Vec<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayBinding {
    origin: String,
    issuer: String,
    jwks_url: String,
    audience: String,
    allowed_clients: Vec<String>,
    #[serde(default)]
    local_api_keys: Option<RelayLocalApiKeyBinding>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayLocalApiKeyBinding {
    match_principal: String,
    no_match_principal: String,
    scopes: Vec<String>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryRelayBinding {
    base_url: String,
    workload_client_id: String,
    token_file: PathBuf,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayStateBinding {
    postgresql: RelayPostgresqlBinding,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayPostgresqlBinding {
    root_certificate_path: PathBuf,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryStateBinding {
    postgresql: NotaryPostgresqlBinding,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryPostgresqlBinding {
    root_certificate_path: PathBuf,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NotaryCelBinding {
    worker_memory_bytes: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciBinding {
    public_base_url: String,
    credential: Oid4vciCredentialBinding,
    authorization_server: Oid4vciAuthorizationServerBinding,
    client: Oid4vciClientBinding,
    /// Machine OIDC clients admitted to create registrar-initiated offers.
    ///
    /// These clients use the pinned authorization server and the Notary public
    /// base URL as their resource audience. They are deliberately separate
    /// from the citizen client so generated subject-access classification
    /// remains closed.
    #[serde(default)]
    registrar_clients: Vec<String>,
    access_token: Oid4vciSigningKeyBinding,
    sensitive_state_key: SecretReference,
    subject: Oid4vciSubjectBinding,
    redirect_uri: String,
    allowed_wallet_origins: Vec<String>,
    #[serde(default)]
    tx_code: Oid4vciTxCodeBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    representative_issuance: Option<Oid4vciRepresentativeIssuanceBinding>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciRepresentativeIssuanceBinding {
    relationship: String,
    proof_claim: String,
    target_id_type: String,
    #[serde(default = "default_oid4vci_representative_max_proof_age_seconds")]
    max_proof_age_seconds: u64,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciTxCodeBinding {
    #[serde(default = "default_oid4vci_tx_code_required")]
    required: bool,
}

impl Default for Oid4vciTxCodeBinding {
    fn default() -> Self {
        Self {
            required: default_oid4vci_tx_code_required(),
        }
    }
}

const fn default_oid4vci_tx_code_required() -> bool {
    true
}

const fn default_oid4vci_representative_max_proof_age_seconds() -> u64 {
    300
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciCredentialBinding {
    service: String,
    profile: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciAuthorizationServerBinding {
    issuer: String,
    jwks_url: String,
    userinfo_url: String,
    authorize_url: String,
    token_url: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciClientBinding {
    id: String,
    signing_key: SecretReference,
    signing_kid: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciSigningKeyBinding {
    signing_key: SecretReference,
    signing_kid: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Oid4vciSubjectBinding {
    token_claim: String,
    id_type: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBinding {
    profile: DeploymentProfile,
    #[serde(default)]
    relay: Option<ServiceBinding>,
    #[serde(default)]
    notary: Option<ServiceBinding>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceBinding {
    service: String,
}

#[derive(Debug, Serialize)]
struct FixtureDocument {
    name: String,
    classification: AuthoredFixtureClassification,
    #[serde(default)]
    request: Option<GovernedFixtureRequest>,
    input: BTreeMap<String, Value>,
    #[serde(default)]
    variables: BTreeMap<String, Value>,
    interactions: Vec<FixtureInteraction>,
    expect: FixtureExpectation,
}

/// The closed governed request accepted by an independently authored synthetic
/// fixture witness.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GovernedFixtureRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester: Option<GovernedFixtureTarget>,
    target: GovernedFixtureTarget,
    #[cfg_attr(test, schemars(with = "BTreeMap<String, String>"))]
    #[serde(
        default,
        skip_serializing_if = "registry_notary_core::RequestVariables::is_empty"
    )]
    variables: registry_notary_core::RequestVariables,
    claims: Vec<registry_notary_core::ClaimRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    purpose: String,
}

impl GovernedFixtureRequest {
    fn to_evaluate_request(&self) -> registry_notary_core::EvaluateRequest {
        registry_notary_core::EvaluateRequest {
            requester: self.requester.as_ref().map(governed_fixture_entity),
            target: Some(registry_notary_core::EvidenceEntity {
                entity_type: self.target.entity_type.clone(),
                id: self.target.id.clone(),
                identifiers: self
                    .target
                    .identifiers
                    .iter()
                    .map(|identifier| registry_notary_core::EvidenceIdentifier {
                        scheme: identifier.scheme.clone(),
                        value: identifier.value.clone(),
                        issuer: None,
                        country: None,
                    })
                    .collect(),
                attributes: self.target.attributes.clone(),
                assurance: None,
                profile: None,
            }),
            relationship: None,
            on_behalf_of: None,
            variables: self.variables.clone(),
            claims: self.claims.clone(),
            disclosure: self.disclosure.clone(),
            format: self.format.clone(),
            purpose: Some(self.purpose.clone()),
        }
    }
}

fn governed_fixture_entity(entity: &GovernedFixtureTarget) -> registry_notary_core::EvidenceEntity {
    registry_notary_core::EvidenceEntity {
        entity_type: entity.entity_type.clone(),
        id: entity.id.clone(),
        identifiers: entity
            .identifiers
            .iter()
            .map(|identifier| registry_notary_core::EvidenceIdentifier {
                scheme: identifier.scheme.clone(),
                value: identifier.value.clone(),
                issuer: None,
                country: None,
            })
            .collect(),
        attributes: entity.attributes.clone(),
        assurance: None,
        profile: None,
    }
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GovernedFixtureTarget {
    #[serde(rename = "type")]
    entity_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    identifiers: Vec<GovernedFixtureIdentifier>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    attributes: BTreeMap<String, Value>,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GovernedFixtureIdentifier {
    scheme: String,
    value: String,
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

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    artifact_inputs: Vec<ArtifactInputDigest>,
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
    relay_consultation_private: BTreeMap<PathBuf, Box<[u8]>>,
    notary_private: BTreeMap<PathBuf, Box<[u8]>>,
    review: Value,
    approval_state: Value,
    explanation: ProjectExplanationReportV1,
    fixture_profiles: Vec<FixtureProfile>,
    semantic_changes: Vec<SemanticChange>,
    semantic_impact: ProjectSemanticImpactReportV1,
}

struct FixtureProfile {
    service_id: String,
    consultation_id: String,
    integration_alias: String,
    id: String,
    version: String,
    contract_hash: String,
}

#[derive(Clone)]
struct VerifiedBaseline {
    lane: VerifiedBaselineLane,
    approval_state: Value,
    approval_state_digest: String,
    verified_manifest: Value,
    review_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum VerifiedBaselineLane {
    Relay,
    RelayConsultation,
    Notary,
}

#[derive(Default)]
struct VerifiedBaselineSet {
    relay: Option<VerifiedBaseline>,
    relay_consultation: Option<VerifiedBaseline>,
    notary: Option<VerifiedBaseline>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SemanticDigests {
    claim: String,
    integration: String,
    service_policy: String,
    operator_security: String,
}

#[cfg_attr(test, derive(schemars::JsonSchema))]
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
