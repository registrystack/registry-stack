// SPDX-License-Identifier: Apache-2.0
// Strict, versioned machine-report contracts for project authoring.
//
// These DTOs report decisions made by the authoritative authoring model and
// compiler. They deliberately do not restate authoring validation rules.

use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::RequiredProductAction;

pub use super::knowledge::{
    Availability as FieldKnowledgeAvailability, Consumer as FieldKnowledgeConsumer, FieldPathKind,
    GeneratedArtifact as FieldGeneratedArtifact, HumanOwner as FieldHumanOwner,
    Migration as FieldMigration, Product as FieldKnowledgeProduct,
    ReviewClass as FieldKnowledgeReviewClass, SemanticOwner as FieldSemanticOwner,
    SemanticRule as FieldKnowledgeSemanticRule, Sensitivity as FieldSensitivity,
    Stability as FieldKnowledgeStability,
};

pub const PROJECT_COMMAND_REPORT_SCHEMA_VERSION_V1: &str = "registryctl.project_command.v1";
pub const PROJECT_EXPLANATION_SCHEMA_VERSION_V1: &str = "registry.project.explanation.v1";
pub const PROJECT_SEMANTIC_IMPACT_SCHEMA_VERSION_V1: &str = "registry.project.semantic_impact.v1";
pub const PROJECT_ARTIFACT_MANIFEST_SCHEMA_VERSION_V1: &str =
    "registry.project.artifact_manifest.v1";
pub const PROJECT_ARTIFACT_MANIFEST_FORMAT_VERSION_V1: &str =
    "registry.project.artifact_manifest.format.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectCommandSchemaVersion {
    #[serde(rename = "registryctl.project_command.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectExplanationSchemaVersion {
    #[serde(rename = "registry.project.explanation.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectSemanticImpactSchemaVersion {
    #[serde(rename = "registry.project.semantic_impact.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectArtifactManifestSchemaVersion {
    #[serde(rename = "registry.project.artifact_manifest.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectArtifactManifestFormatVersion {
    #[serde(rename = "registry.project.artifact_manifest.format.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCommandStatus {
    Passed,
    Valid,
    Built,
}

impl ProjectCommandStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Valid => "valid",
            Self::Built => "built",
        }
    }
}

impl fmt::Display for ProjectCommandStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<&str> for ProjectCommandStatus {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<ProjectCommandStatus> for &str {
    fn eq(&self, other: &ProjectCommandStatus) -> bool {
        *self == other.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectBaseline {
    InitialWithoutBaseline,
    VerifiedSignedBundle,
}

impl ProjectBaseline {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialWithoutBaseline => "initial_without_baseline",
            Self::VerifiedSignedBundle => "verified_signed_bundle",
        }
    }
}

impl fmt::Display for ProjectBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<&str> for ProjectBaseline {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<ProjectBaseline> for &str {
    fn eq(&self, other: &ProjectBaseline) -> bool {
        *self == other.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCommandReportV1 {
    pub schema_version: ProjectCommandSchemaVersion,
    pub status: ProjectCommandStatus,
    pub project: String,
    pub environment: Option<String>,
    pub fixtures: Vec<ProjectFixtureReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub semantic_changes: Vec<DimensionOnlySemanticChange>,
    pub baseline: ProjectBaseline,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<ProjectRelativePath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_impact: Option<ProjectSemanticImpactReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_manifest: Option<ProjectArtifactManifestRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixture_coverage: Option<super::ProjectFixtureCoverageReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<ProjectExplanationReportV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFixtureReport {
    pub integration: String,
    pub fixture: ProjectFixtureReportId,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProjectFixtureReportId(String);

impl<'de> Deserialize<'de> for ProjectFixtureReportId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if valid_project_fixture_report_id(&value) {
            Ok(Self(value))
        } else {
            Err(de::Error::custom("invalid project fixture report id"))
        }
    }
}

impl ProjectFixtureReportId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_project_fixture_report_id(value: &str) -> bool {
    let (fixture, recipe) = value
        .split_once("::derived/")
        .map_or((value, None), |(fixture, recipe)| (fixture, Some(recipe)));
    let mut fixture_bytes = fixture.bytes();
    if !matches!(fixture_bytes.next(), Some(first) if first.is_ascii_alphanumeric())
        || !fixture_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return false;
    }
    recipe.is_none_or(|recipe| {
        let mut recipe_bytes = recipe.bytes();
        matches!(recipe_bytes.next(), Some(first) if first.is_ascii_lowercase())
            && recipe_bytes
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

/// Compatibility projection retained for existing command consumers.
///
/// Serializing this type always produces the legacy byte shape
/// `{"dimension":"..."}` with no impact details mixed into the record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionOnlySemanticChange {
    pub dimension: SemanticDimension,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectArtifactManifestRef {
    pub path: ProjectRelativePath,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectExplanationReportV1 {
    pub schema_version: ProjectExplanationSchemaVersion,
    pub project: String,
    pub environment: String,
    pub fields: Vec<ProjectFieldExplanation>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldExplanation {
    pub address: ProjectFieldAddress,
    pub source: ProjectFieldSource,
    pub state: ProjectFieldState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<ProjectFieldDefault>,
    pub constraints: ProjectFieldConstraints,
    pub knowledge: ProjectFieldKnowledge,
    pub reported_value: ClassifierSafeReportedValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "document", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectFieldAddress {
    Project {
        path: JsonPointer,
    },
    Integration {
        integration: String,
        path: JsonPointer,
    },
    Entity {
        entity: String,
        path: JsonPointer,
    },
    Environment {
        environment: String,
        path: JsonPointer,
    },
    Fixture {
        integration: String,
        fixture: String,
        path: JsonPointer,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSourceKind {
    Authored,
    Defaulted,
    Detected,
    Derived,
    EnvironmentBound,
    Generated,
    Runtime,
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldSource {
    pub kind: FieldSourceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<ProjectFieldAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_rule_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPresence {
    Authored,
    Defaulted,
    Detected,
    Derived,
    EnvironmentBound,
    Generated,
    Runtime,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldEffect {
    Effective,
    Shadowed,
    Inactive,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldState {
    pub presence: FieldPresence,
    pub effect: FieldEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldDefaultSource {
    AuthoringSchema,
    SemanticRule,
    Compiler,
    Product,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldDefault {
    pub source: FieldDefaultSource,
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_value: Option<ClassifierSafeReportedValue>,
}

/// References constraints without duplicating their validation facts.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldConstraints {
    pub schema_refs: Vec<ProjectSchemaRef>,
    pub semantic_rule_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectAuthoringSchema {
    Project,
    Integration,
    Entity,
    Environment,
    Fixture,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSchemaRef {
    pub schema: ProjectAuthoringSchema,
    pub path: JsonPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactConsumer {
    RegistryctlAuthoring,
    RegistryRelay,
    RegistryNotary,
    EditorTooling,
    DocsGenerator,
    BundleSigner,
    DeploymentTooling,
    Operator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactReviewClass {
    Contract,
    Authoring,
    Semantics,
    Interoperability,
    Privacy,
    Security,
    Relay,
    Notary,
    Compatibility,
    Documentation,
    Testing,
    Operations,
    Release,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFieldKnowledge {
    pub path_kind: FieldPathKind,
    pub semantic_owner: FieldSemanticOwner,
    pub human_owner: FieldHumanOwner,
    pub sensitivity: FieldSensitivity,
    pub products: Vec<FieldKnowledgeProduct>,
    pub introduced_in: String,
    pub availability: FieldKnowledgeAvailability,
    pub stability: FieldKnowledgeStability,
    pub migration: FieldMigration,
    pub consumers: Vec<FieldKnowledgeConsumer>,
    pub generated_artifacts: Vec<FieldGeneratedArtifact>,
    pub review_classes: Vec<FieldKnowledgeReviewClass>,
    pub semantic_rules: Vec<FieldKnowledgeSemanticRule>,
}

/// A report value after the classifier/redaction boundary has been applied.
///
/// Only the `public` variant carries JSON. The private
/// [`ClassifierApprovedJson`] field prevents callers from constructing it
/// accidentally; producer code must opt in through
/// [`ClassifierApprovedJson::after_classification`]. Non-public values retain
/// only their classification and redaction reason.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClassifierSafeReportedValue {
    Public {
        value: ClassifierApprovedJson,
    },
    Redacted {
        classification: FieldSensitivity,
        reason: RedactionReason,
    },
    Absent,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ClassifierApprovedJson(Value);

impl ClassifierApprovedJson {
    /// Marks a value as safe only after the caller has classified and redacted
    /// it at the producer boundary.
    pub(crate) fn after_classification(
        classification: FieldSensitivity,
        semantic_approved: bool,
        value: Value,
    ) -> Option<Self> {
        classification
            .value_is_reportable(semantic_approved)
            .then_some(Self(value))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionReason {
    Policy,
    SecretMaterial,
    SensitiveMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSemanticImpactReportV1 {
    pub schema_version: ProjectSemanticImpactSchemaVersion,
    pub baseline: ProjectBaseline,
    pub changes: Vec<ProjectSemanticImpact>,
}

impl ProjectSemanticImpactReportV1 {
    /// Produces the stable, de-duplicated legacy dimension projection.
    #[must_use]
    pub fn dimension_only_changes(&self) -> Vec<DimensionOnlySemanticChange> {
        let mut dimensions = self
            .changes
            .iter()
            .map(|change| change.dimension)
            .collect::<Vec<_>>();
        dimensions.sort_unstable();
        dimensions.dedup();
        dimensions
            .into_iter()
            .map(|dimension| DimensionOnlySemanticChange { dimension })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDimension {
    Claim,
    Integration,
    ServicePolicy,
    OperatorSecurity,
    Disclosure,
    Compiler,
}

impl SemanticDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Integration => "integration",
            Self::ServicePolicy => "service_policy",
            Self::OperatorSecurity => "operator_security",
            Self::Disclosure => "disclosure",
            Self::Compiler => "compiler",
        }
    }
}

impl fmt::Display for SemanticDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<&str> for SemanticDimension {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<SemanticDimension> for &str {
    fn eq(&self, other: &SemanticDimension) -> bool {
        *self == other.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDirection {
    Added,
    Removed,
    Changed,
    Narrowed,
    Widened,
    DefaultChanged,
    Unbaselined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticImpactLocation {
    Field { field: ProjectFieldAddress },
    Dimension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SemanticPrecision {
    Field,
    Dimension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectSemanticImpact {
    pub location: SemanticImpactLocation,
    pub dimension: SemanticDimension,
    pub direction: SemanticDirection,
    pub affected_subjects: Vec<AffectedSubject>,
    pub consumers: Vec<ImpactConsumer>,
    pub review_classes: Vec<ImpactReviewClass>,
    pub product_impacts: Vec<ProductImpact>,
    pub requirements: ImpactRequirements,
}

impl Serialize for ProjectSemanticImpact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (precision, field) = match &self.location {
            SemanticImpactLocation::Field { field } => (SemanticPrecision::Field, Some(field)),
            SemanticImpactLocation::Dimension => (SemanticPrecision::Dimension, None),
        };
        ProjectSemanticImpactRef {
            precision,
            field,
            dimension: self.dimension,
            direction: self.direction,
            affected_subjects: &self.affected_subjects,
            consumers: &self.consumers,
            review_classes: &self.review_classes,
            product_impacts: &self.product_impacts,
            requirements: &self.requirements,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProjectSemanticImpact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProjectSemanticImpactWire::deserialize(deserializer)?;
        let location = match (wire.precision, wire.field) {
            (SemanticPrecision::Field, Some(field)) => SemanticImpactLocation::Field { field },
            (SemanticPrecision::Dimension, None) => SemanticImpactLocation::Dimension,
            (SemanticPrecision::Field, None) => {
                return Err(de::Error::custom(
                    "field precision requires a field address",
                ));
            }
            (SemanticPrecision::Dimension, Some(_)) => {
                return Err(de::Error::custom(
                    "dimension precision must not carry a field address",
                ));
            }
        };
        Ok(Self {
            location,
            dimension: wire.dimension,
            direction: wire.direction,
            affected_subjects: wire.affected_subjects,
            consumers: wire.consumers,
            review_classes: wire.review_classes,
            product_impacts: wire.product_impacts,
            requirements: wire.requirements,
        })
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProjectSemanticImpactRef<'a> {
    precision: SemanticPrecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'a ProjectFieldAddress>,
    dimension: SemanticDimension,
    direction: SemanticDirection,
    affected_subjects: &'a [AffectedSubject],
    consumers: &'a [ImpactConsumer],
    review_classes: &'a [ImpactReviewClass],
    product_impacts: &'a [ProductImpact],
    requirements: &'a ImpactRequirements,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectSemanticImpactWire {
    precision: SemanticPrecision,
    field: Option<ProjectFieldAddress>,
    dimension: SemanticDimension,
    direction: SemanticDirection,
    affected_subjects: Vec<AffectedSubject>,
    consumers: Vec<ImpactConsumer>,
    review_classes: Vec<ImpactReviewClass>,
    product_impacts: Vec<ProductImpact>,
    requirements: ImpactRequirements,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AffectedSubjectKind {
    Integration,
    Fixture,
    ServicePolicy,
    Consultation,
    Claim,
    Disclosure,
    ProductInput,
    GeneratedArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedSubject {
    pub kind: AffectedSubjectKind,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectProduct {
    Registryctl,
    Relay,
    Notary,
    Editor,
    Docs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductImpactClass {
    Regenerate,
    Revalidate,
    Reconfigure,
    Republish,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductImpact {
    pub product: ProjectProduct,
    pub impact: ProductImpactClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactRequirements {
    pub signing: Vec<RequiredProductAction>,
    pub activation: Vec<RequiredProductAction>,
    pub restart: Vec<RequiredProductAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectArtifactManifestV1 {
    pub schema_version: ProjectArtifactManifestSchemaVersion,
    pub format_version: ProjectArtifactManifestFormatVersion,
    pub project: String,
    pub environment: String,
    pub generator: ArtifactGenerator,
    pub inputs: Vec<ArtifactInputDigest>,
    pub artifacts: Vec<GeneratedArtifactRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactGenerator {
    pub name: ArtifactGeneratorName,
    pub version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactGeneratorName {
    Registryctl,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInputDigest {
    pub path: ProjectRelativePath,
    pub digest: Sha256Digest,
    pub classification: ArtifactInputClassification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactInputClassification {
    AuthoredProjectInput,
    OperatorOwnedSourceData,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedArtifactRecord {
    pub path: ProjectRelativePath,
    pub format_version: String,
    pub digest: Sha256Digest,
    pub classes: Vec<ArtifactClass>,
    pub sensitivity: ArtifactSensitivity,
    pub publication: ArtifactPublication,
    pub edit: ArtifactEditPolicy,
    pub version_control: ArtifactVersionControl,
    pub review: ArtifactReviewState,
    pub lifecycle: ArtifactLifecycle,
    pub actions: Vec<ArtifactAction>,
    pub consumers: Vec<ArtifactConsumer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClass {
    RuntimeConfig,
    ConsultationContract,
    SourcePlan,
    ClaimConfiguration,
    DeploymentInput,
    ReviewRecord,
    Documentation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSensitivity {
    Public,
    Internal,
    TopologySensitive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPublication {
    Public,
    OperatorOnly,
    NeverPublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEditPolicy {
    GeneratedDoNotEdit,
    GeneratedReviewBeforeEdit,
    HandMaintained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVersionControl {
    Commit,
    Ignore,
    ProjectDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactReviewState {
    GeneratedCandidate,
    NeedsReview,
    Reviewed,
    ReadyCandidate,
    Released,
    Deprecated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactLifecycle {
    UnsignedNonDeployable,
    SignedCandidate,
    VerifiedDeployable,
    ReviewEvidence,
    PublicationOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAction {
    Regenerate,
    Compare,
    Validate,
    Sign,
    Verify,
    Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactConsumer {
    RegistryRelay,
    RegistryNotary,
    BundleSigner,
    DeploymentTooling,
    ProjectDocumentation,
    Operator,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProjectRelativePath(String);

impl ProjectRelativePath {
    pub fn new(path: impl Into<String>) -> Result<Self, ProjectRelativePathError> {
        let path = path.into();
        validate_project_relative_path(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectRelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ProjectRelativePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<std::ffi::OsStr> for ProjectRelativePath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.as_str().as_ref()
    }
}

impl AsRef<std::path::Path> for ProjectRelativePath {
    fn as_ref(&self) -> &std::path::Path {
        self.as_str().as_ref()
    }
}

impl PartialEq<&str> for ProjectRelativePath {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<ProjectRelativePath> for &str {
    fn eq(&self, other: &ProjectRelativePath) -> bool {
        *self == other.as_str()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JsonPointer(String);

impl JsonPointer {
    pub fn new(pointer: impl Into<String>) -> Result<Self, JsonPointerError> {
        let pointer = pointer.into();
        validate_json_pointer(&pointer)?;
        Ok(Self(pointer))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JsonPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pointer = String::deserialize(deserializer)?;
        Self::new(pointer).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonPointerError;

impl fmt::Display for JsonPointerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("field path must be an RFC 6901 JSON Pointer")
    }
}

fn validate_json_pointer(pointer: &str) -> Result<(), JsonPointerError> {
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') || pointer.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(JsonPointerError);
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            index += 1;
            if index == bytes.len() || !matches!(bytes[index], b'0' | b'1') {
                return Err(JsonPointerError);
            }
        }
        index += 1;
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ProjectRelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;
        Self::new(path).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectRelativePathError;

impl fmt::Display for ProjectRelativePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("path must be a normalized, safe project-relative path")
    }
}

fn validate_project_relative_path(path: &str) -> Result<(), ProjectRelativePathError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProjectRelativePathError);
    }
    if path.split('/').any(|part| {
        let mut characters = part.chars();
        let Some(first) = characters.next() else {
            return true;
        };
        let first_is_valid = if first == '.' {
            characters.next().is_some_and(|character| {
                character.is_ascii_alphanumeric() || "_-".contains(character)
            })
        } else {
            first.is_ascii_alphanumeric() || "_-".contains(first)
        };
        !first_is_valid
            || characters
                .any(|character| !character.is_ascii_alphanumeric() && !"._-".contains(character))
    }) {
        return Err(ProjectRelativePathError);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(digest: impl Into<String>) -> Result<Self, Sha256DigestError> {
        let digest = digest.into();
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Err(Sha256DigestError);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(Sha256DigestError);
        }
        Ok(Self(digest))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let digest = String::deserialize(deserializer)?;
        Self::new(digest).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256DigestError;

impl fmt::Display for Sha256DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("digest must be lowercase sha256:<64 hex characters>")
    }
}
