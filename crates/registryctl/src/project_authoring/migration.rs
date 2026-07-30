// SPDX-License-Identifier: Apache-2.0
//! Strict, value-free project authoring migration report contract.
//!
//! [`build_project_migration_report`] is a pure decision boundary. The command
//! adapter detects authoring contract versions, applies a reviewed migration
//! catalog in memory, and supplies only closed classifications to that
//! builder. The report cannot carry authored values, country identifiers,
//! file-system paths, secret names, hashes, or generated product inputs. With
//! explicit authority, the adapter may atomically emit a separate review
//! candidate; neither the builder nor the adapter can apply a migration or
//! overwrite an authored project file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const PROJECT_MIGRATION_SCHEMA_VERSION_V1: &str = "registry.project.migration.v1";
pub(crate) const MAX_MIGRATION_CHANGES: usize = 256;
pub(crate) const MAX_MIGRATION_DECISIONS: usize = 64;
pub(crate) const MAX_MIGRATION_DIAGNOSTICS: usize = 32;
pub(crate) const MAX_MIGRATION_AFFECTED_COUNT: u32 = 1_000_000;
pub(crate) const MAX_AUTHORING_VERSION: u32 = 65_535;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectMigrationSchemaVersion {
    #[serde(rename = "registry.project.migration.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEvidenceGrade {
    OfflineStatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationExecution {
    NotPerformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDisposition {
    NoMigrationRequired,
    ReviewRequired,
    CheckedSafe,
    ReadyForExplicitWrite,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoringContract {
    Project,
    Integration,
    Entity,
    Fixture,
    Environment,
}

impl AuthoringContract {
    const ALL: [Self; 5] = [
        Self::Project,
        Self::Integration,
        Self::Entity,
        Self::Fixture,
        Self::Environment,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoringVersionSet {
    pub project: Option<u32>,
    pub integration: Option<u32>,
    pub entity: Option<u32>,
    pub fixture: Option<u32>,
    pub environment: Option<u32>,
}

impl AuthoringVersionSet {
    const fn get(self, contract: AuthoringContract) -> Option<u32> {
        match contract {
            AuthoringContract::Project => self.project,
            AuthoringContract::Integration => self.integration,
            AuthoringContract::Entity => self.entity,
            AuthoringContract::Fixture => self.fixture,
            AuthoringContract::Environment => self.environment,
        }
    }

    fn from_transitions(transitions: &[MigrationVersionTransition], source: bool) -> Self {
        let version = |contract| {
            transitions
                .iter()
                .find(|transition| transition.contract == contract)
                .and_then(|transition| {
                    if source {
                        transition.source_version
                    } else {
                        transition.target_version
                    }
                })
        };
        Self {
            project: version(AuthoringContract::Project),
            integration: version(AuthoringContract::Integration),
            entity: version(AuthoringContract::Entity),
            fixture: version(AuthoringContract::Fixture),
            environment: version(AuthoringContract::Environment),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationVersionDirection {
    Absent,
    Same,
    Upgrade,
    Downgrade,
    AddedContract,
    RemovedContract,
    UnsupportedTarget,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationVersionTransition {
    pub contract: AuthoringContract,
    pub source_version: Option<u32>,
    pub target_version: Option<u32>,
    pub direction: MigrationVersionDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationVersionSupport {
    Supported,
    Unsupported,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationVersionSupportAssessment {
    pub source: MigrationVersionSupport,
    pub target: MigrationVersionSupport,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDocument {
    Project,
    Integration,
    Entity,
    Fixture,
    Environment,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum MigrationFieldPath {
    #[serde(rename = "")]
    Root,
    #[serde(rename = "/version")]
    Version,
    #[serde(rename = "/registry")]
    ProjectRegistry,
    #[serde(rename = "/integrations/*")]
    ProjectIntegrations,
    #[serde(rename = "/entities/*")]
    ProjectEntities,
    #[serde(rename = "/services/*")]
    ProjectServices,
    #[serde(rename = "/services/*/access")]
    ServicePolicy,
    #[serde(rename = "/services/*/consultations/*")]
    Consultation,
    #[serde(rename = "/services/*/claims/*")]
    Claim,
    #[serde(rename = "/services/*/api/attribute_release_profiles/*/subject/input")]
    AttributeReleaseSubjectInput,
    #[serde(rename = "/services/*/api/attribute_release_profiles/*/response")]
    AttributeReleaseResponse,
    #[serde(rename = "/services/*/api/attribute_release_profiles/*/response/max_age_seconds")]
    AttributeReleaseResponseMaxAge,
    #[serde(rename = "/input")]
    Input,
    #[serde(rename = "/capability")]
    IntegrationCapability,
    #[serde(rename = "/outputs/*")]
    IntegrationOutputs,
    #[serde(rename = "/primary_key")]
    EntityPrimaryKey,
    #[serde(rename = "/schema")]
    EntitySchema,
    #[serde(rename = "/materialization")]
    EntityMaterialization,
    #[serde(rename = "/classification")]
    FixtureClassification,
    #[serde(rename = "/interactions/*")]
    FixtureInteractions,
    #[serde(rename = "/expect")]
    FixtureExpectation,
    #[serde(rename = "/integrations/*/source/origin")]
    EnvironmentOrigin,
    #[serde(rename = "/integrations/*/source/credential")]
    EnvironmentCredentials,
    #[serde(rename = "/relay")]
    EnvironmentTrust,
    #[serde(rename = "/deployment")]
    EnvironmentDeployment,
    #[serde(rename = "/notary_cel")]
    EnvironmentWorkerLimits,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationFieldAddress {
    pub document: MigrationDocument,
    pub path: MigrationFieldPath,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MigrationField {
    ProjectDocument,
    ProjectVersion,
    ProjectRegistry,
    ProjectIntegrations,
    ProjectEntities,
    ProjectServices,
    ServicePolicy,
    Consultation,
    Claim,
    AttributeReleaseSubjectInput,
    AttributeReleaseResponse,
    AttributeReleaseResponseMaxAge,
    IntegrationDocument,
    IntegrationVersion,
    IntegrationInput,
    IntegrationCapability,
    IntegrationOutputs,
    EntityDocument,
    EntityVersion,
    EntityPrimaryKey,
    EntitySchema,
    EntityMaterialization,
    FixtureDocument,
    FixtureClassification,
    FixtureInput,
    FixtureInteractions,
    FixtureExpectation,
    EnvironmentDocument,
    EnvironmentVersion,
    EnvironmentOrigin,
    EnvironmentCredentials,
    EnvironmentTrust,
    EnvironmentDeployment,
    EnvironmentWorkerLimits,
}

impl MigrationField {
    pub const ALL: [Self; 34] = [
        Self::ProjectDocument,
        Self::ProjectVersion,
        Self::ProjectRegistry,
        Self::ProjectIntegrations,
        Self::ProjectEntities,
        Self::ProjectServices,
        Self::ServicePolicy,
        Self::Consultation,
        Self::Claim,
        Self::AttributeReleaseSubjectInput,
        Self::AttributeReleaseResponse,
        Self::AttributeReleaseResponseMaxAge,
        Self::IntegrationDocument,
        Self::IntegrationVersion,
        Self::IntegrationInput,
        Self::IntegrationCapability,
        Self::IntegrationOutputs,
        Self::EntityDocument,
        Self::EntityVersion,
        Self::EntityPrimaryKey,
        Self::EntitySchema,
        Self::EntityMaterialization,
        Self::FixtureDocument,
        Self::FixtureClassification,
        Self::FixtureInput,
        Self::FixtureInteractions,
        Self::FixtureExpectation,
        Self::EnvironmentDocument,
        Self::EnvironmentVersion,
        Self::EnvironmentOrigin,
        Self::EnvironmentCredentials,
        Self::EnvironmentTrust,
        Self::EnvironmentDeployment,
        Self::EnvironmentWorkerLimits,
    ];

    pub const fn address(self) -> MigrationFieldAddress {
        use MigrationDocument as Document;
        use MigrationFieldPath as Path;
        let (document, path) = match self {
            Self::ProjectDocument => (Document::Project, Path::Root),
            Self::ProjectVersion => (Document::Project, Path::Version),
            Self::ProjectRegistry => (Document::Project, Path::ProjectRegistry),
            Self::ProjectIntegrations => (Document::Project, Path::ProjectIntegrations),
            Self::ProjectEntities => (Document::Project, Path::ProjectEntities),
            Self::ProjectServices => (Document::Project, Path::ProjectServices),
            Self::ServicePolicy => (Document::Project, Path::ServicePolicy),
            Self::Consultation => (Document::Project, Path::Consultation),
            Self::Claim => (Document::Project, Path::Claim),
            Self::AttributeReleaseSubjectInput => {
                (Document::Project, Path::AttributeReleaseSubjectInput)
            }
            Self::AttributeReleaseResponse => (Document::Project, Path::AttributeReleaseResponse),
            Self::AttributeReleaseResponseMaxAge => {
                (Document::Project, Path::AttributeReleaseResponseMaxAge)
            }
            Self::IntegrationDocument => (Document::Integration, Path::Root),
            Self::IntegrationVersion => (Document::Integration, Path::Version),
            Self::IntegrationInput => (Document::Integration, Path::Input),
            Self::IntegrationCapability => (Document::Integration, Path::IntegrationCapability),
            Self::IntegrationOutputs => (Document::Integration, Path::IntegrationOutputs),
            Self::EntityDocument => (Document::Entity, Path::Root),
            Self::EntityVersion => (Document::Entity, Path::Version),
            Self::EntityPrimaryKey => (Document::Entity, Path::EntityPrimaryKey),
            Self::EntitySchema => (Document::Entity, Path::EntitySchema),
            Self::EntityMaterialization => (Document::Entity, Path::EntityMaterialization),
            Self::FixtureDocument => (Document::Fixture, Path::Root),
            Self::FixtureClassification => (Document::Fixture, Path::FixtureClassification),
            Self::FixtureInput => (Document::Fixture, Path::Input),
            Self::FixtureInteractions => (Document::Fixture, Path::FixtureInteractions),
            Self::FixtureExpectation => (Document::Fixture, Path::FixtureExpectation),
            Self::EnvironmentDocument => (Document::Environment, Path::Root),
            Self::EnvironmentVersion => (Document::Environment, Path::Version),
            Self::EnvironmentOrigin => (Document::Environment, Path::EnvironmentOrigin),
            Self::EnvironmentCredentials => (Document::Environment, Path::EnvironmentCredentials),
            Self::EnvironmentTrust => (Document::Environment, Path::EnvironmentTrust),
            Self::EnvironmentDeployment => (Document::Environment, Path::EnvironmentDeployment),
            Self::EnvironmentWorkerLimits => (Document::Environment, Path::EnvironmentWorkerLimits),
        };
        MigrationFieldAddress { document, path }
    }

    pub fn from_address(address: MigrationFieldAddress) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|field| field.address() == address)
    }

    const fn owner(self) -> MigrationOwner {
        match self {
            Self::ProjectDocument
            | Self::IntegrationDocument
            | Self::EntityDocument
            | Self::FixtureDocument
            | Self::ProjectServices
            | Self::ServicePolicy
            | Self::Consultation
            | Self::Claim
            | Self::AttributeReleaseSubjectInput
            | Self::AttributeReleaseResponse
            | Self::AttributeReleaseResponseMaxAge
            | Self::FixtureInput
            | Self::FixtureInteractions
            | Self::FixtureExpectation => MigrationOwner::CountryAuthor,
            Self::EnvironmentDocument
            | Self::EnvironmentVersion
            | Self::EnvironmentOrigin
            | Self::EnvironmentCredentials
            | Self::EnvironmentTrust
            | Self::EnvironmentDeployment
            | Self::EnvironmentWorkerLimits => MigrationOwner::Operator,
            _ => MigrationOwner::Registryctl,
        }
    }

    const fn is_reviewed_retired_attribute_release_field(self) -> bool {
        matches!(
            self,
            Self::AttributeReleaseSubjectInput
                | Self::AttributeReleaseResponse
                | Self::AttributeReleaseResponseMaxAge
        )
    }

    const fn classification(self) -> MigrationFieldClassification {
        match self {
            Self::EnvironmentCredentials => MigrationFieldClassification::SecretReference,
            Self::EnvironmentDocument | Self::EnvironmentOrigin | Self::EnvironmentTrust => {
                MigrationFieldClassification::Sensitive
            }
            Self::FixtureDocument
            | Self::FixtureInput
            | Self::FixtureInteractions
            | Self::FixtureExpectation => MigrationFieldClassification::RedactedFixture,
            Self::ProjectVersion
            | Self::IntegrationVersion
            | Self::EntityVersion
            | Self::EnvironmentVersion => MigrationFieldClassification::Public,
            Self::ProjectDocument
            | Self::IntegrationDocument
            | Self::EntityDocument
            | Self::ProjectRegistry
            | Self::ProjectIntegrations
            | Self::ProjectEntities
            | Self::IntegrationCapability
            | Self::EntityPrimaryKey
            | Self::FixtureClassification
            | Self::EnvironmentDeployment => MigrationFieldClassification::Structural,
            _ => MigrationFieldClassification::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationOwner {
    Registryctl,
    CountryAuthor,
    Operator,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationFieldClassification {
    Public,
    Structural,
    Internal,
    Sensitive,
    SecretReference,
    RedactedFixture,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationOperation {
    NormalizeField,
    AddField,
    RemoveField,
    RenameField,
    ChangeSemantics,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationSemanticEffect {
    Preserved,
    Changed,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationSafety {
    Safe,
    Unsafe,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MigrationReplacementInput {
    NotApplicable,
    Field(MigrationField),
    NoReplacement,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationReplacementDisposition {
    NotApplicable,
    Field,
    NoReplacement,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReplacement {
    pub disposition: MigrationReplacementDisposition,
    pub address: Option<MigrationFieldAddress>,
}

impl MigrationReplacement {
    const fn from_input(input: MigrationReplacementInput) -> Self {
        match input {
            MigrationReplacementInput::NotApplicable => Self {
                disposition: MigrationReplacementDisposition::NotApplicable,
                address: None,
            },
            MigrationReplacementInput::Field(field) => Self {
                disposition: MigrationReplacementDisposition::Field,
                address: Some(field.address()),
            },
            MigrationReplacementInput::NoReplacement => Self {
                disposition: MigrationReplacementDisposition::NoReplacement,
                address: None,
            },
            MigrationReplacementInput::Unresolved => Self {
                disposition: MigrationReplacementDisposition::Unresolved,
                address: None,
            },
        }
    }

    fn to_input(self) -> Result<MigrationReplacementInput, &'static str> {
        match (self.disposition, self.address) {
            (MigrationReplacementDisposition::NotApplicable, None) => {
                Ok(MigrationReplacementInput::NotApplicable)
            }
            (MigrationReplacementDisposition::Field, Some(address)) => {
                MigrationField::from_address(address)
                    .map(MigrationReplacementInput::Field)
                    .ok_or("migration replacement address is not a catalogued field")
            }
            (MigrationReplacementDisposition::NoReplacement, None) => {
                Ok(MigrationReplacementInput::NoReplacement)
            }
            (MigrationReplacementDisposition::Unresolved, None) => {
                Ok(MigrationReplacementInput::Unresolved)
            }
            _ => Err("migration replacement disposition and address disagree"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MigrationChangeInput {
    pub field: MigrationField,
    pub operation: MigrationOperation,
    pub semantic_effect: MigrationSemanticEffect,
    pub safety: MigrationSafety,
    pub replacement: MigrationReplacementInput,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationChange {
    pub address: MigrationFieldAddress,
    pub operation: MigrationOperation,
    pub semantic_effect: MigrationSemanticEffect,
    pub safety: MigrationSafety,
    pub replacement: MigrationReplacement,
    pub owner: MigrationOwner,
    pub classification: MigrationFieldClassification,
}

impl MigrationChange {
    fn is_compatible_normalization(self) -> bool {
        self.semantic_effect == MigrationSemanticEffect::Preserved
            && self.safety == MigrationSafety::Safe
    }

    fn to_input(self) -> Result<MigrationChangeInput, &'static str> {
        let field = MigrationField::from_address(self.address)
            .ok_or("migration change address is not a catalogued field")?;
        if self.owner != field.owner() || self.classification != field.classification() {
            return Err("migration field owner or classification disagrees with the catalog");
        }
        Ok(MigrationChangeInput {
            field,
            operation: self.operation,
            semantic_effect: self.semantic_effect,
            safety: self.safety,
            replacement: self.replacement.to_input()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCompatibility {
    NoMigrationRequired,
    CompatibleNormalizationOnly,
    SemanticReviewRequired,
    UnsafeOrUnresolved,
    UnsupportedTransition,
    CatalogIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationAffectedState {
    NotAffected,
    Affected,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationAffectedCount {
    pub state: MigrationAffectedState,
    pub count: Option<u32>,
}

impl MigrationAffectedCount {
    pub const fn known(count: u32) -> Self {
        Self {
            state: if count == 0 {
                MigrationAffectedState::NotAffected
            } else {
                MigrationAffectedState::Affected
            },
            count: Some(count),
        }
    }

    pub const fn unresolved() -> Self {
        Self {
            state: MigrationAffectedState::Unresolved,
            count: None,
        }
    }

    const fn is_affected(self) -> bool {
        matches!(self.state, MigrationAffectedState::Affected)
    }

    const fn is_unresolved(self) -> bool {
        matches!(self.state, MigrationAffectedState::Unresolved)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationArtifact {
    RelayConfig,
    RelayEnvironmentContract,
    NotaryConfig,
    NotaryEnvironmentContract,
    ProjectExplanation,
    ProjectSemanticImpact,
    ProjectFixtureCoverage,
    ProjectArtifactManifest,
    GeneratedConfigurationReference,
    ReleaseReadinessEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationAffectedSurfaces {
    pub fixtures: MigrationAffectedCount,
    pub services: MigrationAffectedCount,
    pub consultations: MigrationAffectedCount,
    pub claims: MigrationAffectedCount,
    pub environments: MigrationAffectedCount,
    pub generated_artifacts: Vec<MigrationArtifact>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationReviewClass {
    Authoring,
    Compatibility,
    Migration,
    Fixtures,
    Relay,
    Notary,
    Interoperability,
    Privacy,
    Security,
    Operations,
    Documentation,
    CountryGovernance,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationReviewStatus {
    RequiredPending,
    Approved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReviewAssessment {
    pub class: MigrationReviewClass,
    pub status: MigrationReviewStatus,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDecisionOwner {
    CountryAuthority,
    ProjectOperator,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDecisionKind {
    CountrySemanticIntent,
    CountryLegalBasis,
    FieldReplacement,
    DataMinimization,
    ServicePolicy,
    ClaimSemantics,
    OperatorTrust,
    OperatorSecretBinding,
    OperatorDeployment,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDecisionScope {
    Project,
    Service,
    Consultation,
    Claim,
    Environment,
    GeneratedArtifacts,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedMigrationDecision {
    pub owner: MigrationDecisionOwner,
    pub kind: MigrationDecisionKind,
    pub scope: MigrationDecisionScope,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRerunGate {
    Schema,
    Fixture,
    Check,
    Build,
    GeneratedReference,
}

impl MigrationRerunGate {
    const ALL: [Self; 5] = [
        Self::Schema,
        Self::Fixture,
        Self::Check,
        Self::Build,
        Self::GeneratedReference,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationGateStatus {
    Passed,
    Failed,
    NotRun,
    NotRequired,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationGateResults {
    pub schema: MigrationGateStatus,
    pub fixture: MigrationGateStatus,
    pub check: MigrationGateStatus,
    pub build: MigrationGateStatus,
    pub generated_reference: MigrationGateStatus,
}

impl MigrationGateResults {
    const fn get(self, gate: MigrationRerunGate) -> MigrationGateStatus {
        match gate {
            MigrationRerunGate::Schema => self.schema,
            MigrationRerunGate::Fixture => self.fixture,
            MigrationRerunGate::Check => self.check,
            MigrationRerunGate::Build => self.build,
            MigrationRerunGate::GeneratedReference => self.generated_reference,
        }
    }

    fn from_assessments(assessments: &[MigrationGateAssessment]) -> Result<Self, &'static str> {
        if assessments.len() != MigrationRerunGate::ALL.len()
            || assessments
                .iter()
                .zip(MigrationRerunGate::ALL)
                .any(|(assessment, expected)| assessment.gate != expected)
        {
            return Err(
                "migration rerun gates must contain schema, fixture, check, build, and generated reference in canonical order",
            );
        }
        Ok(Self {
            schema: assessments[0].status,
            fixture: assessments[1].status,
            check: assessments[2].status,
            build: assessments[3].status,
            generated_reference: assessments[4].status,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationGateAssessment {
    pub gate: MigrationRerunGate,
    pub status: MigrationGateStatus,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDiagnosticCode {
    SourceYamlMalformed,
    SourceVersionMissing,
    SourceVersionMalformed,
    SourceVersionZero,
    SourceVersionOutOfBounds,
    SourceVersionUnsupported,
    SourceVersionsMixed,
    TargetVersionOutOfBounds,
    TargetVersionUnsupported,
    RerunGateFailed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDiagnosticPhase {
    SourceInspection,
    VersionInspection,
    SchemaGate,
    FixtureGate,
    CheckGate,
    BuildGate,
    GeneratedReferenceGate,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDiagnosticRemediation {
    CorrectSourceYaml,
    DeclareSupportedVersion,
    AlignContractVersions,
    SelectSupportedTargetVersion,
    InspectCandidateSchema,
    RepairFixtures,
    ResolveProjectCheck,
    ResolveProjectBuild,
    RegenerateConfigurationReference,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationDiagnostic {
    pub code: MigrationDiagnosticCode,
    pub phase: MigrationDiagnosticPhase,
    pub contract: Option<AuthoringContract>,
    pub remediation: MigrationDiagnosticRemediation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationOutputMode {
    CheckOnly,
    ReviewablePatch,
    SeparateOutputDirectory,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationWriteAuthority {
    NotGranted,
    ExplicitCandidateWriteGranted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCandidateArtifact {
    None,
    ReviewablePatch,
    SeparateOutputDirectory,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCandidateEligibility {
    NotRequested,
    EligibleToEmit,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationAuthoredFilePolicy {
    NeverOverwriteAuthoredFiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationApplicationPolicy {
    ExplicitOperatorApplyRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationCandidateEmission {
    NotEmitted,
    ReviewablePatchCandidateEmitted,
    SeparateOutputCandidateEmitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationOutputRequest {
    pub mode: MigrationOutputMode,
    pub write_authority: MigrationWriteAuthority,
    pub candidate_emission: MigrationCandidateEmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationOutputPlan {
    pub mode: MigrationOutputMode,
    pub write_authority: MigrationWriteAuthority,
    pub candidate_artifact: MigrationCandidateArtifact,
    pub candidate_eligibility: MigrationCandidateEligibility,
    pub authored_file_policy: MigrationAuthoredFilePolicy,
    pub application_policy: MigrationApplicationPolicy,
    pub candidate_emission: MigrationCandidateEmission,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationBlockingReason {
    SourceInspectionFailed,
    SourceVersionUnsupported,
    TargetVersionUnsupported,
    VersionSupportNotEvaluated,
    DowngradeOrContractRemoval,
    MigrationCatalogIncomplete,
    UnsafeChange,
    UnresolvedChange,
    RemovedFieldWithoutReplacement,
    AffectedSurfaceUnresolved,
    UnresolvedCountryOrOperatorDecision,
    RerunGateFailed,
    RerunGateNotRun,
    ExplicitWriteAuthorityMissing,
    WriteAuthorityScopeMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEvidenceLimitation {
    OfflineStaticOnly,
    MigrationNotPerformed,
    CandidateDoesNotApplyMigration,
    AuthoredFilesNeverOverwritten,
    SecretMaterialNotInspected,
    RawAuthoredValuesOmitted,
    RuntimeNotEvaluated,
    DeploymentNotPerformed,
    CountryApprovalNotInferred,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectMigrationInput {
    pub source_versions: AuthoringVersionSet,
    pub target_versions: AuthoringVersionSet,
    pub version_support: MigrationVersionSupportAssessment,
    pub changes: Vec<MigrationChangeInput>,
    pub affected: MigrationAffectedSurfaces,
    pub approved_reviews: Vec<MigrationReviewClass>,
    pub output: MigrationOutputRequest,
    pub rerun_gates: MigrationGateResults,
    pub diagnostics: Vec<MigrationDiagnostic>,
    pub unresolved_decisions: Vec<UnresolvedMigrationDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMigrationReportV1 {
    pub schema_version: ProjectMigrationSchemaVersion,
    pub evidence_grade: MigrationEvidenceGrade,
    pub migration_execution: MigrationExecution,
    pub disposition: MigrationDisposition,
    pub version_support: MigrationVersionSupportAssessment,
    pub version_transitions: Vec<MigrationVersionTransition>,
    pub compatibility: MigrationCompatibility,
    pub compatible_normalizations: Vec<MigrationChange>,
    pub semantic_changes: Vec<MigrationChange>,
    pub affected: MigrationAffectedSurfaces,
    pub reviews: Vec<MigrationReviewAssessment>,
    pub output: MigrationOutputPlan,
    pub rerun_gates: Vec<MigrationGateAssessment>,
    pub diagnostics: Vec<MigrationDiagnostic>,
    pub unresolved_decisions: Vec<UnresolvedMigrationDecision>,
    pub blocking_reasons: Vec<MigrationBlockingReason>,
    pub evidence_limitations: Vec<MigrationEvidenceLimitation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectMigrationReportWire {
    schema_version: ProjectMigrationSchemaVersion,
    evidence_grade: MigrationEvidenceGrade,
    migration_execution: MigrationExecution,
    disposition: MigrationDisposition,
    version_support: MigrationVersionSupportAssessment,
    version_transitions: Vec<MigrationVersionTransition>,
    compatibility: MigrationCompatibility,
    compatible_normalizations: Vec<MigrationChange>,
    semantic_changes: Vec<MigrationChange>,
    affected: MigrationAffectedSurfaces,
    reviews: Vec<MigrationReviewAssessment>,
    output: MigrationOutputPlan,
    rerun_gates: Vec<MigrationGateAssessment>,
    diagnostics: Vec<MigrationDiagnostic>,
    unresolved_decisions: Vec<UnresolvedMigrationDecision>,
    blocking_reasons: Vec<MigrationBlockingReason>,
    evidence_limitations: Vec<MigrationEvidenceLimitation>,
}

impl<'de> Deserialize<'de> for ProjectMigrationReportV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProjectMigrationReportWire::deserialize(deserializer)?;
        let candidate = Self {
            schema_version: wire.schema_version,
            evidence_grade: wire.evidence_grade,
            migration_execution: wire.migration_execution,
            disposition: wire.disposition,
            version_support: wire.version_support,
            version_transitions: wire.version_transitions,
            compatibility: wire.compatibility,
            compatible_normalizations: wire.compatible_normalizations,
            semantic_changes: wire.semantic_changes,
            affected: wire.affected,
            reviews: wire.reviews,
            output: wire.output,
            rerun_gates: wire.rerun_gates,
            diagnostics: wire.diagnostics,
            unresolved_decisions: wire.unresolved_decisions,
            blocking_reasons: wire.blocking_reasons,
            evidence_limitations: wire.evidence_limitations,
        };
        let expected = rebuild_report_from_wire(&candidate).map_err(de::Error::custom)?;
        if candidate != expected {
            return Err(de::Error::custom(
                "migration report decisions do not match its classified migration evidence",
            ));
        }
        Ok(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectMigrationBuildError {
    MissingProjectVersion,
    InvalidAuthoringVersion,
    InvalidVersionSupportEvidence,
    InvalidPreMigrationEvidence,
    InvalidGateStatus,
    TooManyChanges,
    InvalidChange,
    TooManyAffectedItems,
    InvalidAffectedCount,
    TooManyReviewApprovals,
    ApprovalNotRequired,
    TooManyDecisions,
    TooManyDiagnostics,
    InvalidDiagnostic,
    InvalidCandidateEmission,
}

fn rebuild_report_from_wire(
    report: &ProjectMigrationReportV1,
) -> Result<ProjectMigrationReportV1, &'static str> {
    if report.version_transitions.len() != AuthoringContract::ALL.len()
        || report
            .version_transitions
            .iter()
            .zip(AuthoringContract::ALL)
            .any(|(transition, expected)| transition.contract != expected)
    {
        return Err("migration version transitions are not in canonical order");
    }

    let changes = report
        .compatible_normalizations
        .iter()
        .chain(&report.semantic_changes)
        .copied()
        .map(MigrationChange::to_input)
        .collect::<Result<Vec<_>, _>>()?;
    let approved_reviews = report
        .reviews
        .iter()
        .filter(|review| review.status == MigrationReviewStatus::Approved)
        .map(|review| review.class)
        .collect::<Vec<_>>();
    let output = MigrationOutputRequest {
        mode: report.output.mode,
        write_authority: report.output.write_authority,
        candidate_emission: report.output.candidate_emission,
    };
    build_project_migration_report(ProjectMigrationInput {
        source_versions: AuthoringVersionSet::from_transitions(&report.version_transitions, true),
        target_versions: AuthoringVersionSet::from_transitions(&report.version_transitions, false),
        version_support: report.version_support,
        changes,
        affected: report.affected.clone(),
        approved_reviews,
        output,
        rerun_gates: MigrationGateResults::from_assessments(&report.rerun_gates)?,
        diagnostics: report.diagnostics.clone(),
        unresolved_decisions: report.unresolved_decisions.clone(),
    })
    .map_err(|_| "migration report evidence cannot be rebuilt")
}

pub fn build_project_migration_report(
    input: ProjectMigrationInput,
) -> Result<ProjectMigrationReportV1, ProjectMigrationBuildError> {
    validate_versions(input.source_versions)?;
    validate_versions(input.target_versions)?;
    validate_version_support_evidence(
        input.source_versions,
        input.target_versions,
        input.version_support,
    )?;
    validate_pre_migration_evidence(&input)?;
    if (input.source_versions.project.is_none()
        && input.version_support.source == MigrationVersionSupport::Supported)
        || (input.target_versions.project.is_none()
            && input.version_support.target != MigrationVersionSupport::Unsupported)
    {
        return Err(ProjectMigrationBuildError::MissingProjectVersion);
    }
    if input.changes.len() > MAX_MIGRATION_CHANGES {
        return Err(ProjectMigrationBuildError::TooManyChanges);
    }
    if input.unresolved_decisions.len() > MAX_MIGRATION_DECISIONS {
        return Err(ProjectMigrationBuildError::TooManyDecisions);
    }
    if input.diagnostics.len() > MAX_MIGRATION_DIAGNOSTICS {
        return Err(ProjectMigrationBuildError::TooManyDiagnostics);
    }
    if input.approved_reviews.len() > MigrationReviewClass::COUNT {
        return Err(ProjectMigrationBuildError::TooManyReviewApprovals);
    }
    validate_affected(&input.affected)?;

    let version_transitions = AuthoringContract::ALL
        .into_iter()
        .map(|contract| {
            let source_version = input.source_versions.get(contract);
            let target_version = input.target_versions.get(contract);
            MigrationVersionTransition {
                contract,
                source_version,
                target_version,
                direction: version_direction(
                    source_version,
                    target_version,
                    input.version_support.target,
                ),
            }
        })
        .collect::<Vec<_>>();
    let version_changed = version_transitions.iter().any(|transition| {
        transition.direction != MigrationVersionDirection::Same
            && transition.direction != MigrationVersionDirection::Absent
    });

    let mut changes = input
        .changes
        .into_iter()
        .map(classify_change)
        .collect::<Result<Vec<_>, _>>()?;
    changes.sort_unstable();
    changes.dedup();
    let (mut compatible_normalizations, mut semantic_changes): (Vec<_>, Vec<_>) = changes
        .into_iter()
        .partition(|change| change.is_compatible_normalization());
    compatible_normalizations.sort_unstable();
    semantic_changes.sort_unstable();

    let mut affected = input.affected;
    affected.generated_artifacts.sort_unstable();
    affected.generated_artifacts.dedup();

    let mut unresolved_decisions = input.unresolved_decisions;
    unresolved_decisions.sort_unstable();
    unresolved_decisions.dedup();
    let mut diagnostics = input.diagnostics;
    diagnostics.sort_unstable();
    diagnostics.dedup();
    validate_diagnostics(&diagnostics, input.version_support, input.rerun_gates)?;

    let transition_supported = input.version_support.source == MigrationVersionSupport::Supported
        && input.version_support.target == MigrationVersionSupport::Supported;
    let required_reviews = required_reviews(
        transition_supported && version_changed,
        &compatible_normalizations,
        &semantic_changes,
        &affected,
    );
    let approved_reviews = input.approved_reviews.into_iter().collect::<BTreeSet<_>>();
    if approved_reviews
        .iter()
        .any(|review| !required_reviews.contains(review))
    {
        return Err(ProjectMigrationBuildError::ApprovalNotRequired);
    }
    let reviews = required_reviews
        .iter()
        .map(|class| MigrationReviewAssessment {
            class: *class,
            status: if approved_reviews.contains(class) {
                MigrationReviewStatus::Approved
            } else {
                MigrationReviewStatus::RequiredPending
            },
        })
        .collect::<Vec<_>>();

    let rerun_gates = MigrationRerunGate::ALL
        .into_iter()
        .map(|gate| MigrationGateAssessment {
            gate,
            status: input.rerun_gates.get(gate),
        })
        .collect::<Vec<_>>();

    let no_changes = compatible_normalizations.is_empty() && semantic_changes.is_empty();
    let compatibility = migration_compatibility(
        input.version_support,
        &version_transitions,
        version_changed,
        no_changes,
        &semantic_changes,
    );

    let mut blocking_reasons = BTreeSet::new();
    add_version_blockers(
        input.version_support,
        &version_transitions,
        version_changed,
        no_changes,
        &mut blocking_reasons,
    );
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.phase == MigrationDiagnosticPhase::SourceInspection)
    {
        blocking_reasons.insert(MigrationBlockingReason::SourceInspectionFailed);
    }
    for change in compatible_normalizations.iter().chain(&semantic_changes) {
        if change.safety == MigrationSafety::Unsafe {
            blocking_reasons.insert(MigrationBlockingReason::UnsafeChange);
        }
        if change.safety == MigrationSafety::Unresolved
            || change.semantic_effect == MigrationSemanticEffect::Unresolved
            || change.replacement.disposition == MigrationReplacementDisposition::Unresolved
        {
            blocking_reasons.insert(MigrationBlockingReason::UnresolvedChange);
        }
        let field = MigrationField::from_address(change.address)
            .expect("builder only emits catalogued migration fields");
        if change.operation == MigrationOperation::RemoveField
            && change.replacement.disposition == MigrationReplacementDisposition::NoReplacement
            && !field.is_reviewed_retired_attribute_release_field()
        {
            blocking_reasons.insert(MigrationBlockingReason::RemovedFieldWithoutReplacement);
        }
    }
    if affected_counts(&affected).any(MigrationAffectedCount::is_unresolved) {
        blocking_reasons.insert(MigrationBlockingReason::AffectedSurfaceUnresolved);
    }
    if !unresolved_decisions.is_empty() {
        blocking_reasons.insert(MigrationBlockingReason::UnresolvedCountryOrOperatorDecision);
    }

    let migration_required = transition_supported && (version_changed || !no_changes);
    if migration_required {
        if rerun_gates
            .iter()
            .any(|gate| gate.status == MigrationGateStatus::Failed)
        {
            blocking_reasons.insert(MigrationBlockingReason::RerunGateFailed);
        }
        if rerun_gates.iter().any(|gate| {
            matches!(
                gate.status,
                MigrationGateStatus::NotRun | MigrationGateStatus::NotRequired
            )
        }) {
            blocking_reasons.insert(MigrationBlockingReason::RerunGateNotRun);
        }
    }

    if migration_required {
        match (input.output.mode, input.output.write_authority) {
            (MigrationOutputMode::CheckOnly, MigrationWriteAuthority::NotGranted) => {}
            (
                MigrationOutputMode::CheckOnly,
                MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            ) => {
                blocking_reasons.insert(MigrationBlockingReason::WriteAuthorityScopeMismatch);
            }
            (
                MigrationOutputMode::ReviewablePatch | MigrationOutputMode::SeparateOutputDirectory,
                MigrationWriteAuthority::NotGranted,
            ) => {
                blocking_reasons.insert(MigrationBlockingReason::ExplicitWriteAuthorityMissing);
            }
            (
                MigrationOutputMode::ReviewablePatch | MigrationOutputMode::SeparateOutputDirectory,
                MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            ) => {}
        }
    }

    let blocking_reasons = blocking_reasons.into_iter().collect::<Vec<_>>();
    let reviews_pending = reviews
        .iter()
        .any(|review| review.status == MigrationReviewStatus::RequiredPending);
    let disposition = if !blocking_reasons.is_empty() {
        MigrationDisposition::Blocked
    } else if !migration_required {
        MigrationDisposition::NoMigrationRequired
    } else if reviews_pending {
        MigrationDisposition::ReviewRequired
    } else {
        match input.output.mode {
            MigrationOutputMode::CheckOnly => MigrationDisposition::CheckedSafe,
            MigrationOutputMode::ReviewablePatch | MigrationOutputMode::SeparateOutputDirectory => {
                MigrationDisposition::ReadyForExplicitWrite
            }
        }
    };
    let candidate_artifact = match (migration_required, input.output.mode) {
        (false, _) | (_, MigrationOutputMode::CheckOnly) => MigrationCandidateArtifact::None,
        (true, MigrationOutputMode::ReviewablePatch) => MigrationCandidateArtifact::ReviewablePatch,
        (true, MigrationOutputMode::SeparateOutputDirectory) => {
            MigrationCandidateArtifact::SeparateOutputDirectory
        }
    };
    let candidate_eligibility = match (migration_required, input.output.mode) {
        (false, _) | (_, MigrationOutputMode::CheckOnly) => {
            MigrationCandidateEligibility::NotRequested
        }
        _ if blocking_reasons.is_empty() => MigrationCandidateEligibility::EligibleToEmit,
        _ => MigrationCandidateEligibility::Blocked,
    };
    let candidate_emission_valid = matches!(
        (
            candidate_artifact,
            candidate_eligibility,
            input.output.write_authority,
            input.output.candidate_emission,
        ),
        (
            MigrationCandidateArtifact::None,
            MigrationCandidateEligibility::NotRequested,
            _,
            MigrationCandidateEmission::NotEmitted,
        ) | (
            MigrationCandidateArtifact::ReviewablePatch,
            MigrationCandidateEligibility::EligibleToEmit,
            MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            MigrationCandidateEmission::NotEmitted
                | MigrationCandidateEmission::ReviewablePatchCandidateEmitted,
        ) | (
            MigrationCandidateArtifact::SeparateOutputDirectory,
            MigrationCandidateEligibility::EligibleToEmit,
            MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            MigrationCandidateEmission::NotEmitted
                | MigrationCandidateEmission::SeparateOutputCandidateEmitted,
        ) | (
            MigrationCandidateArtifact::ReviewablePatch
                | MigrationCandidateArtifact::SeparateOutputDirectory,
            MigrationCandidateEligibility::Blocked,
            _,
            MigrationCandidateEmission::NotEmitted,
        )
    );
    if !candidate_emission_valid {
        return Err(ProjectMigrationBuildError::InvalidCandidateEmission);
    }

    Ok(ProjectMigrationReportV1 {
        schema_version: ProjectMigrationSchemaVersion::V1,
        evidence_grade: MigrationEvidenceGrade::OfflineStatic,
        migration_execution: MigrationExecution::NotPerformed,
        disposition,
        version_support: input.version_support,
        version_transitions,
        compatibility,
        compatible_normalizations,
        semantic_changes,
        affected,
        reviews,
        output: MigrationOutputPlan {
            mode: input.output.mode,
            write_authority: input.output.write_authority,
            candidate_artifact,
            candidate_eligibility,
            authored_file_policy: MigrationAuthoredFilePolicy::NeverOverwriteAuthoredFiles,
            application_policy: MigrationApplicationPolicy::ExplicitOperatorApplyRequired,
            candidate_emission: input.output.candidate_emission,
        },
        rerun_gates,
        diagnostics,
        unresolved_decisions,
        blocking_reasons,
        evidence_limitations: vec![
            MigrationEvidenceLimitation::OfflineStaticOnly,
            MigrationEvidenceLimitation::MigrationNotPerformed,
            MigrationEvidenceLimitation::CandidateDoesNotApplyMigration,
            MigrationEvidenceLimitation::AuthoredFilesNeverOverwritten,
            MigrationEvidenceLimitation::SecretMaterialNotInspected,
            MigrationEvidenceLimitation::RawAuthoredValuesOmitted,
            MigrationEvidenceLimitation::RuntimeNotEvaluated,
            MigrationEvidenceLimitation::DeploymentNotPerformed,
            MigrationEvidenceLimitation::CountryApprovalNotInferred,
        ],
    })
}

impl MigrationReviewClass {
    pub const ALL: [Self; 13] = [
        Self::Authoring,
        Self::Compatibility,
        Self::Migration,
        Self::Fixtures,
        Self::Relay,
        Self::Notary,
        Self::Interoperability,
        Self::Privacy,
        Self::Security,
        Self::Operations,
        Self::Documentation,
        Self::CountryGovernance,
        Self::Release,
    ];
    const COUNT: usize = Self::ALL.len();
}

fn validate_versions(versions: AuthoringVersionSet) -> Result<(), ProjectMigrationBuildError> {
    for contract in AuthoringContract::ALL {
        if matches!(versions.get(contract), Some(0))
            || versions
                .get(contract)
                .is_some_and(|version| version > MAX_AUTHORING_VERSION)
        {
            return Err(ProjectMigrationBuildError::InvalidAuthoringVersion);
        }
    }
    Ok(())
}

fn validate_version_support_evidence(
    source: AuthoringVersionSet,
    target: AuthoringVersionSet,
    support: MigrationVersionSupportAssessment,
) -> Result<(), ProjectMigrationBuildError> {
    if source.project.is_none() && support.source == MigrationVersionSupport::Supported {
        return Err(ProjectMigrationBuildError::MissingProjectVersion);
    }
    if target.project.is_none() && support.target != MigrationVersionSupport::Unsupported {
        return Err(ProjectMigrationBuildError::MissingProjectVersion);
    }
    if support.target == MigrationVersionSupport::Unsupported
        && AuthoringContract::ALL
            .into_iter()
            .any(|contract| target.get(contract).is_some())
    {
        return Err(ProjectMigrationBuildError::InvalidVersionSupportEvidence);
    }
    Ok(())
}

fn validate_pre_migration_evidence(
    input: &ProjectMigrationInput,
) -> Result<(), ProjectMigrationBuildError> {
    let rejected = input.version_support.source != MigrationVersionSupport::Supported
        || input.version_support.target != MigrationVersionSupport::Supported;
    let gates_not_applicable = MigrationRerunGate::ALL
        .into_iter()
        .all(|gate| input.rerun_gates.get(gate) == MigrationGateStatus::NotApplicable);
    if rejected != gates_not_applicable {
        return Err(ProjectMigrationBuildError::InvalidGateStatus);
    }
    if rejected
        && (!input.changes.is_empty()
            || input.affected != unaffected_surfaces()
            || !input.approved_reviews.is_empty()
            || !input.unresolved_decisions.is_empty())
    {
        return Err(ProjectMigrationBuildError::InvalidPreMigrationEvidence);
    }
    Ok(())
}

fn validate_diagnostics(
    diagnostics: &[MigrationDiagnostic],
    support: MigrationVersionSupportAssessment,
    gates: MigrationGateResults,
) -> Result<(), ProjectMigrationBuildError> {
    for diagnostic in diagnostics {
        let valid = matches!(
            (
                diagnostic.code,
                diagnostic.phase,
                diagnostic.contract,
                diagnostic.remediation,
            ),
            (
                MigrationDiagnosticCode::SourceYamlMalformed,
                MigrationDiagnosticPhase::SourceInspection,
                Some(_),
                MigrationDiagnosticRemediation::CorrectSourceYaml,
            ) | (
                MigrationDiagnosticCode::SourceVersionMissing
                    | MigrationDiagnosticCode::SourceVersionMalformed
                    | MigrationDiagnosticCode::SourceVersionZero
                    | MigrationDiagnosticCode::SourceVersionOutOfBounds
                    | MigrationDiagnosticCode::SourceVersionUnsupported,
                MigrationDiagnosticPhase::VersionInspection,
                Some(_),
                MigrationDiagnosticRemediation::DeclareSupportedVersion,
            ) | (
                MigrationDiagnosticCode::SourceVersionsMixed,
                MigrationDiagnosticPhase::VersionInspection,
                Some(_),
                MigrationDiagnosticRemediation::AlignContractVersions,
            ) | (
                MigrationDiagnosticCode::TargetVersionOutOfBounds
                    | MigrationDiagnosticCode::TargetVersionUnsupported,
                MigrationDiagnosticPhase::VersionInspection,
                None,
                MigrationDiagnosticRemediation::SelectSupportedTargetVersion,
            ) | (
                MigrationDiagnosticCode::RerunGateFailed,
                MigrationDiagnosticPhase::SchemaGate,
                None,
                MigrationDiagnosticRemediation::InspectCandidateSchema,
            ) | (
                MigrationDiagnosticCode::RerunGateFailed,
                MigrationDiagnosticPhase::FixtureGate,
                None,
                MigrationDiagnosticRemediation::RepairFixtures,
            ) | (
                MigrationDiagnosticCode::RerunGateFailed,
                MigrationDiagnosticPhase::CheckGate,
                None,
                MigrationDiagnosticRemediation::ResolveProjectCheck,
            ) | (
                MigrationDiagnosticCode::RerunGateFailed,
                MigrationDiagnosticPhase::BuildGate,
                None,
                MigrationDiagnosticRemediation::ResolveProjectBuild,
            ) | (
                MigrationDiagnosticCode::RerunGateFailed,
                MigrationDiagnosticPhase::GeneratedReferenceGate,
                None,
                MigrationDiagnosticRemediation::RegenerateConfigurationReference,
            )
        );
        if !valid {
            return Err(ProjectMigrationBuildError::InvalidDiagnostic);
        }
    }

    let has_source_diagnostic = diagnostics.iter().any(|diagnostic| {
        matches!(
            diagnostic.phase,
            MigrationDiagnosticPhase::SourceInspection
                | MigrationDiagnosticPhase::VersionInspection
        ) && !matches!(
            diagnostic.code,
            MigrationDiagnosticCode::TargetVersionOutOfBounds
                | MigrationDiagnosticCode::TargetVersionUnsupported
        )
    });
    let has_target_diagnostic = diagnostics.iter().any(|diagnostic| {
        matches!(
            diagnostic.code,
            MigrationDiagnosticCode::TargetVersionOutOfBounds
                | MigrationDiagnosticCode::TargetVersionUnsupported
        )
    });
    if (support.source == MigrationVersionSupport::Supported && has_source_diagnostic)
        || (support.source != MigrationVersionSupport::Supported && !has_source_diagnostic)
        || (support.target == MigrationVersionSupport::Supported && has_target_diagnostic)
        || (support.target != MigrationVersionSupport::Supported && !has_target_diagnostic)
    {
        return Err(ProjectMigrationBuildError::InvalidDiagnostic);
    }

    for gate in MigrationRerunGate::ALL {
        let phase = diagnostic_phase_for_gate(gate);
        let diagnostic_count = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.phase == phase)
            .count();
        let expected = usize::from(gates.get(gate) == MigrationGateStatus::Failed);
        if diagnostic_count != expected {
            return Err(ProjectMigrationBuildError::InvalidDiagnostic);
        }
    }
    Ok(())
}

const fn diagnostic_phase_for_gate(gate: MigrationRerunGate) -> MigrationDiagnosticPhase {
    match gate {
        MigrationRerunGate::Schema => MigrationDiagnosticPhase::SchemaGate,
        MigrationRerunGate::Fixture => MigrationDiagnosticPhase::FixtureGate,
        MigrationRerunGate::Check => MigrationDiagnosticPhase::CheckGate,
        MigrationRerunGate::Build => MigrationDiagnosticPhase::BuildGate,
        MigrationRerunGate::GeneratedReference => MigrationDiagnosticPhase::GeneratedReferenceGate,
    }
}

fn version_direction(
    source: Option<u32>,
    target: Option<u32>,
    target_support: MigrationVersionSupport,
) -> MigrationVersionDirection {
    if target_support == MigrationVersionSupport::Unsupported {
        return MigrationVersionDirection::UnsupportedTarget;
    }
    match (source, target) {
        (None, None) => MigrationVersionDirection::Absent,
        (Some(source), Some(target)) if source == target => MigrationVersionDirection::Same,
        (Some(source), Some(target)) if source < target => MigrationVersionDirection::Upgrade,
        (Some(_), Some(_)) => MigrationVersionDirection::Downgrade,
        (None, Some(_)) => MigrationVersionDirection::AddedContract,
        (Some(_), None) => MigrationVersionDirection::RemovedContract,
    }
}

fn classify_change(
    input: MigrationChangeInput,
) -> Result<MigrationChange, ProjectMigrationBuildError> {
    let replacement = MigrationReplacement::from_input(input.replacement);
    let replacement_valid = match input.operation {
        MigrationOperation::NormalizeField
        | MigrationOperation::AddField
        | MigrationOperation::ChangeSemantics => {
            replacement.disposition == MigrationReplacementDisposition::NotApplicable
        }
        MigrationOperation::RemoveField => matches!(
            replacement.disposition,
            MigrationReplacementDisposition::Field
                | MigrationReplacementDisposition::NoReplacement
                | MigrationReplacementDisposition::Unresolved
        ),
        MigrationOperation::RenameField => matches!(
            replacement.disposition,
            MigrationReplacementDisposition::Field | MigrationReplacementDisposition::Unresolved
        ),
    };
    let effect_valid = match input.operation {
        MigrationOperation::NormalizeField => {
            input.semantic_effect == MigrationSemanticEffect::Preserved
                && input.safety == MigrationSafety::Safe
        }
        MigrationOperation::ChangeSemantics => {
            input.semantic_effect != MigrationSemanticEffect::Preserved
        }
        MigrationOperation::RemoveField
            if replacement.disposition == MigrationReplacementDisposition::NoReplacement
                && !input.field.is_reviewed_retired_attribute_release_field() =>
        {
            input.semantic_effect != MigrationSemanticEffect::Preserved
        }
        _ => true,
    };
    let distinct_replacement = replacement
        .address
        .map(|address| address != input.field.address())
        .unwrap_or(true);
    if !replacement_valid || !effect_valid || !distinct_replacement {
        return Err(ProjectMigrationBuildError::InvalidChange);
    }
    Ok(MigrationChange {
        address: input.field.address(),
        operation: input.operation,
        semantic_effect: input.semantic_effect,
        safety: input.safety,
        replacement,
        owner: input.field.owner(),
        classification: input.field.classification(),
    })
}

fn validate_affected(
    affected: &MigrationAffectedSurfaces,
) -> Result<(), ProjectMigrationBuildError> {
    if affected.generated_artifacts.len() > MigrationArtifact::COUNT {
        return Err(ProjectMigrationBuildError::TooManyAffectedItems);
    }
    for count in affected_counts(affected) {
        if count
            .count
            .is_some_and(|value| value > MAX_MIGRATION_AFFECTED_COUNT)
        {
            return Err(ProjectMigrationBuildError::TooManyAffectedItems);
        }
        let valid = match count.state {
            MigrationAffectedState::NotAffected => count.count == Some(0),
            MigrationAffectedState::Affected => {
                matches!(count.count, Some(value) if value > 0)
            }
            MigrationAffectedState::Unresolved => count.count.is_none(),
        };
        if !valid {
            return Err(ProjectMigrationBuildError::InvalidAffectedCount);
        }
    }
    Ok(())
}

impl MigrationArtifact {
    pub const ALL: [Self; 10] = [
        Self::RelayConfig,
        Self::RelayEnvironmentContract,
        Self::NotaryConfig,
        Self::NotaryEnvironmentContract,
        Self::ProjectExplanation,
        Self::ProjectSemanticImpact,
        Self::ProjectFixtureCoverage,
        Self::ProjectArtifactManifest,
        Self::GeneratedConfigurationReference,
        Self::ReleaseReadinessEvidence,
    ];
    const COUNT: usize = Self::ALL.len();
}

fn affected_counts(
    affected: &MigrationAffectedSurfaces,
) -> impl Iterator<Item = MigrationAffectedCount> {
    [
        affected.fixtures,
        affected.services,
        affected.consultations,
        affected.claims,
        affected.environments,
    ]
    .into_iter()
}

fn migration_compatibility(
    support: MigrationVersionSupportAssessment,
    transitions: &[MigrationVersionTransition],
    version_changed: bool,
    no_changes: bool,
    semantic_changes: &[MigrationChange],
) -> MigrationCompatibility {
    if support.source != MigrationVersionSupport::Supported
        || support.target != MigrationVersionSupport::Supported
    {
        MigrationCompatibility::UnsupportedTransition
    } else if transitions.iter().any(|transition| {
        matches!(
            transition.direction,
            MigrationVersionDirection::Downgrade | MigrationVersionDirection::RemovedContract
        )
    }) {
        MigrationCompatibility::UnsafeOrUnresolved
    } else if version_changed && no_changes {
        MigrationCompatibility::CatalogIncomplete
    } else if !version_changed && no_changes {
        MigrationCompatibility::NoMigrationRequired
    } else if semantic_changes.is_empty() {
        MigrationCompatibility::CompatibleNormalizationOnly
    } else if semantic_changes.iter().any(|change| {
        change.safety != MigrationSafety::Safe
            || change.semantic_effect == MigrationSemanticEffect::Unresolved
            || change.replacement.disposition == MigrationReplacementDisposition::Unresolved
    }) {
        MigrationCompatibility::UnsafeOrUnresolved
    } else {
        MigrationCompatibility::SemanticReviewRequired
    }
}

fn add_version_blockers(
    support: MigrationVersionSupportAssessment,
    transitions: &[MigrationVersionTransition],
    version_changed: bool,
    no_changes: bool,
    blocking: &mut BTreeSet<MigrationBlockingReason>,
) {
    match support.source {
        MigrationVersionSupport::Supported => {}
        MigrationVersionSupport::Unsupported => {
            blocking.insert(MigrationBlockingReason::SourceVersionUnsupported);
        }
        MigrationVersionSupport::NotEvaluated => {
            blocking.insert(MigrationBlockingReason::VersionSupportNotEvaluated);
        }
    }
    match support.target {
        MigrationVersionSupport::Supported => {}
        MigrationVersionSupport::Unsupported => {
            blocking.insert(MigrationBlockingReason::TargetVersionUnsupported);
        }
        MigrationVersionSupport::NotEvaluated => {
            blocking.insert(MigrationBlockingReason::VersionSupportNotEvaluated);
        }
    }
    if support.source != MigrationVersionSupport::Supported
        || support.target != MigrationVersionSupport::Supported
    {
        return;
    }
    if transitions.iter().any(|transition| {
        matches!(
            transition.direction,
            MigrationVersionDirection::Downgrade | MigrationVersionDirection::RemovedContract
        )
    }) {
        blocking.insert(MigrationBlockingReason::DowngradeOrContractRemoval);
    }
    if version_changed && no_changes {
        blocking.insert(MigrationBlockingReason::MigrationCatalogIncomplete);
    }
}

fn required_reviews(
    version_changed: bool,
    compatible: &[MigrationChange],
    semantic: &[MigrationChange],
    affected: &MigrationAffectedSurfaces,
) -> BTreeSet<MigrationReviewClass> {
    let mut reviews = BTreeSet::new();
    if version_changed || !compatible.is_empty() || !semantic.is_empty() {
        reviews.extend([
            MigrationReviewClass::Authoring,
            MigrationReviewClass::Compatibility,
            MigrationReviewClass::Migration,
        ]);
    }
    if affected.fixtures.is_affected() {
        reviews.insert(MigrationReviewClass::Fixtures);
    }
    if affected.services.is_affected() {
        reviews.insert(MigrationReviewClass::Relay);
    }
    if affected.consultations.is_affected() {
        reviews.extend([
            MigrationReviewClass::Relay,
            MigrationReviewClass::Notary,
            MigrationReviewClass::Interoperability,
        ]);
    }
    if affected.claims.is_affected() {
        reviews.extend([
            MigrationReviewClass::Notary,
            MigrationReviewClass::Privacy,
            MigrationReviewClass::Security,
        ]);
    }
    if affected.environments.is_affected() {
        reviews.extend([
            MigrationReviewClass::Operations,
            MigrationReviewClass::Security,
        ]);
    }
    for artifact in &affected.generated_artifacts {
        reviews.insert(MigrationReviewClass::Release);
        match artifact {
            MigrationArtifact::RelayConfig | MigrationArtifact::RelayEnvironmentContract => {
                reviews.insert(MigrationReviewClass::Relay);
            }
            MigrationArtifact::NotaryConfig | MigrationArtifact::NotaryEnvironmentContract => {
                reviews.insert(MigrationReviewClass::Notary);
            }
            MigrationArtifact::GeneratedConfigurationReference => {
                reviews.insert(MigrationReviewClass::Documentation);
            }
            _ => {}
        }
    }
    for change in compatible.iter().chain(semantic) {
        let field = MigrationField::from_address(change.address)
            .expect("builder only emits catalogued migration fields");
        match field {
            MigrationField::ProjectServices
            | MigrationField::ServicePolicy
            | MigrationField::Consultation
            | MigrationField::Claim
            | MigrationField::AttributeReleaseSubjectInput
            | MigrationField::AttributeReleaseResponse
            | MigrationField::AttributeReleaseResponseMaxAge => {
                reviews.insert(MigrationReviewClass::CountryGovernance);
            }
            _ => {}
        }
        match field {
            MigrationField::ServicePolicy | MigrationField::Claim => {
                reviews.extend([
                    MigrationReviewClass::Privacy,
                    MigrationReviewClass::Security,
                ]);
            }
            MigrationField::AttributeReleaseResponse
            | MigrationField::AttributeReleaseResponseMaxAge => {
                reviews.extend([
                    MigrationReviewClass::Relay,
                    MigrationReviewClass::Privacy,
                    MigrationReviewClass::Security,
                ]);
            }
            MigrationField::Consultation => {
                reviews.extend([
                    MigrationReviewClass::Relay,
                    MigrationReviewClass::Notary,
                    MigrationReviewClass::Interoperability,
                ]);
            }
            MigrationField::EnvironmentCredentials | MigrationField::EnvironmentTrust => {
                reviews.extend([
                    MigrationReviewClass::Security,
                    MigrationReviewClass::Operations,
                ]);
            }
            MigrationField::EnvironmentVersion
            | MigrationField::EnvironmentOrigin
            | MigrationField::EnvironmentDeployment
            | MigrationField::EnvironmentWorkerLimits => {
                reviews.insert(MigrationReviewClass::Operations);
            }
            _ => {}
        }
    }
    reviews
}

/// Options for a local, offline authoring migration check.
///
/// Candidate publication is deliberately a two-part opt in: callers must name
/// a separate destination and grant candidate-write authority. The source
/// project is never a destination.
#[derive(Clone, Debug)]
pub struct ProjectMigrationOptions {
    pub project_directory: PathBuf,
    pub target_version: u32,
    pub output_directory: Option<PathBuf>,
    pub write_candidate: bool,
}

/// Checks a project migration using the current `registryctl` executable for
/// the same offline fixture workers used by `project test`, `check`, and
/// `build`.
pub fn migrate_registry_project(
    options: &ProjectMigrationOptions,
) -> Result<ProjectMigrationReportV1> {
    let execution_context = super::ProjectExecutionContext::for_current_executable()?;
    migrate_registry_project_with_context(options, &execution_context)
}

/// Checks a project migration with an explicitly reviewed worker executable.
///
/// Only the reviewed v1-to-v1 normalization catalog is implemented. Unknown
/// source or target versions produce a blocked, value-free report. A requested
/// candidate is published atomically to a separate absent directory only
/// after the schema, semantic, fixture, check, build, and generated-reference
/// gates pass.
pub fn migrate_registry_project_with_context(
    options: &ProjectMigrationOptions,
    execution_context: &super::ProjectExecutionContext,
) -> Result<ProjectMigrationReportV1> {
    validate_candidate_options(options)?;
    let root = super::canonical_root(&options.project_directory)?;
    let candidate_destination = options
        .output_directory
        .as_deref()
        .map(|destination| resolve_candidate_destination(&root, destination))
        .transpose()?;
    let inspection = inspect_authoring_contract_versions(&root)?;
    let mut diagnostics = inspection.diagnostics.clone();
    let source_support = if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.phase == MigrationDiagnosticPhase::SourceInspection)
    {
        MigrationVersionSupport::NotEvaluated
    } else if diagnostics.is_empty() {
        MigrationVersionSupport::Supported
    } else {
        MigrationVersionSupport::Unsupported
    };
    let (target_versions, target_support) = target_version_set(
        options.target_version,
        inspection.presence,
        &mut diagnostics,
    );
    let version_support = MigrationVersionSupportAssessment {
        source: source_support,
        target: target_support,
    };
    if version_support.source != MigrationVersionSupport::Supported
        || version_support.target != MigrationVersionSupport::Supported
    {
        return build_migration_report(ProjectMigrationInput {
            source_versions: inspection.versions,
            target_versions,
            version_support,
            changes: Vec::new(),
            affected: unaffected_surfaces(),
            approved_reviews: Vec::new(),
            output: migration_output_request(options, MigrationCandidateEmission::NotEmitted),
            rerun_gates: not_applicable_gates(),
            diagnostics,
            unresolved_decisions: Vec::new(),
        });
    }

    let project_document = inspection
        .project_document
        .as_ref()
        .ok_or_else(|| anyhow!("supported source inspection must retain the project document"))?;
    let project_bytes = inspection
        .project_bytes
        .as_ref()
        .ok_or_else(|| anyhow!("supported source inspection must retain the project bytes"))?;
    let transform = apply_same_v1_attribute_release_catalog(project_document, project_bytes)?;
    if transform.changed.changes.is_empty() {
        // A current project is already canonical. Loading proves it still
        // satisfies the current contract, but migration never rewrites it for
        // formatting alone.
        super::load_registry_project(&root, None)?;
        for environment in &inspection.environments {
            super::load_registry_project(&root, Some(environment))?;
        }
        return build_migration_report(ProjectMigrationInput {
            source_versions: inspection.versions,
            target_versions,
            version_support: supported_versions(),
            changes: Vec::new(),
            affected: unaffected_surfaces(),
            approved_reviews: Vec::new(),
            output: migration_output_request(options, MigrationCandidateEmission::NotEmitted),
            rerun_gates: not_required_gates(),
            diagnostics: Vec::new(),
            unresolved_decisions: Vec::new(),
        });
    }

    let validation = tempfile::Builder::new()
        .prefix("registryctl-migration-validation-")
        .tempdir()
        .context("failed to create private migration validation directory")?;
    tighten_private_directory(validation.path())?;
    stage_catalog_candidate(&root, validation.path(), &transform.project_bytes)?;
    let validation_root = super::canonical_root(validation.path())?;
    let candidate = super::load_registry_project(&validation_root, None)?;
    let mut candidate_environments = Vec::with_capacity(inspection.environments.len());
    for environment in &inspection.environments {
        candidate_environments.push((
            environment.clone(),
            super::load_registry_project(&validation_root, Some(environment))?,
        ));
    }
    let candidate_files =
        collect_authored_files(&validation_root, &candidate, &candidate_environments)?;
    let gate_run = run_migration_gates(
        &validation_root,
        &inspection.environments,
        execution_context,
    );
    let affected = affected_surfaces(
        &candidate,
        &transform.changed,
        inspection.environments.len(),
    )?;
    let requested_output =
        migration_output_request(options, MigrationCandidateEmission::NotEmitted);
    let preliminary = build_migration_report(ProjectMigrationInput {
        source_versions: inspection.versions,
        target_versions,
        version_support: supported_versions(),
        changes: transform.changed.changes.clone(),
        affected: affected.clone(),
        approved_reviews: Vec::new(),
        output: requested_output,
        rerun_gates: gate_run.results,
        diagnostics: gate_run.diagnostics.clone(),
        unresolved_decisions: Vec::new(),
    })?;

    let Some(destination) = candidate_destination else {
        return Ok(preliminary);
    };
    if preliminary.output.candidate_eligibility != MigrationCandidateEligibility::EligibleToEmit {
        return Ok(preliminary);
    }

    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("migration candidate destination has no parent"))?;
    let staging = tempfile::Builder::new()
        .prefix(".registryctl-migration-")
        .tempdir_in(parent)
        .context("failed to create private migration candidate staging directory")?;
    tighten_private_directory(staging.path())?;
    write_candidate_tree(staging.path(), &candidate_files)?;
    let final_report = build_migration_report(ProjectMigrationInput {
        source_versions: inspection.versions,
        target_versions,
        version_support: supported_versions(),
        changes: transform.changed.changes,
        affected,
        approved_reviews: Vec::new(),
        output: migration_output_request(
            options,
            MigrationCandidateEmission::SeparateOutputCandidateEmitted,
        ),
        rerun_gates: gate_run.results,
        diagnostics: gate_run.diagnostics,
        unresolved_decisions: Vec::new(),
    })?;
    let report_bytes =
        serde_json::to_vec_pretty(&final_report).context("failed to serialize migration report")?;
    super::write_private_file(&staging.path().join("migration-report.json"), &report_bytes)?;
    super::rename_project_init_noreplace(staging.path(), &destination)?;
    Ok(final_report)
}

fn validate_candidate_options(options: &ProjectMigrationOptions) -> Result<()> {
    match (options.output_directory.is_some(), options.write_candidate) {
        (false, false) | (true, true) => Ok(()),
        (true, false) => {
            bail!("--output requires explicit --write-candidate authority")
        }
        (false, true) => {
            bail!("--write-candidate requires a separate --output destination")
        }
    }
}

#[derive(Clone, Copy)]
struct AuthoringContractPresence {
    project: bool,
    integration: bool,
    entity: bool,
    fixture: bool,
    environment: bool,
}

#[derive(Clone)]
struct AuthoringVersionInspection {
    versions: AuthoringVersionSet,
    presence: AuthoringContractPresence,
    environments: Vec<String>,
    project_document: Option<Value>,
    project_bytes: Option<Vec<u8>>,
    diagnostics: Vec<MigrationDiagnostic>,
}

fn inspect_authoring_contract_versions(root: &Path) -> Result<AuthoringVersionInspection> {
    let project_path = root.join(super::PROJECT_FILE);
    let project_bytes = super::read_authored_file(root, &project_path)?;
    let project: Value = match serde_norway::from_slice(&project_bytes) {
        Ok(project) => project,
        Err(_) => {
            return Ok(AuthoringVersionInspection {
                versions: empty_versions(),
                presence: AuthoringContractPresence {
                    project: true,
                    integration: false,
                    entity: false,
                    fixture: false,
                    environment: false,
                },
                environments: Vec::new(),
                project_document: None,
                project_bytes: None,
                diagnostics: vec![source_yaml_diagnostic(AuthoringContract::Project)],
            })
        }
    };
    let mut diagnostics = Vec::new();
    let project_version =
        inspect_document_version(&project, AuthoringContract::Project, &mut diagnostics);
    let integration_documents = inspect_referenced_contracts(root, &project, "integrations")?;
    let entity_documents = inspect_referenced_contracts(root, &project, "entities")?;
    let mut integration_versions = Vec::with_capacity(integration_documents.len());
    let mut fixture_versions = Vec::new();
    for (document, relative) in &integration_documents {
        let Some(document) = document.as_ref() else {
            diagnostics.push(source_yaml_diagnostic(AuthoringContract::Integration));
            integration_versions.push(None);
            continue;
        };
        let version =
            inspect_document_version(document, AuthoringContract::Integration, &mut diagnostics);
        integration_versions.push(version);
        if integration_has_fixtures(root, relative)? {
            fixture_versions.push(version);
        }
    }
    let mut entity_versions = Vec::with_capacity(entity_documents.len());
    for (document, _) in &entity_documents {
        let Some(document) = document.as_ref() else {
            diagnostics.push(source_yaml_diagnostic(AuthoringContract::Entity));
            entity_versions.push(None);
            continue;
        };
        entity_versions.push(inspect_document_version(
            document,
            AuthoringContract::Entity,
            &mut diagnostics,
        ));
    }
    let environments = migration_environment_names(root)?;
    let mut environment_versions = Vec::with_capacity(environments.len());
    for environment in &environments {
        let relative = PathBuf::from("environments").join(format!("{environment}.yaml"));
        let path = super::resolve_authored_path(root, &relative)?;
        let bytes = super::read_authored_file(root, &path)?;
        let document: Value = match serde_norway::from_slice(&bytes) {
            Ok(document) => document,
            Err(_) => {
                diagnostics.push(source_yaml_diagnostic(AuthoringContract::Environment));
                continue;
            }
        };
        environment_versions.push(inspect_document_version(
            &document,
            AuthoringContract::Environment,
            &mut diagnostics,
        ));
    }
    let integration = representative_contract_version(
        &integration_versions,
        AuthoringContract::Integration,
        &mut diagnostics,
    );
    let entity = representative_contract_version(
        &entity_versions,
        AuthoringContract::Entity,
        &mut diagnostics,
    );
    let fixture = representative_contract_version(
        &fixture_versions,
        AuthoringContract::Fixture,
        &mut diagnostics,
    );
    let environment = representative_contract_version(
        &environment_versions,
        AuthoringContract::Environment,
        &mut diagnostics,
    );
    diagnostics.sort_unstable();
    diagnostics.dedup();
    Ok(AuthoringVersionInspection {
        versions: AuthoringVersionSet {
            project: project_version,
            integration,
            entity,
            // Fixture documents deliberately have no independent version.
            // Presence is real fixture YAML, and their version follows the
            // integration contract that owns them.
            fixture,
            environment,
        },
        presence: AuthoringContractPresence {
            project: true,
            integration: !integration_documents.is_empty(),
            entity: !entity_documents.is_empty(),
            fixture: !fixture_versions.is_empty(),
            environment: !environments.is_empty(),
        },
        environments,
        project_document: Some(project),
        project_bytes: Some(project_bytes),
        diagnostics,
    })
}

fn inspect_document_version(
    document: &Value,
    contract: AuthoringContract,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> Option<u32> {
    let Some(version) = document
        .as_object()
        .and_then(|object| object.get("version"))
    else {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionMissing,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
        return None;
    };
    let Some(version) = version.as_u64() else {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionMalformed,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
        return None;
    };
    if version == 0 {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionZero,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
        return None;
    }
    let Ok(version) = u32::try_from(version) else {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionOutOfBounds,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
        return None;
    };
    if version > MAX_AUTHORING_VERSION {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionOutOfBounds,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
        return None;
    }
    if version != 1 {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionUnsupported,
            contract,
            MigrationDiagnosticRemediation::DeclareSupportedVersion,
        ));
    }
    Some(version)
}

fn inspect_referenced_contracts(
    root: &Path,
    project: &Value,
    field: &str,
) -> Result<Vec<(Option<Value>, PathBuf)>> {
    let Some(references) = project
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_object)
    else {
        return Ok(Vec::new());
    };
    let mut documents = Vec::with_capacity(references.len());
    for reference in references.values() {
        let relative = reference
            .as_object()
            .and_then(|object| object.get("file"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("authoring file reference is missing or invalid"))?;
        let relative = PathBuf::from(relative);
        let path = super::resolve_authored_path(root, &relative)?;
        let bytes = super::read_authored_file(root, &path)?;
        let document = serde_norway::from_slice(&bytes).ok();
        documents.push((document, relative));
    }
    Ok(documents)
}

fn representative_contract_version(
    versions: &[Option<u32>],
    contract: AuthoringContract,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> Option<u32> {
    let representative = versions.iter().flatten().copied().min()?;
    if versions
        .iter()
        .flatten()
        .any(|version| *version != representative)
    {
        diagnostics.push(version_diagnostic(
            MigrationDiagnosticCode::SourceVersionsMixed,
            contract,
            MigrationDiagnosticRemediation::AlignContractVersions,
        ));
    }
    Some(representative)
}

fn integration_has_fixtures(root: &Path, relative: &Path) -> Result<bool> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let directory_relative = parent.join("fixtures");
    super::validate_relative_authored_path(&directory_relative)?;
    let directory = root.join(&directory_relative);
    super::reject_symlink_components(root, &directory)?;
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("failed to inspect integration fixture directory"),
    };
    if !metadata.is_dir() {
        bail!("integration fixture path must be a real directory");
    }
    for entry in fs::read_dir(&directory).context("failed to inspect integration fixtures")? {
        let entry = entry.context("failed to inspect integration fixture entry")?;
        let metadata =
            fs::symlink_metadata(entry.path()).context("failed to inspect integration fixture")?;
        if metadata.file_type().is_symlink() {
            bail!("symlinks are forbidden at the project authoring boundary");
        }
        if metadata.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("yaml")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

const fn empty_versions() -> AuthoringVersionSet {
    AuthoringVersionSet {
        project: None,
        integration: None,
        entity: None,
        fixture: None,
        environment: None,
    }
}

const fn source_yaml_diagnostic(contract: AuthoringContract) -> MigrationDiagnostic {
    MigrationDiagnostic {
        code: MigrationDiagnosticCode::SourceYamlMalformed,
        phase: MigrationDiagnosticPhase::SourceInspection,
        contract: Some(contract),
        remediation: MigrationDiagnosticRemediation::CorrectSourceYaml,
    }
}

const fn version_diagnostic(
    code: MigrationDiagnosticCode,
    contract: AuthoringContract,
    remediation: MigrationDiagnosticRemediation,
) -> MigrationDiagnostic {
    MigrationDiagnostic {
        code,
        phase: MigrationDiagnosticPhase::VersionInspection,
        contract: Some(contract),
        remediation,
    }
}

fn target_version_set(
    target_version: u32,
    presence: AuthoringContractPresence,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> (AuthoringVersionSet, MigrationVersionSupport) {
    if target_version == 0 || target_version > MAX_AUTHORING_VERSION {
        diagnostics.push(MigrationDiagnostic {
            code: MigrationDiagnosticCode::TargetVersionOutOfBounds,
            phase: MigrationDiagnosticPhase::VersionInspection,
            contract: None,
            remediation: MigrationDiagnosticRemediation::SelectSupportedTargetVersion,
        });
        return (empty_versions(), MigrationVersionSupport::Unsupported);
    }
    if target_version != 1 {
        diagnostics.push(MigrationDiagnostic {
            code: MigrationDiagnosticCode::TargetVersionUnsupported,
            phase: MigrationDiagnosticPhase::VersionInspection,
            contract: None,
            remediation: MigrationDiagnosticRemediation::SelectSupportedTargetVersion,
        });
        (empty_versions(), MigrationVersionSupport::Unsupported)
    } else {
        let versions = AuthoringVersionSet {
            project: presence.project.then_some(target_version),
            integration: presence.integration.then_some(target_version),
            entity: presence.entity.then_some(target_version),
            fixture: presence.fixture.then_some(target_version),
            environment: presence.environment.then_some(target_version),
        };
        (versions, MigrationVersionSupport::Supported)
    }
}

struct CatalogTransform {
    project_bytes: Vec<u8>,
    changed: ChangedDocuments,
}

fn apply_same_v1_attribute_release_catalog(
    source: &Value,
    source_bytes: &[u8],
) -> Result<CatalogTransform> {
    let mut candidate = source.clone();
    let mut changes = BTreeSet::new();
    let mut affected_services = 0;
    let Some(services) = candidate
        .as_object_mut()
        .and_then(|project| project.get_mut("services"))
        .and_then(Value::as_object_mut)
    else {
        return Ok(CatalogTransform {
            project_bytes: source_bytes.to_vec(),
            changed: ChangedDocuments::default(),
        });
    };

    for service in services.values_mut() {
        let Some(profiles) = service
            .as_object_mut()
            .and_then(|service| service.get_mut("api"))
            .and_then(Value::as_object_mut)
            .and_then(|api| api.get_mut("attribute_release_profiles"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        let mut service_changed = false;
        for profile in profiles.values_mut() {
            let Some(profile) = profile.as_object_mut() else {
                continue;
            };
            if let Some(subject) = profile.get_mut("subject").and_then(Value::as_object_mut) {
                let removable_input = subject
                    .get("input")
                    .and_then(Value::as_str)
                    .is_some_and(|input| super::validate_input_name(input).is_ok());
                if removable_input {
                    subject.remove("input");
                    changes.insert(retired_field_removal(
                        MigrationField::AttributeReleaseSubjectInput,
                        MigrationSemanticEffect::Preserved,
                    ));
                    service_changed = true;
                }
            }

            let mut remove_response = false;
            let mut response_effect = None;
            if let Some(response) = profile.get_mut("response").and_then(Value::as_object_mut) {
                let removable_max_age = response
                    .get("max_age_seconds")
                    .and_then(Value::as_u64)
                    .is_some_and(|seconds| (1..=3600).contains(&seconds));
                if removable_max_age {
                    response.remove("max_age_seconds");
                    changes.insert(retired_field_removal(
                        MigrationField::AttributeReleaseResponseMaxAge,
                        MigrationSemanticEffect::Changed,
                    ));
                    response_effect = Some(MigrationSemanticEffect::Changed);
                    service_changed = true;
                }
                if response.is_empty() {
                    remove_response = true;
                    response_effect.get_or_insert(MigrationSemanticEffect::Preserved);
                }
            }
            if remove_response {
                profile.remove("response");
                changes.insert(retired_field_removal(
                    MigrationField::AttributeReleaseResponse,
                    response_effect.expect("empty response has a classified effect"),
                ));
                service_changed = true;
            }
        }
        affected_services += usize::from(service_changed);
    }

    if changes.is_empty() {
        return Ok(CatalogTransform {
            project_bytes: source_bytes.to_vec(),
            changed: ChangedDocuments::default(),
        });
    }
    let project_bytes = serde_norway::to_string(&candidate)
        .context("failed to serialize the reviewed same-v1 migration candidate")?
        .into_bytes();
    let reparsed: Value = serde_norway::from_slice(&project_bytes)
        .context("reviewed same-v1 migration candidate did not roundtrip")?;
    if reparsed != candidate {
        bail!("reviewed same-v1 migration candidate changed outside the catalog");
    }
    Ok(CatalogTransform {
        project_bytes,
        changed: ChangedDocuments {
            changes: changes.into_iter().collect(),
            fixtures: 0,
            services: affected_services,
            environments: 0,
        },
    })
}

const fn retired_field_removal(
    field: MigrationField,
    semantic_effect: MigrationSemanticEffect,
) -> MigrationChangeInput {
    MigrationChangeInput {
        field,
        operation: MigrationOperation::RemoveField,
        semantic_effect,
        safety: MigrationSafety::Safe,
        replacement: MigrationReplacementInput::NoReplacement,
    }
}

fn stage_catalog_candidate(root: &Path, candidate: &Path, project_bytes: &[u8]) -> Result<()> {
    const MAX_STAGE_FILES: usize = 4096;
    const MAX_STAGE_FILE_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_STAGE_BYTES: u64 = 64 * 1024 * 1024;

    // The compatibility adapter never follows links. This temporary full-tree
    // staging is needed only because the old project cannot pass the current
    // strict loader before its retired fields are removed. Final candidates
    // are reduced back to the loader's exact artifact-input closure.
    fn visit(
        root: &Path,
        directory: &Path,
        candidate: &Path,
        files: &mut usize,
        bytes: &mut u64,
    ) -> Result<()> {
        let mut entries = fs::read_dir(directory)
            .context("failed to inspect migration source directory")?
            .collect::<Result<Vec<_>, _>>()
            .context("failed to inspect migration source entry")?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("migration source entry escaped its root"))?;
            if relative == Path::new(super::PROJECT_FILE) {
                continue;
            }
            if relative.components().count() == 1
                && matches!(
                    relative.file_name().and_then(|name| name.to_str()),
                    Some(".git" | ".registry-stack")
                )
            {
                continue;
            }
            let metadata =
                fs::symlink_metadata(&path).context("failed to inspect migration source entry")?;
            if metadata.file_type().is_symlink() {
                bail!("symlinks are forbidden at the migration source boundary");
            }
            if metadata.is_dir() {
                visit(root, &path, candidate, files, bytes)?;
                continue;
            }
            if !metadata.is_file() || metadata.len() > MAX_STAGE_FILE_BYTES {
                bail!("migration source contains an unsupported or oversized file");
            }
            *files += 1;
            *bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow!("migration source closure exceeds its size bound"))?;
            if *files > MAX_STAGE_FILES || *bytes > MAX_STAGE_BYTES {
                bail!("migration source closure exceeds its bounded staging capacity");
            }
            let content = fs::read(&path).context("failed to read migration source entry")?;
            super::write_private_file(&candidate.join(relative), &content)?;
        }
        Ok(())
    }

    super::create_dir_owner_only(candidate)?;
    let mut files = 0;
    let mut bytes = 0;
    visit(root, root, candidate, &mut files, &mut bytes)?;
    super::write_private_file(&candidate.join(super::PROJECT_FILE), project_bytes)
}

fn migration_environment_names(root: &Path) -> Result<Vec<String>> {
    let directory = root.join("environments");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    super::reject_symlink_components(root, &directory)?;
    let metadata = fs::symlink_metadata(&directory)
        .context("failed to inspect project environments directory")?;
    if !metadata.is_dir() {
        bail!("project environments path must be a real directory");
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&directory).context("failed to read project environments")? {
        let entry = entry.context("failed to read project environment entry")?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).context("failed to inspect project environment entry")?;
        if metadata.file_type().is_symlink() {
            bail!("symlinks are forbidden at the project authoring boundary");
        }
        if !metadata.is_file() || path.extension().and_then(|value| value.to_str()) != Some("yaml")
        {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("environment file name is not Unicode"))?;
        super::validate_stable_id(name, "environment")?;
        names.push(name.to_owned());
        if names.len() > super::MAX_ENVIRONMENTS {
            bail!("project contains too many environments");
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn collect_authored_files(
    root: &Path,
    base: &super::LoadedRegistryProject,
    environments: &[(String, super::LoadedRegistryProject)],
) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut paths = BTreeSet::new();
    for input in base.artifact_inputs.iter().chain(
        environments
            .iter()
            .flat_map(|(_, loaded)| &loaded.artifact_inputs),
    ) {
        paths.insert(PathBuf::from(input.path.as_str()));
    }
    let mut files = BTreeMap::new();
    for relative in paths {
        let path = super::resolve_authored_path(root, &relative)?;
        files.insert(relative, super::read_authored_file(root, &path)?);
    }
    Ok(files)
}

#[derive(Clone, Default)]
struct ChangedDocuments {
    changes: Vec<MigrationChangeInput>,
    fixtures: usize,
    services: usize,
    environments: usize,
}

fn write_candidate_tree(root: &Path, files: &BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    super::create_dir_owner_only(root)?;
    for (relative, bytes) in files {
        super::validate_relative_authored_path(relative)?;
        super::write_private_file(&root.join(relative), bytes)?;
    }
    Ok(())
}

#[cfg(unix)]
fn tighten_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("failed to make migration directory owner-only")
}

#[cfg(not(unix))]
fn tighten_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

struct MigrationGateRun {
    results: MigrationGateResults,
    diagnostics: Vec<MigrationDiagnostic>,
}

fn run_migration_gates(
    candidate_root: &Path,
    environments: &[String],
    execution_context: &super::ProjectExecutionContext,
) -> MigrationGateRun {
    let mut diagnostics = Vec::new();
    let schema = gate_status(
        MigrationRerunGate::Schema,
        (|| -> Result<()> {
            super::load_registry_project(candidate_root, None)?;
            for environment in environments {
                super::load_registry_project(candidate_root, Some(environment))?;
            }
            Ok(())
        })(),
        &mut diagnostics,
    );
    let fixture = gate_status(
        MigrationRerunGate::Fixture,
        super::test_registry_project_with_context(
            &super::ProjectTestOptions {
                project_directory: candidate_root.to_path_buf(),
                environment: None,
            },
            execution_context,
        )
        .map(|_| ()),
        &mut diagnostics,
    );
    let check = if environments.is_empty() {
        MigrationGateStatus::NotRun
    } else {
        gate_status(
            MigrationRerunGate::Check,
            (|| -> Result<()> {
                for environment in environments {
                    super::check_registry_project_with_context(
                        &super::ProjectCheckOptions {
                            project_directory: candidate_root.to_path_buf(),
                            environment: environment.clone(),
                            explain: false,
                            against: None,
                            anchor: None,
                        },
                        execution_context,
                    )?;
                }
                Ok(())
            })(),
            &mut diagnostics,
        )
    };
    let build = if environments.is_empty() {
        MigrationGateStatus::NotRun
    } else {
        gate_status(
            MigrationRerunGate::Build,
            (|| -> Result<()> {
                for environment in environments {
                    super::build_registry_project_with_context(
                        &super::ProjectBuildOptions {
                            project_directory: candidate_root.to_path_buf(),
                            environment: environment.clone(),
                            against: None,
                            anchor: None,
                        },
                        execution_context,
                    )?;
                }
                Ok(())
            })(),
            &mut diagnostics,
        )
    };
    let generated_reference = gate_status(
        MigrationRerunGate::GeneratedReference,
        (|| -> Result<()> {
            super::embedded_configuration_reference().map_err(anyhow::Error::from)?;
            let coverage =
                super::embedded_configuration_reference_coverage().map_err(anyhow::Error::from)?;
            if coverage.status != super::CoverageStatus::Complete {
                bail!("generated configuration reference coverage is incomplete");
            }
            Ok(())
        })(),
        &mut diagnostics,
    );
    MigrationGateRun {
        results: MigrationGateResults {
            schema,
            fixture,
            check,
            build,
            generated_reference,
        },
        diagnostics,
    }
}

fn gate_status(
    gate: MigrationRerunGate,
    result: Result<()>,
    diagnostics: &mut Vec<MigrationDiagnostic>,
) -> MigrationGateStatus {
    if result.is_ok() {
        return MigrationGateStatus::Passed;
    }
    let (phase, remediation) = match gate {
        MigrationRerunGate::Schema => (
            MigrationDiagnosticPhase::SchemaGate,
            MigrationDiagnosticRemediation::InspectCandidateSchema,
        ),
        MigrationRerunGate::Fixture => (
            MigrationDiagnosticPhase::FixtureGate,
            MigrationDiagnosticRemediation::RepairFixtures,
        ),
        MigrationRerunGate::Check => (
            MigrationDiagnosticPhase::CheckGate,
            MigrationDiagnosticRemediation::ResolveProjectCheck,
        ),
        MigrationRerunGate::Build => (
            MigrationDiagnosticPhase::BuildGate,
            MigrationDiagnosticRemediation::ResolveProjectBuild,
        ),
        MigrationRerunGate::GeneratedReference => (
            MigrationDiagnosticPhase::GeneratedReferenceGate,
            MigrationDiagnosticRemediation::RegenerateConfigurationReference,
        ),
    };
    diagnostics.push(MigrationDiagnostic {
        code: MigrationDiagnosticCode::RerunGateFailed,
        phase,
        contract: None,
        remediation,
    });
    MigrationGateStatus::Failed
}

fn affected_surfaces(
    loaded: &super::LoadedRegistryProject,
    changed: &ChangedDocuments,
    environment_count: usize,
) -> Result<MigrationAffectedSurfaces> {
    let (relay, notary) = super::project_product_topology(&loaded.project);
    let mut generated_artifacts = vec![
        MigrationArtifact::ProjectExplanation,
        MigrationArtifact::ProjectSemanticImpact,
        MigrationArtifact::ProjectFixtureCoverage,
        MigrationArtifact::ProjectArtifactManifest,
        MigrationArtifact::GeneratedConfigurationReference,
        MigrationArtifact::ReleaseReadinessEvidence,
    ];
    if relay {
        generated_artifacts.extend([
            MigrationArtifact::RelayConfig,
            MigrationArtifact::RelayEnvironmentContract,
        ]);
    }
    if notary {
        generated_artifacts.extend([
            MigrationArtifact::NotaryConfig,
            MigrationArtifact::NotaryEnvironmentContract,
        ]);
    }
    Ok(MigrationAffectedSurfaces {
        fixtures: MigrationAffectedCount::known(bounded_count(changed.fixtures)?),
        services: MigrationAffectedCount::known(bounded_count(changed.services)?),
        consultations: MigrationAffectedCount::known(0),
        claims: MigrationAffectedCount::known(0),
        environments: MigrationAffectedCount::known(bounded_count(
            changed.environments.min(environment_count),
        )?),
        generated_artifacts,
    })
}

fn bounded_count(value: usize) -> Result<u32> {
    u32::try_from(value).context("migration affected count exceeds the supported bound")
}

fn resolve_candidate_destination(root: &Path, requested: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(requested) {
        Ok(_) => bail!("migration candidate destination must not already exist"),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).context("failed to inspect migration candidate destination")
        }
    }
    let file_name = requested
        .file_name()
        .ok_or_else(|| anyhow!("migration candidate destination must name a directory"))?;
    let requested_parent = requested.parent().unwrap_or_else(|| Path::new("."));
    let parent = super::canonical_root(requested_parent)
        .context("migration candidate parent must be an existing real directory")?;
    let destination = parent.join(file_name);
    if destination.starts_with(root) {
        bail!("migration candidate destination must be outside the source project");
    }
    Ok(destination)
}

fn migration_output_request(
    options: &ProjectMigrationOptions,
    candidate_emission: MigrationCandidateEmission,
) -> MigrationOutputRequest {
    if options.output_directory.is_some() {
        MigrationOutputRequest {
            mode: MigrationOutputMode::SeparateOutputDirectory,
            write_authority: MigrationWriteAuthority::ExplicitCandidateWriteGranted,
            candidate_emission,
        }
    } else {
        check_only_output()
    }
}

const fn check_only_output() -> MigrationOutputRequest {
    MigrationOutputRequest {
        mode: MigrationOutputMode::CheckOnly,
        write_authority: MigrationWriteAuthority::NotGranted,
        candidate_emission: MigrationCandidateEmission::NotEmitted,
    }
}

const fn supported_versions() -> MigrationVersionSupportAssessment {
    MigrationVersionSupportAssessment {
        source: MigrationVersionSupport::Supported,
        target: MigrationVersionSupport::Supported,
    }
}

const fn unaffected_surfaces() -> MigrationAffectedSurfaces {
    MigrationAffectedSurfaces {
        fixtures: MigrationAffectedCount::known(0),
        services: MigrationAffectedCount::known(0),
        consultations: MigrationAffectedCount::known(0),
        claims: MigrationAffectedCount::known(0),
        environments: MigrationAffectedCount::known(0),
        generated_artifacts: Vec::new(),
    }
}

const fn not_required_gates() -> MigrationGateResults {
    MigrationGateResults {
        schema: MigrationGateStatus::NotRequired,
        fixture: MigrationGateStatus::NotRequired,
        check: MigrationGateStatus::NotRequired,
        build: MigrationGateStatus::NotRequired,
        generated_reference: MigrationGateStatus::NotRequired,
    }
}

const fn not_applicable_gates() -> MigrationGateResults {
    MigrationGateResults {
        schema: MigrationGateStatus::NotApplicable,
        fixture: MigrationGateStatus::NotApplicable,
        check: MigrationGateStatus::NotApplicable,
        build: MigrationGateStatus::NotApplicable,
        generated_reference: MigrationGateStatus::NotApplicable,
    }
}

fn build_migration_report(input: ProjectMigrationInput) -> Result<ProjectMigrationReportV1> {
    build_project_migration_report(input)
        .map_err(|error| anyhow!("migration report evidence is invalid: {error:?}"))
}
