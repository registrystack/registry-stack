// SPDX-License-Identifier: Apache-2.0
//! Strict, value-free capability inventory for project authoring.
//!
//! The inventory is intentionally limited to closed identifiers, release
//! metadata, state enums, and bounded counts. Country identifiers, origins,
//! paths, secret names, authored values, and runtime observations have no
//! representation in either the builder input or the report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub const PROJECT_CAPABILITY_INVENTORY_SCHEMA_VERSION_V1: &str =
    "registry.project.capability_inventory.v1";
pub(crate) const MAX_CAPABILITY_USAGE_COUNT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectCapabilityInventorySchemaVersion {
    #[serde(rename = "registry.project.capability_inventory.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityInventoryEvidenceGrade {
    OfflineStatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeActivationEvaluation {
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    SourceHttp,
    SourceScript,
    SourceSnapshot,
    RhaiRuntime,
    RhaiAbi,
    RegistryRelayProduct,
    RegistryRelayValidator,
    ProjectAuthoringSchemas,
    RegistryRelayConfigSchema,
}

impl CapabilityId {
    const ALL: [Self; 9] = [
        Self::SourceHttp,
        Self::SourceScript,
        Self::SourceSnapshot,
        Self::RhaiRuntime,
        Self::RhaiAbi,
        Self::RegistryRelayProduct,
        Self::RegistryRelayValidator,
        Self::ProjectAuthoringSchemas,
        Self::RegistryRelayConfigSchema,
    ];

    const fn project_declarable(self) -> bool {
        matches!(
            self,
            Self::SourceHttp
                | Self::SourceScript
                | Self::SourceSnapshot
                | Self::RegistryRelayProduct
        )
    }

    const fn environment_enableable(self) -> bool {
        self.project_declarable()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Source,
    Runtime,
    Abi,
    Product,
    ProductValidator,
    Schema,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOwner {
    Registryctl,
    RegistryRelay,
    ReleaseEngineering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMaturity {
    ReleaseGated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportedCapabilityVersion {
    ProjectAuthoringV1,
    RelayIntegrationPackV1,
    RhaiLanguageV1,
    RhaiXwV1,
    RegistryRelayConfigV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstalledCapabilityState {
    Compiled,
    NotCompiled,
    Unsupported,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstalledCapabilityEvidence {
    LinkedCrate,
    EmbeddedCompiler,
    EmbeddedSchema,
    LinkedProductValidator,
    ReleaseMetadata,
    ExplicitlyUnsupported,
    NoEvidence,
}

pub(crate) const COMPILED_CAPABILITY_RELEASE_FACTS: [(
    CapabilityId,
    InstalledCapabilityState,
    InstalledCapabilityEvidence,
); 9] = [
    (
        CapabilityId::SourceHttp,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::EmbeddedCompiler,
    ),
    (
        CapabilityId::SourceScript,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::EmbeddedCompiler,
    ),
    (
        CapabilityId::SourceSnapshot,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::EmbeddedCompiler,
    ),
    (
        CapabilityId::RhaiRuntime,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::LinkedCrate,
    ),
    (
        CapabilityId::RhaiAbi,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::LinkedCrate,
    ),
    (
        CapabilityId::RegistryRelayProduct,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::LinkedCrate,
    ),
    (
        CapabilityId::RegistryRelayValidator,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::LinkedProductValidator,
    ),
    (
        CapabilityId::ProjectAuthoringSchemas,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::EmbeddedSchema,
    ),
    (
        CapabilityId::RegistryRelayConfigSchema,
        InstalledCapabilityState::Compiled,
        InstalledCapabilityEvidence::EmbeddedSchema,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectDeclarationState {
    Declared,
    NotDeclared,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentEnablementState {
    Enabled,
    NotEnabled,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityUsageCounts {
    pub services: u32,
    pub consultations: u32,
}

impl CapabilityUsageCounts {
    fn total(self) -> Option<u32> {
        self.services.checked_add(self.consultations)
    }

    fn is_empty(self) -> bool {
        self == Self::default()
    }
}

impl Serialize for CapabilityUsageCounts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let total = self
            .total()
            .filter(|total| *total <= MAX_CAPABILITY_USAGE_COUNT)
            .ok_or_else(|| serde::ser::Error::custom("capability usage exceeds the report cap"))?;
        let mut state = serializer.serialize_struct("CapabilityUsageCounts", 3)?;
        state.serialize_field("services", &self.services)?;
        state.serialize_field("consultations", &self.consultations)?;
        state.serialize_field("total", &total)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CapabilityUsageCounts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            services: u32,
            consultations: u32,
            total: u32,
        }

        let wire = Wire::deserialize(deserializer)?;
        let usage = Self {
            services: wire.services,
            consultations: wire.consultations,
        };
        validate_usage(usage).map_err(|_| {
            de::Error::custom("capability usage total exceeds the report aggregate cap")
        })?;
        if usage.total() != Some(wire.total) {
            return Err(de::Error::custom(
                "capability usage total does not equal its breakdown",
            ));
        }
        Ok(usage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDisposition {
    Used,
    UsedButNotEnabled,
    UsedWithMissingSupport,
    DeclaredEnabledUnused,
    DeclaredInactive,
    InstalledUnused,
    UnavailableUnused,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityInventoryRecord {
    pub capability: CapabilityId,
    pub kind: CapabilityKind,
    pub owner: CapabilityOwner,
    pub maturity: CapabilityMaturity,
    pub supported_versions: Vec<SupportedCapabilityVersion>,
    pub installed_release: InstalledCapabilityState,
    pub installed_evidence: InstalledCapabilityEvidence,
    pub project_declaration: ProjectDeclarationState,
    pub environment_enablement: EnvironmentEnablementState,
    pub used_by: CapabilityUsageCounts,
    pub disposition: CapabilityDisposition,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportComponent {
    HttpSourceWorker,
    RhaiScriptWorker,
    SnapshotMaterializationWorker,
    RhaiXwProtocolHelper,
    RegistryRelayProduct,
    RegistryRelayValidator,
    ProjectAuthoringSchema,
    RegistryRelayConfigSchema,
    RegistryctlDistribution,
    RegistryRelayImage,
}

impl SupportComponent {
    const ALL: [Self; 10] = [
        Self::HttpSourceWorker,
        Self::RhaiScriptWorker,
        Self::SnapshotMaterializationWorker,
        Self::RhaiXwProtocolHelper,
        Self::RegistryRelayProduct,
        Self::RegistryRelayValidator,
        Self::ProjectAuthoringSchema,
        Self::RegistryRelayConfigSchema,
        Self::RegistryctlDistribution,
        Self::RegistryRelayImage,
    ];

    const fn is_image(self) -> bool {
        matches!(self, Self::RegistryRelayImage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportKind {
    Worker,
    ProtocolHelper,
    Product,
    ProductValidator,
    Schema,
    Distribution,
    Image,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Available,
    Missing,
    Unsupported,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportEvidence {
    LinkedCrate,
    EmbeddedSchema,
    LinkedProductValidator,
    ReleaseMetadata,
    ExplicitlyMissing,
    ExplicitlyUnsupported,
    NoEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportAssessment {
    pub component: SupportComponent,
    pub kind: SupportKind,
    pub owner: CapabilityOwner,
    pub state: SupportState,
    pub evidence: SupportEvidence,
    pub required_by: Vec<CapabilityId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InactiveOrUnusedReason {
    DeclaredNotEnabled,
    DeclaredEnabledNotUsed,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InactiveOrUnusedDeclaration {
    pub capability: CapabilityId,
    pub reason: InactiveOrUnusedReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MissingSupport {
    pub component: SupportComponent,
    pub kind: SupportKind,
    pub state: SupportState,
    pub required_by: Vec<CapabilityId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectCapabilityInventoryReportV1 {
    pub schema_version: ProjectCapabilityInventorySchemaVersion,
    pub evidence_grade: CapabilityInventoryEvidenceGrade,
    pub runtime_activation: RuntimeActivationEvaluation,
    pub capabilities: Vec<CapabilityInventoryRecord>,
    pub support: Vec<SupportAssessment>,
    pub missing_support: Vec<MissingSupport>,
    pub inactive_or_unused: Vec<InactiveOrUnusedDeclaration>,
}

fn validate_decoded_inventory(
    capabilities: &[CapabilityInventoryRecord],
    support: &[SupportAssessment],
    missing_support: &[MissingSupport],
    inactive_or_unused: &[InactiveOrUnusedDeclaration],
) -> Result<(), &'static str> {
    for assessment in support {
        let metadata = support_metadata(assessment.component);
        if assessment.kind != metadata.kind
            || assessment.owner != metadata.owner
            || assessment.required_by.as_slice() != metadata.required_by
        {
            return Err("support row metadata does not match its closed component");
        }
        validate_support_evidence(assessment.component, assessment.state, assessment.evidence)
            .map_err(|_| "support row state and evidence are inconsistent")?;
    }

    let mut reported_missing = BTreeMap::new();
    for missing in missing_support {
        if reported_missing
            .insert(missing.component, missing)
            .is_some()
        {
            return Err("missing-support rows contain a duplicate component");
        }
    }
    let expected_missing = support
        .iter()
        .filter(|assessment| {
            matches!(
                assessment.state,
                SupportState::Missing | SupportState::Unsupported
            )
        })
        .count();
    if reported_missing.len() != expected_missing {
        return Err("missing-support rows do not match support assessments");
    }
    for assessment in support.iter().filter(|assessment| {
        matches!(
            assessment.state,
            SupportState::Missing | SupportState::Unsupported
        )
    }) {
        let missing = reported_missing
            .get(&assessment.component)
            .ok_or("missing-support row is absent for unavailable support")?;
        if missing.kind != assessment.kind
            || missing.state != assessment.state
            || missing.required_by != assessment.required_by
        {
            return Err("missing-support row contradicts its support assessment");
        }
    }

    let mut reported_inactive = BTreeMap::new();
    for inactive in inactive_or_unused {
        if reported_inactive
            .insert(inactive.capability, inactive.reason)
            .is_some()
        {
            return Err("inactive-or-unused rows contain a duplicate capability");
        }
    }
    let mut expected_inactive = BTreeMap::new();
    for record in capabilities {
        let metadata = capability_metadata(record.capability);
        if record.kind != metadata.kind
            || record.owner != metadata.owner
            || record.supported_versions.as_slice() != metadata.supported_versions
        {
            return Err("capability row metadata does not match its closed capability");
        }
        validate_installed_evidence(record.installed_release, record.installed_evidence)
            .map_err(|_| "installed capability state and evidence are inconsistent")?;

        let declarable = record.capability.project_declarable();
        if declarable
            != matches!(
                record.project_declaration,
                ProjectDeclarationState::Declared | ProjectDeclarationState::NotDeclared
            )
            || declarable
                != matches!(
                    record.environment_enablement,
                    EnvironmentEnablementState::Enabled | EnvironmentEnablementState::NotEnabled
                )
        {
            return Err("capability declaration applicability is inconsistent");
        }
        let declared = record.project_declaration == ProjectDeclarationState::Declared;
        let enabled = record.environment_enablement == EnvironmentEnablementState::Enabled;
        if enabled && !declared {
            return Err("capability is enabled without a project declaration");
        }
        if declarable && !record.used_by.is_empty() && !declared {
            return Err("capability is used without a project declaration");
        }
        let missing_required_support = support.iter().any(|assessment| {
            support_metadata(assessment.component)
                .required_by
                .contains(&record.capability)
                && matches!(
                    assessment.state,
                    SupportState::Missing | SupportState::Unsupported
                )
        });
        if record.disposition
            != capability_disposition(
                record.capability,
                record.installed_release,
                declared,
                enabled,
                record.used_by,
                missing_required_support,
            )
        {
            return Err("capability disposition contradicts its reported state");
        }
        if declared && record.used_by.is_empty() {
            expected_inactive.insert(
                record.capability,
                if enabled {
                    InactiveOrUnusedReason::DeclaredEnabledNotUsed
                } else {
                    InactiveOrUnusedReason::DeclaredNotEnabled
                },
            );
        }
    }
    if reported_inactive != expected_inactive {
        return Err("inactive-or-unused rows do not match capability state");
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ProjectCapabilityInventoryReportV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: ProjectCapabilityInventorySchemaVersion,
            evidence_grade: CapabilityInventoryEvidenceGrade,
            runtime_activation: RuntimeActivationEvaluation,
            capabilities: Vec<CapabilityInventoryRecord>,
            support: Vec<SupportAssessment>,
            missing_support: Vec<MissingSupport>,
            inactive_or_unused: Vec<InactiveOrUnusedDeclaration>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let capability_ids = wire
            .capabilities
            .iter()
            .map(|record| record.capability)
            .collect::<BTreeSet<_>>();
        if wire.capabilities.len() != CapabilityId::ALL.len()
            || capability_ids != CapabilityId::ALL.into_iter().collect()
        {
            return Err(de::Error::custom(
                "capability rows must contain every closed capability exactly once",
            ));
        }
        let support_ids = wire
            .support
            .iter()
            .map(|assessment| assessment.component)
            .collect::<BTreeSet<_>>();
        if wire.support.len() != SupportComponent::ALL.len()
            || support_ids != SupportComponent::ALL.into_iter().collect()
        {
            return Err(de::Error::custom(
                "support rows must contain every closed component exactly once",
            ));
        }
        validate_decoded_inventory(
            &wire.capabilities,
            &wire.support,
            &wire.missing_support,
            &wire.inactive_or_unused,
        )
        .map_err(de::Error::custom)?;

        Ok(Self {
            schema_version: wire.schema_version,
            evidence_grade: wire.evidence_grade,
            runtime_activation: wire.runtime_activation,
            capabilities: wire.capabilities,
            support: wire.support,
            missing_support: wire.missing_support,
            inactive_or_unused: wire.inactive_or_unused,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstalledCapabilityInput {
    state: InstalledCapabilityState,
    evidence: InstalledCapabilityEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SupportAssessmentInput {
    state: SupportState,
    evidence: SupportEvidence,
}

/// Pure, value-free input seam for a command adapter.
///
/// A command adapter should populate this only from the already validated
/// authoring model, compile-time/link-time release facts, and local schema or
/// validator availability. It must not populate this from runtime health,
/// image inspection, network calls, or secret lookup.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CapabilityInventoryInput {
    installed: BTreeMap<CapabilityId, InstalledCapabilityInput>,
    declared: BTreeSet<CapabilityId>,
    enabled: BTreeSet<CapabilityId>,
    usage: BTreeMap<CapabilityId, CapabilityUsageCounts>,
    support: BTreeMap<SupportComponent, SupportAssessmentInput>,
}

impl CapabilityInventoryInput {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_installed_capability(
        &mut self,
        capability: CapabilityId,
        state: InstalledCapabilityState,
        evidence: InstalledCapabilityEvidence,
    ) -> Result<(), CapabilityInventoryError> {
        validate_installed_evidence(state, evidence)?;
        if self.installed.contains_key(&capability) {
            return Err(CapabilityInventoryError::DuplicateInstalledCapability(
                capability,
            ));
        }
        self.installed
            .insert(capability, InstalledCapabilityInput { state, evidence });
        Ok(())
    }

    pub(crate) fn record_project_declaration(
        &mut self,
        capability: CapabilityId,
    ) -> Result<(), CapabilityInventoryError> {
        if !capability.project_declarable() {
            return Err(CapabilityInventoryError::CapabilityNotProjectDeclarable(
                capability,
            ));
        }
        if !self.declared.insert(capability) {
            return Err(CapabilityInventoryError::DuplicateProjectDeclaration(
                capability,
            ));
        }
        Ok(())
    }

    pub(crate) fn record_environment_enablement(
        &mut self,
        capability: CapabilityId,
    ) -> Result<(), CapabilityInventoryError> {
        if !capability.environment_enableable() {
            return Err(CapabilityInventoryError::CapabilityNotEnvironmentEnableable(capability));
        }
        if !self.enabled.insert(capability) {
            return Err(CapabilityInventoryError::DuplicateEnvironmentEnablement(
                capability,
            ));
        }
        Ok(())
    }

    pub(crate) fn record_usage(
        &mut self,
        capability: CapabilityId,
        usage: CapabilityUsageCounts,
    ) -> Result<(), CapabilityInventoryError> {
        validate_usage(usage)?;
        if usage.is_empty() {
            return Err(CapabilityInventoryError::EmptyUsage(capability));
        }
        if self.usage.contains_key(&capability) {
            return Err(CapabilityInventoryError::DuplicateUsage(capability));
        }
        self.usage.insert(capability, usage);
        Ok(())
    }

    pub(crate) fn record_support(
        &mut self,
        component: SupportComponent,
        state: SupportState,
        evidence: SupportEvidence,
    ) -> Result<(), CapabilityInventoryError> {
        validate_support_evidence(component, state, evidence)?;
        if self.support.contains_key(&component) {
            return Err(CapabilityInventoryError::DuplicateSupport(component));
        }
        self.support
            .insert(component, SupportAssessmentInput { state, evidence });
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityInventoryError {
    DuplicateInstalledCapability(CapabilityId),
    DuplicateProjectDeclaration(CapabilityId),
    DuplicateEnvironmentEnablement(CapabilityId),
    DuplicateUsage(CapabilityId),
    DuplicateSupport(SupportComponent),
    CapabilityNotProjectDeclarable(CapabilityId),
    CapabilityNotEnvironmentEnableable(CapabilityId),
    EnabledWithoutDeclaration(CapabilityId),
    UsedWithoutDeclaration(CapabilityId),
    EmptyUsage(CapabilityId),
    UsageCountOutOfRange,
    InvalidInstalledEvidence,
    InvalidSupportEvidence,
    ImageAvailabilityCannotBeClaimed,
}

impl fmt::Display for CapabilityInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CapabilityInventoryError {}

pub(crate) fn build_capability_inventory(
    input: CapabilityInventoryInput,
) -> Result<ProjectCapabilityInventoryReportV1, CapabilityInventoryError> {
    for capability in &input.enabled {
        if !input.declared.contains(capability) {
            return Err(CapabilityInventoryError::EnabledWithoutDeclaration(
                *capability,
            ));
        }
    }
    for capability in input.usage.keys() {
        if capability.project_declarable() && !input.declared.contains(capability) {
            return Err(CapabilityInventoryError::UsedWithoutDeclaration(
                *capability,
            ));
        }
    }

    let mut capabilities = Vec::with_capacity(CapabilityId::ALL.len());
    let mut inactive_or_unused = Vec::new();
    for capability in CapabilityId::ALL {
        let metadata = capability_metadata(capability);
        let installed =
            input
                .installed
                .get(&capability)
                .copied()
                .unwrap_or(InstalledCapabilityInput {
                    state: InstalledCapabilityState::NotEvaluated,
                    evidence: InstalledCapabilityEvidence::NoEvidence,
                });
        let usage = input.usage.get(&capability).copied().unwrap_or_default();
        let declared = input.declared.contains(&capability);
        let enabled = input.enabled.contains(&capability);
        let project_declaration = if capability.project_declarable() {
            if declared {
                ProjectDeclarationState::Declared
            } else {
                ProjectDeclarationState::NotDeclared
            }
        } else {
            ProjectDeclarationState::NotApplicable
        };
        let environment_enablement = if capability.environment_enableable() {
            if enabled {
                EnvironmentEnablementState::Enabled
            } else {
                EnvironmentEnablementState::NotEnabled
            }
        } else {
            EnvironmentEnablementState::NotApplicable
        };
        let disposition = capability_disposition(
            capability,
            installed.state,
            declared,
            enabled,
            usage,
            has_missing_support(&input, capability),
        );
        if declared && usage.is_empty() {
            inactive_or_unused.push(InactiveOrUnusedDeclaration {
                capability,
                reason: if enabled {
                    InactiveOrUnusedReason::DeclaredEnabledNotUsed
                } else {
                    InactiveOrUnusedReason::DeclaredNotEnabled
                },
            });
        }
        capabilities.push(CapabilityInventoryRecord {
            capability,
            kind: metadata.kind,
            owner: metadata.owner,
            maturity: CapabilityMaturity::ReleaseGated,
            supported_versions: metadata.supported_versions.to_vec(),
            installed_release: installed.state,
            installed_evidence: installed.evidence,
            project_declaration,
            environment_enablement,
            used_by: usage,
            disposition,
        });
    }

    let mut support = Vec::with_capacity(SupportComponent::ALL.len());
    let mut missing_support = Vec::new();
    for component in SupportComponent::ALL {
        let metadata = support_metadata(component);
        let assessment = input
            .support
            .get(&component)
            .copied()
            .unwrap_or(SupportAssessmentInput {
                state: SupportState::NotEvaluated,
                evidence: SupportEvidence::NoEvidence,
            });
        let required_by = metadata.required_by.to_vec();
        if matches!(
            assessment.state,
            SupportState::Missing | SupportState::Unsupported
        ) {
            missing_support.push(MissingSupport {
                component,
                kind: metadata.kind,
                state: assessment.state,
                required_by: required_by.clone(),
            });
        }
        support.push(SupportAssessment {
            component,
            kind: metadata.kind,
            owner: metadata.owner,
            state: assessment.state,
            evidence: assessment.evidence,
            required_by,
        });
    }

    Ok(ProjectCapabilityInventoryReportV1 {
        schema_version: ProjectCapabilityInventorySchemaVersion::V1,
        evidence_grade: CapabilityInventoryEvidenceGrade::OfflineStatic,
        runtime_activation: RuntimeActivationEvaluation::NotEvaluated,
        capabilities,
        support,
        missing_support,
        inactive_or_unused,
    })
}

fn validate_usage(usage: CapabilityUsageCounts) -> Result<(), CapabilityInventoryError> {
    let total = usage
        .total()
        .ok_or(CapabilityInventoryError::UsageCountOutOfRange)?;
    if usage.services > MAX_CAPABILITY_USAGE_COUNT
        || usage.consultations > MAX_CAPABILITY_USAGE_COUNT
        || total > MAX_CAPABILITY_USAGE_COUNT
    {
        return Err(CapabilityInventoryError::UsageCountOutOfRange);
    }
    Ok(())
}

fn validate_installed_evidence(
    state: InstalledCapabilityState,
    evidence: InstalledCapabilityEvidence,
) -> Result<(), CapabilityInventoryError> {
    let valid = match state {
        InstalledCapabilityState::Compiled => matches!(
            evidence,
            InstalledCapabilityEvidence::LinkedCrate
                | InstalledCapabilityEvidence::EmbeddedCompiler
                | InstalledCapabilityEvidence::EmbeddedSchema
                | InstalledCapabilityEvidence::LinkedProductValidator
                | InstalledCapabilityEvidence::ReleaseMetadata
        ),
        InstalledCapabilityState::NotCompiled => {
            evidence == InstalledCapabilityEvidence::ReleaseMetadata
        }
        InstalledCapabilityState::Unsupported => {
            evidence == InstalledCapabilityEvidence::ExplicitlyUnsupported
        }
        InstalledCapabilityState::NotEvaluated => {
            evidence == InstalledCapabilityEvidence::NoEvidence
        }
    };
    if valid {
        Ok(())
    } else {
        Err(CapabilityInventoryError::InvalidInstalledEvidence)
    }
}

fn validate_support_evidence(
    component: SupportComponent,
    state: SupportState,
    evidence: SupportEvidence,
) -> Result<(), CapabilityInventoryError> {
    if component.is_image()
        && !matches!(
            state,
            SupportState::Unsupported | SupportState::NotEvaluated
        )
    {
        return Err(CapabilityInventoryError::ImageAvailabilityCannotBeClaimed);
    }
    let valid = match state {
        SupportState::Available => matches!(
            evidence,
            SupportEvidence::LinkedCrate
                | SupportEvidence::EmbeddedSchema
                | SupportEvidence::LinkedProductValidator
                | SupportEvidence::ReleaseMetadata
        ),
        SupportState::Missing => evidence == SupportEvidence::ExplicitlyMissing,
        SupportState::Unsupported => evidence == SupportEvidence::ExplicitlyUnsupported,
        SupportState::NotEvaluated => evidence == SupportEvidence::NoEvidence,
    };
    if valid {
        Ok(())
    } else {
        Err(CapabilityInventoryError::InvalidSupportEvidence)
    }
}

fn capability_disposition(
    capability: CapabilityId,
    installed: InstalledCapabilityState,
    declared: bool,
    enabled: bool,
    usage: CapabilityUsageCounts,
    missing_support: bool,
) -> CapabilityDisposition {
    if !usage.is_empty() {
        if installed != InstalledCapabilityState::Compiled || missing_support {
            CapabilityDisposition::UsedWithMissingSupport
        } else if capability.environment_enableable() && !enabled {
            CapabilityDisposition::UsedButNotEnabled
        } else {
            CapabilityDisposition::Used
        }
    } else if declared && enabled {
        CapabilityDisposition::DeclaredEnabledUnused
    } else if declared {
        CapabilityDisposition::DeclaredInactive
    } else if installed == InstalledCapabilityState::Compiled {
        CapabilityDisposition::InstalledUnused
    } else {
        CapabilityDisposition::UnavailableUnused
    }
}

fn has_missing_support(input: &CapabilityInventoryInput, capability: CapabilityId) -> bool {
    SupportComponent::ALL.into_iter().any(|component| {
        support_metadata(component)
            .required_by
            .contains(&capability)
            && input.support.get(&component).is_some_and(|assessment| {
                matches!(
                    assessment.state,
                    SupportState::Missing | SupportState::Unsupported
                )
            })
    })
}

struct CapabilityMetadata {
    kind: CapabilityKind,
    owner: CapabilityOwner,
    supported_versions: &'static [SupportedCapabilityVersion],
}

fn capability_metadata(capability: CapabilityId) -> CapabilityMetadata {
    use SupportedCapabilityVersion as Version;
    match capability {
        CapabilityId::SourceHttp | CapabilityId::SourceScript | CapabilityId::SourceSnapshot => {
            CapabilityMetadata {
                kind: CapabilityKind::Source,
                owner: CapabilityOwner::Registryctl,
                supported_versions: &[Version::ProjectAuthoringV1, Version::RelayIntegrationPackV1],
            }
        }
        CapabilityId::RhaiRuntime => CapabilityMetadata {
            kind: CapabilityKind::Runtime,
            owner: CapabilityOwner::RegistryRelay,
            supported_versions: &[Version::RhaiLanguageV1],
        },
        CapabilityId::RhaiAbi => CapabilityMetadata {
            kind: CapabilityKind::Abi,
            owner: CapabilityOwner::RegistryRelay,
            supported_versions: &[Version::RhaiXwV1],
        },
        CapabilityId::RegistryRelayProduct => CapabilityMetadata {
            kind: CapabilityKind::Product,
            owner: CapabilityOwner::RegistryRelay,
            supported_versions: &[Version::RegistryRelayConfigV1],
        },
        CapabilityId::RegistryRelayValidator => CapabilityMetadata {
            kind: CapabilityKind::ProductValidator,
            owner: CapabilityOwner::RegistryRelay,
            supported_versions: &[Version::RegistryRelayConfigV1],
        },
        CapabilityId::ProjectAuthoringSchemas => CapabilityMetadata {
            kind: CapabilityKind::Schema,
            owner: CapabilityOwner::Registryctl,
            supported_versions: &[Version::ProjectAuthoringV1],
        },
        CapabilityId::RegistryRelayConfigSchema => CapabilityMetadata {
            kind: CapabilityKind::Schema,
            owner: CapabilityOwner::RegistryRelay,
            supported_versions: &[Version::RegistryRelayConfigV1],
        },
    }
}

struct SupportMetadata {
    kind: SupportKind,
    owner: CapabilityOwner,
    required_by: &'static [CapabilityId],
}

fn support_metadata(component: SupportComponent) -> SupportMetadata {
    use CapabilityId as Capability;
    match component {
        SupportComponent::HttpSourceWorker => SupportMetadata {
            kind: SupportKind::Worker,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::SourceHttp],
        },
        SupportComponent::RhaiScriptWorker => SupportMetadata {
            kind: SupportKind::Worker,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::SourceScript, Capability::RhaiRuntime],
        },
        SupportComponent::SnapshotMaterializationWorker => SupportMetadata {
            kind: SupportKind::Worker,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::SourceSnapshot],
        },
        SupportComponent::RhaiXwProtocolHelper => SupportMetadata {
            kind: SupportKind::ProtocolHelper,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::SourceScript, Capability::RhaiAbi],
        },
        SupportComponent::RegistryRelayProduct => SupportMetadata {
            kind: SupportKind::Product,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[
                Capability::SourceHttp,
                Capability::SourceScript,
                Capability::SourceSnapshot,
                Capability::RegistryRelayProduct,
            ],
        },
        SupportComponent::RegistryRelayValidator => SupportMetadata {
            kind: SupportKind::ProductValidator,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::RegistryRelayProduct],
        },
        SupportComponent::ProjectAuthoringSchema => SupportMetadata {
            kind: SupportKind::Schema,
            owner: CapabilityOwner::Registryctl,
            required_by: &[
                Capability::SourceHttp,
                Capability::SourceScript,
                Capability::SourceSnapshot,
            ],
        },
        SupportComponent::RegistryRelayConfigSchema => SupportMetadata {
            kind: SupportKind::Schema,
            owner: CapabilityOwner::RegistryRelay,
            required_by: &[Capability::RegistryRelayProduct],
        },
        SupportComponent::RegistryctlDistribution => SupportMetadata {
            kind: SupportKind::Distribution,
            owner: CapabilityOwner::ReleaseEngineering,
            required_by: &[
                Capability::SourceHttp,
                Capability::SourceScript,
                Capability::SourceSnapshot,
                Capability::ProjectAuthoringSchemas,
            ],
        },
        SupportComponent::RegistryRelayImage => SupportMetadata {
            kind: SupportKind::Image,
            owner: CapabilityOwner::ReleaseEngineering,
            required_by: &[Capability::RegistryRelayProduct],
        },
    }
}
