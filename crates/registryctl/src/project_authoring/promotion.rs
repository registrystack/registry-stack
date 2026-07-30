// SPDX-License-Identifier: Apache-2.0
//! Value-free environment comparison and promotion decision contract.
//!
//! This module is deliberately a pure boundary. A command adapter must first
//! compare authoritative, normalized project semantics and then translate only
//! closed classifications into [`ProjectPromotionInput`]. Raw authored values,
//! environment names, origins, credential identifiers, paths, hashes, and
//! runtime observations have no representation here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de, Deserialize, Deserializer, Serialize};

use super::RequiredProductAction;

pub const PROJECT_PROMOTION_SCHEMA_VERSION_V1: &str = "registry.project.promotion.v1";
pub(crate) const MAX_PROMOTION_CHANGES: usize = 256;
// The largest current valid projection is disclosure authority:
// 32 services × 64 claims × 3 disclosure modes = 6,144 members.
// Keep a finite review-evidence bound with headroom for the other closed
// authoring collections.
pub(crate) const MAX_PROMOTION_AUTHORITY_MEMBERS: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectPromotionSchemaVersion {
    #[serde(rename = "registry.project.promotion.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceGrade {
    OfflineStatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDeploymentEvaluation {
    NotPerformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionActivationEvaluation {
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDisposition {
    Ready,
    ReadyAfterRequiredActions,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewedRevisionComparison {
    SameReviewedSemanticRevision,
    DifferentReviewedSemanticRevision,
    NotProven,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDocument {
    Project,
    Environment,
}

/// Closed field paths prevent a promotion report from becoming a carrier for
/// country identifiers or values. The adapter maps catalogued field addresses
/// to these semantic address families after normalized comparison.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum PromotionFieldPath {
    #[serde(rename = "/integrations/*/origin")]
    IntegrationOrigin,
    #[serde(rename = "/integrations/*/credentials")]
    IntegrationCredentials,
    #[serde(rename = "/integrations/*/trust")]
    IntegrationTrust,
    #[serde(rename = "/notary/callers/*")]
    NotaryCaller,
    #[serde(rename = "/operations")]
    OperationalSettings,
    #[serde(rename = "/purposes/*")]
    Purpose,
    #[serde(rename = "/service_policy")]
    ServicePolicy,
    #[serde(rename = "/notary/claims/*")]
    Claim,
    #[serde(rename = "/notary/disclosures/*")]
    Disclosure,
    #[serde(rename = "/products/*")]
    ProductEnablement,
    #[serde(rename = "/integrations/*/capabilities/*")]
    CapabilityEnablement,
    #[serde(rename = "/integrations/*/limits")]
    IntegrationCeiling,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionFieldAddress {
    pub document: PromotionDocument,
    pub path: PromotionFieldPath,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionChangeKind {
    Origin,
    CredentialBinding,
    Trust,
    Caller,
    Operational,
    Purpose,
    ServicePolicy,
    Claim,
    Disclosure,
    ProductEnablement,
    CapabilityEnablement,
    IntegrationCeiling,
}

impl PromotionChangeKind {
    pub(crate) const ALL: [Self; 12] = [
        Self::Origin,
        Self::CredentialBinding,
        Self::Trust,
        Self::Caller,
        Self::Operational,
        Self::Purpose,
        Self::ServicePolicy,
        Self::Claim,
        Self::Disclosure,
        Self::ProductEnablement,
        Self::CapabilityEnablement,
        Self::IntegrationCeiling,
    ];

    pub(crate) const fn address(self) -> PromotionFieldAddress {
        let (document, path) = match self {
            Self::Origin => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationOrigin,
            ),
            Self::CredentialBinding => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationCredentials,
            ),
            Self::Trust => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationTrust,
            ),
            Self::Caller => (
                PromotionDocument::Environment,
                PromotionFieldPath::NotaryCaller,
            ),
            Self::Operational => (
                PromotionDocument::Environment,
                PromotionFieldPath::OperationalSettings,
            ),
            Self::ProductEnablement => (
                PromotionDocument::Environment,
                PromotionFieldPath::ProductEnablement,
            ),
            Self::CapabilityEnablement => (
                PromotionDocument::Environment,
                PromotionFieldPath::CapabilityEnablement,
            ),
            Self::IntegrationCeiling => (
                PromotionDocument::Project,
                PromotionFieldPath::IntegrationCeiling,
            ),
            Self::Purpose => (PromotionDocument::Project, PromotionFieldPath::Purpose),
            Self::ServicePolicy => (
                PromotionDocument::Project,
                PromotionFieldPath::ServicePolicy,
            ),
            Self::Claim => (PromotionDocument::Project, PromotionFieldPath::Claim),
            Self::Disclosure => (PromotionDocument::Project, PromotionFieldPath::Disclosure),
        };
        PromotionFieldAddress { document, path }
    }

    const fn is_environment_owned(self) -> bool {
        matches!(
            self,
            Self::Origin
                | Self::CredentialBinding
                | Self::Trust
                | Self::Caller
                | Self::Operational
                | Self::ProductEnablement
                | Self::CapabilityEnablement
        )
    }

    const fn is_policy(self) -> bool {
        matches!(
            self,
            Self::Caller
                | Self::Purpose
                | Self::ServicePolicy
                | Self::Claim
                | Self::Disclosure
                | Self::IntegrationCeiling
        )
    }

    pub(crate) const fn expected_ownership(self) -> PromotionFieldOwnership {
        if self.is_environment_owned() {
            PromotionFieldOwnership::EnvironmentOwned
        } else {
            PromotionFieldOwnership::ReviewedProjectOwned
        }
    }

    pub(crate) const fn expected_classification(self) -> PromotionFieldClassification {
        match self {
            Self::CredentialBinding => PromotionFieldClassification::SecretReference,
            Self::Origin | Self::Trust | Self::Caller => PromotionFieldClassification::Sensitive,
            Self::Operational
            | Self::Purpose
            | Self::ServicePolicy
            | Self::Claim
            | Self::Disclosure => PromotionFieldClassification::Internal,
            Self::ProductEnablement | Self::CapabilityEnablement | Self::IntegrationCeiling => {
                PromotionFieldClassification::Structural
            }
        }
    }

    pub(crate) const fn projection_effect_strategy(self) -> PromotionProjectionEffectStrategy {
        match self {
            Self::Origin | Self::CredentialBinding | Self::Operational | Self::Purpose => {
                PromotionProjectionEffectStrategy::ChangedWithinReviewedAuthority
            }
            Self::IntegrationCeiling => {
                PromotionProjectionEffectStrategy::AuthorityMembersRequireDirection
            }
            Self::Trust
            | Self::Caller
            | Self::ServicePolicy
            | Self::Claim
            | Self::Disclosure
            | Self::ProductEnablement
            | Self::CapabilityEnablement => {
                PromotionProjectionEffectStrategy::AuthorityMembersWithSafeReplacement
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionFieldClassification {
    Public,
    Internal,
    Sensitive,
    SecretReference,
    SecretValue,
    RedactedFixture,
    Structural,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionFieldOwnership {
    EnvironmentOwned,
    ReviewedProjectOwned,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionChangeEffect {
    ChangedWithinReviewedAuthority,
    Narrowed,
    Widened,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PromotionProjectionEffectStrategy {
    ChangedWithinReviewedAuthority,
    AuthorityMembersWithSafeReplacement,
    AuthorityMembersRequireDirection,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionBoundaryAssessment {
    AllowedEnvironmentOwned,
    ReviewedProjectRevisionDifference,
    Violation,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PromotionChangeInput {
    pub kind: PromotionChangeKind,
    pub classification: Option<PromotionFieldClassification>,
    pub ownership: PromotionFieldOwnership,
    pub effect: PromotionChangeEffect,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionChange {
    pub address: PromotionFieldAddress,
    pub kind: PromotionChangeKind,
    pub classification: PromotionFieldClassification,
    pub ownership: PromotionFieldOwnership,
    pub boundary: PromotionBoundaryAssessment,
    pub effect: PromotionChangeEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedCeilingInput {
    WithinReviewedCeiling,
    Narrowed,
    Widened,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewedCeilingAssessment {
    WithinReviewedCeiling,
    Narrowed,
    WidenedBlocked,
    UnresolvedBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustResolutionInput {
    Resolved,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustResolutionAssessment {
    Resolved,
    UnresolvedBlocked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionCompatibilityComponent {
    Product,
    Capability,
    Schema,
    Abi,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionCompatibilityState {
    Compatible,
    Missing,
    Incompatible,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromotionCompatibilityInput {
    pub product: PromotionCompatibilityState,
    pub capability: PromotionCompatibilityState,
    pub schema: PromotionCompatibilityState,
    pub abi: PromotionCompatibilityState,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionCompatibilityAssessment {
    pub component: PromotionCompatibilityComponent,
    pub state: PromotionCompatibilityState,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionReviewClass {
    Authoring,
    Contract,
    Semantics,
    Interoperability,
    Privacy,
    Security,
    Compatibility,
    Operations,
    Release,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionRequiredActions {
    pub review_classes: Vec<PromotionReviewClass>,
    pub re_sign: Vec<RequiredProductAction>,
    pub reactivate: Vec<RequiredProductAction>,
    pub restart: Vec<RequiredProductAction>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionBlockingReason {
    ReviewedRevisionNotProven,
    ComparisonEvidenceIncomplete,
    EnvironmentOwnershipViolation,
    UnclassifiedChange,
    UnresolvedChange,
    PolicyWidening,
    AuthorityWidening,
    ReviewedCeilingWidening,
    ReviewedCeilingUnresolved,
    TrustUnresolved,
    MissingProduct,
    MissingCapability,
    MissingSchema,
    MissingAbi,
    IncompatibleProduct,
    IncompatibleCapability,
    IncompatibleSchema,
    IncompatibleAbi,
    CompatibilityUnresolved,
    LegacyRelayConsultationBaselineMigrationRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionBaselineMigration {
    NotRequired,
    ReReviewAndSignSeparateRelayPublicAndConsultationInputs,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceLimitation {
    OfflineStaticOnly,
    RuntimeActivationNotEvaluated,
    DeploymentNotPerformed,
    LiveEndpointReachabilityNotEvaluated,
    SecretMaterialNotInspected,
    RawAuthoredValuesOmitted,
    SeparateRelayPublicRelayConsultationAndNotaryBundleLifecycle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectPromotionInput {
    pub reviewed_revision: ReviewedRevisionComparison,
    pub product_lanes: Vec<RequiredProductAction>,
    pub baseline_migration: PromotionBaselineMigration,
    pub changes: Vec<PromotionChangeInput>,
    pub reviewed_ceiling: ReviewedCeilingInput,
    pub trust: TrustResolutionInput,
    pub compatibility: PromotionCompatibilityInput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum ProjectPromotionProjectionSchemaVersion {
    #[serde(rename = "registry.project.promotion-projection.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionProjectedProduct {
    Relay,
    Notary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionProjectedCapability {
    Http,
    Script,
    Snapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromotionAuthoringSchemaVersions {
    pub project: u8,
    pub environment: u8,
    pub integrations: Vec<u8>,
    pub entities: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromotionProjectedField {
    pub address: PromotionFieldAddress,
    pub kind: PromotionChangeKind,
    pub classification: PromotionFieldClassification,
    pub ownership: PromotionFieldOwnership,
    pub digest: String,
    pub authority_members: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectPromotionProjectionV1 {
    pub schema_version: ProjectPromotionProjectionSchemaVersion,
    pub field_knowledge_revision: String,
    pub authoring_schemas: PromotionAuthoringSchemaVersions,
    pub products: Vec<PromotionProjectedProduct>,
    pub capabilities: Vec<PromotionProjectedCapability>,
    pub fields: Vec<PromotionProjectedField>,
}

impl ProjectPromotionProjectionV1 {
    pub(crate) fn fields_by_kind(&self) -> BTreeMap<PromotionChangeKind, &PromotionProjectedField> {
        self.fields
            .iter()
            .map(|field| (field.kind, field))
            .collect()
    }
}

pub(crate) fn validate_project_promotion_projection(
    projection: &ProjectPromotionProjectionV1,
    expected_field_knowledge_revision: &str,
) -> Result<(), &'static str> {
    validate_project_promotion_projection_structure(projection)?;
    if projection.field_knowledge_revision != expected_field_knowledge_revision {
        return Err("promotion projection field-knowledge revision is not current");
    }
    Ok(())
}

pub(crate) fn validate_project_promotion_projection_structure(
    projection: &ProjectPromotionProjectionV1,
) -> Result<(), &'static str> {
    if projection.schema_version != ProjectPromotionProjectionSchemaVersion::V1 {
        return Err("promotion projection has an unsupported schema version");
    }
    if !is_sha256_uri(&projection.field_knowledge_revision) {
        return Err("promotion projection field-knowledge revision is invalid");
    }
    if projection.authoring_schemas.project == 0
        || projection.authoring_schemas.environment == 0
        || projection.authoring_schemas.integrations.contains(&0)
        || projection.authoring_schemas.entities.contains(&0)
        || !is_strictly_sorted_unique(&projection.authoring_schemas.integrations)
        || !is_strictly_sorted_unique(&projection.authoring_schemas.entities)
    {
        return Err("promotion projection authoring schema versions are invalid");
    }
    if projection.products.is_empty()
        || !is_strictly_sorted_unique(&projection.products)
        || !is_strictly_sorted_unique(&projection.capabilities)
    {
        return Err("promotion projection product or capability inventory is invalid");
    }
    if projection.fields.len() != PromotionChangeKind::ALL.len() {
        return Err("promotion projection must cover every classified field address exactly once");
    }

    for (expected_kind, field) in PromotionChangeKind::ALL.iter().zip(&projection.fields) {
        if field.kind != *expected_kind
            || field.address != field.kind.address()
            || field.ownership != field.kind.expected_ownership()
            || field.classification != field.kind.expected_classification()
            || !is_sha256_uri(&field.digest)
            || field.authority_members.len() > MAX_PROMOTION_AUTHORITY_MEMBERS
            || field
                .authority_members
                .iter()
                .any(|member| !is_sha256_uri(member))
            || !is_strictly_sorted_unique(&field.authority_members)
        {
            return Err("promotion projection field evidence is incomplete or non-canonical");
        }
    }
    Ok(())
}

pub(crate) fn classify_projected_change_effect(
    kind: PromotionChangeKind,
    previous: &PromotionProjectedField,
    current: &PromotionProjectedField,
) -> PromotionChangeEffect {
    if previous.digest == current.digest {
        return PromotionChangeEffect::ChangedWithinReviewedAuthority;
    }
    match kind.projection_effect_strategy() {
        PromotionProjectionEffectStrategy::ChangedWithinReviewedAuthority => {
            PromotionChangeEffect::ChangedWithinReviewedAuthority
        }
        PromotionProjectionEffectStrategy::AuthorityMembersWithSafeReplacement
        | PromotionProjectionEffectStrategy::AuthorityMembersRequireDirection => {
            let previous = previous.authority_members.iter().collect::<BTreeSet<_>>();
            let current = current.authority_members.iter().collect::<BTreeSet<_>>();
            if current != previous && current.is_subset(&previous) {
                PromotionChangeEffect::Narrowed
            } else if current != previous && previous.is_subset(&current) {
                PromotionChangeEffect::Widened
            } else if current == previous
                && kind.projection_effect_strategy()
                    == PromotionProjectionEffectStrategy::AuthorityMembersWithSafeReplacement
            {
                PromotionChangeEffect::ChangedWithinReviewedAuthority
            } else {
                PromotionChangeEffect::Unresolved
            }
        }
    }
}

fn is_strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_sha256_uri(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPromotionReportV1 {
    pub schema_version: ProjectPromotionSchemaVersion,
    pub evidence_grade: PromotionEvidenceGrade,
    pub deployment: PromotionDeploymentEvaluation,
    pub runtime_activation: PromotionActivationEvaluation,
    pub disposition: PromotionDisposition,
    pub reviewed_revision: ReviewedRevisionComparison,
    pub product_lanes: Vec<RequiredProductAction>,
    pub baseline_migration: PromotionBaselineMigration,
    pub changes: Vec<PromotionChange>,
    pub reviewed_ceiling: ReviewedCeilingAssessment,
    pub trust: TrustResolutionAssessment,
    pub compatibility: Vec<PromotionCompatibilityAssessment>,
    pub required_actions: PromotionRequiredActions,
    pub blocking_reasons: Vec<PromotionBlockingReason>,
    pub evidence_limitations: Vec<PromotionEvidenceLimitation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectPromotionReportWire {
    schema_version: ProjectPromotionSchemaVersion,
    evidence_grade: PromotionEvidenceGrade,
    deployment: PromotionDeploymentEvaluation,
    runtime_activation: PromotionActivationEvaluation,
    disposition: PromotionDisposition,
    reviewed_revision: ReviewedRevisionComparison,
    product_lanes: Vec<RequiredProductAction>,
    baseline_migration: PromotionBaselineMigration,
    changes: Vec<PromotionChange>,
    reviewed_ceiling: ReviewedCeilingAssessment,
    trust: TrustResolutionAssessment,
    compatibility: Vec<PromotionCompatibilityAssessment>,
    required_actions: PromotionRequiredActions,
    blocking_reasons: Vec<PromotionBlockingReason>,
    evidence_limitations: Vec<PromotionEvidenceLimitation>,
}

impl<'de> Deserialize<'de> for ProjectPromotionReportV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProjectPromotionReportWire::deserialize(deserializer)?;
        let candidate = Self {
            schema_version: wire.schema_version,
            evidence_grade: wire.evidence_grade,
            deployment: wire.deployment,
            runtime_activation: wire.runtime_activation,
            disposition: wire.disposition,
            reviewed_revision: wire.reviewed_revision,
            product_lanes: wire.product_lanes,
            baseline_migration: wire.baseline_migration,
            changes: wire.changes,
            reviewed_ceiling: wire.reviewed_ceiling,
            trust: wire.trust,
            compatibility: wire.compatibility,
            required_actions: wire.required_actions,
            blocking_reasons: wire.blocking_reasons,
            evidence_limitations: wire.evidence_limitations,
        };
        let expected = rebuild_report_from_wire(&candidate).map_err(de::Error::custom)?;
        if candidate != expected {
            return Err(de::Error::custom(
                "promotion report decisions do not match its classified comparison evidence",
            ));
        }
        Ok(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectPromotionBuildError {
    TooManyChanges,
    InvalidProductLanes,
}

fn rebuild_report_from_wire(
    report: &ProjectPromotionReportV1,
) -> Result<ProjectPromotionReportV1, &'static str> {
    if report.compatibility.len() != 4
        || report.compatibility[0].component != PromotionCompatibilityComponent::Product
        || report.compatibility[1].component != PromotionCompatibilityComponent::Capability
        || report.compatibility[2].component != PromotionCompatibilityComponent::Schema
        || report.compatibility[3].component != PromotionCompatibilityComponent::Abi
    {
        return Err("promotion compatibility evidence must contain product, capability, schema, and ABI exactly once in canonical order");
    }
    let reviewed_ceiling = match report.reviewed_ceiling {
        ReviewedCeilingAssessment::WithinReviewedCeiling => {
            ReviewedCeilingInput::WithinReviewedCeiling
        }
        ReviewedCeilingAssessment::Narrowed => ReviewedCeilingInput::Narrowed,
        ReviewedCeilingAssessment::WidenedBlocked => ReviewedCeilingInput::Widened,
        ReviewedCeilingAssessment::UnresolvedBlocked => ReviewedCeilingInput::Unresolved,
    };
    let trust = match report.trust {
        TrustResolutionAssessment::Resolved => TrustResolutionInput::Resolved,
        TrustResolutionAssessment::UnresolvedBlocked => TrustResolutionInput::Unresolved,
    };
    let compatibility = PromotionCompatibilityInput {
        product: report.compatibility[0].state,
        capability: report.compatibility[1].state,
        schema: report.compatibility[2].state,
        abi: report.compatibility[3].state,
    };
    build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: report.reviewed_revision,
        product_lanes: report.product_lanes.clone(),
        baseline_migration: report.baseline_migration,
        changes: report
            .changes
            .iter()
            .map(|change| PromotionChangeInput {
                kind: change.kind,
                classification: Some(change.classification),
                ownership: change.ownership,
                effect: change.effect,
            })
            .collect(),
        reviewed_ceiling,
        trust,
        compatibility,
    })
    .map_err(|_| "promotion report exceeds the bounded change capacity")
}

pub fn build_project_promotion_report(
    input: ProjectPromotionInput,
) -> Result<ProjectPromotionReportV1, ProjectPromotionBuildError> {
    if input.changes.len() > MAX_PROMOTION_CHANGES {
        return Err(ProjectPromotionBuildError::TooManyChanges);
    }

    let mut blocking_reasons = BTreeSet::new();
    if input.reviewed_revision == ReviewedRevisionComparison::NotProven {
        blocking_reasons.insert(PromotionBlockingReason::ReviewedRevisionNotProven);
    }
    if input.baseline_migration
        == PromotionBaselineMigration::ReReviewAndSignSeparateRelayPublicAndConsultationInputs
    {
        blocking_reasons
            .insert(PromotionBlockingReason::LegacyRelayConsultationBaselineMigrationRequired);
    }

    let product_lanes = input.product_lanes.into_iter().collect::<BTreeSet<_>>();
    if product_lanes.is_empty()
        || (product_lanes.contains(&RequiredProductAction::RelayConsultation)
            && !product_lanes.contains(&RequiredProductAction::RelayPublic))
        || (input.baseline_migration
            == PromotionBaselineMigration::ReReviewAndSignSeparateRelayPublicAndConsultationInputs
            && (!product_lanes.contains(&RequiredProductAction::RelayPublic)
                || !product_lanes.contains(&RequiredProductAction::RelayConsultation)))
    {
        return Err(ProjectPromotionBuildError::InvalidProductLanes);
    }

    let mut review_classes = BTreeSet::new();
    let mut action_products = ProductActionSet::default();
    if input.reviewed_revision == ReviewedRevisionComparison::DifferentReviewedSemanticRevision {
        review_classes.extend([
            PromotionReviewClass::Authoring,
            PromotionReviewClass::Contract,
            PromotionReviewClass::Semantics,
        ]);
    }

    let has_reviewed_project_change = input
        .changes
        .iter()
        .any(|change| !change.kind.is_environment_owned());
    let has_ceiling_change = input
        .changes
        .iter()
        .any(|change| change.kind == PromotionChangeKind::IntegrationCeiling);
    if input.reviewed_revision == ReviewedRevisionComparison::DifferentReviewedSemanticRevision
        && !has_reviewed_project_change
    {
        blocking_reasons.insert(PromotionBlockingReason::ComparisonEvidenceIncomplete);
    }
    if input.reviewed_ceiling != ReviewedCeilingInput::WithinReviewedCeiling && !has_ceiling_change
    {
        blocking_reasons.insert(PromotionBlockingReason::ComparisonEvidenceIncomplete);
    }

    let mut changes = input
        .changes
        .into_iter()
        .map(|change| {
            let classification = change
                .classification
                .unwrap_or(PromotionFieldClassification::Unclassified);
            if classification == PromotionFieldClassification::Unclassified
                || change.ownership == PromotionFieldOwnership::Unclassified
            {
                blocking_reasons.insert(PromotionBlockingReason::UnclassifiedChange);
            }
            if change.effect == PromotionChangeEffect::Unresolved {
                blocking_reasons.insert(PromotionBlockingReason::UnresolvedChange);
            }
            if change.effect == PromotionChangeEffect::Widened && change.kind.is_policy() {
                blocking_reasons.insert(PromotionBlockingReason::PolicyWidening);
            } else if change.effect == PromotionChangeEffect::Widened {
                blocking_reasons.insert(PromotionBlockingReason::AuthorityWidening);
            }

            let boundary = if classification == PromotionFieldClassification::Unclassified
                || change.ownership == PromotionFieldOwnership::Unclassified
            {
                PromotionBoundaryAssessment::Unclassified
            } else if change.kind.is_environment_owned()
                && change.ownership == PromotionFieldOwnership::EnvironmentOwned
            {
                PromotionBoundaryAssessment::AllowedEnvironmentOwned
            } else if !change.kind.is_environment_owned()
                && change.ownership == PromotionFieldOwnership::ReviewedProjectOwned
                && input.reviewed_revision
                    == ReviewedRevisionComparison::DifferentReviewedSemanticRevision
            {
                PromotionBoundaryAssessment::ReviewedProjectRevisionDifference
            } else {
                blocking_reasons.insert(PromotionBlockingReason::EnvironmentOwnershipViolation);
                PromotionBoundaryAssessment::Violation
            };

            add_change_actions(
                change.kind,
                &product_lanes,
                &mut review_classes,
                &mut action_products,
            );
            PromotionChange {
                address: change.kind.address(),
                kind: change.kind,
                classification,
                ownership: change.ownership,
                boundary,
                effect: change.effect,
            }
        })
        .collect::<Vec<_>>();
    changes.sort_unstable();
    changes.dedup();

    let reviewed_ceiling = match input.reviewed_ceiling {
        ReviewedCeilingInput::WithinReviewedCeiling => {
            ReviewedCeilingAssessment::WithinReviewedCeiling
        }
        ReviewedCeilingInput::Narrowed => ReviewedCeilingAssessment::Narrowed,
        ReviewedCeilingInput::Widened => {
            blocking_reasons.insert(PromotionBlockingReason::ReviewedCeilingWidening);
            ReviewedCeilingAssessment::WidenedBlocked
        }
        ReviewedCeilingInput::Unresolved => {
            blocking_reasons.insert(PromotionBlockingReason::ReviewedCeilingUnresolved);
            ReviewedCeilingAssessment::UnresolvedBlocked
        }
    };

    let trust = match input.trust {
        TrustResolutionInput::Resolved => TrustResolutionAssessment::Resolved,
        TrustResolutionInput::Unresolved => {
            blocking_reasons.insert(PromotionBlockingReason::TrustUnresolved);
            TrustResolutionAssessment::UnresolvedBlocked
        }
    };

    let compatibility = [
        (
            PromotionCompatibilityComponent::Product,
            input.compatibility.product,
        ),
        (
            PromotionCompatibilityComponent::Capability,
            input.compatibility.capability,
        ),
        (
            PromotionCompatibilityComponent::Schema,
            input.compatibility.schema,
        ),
        (
            PromotionCompatibilityComponent::Abi,
            input.compatibility.abi,
        ),
    ]
    .into_iter()
    .map(|(component, state)| {
        if state != PromotionCompatibilityState::Compatible {
            blocking_reasons.insert(compatibility_reason(component, state));
        }
        PromotionCompatibilityAssessment { component, state }
    })
    .collect::<Vec<_>>();

    let required_actions = PromotionRequiredActions {
        review_classes: review_classes.into_iter().collect(),
        re_sign: action_products.actions(),
        reactivate: action_products.actions(),
        restart: action_products.actions(),
    };
    let blocking_reasons = blocking_reasons.into_iter().collect::<Vec<_>>();
    let disposition = if !blocking_reasons.is_empty() {
        PromotionDisposition::Blocked
    } else if changes.is_empty()
        && input.reviewed_revision == ReviewedRevisionComparison::SameReviewedSemanticRevision
    {
        PromotionDisposition::Ready
    } else {
        PromotionDisposition::ReadyAfterRequiredActions
    };

    Ok(ProjectPromotionReportV1 {
        schema_version: ProjectPromotionSchemaVersion::V1,
        evidence_grade: PromotionEvidenceGrade::OfflineStatic,
        deployment: PromotionDeploymentEvaluation::NotPerformed,
        runtime_activation: PromotionActivationEvaluation::NotEvaluated,
        disposition,
        reviewed_revision: input.reviewed_revision,
        product_lanes: product_lanes.into_iter().collect(),
        baseline_migration: input.baseline_migration,
        changes,
        reviewed_ceiling,
        trust,
        compatibility,
        required_actions,
        blocking_reasons,
        evidence_limitations: vec![
            PromotionEvidenceLimitation::OfflineStaticOnly,
            PromotionEvidenceLimitation::RuntimeActivationNotEvaluated,
            PromotionEvidenceLimitation::DeploymentNotPerformed,
            PromotionEvidenceLimitation::LiveEndpointReachabilityNotEvaluated,
            PromotionEvidenceLimitation::SecretMaterialNotInspected,
            PromotionEvidenceLimitation::RawAuthoredValuesOmitted,
            PromotionEvidenceLimitation::SeparateRelayPublicRelayConsultationAndNotaryBundleLifecycle,
        ],
    })
}

fn compatibility_reason(
    component: PromotionCompatibilityComponent,
    state: PromotionCompatibilityState,
) -> PromotionBlockingReason {
    use PromotionBlockingReason as Reason;
    use PromotionCompatibilityComponent as Component;
    use PromotionCompatibilityState as State;
    match (component, state) {
        (Component::Product, State::Missing) => Reason::MissingProduct,
        (Component::Capability, State::Missing) => Reason::MissingCapability,
        (Component::Schema, State::Missing) => Reason::MissingSchema,
        (Component::Abi, State::Missing) => Reason::MissingAbi,
        (Component::Product, State::Incompatible) => Reason::IncompatibleProduct,
        (Component::Capability, State::Incompatible) => Reason::IncompatibleCapability,
        (Component::Schema, State::Incompatible) => Reason::IncompatibleSchema,
        (Component::Abi, State::Incompatible) => Reason::IncompatibleAbi,
        (_, State::Unresolved) => Reason::CompatibilityUnresolved,
        (_, State::Compatible) => unreachable!("compatible components have no blocking reason"),
    }
}

fn add_change_actions(
    kind: PromotionChangeKind,
    product_lanes: &BTreeSet<RequiredProductAction>,
    reviews: &mut BTreeSet<PromotionReviewClass>,
    products: &mut ProductActionSet,
) {
    match kind {
        PromotionChangeKind::Origin | PromotionChangeKind::CredentialBinding => {
            reviews.insert(PromotionReviewClass::Security);
            reviews.insert(PromotionReviewClass::Interoperability);
            products.add(
                if product_lanes.contains(&RequiredProductAction::RelayConsultation) {
                    ProductActionSet::RELAY_CONSULTATION
                } else {
                    ProductActionSet::RELAY_PUBLIC
                },
            );
        }
        PromotionChangeKind::Trust => {
            reviews.insert(PromotionReviewClass::Security);
            reviews.insert(PromotionReviewClass::Interoperability);
            products.add(ProductActionSet::ALL);
        }
        PromotionChangeKind::Caller
        | PromotionChangeKind::Purpose
        | PromotionChangeKind::ServicePolicy
        | PromotionChangeKind::Claim
        | PromotionChangeKind::Disclosure => {
            reviews.insert(PromotionReviewClass::Privacy);
            reviews.insert(PromotionReviewClass::Security);
            products.add(ProductActionSet::NOTARY);
        }
        PromotionChangeKind::Operational => {
            reviews.insert(PromotionReviewClass::Operations);
            reviews.insert(PromotionReviewClass::Security);
            products.add(ProductActionSet::ALL);
        }
        PromotionChangeKind::ProductEnablement | PromotionChangeKind::CapabilityEnablement => {
            reviews.insert(PromotionReviewClass::Compatibility);
            reviews.insert(PromotionReviewClass::Release);
            products.add(ProductActionSet::ALL);
        }
        PromotionChangeKind::IntegrationCeiling => {
            reviews.insert(PromotionReviewClass::Compatibility);
            reviews.insert(PromotionReviewClass::Release);
            products.add(
                if product_lanes.contains(&RequiredProductAction::RelayConsultation) {
                    ProductActionSet::RELAY_CONSULTATION
                } else {
                    ProductActionSet::RELAY_PUBLIC
                } | ProductActionSet::NOTARY,
            );
        }
    }
    products.retain(product_lanes);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProductActionSet(u8);

impl ProductActionSet {
    const RELAY_PUBLIC: u8 = 0b001;
    const RELAY_CONSULTATION: u8 = 0b010;
    const NOTARY: u8 = 0b100;
    const ALL: u8 = Self::RELAY_PUBLIC | Self::RELAY_CONSULTATION | Self::NOTARY;

    fn add(&mut self, product: u8) {
        self.0 |= product;
    }

    fn retain(&mut self, product_lanes: &BTreeSet<RequiredProductAction>) {
        let mut available = 0;
        for lane in product_lanes {
            available |= match lane {
                RequiredProductAction::RelayPublic => Self::RELAY_PUBLIC,
                RequiredProductAction::RelayConsultation => Self::RELAY_CONSULTATION,
                RequiredProductAction::Notary => Self::NOTARY,
            };
        }
        self.0 &= available;
    }

    fn actions(self) -> Vec<RequiredProductAction> {
        [
            (Self::RELAY_PUBLIC, RequiredProductAction::RelayPublic),
            (
                Self::RELAY_CONSULTATION,
                RequiredProductAction::RelayConsultation,
            ),
            (Self::NOTARY, RequiredProductAction::Notary),
        ]
        .into_iter()
        .filter_map(|(bit, action)| (self.0 & bit != 0).then_some(action))
        .collect()
    }
}
