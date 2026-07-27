// SPDX-License-Identifier: Apache-2.0
//! Value-free, offline semantic comparison for normalized Registry projects.
//!
//! This is intentionally separate from the signed approval-state comparison.
//! Current signed v1/v2 baselines bind coarse digests and cannot prove a
//! field-addressed diff. This module instead loads both local inputs through
//! the typed authoring model, compares effective fields with internally held
//! fingerprints, and emits only closed classifications and wildcard-free
//! published schema addresses. It also compares the compiler's in-memory
//! review and approval projections. It never reads a build directory.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::*;

pub const PROJECT_SEMANTIC_COMPARISON_SCHEMA_VERSION_V1: &str =
    "registry.project.semantic_comparison.v1";
const MAX_SEMANTIC_COMPARISON_CHANGES: usize = 1_024;
const MAX_SEMANTIC_COMPARISON_OCCURRENCES: usize = 8_192;

#[derive(Clone, Debug)]
pub struct ProjectSemanticComparisonOptions {
    pub current_project_directory: PathBuf,
    pub current_environment: String,
    pub baseline_project_directory: PathBuf,
    pub baseline_environment: String,
}

#[derive(Clone, Debug)]
pub struct ProjectEnvironmentSemanticComparisonOptions {
    pub project_directory: PathBuf,
    pub current_environment: String,
    pub baseline_environment: String,
}

#[derive(Clone, Debug)]
pub struct ProjectStarterSemanticComparisonOptions {
    pub project_directory: PathBuf,
    pub environment: String,
    /// An explicitly selected embedded starter kind. `None` uses, and still
    /// verifies, the starter id recorded by the authored project.
    pub starter: Option<ProjectStarter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectSemanticComparisonSchemaVersion {
    #[serde(rename = "registry.project.semantic_comparison.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonKind {
    LocalProjectToProject,
    SameProjectEnvironmentToEnvironment,
    EmbeddedStarterToProject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonEvidenceGrade {
    OfflineStatic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonAssurance {
    LocalUnverified,
    EmbeddedExactRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonExternalApproval {
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonEquivalence {
    Equivalent,
    Different,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonPrecision {
    FieldAndGeneratedProjection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonReviewPlanState {
    GeneratedNoChanges,
    GeneratedPendingReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonEvidenceLimitation {
    OfflineInputsOnly,
    RuntimeNotObserved,
    SignedBundleAuthorityNotEvaluated,
    ExternalApprovalNotEvaluated,
    FingerprintsNotPublished,
}

const EVIDENCE_LIMITATIONS: [SemanticComparisonEvidenceLimitation; 5] = [
    SemanticComparisonEvidenceLimitation::OfflineInputsOnly,
    SemanticComparisonEvidenceLimitation::RuntimeNotObserved,
    SemanticComparisonEvidenceLimitation::SignedBundleAuthorityNotEvaluated,
    SemanticComparisonEvidenceLimitation::ExternalApprovalNotEvaluated,
    SemanticComparisonEvidenceLimitation::FingerprintsNotPublished,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonRequiredAction {
    ReviewSemanticChanges,
    RunAffectedFixtures,
    RegenerateGeneratedArtifacts,
    ResignRelayBundle,
    ResignNotaryBundle,
    ReactivateRelayConfiguration,
    ReactivateNotaryConfiguration,
    RestartRegistryRelay,
    RestartRegistryNotary,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonSchemaFamily {
    Project,
    Environment,
    Integration,
    Fixture,
    Entity,
    GeneratedReview,
    GeneratedApproval,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComparisonFieldAddress {
    pub schema_family: SemanticComparisonSchemaFamily,
    /// RFC 6901 address in the installed published schema, never an authored
    /// file path or a concrete project member address.
    pub field: JsonPointer,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonChangeSource {
    Authored,
    Defaulted,
    Derived,
    EnvironmentBound,
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonDimension {
    Project,
    Integration,
    Fixture,
    Entity,
    ServicePolicy,
    Consultation,
    Claim,
    Disclosure,
    OperatorSecurity,
    GeneratedReview,
    GeneratedApproval,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonDirection {
    Added,
    Removed,
    Changed,
    Narrowed,
    Widened,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonConsumer {
    RegistryctlAuthoring,
    RegistryRelay,
    RegistryNotary,
    EditorTooling,
    DocsGenerator,
    BundleSigner,
    DeploymentTooling,
    Operator,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonGeneratedArtifact {
    EditorSchemas,
    ProjectBuild,
    RelayConfig,
    NotaryConfig,
    FixtureReport,
    FieldReference,
    ReviewPlan,
    ApprovalProjection,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonReviewClass {
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonAffectedSubjectKind {
    Integration,
    Fixture,
    Entity,
    ServicePolicy,
    Consultation,
    Claim,
    Disclosure,
    ProductInput,
    GeneratedArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComparisonAffectedSubject {
    pub kind: SemanticComparisonAffectedSubjectKind,
    pub count: u16,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonSigningRequirement {
    None,
    RelayBundle,
    NotaryBundle,
    RelayAndNotaryBundles,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonActivationRequirement {
    None,
    ApplyRelayConfig,
    ApplyNotaryConfig,
    ApplyRelayAndNotaryConfig,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticComparisonRestartRequirement {
    None,
    RegistryRelay,
    RegistryNotary,
    RegistryRelayAndNotary,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComparisonRequirements {
    pub signing: SemanticComparisonSigningRequirement,
    pub activation: SemanticComparisonActivationRequirement,
    pub restart: SemanticComparisonRestartRequirement,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSemanticComparisonChange {
    pub address: SemanticComparisonFieldAddress,
    pub source: SemanticComparisonChangeSource,
    pub dimension: SemanticComparisonDimension,
    pub direction: SemanticComparisonDirection,
    pub sensitivity: knowledge::Sensitivity,
    pub semantic_owner: knowledge::SemanticOwner,
    pub human_owner: knowledge::HumanOwner,
    pub consumers: Vec<SemanticComparisonConsumer>,
    pub generated_artifacts: Vec<SemanticComparisonGeneratedArtifact>,
    pub review_classes: Vec<SemanticComparisonReviewClass>,
    pub affected_subjects: Vec<SemanticComparisonAffectedSubject>,
    pub occurrences: u16,
    pub requirements: SemanticComparisonRequirements,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticComparisonReviewPlan {
    pub state: SemanticComparisonReviewPlanState,
    pub review_classes: Vec<SemanticComparisonReviewClass>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSemanticComparisonReportV1 {
    pub schema_version: ProjectSemanticComparisonSchemaVersion,
    pub comparison: SemanticComparisonKind,
    pub evidence_grade: SemanticComparisonEvidenceGrade,
    pub assurance: SemanticComparisonAssurance,
    pub external_approval: SemanticComparisonExternalApproval,
    pub equivalence: SemanticComparisonEquivalence,
    pub comparison_precision: SemanticComparisonPrecision,
    pub review_plan: SemanticComparisonReviewPlan,
    pub changes: Vec<ProjectSemanticComparisonChange>,
    pub required_actions: Vec<SemanticComparisonRequiredAction>,
    pub evidence_limitations: Vec<SemanticComparisonEvidenceLimitation>,
}

impl ProjectSemanticComparisonReportV1 {
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .context("semantic comparison report could not be serialized safely")?;
        if value.get("schema_version").and_then(Value::as_str)
            != Some(PROJECT_SEMANTIC_COMPARISON_SCHEMA_VERSION_V1)
        {
            bail!("semantic comparison report has an unsupported schema version");
        }
        canonical_json_line(&value)
            .context("semantic comparison report could not be canonicalized safely")
    }

    pub fn human_safe_summary(&self) -> String {
        format!(
            "semantic comparison: {}; assurance: {}; changes: {}; review plan: {}",
            equivalence_label(self.equivalence),
            assurance_label(self.assurance),
            self.changes.len(),
            review_plan_label(self.review_plan.state),
        )
    }
}

impl fmt::Display for ProjectSemanticComparisonReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.human_safe_summary())
    }
}

fn equivalence_label(value: SemanticComparisonEquivalence) -> &'static str {
    match value {
        SemanticComparisonEquivalence::Equivalent => "equivalent",
        SemanticComparisonEquivalence::Different => "different",
    }
}

fn assurance_label(value: SemanticComparisonAssurance) -> &'static str {
    match value {
        SemanticComparisonAssurance::LocalUnverified => "local_unverified",
        SemanticComparisonAssurance::EmbeddedExactRelease => "embedded_exact_release",
    }
}

fn review_plan_label(value: SemanticComparisonReviewPlanState) -> &'static str {
    match value {
        SemanticComparisonReviewPlanState::GeneratedNoChanges => "generated_no_changes",
        SemanticComparisonReviewPlanState::GeneratedPendingReview => "generated_pending_review",
    }
}

/// Compares two explicitly environment-bound local projects. Neither input is
/// promoted to reviewed or signed authority.
pub fn compare_registry_projects_semantically(
    options: &ProjectSemanticComparisonOptions,
) -> Result<ProjectSemanticComparisonReportV1> {
    let current = load_comparison_input(
        &options.current_project_directory,
        &options.current_environment,
    )?;
    let baseline = load_comparison_input(
        &options.baseline_project_directory,
        &options.baseline_environment,
    )?;
    compare_loaded_projects(
        &current,
        &baseline,
        SemanticComparisonKind::LocalProjectToProject,
        SemanticComparisonAssurance::LocalUnverified,
    )
}

/// Compares two environments of the same locally loaded authored project.
pub fn compare_registry_project_environments_semantically(
    options: &ProjectEnvironmentSemanticComparisonOptions,
) -> Result<ProjectSemanticComparisonReportV1> {
    let current = load_comparison_input(&options.project_directory, &options.current_environment)?;
    let baseline =
        load_comparison_input(&options.project_directory, &options.baseline_environment)?;
    compare_loaded_projects(
        &current,
        &baseline,
        SemanticComparisonKind::SameProjectEnvironmentToEnvironment,
        SemanticComparisonAssurance::LocalUnverified,
    )
}

/// Compares the project with the exact starter embedded in this binary.
///
/// The current project's recorded starter id, release, and starter-content
/// digest must exactly match the independently validated embedded starter.
/// Missing, unknown, or stale provenance fails closed without echoing it.
pub fn compare_registry_project_to_embedded_starter_semantically(
    options: &ProjectStarterSemanticComparisonOptions,
) -> Result<ProjectSemanticComparisonReportV1> {
    let current = load_comparison_input(&options.project_directory, &options.environment)?;
    let recorded = current
        .project
        .starter
        .as_ref()
        .ok_or_else(|| anyhow!("project starter provenance cannot be proved by this binary"))?;
    let selected = if let Some(selected) = options.starter {
        if recorded.id != selected.id() {
            bail!("selected embedded starter does not match project starter provenance");
        }
        selected
    } else {
        project_starter_by_id(&recorded.id)
            .ok_or_else(|| anyhow!("project starter provenance cannot be proved by this binary"))?
    };
    let embedded = selected
        .embedded()
        .map_err(|_| anyhow!("project starter provenance cannot be proved by this binary"))?;
    let staging =
        tempfile::tempdir().context("embedded starter comparison staging could not be created")?;
    copy_embedded_dir(embedded, staging.path())
        .map_err(|_| anyhow!("embedded starter comparison could not be prepared safely"))?;
    let baseline = load_comparison_input(staging.path(), &options.environment)
        .map_err(|_| anyhow!("embedded starter cannot be proved for the requested environment"))?;
    let embedded_recorded =
        baseline.project.starter.as_ref().ok_or_else(|| {
            anyhow!("embedded starter provenance cannot be proved by this binary")
        })?;
    if embedded_recorded.id != selected.id()
        || embedded_recorded.content_digest != baseline.project_content_digest
        || recorded.id != embedded_recorded.id
        || recorded.release != embedded_recorded.release
        || recorded.content_digest != embedded_recorded.content_digest
    {
        bail!("project starter provenance cannot be proved by this binary");
    }
    compare_loaded_projects(
        &current,
        &baseline,
        SemanticComparisonKind::EmbeddedStarterToProject,
        SemanticComparisonAssurance::EmbeddedExactRelease,
    )
}

fn project_starter_by_id(id: &str) -> Option<ProjectStarter> {
    [
        ProjectStarter::Http,
        ProjectStarter::Spreadsheet,
        ProjectStarter::Dhis2Tracker,
        ProjectStarter::OpencrvsDci,
        ProjectStarter::FhirR4,
        ProjectStarter::Snapshot,
    ]
    .into_iter()
    .find(|starter| starter.id() == id)
}

fn load_comparison_input(root: &Path, environment: &str) -> Result<LoadedRegistryProject> {
    load_registry_project(root, Some(environment))
        .map_err(|_| anyhow!("semantic comparison input could not be loaded safely"))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SnapshotScope {
    Project,
    Integration(String),
    Fixture(String, String),
    Entity(String),
    Environment,
    Generated,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SnapshotKey {
    scope: SnapshotScope,
    instance_field: String,
}

#[derive(Clone)]
struct SnapshotField {
    address: SemanticComparisonFieldAddress,
    source: SemanticComparisonChangeSource,
    dimension: SemanticComparisonDimension,
    sensitivity: knowledge::Sensitivity,
    semantic_owner: knowledge::SemanticOwner,
    human_owner: knowledge::HumanOwner,
    consumers: Vec<SemanticComparisonConsumer>,
    generated_artifacts: Vec<SemanticComparisonGeneratedArtifact>,
    review_classes: Vec<SemanticComparisonReviewClass>,
    fingerprint: [u8; 32],
    comparable: Option<Value>,
}

#[derive(Clone, Copy)]
struct ComparisonProductTopology {
    relay: bool,
    notary: bool,
}

impl ComparisonProductTopology {
    fn from_loaded(loaded: &LoadedRegistryProject) -> Self {
        let (relay, notary) = project_product_topology(&loaded.project);
        Self { relay, notary }
    }

    const fn union(self, other: Self) -> Self {
        Self {
            relay: self.relay || other.relay,
            notary: self.notary || other.notary,
        }
    }

    fn retains_runtime_consumer(self, consumers: &[SemanticComparisonConsumer]) -> bool {
        (self.relay && consumers.contains(&SemanticComparisonConsumer::RegistryRelay))
            || (self.notary && consumers.contains(&SemanticComparisonConsumer::RegistryNotary))
    }
}

fn compare_loaded_projects(
    current: &LoadedRegistryProject,
    baseline: &LoadedRegistryProject,
    comparison: SemanticComparisonKind,
    assurance: SemanticComparisonAssurance,
) -> Result<ProjectSemanticComparisonReportV1> {
    let current_snapshot = semantic_snapshot(current)?;
    let baseline_snapshot = semantic_snapshot(baseline)?;
    // The normalized compiler projections are the final effective-state
    // authority for this local comparison. If both are byte-equivalent, raw
    // presence differences such as an explicit value versus its equivalent
    // default are not semantic changes.
    if generated_projections_equal(&current_snapshot, &baseline_snapshot) {
        return Ok(equivalent_report(comparison, assurance));
    }
    let product_topology = ComparisonProductTopology::from_loaded(current)
        .union(ComparisonProductTopology::from_loaded(baseline));
    let subjects = affected_subject_inventory(current, baseline)?;
    let mut changes = Vec::new();
    let keys = current_snapshot
        .keys()
        .chain(baseline_snapshot.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for key in keys {
        let current_field = current_snapshot.get(&key);
        let baseline_field = baseline_snapshot.get(&key);
        if current_field
            .zip(baseline_field)
            .is_some_and(|(current, baseline)| current.fingerprint == baseline.fingerprint)
        {
            continue;
        }
        let field = current_field
            .or(baseline_field)
            .ok_or_else(|| anyhow!("semantic comparison encountered an empty field projection"))?;
        let direction = match (current_field, baseline_field) {
            (Some(_), None) => SemanticComparisonDirection::Added,
            (None, Some(_)) => SemanticComparisonDirection::Removed,
            (Some(current), Some(baseline)) => comparison_direction(current, baseline),
            (None, None) => unreachable!(),
        };
        let consumers =
            filter_consumers_for_topology(&field.consumers, product_topology, field.source);
        let generated_artifacts =
            filter_artifacts_for_topology(&field.generated_artifacts, product_topology);
        let review_classes = filter_reviews_for_topology(&field.review_classes, product_topology);
        let requirements = requirements_for_consumers(&consumers);
        changes.push(ProjectSemanticComparisonChange {
            address: field.address.clone(),
            source: field.source,
            dimension: field.dimension,
            direction,
            sensitivity: field.sensitivity,
            semantic_owner: field.semantic_owner,
            human_owner: field.human_owner,
            consumers,
            generated_artifacts,
            review_classes,
            affected_subjects: subjects.clone(),
            occurrences: 1,
            requirements,
        });
        if changes.len() > MAX_SEMANTIC_COMPARISON_CHANGES {
            bail!("semantic comparison exceeds the bounded change-report capacity");
        }
    }
    let changes = aggregate_changes(changes)?;
    let review_classes = changes
        .iter()
        .flat_map(|change| change.review_classes.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let required_actions = required_actions(&changes);
    let equivalent = changes.is_empty();
    Ok(ProjectSemanticComparisonReportV1 {
        schema_version: ProjectSemanticComparisonSchemaVersion::V1,
        comparison,
        evidence_grade: SemanticComparisonEvidenceGrade::OfflineStatic,
        assurance,
        external_approval: SemanticComparisonExternalApproval::NotEvaluated,
        equivalence: if equivalent {
            SemanticComparisonEquivalence::Equivalent
        } else {
            SemanticComparisonEquivalence::Different
        },
        comparison_precision: SemanticComparisonPrecision::FieldAndGeneratedProjection,
        review_plan: SemanticComparisonReviewPlan {
            state: if equivalent {
                SemanticComparisonReviewPlanState::GeneratedNoChanges
            } else {
                SemanticComparisonReviewPlanState::GeneratedPendingReview
            },
            review_classes,
        },
        changes,
        required_actions,
        evidence_limitations: EVIDENCE_LIMITATIONS.to_vec(),
    })
}

fn generated_projections_equal(
    current: &BTreeMap<SnapshotKey, SnapshotField>,
    baseline: &BTreeMap<SnapshotKey, SnapshotField>,
) -> bool {
    ["/review_plan", "/approval_projection"]
        .into_iter()
        .all(|field| {
            let key = SnapshotKey {
                scope: SnapshotScope::Generated,
                instance_field: field.to_owned(),
            };
            current
                .get(&key)
                .zip(baseline.get(&key))
                .is_some_and(|(current, baseline)| current.fingerprint == baseline.fingerprint)
        })
}

fn equivalent_report(
    comparison: SemanticComparisonKind,
    assurance: SemanticComparisonAssurance,
) -> ProjectSemanticComparisonReportV1 {
    ProjectSemanticComparisonReportV1 {
        schema_version: ProjectSemanticComparisonSchemaVersion::V1,
        comparison,
        evidence_grade: SemanticComparisonEvidenceGrade::OfflineStatic,
        assurance,
        external_approval: SemanticComparisonExternalApproval::NotEvaluated,
        equivalence: SemanticComparisonEquivalence::Equivalent,
        comparison_precision: SemanticComparisonPrecision::FieldAndGeneratedProjection,
        review_plan: SemanticComparisonReviewPlan {
            state: SemanticComparisonReviewPlanState::GeneratedNoChanges,
            review_classes: Vec::new(),
        },
        changes: Vec::new(),
        required_actions: Vec::new(),
        evidence_limitations: EVIDENCE_LIMITATIONS.to_vec(),
    }
}

fn aggregate_changes(
    changes: Vec<ProjectSemanticComparisonChange>,
) -> Result<Vec<ProjectSemanticComparisonChange>> {
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct AggregateKey {
        address: SemanticComparisonFieldAddress,
        source: SemanticComparisonChangeSource,
        dimension: SemanticComparisonDimension,
        direction: SemanticComparisonDirection,
        sensitivity: knowledge::Sensitivity,
        semantic_owner: knowledge::SemanticOwner,
        human_owner: knowledge::HumanOwner,
        consumers: Vec<SemanticComparisonConsumer>,
        generated_artifacts: Vec<SemanticComparisonGeneratedArtifact>,
        review_classes: Vec<SemanticComparisonReviewClass>,
        requirements: SemanticComparisonRequirements,
    }

    let mut aggregated = BTreeMap::<AggregateKey, ProjectSemanticComparisonChange>::new();
    for change in changes {
        let key = AggregateKey {
            address: change.address.clone(),
            source: change.source,
            dimension: change.dimension,
            direction: change.direction,
            sensitivity: change.sensitivity,
            semantic_owner: change.semantic_owner,
            human_owner: change.human_owner,
            consumers: change.consumers.clone(),
            generated_artifacts: change.generated_artifacts.clone(),
            review_classes: change.review_classes.clone(),
            requirements: change.requirements,
        };
        if let Some(existing) = aggregated.get_mut(&key) {
            existing.occurrences = existing
                .occurrences
                .checked_add(change.occurrences)
                .filter(|count| usize::from(*count) <= MAX_SEMANTIC_COMPARISON_OCCURRENCES)
                .ok_or_else(|| anyhow!("semantic comparison occurrence bound was exceeded"))?;
        } else {
            aggregated.insert(key, change);
        }
    }
    if aggregated.len() > MAX_SEMANTIC_COMPARISON_CHANGES {
        bail!("semantic comparison exceeds the bounded change-report capacity");
    }
    Ok(aggregated.into_values().collect())
}

fn semantic_snapshot(
    loaded: &LoadedRegistryProject,
) -> Result<BTreeMap<SnapshotKey, SnapshotField>> {
    let environment_name = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("semantic comparison requires an explicit environment"))?;
    let explanation = generated_explanation(loaded, environment_name)
        .map_err(|_| anyhow!("semantic comparison projection could not be generated safely"))?;
    let documents = typed_documents(loaded)?;
    let mut snapshot = BTreeMap::new();
    for field in explanation.fields {
        let (scope, instance_field) = snapshot_scope(&field.address);
        if comparison_ignores_field(&scope, &instance_field) {
            continue;
        }
        let schema_ref =
            field.constraints.schema_refs.first().ok_or_else(|| {
                anyhow!("semantic comparison field has no published schema address")
            })?;
        let schema_family = schema_family(schema_ref.schema);
        let actual = documents
            .value(&scope)
            .and_then(|document| document.pointer(&instance_field))
            .cloned();
        let fallback = serde_json::to_value(&field.reported_value)
            .context("semantic comparison safe field projection could not be serialized")?;
        let sensitivity =
            comparison_sensitivity(schema_family, &instance_field, field.knowledge.sensitivity);
        let approved_fallback = if sensitivity.value_is_reportable(true) {
            match &field.reported_value {
                ClassifierSafeReportedValue::Public { value } => Some(value.as_value().clone()),
                ClassifierSafeReportedValue::Redacted { .. }
                | ClassifierSafeReportedValue::Absent => None,
            }
        } else {
            None
        };
        let normalized = actual
            .clone()
            .or_else(|| approved_fallback.clone())
            .unwrap_or(fallback);
        let fingerprint = fingerprint_json(&normalized)?;
        let comparable = sensitivity.value_is_reportable(true).then_some(normalized);
        let dimension =
            comparison_dimension(schema_family, schema_ref.path.as_str(), &instance_field);
        let key = SnapshotKey {
            scope,
            instance_field,
        };
        let projected = SnapshotField {
            address: SemanticComparisonFieldAddress {
                schema_family,
                field: schema_ref.path.clone(),
            },
            source: comparison_source(field.source.kind),
            dimension,
            sensitivity,
            semantic_owner: field.knowledge.semantic_owner,
            human_owner: field.knowledge.human_owner,
            consumers: comparison_consumers(&field.knowledge.consumers),
            generated_artifacts: comparison_artifacts(&field.knowledge.generated_artifacts),
            review_classes: comparison_reviews(&field.knowledge.review_classes),
            fingerprint,
            comparable,
        };
        snapshot.insert(key, projected);
    }
    add_script_fingerprints(loaded, &mut snapshot)?;
    add_generated_projection_fingerprints(loaded, &mut snapshot)?;
    Ok(snapshot)
}

fn comparison_sensitivity(
    schema: SemanticComparisonSchemaFamily,
    instance_field: &str,
    declared: knowledge::Sensitivity,
) -> knowledge::Sensitivity {
    if schema == SemanticComparisonSchemaFamily::Environment
        && (instance_field.contains("/credential")
            || instance_field.ends_with("/signing_key")
            || instance_field.ends_with("/api_key_fingerprint")
            || instance_field.ends_with("/private_key")
            || instance_field.ends_with("/connection"))
    {
        knowledge::Sensitivity::SecretReference
    } else {
        declared
    }
}

struct TypedDocuments {
    project: Value,
    environment: Value,
    integrations: BTreeMap<String, Value>,
    fixtures: BTreeMap<(String, String), Value>,
    entities: BTreeMap<String, Value>,
}

impl TypedDocuments {
    fn value(&self, scope: &SnapshotScope) -> Option<&Value> {
        match scope {
            SnapshotScope::Project => Some(&self.project),
            SnapshotScope::Environment => Some(&self.environment),
            SnapshotScope::Integration(id) => self.integrations.get(id),
            SnapshotScope::Fixture(integration, fixture) => {
                self.fixtures.get(&(integration.clone(), fixture.clone()))
            }
            SnapshotScope::Entity(id) => self.entities.get(id),
            SnapshotScope::Generated => None,
        }
    }
}

fn typed_documents(loaded: &LoadedRegistryProject) -> Result<TypedDocuments> {
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("semantic comparison requires an explicit environment"))?;
    let project = serde_json::to_value(&loaded.project)
        .context("semantic comparison project normalization failed")?;
    let environment = serde_json::to_value(environment)
        .context("semantic comparison environment normalization failed")?;
    let integrations = loaded
        .integrations
        .iter()
        .map(|(id, integration)| {
            serde_json::to_value(&integration.document)
                .map(|document| (id.clone(), document))
                .context("semantic comparison integration normalization failed")
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let fixtures = loaded
        .integrations
        .iter()
        .flat_map(|(integration, loaded)| {
            loaded.fixtures.iter().map(move |(_, fixture)| {
                serde_json::to_value(fixture)
                    .map(|document| ((integration.clone(), fixture.name.clone()), document))
                    .context("semantic comparison fixture normalization failed")
            })
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let entities = loaded
        .entities
        .iter()
        .map(|(id, entity)| {
            serde_json::to_value(&entity.document)
                .map(|document| (id.clone(), document))
                .context("semantic comparison entity normalization failed")
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(TypedDocuments {
        project,
        environment,
        integrations,
        fixtures,
        entities,
    })
}

fn snapshot_scope(address: &ProjectFieldAddress) -> (SnapshotScope, String) {
    match address {
        ProjectFieldAddress::Project { path } => (SnapshotScope::Project, path.as_str().to_owned()),
        ProjectFieldAddress::Integration { integration, path } => (
            SnapshotScope::Integration(integration.clone()),
            path.as_str().to_owned(),
        ),
        ProjectFieldAddress::Entity { entity, path } => (
            SnapshotScope::Entity(entity.clone()),
            path.as_str().to_owned(),
        ),
        ProjectFieldAddress::Environment { path, .. } => {
            (SnapshotScope::Environment, path.as_str().to_owned())
        }
        ProjectFieldAddress::Fixture {
            integration,
            fixture,
            path,
        } => (
            SnapshotScope::Fixture(integration.clone(), fixture.clone()),
            path.as_str().to_owned(),
        ),
    }
}

fn comparison_ignores_field(scope: &SnapshotScope, instance_field: &str) -> bool {
    matches!(scope, SnapshotScope::Project)
        && (instance_field == "/starter"
            || instance_field.starts_with("/starter/")
            || ((instance_field.starts_with("/integrations/")
                || instance_field.starts_with("/entities/"))
                && instance_field.ends_with("/file")))
}

fn schema_family(schema: ProjectAuthoringSchema) -> SemanticComparisonSchemaFamily {
    match schema {
        ProjectAuthoringSchema::Project => SemanticComparisonSchemaFamily::Project,
        ProjectAuthoringSchema::Environment => SemanticComparisonSchemaFamily::Environment,
        ProjectAuthoringSchema::Integration => SemanticComparisonSchemaFamily::Integration,
        ProjectAuthoringSchema::Fixture => SemanticComparisonSchemaFamily::Fixture,
        ProjectAuthoringSchema::Entity => SemanticComparisonSchemaFamily::Entity,
    }
}

fn comparison_source(source: FieldSourceKind) -> SemanticComparisonChangeSource {
    match source {
        FieldSourceKind::Authored => SemanticComparisonChangeSource::Authored,
        FieldSourceKind::Defaulted => SemanticComparisonChangeSource::Defaulted,
        FieldSourceKind::Derived | FieldSourceKind::Detected => {
            SemanticComparisonChangeSource::Derived
        }
        FieldSourceKind::EnvironmentBound => SemanticComparisonChangeSource::EnvironmentBound,
        FieldSourceKind::Generated => SemanticComparisonChangeSource::Generated,
        FieldSourceKind::Runtime | FieldSourceKind::Absent => {
            SemanticComparisonChangeSource::Derived
        }
    }
}

fn comparison_dimension(
    schema: SemanticComparisonSchemaFamily,
    schema_field: &str,
    instance_field: &str,
) -> SemanticComparisonDimension {
    match schema {
        SemanticComparisonSchemaFamily::Environment => {
            SemanticComparisonDimension::OperatorSecurity
        }
        SemanticComparisonSchemaFamily::Integration => SemanticComparisonDimension::Integration,
        SemanticComparisonSchemaFamily::Fixture => SemanticComparisonDimension::Fixture,
        SemanticComparisonSchemaFamily::Entity => SemanticComparisonDimension::Entity,
        SemanticComparisonSchemaFamily::GeneratedReview => {
            SemanticComparisonDimension::GeneratedReview
        }
        SemanticComparisonSchemaFamily::GeneratedApproval => {
            SemanticComparisonDimension::GeneratedApproval
        }
        SemanticComparisonSchemaFamily::Project => {
            if schema_field.contains("/consultations") || instance_field.contains("/consultations/")
            {
                SemanticComparisonDimension::Consultation
            } else if schema_field.contains("/disclosure")
                || (instance_field.contains("/claims/") && instance_field.ends_with("/disclosure"))
            {
                SemanticComparisonDimension::Disclosure
            } else if schema_field.contains("/claims")
                || schema_field.contains("/credential_profiles")
                || instance_field.contains("/claims/")
                || instance_field.contains("/credential_profiles/")
            {
                SemanticComparisonDimension::Claim
            } else if schema_field.contains("/integrations")
                || instance_field.starts_with("/integrations/")
            {
                SemanticComparisonDimension::Integration
            } else if schema_field.contains("/entities") || instance_field.starts_with("/entities/")
            {
                SemanticComparisonDimension::Entity
            } else if schema_field.contains("/services") || instance_field.starts_with("/services/")
            {
                SemanticComparisonDimension::ServicePolicy
            } else {
                SemanticComparisonDimension::Project
            }
        }
    }
}

fn comparison_consumers(consumers: &[knowledge::Consumer]) -> Vec<SemanticComparisonConsumer> {
    let mut result = consumers
        .iter()
        .map(|consumer| match consumer {
            knowledge::Consumer::RegistryctlAuthoring => {
                SemanticComparisonConsumer::RegistryctlAuthoring
            }
            knowledge::Consumer::RegistryRelay => SemanticComparisonConsumer::RegistryRelay,
            knowledge::Consumer::RegistryNotary => SemanticComparisonConsumer::RegistryNotary,
            knowledge::Consumer::EditorTooling => SemanticComparisonConsumer::EditorTooling,
            knowledge::Consumer::DocsGenerator => SemanticComparisonConsumer::DocsGenerator,
        })
        .collect::<BTreeSet<_>>();
    if result.contains(&SemanticComparisonConsumer::RegistryRelay)
        || result.contains(&SemanticComparisonConsumer::RegistryNotary)
    {
        result.extend([
            SemanticComparisonConsumer::BundleSigner,
            SemanticComparisonConsumer::DeploymentTooling,
            SemanticComparisonConsumer::Operator,
        ]);
    }
    result.into_iter().collect()
}

fn filter_consumers_for_topology(
    consumers: &[SemanticComparisonConsumer],
    topology: ComparisonProductTopology,
    source: SemanticComparisonChangeSource,
) -> Vec<SemanticComparisonConsumer> {
    let retains_generic_runtime_consumer = topology.retains_runtime_consumer(consumers)
        || source == SemanticComparisonChangeSource::Generated;
    consumers
        .iter()
        .copied()
        .filter(|consumer| match consumer {
            SemanticComparisonConsumer::RegistryRelay => topology.relay,
            SemanticComparisonConsumer::RegistryNotary => topology.notary,
            SemanticComparisonConsumer::BundleSigner
            | SemanticComparisonConsumer::DeploymentTooling
            | SemanticComparisonConsumer::Operator => retains_generic_runtime_consumer,
            SemanticComparisonConsumer::RegistryctlAuthoring
            | SemanticComparisonConsumer::EditorTooling
            | SemanticComparisonConsumer::DocsGenerator => true,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn comparison_artifacts(
    artifacts: &[knowledge::GeneratedArtifact],
) -> Vec<SemanticComparisonGeneratedArtifact> {
    artifacts
        .iter()
        .map(|artifact| match artifact {
            knowledge::GeneratedArtifact::EditorSchemas => {
                SemanticComparisonGeneratedArtifact::EditorSchemas
            }
            knowledge::GeneratedArtifact::ProjectBuild => {
                SemanticComparisonGeneratedArtifact::ProjectBuild
            }
            knowledge::GeneratedArtifact::RelayConfig => {
                SemanticComparisonGeneratedArtifact::RelayConfig
            }
            knowledge::GeneratedArtifact::NotaryConfig => {
                SemanticComparisonGeneratedArtifact::NotaryConfig
            }
            knowledge::GeneratedArtifact::FixtureReport => {
                SemanticComparisonGeneratedArtifact::FixtureReport
            }
            knowledge::GeneratedArtifact::FieldReference => {
                SemanticComparisonGeneratedArtifact::FieldReference
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn filter_artifacts_for_topology(
    artifacts: &[SemanticComparisonGeneratedArtifact],
    topology: ComparisonProductTopology,
) -> Vec<SemanticComparisonGeneratedArtifact> {
    artifacts
        .iter()
        .copied()
        .filter(|artifact| match artifact {
            SemanticComparisonGeneratedArtifact::RelayConfig => topology.relay,
            SemanticComparisonGeneratedArtifact::NotaryConfig => topology.notary,
            SemanticComparisonGeneratedArtifact::EditorSchemas
            | SemanticComparisonGeneratedArtifact::ProjectBuild
            | SemanticComparisonGeneratedArtifact::FixtureReport
            | SemanticComparisonGeneratedArtifact::FieldReference
            | SemanticComparisonGeneratedArtifact::ReviewPlan
            | SemanticComparisonGeneratedArtifact::ApprovalProjection => true,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn comparison_reviews(reviews: &[knowledge::ReviewClass]) -> Vec<SemanticComparisonReviewClass> {
    let mut result = reviews
        .iter()
        .map(|review| match review {
            knowledge::ReviewClass::Contract => SemanticComparisonReviewClass::Contract,
            knowledge::ReviewClass::Security => SemanticComparisonReviewClass::Security,
            knowledge::ReviewClass::Privacy => SemanticComparisonReviewClass::Privacy,
            knowledge::ReviewClass::Relay => SemanticComparisonReviewClass::Relay,
            knowledge::ReviewClass::Notary => SemanticComparisonReviewClass::Notary,
            knowledge::ReviewClass::Compatibility => SemanticComparisonReviewClass::Compatibility,
            knowledge::ReviewClass::Documentation => SemanticComparisonReviewClass::Documentation,
            knowledge::ReviewClass::Testing => SemanticComparisonReviewClass::Testing,
        })
        .collect::<BTreeSet<_>>();
    result.extend([
        SemanticComparisonReviewClass::Authoring,
        SemanticComparisonReviewClass::Semantics,
        SemanticComparisonReviewClass::Interoperability,
        SemanticComparisonReviewClass::Operations,
        SemanticComparisonReviewClass::Release,
    ]);
    result.into_iter().collect()
}

fn filter_reviews_for_topology(
    reviews: &[SemanticComparisonReviewClass],
    topology: ComparisonProductTopology,
) -> Vec<SemanticComparisonReviewClass> {
    reviews
        .iter()
        .copied()
        .filter(|review| match review {
            SemanticComparisonReviewClass::Relay => topology.relay,
            SemanticComparisonReviewClass::Notary => topology.notary,
            SemanticComparisonReviewClass::Contract
            | SemanticComparisonReviewClass::Authoring
            | SemanticComparisonReviewClass::Semantics
            | SemanticComparisonReviewClass::Interoperability
            | SemanticComparisonReviewClass::Privacy
            | SemanticComparisonReviewClass::Security
            | SemanticComparisonReviewClass::Compatibility
            | SemanticComparisonReviewClass::Documentation
            | SemanticComparisonReviewClass::Testing
            | SemanticComparisonReviewClass::Operations
            | SemanticComparisonReviewClass::Release => true,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fingerprint_json(value: &Value) -> Result<[u8; 32]> {
    let canonical =
        canonicalize_json(value).context("semantic comparison value normalization failed")?;
    Ok(Sha256::digest(canonical).into())
}

fn add_script_fingerprints(
    loaded: &LoadedRegistryProject,
    snapshot: &mut BTreeMap<SnapshotKey, SnapshotField>,
) -> Result<()> {
    for (integration, loaded_integration) in &loaded.integrations {
        if loaded_integration.script.is_none() && loaded_integration.script_modules.is_empty() {
            continue;
        }
        let key = snapshot
            .keys()
            .find(|key| {
                matches!(&key.scope, SnapshotScope::Integration(id) if id == integration)
                    && key.instance_field.contains("script")
            })
            .cloned()
            .ok_or_else(|| anyhow!("script integration has no published comparison address"))?;
        let field = snapshot
            .get_mut(&key)
            .ok_or_else(|| anyhow!("script comparison projection is absent"))?;
        let mut hasher = Sha256::new();
        hasher.update(field.fingerprint);
        if let Some((_, bytes)) = &loaded_integration.script {
            hasher.update([0]);
            hasher.update(bytes);
        }
        for (_, bytes) in &loaded_integration.script_modules {
            hasher.update([1]);
            hasher.update(bytes);
        }
        field.fingerprint = hasher.finalize().into();
        field.comparable = None;
    }
    Ok(())
}

fn add_generated_projection_fingerprints(
    loaded: &LoadedRegistryProject,
    snapshot: &mut BTreeMap<SnapshotKey, SnapshotField>,
) -> Result<()> {
    let compiled = compile_project(loaded, None)
        .map_err(|_| anyhow!("semantic comparison generated projection failed safely"))?;
    let mut review = compiled.review;
    remove_projection_identity(&mut review, &["registry", "environment"]);
    let mut approval = compiled.approval_state;
    // The authored-input digest is intentionally byte-sensitive and therefore
    // unsuitable for this semantic comparison. The report digest is derived
    // from the already compared review projection. All semantic and generated
    // closure fingerprints remain internal comparison inputs.
    remove_projection_identity(
        &mut approval,
        &[
            "registry",
            "environment",
            "authored_input_digest",
            "report_digest",
            "baseline",
        ],
    );
    for (schema_family, dimension, field_name, value) in [
        (
            SemanticComparisonSchemaFamily::GeneratedReview,
            SemanticComparisonDimension::GeneratedReview,
            "/review_plan",
            &review,
        ),
        (
            SemanticComparisonSchemaFamily::GeneratedApproval,
            SemanticComparisonDimension::GeneratedApproval,
            "/approval_projection",
            &approval,
        ),
    ] {
        let address = SemanticComparisonFieldAddress {
            schema_family,
            field: JsonPointer::new(field_name)
                .map_err(|_| anyhow!("generated comparison address is invalid"))?,
        };
        snapshot.insert(
            SnapshotKey {
                scope: SnapshotScope::Generated,
                instance_field: field_name.to_owned(),
            },
            SnapshotField {
                address,
                source: SemanticComparisonChangeSource::Generated,
                dimension,
                sensitivity: knowledge::Sensitivity::Internal,
                semantic_owner: knowledge::SemanticOwner::AuthoringContract,
                human_owner: knowledge::HumanOwner::RegistryMaintainers,
                consumers: vec![
                    SemanticComparisonConsumer::RegistryctlAuthoring,
                    SemanticComparisonConsumer::BundleSigner,
                    SemanticComparisonConsumer::DeploymentTooling,
                    SemanticComparisonConsumer::Operator,
                ],
                generated_artifacts: vec![
                    SemanticComparisonGeneratedArtifact::ReviewPlan,
                    SemanticComparisonGeneratedArtifact::ApprovalProjection,
                ],
                review_classes: vec![
                    SemanticComparisonReviewClass::Contract,
                    SemanticComparisonReviewClass::Authoring,
                    SemanticComparisonReviewClass::Semantics,
                    SemanticComparisonReviewClass::Security,
                    SemanticComparisonReviewClass::Compatibility,
                    SemanticComparisonReviewClass::Operations,
                    SemanticComparisonReviewClass::Release,
                ],
                fingerprint: fingerprint_json(value)?,
                comparable: None,
            },
        );
    }
    Ok(())
}

fn remove_projection_identity(value: &mut Value, fields: &[&str]) {
    if let Some(object) = value.as_object_mut() {
        for field in fields {
            object.remove(*field);
        }
    }
}

fn comparison_direction(
    current: &SnapshotField,
    baseline: &SnapshotField,
) -> SemanticComparisonDirection {
    let Some(current_value) = current.comparable.as_ref() else {
        return SemanticComparisonDirection::Changed;
    };
    let Some(baseline_value) = baseline.comparable.as_ref() else {
        return SemanticComparisonDirection::Changed;
    };
    direction_for_values(
        current.address.field.as_str(),
        current_value,
        baseline_value,
    )
}

fn direction_for_values(
    schema_field: &str,
    current: &Value,
    baseline: &Value,
) -> SemanticComparisonDirection {
    if let Some(ordering) = numeric_ordering(current, baseline) {
        if ordering == Ordering::Equal {
            return SemanticComparisonDirection::Changed;
        }
        if lower_bound_field(schema_field) {
            return if ordering == Ordering::Greater {
                SemanticComparisonDirection::Narrowed
            } else {
                SemanticComparisonDirection::Widened
            };
        }
        if upper_bound_field(schema_field) {
            return if ordering == Ordering::Less {
                SemanticComparisonDirection::Narrowed
            } else {
                SemanticComparisonDirection::Widened
            };
        }
    }
    if required_field(schema_field) {
        if let (Some(current), Some(baseline)) = (current.as_bool(), baseline.as_bool()) {
            return match (current, baseline) {
                (true, false) => SemanticComparisonDirection::Narrowed,
                (false, true) => SemanticComparisonDirection::Widened,
                _ => SemanticComparisonDirection::Changed,
            };
        }
    }
    if disclosure_field(schema_field) {
        if let (Some(current), Some(baseline)) = (current.as_str(), baseline.as_str()) {
            let rank = |value| match value {
                "redacted" => Some(0),
                "predicate" => Some(1),
                "value" => Some(2),
                _ => None,
            };
            if let (Some(current), Some(baseline)) = (rank(current), rank(baseline)) {
                return if current < baseline {
                    SemanticComparisonDirection::Narrowed
                } else {
                    SemanticComparisonDirection::Widened
                };
            }
        }
    }
    SemanticComparisonDirection::Changed
}

fn numeric_ordering(current: &Value, baseline: &Value) -> Option<Ordering> {
    let current = current.as_number()?;
    let baseline = baseline.as_number()?;
    let exact_integer = |number: &serde_json::Number| {
        number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))
    };
    match (exact_integer(current), exact_integer(baseline)) {
        (Some(current), Some(baseline)) => Some(current.cmp(&baseline)),
        _ => current.as_f64()?.partial_cmp(&baseline.as_f64()?),
    }
}

fn lower_bound_field(field: &str) -> bool {
    [
        "/properties/minLength",
        "/properties/minimum",
        "/properties/min_group_size",
    ]
    .iter()
    .any(|suffix| field.ends_with(suffix))
}

fn upper_bound_field(field: &str) -> bool {
    [
        "/properties/maxLength",
        "/properties/maximum",
        "/properties/max_bytes",
        "/properties/max_items",
        "/properties/max_records",
        "/properties/max_limit",
        "/properties/calls",
        "/properties/request_bytes",
        "/properties/source_bytes",
        "/properties/concurrency",
        "/properties/per_minute",
        "/properties/burst",
        "/properties/worker_memory_bytes",
        "/properties/retain_generations",
    ]
    .iter()
    .any(|suffix| field.ends_with(suffix))
}

fn required_field(field: &str) -> bool {
    field.ends_with("/properties/required")
}

fn disclosure_field(field: &str) -> bool {
    field.ends_with("/properties/disclosure")
}

fn requirements_for_consumers(
    consumers: &[SemanticComparisonConsumer],
) -> SemanticComparisonRequirements {
    let relay = consumers.contains(&SemanticComparisonConsumer::RegistryRelay);
    let notary = consumers.contains(&SemanticComparisonConsumer::RegistryNotary);
    match (relay, notary) {
        (true, true) => SemanticComparisonRequirements {
            signing: SemanticComparisonSigningRequirement::RelayAndNotaryBundles,
            activation: SemanticComparisonActivationRequirement::ApplyRelayAndNotaryConfig,
            restart: SemanticComparisonRestartRequirement::RegistryRelayAndNotary,
        },
        (true, false) => SemanticComparisonRequirements {
            signing: SemanticComparisonSigningRequirement::RelayBundle,
            activation: SemanticComparisonActivationRequirement::ApplyRelayConfig,
            restart: SemanticComparisonRestartRequirement::RegistryRelay,
        },
        (false, true) => SemanticComparisonRequirements {
            signing: SemanticComparisonSigningRequirement::NotaryBundle,
            activation: SemanticComparisonActivationRequirement::ApplyNotaryConfig,
            restart: SemanticComparisonRestartRequirement::RegistryNotary,
        },
        (false, false) => SemanticComparisonRequirements {
            signing: SemanticComparisonSigningRequirement::None,
            activation: SemanticComparisonActivationRequirement::None,
            restart: SemanticComparisonRestartRequirement::None,
        },
    }
}

fn required_actions(
    changes: &[ProjectSemanticComparisonChange],
) -> Vec<SemanticComparisonRequiredAction> {
    let mut actions = BTreeSet::new();
    if !changes.is_empty() {
        actions.extend([
            SemanticComparisonRequiredAction::ReviewSemanticChanges,
            SemanticComparisonRequiredAction::RunAffectedFixtures,
            SemanticComparisonRequiredAction::RegenerateGeneratedArtifacts,
        ]);
    }
    for change in changes {
        match change.requirements.signing {
            SemanticComparisonSigningRequirement::RelayBundle => {
                actions.insert(SemanticComparisonRequiredAction::ResignRelayBundle);
            }
            SemanticComparisonSigningRequirement::NotaryBundle => {
                actions.insert(SemanticComparisonRequiredAction::ResignNotaryBundle);
            }
            SemanticComparisonSigningRequirement::RelayAndNotaryBundles => {
                actions.extend([
                    SemanticComparisonRequiredAction::ResignRelayBundle,
                    SemanticComparisonRequiredAction::ResignNotaryBundle,
                ]);
            }
            SemanticComparisonSigningRequirement::None => {}
        }
        match change.requirements.activation {
            SemanticComparisonActivationRequirement::ApplyRelayConfig => {
                actions.insert(SemanticComparisonRequiredAction::ReactivateRelayConfiguration);
            }
            SemanticComparisonActivationRequirement::ApplyNotaryConfig => {
                actions.insert(SemanticComparisonRequiredAction::ReactivateNotaryConfiguration);
            }
            SemanticComparisonActivationRequirement::ApplyRelayAndNotaryConfig => {
                actions.extend([
                    SemanticComparisonRequiredAction::ReactivateRelayConfiguration,
                    SemanticComparisonRequiredAction::ReactivateNotaryConfiguration,
                ]);
            }
            SemanticComparisonActivationRequirement::None => {}
        }
        match change.requirements.restart {
            SemanticComparisonRestartRequirement::RegistryRelay => {
                actions.insert(SemanticComparisonRequiredAction::RestartRegistryRelay);
            }
            SemanticComparisonRestartRequirement::RegistryNotary => {
                actions.insert(SemanticComparisonRequiredAction::RestartRegistryNotary);
            }
            SemanticComparisonRestartRequirement::RegistryRelayAndNotary => {
                actions.extend([
                    SemanticComparisonRequiredAction::RestartRegistryRelay,
                    SemanticComparisonRequiredAction::RestartRegistryNotary,
                ]);
            }
            SemanticComparisonRestartRequirement::None => {}
        }
    }
    actions.into_iter().collect()
}

fn affected_subject_inventory(
    current: &LoadedRegistryProject,
    baseline: &LoadedRegistryProject,
) -> Result<Vec<SemanticComparisonAffectedSubject>> {
    let mut counts = BTreeMap::new();
    counts.insert(
        SemanticComparisonAffectedSubjectKind::Integration,
        union_count(
            current.integrations.keys().cloned(),
            baseline.integrations.keys().cloned(),
        )?,
    );
    counts.insert(
        SemanticComparisonAffectedSubjectKind::Fixture,
        union_count(
            fixture_subjects(current).into_iter(),
            fixture_subjects(baseline).into_iter(),
        )?,
    );
    counts.insert(
        SemanticComparisonAffectedSubjectKind::Entity,
        union_count(
            current.entities.keys().cloned(),
            baseline.entities.keys().cloned(),
        )?,
    );
    counts.insert(
        SemanticComparisonAffectedSubjectKind::ServicePolicy,
        union_count(
            current.project.services.keys().cloned(),
            baseline.project.services.keys().cloned(),
        )?,
    );
    counts.insert(
        SemanticComparisonAffectedSubjectKind::Consultation,
        union_count(
            consultation_subjects(current).into_iter(),
            consultation_subjects(baseline).into_iter(),
        )?,
    );
    let claims = union_count(
        claim_subjects(current).into_iter(),
        claim_subjects(baseline).into_iter(),
    )?;
    counts.insert(SemanticComparisonAffectedSubjectKind::Claim, claims);
    counts.insert(SemanticComparisonAffectedSubjectKind::Disclosure, claims);
    counts.insert(SemanticComparisonAffectedSubjectKind::ProductInput, 2);
    counts.insert(SemanticComparisonAffectedSubjectKind::GeneratedArtifact, 8);
    Ok(counts
        .into_iter()
        .filter_map(|(kind, count)| {
            (count > 0).then_some(SemanticComparisonAffectedSubject { kind, count })
        })
        .collect())
}

fn fixture_subjects(loaded: &LoadedRegistryProject) -> BTreeSet<(String, String)> {
    loaded
        .integrations
        .iter()
        .flat_map(|(integration, loaded)| {
            loaded
                .fixtures
                .iter()
                .map(move |(_, fixture)| (integration.clone(), fixture.name.clone()))
        })
        .collect()
}

fn consultation_subjects(loaded: &LoadedRegistryProject) -> BTreeSet<(String, String)> {
    loaded
        .project
        .services
        .iter()
        .flat_map(|(service, declaration)| {
            declaration
                .consultations
                .keys()
                .map(move |consultation| (service.clone(), consultation.clone()))
        })
        .collect()
}

fn claim_subjects(loaded: &LoadedRegistryProject) -> BTreeSet<(String, String)> {
    loaded
        .project
        .services
        .iter()
        .flat_map(|(service, declaration)| {
            declaration
                .claims
                .keys()
                .map(move |claim| (service.clone(), claim.clone()))
        })
        .collect()
}

fn union_count<T>(
    current: impl Iterator<Item = T>,
    baseline: impl Iterator<Item = T>,
) -> Result<u16>
where
    T: Ord,
{
    let count = current.chain(baseline).collect::<BTreeSet<_>>().len();
    if count > MAX_SEMANTIC_COMPARISON_OCCURRENCES {
        bail!("semantic comparison affected-subject bound was exceeded");
    }
    u16::try_from(count)
        .map_err(|_| anyhow!("semantic comparison affected-subject bound was exceeded"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn initialized_http_project(parent: &Path, name: &str) -> PathBuf {
        let project = parent.join(name);
        init_registry_project(&ProjectInitOptions {
            starter: ProjectStarter::Http,
            directory: project.clone(),
        })
        .expect("HTTP project initializes");
        project
    }

    fn rewrite_yaml(path: &Path, update: impl FnOnce(&mut Value)) {
        let bytes = fs::read(path).expect("YAML reads");
        let mut document: Value = serde_norway::from_slice(&bytes).expect("YAML parses");
        update(&mut document);
        fs::write(
            path,
            serde_norway::to_string(&document).expect("YAML serializes"),
        )
        .expect("YAML writes");
    }

    fn assert_schema_valid(report: &ProjectSemanticComparisonReportV1) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../schemas/project-reports/registry.project.semantic_comparison.v1.schema.json"
        ))
        .expect("schema parses");
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("schema compiles");
        let report = serde_json::to_value(report).expect("report serializes");
        if let Err(errors) = validator.validate(&report) {
            panic!(
                "produced report validates: {:?}",
                errors.map(|error| error.to_string()).collect::<Vec<_>>()
            );
        };
    }

    #[test]
    fn direction_reverses_for_proven_upper_and_lower_bounds() {
        let upper = "/$defs/limits/properties/max_bytes";
        assert_eq!(
            direction_for_values(upper, &Value::from(8), &Value::from(16)),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(upper, &Value::from(16), &Value::from(8)),
            SemanticComparisonDirection::Widened
        );
        let lower = "/$defs/schema/properties/minimum";
        assert_eq!(
            direction_for_values(lower, &Value::from(8), &Value::from(4)),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(lower, &Value::from(4), &Value::from(8)),
            SemanticComparisonDirection::Widened
        );
    }

    #[test]
    fn integer_bound_direction_is_exact_above_f64_precision() {
        let upper = "/$defs/materialization/properties/max_records";
        let smaller = Value::from(9_007_199_254_740_992_u64);
        let larger = Value::from(9_007_199_254_740_993_u64);
        assert_eq!(
            direction_for_values(upper, &smaller, &larger),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(upper, &larger, &smaller),
            SemanticComparisonDirection::Widened
        );
        assert_eq!(
            direction_for_values(upper, &Value::from(u64::MAX - 1), &Value::from(u64::MAX),),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(
                upper,
                &Value::from(-9_007_199_254_740_993_i64),
                &Value::from(-9_007_199_254_740_992_i64),
            ),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(upper, &Value::from(-1_i64), &Value::from(0_u64)),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(upper, &Value::from(8.5_f64), &Value::from(16.0_f64)),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(upper, &Value::from(16_u64), &Value::from(16.0_f64)),
            SemanticComparisonDirection::Changed
        );

        let lower = "/$defs/schema/properties/minimum";
        assert_eq!(
            direction_for_values(lower, &larger, &smaller),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(lower, &smaller, &larger),
            SemanticComparisonDirection::Widened
        );
        assert_eq!(
            direction_for_values(lower, &Value::from(i64::MIN + 1), &Value::from(i64::MIN),),
            SemanticComparisonDirection::Narrowed
        );
        assert_eq!(
            direction_for_values(lower, &Value::from(i64::MIN), &Value::from(i64::MIN + 1),),
            SemanticComparisonDirection::Widened
        );
    }

    #[test]
    fn report_roundtrip_is_strict_and_human_summary_is_value_free() {
        let report = ProjectSemanticComparisonReportV1 {
            schema_version: ProjectSemanticComparisonSchemaVersion::V1,
            comparison: SemanticComparisonKind::LocalProjectToProject,
            evidence_grade: SemanticComparisonEvidenceGrade::OfflineStatic,
            assurance: SemanticComparisonAssurance::LocalUnverified,
            external_approval: SemanticComparisonExternalApproval::NotEvaluated,
            equivalence: SemanticComparisonEquivalence::Equivalent,
            comparison_precision: SemanticComparisonPrecision::FieldAndGeneratedProjection,
            review_plan: SemanticComparisonReviewPlan {
                state: SemanticComparisonReviewPlanState::GeneratedNoChanges,
                review_classes: Vec::new(),
            },
            changes: Vec::new(),
            required_actions: Vec::new(),
            evidence_limitations: EVIDENCE_LIMITATIONS.to_vec(),
        };
        let value = serde_json::to_value(&report).expect("report serializes");
        let decoded: ProjectSemanticComparisonReportV1 =
            serde_json::from_value(value.clone()).expect("report decodes");
        assert_eq!(decoded, report);
        let mut unknown = value;
        unknown["future"] = Value::Bool(true);
        assert!(
            serde_json::from_value::<ProjectSemanticComparisonReportV1>(unknown).is_err(),
            "unknown fields fail closed"
        );
        assert_eq!(
            report.human_safe_summary(),
            "semantic comparison: equivalent; assurance: local_unverified; changes: 0; review plan: generated_no_changes"
        );
    }

    #[test]
    fn strict_schema_validates_the_canonical_fixture_and_rejects_unknown_fields() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../schemas/project-reports/registry.project.semantic_comparison.v1.schema.json"
        ))
        .expect("schema parses");
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/project-reports/registry.project.semantic_comparison.v1.json"
        ))
        .expect("fixture parses");
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .expect("schema compiles");
        if let Err(errors) = validator.validate(&fixture) {
            panic!(
                "fixture validates: {:?}",
                errors.map(|error| error.to_string()).collect::<Vec<_>>()
            );
        }
        let decoded: ProjectSemanticComparisonReportV1 =
            serde_json::from_value(fixture.clone()).expect("fixture decodes");
        assert_eq!(
            serde_json::to_value(decoded).expect("fixture re-encodes"),
            fixture
        );
        let mut unknown = fixture;
        unknown["changes"][0]["address"]["future"] = Value::Bool(true);
        assert!(validator.validate(&unknown).is_err());
        assert!(
            serde_json::from_value::<ProjectSemanticComparisonReportV1>(unknown).is_err(),
            "typed ingress rejects nested unknown fields"
        );
    }

    #[test]
    fn formatting_defaults_and_exact_starter_modes_use_effective_state() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let baseline = initialized_http_project(temporary.path(), "baseline");
        let current = initialized_http_project(temporary.path(), "current");
        let compare = || {
            compare_registry_projects_semantically(&ProjectSemanticComparisonOptions {
                current_project_directory: current.clone(),
                current_environment: "local".to_owned(),
                baseline_project_directory: baseline.clone(),
                baseline_environment: "local".to_owned(),
            })
            .expect("projects compare")
        };

        let project_path = current.join(PROJECT_FILE);
        let original = fs::read_to_string(&project_path).expect("project reads");
        fs::write(&project_path, format!("# formatting only\n\n{original}\n"))
            .expect("project writes");
        assert_eq!(
            compare().equivalence,
            SemanticComparisonEquivalence::Equivalent
        );

        rewrite_yaml(&current.join("environments/local.yaml"), |document| {
            document["issuance"]["algorithm"] = Value::String("EdDSA".to_owned());
        });
        assert_eq!(
            compare().equivalence,
            SemanticComparisonEquivalence::Equivalent
        );

        let starter = compare_registry_project_to_embedded_starter_semantically(
            &ProjectStarterSemanticComparisonOptions {
                project_directory: baseline,
                environment: "local".to_owned(),
                starter: None,
            },
        )
        .expect("exact embedded starter compares");
        assert_eq!(
            starter.assurance,
            SemanticComparisonAssurance::EmbeddedExactRelease
        );
        assert_eq!(
            starter.equivalence,
            SemanticComparisonEquivalence::Equivalent
        );
    }

    #[test]
    fn sensitive_environment_change_is_detected_but_never_reported() {
        const SENTINEL: &str = "SEMANTIC_COMPARISON_SECRET_SENTINEL";

        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = initialized_http_project(temporary.path(), "project");
        let candidate = project.join("environments/candidate.yaml");
        fs::copy(project.join("environments/local.yaml"), &candidate).expect("environment copies");
        rewrite_yaml(&candidate, |document| {
            document["integrations"]["person-record"]["source"]["credential"]["token"]["secret"] =
                Value::String(SENTINEL.to_owned());
        });
        let report = compare_registry_project_environments_semantically(
            &ProjectEnvironmentSemanticComparisonOptions {
                project_directory: project,
                current_environment: "candidate".to_owned(),
                baseline_environment: "local".to_owned(),
            },
        )
        .expect("environments compare");
        assert_eq!(report.equivalence, SemanticComparisonEquivalence::Different);
        assert!(report.changes.iter().any(|change| {
            change.dimension == SemanticComparisonDimension::OperatorSecurity
                && change.sensitivity == knowledge::Sensitivity::SecretReference
        }));
        let json = String::from_utf8(report.canonical_json_bytes().expect("report serializes"))
            .expect("JSON is UTF-8");
        assert!(!json.contains(SENTINEL));
        assert!(!report.human_safe_summary().contains(SENTINEL));
        assert!(!format!("{report:?}").contains(SENTINEL));
        assert_schema_valid(&report);
    }

    #[test]
    fn starter_adaptation_compares_and_stale_provenance_fails_value_free() {
        const STALE_SENTINEL: &str = "SEMANTIC_COMPARISON_STALE_SENTINEL";

        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = initialized_http_project(temporary.path(), "project");
        let options = ProjectStarterSemanticComparisonOptions {
            project_directory: project.clone(),
            environment: "local".to_owned(),
            starter: None,
        };
        rewrite_yaml(&project.join(PROJECT_FILE), |document| {
            document["services"]["person-verification"]["purpose"] =
                Value::String("adapted-purpose".to_owned());
        });
        assert_eq!(
            compare_registry_project_to_embedded_starter_semantically(&options)
                .expect("adapted starter compares")
                .equivalence,
            SemanticComparisonEquivalence::Different
        );
        rewrite_yaml(&project.join(PROJECT_FILE), |document| {
            document["starter"]["release"] = Value::String(STALE_SENTINEL.to_owned());
        });
        let error = compare_registry_project_to_embedded_starter_semantically(&options)
            .expect_err("stale provenance fails closed");
        let error = format!("{error:#}");
        assert_eq!(
            error,
            "project starter provenance cannot be proved by this binary"
        );
        assert!(!error.contains(STALE_SENTINEL));
    }

    #[test]
    fn fixture_changes_feed_the_generated_pending_review_plan() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let baseline = initialized_http_project(temporary.path(), "baseline");
        let current = initialized_http_project(temporary.path(), "current");
        rewrite_yaml(
            &current.join("integrations/person-record/fixtures/active.yaml"),
            |document| {
                document["interactions"][0]["respond"]["body"]["active"] = Value::Bool(false);
                document["expect"]["outputs"]["active"] = Value::Bool(false);
                document["expect"]["claims"]["person-active"] = Value::Bool(false);
            },
        );
        let report = compare_registry_projects_semantically(&ProjectSemanticComparisonOptions {
            current_project_directory: current,
            current_environment: "local".to_owned(),
            baseline_project_directory: baseline,
            baseline_environment: "local".to_owned(),
        })
        .expect("fixture-bearing projects compare");
        assert_eq!(
            report.review_plan.state,
            SemanticComparisonReviewPlanState::GeneratedPendingReview
        );
        assert!(report
            .changes
            .iter()
            .any(|change| change.dimension == SemanticComparisonDimension::Fixture));
        assert!(report.changes.iter().any(|change| {
            change.address.schema_family == SemanticComparisonSchemaFamily::GeneratedApproval
        }));
        assert_schema_valid(&report);
    }
}
