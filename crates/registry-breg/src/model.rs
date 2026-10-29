// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_hooks::HookHandlerKind;
use serde::{Deserialize, Serialize};

use crate::artifacts::GeneratedArtifacts;
use crate::contract::{
    AccessLogSource, AccessProfileSource, BatchSource, Classification, ConstraintSource,
    EventConditionSource, FieldTypeSource, HookAuthenticationProfile, HookDeadLetterMode,
    HookSource, ManifestProjectionCatalogSource, ManifestProjectionDataServiceSource,
    ManifestProjectionDatasetSource, ManifestProjectionDistributionSource,
    ManifestProjectionEntitySource, ManifestProjectionPublicServiceSource,
    ManifestProjectionVocabularySource, MutationMode, NormalizationStep, Operation,
    PackageIdentitySource, ProvenanceFieldSource, RecipientGroupSource,
    RecipientOrganizationSource, RowBoundarySource, TemporalSource, ValidTimeRole,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::physical_names::PhysicalNameInventory;

#[cfg(feature = "runtime")]
pub(crate) const MAX_TARGET_CONTEXT_FIELDS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledField {
    pub id: String,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_role: Option<ValidTimeRole>,
    pub physical_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Storage is an encrypted envelope column instead of the plaintext type.
    /// `physical_name` points at the envelope column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<CompiledFieldEncryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<CompiledGeneratedIdentifier>,
    pub display: crate::contract::DisplaySource,
    pub relationship: Option<crate::contract::RelationshipSource>,
}

/// The compiled storage shape of an encrypted field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledFieldEncryption {
    /// The blind-index sibling column, present only when the author declared
    /// a lookup for the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blind_index: Option<CompiledBlindIndex>,
}

/// The compiled blind-index sibling of an encrypted column.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledBlindIndex {
    pub physical_name: String,
    pub normalization: Vec<NormalizationStep>,
    pub unique: bool,
}

/// Server-owned business identifier generation attached to one stored string
/// field. This does not replace the canonical record UUID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledGeneratedIdentifier {
    pub strategy: CompiledGeneratedIdentifierStrategy,
    pub prefix: String,
    /// The fields that partition a sequence; always empty for a random code.
    pub scope: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CompiledGeneratedIdentifierStrategy {
    Sequence { minimum_digits: u32 },
    Random { length: u32 },
}

/// Binary slot policy, separate from scalar fields and physical SQL columns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAttachmentSlot {
    pub id: String,
    pub required: bool,
    pub maximum_bytes: u32,
    pub content_types: Vec<String>,
    pub classification: Classification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledLogicalField {
    pub id: String,
    pub api_name: String,
    pub sql_name: String,
    pub field_type: FieldTypeSource,
    pub classification: Classification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<CompiledFieldEncryption>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledStoredField {
    #[serde(flatten)]
    pub logical: CompiledLogicalField,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_time_role: Option<ValidTimeRole>,
    pub physical_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledDerivedField {
    #[serde(flatten)]
    pub logical: CompiledLogicalField,
    #[serde(default, skip_serializing_if = "display_is_empty")]
    pub display: crate::contract::DisplaySource,
    pub derivation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledDerivedRelation {
    pub id: String,
    pub sql_path: String,
    pub key_field: String,
    pub execution: crate::contract::DerivedExecutionSource,
    pub sql_sha256: String,
    pub sql_bytes: Vec<u8>,
    pub fields: Vec<String>,
    /// Entity ids whose `registry_source` relations this SQL reads.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub source_entities: BTreeSet<String>,
    /// Whether this SQL calls `registry_context.evaluation_date()`.
    #[serde(default)]
    pub uses_evaluation_date: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledStatisticalDataset {
    pub id: String,
    #[serde(
        default,
        skip_serializing_if = "crate::contract::PresentationSource::is_empty"
    )]
    pub display: crate::contract::PresentationSource,
    pub unit_entity_id: String,
    pub population: String,
    pub period: CompiledStatisticalPeriod,
    pub dimensions: Vec<CompiledStatisticalDimension>,
    pub disclosure: crate::statistics::DisclosureParameters,
    /// Authentication requirements for every dataset grant, including
    /// release readers which need no entity permission.
    pub access_profiles: BTreeMap<String, AccessProfileSource>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub live_profiles: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases: Option<CompiledStatisticalReleases>,
    pub dependency_entities: BTreeSet<String>,
    pub referenced_fields: BTreeSet<String>,
    pub evaluation_date_dependent: bool,
    pub definition_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CompiledStatisticalPeriod {
    Flow {
        field: String,
        granularity: crate::statistics::PeriodGranularity,
        first_period: String,
    },
    Stock {
        granularity: crate::statistics::PeriodGranularity,
        first_period: String,
        validity: CompiledStatisticalValidity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CompiledStatisticalValidity {
    Temporal { from: String, until: String },
    Fields { from: String, until: Option<String> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledStatisticalDimension {
    pub field: String,
    pub domain: CompiledStatisticalDimensionDomain,
    pub codes: Vec<String>,
    pub include_unknown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CompiledStatisticalDimensionDomain {
    Boolean,
    Vocabulary { vocabulary: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledStatisticalReleases {
    pub publisher: String,
    pub readers: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSourceRelation {
    #[serde(rename = "recordType", alias = "entityId")]
    pub entity_id: String,
    pub sql_name: String,
    pub stored_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSelectorProfile {
    pub id: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledReadPath {
    pub id: String,
    pub through: String,
    pub to: String,
    pub route: String,
    pub source_ref: String,
    pub target_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeControl {
    pub required_for: BTreeSet<Operation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledCurrentDateRelation {
    OnOrAfter,
    OnOrBefore,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledCommitEvidence {
    pub capability: crate::action_evidence_contracts::CompiledEvidenceCapability,
    pub subjects: BTreeMap<String, CompiledCommitEvidenceSubject>,
    pub requires: Vec<CompiledCommitEvidenceRequirement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledCommitEvidenceSubject {
    pub profile: String,
    pub selectors: BTreeMap<String, CompiledCommitEvidenceSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "type")]
pub enum CompiledCommitEvidenceSelector {
    Input { input: String },
    TargetField { input: String, field: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledCommitEvidenceRequirement {
    pub output: String,
    pub expected: CompiledCommitEvidenceExpected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum CompiledCommitEvidenceExpected {
    Literal { value: serde_json::Value },
    FromInput { input: String },
    AtLeast { value: i64 },
    AtMost { value: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanWrite {
    #[serde(rename = "targetRecordType")]
    pub target_entity_id: String,
    pub target_from_input: Option<String>,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub field_types: BTreeMap<String, FieldTypeSource>,
    pub required_fields: BTreeSet<String>,
    pub reference_sources: BTreeMap<String, CompiledPlanReferenceSources>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanReferenceSources {
    pub inputs: BTreeSet<String>,
    pub create_entities: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanFunctionLimits {
    pub maximum_source_bytes: u32,
    pub maximum_operations: u64,
    pub maximum_call_depth: u16,
    pub maximum_expression_depth: u16,
    pub maximum_string_bytes: u32,
    pub maximum_array_items: u16,
    pub maximum_map_entries: u16,
    pub maximum_modules: u16,
    pub maximum_output_bytes: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionInventory {
    pub actions: Vec<CompiledAction>,
    pub routes: Vec<CompiledActionRoute>,
    pub access: Vec<CompiledActionAccessEntry>,
}

impl CompiledActionInventory {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.routes.is_empty() && self.access.is_empty()
    }

    /// Actions with a compiled public route and matching access entry.
    /// Governed internal Actions remain in `actions` for inspection and
    /// trusted execution, but are not callable client contracts.
    pub fn public_actions(&self) -> impl Iterator<Item = &CompiledAction> {
        self.actions.iter().filter(|action| {
            self.routes.iter().any(|route| {
                route.action_id == action.id
                    && self
                        .access
                        .iter()
                        .any(|access| access.route_id == route.id && access.action_id == action.id)
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAction {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::action_evidence_contracts::CompiledEvidenceCapability>,
    pub commit_evidence: Vec<CompiledCommitEvidence>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<CompiledPlanFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    pub route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_route: Option<String>,
    pub inputs: Vec<CompiledActionInput>,
    pub effects: Vec<CompiledPlanEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<CompiledCommitGuard>,
    pub target_uses: Vec<CompiledActionTargetUse>,
    pub permissions: Vec<CompiledActionPermission>,
    pub result_effects: BTreeSet<String>,
    pub maximum_targets: u16,
    pub maximum_field_mutations: u16,
    pub maximum_snapshot_bytes: u32,
    /// Who the action creates consent rows for; absent on every action that
    /// creates none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_issuer: Option<crate::contract::ConsentIssuerSource>,
    pub api_name: String,
    pub display: crate::contract::DisplaySource,
    /// Presentation-only purpose and group; excluded from every execution
    /// identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping: Option<CompiledGrouping>,
    pub execution: CompiledActionExecution,
    pub definition_revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
// This is a bounded, package-loaded policy, not a per-record allocation.
#[allow(clippy::large_enum_variant)]
pub enum CompiledActionExecution {
    Immediate,
    Proposal { proposal: CompiledProposalPolicy },
}
impl CompiledActionExecution {
    pub fn is_proposal(&self) -> bool {
        matches!(self, Self::Proposal { .. })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProposalPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<CompiledProposalHook>,
    pub review: CompiledProposalReview,
    pub application: CompiledProposalApplication,
    pub retention: CompiledProposalRetentionMode,
    pub review_context: Option<crate::contract::ProposalReviewContextSource>,
    pub attachments: BTreeMap<String, CompiledAttachmentSlot>,
    pub permissions: Vec<CompiledProposalPermission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_apply_grant: Option<CompiledSystemApplyGrant>,
}

/// Static package-approved scope for the built-in executor. This definition
/// alone is inert; application intersects it with a frozen submission scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledSystemApplyGrant {
    pub revision: String,
    pub action_id: String,
    pub action_revision: String,
    pub targets: Vec<CompiledSystemApplyTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledSystemApplyTarget {
    #[serde(rename = "recordType")]
    pub entity_id: String,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub read_fields: BTreeSet<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CompiledProposalReview {
    None,
    Required {
        authority: String,
        source: String,
        policy: registry_review_protocol::PolicySelection,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CompiledProposalApplication {
    Manual,
    Automatic { maximum_attempts: u16 },
}
impl Default for CompiledProposalApplication {
    fn default() -> Self {
        Self::Automatic {
            maximum_attempts: 3,
        }
    }
}

impl CompiledProposalApplication {
    pub fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic { .. })
    }
    pub fn maximum_attempts(&self) -> u16 {
        match self {
            Self::Manual => 1,
            Self::Automatic {
                maximum_attempts, ..
            } => *maximum_attempts,
        }
    }
}
pub use crate::contract::{ProposalOperation, ProposalOwnership};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledProposalRetentionMode {
    Retain,
    OperatorErase,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProposalPermission {
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_authority: Option<String>,
    pub default: bool,
    pub actor_kind: Option<crate::contract::ActorKindSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant: Option<crate::contract::TaskGrantSource>,
    pub requester_clients: BTreeSet<String>,
    pub principal_claim: Option<String>,
    pub required_scopes: BTreeSet<String>,
    pub required_purposes: BTreeSet<String>,
    pub operations: BTreeSet<ProposalOperation>,
    pub ownership: Option<ProposalOwnership>,
    pub targets: Vec<CompiledProposalTargetPermission>,
    pub readable_context_fields: BTreeSet<String>,
    #[serde(default)]
    pub readable_inputs: BTreeSet<String>,
    pub readable_attachments: BTreeSet<String>,
    pub writable_attachments: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable_inputs: Option<BTreeSet<String>>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProposalTargetPermission {
    #[serde(rename = "recordType")]
    pub entity_id: String,
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledCommitGuard {
    pub input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "recordType")]
    pub entity_id: String,
    pub field: String,
    #[serde(
        default,
        deserialize_with = "crate::contract::present_json_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub equals: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals_input: Option<String>,
    pub revision_unchanged: bool,
    pub at_least: Option<i64>,
    pub at_most: Option<i64>,
    pub current_date: Option<CompiledCurrentDateRelation>,
    /// Keeps the stored field at or above the named action input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_least_input: Option<String>,
    /// Keeps the stored field at or below the named action input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_most_input: Option<String>,
}

impl CompiledCommitGuard {
    /// The action input this guard compares the stored field with, if any.
    pub fn compared_input(&self) -> Option<&str> {
        self.equals_input
            .as_deref()
            .or(self.at_least_input.as_deref())
            .or(self.at_most_input.as_deref())
    }
}

/// The compiled action-handler backend tag, owned by the handler alone. A
/// build with the `wasm` feature compiles and executes WASM handlers; a build
/// without it refuses them at compile time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledPlanFunctionKind {
    Rhai,
    Wasm,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanFunction {
    pub kind: CompiledPlanFunctionKind,
    pub source_module: Option<String>,
    #[serde(skip)]
    pub script_path: String,
    /// The WASM module path, project-local. Carried for wasm handlers only.
    #[serde(skip)]
    pub module_path: String,
    pub abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rhai_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_sha256: Option<String>,
    #[serde(skip)]
    pub script_bytes: Vec<u8>,
    #[serde(skip)]
    pub module_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<CompiledPlanFunctionLimits>,
    pub writes: Vec<CompiledPlanFunctionWrite>,
    pub refusals: BTreeMap<String, String>,
    pub id: String,
    pub entrypoint: String,
    pub capabilities: BTreeSet<String>,
    pub bound_inputs: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanFunctionWrite {
    pub id: String,
    #[serde(flatten)]
    pub ceiling: CompiledPlanWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionInput {
    pub id: String,
    pub api_name: String,
    pub field_type: FieldTypeSource,
    /// Native PostgreSQL ARE expression a submitted string value must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    pub required: bool,
    pub classification: Classification,
    #[serde(default)]
    pub display: crate::contract::DisplaySource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanEffect {
    pub id: String,
    pub target: CompiledPlanTarget,
    pub operation: Operation,
    pub mutations: Vec<CompiledPlanMutation>,
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledPlanTarget {
    #[serde(rename = "recordType")]
    pub entity_id: String,
    pub binding: CompiledPlanTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum CompiledPlanTargetBinding {
    Create,
    Existing { input: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum CompiledPlanMutation {
    Set {
        field: String,
        value: CompiledPlanValue,
    },
    Clear {
        field: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum CompiledPlanValue {
    Literal {
        value: serde_json::Value,
    },
    FromInput {
        input: String,
    },
    FromEffect {
        effect: String,
        target_entity_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionRouteKind {
    Availability,
    Invoke,
    TargetConditions,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionRoute {
    pub id: String,
    pub action_id: String,
    pub kind: ActionRouteKind,
    pub method: HttpMethod,
    pub path: String,
    pub operation: Operation,
    pub access_profiles: Vec<String>,
    /// Absent when callers must explicitly select among multiple eligible profiles.
    pub default_access_profile: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionAccessEntry {
    pub route_id: String,
    pub action_id: String,
    pub operation: Operation,
    pub profile_ids: BTreeSet<String>,
    pub default_profile_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionPermission {
    pub profile_id: String,
    pub default: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<crate::contract::ActorKindSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_grant: Option<crate::contract::TaskGrantSource>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub requester_clients: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_claim: Option<String>,
    pub required_scopes: BTreeSet<String>,
    pub required_purposes: BTreeSet<String>,
    pub operations: BTreeSet<Operation>,
    pub targets: Vec<CompiledActionTargetPermission>,
    pub results: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionTargetPermission {
    #[serde(rename = "recordType")]
    pub entity_id: String,
    /// The action target operation this permission entry governs.
    pub operation: Operation,
    /// The effect or input that identifies this action target use.
    pub source: CompiledActionTargetUseSource,
    pub row_boundaries: Vec<RowBoundarySource>,
}

impl CompiledActionPermission {
    /// Returns each entity-level authority lock once. Permission targets are
    /// discriminated by action use for authoring and explanation, but runtime
    /// row authority remains one lock per entity.
    pub(crate) fn entity_target_locks(
        &self,
    ) -> impl Iterator<Item = &CompiledActionTargetPermission> {
        self.targets
            .iter()
            .enumerate()
            .filter(|(index, target)| {
                !self.targets[..*index]
                    .iter()
                    .any(|prior| prior.entity_id == target.entity_id)
            })
            .map(|(_, target)| target)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionTargetUse {
    #[serde(rename = "recordType")]
    pub entity_id: String,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub source: CompiledActionTargetUseSource,
    pub condition_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case", tag = "kind")]
pub enum CompiledActionTargetUseSource {
    Effect { effect: String },
    Input { input: String },
}

/// Resolved stored columns and decision sets of one consent-record entity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledConsentRecord {
    pub subject_column: String,
    pub recipient_column: String,
    pub purpose_column: String,
    pub scope_column: String,
    /// The logical decision field, bound by the recipient feed's decision set.
    pub decision_field: String,
    pub decision_column: String,
    pub from_column: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_column: Option<String>,
    pub gives: BTreeSet<String>,
    pub revokes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub refusals: BTreeSet<String>,
    /// The longest a give lasts, in whole days of 24 hours.
    pub maximum_duration_days: u32,
}

impl CompiledConsentRecord {
    /// The decisions a recipient may see: every give and every revoke that is
    /// not a refusal.
    pub fn feed_decisions(&self) -> BTreeSet<String> {
        self.gives
            .iter()
            .chain(self.revokes.difference(&self.refusals))
            .cloned()
            .collect()
    }
}

/// One consent check of one gated profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledConsentRequirement {
    /// The consent-record entity.
    pub record: String,
    /// The protected entity's field the consent subject references; `id` is
    /// the row's own identity.
    pub on: String,
}

/// Declared consent recipients and the recipient set of each client.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRecipients {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organizations: Vec<RecipientOrganizationSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<RecipientGroupSource>,
}

impl CompiledRecipients {
    pub fn is_empty(&self) -> bool {
        self.organizations.is_empty() && self.groups.is_empty()
    }

    /// Every client an organization acts through.
    pub fn clients(&self) -> impl Iterator<Item = &str> {
        self.organizations
            .iter()
            .flat_map(|organization| organization.clients.iter().map(String::as_str))
    }

    /// The organization a client acts for plus every group containing it.
    /// Empty for a client no organization lists, so every consent check of
    /// that caller fails closed.
    pub fn recipient_set(&self, client: &str) -> BTreeSet<String> {
        let Some(organization) = self
            .organizations
            .iter()
            .find(|organization| organization.clients.iter().any(|id| id == client))
        else {
            return BTreeSet::new();
        };
        std::iter::once(organization.id.clone())
            .chain(
                self.groups
                    .iter()
                    .filter(|group| group.members.contains(&organization.id))
                    .map(|group| group.id.clone()),
            )
            .collect()
    }
}

/// Resolved stored-column inputs for one current membership predicate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMembershipBoundary {
    pub field: String,
    #[serde(rename = "membershipRecordType")]
    pub membership_entity: String,
    pub membership_table: String,
    pub membership_key_column: String,
    pub principal_column: String,
    pub active_column: String,
}

/// Member-id prefix of the compiler-owned index on a reference column in
/// [`CompiledEntity::indexes`]. Authored index ids cannot contain `:`.
pub const REFERENCE_INDEX_PREFIX: &str = "reference:";

/// Whether an index or a whole-table unique constraint leads with `field`,
/// so an equality match or an ordered scan on it can use a btree index. A
/// partial unique index covers only the rows its predicate admits.
pub(crate) fn leading_field_indexed(
    field: &str,
    indexes: &BTreeMap<String, Vec<String>>,
    constraints: &BTreeMap<String, crate::contract::ConstraintSource>,
) -> bool {
    indexes
        .values()
        .any(|fields| fields.first().is_some_and(|first| first == field))
        || constraints.values().any(|constraint| {
            matches!(
                constraint,
                crate::contract::ConstraintSource::Unique { fields, when: None, .. }
                    if fields.first().is_some_and(|first| first == field)
            )
        })
}

/// Whether a list read path can use an index leading with `field`. Beyond
/// [`leading_field_indexed`], a unique constraint scoped to exactly
/// `when: [active-lifecycle]` counts on an entity without a change request,
/// because every select policy there already requires
/// `record_lifecycle = 'active'`. A change request's select policy also
/// admits tombstoned rows, and a reference index needs whole-table coverage
/// for foreign-key checks, so neither may use this.
pub(crate) fn leading_field_indexed_for_list_finding(
    field: &str,
    indexes: &BTreeMap<String, Vec<String>>,
    constraints: &BTreeMap<String, crate::contract::ConstraintSource>,
) -> bool {
    leading_field_indexed(field, indexes, constraints)
        || constraints.values().any(|constraint| {
            matches!(
                constraint,
                crate::contract::ConstraintSource::Unique { fields, when: Some(when), .. }
                    if fields.first().is_some_and(|first| first == field)
                        && when.as_slice()
                            == [crate::contract::UniqueWhenPredicate::ActiveLifecycle {}]
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEntity {
    pub id: String,
    /// The module that declared this entity. Absent means the project root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_dataset: Option<String>,
    pub route: String,
    pub mutation_mode: MutationMode,
    pub tombstone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchSource>,
    pub classification: Classification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_requirements: Option<crate::contract::AccessRequirementsSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<AccessLogSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geojson: Option<CompiledGeoJsonBinding>,
    pub physical_table: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<CompiledTemporal>,
    pub canonical_id: CompiledLogicalField,
    pub stored_fields: Vec<CompiledStoredField>,
    pub derived_fields: BTreeMap<String, CompiledDerivedField>,
    pub derived_relations: BTreeMap<String, CompiledDerivedRelation>,
    pub source_relation: CompiledSourceRelation,
    pub selector_profiles: BTreeMap<String, CompiledSelectorProfile>,
    /// Root-enabled autonomous timers keyed by their stable identifier.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub timers: BTreeMap<String, CompiledTimer>,
    pub read_paths: BTreeMap<String, CompiledReadPath>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relationships: BTreeMap<String, CompiledRelationship>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_control: Option<CompiledChangeControl>,
    pub fields: BTreeMap<String, CompiledField>,
    pub constraints: BTreeMap<String, ConstraintSource>,
    pub indexes: BTreeMap<String, Vec<String>>,
    pub access_profiles: BTreeMap<String, AccessProfileSource>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub membership_boundaries: BTreeMap<String, Vec<CompiledMembershipBoundary>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_record: Option<CompiledConsentRecord>,
    /// The consent checks of each gated profile, ANDed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub consent_requirements: BTreeMap<String, Vec<CompiledConsentRequirement>>,
    pub hooks: BTreeMap<String, HookSource>,
    /// Which module contributed each id in this entity's id-keyed
    /// collections. An id absent from a map was contributed by the project
    /// root. Two modules can never declare the same id (every level is a
    /// compile error), so this is exactly one contributing module per id,
    /// never a list.
    #[serde(default, skip_serializing_if = "CompiledEntityModuleOrigins::is_empty")]
    pub module_origins: CompiledEntityModuleOrigins,
    pub api_name: String,
    pub display: crate::contract::DisplaySource,
    /// Presentation-only purpose and group; excluded from every execution
    /// identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grouping: Option<CompiledGrouping>,
    /// The resolved event record descriptor; excluded from every execution
    /// identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_record: Option<CompiledEventRecord>,
    pub definition_revision: String,
}

/// The authored purpose and group of a Record or Action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledGrouping {
    pub purpose: Option<crate::contract::DisplayPurpose>,
    pub group: Option<String>,
}

/// The descriptor version this compiler emits.
pub const EVENT_RECORD_DESCRIPTOR_VERSION: u64 = 1;

/// A record type's event record mapping with every field resolved once. The
/// serialized form is the descriptor shown in the model explanation; runtime
/// metadata filters it per caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventRecord {
    pub descriptor_version: u64,
    pub label: String,
    pub subjects: Vec<CompiledEventRecordRole>,
    pub summary: Option<CompiledEventRecordField>,
    pub occurred_at: Option<CompiledEventRecordTime>,
    pub effective: Option<CompiledEventRecordTime>,
    pub sources: Vec<CompiledEventRecordRole>,
    pub correction: Option<CompiledEventRecordCorrection>,
    pub source_event_id: Option<CompiledSourceEventId>,
    pub recorded_time: CompiledRecordedTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventRecordRole {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub kind: EventRecordRoleKind,
    /// The namespace of an external identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub field: CompiledEventRecordField,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventRecordRoleKind {
    /// A reference to a record of this registry.
    Native,
    /// An opaque identifier owned by another system; never resolved.
    External,
}

/// A stored field named by id and by its API name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventRecordField {
    pub id: String,
    pub api_name: String,
    #[serde(rename = "type")]
    pub value_type: EventRecordValueType,
    /// The record type a `reference` field points at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// The field types an event record role can map.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventRecordValueType {
    Reference,
    String,
    Text,
    Date,
    Timestamp,
    Uuid,
    VocabularyCode,
}

impl EventRecordValueType {
    /// The field type's kebab-case name, as authored.
    pub fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::String => "string",
            Self::Text => "text",
            Self::Date => "date",
            Self::Timestamp => "timestamp",
            Self::Uuid => "uuid",
            Self::VocabularyCode => "vocabulary-code",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CompiledEventRecordTime {
    Point {
        at: CompiledEventRecordField,
    },
    Interval {
        meaning: crate::contract::IntervalMeaning,
        start: CompiledEventRecordField,
        /// Absent for an open-ended span.
        end: Option<CompiledEventRecordField>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventRecordCorrection {
    pub relation: crate::contract::CorrectionRelation,
    pub field: CompiledEventRecordField,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSourceEventId {
    pub field: CompiledEventRecordField,
    pub namespace: Option<String>,
    pub namespace_field: Option<CompiledEventRecordField>,
    pub duplicates: crate::contract::DuplicatePolicy,
    pub constraint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRecordedTime {
    pub source: RecordedTimeSource,
}

/// Recorded time is never authored; it is read from native record history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordedTimeSource {
    /// The creation time of the record's first revision.
    CreationRevision,
}

impl CompiledEntity {
    /// The fields whose values the server generates on create.
    pub fn generated_fields(&self) -> impl Iterator<Item = &CompiledField> {
        self.fields
            .values()
            .filter(|field| field.generate.is_some())
    }

    /// Generated values and every field that partitions their namespace are
    /// immutable after create. Action compilation, Proposal preparation, and
    /// direct mutation admission share this predicate so work cannot freeze
    /// only to fail later at apply.
    pub fn is_generated_identifier_immutable(&self, field_id: &str) -> bool {
        self.fields
            .get(field_id)
            .is_some_and(|field| field.generate.is_some())
            || self.generated_fields().any(|field| {
                field.generate.as_ref().is_some_and(|generation| {
                    generation.scope.iter().any(|scope| scope == field_id)
                })
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRelationship {
    pub name: String,
    #[serde(rename = "sourceRecordType")]
    pub source_entity_id: String,
    #[serde(rename = "targetRecordType")]
    pub target_entity_id: String,
    pub field_id: String,
    pub cardinality: RelationshipCardinality,
    pub inverse: bool,
    pub inverse_name: Option<String>,
    pub read_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationshipCardinality {
    One,
    OptionalOne,
    Many,
}

/// Per-collection module provenance for one [`CompiledEntity`]. See
/// [`CompiledEntity::module_origins`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEntityModuleOrigins {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hooks: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub derived_relations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub indexes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub access_profiles: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selector_profiles: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub timers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub read_paths: BTreeMap<String, String>,
}

impl CompiledEntityModuleOrigins {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
            && self.constraints.is_empty()
            && self.hooks.is_empty()
            && self.derived_relations.is_empty()
            && self.indexes.is_empty()
            && self.access_profiles.is_empty()
            && self.selector_profiles.is_empty()
            && self.timers.is_empty()
            && self.read_paths.is_empty()
    }
}

/// One root-enabled Record timer with its complete current-policy authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTimer {
    #[serde(rename = "recordType")]
    pub record_type: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rearm_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<CompiledTimerPredicate>,
    pub invoke: String,
    pub input: BTreeMap<String, CompiledTimerInput>,
    /// Fields whose material tuple creates, supersedes, or cancels a generation.
    pub control_fields: BTreeSet<String>,
    /// Current fields that hold or release an unfinished generation without
    /// changing its business identity.
    pub predicate_fields: BTreeSet<String>,
    /// Current stored facts whose values shape a pending execution without rearming it.
    pub effect_input_fields: BTreeSet<String>,
    pub action_revision: String,
    pub system_grant: CompiledSystemApplyGrant,
    /// Compiled delivery identifiers whose definitions are covered by this
    /// timer revision because the invoked Action may produce their trigger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_deliveries: Vec<String>,
    pub definition_revision: String,
}

/// Typed conjunction over the locked current anchor image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTimerPredicate {
    pub equals: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub timestamp_fields: BTreeSet<String>,
}

impl CompiledTimerPredicate {
    /// A missing or unequal current field holds the same pending generation.
    #[must_use]
    pub fn matches(&self, record: &serde_json::Map<String, serde_json::Value>) -> bool {
        self.equals.iter().all(|(field, expected)| {
            let Some(actual) = record.get(field) else {
                return false;
            };
            if !self.timestamp_fields.contains(field) {
                return actual == expected;
            }
            let (Some(actual), Some(expected)) = (actual.as_str(), expected.as_str()) else {
                return false;
            };
            match (
                crate::contract::postgres_timestamp_micros(actual),
                crate::contract::postgres_timestamp_micros(expected),
            ) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            }
        })
    }
}

/// One complete value mapping into an ordinary Action input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CompiledTimerInput {
    RecordId,
    Field { field: String },
    Timer { value: CompiledTimerValue },
    Literal { value: serde_json::Value },
}

/// Runtime-owned facts supplied by the timer executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledTimerValue {
    OccurrenceId,
    DueAt,
}

/// Governed catalogue projection with every resource reference resolved once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestProjection {
    pub canonical_base_iri: String,
    pub access_profile: String,
    pub classification_ceiling: Classification,
    pub catalog: ManifestProjectionCatalogSource,
    pub primary_authority: CompiledManifestAuthority,
    pub public_service: CompiledManifestPublicService,
    pub datasets: BTreeMap<String, CompiledManifestDataset>,
    pub data_services: BTreeMap<String, CompiledManifestDataService>,
    pub distributions: BTreeMap<String, CompiledManifestDistribution>,
    pub entity_datasets: BTreeMap<String, String>,
    pub entities: Vec<ManifestProjectionEntitySource>,
    pub vocabularies: Vec<ManifestProjectionVocabularySource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestAuthority {
    pub id: String,
    pub iri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestPublicService {
    pub source: ManifestProjectionPublicServiceSource,
    pub iri: String,
    pub competent_authority: String,
    pub produces: BTreeSet<String>,
    pub data_services: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestDataset {
    pub source: ManifestProjectionDatasetSource,
    pub iri: String,
    pub effective_access_profile: String,
    pub effective_classification_ceiling: Classification,
    pub entities: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestDataService {
    pub source: ManifestProjectionDataServiceSource,
    pub iri: String,
    pub serves_datasets: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledManifestDistribution {
    pub source: ManifestProjectionDistributionSource,
    pub iri: String,
    pub dataset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_service: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledGeoJsonBinding {
    pub geometry_field: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledTemporal {
    pub start_field: String,
    pub end_field: String,
}

impl From<TemporalSource> for CompiledTemporal {
    fn from(source: TemporalSource) -> Self {
        Self {
            start_field: source.start_field,
            end_field: source.end_field,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Delete,
    Get,
    Patch,
    Post,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRoute {
    pub id: String,
    #[serde(rename = "recordType", alias = "entityId")]
    pub entity_id: String,
    pub method: HttpMethod,
    pub path: String,
    pub operation: Operation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_kind: Option<CompiledQueryKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_kind: Option<CompiledRevisionKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_records: Option<u16>,
    pub access_profiles: Vec<String>,
    /// Absent when callers must explicitly select among multiple eligible profiles.
    pub default_access_profile: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRouteInventory {
    pub routes: Vec<CompiledRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventDelivery {
    pub id: String,
    pub owner: CompiledEventOwner,
    pub event_id: String,
    /// The bound destination this delivery is sent to. Present for the `url`
    /// handler kind and absent for a local kind, which is sent nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_id: Option<String>,
    /// The reviewed program this delivery runs in the post-commit worker.
    /// Present for the `rhai` and `wasm` handler kinds and absent for `url`,
    /// which holds no program. Exactly one of this and `destination_id` is
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<CompiledHookHandler>,
    pub projection_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<EventConditionSource>,
    /// The access profile a proposal from this hook is applied under, carried
    /// opaquely from the declaration. Absent for a non-proposing hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    pub classification_ceiling: Classification,
    pub data_schema: String,
    pub data_schema_fingerprint: String,
    pub data_schema_artifact_path: String,
    pub authentication_profile: HookAuthenticationProfile,
    pub delivery_mode: CompiledHookDeliveryMode,
    pub retry_profile: CompiledHookRetryProfile,
    pub attempt_timeout_ms: u32,
    pub initial_backoff_ms: u32,
    pub maximum_backoff_ms: u32,
    /// Fixed V1 exponential multiplier. Runtime configuration may only tighten
    /// the resulting delays.
    pub exponential_backoff_multiplier: u8,
    pub maximum_attempts: u8,
    pub retry_delays_ms: Vec<u32>,
    /// Compiler-proved upper bound for the canonical projected JSON body.
    pub maximum_payload_bytes: u32,
    pub dead_letter: HookDeadLetterMode,
    pub operator_replay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CompiledEventOwner {
    RecordType {
        record_type: String,
        trigger: crate::contract::EventTrigger,
    },
    ProposalAction {
        action: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledProposalHook {
    pub id: String,
    #[serde(
        default,
        skip_serializing_if = "crate::contract::PresentationSource::is_empty"
    )]
    pub display: crate::contract::PresentationSource,
    pub transitions: BTreeSet<crate::contract::ProposalEventTransition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler: Option<CompiledHookHandler>,
}

impl CompiledEventDelivery {
    /// The handler kind this delivery binds, read from the one of the two
    /// bindings it carries.
    #[must_use]
    pub fn handler_kind(&self) -> HookHandlerKind {
        self.handler
            .as_ref()
            .map_or(HookHandlerKind::Url, |handler| handler.kind.shared())
    }

    /// The delivery row's handler identity digest: the destination binding
    /// digest for the `url` kind, and the reviewed program's digest for a
    /// local kind.
    #[must_use]
    pub fn handler_digest(&self) -> Option<&str> {
        self.handler.as_ref().map(|handler| handler.digest.as_str())
    }
}

/// The compiled backend tag of a local hook handler. The engine holds the
/// reviewed program and runs it in the post-commit worker, so a local kind
/// binds no destination and sends nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledHookHandlerKind {
    Rhai,
    Wasm,
}

impl CompiledHookHandlerKind {
    /// The shared handler-kind spelling the delivery row stores.
    #[must_use]
    pub const fn shared(self) -> HookHandlerKind {
        match self {
            Self::Rhai => HookHandlerKind::Rhai,
            Self::Wasm => HookHandlerKind::Wasm,
        }
    }
}

/// The reviewed local program one hook delivery runs.
///
/// `digest` is the delivery row's handler identity. A retained delivery runs
/// exactly the program it was captured under, or it is refused: the worker
/// compares this value against the digest the row recorded, the way it
/// compares a destination's binding digest for the `url` kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledHookHandler {
    pub kind: CompiledHookHandlerKind,
    pub abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    /// The script or module path, project-local.
    #[serde(skip)]
    pub source_path: String,
    /// `sha256:<hex>` over the reviewed bytes.
    pub digest: String,
    /// The reviewed bytes, rederived when the package is loaded.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledHookDeliveryMode {
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledHookRetryProfile {
    RegistryV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEventDeliveryInventory {
    pub deliveries: Vec<CompiledEventDelivery>,
}

/// Conservative, non-pageable bound for one record's newest revision entries.
pub const MAX_REVISION_HISTORY_RECORDS: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledRevisionKind {
    List,
    Detail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessEntry {
    #[serde(default)]
    pub route_id: String,
    #[serde(rename = "recordType", alias = "entityId")]
    pub entity_id: String,
    pub operation: Operation,
    pub profile_ids: BTreeSet<String>,
    pub default_profile_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessInventory {
    pub entries: Vec<CompiledAccessEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataEntry {
    pub route_id: String,
    pub operation: Operation,
    pub access_profile: String,
    #[serde(rename = "responseRecordType")]
    pub response_entity_id: String,
    pub readable_fields: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_fields: Vec<ProvenanceFieldSource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataEntity {
    pub id: String,
    pub route: String,
    pub schema_path: String,
    pub entries: Vec<CompiledMetadataEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledMetadataInventory {
    pub registry_id: String,
    pub version: String,
    #[serde(rename = "recordTypes")]
    pub entities: Vec<CompiledMetadataEntity>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledQueryKind {
    List,
    Current,
    AsOf,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledQueryFilterOperator {
    Equals,
    In,
    Range,
    IsNull,
    IsNotNull,
    Prefix,
    Contains,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledQuerySortDirection {
    Asc,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryFilterField {
    pub field: String,
    pub operators: Vec<CompiledQueryFilterOperator>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQuerySortField {
    pub field: String,
    pub directions: Vec<CompiledQuerySortDirection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryTemporalBinding {
    pub start_field: String,
    pub end_field: String,
    pub value_kind: CompiledQueryTemporalValueKind,
    pub semantics: CompiledQueryTemporalSemantics,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledQueryTemporalValueKind {
    Date,
    Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompiledQueryTemporalSemantics {
    StartInclusiveEndExclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryOperation {
    pub id: String,
    pub route_id: String,
    #[serde(rename = "recordType", alias = "entityId")]
    pub entity_id: String,
    pub profile_id: String,
    pub kind: CompiledQueryKind,
    pub max_page_size: u16,
    pub projection_fields: Vec<String>,
    pub filter_fields: Vec<CompiledQueryFilterField>,
    pub sort_fields: Vec<CompiledQuerySortField>,
    #[serde(default)]
    pub allow_count: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processing_fields: Vec<String>,
    pub stable_tie_breaker: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spatial: Option<CompiledSpatialQueryCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal: Option<CompiledQueryTemporalBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSpatialQueryCapability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbox: Option<CompiledBboxQueryCapability>,
}

impl CompiledQueryOperation {
    /// Stable QGIS collection identity for one direct spatial grant. Logical
    /// identifiers cannot contain dots, so the entity/profile pair is unambiguous.
    pub fn gis_collection_id(&self) -> Option<String> {
        (self.kind == CompiledQueryKind::List
            && self.read_path.is_none()
            && self
                .spatial
                .as_ref()
                .and_then(|spatial| spatial.bbox.as_ref())
                .is_some())
        .then(|| format!("{}.{}", self.entity_id, self.profile_id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledBboxQueryCapability {
    pub geometry_field: String,
    pub maximum_longitude_span_degrees: serde_json::Number,
    pub maximum_latitude_span_degrees: serde_json::Number,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryInventory {
    pub operations: Vec<CompiledQueryOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledModuleIdentity {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Presentation of a project access profile, including profiles with no grants.
/// The identifier remains the sole identity used by authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessProfileDisplay {
    pub id: String,
    pub display: crate::contract::PresentationSource,
}

/// Immutable result consumed by runtime, migration, and authoring surfaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistry {
    registry_id: String,
    version: String,
    default_language: String,
    #[serde(default, skip_serializing_if = "display_is_empty")]
    display: crate::contract::DisplaySource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    review_authorities: Vec<crate::contract::ReviewAuthoritySource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    datasets: Vec<crate::contract::DatasetSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    access_profile_displays: Vec<CompiledAccessProfileDisplay>,
    package: Option<PackageIdentitySource>,
    manifest_projection: Option<CompiledManifestProjection>,
    module_order: Vec<String>,
    module_closure: Vec<CompiledModuleIdentity>,
    entities: BTreeMap<String, CompiledEntity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    statistical_datasets: BTreeMap<String, CompiledStatisticalDataset>,
    physical_names: PhysicalNameInventory,
    action_inventory: CompiledActionInventory,
    route_inventory: CompiledRouteInventory,
    access_inventory: CompiledAccessInventory,
    metadata_inventory: CompiledMetadataInventory,
    query_inventory: CompiledQueryInventory,
    event_delivery_inventory: CompiledEventDeliveryInventory,
    #[serde(default, skip_serializing_if = "CompiledRecipients::is_empty")]
    recipients: CompiledRecipients,
    ddl: DdlInventory,
    artifacts: GeneratedArtifacts,
    findings: Vec<Diagnostic>,
    revision: String,
}

impl CompiledRegistry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry_id: String,
        version: String,
        default_language: String,
        display: crate::contract::DisplaySource,
        review_authorities: Vec<crate::contract::ReviewAuthoritySource>,
        datasets: Vec<crate::contract::DatasetSource>,
        access_profile_displays: Vec<CompiledAccessProfileDisplay>,
        package: Option<PackageIdentitySource>,
        manifest_projection: Option<CompiledManifestProjection>,
        module_order: Vec<String>,
        module_closure: Vec<CompiledModuleIdentity>,
        entities: BTreeMap<String, CompiledEntity>,
        statistical_datasets: BTreeMap<String, CompiledStatisticalDataset>,
        physical_names: PhysicalNameInventory,
        action_inventory: CompiledActionInventory,
        route_inventory: CompiledRouteInventory,
        access_inventory: CompiledAccessInventory,
        metadata_inventory: CompiledMetadataInventory,
        query_inventory: CompiledQueryInventory,
        event_delivery_inventory: CompiledEventDeliveryInventory,
        recipients: CompiledRecipients,
        ddl: DdlInventory,
        artifacts: GeneratedArtifacts,
        findings: Vec<Diagnostic>,
        revision: String,
    ) -> Self {
        Self {
            registry_id,
            version,
            default_language,
            display,
            review_authorities,
            datasets,
            access_profile_displays,
            package,
            manifest_projection,
            module_order,
            module_closure,
            entities,
            statistical_datasets,
            physical_names,
            action_inventory,
            route_inventory,
            access_inventory,
            metadata_inventory,
            query_inventory,
            event_delivery_inventory,
            recipients,
            ddl,
            artifacts,
            findings,
            revision,
        }
    }

    /// This registry with the schema-bearing inventories of a retained
    /// migration baseline: its entities, physical names, actions, and the DDL
    /// this generator emits for them. A successor plan is computed from the
    /// baseline, so this is the schema the plan runs over, even when the
    /// predecessor's sources compile to more engine-owned objects under this
    /// compiler.
    #[cfg(all(feature = "runtime", feature = "tooling"))]
    pub fn with_migration_baseline_schema(
        &self,
        baseline: &crate::package::CompiledRegistryMigrationBaseline,
    ) -> Self {
        Self {
            entities: baseline.entities.clone(),
            physical_names: baseline.physical_names.clone(),
            action_inventory: baseline.actions.clone(),
            ddl: crate::generated_ddl::generate_ddl_with_actions(
                &baseline.entities,
                &baseline.physical_names,
                &baseline.actions,
            ),
            ..self.clone()
        }
    }

    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn display(&self) -> &crate::contract::DisplaySource {
        &self.display
    }

    pub fn review_authorities(&self) -> &[crate::contract::ReviewAuthoritySource] {
        &self.review_authorities
    }

    pub fn datasets(&self) -> &[crate::contract::DatasetSource] {
        &self.datasets
    }

    pub fn access_profile_displays(&self) -> &[CompiledAccessProfileDisplay] {
        &self.access_profile_displays
    }

    pub fn package(&self) -> Option<&PackageIdentitySource> {
        self.package.as_ref()
    }

    pub fn manifest_projection(&self) -> Option<&CompiledManifestProjection> {
        self.manifest_projection.as_ref()
    }

    pub fn module_order(&self) -> &[String] {
        &self.module_order
    }

    pub fn module_closure(&self) -> &[CompiledModuleIdentity] {
        &self.module_closure
    }

    pub fn entities(&self) -> &BTreeMap<String, CompiledEntity> {
        &self.entities
    }

    /// Every enabled timer in stable Record-type and timer-id order.
    pub fn timers(&self) -> impl Iterator<Item = (&str, &CompiledTimer)> {
        self.entities.iter().flat_map(|(record_type, entity)| {
            entity
                .timers
                .values()
                .map(move |timer| (record_type.as_str(), timer))
        })
    }

    pub fn statistical_datasets(&self) -> &BTreeMap<String, CompiledStatisticalDataset> {
        &self.statistical_datasets
    }

    pub fn physical_names(&self) -> &PhysicalNameInventory {
        &self.physical_names
    }

    pub fn actions(&self) -> &CompiledActionInventory {
        &self.action_inventory
    }

    pub fn routes(&self) -> &CompiledRouteInventory {
        &self.route_inventory
    }

    pub fn access(&self) -> &CompiledAccessInventory {
        &self.access_inventory
    }

    pub fn metadata(&self) -> &CompiledMetadataInventory {
        &self.metadata_inventory
    }

    pub fn queries(&self) -> &CompiledQueryInventory {
        &self.query_inventory
    }

    pub fn event_deliveries(&self) -> &CompiledEventDeliveryInventory {
        &self.event_delivery_inventory
    }

    pub fn recipients(&self) -> &CompiledRecipients {
        &self.recipients
    }

    pub fn ddl(&self) -> &DdlInventory {
        &self.ddl
    }

    pub fn artifacts(&self) -> &GeneratedArtifacts {
        &self.artifacts
    }

    pub fn findings(&self) -> &[Diagnostic] {
        &self.findings
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }
}

pub(crate) fn display_is_empty(display: &crate::contract::DisplaySource) -> bool {
    display.label.is_none() && display.description.is_none() && display.title_field.is_none()
}
