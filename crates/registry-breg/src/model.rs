// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_hooks::HookHandlerKind;
use serde::{Deserialize, Serialize};

use crate::artifacts::GeneratedArtifacts;
use crate::contract::{
    AccessProfileSource, BatchSource, Classification, ConstraintSource, EventConditionSource,
    FieldTypeSource, HookSource, ManifestProjectionCatalogSource,
    ManifestProjectionDataServiceSource, ManifestProjectionDatasetSource,
    ManifestProjectionDistributionSource, ManifestProjectionEntitySource,
    ManifestProjectionPublicServiceSource, ManifestProjectionVocabularySource, MutationMode,
    NormalizationStep, Operation, PackageIdentitySource, ProvenanceFieldSource,
    RecipientGroupSource, RecipientOrganizationSource, RowBoundarySource, TemporalSource,
    ValidTimeRole, WebhookAuthenticationProfile, WebhookDeadLetterMode,
};
use crate::diagnostics::Diagnostic;
use crate::generated_ddl::DdlInventory;
use crate::physical_names::PhysicalNameInventory;

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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledSourceRelation {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequest {
    pub request_entity_id: String,
    pub contract_fingerprint: String,
    pub retention_mode: CompiledChangeRequestRetentionMode,
    pub review: CompiledChangeRequestReview,
    pub on_approved: CompiledChangeRequestOnApproved,
    #[serde(
        default,
        skip_serializing_if = "CompiledChangeRequestApplication::is_empty"
    )]
    pub application: CompiledChangeRequestApplication,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner: Option<CompiledChangeRequestPlanner>,
    pub effects: Vec<CompiledChangeRequestEffect>,
    pub actions: Vec<CompiledChangeRequestActionRoute>,
    pub apply_permissions: Vec<CompiledChangeRequestApplyPermission>,
    pub presence_permissions: Vec<CompiledChangeRequestPresencePermission>,
    pub target_entities: BTreeSet<String>,
    pub maximum_targets: u16,
    pub maximum_field_mutations: u16,
    pub maximum_snapshot_bytes: u32,
}

impl CompiledChangeRequest {
    /// Records needed for applying effects or checking frozen guards. Request-self
    /// attachment permissions do not create additional lifecycle target authority.
    pub(crate) fn application_target_entities(&self) -> BTreeSet<String> {
        self.target_entities
            .iter()
            .cloned()
            .chain(
                self.application
                    .preconditions
                    .targets
                    .iter()
                    .map(|target| target.entity_id.clone()),
            )
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompiledChangeRequestReview {
    Required(CompiledChangeRequestReviewRequirement),
    None(CompiledChangeRequestNoReview),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestReviewRequirement {
    pub authority: String,
    pub policy_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestNoReview {
    pub mode: CompiledChangeRequestNoReviewMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledChangeRequestNoReviewMode {
    None,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestOnApproved {
    pub mode: CompiledChangeRequestOnApprovedMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledChangeRequestOnApprovedMode {
    #[default]
    Manual,
    Automatic,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestApplication {
    #[serde(
        default,
        skip_serializing_if = "CompiledChangeRequestPreconditions::is_empty"
    )]
    pub preconditions: CompiledChangeRequestPreconditions,
}

impl CompiledChangeRequestApplication {
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPreconditions {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request: Vec<CompiledChangeRequestPredicate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<CompiledChangeRequestGuardTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<CompiledChangeRequestEvidence>,
}

impl CompiledChangeRequestPreconditions {
    pub fn is_empty(&self) -> bool {
        self.request.is_empty() && self.targets.is_empty() && self.evidence.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestGuardTarget {
    pub id: String,
    pub entity_id: String,
    pub from_field: String,
    pub requires: Vec<CompiledChangeRequestPredicate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPredicate {
    pub field: String,
    pub expected: CompiledChangeRequestPredicateExpected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum CompiledChangeRequestPredicateExpected {
    Literal {
        value: serde_json::Value,
    },
    RequestField {
        field: String,
    },
    CurrentDate {
        relation: CompiledCurrentDateRelation,
    },
    AtLeast {
        value: i64,
    },
    AtMost {
        value: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledCurrentDateRelation {
    OnOrAfter,
    OnOrBefore,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestEvidence {
    pub capability: crate::action_evidence_contracts::CompiledEvidenceCapability,
    pub subjects: BTreeMap<String, CompiledChangeRequestEvidenceSubject>,
    pub requires: Vec<CompiledChangeRequestEvidenceRequirement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestEvidenceSubject {
    pub profile: String,
    pub selectors: BTreeMap<String, CompiledChangeRequestSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "source")]
pub enum CompiledChangeRequestSelector {
    RequestField { field: String },
    TargetField { target: String, field: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestEvidenceRequirement {
    pub output: String,
    pub expected: CompiledChangeRequestEvidenceExpected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum CompiledChangeRequestEvidenceExpected {
    Literal { value: serde_json::Value },
    RequestField { field: String },
    AtLeast { value: i64 },
    AtMost { value: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPlanner {
    pub kind: CompiledChangeRequestPlannerKind,
    pub source_module: Option<String>,
    #[serde(skip)]
    pub script_path: String,
    pub abi: String,
    pub rhai_version: String,
    pub script_sha256: String,
    #[serde(skip)]
    pub script_bytes: Vec<u8>,
    pub limits: CompiledChangeRequestPlannerLimits,
    pub request_fields: Vec<String>,
    pub writes: Vec<CompiledChangeRequestPlannerWrite>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledChangeRequestPlannerKind {
    Rhai,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPlannerWrite {
    pub target_entity_id: String,
    pub target_from_field: Option<String>,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub field_types: BTreeMap<String, FieldTypeSource>,
    pub required_fields: BTreeSet<String>,
    pub reference_sources: BTreeMap<String, CompiledChangeRequestReferenceSources>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestReferenceSources {
    pub request_fields: BTreeSet<String>,
    pub create_entities: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPlannerLimits {
    pub maximum_source_bytes: u32,
    pub maximum_operations: u64,
    pub maximum_call_depth: u16,
    pub maximum_expression_depth: u16,
    pub maximum_string_bytes: u32,
    pub maximum_array_items: u16,
    pub maximum_map_entries: u16,
    pub maximum_modules: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledChangeRequestRetentionMode {
    #[default]
    Retain,
    OperatorErase,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestEffect {
    pub id: String,
    pub target: CompiledChangeRequestTarget,
    pub operation: Operation,
    pub mutations: Vec<CompiledChangeRequestMutation>,
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestTarget {
    pub entity_id: String,
    pub binding: CompiledChangeRequestTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestTargetBinding {
    Existing { from_field: String },
    ReservedCreate { effect: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestMutation {
    Set {
        field: String,
        value: CompiledChangeRequestValue,
    },
    Clear {
        field: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledChangeRequestValue {
    FromField {
        field: String,
    },
    FromEffect {
        effect: String,
        target_entity_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestOperation {
    SubmitRequest,
    ReviseRequest,
    CancelRequest,
    ApplyRequest,
}

impl ChangeRequestOperation {
    pub fn access_operation(self) -> Operation {
        match self {
            Self::SubmitRequest => Operation::SubmitRequest,
            Self::ReviseRequest => Operation::ReviseRequest,
            Self::CancelRequest => Operation::CancelRequest,
            Self::ApplyRequest => Operation::ApplyRequest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestActionRoute {
    pub operation: ChangeRequestOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestApplyPermission {
    pub profile_id: String,
    pub target_entity_id: String,
    pub row_boundaries: Vec<RowBoundarySource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledChangeRequestPresencePermission {
    pub profile_id: String,
    pub target_entity_id: String,
    pub request_row_boundaries: Vec<RowBoundarySource>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionInventory {
    pub actions: Vec<CompiledAction>,
    pub routes: Vec<CompiledActionRoute>,
    pub access: Vec<CompiledActionAccessEntry>,
    /// Every code of each vocabulary an action input is bound to, including
    /// codes no input accepts. A successor compares them to tell a code new to
    /// its vocabulary from one an input only started accepting.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub input_vocabularies: BTreeMap<String, BTreeSet<String>>,
}

impl CompiledActionInventory {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.routes.is_empty() && self.access.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAction {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::action_evidence_contracts::CompiledEvidenceCapability>,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<CompiledActionHandler>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_module: Option<String>,
    pub route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_route: Option<String>,
    pub contract_fingerprint: String,
    pub inputs: Vec<CompiledActionInput>,
    pub effects: Vec<CompiledActionEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<CompiledActionRequirement>,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionRequirement {
    pub input: String,
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
}

/// The compiled action-handler backend tag, owned by the handler alone. A
/// build with the `wasm` feature can compile WASM handlers; the
/// runtime still refuses to execute them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledActionHandlerKind {
    Rhai,
    Wasm,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionHandler {
    pub kind: CompiledActionHandlerKind,
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
    pub limits: Option<CompiledChangeRequestPlannerLimits>,
    pub writes: Vec<CompiledActionHandlerWrite>,
    pub refusals: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionHandlerWrite {
    pub id: String,
    #[serde(flatten)]
    pub ceiling: CompiledChangeRequestPlannerWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionInput {
    pub id: String,
    pub api_name: String,
    pub field_type: FieldTypeSource,
    pub required: bool,
    pub classification: Classification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionEffect {
    pub id: String,
    pub target: CompiledActionTarget,
    pub operation: Operation,
    pub mutations: Vec<CompiledActionMutation>,
    pub depends_on: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledActionTarget {
    pub entity_id: String,
    pub binding: CompiledActionTargetBinding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledActionTargetBinding {
    Create,
    Existing { input: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledActionMutation {
    Set {
        field: String,
        value: CompiledActionValue,
    },
    Clear {
        field: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
pub enum CompiledActionValue {
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
#[serde(rename_all = "snake_case")]
pub enum ActionRouteKind {
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
    pub anonymous: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<crate::contract::ActorKindSource>,
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
    pub entity_id: String,
    /// The action target operation this permission entry governs. Absent only
    /// when reading a package compiled before discriminated targets existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,
    /// The effect or input that identifies this action target use. Absent only
    /// when reading a package compiled before discriminated targets existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CompiledActionTargetUseSource>,
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
    pub entity_id: String,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub source: CompiledActionTargetUseSource,
    pub condition_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind")]
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
    pub max_duration: CompiledConsentDuration,
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

/// A parsed ISO 8601 duration. Components are kept apart so PostgreSQL adds
/// calendar months and years the way the adopter wrote them.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledConsentDuration {
    pub iso: String,
    pub years: u32,
    pub months: u32,
    pub weeks: u32,
    pub days: u32,
    pub hours: u32,
    pub minutes: u32,
    pub seconds: u32,
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
/// `when: [active_lifecycle]` counts on an entity without a change request,
/// because every select policy there already requires
/// `record_lifecycle = 'active'`. A change request's select policy also
/// admits tombstoned rows, and a reference index needs whole-table coverage
/// for foreign-key checks, so neither may use this.
pub(crate) fn leading_field_indexed_for_list_finding(
    field: &str,
    indexes: &BTreeMap<String, Vec<String>>,
    constraints: &BTreeMap<String, crate::contract::ConstraintSource>,
    has_change_request: bool,
) -> bool {
    leading_field_indexed(field, indexes, constraints)
        || (!has_change_request
            && constraints.values().any(|constraint| {
                matches!(
                    constraint,
                    crate::contract::ConstraintSource::Unique { fields, when: Some(when), .. }
                        if fields.first().is_some_and(|first| first == field)
                            && when.as_slice()
                                == [crate::contract::UniqueWhenPredicate::ActiveLifecycle {}]
                )
            }))
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
    pub read_paths: BTreeMap<String, CompiledReadPath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_control: Option<CompiledChangeControl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_request: Option<CompiledChangeRequest>,
    pub fields: BTreeMap<String, CompiledField>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attachments: BTreeMap<String, CompiledAttachmentSlot>,
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
            && self.read_paths.is_empty()
    }
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
    /// Deprecated predecessor compatibility. New compiled temporal semantics do
    /// not derive query scope or exclusion policy from this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_fields: Vec<String>,
}

impl From<TemporalSource> for CompiledTemporal {
    fn from(source: TemporalSource) -> Self {
        Self {
            start_field: source.start_field,
            end_field: source.end_field,
            scope_fields: Vec::new(),
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
    pub entity_id: String,
    pub event_id: String,
    pub trigger: crate::contract::EventTrigger,
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
    pub authentication_profile: WebhookAuthenticationProfile,
    pub delivery_mode: CompiledWebhookDeliveryMode,
    pub retry_profile: CompiledWebhookRetryProfile,
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
    pub dead_letter: WebhookDeadLetterMode,
    pub operator_replay: bool,
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub enum CompiledWebhookDeliveryMode {
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledWebhookRetryProfile {
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
#[serde(rename_all = "snake_case")]
pub enum CompiledRevisionKind {
    List,
    Detail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledAccessEntry {
    #[serde(default)]
    pub route_id: String,
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
    pub entities: Vec<CompiledMetadataEntity>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryKind {
    List,
    Current,
    AsOf,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
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
    /// Deprecated predecessor compatibility. New query bindings leave this
    /// empty and generated contracts do not expose it as temporal semantics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_fields: Vec<String>,
    pub semantics: CompiledQueryTemporalSemantics,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryTemporalValueKind {
    Date,
    Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledQueryTemporalSemantics {
    StartInclusiveEndExclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledQueryOperation {
    pub id: String,
    pub route_id: String,
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

pub const REQUEST_BREG_STATE_QUERY_FIELD: &str = "__request_breg_state";
pub const REQUEST_PROPOSAL_VERSION_QUERY_FIELD: &str = "__request_proposal_version";
pub const REQUEST_EFFECT_DIGEST_QUERY_FIELD: &str = "__request_effect_digest";
/// The settled review outcome of the current proposal. It is review state, so
/// only a profile that may read review state may filter on it.
pub const REQUEST_REVIEW_OUTCOME_QUERY_FIELD: &str = "__request_review_outcome";

pub fn request_query_field_id_for_api(api_name: &str) -> Option<&'static str> {
    match api_name {
        "bregState" => Some(REQUEST_BREG_STATE_QUERY_FIELD),
        "proposalVersion" => Some(REQUEST_PROPOSAL_VERSION_QUERY_FIELD),
        "effectDigest" => Some(REQUEST_EFFECT_DIGEST_QUERY_FIELD),
        "reviewOutcome" => Some(REQUEST_REVIEW_OUTCOME_QUERY_FIELD),
        _ => None,
    }
}

pub fn request_query_field_api_name(field_id: &str) -> Option<&'static str> {
    match field_id {
        REQUEST_BREG_STATE_QUERY_FIELD => Some("bregState"),
        REQUEST_PROPOSAL_VERSION_QUERY_FIELD => Some("proposalVersion"),
        REQUEST_EFFECT_DIGEST_QUERY_FIELD => Some("effectDigest"),
        REQUEST_REVIEW_OUTCOME_QUERY_FIELD => Some("reviewOutcome"),
        _ => None,
    }
}

pub fn request_query_field_type(field_id: &str) -> Option<FieldTypeSource> {
    match field_id {
        REQUEST_BREG_STATE_QUERY_FIELD => Some(FieldTypeSource::String {
            min_length: 4,
            max_length: 16,
        }),
        REQUEST_PROPOSAL_VERSION_QUERY_FIELD => Some(FieldTypeSource::Int64),
        REQUEST_EFFECT_DIGEST_QUERY_FIELD => Some(FieldTypeSource::String {
            min_length: 71,
            max_length: 71,
        }),
        REQUEST_REVIEW_OUTCOME_QUERY_FIELD => Some(FieldTypeSource::String {
            min_length: 7,
            max_length: 16,
        }),
        _ => None,
    }
}

pub fn request_state_query_filter_fields() -> Vec<CompiledQueryFilterField> {
    vec![
        CompiledQueryFilterField {
            field: REQUEST_BREG_STATE_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
            ],
        },
        CompiledQueryFilterField {
            field: REQUEST_PROPOSAL_VERSION_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
                CompiledQueryFilterOperator::Range,
            ],
        },
        CompiledQueryFilterField {
            field: REQUEST_EFFECT_DIGEST_QUERY_FIELD.to_owned(),
            operators: vec![
                CompiledQueryFilterOperator::Equals,
                CompiledQueryFilterOperator::In,
                CompiledQueryFilterOperator::IsNull,
                CompiledQueryFilterOperator::IsNotNull,
            ],
        },
    ]
}

/// Filter-only: the outcome is a queue selector, not an ordering.
pub fn request_review_query_filter_field() -> CompiledQueryFilterField {
    CompiledQueryFilterField {
        field: REQUEST_REVIEW_OUTCOME_QUERY_FIELD.to_owned(),
        operators: vec![
            CompiledQueryFilterOperator::Equals,
            CompiledQueryFilterOperator::In,
        ],
    }
}

pub fn request_state_query_sort_fields() -> Vec<CompiledQuerySortField> {
    vec![
        CompiledQuerySortField {
            field: REQUEST_BREG_STATE_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
        CompiledQuerySortField {
            field: REQUEST_PROPOSAL_VERSION_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
        CompiledQuerySortField {
            field: REQUEST_EFFECT_DIGEST_QUERY_FIELD.to_owned(),
            directions: vec![CompiledQuerySortDirection::Asc],
        },
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledModuleIdentity {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// Immutable result consumed by runtime, migration, and authoring surfaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledRegistry {
    registry_id: String,
    version: String,
    default_language: String,
    package: Option<PackageIdentitySource>,
    manifest_projection: Option<CompiledManifestProjection>,
    module_order: Vec<String>,
    module_closure: Vec<CompiledModuleIdentity>,
    entities: BTreeMap<String, CompiledEntity>,
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
        package: Option<PackageIdentitySource>,
        manifest_projection: Option<CompiledManifestProjection>,
        module_order: Vec<String>,
        module_closure: Vec<CompiledModuleIdentity>,
        entities: BTreeMap<String, CompiledEntity>,
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
            package,
            manifest_projection,
            module_order,
            module_closure,
            entities,
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

    pub fn registry_id(&self) -> &str {
        &self.registry_id
    }

    pub fn version(&self) -> &str {
        &self.version
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
