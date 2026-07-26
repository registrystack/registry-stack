// SPDX-License-Identifier: Apache-2.0
//! Strict, value-free fixture-coverage evidence for offline project tests.
//!
//! Coverage is reported per integration target. Evidence contains only stable
//! identifiers, content digests, bounded counts, closed outcomes, and closed
//! safe error classes. Fixture values, request material, source observations,
//! paths, origins, outputs, claims, and secrets have no representation here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::Sha256Digest;

pub const PROJECT_FIXTURE_COVERAGE_SCHEMA_VERSION_V1: &str = "registry.project.fixture_coverage.v1";
pub(crate) const MAX_FIXTURE_COVERAGE_TARGETS: usize = 256;
pub(crate) const MAX_FIXTURE_COVERAGE_AUTHORED_RECORDS: usize = 1_024;
pub(crate) const MAX_FIXTURE_COVERAGE_GENERATED_RECORDS: usize =
    MAX_FIXTURE_COVERAGE_AUTHORED_RECORDS * GeneratorRecipeId::ALL.len();
pub(crate) const MAX_FIXTURE_COVERAGE_PLATFORM_RECORDS: usize = PlatformGeneratedCaseId::ALL.len();

const INVALID_REPORT: &str = "fixture coverage report violates the closed v1 invariants";
const INVALID_COMPARISON: &str =
    "fixture coverage comparison input violates the closed v1 invariants";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ProjectFixtureCoverageSchemaVersion {
    #[serde(rename = "registry.project.fixture_coverage.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureEvidenceScope {
    OfflineSynthetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCompatibilityClaim {
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCompatibilityEvaluation {
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCapability {
    DeclarativeHttp,
    Script,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageClassification {
    Synthetic,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureSetState {
    FixtureBearing,
    Fixtureless,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureSemanticOutcome {
    Match,
    NoMatch,
    Ambiguous,
    Successful,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum FixtureSafeCode {
    #[serde(rename = "authorization.denied")]
    AuthorizationDenied,
    #[serde(rename = "failure.subject_mismatch")]
    FailureSubjectMismatch,
    #[serde(rename = "fixture.execution_contract_invalid")]
    FixtureExecutionContractInvalid,
    #[serde(rename = "fixture.profile_not_found")]
    FixtureProfileNotFound,
    #[serde(rename = "fixture.request_mismatch")]
    FixtureRequestMismatch,
    #[serde(rename = "fixture.source_operation_unknown")]
    FixtureSourceOperationUnknown,
    #[serde(rename = "input.pattern_mismatch")]
    InputPatternMismatch,
    #[serde(rename = "source.cardinality_violation")]
    SourceCardinalityViolation,
    #[serde(rename = "source.deadline_exceeded")]
    SourceDeadlineExceeded,
    #[serde(rename = "source.response_malformed")]
    SourceResponseMalformed,
    #[serde(rename = "source.response_too_large")]
    SourceResponseTooLarge,
    #[serde(rename = "source.call_budget_exceeded")]
    SourceCallBudgetExceeded,
    #[serde(rename = "source.status_rejected")]
    SourceStatusRejected,
    #[serde(rename = "source.unavailable")]
    SourceUnavailable,
    #[serde(rename = "source_unavailable")]
    SourceUnavailableLegacy,
    /// A runtime error class outside the reviewed allow-list. Its value is
    /// intentionally not copied into the report.
    #[serde(rename = "redacted_unclassified_error")]
    RedactedUnclassifiedError,
}

impl FixtureSafeCode {
    pub(crate) fn from_runtime_code(code: &str) -> Self {
        match code {
            "authorization.denied" => Self::AuthorizationDenied,
            "failure.subject_mismatch" => Self::FailureSubjectMismatch,
            "fixture.execution_contract_invalid" => Self::FixtureExecutionContractInvalid,
            "fixture.profile_not_found" => Self::FixtureProfileNotFound,
            "fixture.request_mismatch" => Self::FixtureRequestMismatch,
            "fixture.source_operation_unknown" => Self::FixtureSourceOperationUnknown,
            "input.pattern_mismatch" => Self::InputPatternMismatch,
            "source.cardinality_violation" => Self::SourceCardinalityViolation,
            "source.deadline_exceeded" => Self::SourceDeadlineExceeded,
            "source.response_malformed" => Self::SourceResponseMalformed,
            "source.response_too_large" => Self::SourceResponseTooLarge,
            "source.call_budget_exceeded" => Self::SourceCallBudgetExceeded,
            "source.status_rejected" => Self::SourceStatusRejected,
            "source.unavailable" => Self::SourceUnavailable,
            "source_unavailable" => Self::SourceUnavailableLegacy,
            _ => Self::RedactedUnclassifiedError,
        }
    }

    pub(crate) const fn is_source_failure(self) -> bool {
        matches!(
            self,
            Self::SourceCardinalityViolation
                | Self::SourceDeadlineExceeded
                | Self::SourceResponseMalformed
                | Self::SourceResponseTooLarge
                | Self::SourceCallBudgetExceeded
                | Self::SourceStatusRejected
                | Self::SourceUnavailable
                | Self::SourceUnavailableLegacy
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FixtureSemanticExpectation {
    Outcome { outcome: FixtureSemanticOutcome },
    SafeErrorCode { code: FixtureSafeCode },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixturePassState {
    Passed,
    Failed,
    NotExecuted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureDisclosureMode {
    Predicate,
    Redacted,
    Value,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatusOutcome {
    Ambiguous,
    NoMatch,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureStatusMapping {
    pub outcome: FixtureStatusOutcome,
    pub statuses: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureProtocolHelper {
    RequestPrimitive,
    ResponseCodec,
    SignedDci,
    Verification,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureLimit {
    AggregateSourceBytes,
    CallCount,
    Deadline,
    OutputBytes,
    RequestBytes,
    ResponseBytes,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageEvidenceKind {
    AuthoredFixture,
    GeneratedCase,
    PlatformCase,
    CompiledContract,
    SemanticComparison,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageEvidence {
    pub kind: FixtureCoverageEvidenceKind,
    pub id: String,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSemanticFixtureCoverage {
    pub evidence: FixtureCoverageEvidence,
    pub fixture_id: String,
    pub fixture_digest: Sha256Digest,
    pub expectation: FixtureSemanticExpectation,
    pub semantic_null: bool,
    pub interaction_count: u32,
    pub input_ids: Vec<String>,
    pub output_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub exercised_status_mappings: Vec<FixtureStatusMapping>,
    pub classification: FixtureCoverageClassification,
    pub pass_state: FixturePassState,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratorRecipeId {
    RequestAuthority,
    RequestOrder,
    StatusRejection,
    MalformedDecode,
    ByteCeiling,
    Timeout,
    ProtocolVerification,
    AuthorizationBeforeSource,
    OutputMinimization,
}

impl GeneratorRecipeId {
    pub const ALL: [Self; 9] = [
        Self::RequestAuthority,
        Self::RequestOrder,
        Self::StatusRejection,
        Self::MalformedDecode,
        Self::ByteCeiling,
        Self::Timeout,
        Self::ProtocolVerification,
        Self::AuthorizationBeforeSource,
        Self::OutputMinimization,
    ];

    pub(crate) const fn mutation_target(self) -> FixtureMutationTargetClass {
        match self {
            Self::RequestAuthority => FixtureMutationTargetClass::RequestPathAuthority,
            Self::RequestOrder => FixtureMutationTargetClass::RequestInteractionOrder,
            Self::StatusRejection => FixtureMutationTargetClass::SourceStatus,
            Self::MalformedDecode => FixtureMutationTargetClass::ResponseBodyDecoding,
            Self::ByteCeiling => FixtureMutationTargetClass::DeclaredResponseByteCount,
            Self::Timeout => FixtureMutationTargetClass::SourceDeadline,
            Self::ProtocolVerification => FixtureMutationTargetClass::ProtocolResponseEnvelope,
            Self::AuthorizationBeforeSource => FixtureMutationTargetClass::AuthorizationGate,
            Self::OutputMinimization => FixtureMutationTargetClass::UnselectedResponseMember,
        }
    }

    pub(crate) const fn expected_safe_code(self) -> Option<FixtureSafeCode> {
        match self {
            Self::RequestAuthority | Self::RequestOrder => {
                Some(FixtureSafeCode::FixtureRequestMismatch)
            }
            Self::StatusRejection => Some(FixtureSafeCode::SourceStatusRejected),
            Self::MalformedDecode | Self::ProtocolVerification => {
                Some(FixtureSafeCode::SourceResponseMalformed)
            }
            Self::ByteCeiling => Some(FixtureSafeCode::SourceResponseTooLarge),
            Self::Timeout => Some(FixtureSafeCode::SourceDeadlineExceeded),
            Self::AuthorizationBeforeSource => Some(FixtureSafeCode::AuthorizationDenied),
            Self::OutputMinimization => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum GeneratorRecipeVersion {
    #[serde(rename = "v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorRecipe {
    pub id: GeneratorRecipeId,
    pub version: GeneratorRecipeVersion,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureMutationTargetClass {
    RequestPathAuthority,
    RequestInteractionOrder,
    SourceStatus,
    ResponseBodyDecoding,
    DeclaredResponseByteCount,
    SourceDeadline,
    ProtocolResponseEnvelope,
    AuthorizationGate,
    UnselectedResponseMember,
    SourceCallBudget,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedNotApplicableReason {
    NoRemoteSourceCapability,
    NoSourceInteraction,
    SingleSourceInteraction,
    NoDistinguishableRequestPair,
    NoGeneratedRequestMatcher,
    FinalResponseIsNotJsonObject,
    IntegrationHasNoProductClaims,
    SnapshotUsesClosedMaterialization,
    ProtocolMatcherOwnsResponseMutation,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageInvariant {
    RemoteMutationRequiresRemoteSourceCapability,
    MutationRequiresSourceInteraction,
    OrderMutationRequiresMultipleSourceInteractions,
    OrderMutationRequiresDistinguishableSourceInteractions,
    ProtocolMutationRequiresGeneratedRequestMatcher,
    MutationRequiresFinalJsonObjectResponse,
    AuthorizationCheckRequiresProductClaimEvaluation,
    SnapshotOutputUsesClosedMaterializationProjection,
    ProtocolMatcherFixtureUsesProtocolVerificationInstead,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedRecipeApplicability {
    Applicable {},
    NotApplicable {
        reason: GeneratedNotApplicableReason,
        invariant: CoverageInvariant,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedSourceFixture {
    pub fixture_id: String,
    pub fixture_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCallExpectation {
    Zero,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAccessAssertion {
    pub expected_source_calls: SourceCallExpectation,
    pub actual_source_calls: Option<u32>,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedFixtureCoverage {
    pub evidence: FixtureCoverageEvidence,
    pub recipe: GeneratorRecipe,
    pub source_fixture: GeneratedSourceFixture,
    pub applicability: GeneratedRecipeApplicability,
    pub mutation_target_class: FixtureMutationTargetClass,
    pub expected_safe_code: Option<FixtureSafeCode>,
    pub actual_safe_code: Option<FixtureSafeCode>,
    pub pass_state: FixturePassState,
    pub source_access_assertion: Option<SourceAccessAssertion>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformGeneratedCaseId {
    RelayScriptCallBudget,
}

impl PlatformGeneratedCaseId {
    pub const ALL: [Self; 1] = [Self::RelayScriptCallBudget];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformCoverageComponent {
    RelayScriptWorker,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformGeneratedFixtureCoverage {
    pub evidence: FixtureCoverageEvidence,
    pub case_id: PlatformGeneratedCaseId,
    pub version: GeneratorRecipeVersion,
    pub component: PlatformCoverageComponent,
    pub mutation_target_class: FixtureMutationTargetClass,
    pub expected_safe_code: FixtureSafeCode,
    pub actual_safe_code: FixtureSafeCode,
    pub pass_state: FixturePassState,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageDimensions {
    pub input_ids: Vec<String>,
    pub output_ids: Vec<String>,
    pub claim_ids: Vec<String>,
    pub disclosure_modes: Vec<FixtureDisclosureMode>,
    pub status_mappings: Vec<FixtureStatusMapping>,
    pub protocol_helpers: Vec<FixtureProtocolHelper>,
    pub limits: Vec<FixtureLimit>,
    /// Real branch identifiers only. Semantic outcomes must never be copied
    /// here as a proxy for implementation branch coverage.
    pub script_branch_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageTargetIdentity {
    pub integration: String,
    pub capability: FixtureCapability,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageReviewedNotApplicable {
    SemanticAmbiguity,
    SubjectMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageTargetContract {
    /// Present only for declarative HTTP targets. This is the compiled
    /// operation cardinality, not a source endpoint or authored path.
    pub source_operation_count: Option<u32>,
    pub reviewed_not_applicable: Vec<FixtureCoverageReviewedNotApplicable>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredFixtureCoverageRequirement {
    SemanticMatch,
    SemanticNoMatch,
    SemanticAmbiguity,
    SubjectMismatch,
    SemanticNull,
    AuthorizationDenial,
    SourceFailure,
    RequestRendering,
    ExpectedSourceInteractions,
    SourceInteractionOrder,
    OutputFields,
    Claims,
    DeclaredDisclosureModes,
    ExercisedDisclosureModes,
    ScriptBranches,
    PaginationAndContinuation,
    StatusMappings,
    ProtocolHelpers,
    ProtocolVerification,
    AuthorizationBeforeSource,
    MalformedDecoding,
    StructuralLimits,
    RequestBytes,
    ResponseBytes,
    AggregateSourceBytes,
    OutputBytes,
    CallLimits,
    TimeoutClassification,
    NumericDeadlineEnforcement,
    OutputMinimization,
    ChangedInputAffectedFixtures,
    ChangedOutputAffectedFixtures,
    ChangedClaimAffectedFixtures,
    ChangedSourceContractAffectedFixtures,
}

impl RequiredFixtureCoverageRequirement {
    pub const ALL: [Self; 34] = [
        Self::SemanticMatch,
        Self::SemanticNoMatch,
        Self::SemanticAmbiguity,
        Self::SubjectMismatch,
        Self::SemanticNull,
        Self::AuthorizationDenial,
        Self::SourceFailure,
        Self::RequestRendering,
        Self::ExpectedSourceInteractions,
        Self::SourceInteractionOrder,
        Self::OutputFields,
        Self::Claims,
        Self::DeclaredDisclosureModes,
        Self::ExercisedDisclosureModes,
        Self::ScriptBranches,
        Self::PaginationAndContinuation,
        Self::StatusMappings,
        Self::ProtocolHelpers,
        Self::ProtocolVerification,
        Self::AuthorizationBeforeSource,
        Self::MalformedDecoding,
        Self::StructuralLimits,
        Self::RequestBytes,
        Self::ResponseBytes,
        Self::AggregateSourceBytes,
        Self::OutputBytes,
        Self::CallLimits,
        Self::TimeoutClassification,
        Self::NumericDeadlineEnforcement,
        Self::OutputMinimization,
        Self::ChangedInputAffectedFixtures,
        Self::ChangedOutputAffectedFixtures,
        Self::ChangedClaimAffectedFixtures,
        Self::ChangedSourceContractAffectedFixtures,
    ];
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageGapReason {
    RequiredEvidenceMissing,
    TargetHasNoFixtures,
    RuntimeDimensionNotObserved,
    NumericBoundaryNotExercised,
    ScriptBranchContractNotDeclared,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageNotApplicableReason {
    NoProductClaimsDeclared,
    NoProtocolHelpersDeclared,
    NoVerificationProtocolDeclared,
    NoContinuationProtocolDeclared,
    NoRemoteSourceCapability,
    NoScriptCapability,
    NoStatusMappingsDeclared,
    NoDynamicSourceCallsCapability,
    SingleCompiledSourceOperation,
    ProtocolMatcherOwnsOutputValidation,
    ReviewedAmbiguityNotApplicable,
    ReviewedSubjectMismatchNotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageNotEvaluatedReason {
    ComparisonInputAbsent,
    TargetComparisonAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum FixtureRequirementCoverage {
    Covered {
        requirement: RequiredFixtureCoverageRequirement,
        evidence: Vec<FixtureCoverageEvidence>,
    },
    Missing {
        requirement: RequiredFixtureCoverageRequirement,
        reason: FixtureCoverageGapReason,
        evidence: Vec<FixtureCoverageEvidence>,
    },
    NotApplicable {
        requirement: RequiredFixtureCoverageRequirement,
        reason: FixtureCoverageNotApplicableReason,
        evidence: Vec<FixtureCoverageEvidence>,
    },
    NotEvaluated {
        requirement: RequiredFixtureCoverageRequirement,
        reason: FixtureCoverageNotEvaluatedReason,
        evidence: Vec<FixtureCoverageEvidence>,
    },
}

impl FixtureRequirementCoverage {
    pub fn requirement(&self) -> RequiredFixtureCoverageRequirement {
        match self {
            Self::Covered { requirement, .. }
            | Self::Missing { requirement, .. }
            | Self::NotApplicable { requirement, .. }
            | Self::NotEvaluated { requirement, .. } => *requirement,
        }
    }

    pub fn evidence(&self) -> &[FixtureCoverageEvidence] {
        match self {
            Self::Covered { evidence, .. }
            | Self::Missing { evidence, .. }
            | Self::NotApplicable { evidence, .. }
            | Self::NotEvaluated { evidence, .. } => evidence,
        }
    }

    pub const fn state(&self) -> FixtureCoverageRequirementState {
        match self {
            Self::Covered { .. } => FixtureCoverageRequirementState::Covered,
            Self::Missing { .. } => FixtureCoverageRequirementState::Missing,
            Self::NotApplicable { .. } => FixtureCoverageRequirementState::NotApplicable,
            Self::NotEvaluated { .. } => FixtureCoverageRequirementState::NotEvaluated,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageRequirementState {
    Covered,
    Missing,
    NotApplicable,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum FixtureCoverageChangeKind {
    ChangedInput,
    ChangedOutput,
    ChangedClaim,
    ChangedSourceContract,
}

impl FixtureCoverageChangeKind {
    pub const ALL: [Self; 4] = [
        Self::ChangedInput,
        Self::ChangedOutput,
        Self::ChangedClaim,
        Self::ChangedSourceContract,
    ];

    pub const fn requirement(self) -> RequiredFixtureCoverageRequirement {
        match self {
            Self::ChangedInput => RequiredFixtureCoverageRequirement::ChangedInputAffectedFixtures,
            Self::ChangedOutput => {
                RequiredFixtureCoverageRequirement::ChangedOutputAffectedFixtures
            }
            Self::ChangedClaim => RequiredFixtureCoverageRequirement::ChangedClaimAffectedFixtures,
            Self::ChangedSourceContract => {
                RequiredFixtureCoverageRequirement::ChangedSourceContractAffectedFixtures
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageChangeImpact {
    pub kind: FixtureCoverageChangeKind,
    pub changed_member_ids: Vec<String>,
    pub affected_fixture_ids: Vec<String>,
    pub evidence: FixtureCoverageEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageSemanticComparison {
    pub baseline_digest: Sha256Digest,
    pub candidate_digest: Sha256Digest,
    pub impacts: Vec<FixtureCoverageChangeImpact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageTarget {
    pub identity: FixtureCoverageTargetIdentity,
    pub contract: FixtureCoverageTargetContract,
    pub fixture_set_state: FixtureSetState,
    pub compiled_contract: FixtureCoverageEvidence,
    pub fixture_inventory: Vec<AuthoredSemanticFixtureCoverage>,
    pub generated_cases: Vec<GeneratedFixtureCoverage>,
    pub platform_cases: Vec<PlatformGeneratedFixtureCoverage>,
    pub declared: FixtureCoverageDimensions,
    pub exercised: FixtureCoverageDimensions,
    pub comparison: Option<FixtureCoverageSemanticComparison>,
    pub requirements: Vec<FixtureRequirementCoverage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageTargetSetState {
    NoTargets,
    TargetsPresent,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageRequirementCounts {
    pub covered: u32,
    pub missing: u32,
    pub not_applicable: u32,
    pub not_evaluated: u32,
    pub total: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageSummary {
    pub target_set_state: FixtureCoverageTargetSetState,
    pub target_count: u32,
    pub fixture_bearing_target_count: u32,
    pub fixtureless_target_count: u32,
    pub requirements: FixtureCoverageRequirementCounts,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "UncheckedProjectFixtureCoverageReportV1")]
#[serde(deny_unknown_fields)]
pub struct ProjectFixtureCoverageReportV1 {
    pub schema_version: ProjectFixtureCoverageSchemaVersion,
    pub project: String,
    pub environment: Option<String>,
    pub evidence_scope: FixtureEvidenceScope,
    pub compatibility_claim: FixtureCompatibilityClaim,
    pub live_compatibility: LiveCompatibilityEvaluation,
    pub targets: Vec<FixtureCoverageTarget>,
    pub summary: FixtureCoverageSummary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedProjectFixtureCoverageReportV1 {
    schema_version: ProjectFixtureCoverageSchemaVersion,
    project: String,
    environment: Option<String>,
    evidence_scope: FixtureEvidenceScope,
    compatibility_claim: FixtureCompatibilityClaim,
    live_compatibility: LiveCompatibilityEvaluation,
    targets: Vec<FixtureCoverageTarget>,
    summary: FixtureCoverageSummary,
}

impl ProjectFixtureCoverageReportV1 {
    pub fn from_targets(
        project: String,
        environment: Option<String>,
        targets: Vec<FixtureCoverageTarget>,
    ) -> Result<Self, &'static str> {
        let summary = derive_fixture_coverage_summary(&targets)?;
        let unchecked = UncheckedProjectFixtureCoverageReportV1 {
            schema_version: ProjectFixtureCoverageSchemaVersion::V1,
            project,
            environment,
            evidence_scope: FixtureEvidenceScope::OfflineSynthetic,
            compatibility_claim: FixtureCompatibilityClaim::None,
            live_compatibility: LiveCompatibilityEvaluation::NotEvaluated,
            targets,
            summary,
        };
        Self::try_from(unchecked)
    }

    /// Adds a closed semantic comparison and recomputes the four affected
    /// fixture requirements for every target. Selection is deliberately based
    /// only on declared fixture member identifiers. Generated cases are a
    /// different evidence class and can never become affected authored
    /// fixtures.
    pub fn with_comparison(
        mut self,
        input: &FixtureCoverageComparisonInput,
    ) -> Result<Self, &'static str> {
        input.validate()?;
        for target in &mut self.targets {
            let comparison_input = input
                .targets
                .binary_search_by(|candidate| {
                    candidate
                        .integration
                        .as_str()
                        .cmp(target.identity.integration.as_str())
                })
                .ok()
                .map(|index| &input.targets[index]);
            target.comparison = comparison_input
                .map(|comparison_input| {
                    build_target_comparison(
                        target,
                        input.baseline_digest.clone(),
                        input.candidate_digest.clone(),
                        comparison_input,
                    )
                })
                .transpose()?;
            replace_comparison_requirements(target)?;
        }
        self.summary = derive_fixture_coverage_summary(&self.targets)?;
        let unchecked = UncheckedProjectFixtureCoverageReportV1 {
            schema_version: self.schema_version,
            project: self.project,
            environment: self.environment,
            evidence_scope: self.evidence_scope,
            compatibility_claim: self.compatibility_claim,
            live_compatibility: self.live_compatibility,
            targets: self.targets,
            summary: self.summary,
        };
        Self::try_from(unchecked)
    }
}

impl TryFrom<UncheckedProjectFixtureCoverageReportV1> for ProjectFixtureCoverageReportV1 {
    type Error = &'static str;

    fn try_from(value: UncheckedProjectFixtureCoverageReportV1) -> Result<Self, Self::Error> {
        validate_fixture_coverage_report(&value)?;
        Ok(Self {
            schema_version: value.schema_version,
            project: value.project,
            environment: value.environment,
            evidence_scope: value.evidence_scope,
            compatibility_claim: value.compatibility_claim,
            live_compatibility: value.live_compatibility,
            targets: value.targets,
            summary: value.summary,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "UncheckedFixtureCoverageComparisonInput")]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageComparisonInput {
    pub baseline_digest: Sha256Digest,
    pub candidate_digest: Sha256Digest,
    pub targets: Vec<FixtureCoverageTargetComparisonInput>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCoverageTargetComparisonInput {
    pub integration: String,
    pub changed_input_ids: Vec<String>,
    pub changed_output_ids: Vec<String>,
    pub changed_claim_ids: Vec<String>,
    pub source_contract_changed: bool,
}

impl FixtureCoverageComparisonInput {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_comparison_input_targets(&self.targets)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedFixtureCoverageComparisonInput {
    baseline_digest: Sha256Digest,
    candidate_digest: Sha256Digest,
    targets: Vec<FixtureCoverageTargetComparisonInput>,
}

impl TryFrom<UncheckedFixtureCoverageComparisonInput> for FixtureCoverageComparisonInput {
    type Error = &'static str;

    fn try_from(value: UncheckedFixtureCoverageComparisonInput) -> Result<Self, Self::Error> {
        validate_comparison_input_targets(&value.targets)?;
        Ok(Self {
            baseline_digest: value.baseline_digest,
            candidate_digest: value.candidate_digest,
            targets: value.targets,
        })
    }
}

fn validate_comparison_input_targets(
    targets: &[FixtureCoverageTargetComparisonInput],
) -> Result<(), &'static str> {
    if targets.len() > MAX_FIXTURE_COVERAGE_TARGETS
        || !targets
            .windows(2)
            .all(|pair| pair[0].integration < pair[1].integration)
        || targets.iter().any(|target| {
            !is_report_identifier(&target.integration)
                || !is_sorted_unique_identifiers(&target.changed_input_ids)
                || !is_sorted_unique_identifiers(&target.changed_output_ids)
                || !is_sorted_unique_identifiers(&target.changed_claim_ids)
        })
    {
        return Err(INVALID_COMPARISON);
    }
    Ok(())
}

pub(crate) fn fixture_coverage_digest(
    serializable: &impl Serialize,
) -> Result<Sha256Digest, &'static str> {
    let bytes = serde_json::to_vec(serializable).map_err(|_| INVALID_REPORT)?;
    let digest = Sha256::digest(bytes);
    Sha256Digest::new(format!("sha256:{}", hex::encode(digest))).map_err(|_| INVALID_REPORT)
}

pub(crate) fn fixture_coverage_evidence(
    kind: FixtureCoverageEvidenceKind,
    id: String,
    digest: Sha256Digest,
) -> Result<FixtureCoverageEvidence, &'static str> {
    if !is_evidence_id(&id) {
        return Err(INVALID_REPORT);
    }
    Ok(FixtureCoverageEvidence { kind, id, digest })
}

pub(crate) fn target_compiled_contract_evidence(
    identity: &FixtureCoverageTargetIdentity,
    contract: &FixtureCoverageTargetContract,
    declared: &FixtureCoverageDimensions,
) -> Result<FixtureCoverageEvidence, &'static str> {
    let digest = fixture_coverage_digest(&(identity, contract, declared))?;
    fixture_coverage_evidence(
        FixtureCoverageEvidenceKind::CompiledContract,
        format!(
            "target/{}/compiled-contract/v1",
            identity.integration.as_str()
        ),
        digest,
    )
}

fn build_target_comparison(
    target: &FixtureCoverageTarget,
    baseline_digest: Sha256Digest,
    candidate_digest: Sha256Digest,
    input: &FixtureCoverageTargetComparisonInput,
) -> Result<FixtureCoverageSemanticComparison, &'static str> {
    let mut impacts = Vec::with_capacity(FixtureCoverageChangeKind::ALL.len());
    for kind in FixtureCoverageChangeKind::ALL {
        let changed_member_ids = match kind {
            FixtureCoverageChangeKind::ChangedInput => input.changed_input_ids.clone(),
            FixtureCoverageChangeKind::ChangedOutput => input.changed_output_ids.clone(),
            FixtureCoverageChangeKind::ChangedClaim => input.changed_claim_ids.clone(),
            FixtureCoverageChangeKind::ChangedSourceContract if input.source_contract_changed => {
                vec!["source-contract".to_owned()]
            }
            FixtureCoverageChangeKind::ChangedSourceContract => Vec::new(),
        };
        let affected_fixture_ids = target
            .fixture_inventory
            .iter()
            .filter(|fixture| match kind {
                FixtureCoverageChangeKind::ChangedInput => {
                    slices_intersect(&fixture.input_ids, &changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedOutput => {
                    slices_intersect(&fixture.output_ids, &changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedClaim => {
                    slices_intersect(&fixture.claim_ids, &changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedSourceContract => input.source_contract_changed,
            })
            .map(|fixture| fixture.fixture_id.clone())
            .collect::<Vec<_>>();
        let digest = fixture_coverage_digest(&(
            &baseline_digest,
            &candidate_digest,
            &target.identity,
            kind,
            &changed_member_ids,
            &affected_fixture_ids,
        ))?;
        let evidence = fixture_coverage_evidence(
            FixtureCoverageEvidenceKind::SemanticComparison,
            format!(
                "target/{}/semantic-comparison/{}/v1",
                target.identity.integration,
                change_suffix(kind)
            ),
            digest,
        )?;
        impacts.push(FixtureCoverageChangeImpact {
            kind,
            changed_member_ids,
            affected_fixture_ids,
            evidence,
        });
    }
    Ok(FixtureCoverageSemanticComparison {
        baseline_digest,
        candidate_digest,
        impacts,
    })
}

fn replace_comparison_requirements(target: &mut FixtureCoverageTarget) -> Result<(), &'static str> {
    target.requirements = derive_fixture_coverage_requirements(
        target,
        FixtureCoverageNotEvaluatedReason::TargetComparisonAbsent,
    );
    Ok(())
}

fn slices_intersect(left: &[String], right: &[String]) -> bool {
    left.iter()
        .any(|candidate| right.binary_search(candidate).is_ok())
}

fn validate_fixture_coverage_report(
    report: &UncheckedProjectFixtureCoverageReportV1,
) -> Result<(), &'static str> {
    if !is_report_identifier(&report.project)
        || report
            .environment
            .as_deref()
            .is_some_and(|value| !is_report_identifier(value))
        || report.targets.len() > MAX_FIXTURE_COVERAGE_TARGETS
        || !report.targets.windows(2).all(|pair| {
            pair[0].identity.integration.as_str() < pair[1].identity.integration.as_str()
        })
        || report.summary != derive_fixture_coverage_summary(&report.targets)?
    {
        return Err(INVALID_REPORT);
    }
    for target in &report.targets {
        validate_target(target)?;
    }
    Ok(())
}

fn validate_target(target: &FixtureCoverageTarget) -> Result<(), &'static str> {
    if !is_report_identifier(&target.identity.integration) {
        return Err("fixture coverage target identity is invalid");
    }
    if !valid_target_contract(&target.identity, &target.contract) {
        return Err("fixture coverage target contract is invalid");
    }
    if target.fixture_inventory.len() > MAX_FIXTURE_COVERAGE_AUTHORED_RECORDS
        || target.generated_cases.len() > MAX_FIXTURE_COVERAGE_GENERATED_RECORDS
        || target.platform_cases.len() > MAX_FIXTURE_COVERAGE_PLATFORM_RECORDS
    {
        return Err("fixture coverage target exceeds a record ceiling");
    }
    if target.fixture_set_state
        != if target.fixture_inventory.is_empty() {
            FixtureSetState::Fixtureless
        } else {
            FixtureSetState::FixtureBearing
        }
    {
        return Err("fixture coverage target fixture state is not derived from inventory");
    }
    if target.compiled_contract
        != target_compiled_contract_evidence(&target.identity, &target.contract, &target.declared)?
    {
        return Err("fixture coverage compiled-contract evidence is inconsistent");
    }
    if !valid_dimensions(&target.declared) {
        return Err("fixture coverage declared dimensions are invalid");
    }
    if !valid_dimensions(&target.exercised) {
        return Err("fixture coverage exercised dimensions are invalid");
    }
    if let Some(error) = dimensions_subset_error(&target.exercised, &target.declared) {
        return Err(error);
    }
    if target
        .requirements
        .iter()
        .map(FixtureRequirementCoverage::requirement)
        .collect::<Vec<_>>()
        != RequiredFixtureCoverageRequirement::ALL
    {
        return Err("fixture coverage target requirements are not the exact ordered contract");
    }

    let mut available_evidence = BTreeSet::from([target.compiled_contract.clone()]);
    let mut fixture_ids = BTreeSet::new();
    let mut prior_fixture = None;
    for fixture in &target.fixture_inventory {
        if !validate_authored_fixture(target, fixture)
            || prior_fixture
                .as_deref()
                .is_some_and(|prior| prior >= fixture.fixture_id.as_str())
            || !fixture_ids.insert(fixture.fixture_id.clone())
        {
            return Err("fixture coverage authored inventory is invalid");
        }
        prior_fixture = Some(fixture.fixture_id.clone());
        available_evidence.insert(fixture.evidence.clone());
    }

    let mut prior_generated = None;
    let mut generated_keys = BTreeSet::new();
    for case in &target.generated_cases {
        let key = (case.source_fixture.fixture_id.as_str(), case.recipe.id);
        if prior_generated.is_some_and(|prior| prior >= key)
            || !generated_keys.insert((case.source_fixture.fixture_id.clone(), case.recipe.id))
            || !validate_generated_case(target, case)
        {
            return Err("fixture coverage generated cases are invalid");
        }
        prior_generated = Some(key);
        available_evidence.insert(case.evidence.clone());
    }
    if target.generated_cases.len()
        != target
            .fixture_inventory
            .len()
            .checked_mul(GeneratorRecipeId::ALL.len())
            .ok_or(INVALID_REPORT)?
    {
        return Err("fixture coverage generated-case cardinality is invalid");
    }

    let mut prior_platform = None;
    for case in &target.platform_cases {
        if prior_platform.is_some_and(|prior| prior >= case.case_id)
            || !validate_platform_case(target, case)
        {
            return Err("fixture coverage platform cases are invalid");
        }
        prior_platform = Some(case.case_id);
        available_evidence.insert(case.evidence.clone());
    }
    if (target.identity.capability == FixtureCapability::Script)
        != (target.platform_cases.len() == PlatformGeneratedCaseId::ALL.len())
    {
        return Err("fixture coverage platform-case capability is inconsistent");
    }

    if let Some(comparison) = &target.comparison {
        validate_comparison(target, comparison)?;
        available_evidence.extend(
            comparison
                .impacts
                .iter()
                .map(|impact| impact.evidence.clone()),
        );
    }

    let comparison_reason = comparison_absence_reason(&target.requirements, target.comparison.is_some())?;
    if target.requirements != derive_fixture_coverage_requirements(target, comparison_reason) {
        return Err("fixture coverage requirement states or evidence are not derived from target evidence");
    }
    for requirement in &target.requirements {
        if !requirement
            .evidence()
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err("fixture coverage requirement evidence is not sorted and unique");
        }
        if requirement
            .evidence()
            .iter()
            .any(|evidence| !available_evidence.contains(evidence))
        {
            return Err("fixture coverage requirement references foreign evidence");
        }
        match requirement {
            FixtureRequirementCoverage::Covered { evidence, .. } if evidence.is_empty() => {
                return Err("fixture coverage covered requirement has no evidence");
            }
            FixtureRequirementCoverage::NotEvaluated { evidence, .. } if !evidence.is_empty() => {
                return Err("fixture coverage unevaluated requirement carries evidence");
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_authored_fixture(
    target: &FixtureCoverageTarget,
    fixture: &AuthoredSemanticFixtureCoverage,
) -> bool {
    fixture.fixture_id.len() <= 256
        && is_report_identifier(&fixture.fixture_id)
        && fixture.interaction_count > 0
        && fixture.interaction_count <= 16
        && is_sorted_unique_identifiers(&fixture.input_ids)
        && is_sorted_unique_identifiers(&fixture.output_ids)
        && is_sorted_unique_identifiers(&fixture.claim_ids)
        && valid_status_mappings(&fixture.exercised_status_mappings)
        && fixture.exercised_status_mappings.iter().all(|mapping| {
            target.declared.status_mappings.iter().any(|declared| {
                mapping.outcome == declared.outcome
                    && slice_is_subset(&mapping.statuses, &declared.statuses)
            })
        })
        && fixture.evidence.kind == FixtureCoverageEvidenceKind::AuthoredFixture
        && fixture.evidence.id
            == format!(
                "target/{}/fixture/{}",
                target.identity.integration, fixture.fixture_id
            )
        && fixture.evidence.digest == fixture.fixture_digest
}

fn valid_target_contract(
    identity: &FixtureCoverageTargetIdentity,
    contract: &FixtureCoverageTargetContract,
) -> bool {
    contract
        .reviewed_not_applicable
        .windows(2)
        .all(|pair| pair[0] < pair[1])
        && match identity.capability {
            FixtureCapability::DeclarativeHttp => contract.source_operation_count.is_some(),
            FixtureCapability::Script | FixtureCapability::Snapshot => {
                contract.source_operation_count.is_none()
            }
        }
}

fn validate_generated_case(
    target: &FixtureCoverageTarget,
    case: &GeneratedFixtureCoverage,
) -> bool {
    let expected_id = format!(
        "target/{}/fixture/{}/generated/{}/v1",
        target.identity.integration,
        case.source_fixture.fixture_id,
        recipe_suffix(case.recipe.id)
    );
    let authored = target
        .fixture_inventory
        .iter()
        .find(|fixture| fixture.fixture_id == case.source_fixture.fixture_id);
    let applicable = matches!(
        case.applicability,
        GeneratedRecipeApplicability::Applicable {}
    );
    if case.evidence.kind != FixtureCoverageEvidenceKind::GeneratedCase
        || case.evidence.id != expected_id
        || case.recipe.version != GeneratorRecipeVersion::V1
        || case.mutation_target_class != case.recipe.id.mutation_target()
        || case.expected_safe_code != case.recipe.id.expected_safe_code()
        || authored
            .is_none_or(|fixture| fixture.fixture_digest != case.source_fixture.fixture_digest)
        || (!applicable
            && (case.pass_state != FixturePassState::NotExecuted
                || case.actual_safe_code.is_some()
                || case.source_access_assertion.is_some()))
        || (applicable
            && case.pass_state == FixturePassState::Passed
            && case.actual_safe_code != case.expected_safe_code)
    {
        return false;
    }
    if let GeneratedRecipeApplicability::NotApplicable { reason, invariant } = case.applicability {
        if !generated_not_applicable_is_valid(case.recipe.id, reason, invariant) {
            return false;
        }
    }
    if case.recipe.id == GeneratorRecipeId::AuthorizationBeforeSource && applicable {
        case.source_access_assertion
            .as_ref()
            .is_some_and(|assertion| {
                assertion.expected_source_calls == SourceCallExpectation::Zero
                    && assertion.passed == (assertion.actual_source_calls == Some(0))
            })
    } else {
        case.source_access_assertion.is_none()
    }
}

fn validate_platform_case(
    target: &FixtureCoverageTarget,
    case: &PlatformGeneratedFixtureCoverage,
) -> bool {
    target.identity.capability == FixtureCapability::Script
        && case.evidence.kind == FixtureCoverageEvidenceKind::PlatformCase
        && case.evidence.id == "platform/relay-script-worker/call-budget/v1"
        && case.case_id == PlatformGeneratedCaseId::RelayScriptCallBudget
        && case.version == GeneratorRecipeVersion::V1
        && case.component == PlatformCoverageComponent::RelayScriptWorker
        && case.mutation_target_class == FixtureMutationTargetClass::SourceCallBudget
        && case.expected_safe_code == FixtureSafeCode::SourceCallBudgetExceeded
        && case.pass_state
            == if case.actual_safe_code == case.expected_safe_code {
                FixturePassState::Passed
            } else {
                FixturePassState::Failed
            }
}

fn validate_comparison(
    target: &FixtureCoverageTarget,
    comparison: &FixtureCoverageSemanticComparison,
) -> Result<(), &'static str> {
    if comparison
        .impacts
        .iter()
        .map(|impact| impact.kind)
        .collect::<Vec<_>>()
        != FixtureCoverageChangeKind::ALL
    {
        return Err(INVALID_REPORT);
    }
    let fixture_ids = target
        .fixture_inventory
        .iter()
        .map(|fixture| fixture.fixture_id.as_str())
        .collect::<BTreeSet<_>>();
    for impact in &comparison.impacts {
        if !is_sorted_unique_identifiers(&impact.changed_member_ids)
            || !is_sorted_unique_identifiers(&impact.affected_fixture_ids)
            || impact
                .affected_fixture_ids
                .iter()
                .any(|id| !fixture_ids.contains(id.as_str()))
            || impact.evidence.kind != FixtureCoverageEvidenceKind::SemanticComparison
            || impact.evidence.id
                != format!(
                    "target/{}/semantic-comparison/{}/v1",
                    target.identity.integration,
                    change_suffix(impact.kind)
                )
            || impact.evidence.digest
                != fixture_coverage_digest(&(
                    &comparison.baseline_digest,
                    &comparison.candidate_digest,
                    &target.identity,
                    impact.kind,
                    &impact.changed_member_ids,
                    &impact.affected_fixture_ids,
                ))?
        {
            return Err(INVALID_REPORT);
        }
        let expected = target
            .fixture_inventory
            .iter()
            .filter(|fixture| match impact.kind {
                FixtureCoverageChangeKind::ChangedInput => {
                    slices_intersect(&fixture.input_ids, &impact.changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedOutput => {
                    slices_intersect(&fixture.output_ids, &impact.changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedClaim => {
                    slices_intersect(&fixture.claim_ids, &impact.changed_member_ids)
                }
                FixtureCoverageChangeKind::ChangedSourceContract => {
                    impact.changed_member_ids == ["source-contract"]
                }
            })
            .map(|fixture| fixture.fixture_id.as_str())
            .collect::<Vec<_>>();
        if impact
            .affected_fixture_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected
        {
            return Err(INVALID_REPORT);
        }
    }
    Ok(())
}

fn comparison_absence_reason(
    requirements: &[FixtureRequirementCoverage],
    has_comparison: bool,
) -> Result<FixtureCoverageNotEvaluatedReason, &'static str> {
    if has_comparison {
        return Ok(FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent);
    }
    let mut reasons = requirements.iter().skip(30).map(|coverage| match coverage {
        FixtureRequirementCoverage::NotEvaluated {
            reason, evidence, ..
        } if evidence.is_empty() => Ok(*reason),
        _ => Err(INVALID_REPORT),
    });
    let first = reasons.next().transpose()?.ok_or(INVALID_REPORT)?;
    if reasons.any(|reason| reason != Ok(first)) {
        return Err(INVALID_REPORT);
    }
    Ok(first)
}

pub(crate) fn derive_fixture_coverage_requirements(
    target: &FixtureCoverageTarget,
    comparison_reason: FixtureCoverageNotEvaluatedReason,
) -> Vec<FixtureRequirementCoverage> {
    RequiredFixtureCoverageRequirement::ALL
        .into_iter()
        .map(|requirement| {
            derive_fixture_coverage_requirement(target, requirement, comparison_reason)
        })
        .collect()
}

fn derive_fixture_coverage_requirement(
    target: &FixtureCoverageTarget,
    requirement: RequiredFixtureCoverageRequirement,
    comparison_reason: FixtureCoverageNotEvaluatedReason,
) -> FixtureRequirementCoverage {
    use RequiredFixtureCoverageRequirement as Requirement;

    let fixture_gap = if target.fixture_inventory.is_empty() {
        FixtureCoverageGapReason::TargetHasNoFixtures
    } else {
        FixtureCoverageGapReason::RequiredEvidenceMissing
    };
    let authored = |predicate: fn(&AuthoredSemanticFixtureCoverage) -> bool| {
        passed_authored_evidence(target, predicate)
    };
    match requirement {
        Requirement::SemanticMatch => covered_or_missing(
            requirement,
            authored(|fixture| {
                fixture.expectation
                    == FixtureSemanticExpectation::Outcome {
                        outcome: FixtureSemanticOutcome::Match,
                    }
            }),
            fixture_gap,
        ),
        Requirement::SemanticNoMatch => covered_or_missing(
            requirement,
            authored(|fixture| {
                fixture.expectation
                    == FixtureSemanticExpectation::Outcome {
                        outcome: FixtureSemanticOutcome::NoMatch,
                    }
            }),
            fixture_gap,
        ),
        Requirement::SemanticAmbiguity => {
            let evidence = authored(|fixture| {
                fixture.expectation
                    == FixtureSemanticExpectation::Outcome {
                        outcome: FixtureSemanticOutcome::Ambiguous,
                    }
            });
            if !evidence.is_empty() {
                covered(requirement, evidence)
            } else if reviewed_not_applicable(
                target,
                FixtureCoverageReviewedNotApplicable::SemanticAmbiguity,
            ) {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::ReviewedAmbiguityNotApplicable,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                missing(requirement, fixture_gap, Vec::new())
            }
        }
        Requirement::SubjectMismatch => {
            let evidence = authored(|fixture| {
                fixture.expectation
                    == FixtureSemanticExpectation::SafeErrorCode {
                        code: FixtureSafeCode::FailureSubjectMismatch,
                    }
            });
            if !evidence.is_empty() {
                covered(requirement, evidence)
            } else if reviewed_not_applicable(
                target,
                FixtureCoverageReviewedNotApplicable::SubjectMismatch,
            ) {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::ReviewedSubjectMismatchNotApplicable,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                missing(requirement, fixture_gap, Vec::new())
            }
        }
        Requirement::SemanticNull => covered_or_missing(
            requirement,
            authored(|fixture| fixture.semantic_null),
            fixture_gap,
        ),
        Requirement::AuthorizationDenial => {
            if target.declared.claim_ids.is_empty() {
                no_claims_not_applicable(target, requirement)
            } else {
                covered_or_missing(
                    requirement,
                    authored(|fixture| {
                        fixture.expectation
                            == FixtureSemanticExpectation::SafeErrorCode {
                                code: FixtureSafeCode::AuthorizationDenied,
                            }
                    }),
                    fixture_gap,
                )
            }
        }
        Requirement::SourceFailure => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                covered_or_missing(
                    requirement,
                    authored(|fixture| {
                        matches!(
                            fixture.expectation,
                            FixtureSemanticExpectation::SafeErrorCode { code }
                                if code.is_source_failure()
                        )
                    }),
                    fixture_gap,
                )
            }
        }
        Requirement::RequestRendering => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::RequestAuthority,
                    fixture_gap,
                )
            }
        }
        Requirement::ExpectedSourceInteractions => {
            let evidence = authored(|_| true);
            if !target.fixture_inventory.is_empty()
                && evidence.len() == target.fixture_inventory.len()
            {
                covered(requirement, evidence)
            } else {
                missing(requirement, fixture_gap, evidence)
            }
        }
        Requirement::SourceInteractionOrder => {
            let (complete, evidence) =
                generated_recipe_evidence(target, GeneratorRecipeId::RequestOrder);
            if complete {
                covered(requirement, evidence)
            } else if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else if target.identity.capability == FixtureCapability::DeclarativeHttp
                && target.contract.source_operation_count.is_some_and(|count| count <= 1)
            {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::SingleCompiledSourceOperation,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                missing(requirement, fixture_gap, evidence)
            }
        }
        Requirement::OutputFields => {
            let evidence = authored(|fixture| !fixture.output_ids.is_empty());
            if !target.declared.output_ids.is_empty()
                && target.exercised.output_ids == target.declared.output_ids
                && !evidence.is_empty()
            {
                covered(requirement, evidence)
            } else {
                missing(requirement, fixture_gap, evidence)
            }
        }
        Requirement::Claims => {
            if target.declared.claim_ids.is_empty() {
                no_claims_not_applicable(target, requirement)
            } else {
                let evidence = authored(|fixture| !fixture.claim_ids.is_empty());
                if target.exercised.claim_ids == target.declared.claim_ids && !evidence.is_empty() {
                    covered(requirement, evidence)
                } else {
                    missing(requirement, fixture_gap, evidence)
                }
            }
        }
        Requirement::DeclaredDisclosureModes => {
            if target.declared.claim_ids.is_empty() {
                no_claims_not_applicable(target, requirement)
            } else {
                covered(requirement, vec![target.compiled_contract.clone()])
            }
        }
        Requirement::ExercisedDisclosureModes => {
            if target.declared.claim_ids.is_empty() {
                no_claims_not_applicable(target, requirement)
            } else {
                missing(
                    requirement,
                    FixtureCoverageGapReason::RuntimeDimensionNotObserved,
                    Vec::new(),
                )
            }
        }
        Requirement::ScriptBranches => {
            if target.identity.capability != FixtureCapability::Script {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::NoScriptCapability,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                missing(
                    requirement,
                    FixtureCoverageGapReason::ScriptBranchContractNotDeclared,
                    Vec::new(),
                )
            }
        }
        Requirement::PaginationAndContinuation => match target.identity.capability {
            FixtureCapability::Snapshot => no_remote_not_applicable(target, requirement),
            FixtureCapability::DeclarativeHttp => not_applicable(
                requirement,
                FixtureCoverageNotApplicableReason::NoContinuationProtocolDeclared,
                vec![target.compiled_contract.clone()],
            ),
            FixtureCapability::Script => {
                missing(requirement, FixtureCoverageGapReason::RequiredEvidenceMissing, Vec::new())
            }
        },
        Requirement::StatusMappings => {
            if target.declared.status_mappings.is_empty() {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::NoStatusMappingsDeclared,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                let evidence =
                    authored(|fixture| !fixture.exercised_status_mappings.is_empty());
                if target.exercised.status_mappings == target.declared.status_mappings
                    && !evidence.is_empty()
                {
                    covered(requirement, evidence)
                } else {
                    missing(requirement, fixture_gap, evidence)
                }
            }
        }
        Requirement::ProtocolHelpers => {
            if target.declared.protocol_helpers.is_empty() {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::NoProtocolHelpersDeclared,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                let (complete, evidence) =
                    generated_recipe_evidence(target, GeneratorRecipeId::ProtocolVerification);
                if complete && target.exercised.protocol_helpers == target.declared.protocol_helpers
                {
                    covered(requirement, evidence)
                } else {
                    missing(requirement, fixture_gap, evidence)
                }
            }
        }
        Requirement::ProtocolVerification => {
            if !target.declared.protocol_helpers.iter().any(|helper| {
                matches!(
                    helper,
                    FixtureProtocolHelper::SignedDci | FixtureProtocolHelper::Verification
                )
            }) {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::NoVerificationProtocolDeclared,
                    vec![target.compiled_contract.clone()],
                )
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::ProtocolVerification,
                    fixture_gap,
                )
            }
        }
        Requirement::AuthorizationBeforeSource => {
            if target.declared.claim_ids.is_empty() {
                no_claims_not_applicable(target, requirement)
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::AuthorizationBeforeSource,
                    fixture_gap,
                )
            }
        }
        Requirement::MalformedDecoding => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::MalformedDecode,
                    fixture_gap,
                )
            }
        }
        Requirement::StructuralLimits => {
            covered(requirement, vec![target.compiled_contract.clone()])
        }
        Requirement::RequestBytes => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                missing(
                    requirement,
                    FixtureCoverageGapReason::NumericBoundaryNotExercised,
                    vec![target.compiled_contract.clone()],
                )
            }
        }
        Requirement::ResponseBytes => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::ByteCeiling,
                    fixture_gap,
                )
            }
        }
        Requirement::AggregateSourceBytes | Requirement::OutputBytes => missing(
            requirement,
            FixtureCoverageGapReason::NumericBoundaryNotExercised,
            vec![target.compiled_contract.clone()],
        ),
        Requirement::CallLimits => {
            if target.identity.capability == FixtureCapability::Script {
                let evidence = target
                    .platform_cases
                    .iter()
                    .filter(|case| case.pass_state == FixturePassState::Passed)
                    .map(|case| case.evidence.clone())
                    .collect::<Vec<_>>();
                covered_or_missing(
                    requirement,
                    evidence,
                    FixtureCoverageGapReason::RequiredEvidenceMissing,
                )
            } else {
                not_applicable(
                    requirement,
                    FixtureCoverageNotApplicableReason::NoDynamicSourceCallsCapability,
                    vec![target.compiled_contract.clone()],
                )
            }
        }
        Requirement::TimeoutClassification => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                generated_requirement(
                    target,
                    requirement,
                    GeneratorRecipeId::Timeout,
                    fixture_gap,
                )
            }
        }
        Requirement::NumericDeadlineEnforcement => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                let (_, mut evidence) =
                    generated_recipe_evidence(target, GeneratorRecipeId::Timeout);
                evidence.push(target.compiled_contract.clone());
                missing(
                    requirement,
                    FixtureCoverageGapReason::NumericBoundaryNotExercised,
                    evidence,
                )
            }
        }
        Requirement::OutputMinimization => {
            if target.identity.capability == FixtureCapability::Snapshot {
                no_remote_not_applicable(target, requirement)
            } else {
                let (protocol_complete, protocol_evidence) =
                    generated_recipe_evidence(target, GeneratorRecipeId::ProtocolVerification);
                let protocol_owns_mutation = target.generated_cases.iter().any(|case| {
                    case.recipe.id == GeneratorRecipeId::OutputMinimization
                        && matches!(
                            case.applicability,
                            GeneratedRecipeApplicability::NotApplicable {
                                reason:
                                    GeneratedNotApplicableReason::ProtocolMatcherOwnsResponseMutation,
                                ..
                            }
                        )
                });
                if protocol_owns_mutation && protocol_complete {
                    not_applicable(
                        requirement,
                        FixtureCoverageNotApplicableReason::ProtocolMatcherOwnsOutputValidation,
                        protocol_evidence,
                    )
                } else {
                    generated_requirement(
                        target,
                        requirement,
                        GeneratorRecipeId::OutputMinimization,
                        fixture_gap,
                    )
                }
            }
        }
        Requirement::ChangedInputAffectedFixtures
        | Requirement::ChangedOutputAffectedFixtures
        | Requirement::ChangedClaimAffectedFixtures
        | Requirement::ChangedSourceContractAffectedFixtures => {
            comparison_requirement(target, requirement, comparison_reason)
        }
    }
}

fn passed_authored_evidence(
    target: &FixtureCoverageTarget,
    predicate: fn(&AuthoredSemanticFixtureCoverage) -> bool,
) -> Vec<FixtureCoverageEvidence> {
    target
        .fixture_inventory
        .iter()
        .filter(|fixture| fixture.pass_state == FixturePassState::Passed && predicate(fixture))
        .map(|fixture| fixture.evidence.clone())
        .collect()
}

fn reviewed_not_applicable(
    target: &FixtureCoverageTarget,
    requirement: FixtureCoverageReviewedNotApplicable,
) -> bool {
    target
        .contract
        .reviewed_not_applicable
        .binary_search(&requirement)
        .is_ok()
}

fn generated_recipe_evidence(
    target: &FixtureCoverageTarget,
    recipe: GeneratorRecipeId,
) -> (bool, Vec<FixtureCoverageEvidence>) {
    let applicable = target
        .generated_cases
        .iter()
        .filter(|case| {
            case.recipe.id == recipe
                && matches!(
                    case.applicability,
                    GeneratedRecipeApplicability::Applicable {}
                )
        })
        .collect::<Vec<_>>();
    let evidence = applicable
        .iter()
        .filter(|case| {
            case.pass_state == FixturePassState::Passed
                && case
                    .source_access_assertion
                    .as_ref()
                    .is_none_or(|assertion| assertion.passed)
        })
        .map(|case| case.evidence.clone())
        .collect::<Vec<_>>();
    (
        !applicable.is_empty() && evidence.len() == applicable.len(),
        evidence,
    )
}

fn generated_requirement(
    target: &FixtureCoverageTarget,
    requirement: RequiredFixtureCoverageRequirement,
    recipe: GeneratorRecipeId,
    gap: FixtureCoverageGapReason,
) -> FixtureRequirementCoverage {
    let (complete, evidence) = generated_recipe_evidence(target, recipe);
    if complete {
        covered(requirement, evidence)
    } else {
        missing(requirement, gap, evidence)
    }
}

fn comparison_requirement(
    target: &FixtureCoverageTarget,
    requirement: RequiredFixtureCoverageRequirement,
    comparison_reason: FixtureCoverageNotEvaluatedReason,
) -> FixtureRequirementCoverage {
    let kind = FixtureCoverageChangeKind::ALL
        .into_iter()
        .find(|kind| kind.requirement() == requirement)
        .expect("comparison requirements have a change kind");
    let Some(impact) = target.comparison.as_ref().and_then(|comparison| {
        comparison
            .impacts
            .iter()
            .find(|impact| impact.kind == kind)
    }) else {
        return FixtureRequirementCoverage::NotEvaluated {
            requirement,
            reason: comparison_reason,
            evidence: Vec::new(),
        };
    };
    let evidence = vec![impact.evidence.clone()];
    if impact.changed_member_ids.is_empty() || !impact.affected_fixture_ids.is_empty() {
        covered(requirement, evidence)
    } else {
        missing(
            requirement,
            FixtureCoverageGapReason::RequiredEvidenceMissing,
            evidence,
        )
    }
}

fn no_claims_not_applicable(
    target: &FixtureCoverageTarget,
    requirement: RequiredFixtureCoverageRequirement,
) -> FixtureRequirementCoverage {
    not_applicable(
        requirement,
        FixtureCoverageNotApplicableReason::NoProductClaimsDeclared,
        vec![target.compiled_contract.clone()],
    )
}

fn no_remote_not_applicable(
    target: &FixtureCoverageTarget,
    requirement: RequiredFixtureCoverageRequirement,
) -> FixtureRequirementCoverage {
    not_applicable(
        requirement,
        FixtureCoverageNotApplicableReason::NoRemoteSourceCapability,
        vec![target.compiled_contract.clone()],
    )
}

fn covered_or_missing(
    requirement: RequiredFixtureCoverageRequirement,
    evidence: Vec<FixtureCoverageEvidence>,
    gap: FixtureCoverageGapReason,
) -> FixtureRequirementCoverage {
    if evidence.is_empty() {
        missing(requirement, gap, evidence)
    } else {
        covered(requirement, evidence)
    }
}

fn covered(
    requirement: RequiredFixtureCoverageRequirement,
    mut evidence: Vec<FixtureCoverageEvidence>,
) -> FixtureRequirementCoverage {
    evidence.sort();
    evidence.dedup();
    FixtureRequirementCoverage::Covered {
        requirement,
        evidence,
    }
}

fn missing(
    requirement: RequiredFixtureCoverageRequirement,
    reason: FixtureCoverageGapReason,
    mut evidence: Vec<FixtureCoverageEvidence>,
) -> FixtureRequirementCoverage {
    evidence.sort();
    evidence.dedup();
    FixtureRequirementCoverage::Missing {
        requirement,
        reason,
        evidence,
    }
}

fn not_applicable(
    requirement: RequiredFixtureCoverageRequirement,
    reason: FixtureCoverageNotApplicableReason,
    mut evidence: Vec<FixtureCoverageEvidence>,
) -> FixtureRequirementCoverage {
    evidence.sort();
    evidence.dedup();
    FixtureRequirementCoverage::NotApplicable {
        requirement,
        reason,
        evidence,
    }
}

fn valid_dimensions(dimensions: &FixtureCoverageDimensions) -> bool {
    is_sorted_unique_identifiers(&dimensions.input_ids)
        && is_sorted_unique_identifiers(&dimensions.output_ids)
        && is_sorted_unique_identifiers(&dimensions.claim_ids)
        && dimensions
            .disclosure_modes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && valid_status_mappings(&dimensions.status_mappings)
        && dimensions
            .protocol_helpers
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        && dimensions.limits.windows(2).all(|pair| pair[0] < pair[1])
        && is_sorted_unique_identifiers(&dimensions.script_branch_ids)
}

fn valid_status_mappings(mappings: &[FixtureStatusMapping]) -> bool {
    mappings.windows(2).all(|pair| pair[0] < pair[1])
        && mappings.iter().all(|mapping| {
            !mapping.statuses.is_empty()
                && mapping.statuses.windows(2).all(|pair| pair[0] < pair[1])
        })
}

fn dimensions_subset_error(
    exercised: &FixtureCoverageDimensions,
    declared: &FixtureCoverageDimensions,
) -> Option<&'static str> {
    if !slice_is_subset(&exercised.input_ids, &declared.input_ids) {
        return Some("fixture coverage exercised inputs exceed declarations");
    }
    if !slice_is_subset(&exercised.output_ids, &declared.output_ids) {
        return Some("fixture coverage exercised outputs exceed declarations");
    }
    if !slice_is_subset(&exercised.claim_ids, &declared.claim_ids) {
        return Some("fixture coverage exercised claims exceed declarations");
    }
    if !slice_is_subset(&exercised.disclosure_modes, &declared.disclosure_modes) {
        return Some("fixture coverage exercised disclosure modes exceed declarations");
    }
    if !exercised.status_mappings.iter().all(|mapping| {
        declared.status_mappings.iter().any(|declared_mapping| {
            mapping.outcome == declared_mapping.outcome
                && slice_is_subset(&mapping.statuses, &declared_mapping.statuses)
        })
    }) {
        return Some("fixture coverage exercised status mappings exceed declarations");
    }
    if !slice_is_subset(&exercised.protocol_helpers, &declared.protocol_helpers) {
        return Some("fixture coverage exercised protocol helpers exceed declarations");
    }
    if !slice_is_subset(&exercised.limits, &declared.limits) {
        return Some("fixture coverage exercised limits exceed declarations");
    }
    if !slice_is_subset(&exercised.script_branch_ids, &declared.script_branch_ids) {
        return Some("fixture coverage exercised script branches exceed declarations");
    }
    None
}

fn slice_is_subset<T: Ord>(subset: &[T], superset: &[T]) -> bool {
    subset
        .iter()
        .all(|value| superset.binary_search(value).is_ok())
}

fn derive_fixture_coverage_summary(
    targets: &[FixtureCoverageTarget],
) -> Result<FixtureCoverageSummary, &'static str> {
    let target_count = u32::try_from(targets.len()).map_err(|_| INVALID_REPORT)?;
    let fixture_bearing_target_count = u32::try_from(
        targets
            .iter()
            .filter(|target| target.fixture_set_state == FixtureSetState::FixtureBearing)
            .count(),
    )
    .map_err(|_| INVALID_REPORT)?;
    let fixtureless_target_count = target_count
        .checked_sub(fixture_bearing_target_count)
        .ok_or(INVALID_REPORT)?;
    let mut covered = 0_u32;
    let mut missing = 0_u32;
    let mut not_applicable = 0_u32;
    let mut not_evaluated = 0_u32;
    for state in targets
        .iter()
        .flat_map(|target| target.requirements.iter())
        .map(FixtureRequirementCoverage::state)
    {
        match state {
            FixtureCoverageRequirementState::Covered => covered += 1,
            FixtureCoverageRequirementState::Missing => missing += 1,
            FixtureCoverageRequirementState::NotApplicable => not_applicable += 1,
            FixtureCoverageRequirementState::NotEvaluated => not_evaluated += 1,
        }
    }
    let total = covered
        .checked_add(missing)
        .and_then(|total| total.checked_add(not_applicable))
        .and_then(|total| total.checked_add(not_evaluated))
        .ok_or(INVALID_REPORT)?;
    Ok(FixtureCoverageSummary {
        target_set_state: if targets.is_empty() {
            FixtureCoverageTargetSetState::NoTargets
        } else {
            FixtureCoverageTargetSetState::TargetsPresent
        },
        target_count,
        fixture_bearing_target_count,
        fixtureless_target_count,
        requirements: FixtureCoverageRequirementCounts {
            covered,
            missing,
            not_applicable,
            not_evaluated,
            total,
        },
    })
}

fn generated_not_applicable_is_valid(
    recipe: GeneratorRecipeId,
    reason: GeneratedNotApplicableReason,
    invariant: CoverageInvariant,
) -> bool {
    match (reason, invariant) {
        (
            GeneratedNotApplicableReason::NoRemoteSourceCapability,
            CoverageInvariant::RemoteMutationRequiresRemoteSourceCapability,
        ) => matches!(
            recipe,
            GeneratorRecipeId::RequestAuthority
                | GeneratorRecipeId::RequestOrder
                | GeneratorRecipeId::StatusRejection
                | GeneratorRecipeId::ProtocolVerification
                | GeneratorRecipeId::MalformedDecode
                | GeneratorRecipeId::ByteCeiling
                | GeneratorRecipeId::Timeout
        ),
        (
            GeneratedNotApplicableReason::NoSourceInteraction,
            CoverageInvariant::MutationRequiresSourceInteraction,
        ) => true,
        (
            GeneratedNotApplicableReason::SingleSourceInteraction,
            CoverageInvariant::OrderMutationRequiresMultipleSourceInteractions,
        ) => recipe == GeneratorRecipeId::RequestOrder,
        (
            GeneratedNotApplicableReason::NoDistinguishableRequestPair,
            CoverageInvariant::OrderMutationRequiresDistinguishableSourceInteractions,
        ) => recipe == GeneratorRecipeId::RequestOrder,
        (
            GeneratedNotApplicableReason::NoGeneratedRequestMatcher,
            CoverageInvariant::ProtocolMutationRequiresGeneratedRequestMatcher,
        ) => recipe == GeneratorRecipeId::ProtocolVerification,
        (
            GeneratedNotApplicableReason::FinalResponseIsNotJsonObject,
            CoverageInvariant::MutationRequiresFinalJsonObjectResponse,
        ) => matches!(
            recipe,
            GeneratorRecipeId::ProtocolVerification | GeneratorRecipeId::OutputMinimization
        ),
        (
            GeneratedNotApplicableReason::IntegrationHasNoProductClaims,
            CoverageInvariant::AuthorizationCheckRequiresProductClaimEvaluation,
        ) => recipe == GeneratorRecipeId::AuthorizationBeforeSource,
        (
            GeneratedNotApplicableReason::SnapshotUsesClosedMaterialization,
            CoverageInvariant::SnapshotOutputUsesClosedMaterializationProjection,
        )
        | (
            GeneratedNotApplicableReason::ProtocolMatcherOwnsResponseMutation,
            CoverageInvariant::ProtocolMatcherFixtureUsesProtocolVerificationInstead,
        ) => recipe == GeneratorRecipeId::OutputMinimization,
        _ => false,
    }
}

pub(crate) const fn recipe_suffix(recipe: GeneratorRecipeId) -> &'static str {
    match recipe {
        GeneratorRecipeId::RequestAuthority => "request_authority",
        GeneratorRecipeId::RequestOrder => "request_order",
        GeneratorRecipeId::StatusRejection => "status_rejection",
        GeneratorRecipeId::MalformedDecode => "malformed_decode",
        GeneratorRecipeId::ByteCeiling => "byte_ceiling",
        GeneratorRecipeId::Timeout => "timeout",
        GeneratorRecipeId::ProtocolVerification => "protocol_verification",
        GeneratorRecipeId::AuthorizationBeforeSource => "authorization_before_source",
        GeneratorRecipeId::OutputMinimization => "output_minimization",
    }
}

pub(crate) const fn change_suffix(kind: FixtureCoverageChangeKind) -> &'static str {
    match kind {
        FixtureCoverageChangeKind::ChangedInput => "changed-input",
        FixtureCoverageChangeKind::ChangedOutput => "changed-output",
        FixtureCoverageChangeKind::ChangedClaim => "changed-claim",
        FixtureCoverageChangeKind::ChangedSourceContract => "changed-source-contract",
    }
}

fn is_report_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 256
        && matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_sorted_unique_identifiers(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| is_report_identifier(value))
}

fn is_evidence_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 800
        && !value.contains("//")
        && matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

#[derive(Clone, Debug)]
pub(crate) struct GeneratedFixtureObservation {
    pub integration: String,
    pub source_fixture_id: String,
    pub recipe_id: GeneratorRecipeId,
    pub actual_safe_code: Option<FixtureSafeCode>,
    pub pass_state: FixturePassState,
    pub actual_source_calls: Option<u32>,
}
