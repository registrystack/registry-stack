// SPDX-License-Identifier: Apache-2.0
//! Canonical, bounded client for Registry Casework.
//!
//! Mutating calls carry a caller-supplied idempotency key; the client never
//! generates one. A keyed mutation whose outcome is unknown (a timeout or
//! broken exchange after the request was sent, or a 5xx answer) is resent,
//! byte for byte and under the same key, at most
//! `CaseworkClientConfig::with_max_mutation_retries` times (2 by default, 0
//! disables it). Reads, unkeyed operations, and the review request create and
//! cancel calls are never resent. A 5xx answer may follow a commit: when
//! `CaseworkClientError::is_outcome_unknown` is still true, the safe recovery
//! is the same request under the same key, never a new key.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;
mod task_assertion_source;

pub use client::CaseworkClient;
pub use config::CaseworkClientConfig;
pub use error::{CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure};
pub use model::{
    CaseworkAuth, CaseworkComplete, OwnReviewDecisionQuery, ReviewPageQuery,
    ReviewResultObservation, ReviewResultResponse, SupervisoryReviewTaskQuery,
};
pub use registry_casework_core::{
    submission_digest, AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, AssignmentRequest,
    BootstrapDirectoryRequest, CalendarPolicy, ClockNextEffect, ClockPolicy, ClockReassignment,
    ClockReminder, ClockRuntimeState, ClockStep, ClockStepAction, ClockStepInstant, ContentDigest,
    Decision, DecisionKind, DelegateRequest, Description, DirectoryMember, DirectoryResponse,
    DirectoryTargetPage, DirectoryTargetPurpose, DirectoryTargetsQuery, DirectoryTeamUpdateRequest,
    ElapsedDuration, EqualsPredicate, HolidaySetDocument, HolidaySetRevisionInput, HumanIdentity,
    IssuerPrincipal, OneOfPredicate, OwnReviewDecision, OwnReviewDecisionPage, Page, PageStatus,
    PolicyBinding, PolicySelection, QueueRecord, ReviewAccountabilityRecord, ReviewCancelRequest,
    ReviewCancelResponse, ReviewCaseloadApplyRequest, ReviewCaseloadMoveRequest,
    ReviewCaseloadPreview, ReviewCaseloadResult, ReviewCaseloadTask, ReviewClockOccurrence,
    ReviewClockRecomputeApplyRequest, ReviewClockRecomputePreview, ReviewClockRecomputeRequest,
    ReviewClockRecomputeResult, ReviewClockRecomputeTask, ReviewCompletion, ReviewCompletionType,
    ReviewContext, ReviewContextCapability, ReviewContextContract, ReviewContextPolicy,
    ReviewContextProviderPolicy, ReviewCreateRequest, ReviewDecisionReceipt, ReviewDecisionType,
    ReviewHistoryAudience, ReviewHistoryEntry, ReviewHistoryPage, ReviewNoteRequest, ReviewPolicy,
    ReviewPolicyClosure, ReviewPolicyDependencies, ReviewPurpose, ReviewRequestAccepted,
    ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
    ReviewResultFeedPage, ReviewResultStatus, ReviewSourceBindingStatus, ReviewSourceProjection,
    ReviewStaffingQuery, ReviewTask, ReviewTaskContext, ReviewTaskContextData,
    ReviewTaskDecisionRequest, ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskOwnership,
    ReviewTaskPage, ReviewTaskSort, ReviewTaskState, ReviewValidationError, ReviewValidationReason,
    RoutingCondition, RoutingPredicate, RoutingRule, SchedulingTaskPermission,
    SourceContextBinding, StaffingDiagnostic, StageClockAnchor, StageClockAnchorType,
    SubjectBinding, SubjectClockAnchor, SubjectClockAnchorType, SubmissionDigest,
    SupervisoryReviewTask, SupervisoryReviewTaskPage, SupervisoryReviewTaskState,
    TaskApprovalRequest, TaskAssertionResponse, TaskAuthorizationMode, TaskGrantBounds,
    TaskGrantList, TaskGrantRevocation, TaskGrantStatus, TaskGrantStatusDetails, TaskGrantView,
    TaskPermission, TaskTemplatePreview, TaskTemplatePreviews, TeamRecord, WorkingDays,
    WorkingDaysBefore, WorkingWeekday,
};
pub use registry_platform_httputil::client::BearerToken;
pub use registry_review_client::ReviewMutationErrorClass;
pub use task_assertion_source::CaseworkTaskAssertionSource;
/// The identifier type every task, request, and event argument carries, so a
/// caller names it through this crate rather than a second `uuid` dependency.
pub use uuid::Uuid;
