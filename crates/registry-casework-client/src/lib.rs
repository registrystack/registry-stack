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
    CaseworkAuth, CaseworkComplete, OwnReviewDecisionQuery, ReviewPageQuery, ReviewResultResponse,
    ReviewTaskDecisionRequest, ReviewTaskQuery, SupervisoryReviewTaskQuery, WorkItemHistoryQuery,
};
pub use registry_casework_core::{
    submission_digest, AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery,
    ActivityClockAnchor, AssignmentContext, AssignmentRequest, AttemptState, AttemptStatus,
    BootstrapDirectoryRequest, CalendarPolicy, CallerSubjectView, CaseloadApplyRequest,
    CaseloadItemOutcome, CaseloadItemResult, CaseloadItemSelection, CaseloadMoveRequest,
    CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkAction, ClaimRequest, ClockNextEffect,
    ClockOccurrenceView, ClockPolicy, ClockReassignment, ClockRecomputeApplyRequest,
    ClockRecomputeChange, ClockRecomputePreview, ClockRecomputeRequest, ClockRecomputeResult,
    ClockReminder, ClockRuntimeState, ClockStep, ClockStepAction, ClockStepInstant, ContentDigest,
    CorrectionRoutingCopy, DecideRequest, DelegateRequest, Description, DirectoryMember,
    DirectoryResponse, DirectoryTargetPage, DirectoryTargetPurpose, DirectoryTargetsQuery,
    DirectoryTeamUpdateRequest, DisplayReferencePolicy, Draft, DraftResponse, EqualsPredicate,
    HistoryEntry, HistoryKind, HistoryPage, HoldingSummary, HoldingsPage, HoldingsQuery,
    HolidaySetDocument, HolidaySetRevisionInput, HumanIdentity, InboxSort, InboxView,
    IssuerPrincipal, ListWorkItemsQuery, MutationResponse, NextWorkItemQuery, OccurrenceKind,
    OccurrenceState, OneOfPredicate, OperationName, OwnReviewDecision, OwnReviewDecisionPage, Page,
    PageStatus, PolicyBinding, QueueRecord, RecoverAttemptRequest, ReleaseRequest,
    ReviewAccountabilityRecord, ReviewCancelRequest, ReviewCancelResponse, ReviewClockOccurrence,
    ReviewCompletion, ReviewCompletionType, ReviewContext, ReviewCreateRequest,
    ReviewDecisionReceipt, ReviewDecisionType, ReviewHistoryAudience, ReviewHistoryEntry,
    ReviewHistoryPage, ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewRequestAccepted,
    ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
    ReviewResultFeedPage, ReviewResultStatus, ReviewSourceBindingStatus, ReviewSourceProjection,
    ReviewTaskContext, ReviewTaskContextData, ReviewTaskDraft, ReviewTaskDraftInput,
    ReviewTaskOwnership, ReviewTaskPage, ReviewValidationError, ReviewValidationReason,
    ReviewerDecisionKind, ReviewerTask, ReviewerTaskState, RoutingActivity, RoutingCondition,
    RoutingPredicate, RoutingRule, SaveDraftRequest, SchedulingTaskPermission, SourceBinding,
    SourceContextBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy, StaffingDiagnostic,
    SubjectClockAnchor, SubjectClockCompletion, SubjectClockPause, SubjectRef, SubmissionDigest,
    SupervisoryReviewTask, SupervisoryReviewTaskPage, SupervisoryReviewTaskState,
    TaskApprovalRequest, TaskAssertionResponse, TaskAuthorizationMode, TaskGrantBounds,
    TaskGrantList, TaskGrantRevocation, TaskGrantStatus, TaskGrantStatusDetails, TaskGrantView,
    TaskPermission, TaskTemplatePreview, TaskTemplatePreviews, TeamRecord, WorkItem, WorkItemPage,
    WorkItemRouting, WorkingDaysAfter, WorkingDaysBefore, WorkingWeekday,
};
pub use registry_platform_httputil::client::BearerToken;
pub use registry_review_client::ReviewMutationErrorClass;
pub use task_assertion_source::CaseworkTaskAssertionSource;
/// The identifier type every item, attempt, and event argument carries, so a
/// caller names it through this crate rather than a second `uuid` dependency.
pub use uuid::Uuid;
