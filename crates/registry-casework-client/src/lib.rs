// SPDX-License-Identifier: Apache-2.0
//! Canonical, bounded client for Registry Casework.

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
    CaseworkAuth, CaseworkComplete, ReviewPageQuery, ReviewResultResponse,
    ReviewTaskDecisionRequest, ReviewTaskQuery, WorkItemHistoryQuery,
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
    OccurrenceState, OneOfPredicate, OperationName, Page, PageStatus, PolicyBinding, QueueRecord,
    RecoverAttemptRequest, ReleaseRequest, ReviewAccountabilityRecord, ReviewCancelRequest,
    ReviewCancelResponse, ReviewCompletion, ReviewCompletionType, ReviewContext,
    ReviewCreateRequest, ReviewHistoryAudience, ReviewHistoryEntry, ReviewHistoryPage,
    ReviewKindPolicySnapshot, ReviewNoteRequest, ReviewRequestAccepted, ReviewRequestLifecycle,
    ReviewRequestView, ReviewResult, ReviewResultFeedEntry, ReviewResultFeedPage,
    ReviewResultStatus, ReviewSourceBindingStatus, ReviewSourceProjection, ReviewTaskContext,
    ReviewTaskContextData, ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskPage,
    ReviewValidationError, ReviewValidationReason, ReviewerDecisionKind, ReviewerTask,
    ReviewerTaskState, RoutingActivity, RoutingCondition, RoutingPredicate, RoutingRule,
    SaveDraftRequest, SourceBinding, SourceContextBinding, SourcePolicy, SourceReceipt,
    SourceRequestPolicy, StaffingDiagnostic, SubjectClockAnchor, SubjectClockCompletion,
    SubjectClockPause, SubjectRef, SubmissionDigest, TaskApprovalRequest, TaskAssertionResponse,
    TaskGrantBounds, TaskGrantList, TaskGrantRevocation, TaskGrantStatus, TaskGrantStatusDetails,
    TaskGrantView, TaskPermission, TaskTemplatePreview, TaskTemplatePreviews, TeamRecord, WorkItem,
    WorkItemPage, WorkItemRouting, WorkingDaysAfter, WorkingDaysBefore, WorkingWeekday,
};
pub use registry_platform_httputil::client::BearerToken;
pub use task_assertion_source::CaseworkTaskAssertionSource;
/// The identifier type every item, attempt, and event argument carries, so a
/// caller names it through this crate rather than a second `uuid` dependency.
pub use uuid::Uuid;
