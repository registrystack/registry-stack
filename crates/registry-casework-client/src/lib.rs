// SPDX-License-Identifier: Apache-2.0
//! Canonical, bounded client for Registry Casework.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::CaseworkClient;
pub use config::CaseworkClientConfig;
pub use error::{CaseworkClientError, CaseworkProblemCode, CaseworkProtocolFailure};
pub use model::{CaseworkAuth, CaseworkComplete};
pub use registry_casework_core::{
    AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, ActivityClockAnchor,
    AssignmentContext, AssignmentRequest, AttemptState, AttemptStatus, BootstrapDirectoryRequest,
    CalendarPolicy, CallerSubjectView, CaseloadApplyRequest, CaseloadItemOutcome,
    CaseloadItemResult, CaseloadItemSelection, CaseloadMoveRequest, CaseloadPreviewPage,
    CaseloadPreviewQuery, CaseworkAction, ClaimRequest, ClockNextEffect, ClockOccurrenceView,
    ClockPolicy, ClockReassignment, ClockRecomputeApplyRequest, ClockRecomputeChange,
    ClockRecomputePreview, ClockRecomputeRequest, ClockRecomputeResult, ClockReminder,
    ClockRuntimeState, ClockStep, ClockStepAction, ClockStepInstant, CorrectionRoutingCopy,
    DecideRequest, DelegateRequest, Description, DirectoryMember, DirectoryResponse,
    DirectoryTargetPage, DirectoryTargetPurpose, DirectoryTargetsQuery, DirectoryTeamUpdateRequest,
    DisplayReferencePolicy, Draft, DraftResponse, EqualsPredicate, HistoryEntry, HistoryKind,
    HistoryPage, HoldingSummary, HoldingsPage, HoldingsQuery, HolidaySetDocument,
    HolidaySetRevisionInput, HostedAccountabilityRecord, HostedCancelRequest, HostedCreateRequest,
    HostedDecisionRequest, HostedHistoryEntry, HostedHistoryKind, HostedHistoryPage,
    HostedKindPolicy, HostedNote, HostedNotePage, HostedNoteRequest, HostedOutcomePolicy,
    HostedPageQuery, HostedTerminalPage, HostedTerminalQuery, HostedTerminalResult,
    HostedTerminalState, HostedValidationError, HostedValidationReason, HostedWorkItemContext,
    InboxSort, InboxView, IssuerPrincipal, ListWorkItemsQuery, MutationResponse, NextWorkItemQuery,
    OccurrenceKind, OccurrenceState, OneOfPredicate, OpaqueActorRef, OperationName, Page,
    PageStatus, QueueRecord, RecoverAttemptRequest, ReleaseRequest, RequesterHostedItem,
    RoutingActivity, RoutingCondition, RoutingPredicate, RoutingRule, SaveDraftRequest,
    SourceBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy, StaffingDiagnostic,
    SubjectClockAnchor, SubjectClockCompletion, SubjectClockPause, SubjectRef, TaskApprovalRequest,
    TaskAssertionResponse, TaskGrantBounds, TaskGrantList, TaskGrantRevocation, TaskGrantStatus,
    TaskGrantStatusDetails, TaskGrantView, TaskPermission, TaskTemplatePreview,
    TaskTemplatePreviews, TeamRecord, WorkItem, WorkItemPage, WorkItemRouting, WorkingDaysAfter,
    WorkingDaysBefore, WorkingWeekday,
};
pub use registry_platform_httputil::client::BearerToken;
/// The identifier type every item, attempt, and event argument carries, so a
/// caller names it through this crate rather than a second `uuid` dependency.
pub use uuid::Uuid;
