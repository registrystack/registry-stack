//! Curated Rust client facade for Registry Stack products.
//!
//! Each product remains in its own module so route, authentication, error,
//! record, and verification contracts cannot be mistaken for one another.

pub mod breg {
    pub use registry_breg_client::{
        occurrence_view, occurrence_view_from_json, verify_hook_delivery, BRegActionBinding,
        BRegActionBounds, BRegActionDescriptor, BRegActionError, BRegActionInputBinding,
        BRegActionInputDescriptor, BRegActionInvocationRequest, BRegActionMode, BRegActionReceipt,
        BRegActionReferenceInputDescriptor, BRegActionResultEffectDescriptor,
        BRegActionResultReference, BRegActionTargetConditions, BRegActionTargetConditionsRequest,
        BRegAvailability, BRegAvailabilityReason, BRegComplete, BRegContinuation,
        BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest, BRegCreationRevision,
        BRegDirectWrite, BRegEtag, BRegHookDelivery, BRegHookVerificationError, BRegIdempotencyKey,
        BRegListRequest, BRegLookupRequest, BRegMetadata, BRegMetadataOperation,
        BRegMetadataSelectionError, BRegMutationRequestError, BRegOccurrenceDescriptor,
        BRegOccurrenceError, BRegOccurrenceEvidence, BRegOccurrenceView, BRegOperationKind,
        BRegPage, BRegPatchBinding, BRegPatchBuilder, BRegPatchRequest, BRegPreparedAction,
        BRegPreparedCreate, BRegPreparedProposal, BRegProbeStatus, BRegProblemCode, BRegProposal,
        BRegProposalApplication, BRegProposalAttachment, BRegProposalAttachmentValue,
        BRegProposalCollection, BRegProposalDecision, BRegProposalDecisionStatus,
        BRegProposalGetBinding, BRegProposalLink, BRegProposalPage, BRegProposalQuery,
        BRegProposalResultReference, BRegProposalReviewBinding, BRegProposalReviewContext,
        BRegProposalReviewDocument, BRegProposalReviewResult, BRegProposalReviewSubject,
        BRegProposalState, BRegProposalSubmission, BRegProposalSubmissionApplication,
        BRegProposalTurn, BRegProtocolFailure, BRegRawDocument, BRegRecordFormat,
        BRegRecordOptions, BRegRecoveryHint, BRegRequestError, BRegResponseMetadata,
        BRegVerifiedHookDelivery, BaseRegistryClient, BaseRegistryClientConfig,
        BaseRegistryClientError, PolicySelection, Uuid, OCCURRENCE_DESCRIPTOR_VERSION,
        OCCURRENCE_VIEW_CONTRACT,
    };
}

pub mod casework {
    pub use registry_casework_client::{
        accepted_binding, submission_digest, AbsenceInput, AbsenceList, AbsenceRecord,
        AbsencesQuery, AcceptedBindingValidation, AssignmentRequest, BearerToken,
        BootstrapDirectoryRequest, CalendarPolicy, CaseworkAuth, CaseworkClient,
        CaseworkClientConfig, CaseworkClientError, CaseworkComplete, CaseworkProblemCode,
        CaseworkProtocolFailure, CaseworkTaskAssertionSource, ClockNextEffect, ClockPolicy,
        ClockReassignment, ClockReminder, ClockRuntimeState, ClockStep, ClockStepAction,
        ClockStepInstant, ContentDigest, Decision, DecisionKind, DelegateRequest, Description,
        DirectoryMember, DirectoryResponse, DirectoryTargetPage, DirectoryTargetPurpose,
        DirectoryTargetsQuery, DirectoryTeamUpdateRequest, ElapsedDuration, EqualsPredicate,
        HolidaySetDocument, HolidaySetRevisionInput, HumanIdentity, IssuerPrincipal,
        OneOfPredicate, OwnReviewDecision, OwnReviewDecisionPage, OwnReviewDecisionQuery, Page,
        PageStatus, PolicyBinding, PolicySelection, QueueRecord, ReviewAccountabilityRecord,
        ReviewCancelRequest, ReviewCancelResponse, ReviewCaseloadApplyRequest,
        ReviewCaseloadMoveRequest, ReviewCaseloadPreview, ReviewCaseloadResult, ReviewCaseloadTask,
        ReviewClockOccurrence, ReviewClockRecomputeApplyRequest, ReviewClockRecomputePreview,
        ReviewClockRecomputeRequest, ReviewClockRecomputeResult, ReviewClockRecomputeTask,
        ReviewCompletion, ReviewCompletionType, ReviewContext, ReviewContextCapability,
        ReviewContextContract, ReviewContextPolicy, ReviewContextProviderPolicy,
        ReviewCreateRequest, ReviewDecisionReceipt, ReviewDecisionType, ReviewHistoryAudience,
        ReviewHistoryEntry, ReviewHistoryPage, ReviewMutationErrorClass,
        ReviewNegativeDecisionMode, ReviewNoteRequest, ReviewPageQuery, ReviewPolicy,
        ReviewPolicyClosure, ReviewPolicyDependencies, ReviewPurpose, ReviewRequestAccepted,
        ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
        ReviewResultFeedPage, ReviewResultObservation, ReviewResultResponse, ReviewResultStatus,
        ReviewSourceBindingStatus, ReviewSourceProjection, ReviewStaffingQuery, ReviewStagePolicy,
        ReviewTask, ReviewTaskContext, ReviewTaskContextData, ReviewTaskDecisionRequest,
        ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskOwnership, ReviewTaskPage, ReviewTaskSort,
        ReviewTaskState, ReviewValidationError, ReviewValidationReason, RoutingCondition,
        RoutingPredicate, RoutingRule, SchedulingTaskPermission, SourceContextBinding,
        StaffingDiagnostic, StageClockAnchor, StageClockAnchorType, SubjectBinding,
        SubjectClockAnchor, SubjectClockAnchorType, SubmissionDigest, SupervisoryReviewTask,
        SupervisoryReviewTaskPage, SupervisoryReviewTaskQuery, SupervisoryReviewTaskState,
        TaskApprovalRequest, TaskAssertionResponse, TaskAuthorizationMode, TaskGrantBounds,
        TaskGrantList, TaskGrantRevocation, TaskGrantStatus, TaskGrantStatusDetails, TaskGrantView,
        TaskPermission, TaskTemplatePreview, TaskTemplatePreviews, TeamRecord, Uuid, WorkingDays,
        WorkingDaysBefore, WorkingWeekday,
    };
}

pub mod messaging {
    pub use registry_messaging_client::{
        type_uri, AttemptOutcome, AttemptSummary, BearerToken, Channel, DirectContent,
        MessageDispatch, MessageLinks, MessageReceipt, MessageReport, MessageStatus, MessageView,
        MessagingClient, MessagingClientConfig, MessagingClientError, MessagingComplete,
        MessagingProtocolFailure, ProblemCode, Recipient, RenderedParts, SegmentCount, SmsEncoding,
        SubmitMessageRequest, TemplatePreview, TemplatePreviewRequest, TemplateReference,
        TransportKind, HEALTH_PATH, IDEMPOTENCY_KEY_HEADER, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
        MAXIMUM_RETRY_AFTER_SECONDS, MESSAGES_PATH, MESSAGE_CANCEL_PATH, MESSAGE_PATH,
        MESSAGE_RECEIPT_PATH, MESSAGING_PROBLEM_TYPE_BASE, READY_PATH, TEMPLATE_PREVIEW_PATH,
    };
}

pub mod scheduling {
    pub use registry_scheduling_client::{
        render_icalendar, type_uri, AdditionalAllocationRequest, AdmissionRequest,
        AllocationDocument, AllocationRequirementDocument, AppointmentDocument,
        AppointmentHistoryEntryDocument, AppointmentStateDocument, AttendanceDocument,
        AttendanceState, AvailabilityEntry, AvailabilityPreviewDocument,
        AvailabilityPreviewRequest, AvailabilitySelection, BearerToken, BusyApplyOutcome,
        BusyApplyOutcomeKind, BusyCommitmentImpact, BusyCoverage, BusyImpactSummary,
        BusyIntervalInput, BusyReconciliationPreview, BusyReconciliationRequest,
        BusyRequestValidationError, BusySourceStatus, CalendarEvent, CalendarExportError,
        CancelAppointmentRequest, CreateAppointmentRequest, ExplainDocument, ExternalReference,
        HoldDocument, LocationDocument, ManagerSelection, OfferingDocument,
        OperationalAllocationDocument, OperationalAppointmentDocument, OperationalAppointmentQuery,
        OperationalTimeBasis, PageDocument, PartyCounts, PartyCountsRequirement, PartyReference,
        PartyReferenceRole, ProblemCode, RecordAttendanceRequest, ReminderDocument,
        RescheduleAppointmentRequest, ResourceDocument, SchedulingAuth, SchedulingClient,
        SchedulingClientConfig, SchedulingClientError, SchedulingComplete, SchedulingModeDocument,
        SchedulingProtocolFailure, SchedulingServiceDocument, ServiceDocument, TransportKind,
        WindowDocument, APPOINTMENTS_PATH, APPOINTMENT_RECEIPT_PATH, AVAILABILITY_EXPLAIN_PATH,
        AVAILABILITY_PATH, AVAILABILITY_PREVIEW_PATH, BUSY_SOURCE_APPLY_PATH,
        BUSY_SOURCE_PREVIEW_PATH, CURSOR_QUERY_PARAMETER, HOLDS_PATH, IDEMPOTENCY_KEY_HEADER,
        LIMIT_QUERY_PARAMETER, LOCATIONS_PATH, MAXIMUM_BOOKING_DURATION_MINUTES,
        MAXIMUM_CALENDAR_EVENTS, MAXIMUM_IDEMPOTENCY_KEY_BYTES, OFFERINGS_PATH,
        OPERATIONAL_APPOINTMENTS_PATH, RESOURCES_PATH, SCHEDULING_PATH,
        SCHEDULING_PROBLEM_TYPE_BASE, SERVICES_PATH,
    };
}

pub mod discovery {
    pub use registry_discovery_client::{
        accept_service_selection, renew_unchanged_service_selection, AcceptedServiceSelection,
        DiscoveryClient, DiscoveryClientConfig, DiscoveryClientError, DiscoveryProblem,
        EvidenceResolutionContext, EvidenceSelectionRequest, EvidenceServiceQuery,
        EvidenceServiceSelection, MatchedCapability, SelectionRequest, ServiceKind, ServiceRecord,
        ServiceSearchResponse, ServiceSelection,
    };
}

pub mod evidence {
    pub use registry_evidence_client::{
        AssuranceProfile, AudienceScopedRequest, AudienceScopedResult, EvidenceClient,
        EvidenceClientConfig, EvidenceClientError, EvidenceRequestBatchItemSpec,
        EvidenceRequestBatchSpec, EvidenceRequestSpec, EvidenceResponseFormat,
        HolderBoundRequestSpec, HolderPublicKey, NonVerifyingEvidenceClient,
        PreparedEvidenceRequest, PreparedEvidenceRequestBatch, PreparedHolderBoundRequest,
        ProgressivePreparedRequest, RawEvidenceRequestBatchResponse, RawEvidenceResponse,
        RetainedEvidenceVerification, SelectorValue, SubjectBindingReceipt, SubjectContinuity,
        SubjectExpectations, SubjectRequest, TrustProfile, VerificationError, VerificationProfile,
        VerifiedAssertion, VerifiedAudienceScopedCredential, VerifiedAudienceScopedEvidence,
        VerifiedEvidence, VerifiedEvidenceRequestBatch,
    };
}

pub mod record {
    pub use registry_record::{
        RegistryRecord, RegistryRecordCollectionResponse, RegistryRecordDecodeError,
        RegistryRecordJsonLdContext, RegistryRecordMeta, RegistryRecordPageInfo,
        RegistryRecordRepresentation, RegistryRecordResponse, RegistryRecordSingleResponse,
        REGISTRY_RECORD_CONTEXT_IDENTIFIER, REGISTRY_RECORD_PROFILE_IDENTIFIER,
        REGISTRY_RECORD_SCHEMA_IDENTIFIER,
    };
}

pub mod auth {
    pub use registry_platform_httputil::client::{
        BearerToken, OAuthErrorCode, PrivateKeyJwt, PrivateKeyJwtConfig, StaticToken, TokenError,
        TokenProvider, MAXIMUM_TRUSTED_ROOT_CERTIFICATE_BUNDLE_BYTES,
    };
}

pub use registry_coordinator_client as coordinator;
pub use registry_render_client as render;
