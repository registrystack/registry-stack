//! Curated Rust client facade for Registry Stack products.
//!
//! Each product remains in its own module so route, authentication, error,
//! record, and verification contracts cannot be mistaken for one another.

pub mod breg {
    pub use registry_breg_client::{
        verify_webhook_delivery, BRegActionInvocationRequest, BRegActionReceipt,
        BRegActionResultReference, BRegActionTargetConditions, BRegActionTargetConditionsRequest,
        BRegAttachmentClassification, BRegAttachmentError, BRegAttachmentSlot,
        BRegAttachmentSlotValue, BRegAttachmentState, BRegAttachmentUpload,
        BRegAttachmentVerificationStatus, BRegComplete, BRegContinuation,
        BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest, BRegDirectWrite,
        BRegEtag, BRegIdempotencyKey, BRegImmediateActionBinding, BRegImmediateActionError,
        BRegLifecycleAction, BRegLifecycleActionReceipt, BRegLifecycleAuthority,
        BRegLifecycleOperation, BRegListRequest, BRegLookupRequest, BRegMetadata,
        BRegMetadataSelectionError, BRegMutationRequestError, BRegOperationKind, BRegPage,
        BRegPatchBinding, BRegPatchBuilder, BRegPatchRequest, BRegPlanRefusal, BRegPreparedAction,
        BRegPreparedCreate, BRegPreparedLifecycle, BRegProbeStatus, BRegProblemCode,
        BRegProtocolFailure, BRegRawDocument, BRegRecordFormat, BRegRecordOptions,
        BRegRequestError, BRegRequestMetadata, BRegRequestResultReference, BRegResponseMetadata,
        BRegRetainedRequestHistoryPage, BRegRetainedRequestProposal, BRegVerifiedWebhookDelivery,
        BRegWebhookDelivery, BRegWebhookVerificationError, BaseRegistryClient,
        BaseRegistryClientConfig, BaseRegistryClientError, Uuid,
    };
}

pub mod casework {
    pub use registry_casework_client::{
        submission_digest, AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery,
        ActivityClockAnchor, AssignmentContext, AssignmentRequest, AttemptState, AttemptStatus,
        BearerToken, BootstrapDirectoryRequest, CalendarPolicy, CallerSubjectView,
        CaseloadApplyRequest, CaseloadItemOutcome, CaseloadItemResult, CaseloadItemSelection,
        CaseloadMoveRequest, CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkAction,
        CaseworkAuth, CaseworkClient, CaseworkClientConfig, CaseworkClientError, CaseworkComplete,
        CaseworkProblemCode, CaseworkProtocolFailure, CaseworkTaskAssertionSource, ClaimRequest,
        ClockNextEffect, ClockOccurrenceView, ClockPolicy, ClockReassignment,
        ClockRecomputeApplyRequest, ClockRecomputeChange, ClockRecomputePreview,
        ClockRecomputeRequest, ClockRecomputeResult, ClockReminder, ClockRuntimeState, ClockStep,
        ClockStepAction, ClockStepInstant, ContentDigest, CorrectionRoutingCopy, DecideRequest,
        DelegateRequest, Description, DirectoryMember, DirectoryResponse, DirectoryTargetPage,
        DirectoryTargetPurpose, DirectoryTargetsQuery, DirectoryTeamUpdateRequest,
        DisplayReferencePolicy, Draft, DraftResponse, EqualsPredicate, HistoryEntry, HistoryKind,
        HistoryPage, HoldingSummary, HoldingsPage, HoldingsQuery, HolidaySetDocument,
        HolidaySetRevisionInput, HumanIdentity, InboxSort, InboxView, IssuerPrincipal,
        ListWorkItemsQuery, MutationResponse, NextWorkItemQuery, OccurrenceKind, OccurrenceState,
        OneOfPredicate, OperationName, Page, PageStatus, PolicyBinding, QueueRecord,
        RecoverAttemptRequest, ReleaseRequest, ReviewAccountabilityRecord, ReviewCancelRequest,
        ReviewCancelResponse, ReviewClockOccurrence, ReviewCompletion, ReviewCompletionType,
        ReviewContext, ReviewCreateRequest, ReviewDecisionReceipt, ReviewDecisionType,
        ReviewHistoryAudience, ReviewHistoryEntry, ReviewHistoryPage, ReviewKindPolicySnapshot,
        ReviewMutationErrorClass, ReviewNoteRequest, ReviewPageQuery, ReviewRequestAccepted,
        ReviewRequestLifecycle, ReviewRequestView, ReviewResult, ReviewResultFeedEntry,
        ReviewResultFeedPage, ReviewResultResponse, ReviewResultStatus, ReviewSourceBindingStatus,
        ReviewSourceProjection, ReviewTaskContext, ReviewTaskContextData,
        ReviewTaskDecisionRequest, ReviewTaskDraft, ReviewTaskDraftInput, ReviewTaskOwnership,
        ReviewTaskPage, ReviewTaskQuery, ReviewValidationError, ReviewValidationReason,
        ReviewerDecisionKind, ReviewerTask, ReviewerTaskState, RoutingActivity, RoutingCondition,
        RoutingPredicate, RoutingRule, SaveDraftRequest, SchedulingTaskPermission, SourceBinding,
        SourceContextBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy, StaffingDiagnostic,
        SubjectClockAnchor, SubjectClockCompletion, SubjectClockPause, SubjectRef,
        SubmissionDigest, SupervisoryReviewTask, SupervisoryReviewTaskPage,
        SupervisoryReviewTaskQuery, SupervisoryReviewTaskState, TaskApprovalRequest,
        TaskAssertionResponse, TaskGrantBounds, TaskGrantList, TaskGrantRevocation,
        TaskGrantStatus, TaskGrantStatusDetails, TaskGrantView, TaskPermission,
        TaskTemplatePreview, TaskTemplatePreviews, TeamRecord, Uuid, WorkItem,
        WorkItemHistoryQuery, WorkItemPage, WorkItemRouting, WorkingDaysAfter, WorkingDaysBefore,
        WorkingWeekday,
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
        MESSAGING_PROBLEM_TYPE_BASE, READY_PATH, TEMPLATE_PREVIEW_PATH,
    };
}

pub mod scheduling {
    pub use registry_scheduling_client::{
        type_uri, AdmissionRequest, AppointmentDocument, AppointmentHistoryEntryDocument,
        AppointmentStateDocument, AvailabilityEntry, BearerToken, CancelAppointmentRequest,
        CreateAppointmentRequest, ExplainDocument, ExternalReference, HoldDocument,
        LocationDocument, OfferingDocument, PageDocument, PartyCounts, ProblemCode,
        ReminderDocument, RescheduleAppointmentRequest, ResourceDocument, SchedulingAuth,
        SchedulingClient, SchedulingClientConfig, SchedulingClientError, SchedulingComplete,
        SchedulingModeDocument, SchedulingProtocolFailure, SchedulingServiceDocument,
        ServiceDocument, TransportKind, WindowDocument, APPOINTMENTS_PATH,
        AVAILABILITY_EXPLAIN_PATH, AVAILABILITY_PATH, CURSOR_QUERY_PARAMETER, HOLDS_PATH,
        IDEMPOTENCY_KEY_HEADER, LIMIT_QUERY_PARAMETER, LOCATIONS_PATH,
        MAXIMUM_IDEMPOTENCY_KEY_BYTES, OFFERINGS_PATH, RESOURCES_PATH, SCHEDULING_PATH,
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
