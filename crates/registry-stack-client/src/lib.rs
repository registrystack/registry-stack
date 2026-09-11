//! Curated Rust client facade for Registry Stack products.
//!
//! Each product remains in its own module so route, authentication, error,
//! record, and verification contracts cannot be mistaken for one another.

pub mod breg {
    pub use registry_breg_client::{
        BRegAttachmentClassification, BRegAttachmentError, BRegAttachmentSlot,
        BRegAttachmentSlotValue, BRegAttachmentState, BRegAttachmentUpload,
        BRegAttachmentVerificationStatus, BRegComplete, BRegContinuation,
        BRegContinuationProjection, BRegCreateBinding, BRegCreateRequest, BRegDirectWrite,
        BRegEtag, BRegIdempotencyKey, BRegLifecycleAction, BRegLifecycleActionReceipt,
        BRegLifecycleAuthority, BRegLifecycleOperation, BRegListRequest, BRegLookupRequest,
        BRegMetadata, BRegMetadataSelectionError, BRegMutationRequestError, BRegOperationKind,
        BRegPage, BRegPatchBinding, BRegPatchBuilder, BRegPatchRequest, BRegPlanRefusal,
        BRegProbeStatus, BRegProblemCode, BRegProtocolFailure, BRegRawDocument, BRegRecordFormat,
        BRegRecordOptions, BRegRequestError, BRegResponseMetadata, BaseRegistryClient,
        BaseRegistryClientConfig, BaseRegistryClientError, Uuid,
    };
}

pub mod casework {
    pub use registry_casework_client::{
        AbsenceInput, AbsenceList, AbsenceRecord, AbsencesQuery, ActivityClockAnchor,
        AssignmentContext, AssignmentRequest, AttemptState, AttemptStatus, BearerToken,
        BootstrapDirectoryRequest, CalendarPolicy, CallerSubjectView, CaseloadApplyRequest,
        CaseloadItemOutcome, CaseloadItemResult, CaseloadItemSelection, CaseloadMoveRequest,
        CaseloadPreviewPage, CaseloadPreviewQuery, CaseworkAction, CaseworkAuth, CaseworkClient,
        CaseworkClientConfig, CaseworkClientError, CaseworkComplete, CaseworkProblemCode,
        CaseworkProtocolFailure, ClaimRequest, ClockNextEffect, ClockOccurrenceView, ClockPolicy,
        ClockReassignment, ClockRecomputeApplyRequest, ClockRecomputeChange, ClockRecomputePreview,
        ClockRecomputeRequest, ClockRecomputeResult, ClockReminder, ClockRuntimeState, ClockStep,
        ClockStepAction, ClockStepInstant, CorrectionRoutingCopy, DecideRequest, DelegateRequest,
        Description, DirectoryMember, DirectoryResponse, DirectoryTargetPage,
        DirectoryTargetPurpose, DirectoryTargetsQuery, DirectoryTeamUpdateRequest,
        DisplayReferencePolicy, Draft, DraftResponse, EqualsPredicate, HistoryEntry, HistoryKind,
        HistoryPage, HoldingSummary, HoldingsPage, HoldingsQuery, HolidaySetDocument,
        HolidaySetRevisionInput, HostedAccountabilityRecord, HostedCancelRequest,
        HostedCreateRequest, HostedDecisionRequest, HostedHistoryEntry, HostedHistoryKind,
        HostedHistoryPage, HostedKindPolicy, HostedNote, HostedNotePage, HostedNoteRequest,
        HostedOutcomePolicy, HostedPageQuery, HostedTerminalPage, HostedTerminalQuery,
        HostedTerminalResult, HostedTerminalState, HostedValidationError, HostedValidationReason,
        HostedWorkItemContext, InboxSort, InboxView, IssuerPrincipal, ListWorkItemsQuery,
        MutationResponse, NextWorkItemQuery, OccurrenceKind, OccurrenceState, OneOfPredicate,
        OpaqueActorRef, OperationName, Page, PageStatus, QueueRecord, RecoverAttemptRequest,
        ReleaseRequest, RequesterHostedItem, RoutingActivity, RoutingCondition, RoutingPredicate,
        RoutingRule, SaveDraftRequest, SourceBinding, SourcePolicy, SourceReceipt,
        SourceRequestPolicy, StaffingDiagnostic, SubjectClockAnchor, SubjectClockCompletion,
        SubjectClockPause, SubjectRef, TeamRecord, Uuid, WorkItem, WorkItemPage, WorkItemRouting,
        WorkingDaysAfter, WorkingDaysBefore, WorkingWeekday,
    };
}

pub mod relay {
    pub use registry_relay_client::{
        BoundingBox, CollectionContinuation, CollectionContinuationProjection, CollectionPage,
        Conditional, ListRequest, LookupRequest, ProblemCode, ProtocolFailure, RawDocument,
        RecordCollectionResponse, RecordFormat, RecordOptions, RecordResponse, RelayClient,
        RelayClientConfig, RelayClientError, ResourceContinuation, ResourceListRequest,
        SdmxDataFormat, SdmxDataRequest, SdmxStructureKind, SdmxStructureRequest, SearchRequest,
        ServiceMetadata, StrongEtag,
    };
}

pub mod discovery {
    pub use registry_discovery_client::{
        accept_service_selection, renew_unchanged_service_selection, AcceptedServiceSelection,
        DiscoveryClient, DiscoveryClientConfig, DiscoveryClientError, DiscoveryProblem,
        EvidenceResolutionContext, EvidenceSelectionRequest, EvidenceServiceQuery,
        EvidenceServiceSelection, MatchedCapability, RelayCapabilityMatch, RelaySelectionRequest,
        RelayServiceQuery, RelayServiceSelection, SelectionRequest, ServiceKind, ServiceRecord,
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
