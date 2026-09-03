//! Curated Rust client facade for Registry Stack products.
//!
//! Each product remains in its own module so route, authentication, error,
//! record, and verification contracts cannot be mistaken for one another.

pub mod breg {
    pub use registry_breg_client::{
        BRegComplete, BRegContinuation, BRegContinuationProjection, BRegCreateBinding,
        BRegCreateRequest, BRegDirectWrite, BRegEtag, BRegIdempotencyKey, BRegLifecycleAction,
        BRegLifecycleActionReceipt, BRegLifecycleAuthority, BRegLifecycleOperation,
        BRegListRequest, BRegLookupRequest, BRegMetadata, BRegMetadataSelectionError,
        BRegMutationRequestError, BRegOperationKind, BRegPage, BRegPatchBinding, BRegPatchBuilder,
        BRegPatchRequest, BRegPlanRefusal, BRegProbeStatus, BRegProblemCode, BRegProtocolFailure,
        BRegRawDocument, BRegRecordFormat, BRegRecordOptions, BRegRequestError,
        BRegResponseMetadata, BaseRegistryClient, BaseRegistryClientConfig,
        BaseRegistryClientError,
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
