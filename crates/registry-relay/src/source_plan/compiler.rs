// SPDX-License-Identifier: Apache-2.0
//! Closed compiler from reviewed artifacts to executable source-plan capabilities.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_httputil::destination::json::ClosedJsonDecoder;
use registry_platform_httputil::destination::{
    CredentialDestinationPolicy, CredentialDestinationRequestTemplate, DataDestinationPolicy,
    DataDestinationRequestTemplate, DestinationAuthorizationTemplate, DestinationBodyTemplate,
    DestinationDnsFamily, DestinationMethod, DestinationProfile, OAuth2ClientCredentialsBodyFormat,
};
use reqwest::Url;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::consultation::{
    AcquiredField, AcquisitionClass, DeclaredOperationFootprint, IntegrationPackId,
    IntegrationPackIdentity, OperationId, ProfileContractHash, ProfileId, ProfileIdentity,
    ProfileVersion,
};

use super::artifact::{
    body_template_max_bytes, decode_pointer_tokens, expression_max_bytes, parse_input_pattern,
    parse_integration_pack, parse_private_binding, parse_public_contract, response_record_schema,
    sha256_label, BodyTemplateDocument, BoundedInputPattern, CanonicalizationDocument,
    CardinalityMechanismDocument, CodecSelectorRoleDocument, CredentialFailurePolicyDocument,
    DestinationDnsFamilyDocument, DestinationDocument, EvidenceClass, ExactSelectorDocument,
    HttpOperationDocument, IntegrationPackArtifact, MaterializationRefreshClassDocument,
    OAuth2ClientCredentialsRequestFormatDocument, OAuth2TokenResponseSchemaDocument,
    OAuth2TokenTypeDocument, OutputTypeDocument, PriorOutputBindingDocument,
    PrivateBindingArtifact, ProjectionMechanismDocument, PublicContractArtifact, ReadMethod,
    RequestCodecDocument, RequestSelectorLocationDocument, RequestSignerDocument,
    ResponseNormalizationDocument, ResponseSchemaDocument, SourceAuthDocument, SourceCardinality,
    SourcePlanArtifactError, SourcePlanKind, SourcePlanLimits, StepConditionDocument,
    ValueExpressionDocument, MAX_ARTIFACTS_PER_BUNDLE, MAX_EVIDENCE_CLASS_BYTES,
    MAX_EVIDENCE_FILES_PER_CLASS, MAX_EVIDENCE_FILE_BYTES,
};
use super::completion_seed::{measure_completion_seed, MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1};
use super::identifiers::{CredentialReferenceId, SourceDestinationId};
use super::runtime_profile::{
    CompiledRuntimeProfile, RhaiPredicateIdentity, MAX_COMPLETION_SEED_CANONICAL_BYTES_V1,
};

/// One raw, hash-pinned public contract or reviewed integration pack.
///
/// The bytes are parsed through the duplicate-rejecting strict JSON boundary.
/// `expected_hash` is compared with the hash of the validated typed object,
/// never with the raw byte representation.
#[derive(Clone, Copy)]
pub struct PinnedSourcePlanArtifact<'a> {
    bytes: &'a [u8],
    expected_hash: &'a str,
}

/// One non-secret conformance or minimization evidence file pinned by raw hash.
#[derive(Clone, Copy)]
pub struct PinnedEvidenceArtifact<'a> {
    class: EvidenceClass,
    bytes: &'a [u8],
    expected_hash: &'a str,
}

impl<'a> PinnedEvidenceArtifact<'a> {
    /// Pair bounded evidence bytes with their committed lowercase SHA-256 label.
    #[must_use]
    pub const fn new(class: EvidenceClass, bytes: &'a [u8], expected_hash: &'a str) -> Self {
        Self {
            class,
            bytes,
            expected_hash,
        }
    }
}

impl<'a> PinnedSourcePlanArtifact<'a> {
    /// Pair raw strict JSON with its committed lowercase `sha256:` identity.
    #[must_use]
    pub const fn new(bytes: &'a [u8], expected_hash: &'a str) -> Self {
        Self {
            bytes,
            expected_hash,
        }
    }
}

/// All artifacts that must be closed under one verified Relay startup bundle.
pub struct SourcePlanArtifactBundle<'a> {
    public_contracts: &'a [PinnedSourcePlanArtifact<'a>],
    integration_packs: &'a [PinnedSourcePlanArtifact<'a>],
    private_bindings: &'a [&'a [u8]],
    evidence: &'a [PinnedEvidenceArtifact<'a>],
    rhai_workers: &'a [RhaiWorkerCapability],
}

impl<'a> SourcePlanArtifactBundle<'a> {
    /// Construct one closed startup input.
    #[must_use]
    pub const fn new(
        public_contracts: &'a [PinnedSourcePlanArtifact<'a>],
        integration_packs: &'a [PinnedSourcePlanArtifact<'a>],
        private_bindings: &'a [&'a [u8]],
    ) -> Self {
        Self {
            public_contracts,
            integration_packs,
            private_bindings,
            evidence: &[],
            rhai_workers: &[],
        }
    }

    /// Close the bundle over every pack-referenced evidence hash.
    #[must_use]
    pub const fn with_evidence(mut self, evidence: &'a [PinnedEvidenceArtifact<'a>]) -> Self {
        self.evidence = evidence;
        self
    }

    /// Attach non-config capabilities minted by initialized one-shot Rhai workers.
    #[must_use]
    pub const fn with_rhai_workers(mut self, workers: &'a [RhaiWorkerCapability]) -> Self {
        self.rhai_workers = workers;
        self
    }
}

/// A safe reason that the closed artifact graph could not compile.
///
/// The error surface carries no raw profile, topology, or credential values.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourcePlanCompileError {
    /// One individual artifact failed strict typed ingestion.
    #[error("source-plan artifact ingestion failed: {0}")]
    Artifact(#[from] SourcePlanArtifactError),
    /// Two public contracts used the same id and version.
    #[error("duplicate consultation profile identity")]
    DuplicateProfile,
    /// Two packs used the same id and version.
    #[error("duplicate integration-pack identity")]
    DuplicatePack,
    /// Two private bindings targeted the same profile identity.
    #[error("duplicate private profile binding")]
    DuplicateBinding,
    /// A public contract did not resolve to exactly one reviewed pack.
    #[error("consultation profile references an unavailable integration pack")]
    MissingPack,
    /// A public contract did not resolve to exactly one private binding.
    #[error("consultation profile is missing its private binding")]
    MissingBinding,
    /// The bundle contained a pack not referenced by a public contract.
    #[error("startup bundle contains an unreferenced integration pack")]
    ExtraPack,
    /// The bundle contained a private binding without a public contract.
    #[error("startup bundle contains an unreferenced private binding")]
    ExtraBinding,
    /// Cross-referenced id, version, or hash values did not match exactly.
    #[error("source-plan artifact cross-reference does not match")]
    ReferenceMismatch,
    /// Pack semantics do not implement the pinned public contract exactly.
    #[error("integration pack does not implement the public contract")]
    ContractMismatch,
    /// The private binding attempted to widen a public or reviewed limit.
    #[error("private source-plan binding widens reviewed limits")]
    BindingWidening,
    /// A deployment parameter is missing, extra, or not reviewed by the pack.
    #[error("private source-plan parameter is outside the reviewed declaration")]
    InvalidDeploymentParameter,
    /// Credential presence does not match the pack's closed auth operation.
    #[error("private source-plan credential binding does not match the pack")]
    InvalidCredentialBinding,
    /// Data and credential destinations overlap or fail the hardened policy.
    #[error("private source-plan destination policy is unsafe")]
    UnsafeDestination,
    /// A sandboxed Rhai pack was not explicitly enabled by this deployment.
    #[error("sandboxed Rhai source plan is not enabled by the private binding")]
    RhaiNotEnabled,
    /// A non-Rhai pack received an unnecessary script-execution capability.
    #[error("private binding enables a capability not used by the reviewed plan")]
    CapabilityMismatch,
    /// A reviewed Rhai plan has no initialized non-config worker capability.
    #[error("sandboxed Rhai source plan has no initialized worker capability")]
    RhaiWorkerUnavailable,
    /// The initialized Rhai worker does not enforce the exact narrowed limits.
    #[error("sandboxed Rhai worker capability does not match the reviewed binding")]
    RhaiWorkerMismatch,
    /// The bundle contains too many governed artifacts for one startup graph.
    #[error("source-plan startup bundle exceeds the artifact-count ceiling")]
    TooManyArtifacts,
    /// Two evidence entries carry the same committed hash.
    #[error("source-plan startup bundle contains duplicate evidence")]
    DuplicateEvidence,
    /// A pack-referenced evidence hash has no verified file in the bundle.
    #[error("source-plan startup bundle is missing referenced evidence")]
    MissingEvidence,
    /// The bundle contains evidence not referenced by a reviewed pack.
    #[error("source-plan startup bundle contains unreferenced evidence")]
    ExtraEvidence,
    /// Evidence bytes do not match their committed raw SHA-256 label.
    #[error("source-plan evidence hash does not match")]
    EvidenceHashMismatch,
    /// Evidence was supplied under a class different from the reviewed manifest.
    #[error("source-plan evidence class does not match the reviewed manifest")]
    MisclassifiedEvidence,
    /// Evidence exceeds the bounded file count or per-class byte budget.
    #[error("source-plan evidence exceeds its class bounds")]
    EvidenceBoundsExceeded,
    /// The full canonical completion seed would exceed durable-state bounds.
    #[error("compiled source plan exceeds the completion-seed persistence ceiling")]
    CompletionSeedTooLarge,
    /// Completion audit context plus bounded pseudonyms would exceed audit bounds.
    #[error("compiled source plan exceeds the completion-audit persistence ceiling")]
    CompletionAuditTooLarge,
    /// A previously validated field could not be represented in the compiled plan.
    #[error("source-plan compiler invariant failed")]
    CompilerInvariant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RhaiWorkerLimits {
    pub(crate) max_calls: u8,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_ms: u32,
    pub(crate) ipc_frame_bytes: u32,
    pub(crate) instructions: u64,
    pub(crate) call_depth: u8,
    pub(crate) string_bytes: u32,
    pub(crate) array_items: u32,
    pub(crate) map_entries: u32,
    pub(crate) output_bytes: u32,
    pub(crate) concurrency: u16,
}

/// Non-config startup capability minted only after the worker harness has
/// installed one-shot process lifetime, rlimits, bounded IPC, and instruction
/// metering for one reviewed integration-pack hash.
pub struct RhaiWorkerCapability {
    integration_pack_hash: Box<str>,
    callable_operations: BTreeSet<Box<str>>,
    limits: RhaiWorkerLimits,
}

impl fmt::Debug for RhaiWorkerCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhaiWorkerCapability")
            .field("initialized", &true)
            .finish_non_exhaustive()
    }
}

impl RhaiWorkerCapability {
    /// Mint a capability only from the initialized worker-harness path.
    ///
    /// This crate-private constructor is intentionally unavailable to artifact
    /// and deployment configuration deserialization.
    pub(crate) fn from_initialized_worker(
        integration_pack_hash: &str,
        callable_operations: &[&str],
        limits: RhaiWorkerLimits,
    ) -> Result<Self, SourcePlanCompileError> {
        if !integration_pack_hash.starts_with("sha256:") || integration_pack_hash.len() != 71 {
            return Err(SourcePlanCompileError::RhaiWorkerMismatch);
        }
        Ok(Self {
            integration_pack_hash: integration_pack_hash.into(),
            callable_operations: callable_operations
                .iter()
                .map(|value| (*value).into())
                .collect(),
            limits,
        })
    }
}

/// Closed input canonicalization compiled from the reviewed public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledInputCanonicalization {
    /// Preserve the exact input bytes.
    Identity,
    /// Lowercase ASCII input before matching and request rendering.
    AsciiLowercase,
}

/// A bounded matcher compiled from the restricted anchored input grammar.
///
/// It retains no regex source string and performs bounded dynamic-programming
/// matching over at most the reviewed input-byte limit.
pub struct CompiledInputMatcher {
    pattern: BoundedInputPattern,
}

impl fmt::Debug for CompiledInputMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledInputMatcher")
            .field("atom_count", &self.pattern.atom_count())
            .finish()
    }
}

impl CompiledInputMatcher {
    /// Match one already-canonicalized input without reparsing a pattern.
    #[must_use]
    pub fn is_match(&self, value: &str) -> bool {
        self.pattern.is_match(value)
    }
}

/// One immutable input slot and its compiled validation capability.
pub struct CompiledInputSlot {
    name: Box<str>,
    profile_contract_hash: ProfileContractHash,
    slot_index: u16,
    max_bytes: u16,
    canonicalization: CompiledInputCanonicalization,
    matcher: CompiledInputMatcher,
}

/// Opaque canonical selector retained in zeroizing storage.
///
/// It is intentionally non-`Clone`, has redacted `Debug`, and exposes bytes
/// only within Relay's bounded request renderer.
///
/// ```compile_fail
/// use registry_relay::source_plan::CompiledInputValue;
///
/// fn cannot_clone(value: CompiledInputValue) {
///     let _ = value.clone();
/// }
/// ```
pub struct CompiledInputValue {
    value: Zeroizing<String>,
    profile_contract_hash: ProfileContractHash,
    slot_name: Box<str>,
    slot_index: u16,
}

impl fmt::Debug for CompiledInputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompiledInputValue([REDACTED])")
    }
}

impl CompiledInputValue {
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn binding_matches(
        &self,
        profile_contract_hash: &ProfileContractHash,
        slot_name: &str,
        slot_index: usize,
    ) -> bool {
        usize::from(self.slot_index) == slot_index
            && self.slot_name.as_ref() == slot_name
            && &self.profile_contract_hash == profile_contract_hash
    }
}

impl fmt::Debug for CompiledInputSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledInputSlot")
            .field("name", &self.name)
            .field("max_bytes", &self.max_bytes)
            .field("canonicalization", &self.canonicalization)
            .field("matcher", &self.matcher)
            .finish()
    }
}

impl CompiledInputSlot {
    /// Return the reviewed stable slot name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the input allocation ceiling.
    #[must_use]
    pub const fn max_bytes(&self) -> u16 {
        self.max_bytes
    }

    /// Canonicalize and validate a candidate, returning no value on mismatch.
    #[must_use]
    pub fn canonicalize_and_validate(&self, value: &str) -> Option<CompiledInputValue> {
        if value.len() > usize::from(self.max_bytes) || !value.is_ascii() {
            return None;
        }
        let canonical = match self.canonicalization {
            CompiledInputCanonicalization::Identity => value.to_owned(),
            CompiledInputCanonicalization::AsciiLowercase => value.to_ascii_lowercase(),
        };
        self.matcher
            .is_match(&canonical)
            .then(|| CompiledInputValue {
                value: Zeroizing::new(canonical),
                profile_contract_hash: self.profile_contract_hash.clone(),
                slot_name: self.name.clone(),
                slot_index: self.slot_index,
            })
    }
}

/// Request body codec frozen by the reviewed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledRequestCodec {
    /// No request body.
    None,
    /// Canonical bounded JSON.
    Json,
    /// Exact DCI v1 request encoding.
    DciExactV1,
}

/// Request signature mechanism frozen by the reviewed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledRequestSigner {
    /// DCI JWS v1.
    DciJwsV1,
}

/// Closed source authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSourceAuth {
    /// No credential.
    None,
    /// Basic authorization rendered only from the bound credential capability.
    Basic,
    /// Bearer authorization rendered only from the bound credential capability.
    StaticBearer,
    /// OAuth client credentials with an isolated token cache identity.
    OAuthClientCredentials,
}

/// A value source whose document references have already been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledValueExpression {
    /// Reviewed fixed text.
    Literal(Box<str>),
    /// Index into [`CompiledSourcePlan::inputs`].
    ConsultationInput { input_index: usize },
    /// Index into the private deployment-parameter value vector.
    DeploymentParameter { parameter_index: usize },
    /// Index into an earlier operation's named normalized output vector.
    PriorStepOutput {
        operation_index: usize,
        output_slot_index: usize,
    },
}

/// Exact normalized source that must populate one selector-bearing request role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSelectorSource {
    ConsultationInput {
        input_index: usize,
    },
    PriorStepOutput {
        operation_index: usize,
        output_slot_index: usize,
    },
}

/// Exact request location populated from [`CompiledSelectorSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledSelectorLocation {
    Query { component_index: usize },
    Body { pointer: CompiledJsonPointer },
    DciIdtypeValue,
}

/// Non-decorative selector binding consumed by the request renderer or codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSelectorBinding {
    source: CompiledSelectorSource,
    location: CompiledSelectorLocation,
}

impl CompiledSelectorBinding {
    #[must_use]
    pub const fn source(&self) -> CompiledSelectorSource {
        self.source
    }

    #[must_use]
    pub const fn location(&self) -> &CompiledSelectorLocation {
        &self.location
    }
}

/// One fixed query or header name and its compiled value source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNamedExpression {
    name: Box<str>,
    value: CompiledValueExpression,
}

impl CompiledNamedExpression {
    /// Return the fixed component name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the index-resolved value source.
    #[must_use]
    pub const fn value(&self) -> &CompiledValueExpression {
        &self.value
    }
}

/// A bounded request-body template with every expression already resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledBodyTemplate {
    Null,
    Boolean(bool),
    Integer(i64),
    StringLiteral(Box<str>),
    Expression(CompiledValueExpression),
    Array(Box<[CompiledBodyTemplate]>),
    Object(Box<[CompiledNamedBodyField]>),
}

/// One fixed object field in a compiled request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNamedBodyField {
    name: Box<str>,
    value: CompiledBodyTemplate,
}

impl CompiledNamedBodyField {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &CompiledBodyTemplate {
        &self.value
    }
}

/// Decoded RFC 6901 tokens. Runtime code never reparses pointer text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompiledJsonPointer {
    tokens: Box<[Box<str>]>,
}

impl CompiledJsonPointer {
    /// Iterate decoded object-key or canonical array-index tokens.
    pub fn tokens(&self) -> impl ExactSizeIterator<Item = &str> {
        self.tokens.iter().map(AsRef::as_ref)
    }
}

/// Bounded normalized scalar shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledScalarShape {
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

impl CompiledScalarShape {
    pub(crate) const fn nullable(&self) -> bool {
        match self {
            Self::String { nullable, .. }
            | Self::Boolean { nullable }
            | Self::Integer { nullable, .. }
            | Self::Number { nullable, .. } => *nullable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompiledResponseSchemaKind {
    Object,
    Array,
    String,
    Boolean,
    Integer,
    Number,
}

/// Closed recursive raw response schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledResponseSchema {
    Object {
        nullable: bool,
        fields: Box<[CompiledResponseField]>,
    },
    Array {
        nullable: bool,
        max_items: u16,
        items: Box<CompiledResponseSchema>,
    },
    Scalar(CompiledScalarShape),
}

impl CompiledResponseSchema {
    pub(crate) const fn kind(&self) -> CompiledResponseSchemaKind {
        match self {
            Self::Object { .. } => CompiledResponseSchemaKind::Object,
            Self::Array { .. } => CompiledResponseSchemaKind::Array,
            Self::Scalar(CompiledScalarShape::String { .. }) => CompiledResponseSchemaKind::String,
            Self::Scalar(CompiledScalarShape::Boolean { .. }) => {
                CompiledResponseSchemaKind::Boolean
            }
            Self::Scalar(CompiledScalarShape::Integer { .. }) => {
                CompiledResponseSchemaKind::Integer
            }
            Self::Scalar(CompiledScalarShape::Number { .. }) => CompiledResponseSchemaKind::Number,
        }
    }

    pub(crate) const fn nullable(&self) -> bool {
        match self {
            Self::Object { nullable, .. } | Self::Array { nullable, .. } => *nullable,
            Self::Scalar(shape) => shape.nullable(),
        }
    }

    pub(crate) fn object_fields(&self) -> Option<&[CompiledResponseField]> {
        match self {
            Self::Object { fields, .. } => Some(fields),
            Self::Array { .. } | Self::Scalar(_) => None,
        }
    }

    pub(crate) const fn array_items(&self) -> Option<(u16, &CompiledResponseSchema)> {
        match self {
            Self::Array {
                max_items, items, ..
            } => Some((*max_items, items)),
            Self::Object { .. } | Self::Scalar(_) => None,
        }
    }

    pub(crate) const fn scalar(&self) -> Option<&CompiledScalarShape> {
        match self {
            Self::Scalar(shape) => Some(shape),
            Self::Object { .. } | Self::Array { .. } => None,
        }
    }
}

/// One required or optional field in a closed response object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledResponseField {
    name: Box<str>,
    required: bool,
    schema: CompiledResponseSchema,
}

impl CompiledResponseField {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub const fn schema(&self) -> &CompiledResponseSchema {
        &self.schema
    }
}

/// Named normalized prior-step slot and its private extraction capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPriorOutputSlot {
    name: Box<str>,
    pointer: CompiledJsonPointer,
    shape: CompiledScalarShape,
}

impl CompiledPriorOutputSlot {
    /// Return the only slot identity visible to later steps.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn extraction_pointer(&self) -> &CompiledJsonPointer {
        &self.pointer
    }

    /// Return the normalized type and bounds enforced at extraction.
    #[must_use]
    pub const fn shape(&self) -> &CompiledScalarShape {
        &self.shape
    }
}

/// One public logical output and its compiled private extraction pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledOutputMapping {
    field: AcquiredField,
    pointer: CompiledJsonPointer,
}

impl CompiledOutputMapping {
    #[must_use]
    pub fn field(&self) -> &str {
        self.field.as_str()
    }

    pub(crate) const fn extraction_pointer(&self) -> &CompiledJsonPointer {
        &self.pointer
    }
}

/// Concrete response-cardinality enforcement compiled from request-linked proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledCardinalityMechanism {
    ProbeQueryParameter { query_index: usize },
    ProbeBodyInteger { pointer: CompiledJsonPointer },
    ReviewedRequestTemplateProbe { evidence_hash: Box<str> },
    SourceEnforcedSingleton { evidence_hash: Box<str> },
}

/// Concrete source-projection mechanism compiled from the fixed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledProjectionMechanism {
    QueryParameterExact { query_index: usize },
    ReviewedRequestTemplate { evidence_hash: Box<str> },
    BoundedFullRecord,
}

/// Root response shape selected by the reviewed normalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledResponseNormalization {
    Object,
    ArrayProbeTwo,
    ObjectArrayProbeTwo { records_field_index: usize },
}

/// Immutable compiled response parser and extraction contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledResponse {
    max_bytes: u32,
    max_records: u8,
    accepted_statuses: Box<[u16]>,
    normalization: CompiledResponseNormalization,
    schema: CompiledResponseSchema,
    outputs: Box<[CompiledOutputMapping]>,
    prior_outputs: Box<[CompiledPriorOutputSlot]>,
    cardinality: CompiledCardinalityMechanism,
}

impl CompiledResponse {
    #[must_use]
    pub const fn max_bytes(&self) -> u32 {
        self.max_bytes
    }

    #[must_use]
    pub const fn max_records(&self) -> u8 {
        self.max_records
    }

    pub fn accepted_statuses(&self) -> impl ExactSizeIterator<Item = u16> + '_ {
        self.accepted_statuses.iter().copied()
    }

    #[must_use]
    pub const fn normalization(&self) -> CompiledResponseNormalization {
        self.normalization
    }

    #[must_use]
    pub const fn schema(&self) -> &CompiledResponseSchema {
        &self.schema
    }

    pub fn outputs(&self) -> impl ExactSizeIterator<Item = &CompiledOutputMapping> {
        self.outputs.iter()
    }

    pub fn prior_outputs(&self) -> impl ExactSizeIterator<Item = &CompiledPriorOutputSlot> {
        self.prior_outputs.iter()
    }

    #[must_use]
    pub const fn cardinality(&self) -> &CompiledCardinalityMechanism {
        &self.cardinality
    }
}

/// Immutable structural metadata for one compiled data operation.
pub struct CompiledOperation {
    id: OperationId,
    method: ReadMethod,
    fixed_path: Box<str>,
    query: Box<[CompiledNamedExpression]>,
    headers: Box<[CompiledNamedExpression]>,
    body: Option<CompiledBodyTemplate>,
    request_codec: CompiledRequestCodec,
    request_signer: Option<CompiledRequestSigner>,
    request_max_bytes: u32,
    request_timeout_ms: u32,
    request_max_in_flight: u16,
    auth: CompiledSourceAuth,
    selector: CompiledSelectorBinding,
    projection: CompiledProjectionMechanism,
    transport_template: DataDestinationRequestTemplate,
    response: CompiledResponse,
    response_decoder: ClosedJsonDecoder,
    acquisition_class: AcquisitionClass,
    cardinality: SourceCardinality,
    total_deadline_ms: u32,
    acquired_fields: BTreeSet<AcquiredField>,
    disclosed_fields: BTreeSet<AcquiredField>,
}

/// One compiled, bounded predicate that can only skip its owning fixed step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledStepPredicate {
    /// Execute when the named normalized output exists.
    Exists,
    /// Execute when the bounded normalized string equals this reviewed literal.
    StringEquals(Box<str>),
    /// Execute when the normalized boolean equals this reviewed literal.
    BooleanEquals(bool),
    /// Execute when the bounded normalized integer equals this reviewed literal.
    IntegerEquals(i64),
}

/// Immutable execution metadata for one statically enumerated data step.
pub struct CompiledStep {
    operation_index: usize,
    condition_source_index: Option<usize>,
    condition_output_slot_index: Option<usize>,
    condition: Option<CompiledStepPredicate>,
}

impl fmt::Debug for CompiledStep {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledStep")
            .field("operation_index", &self.operation_index)
            .field("conditional", &self.condition.is_some())
            .finish()
    }
}

impl CompiledStep {
    pub(crate) const fn operation_index(&self) -> usize {
        self.operation_index
    }

    /// Return the earlier operation index providing the normalized condition slot.
    #[must_use]
    pub const fn condition_source_index(&self) -> Option<usize> {
        self.condition_source_index
    }

    /// Return the resolved normalized output slot used by this condition.
    #[must_use]
    pub const fn condition_output_slot_index(&self) -> Option<usize> {
        self.condition_output_slot_index
    }

    /// Return the reviewed bounded condition, if the fixed step is conditional.
    #[must_use]
    pub const fn condition(&self) -> Option<&CompiledStepPredicate> {
        self.condition.as_ref()
    }
}

impl fmt::Debug for CompiledOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledOperation")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("request_codec", &self.request_codec)
            .field("response_max_bytes", &self.response.max_bytes)
            .field("max_source_records", &self.response.max_records)
            .field("acquisition_class", &self.acquisition_class)
            .field("cardinality", &self.cardinality)
            .field("total_deadline_ms", &self.total_deadline_ms)
            .field("acquired_field_count", &self.acquired_fields.len())
            .finish()
    }
}

impl CompiledOperation {
    /// Return the reviewed named operation id.
    #[must_use]
    pub const fn id(&self) -> &OperationId {
        &self.id
    }

    /// Return the reviewed read-only method.
    #[must_use]
    pub const fn method(&self) -> ReadMethod {
        self.method
    }

    /// Return the fixed path. It contains no host, selector, or template syntax.
    #[must_use]
    pub fn fixed_path(&self) -> &str {
        &self.fixed_path
    }

    /// Return this exchange's response-body ceiling.
    #[must_use]
    pub const fn response_max_bytes(&self) -> u32 {
        self.response.max_bytes
    }

    /// Return the exact maximum source calls made by this fixed step.
    #[must_use]
    pub const fn max_source_calls(&self) -> u8 {
        1
    }

    /// Return the maximum records acquired to prove singleton or ambiguity.
    #[must_use]
    pub const fn max_source_records(&self) -> u8 {
        self.response.max_records
    }

    /// Return this exchange's declared acquisition class.
    #[must_use]
    pub const fn acquisition_class(&self) -> AcquisitionClass {
        self.acquisition_class
    }

    /// Return the cardinality contract enforced for this exchange.
    #[must_use]
    pub const fn cardinality(&self) -> SourceCardinality {
        self.cardinality
    }

    /// Return the shared credential-plus-data deadline for this plan.
    #[must_use]
    pub const fn total_deadline_ms(&self) -> u32 {
        self.total_deadline_ms
    }

    /// Iterate the closed Relay-visible acquisition fields for this exchange.
    pub fn acquired_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.acquired_fields.iter().map(AcquiredField::as_str)
    }

    /// Iterate the subset eligible for normalized consultation output.
    pub fn disclosed_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.disclosed_fields.iter().map(AcquiredField::as_str)
    }

    /// Iterate fixed query components in canonical name order.
    pub fn query(&self) -> impl ExactSizeIterator<Item = &CompiledNamedExpression> {
        self.query.iter()
    }

    /// Iterate fixed non-authorization headers in canonical name order.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = &CompiledNamedExpression> {
        self.headers.iter()
    }

    /// Return the bounded request body template, if any.
    #[must_use]
    pub const fn body(&self) -> Option<&CompiledBodyTemplate> {
        self.body.as_ref()
    }

    #[must_use]
    pub const fn request_codec(&self) -> CompiledRequestCodec {
        self.request_codec
    }

    #[must_use]
    pub const fn request_signer(&self) -> Option<CompiledRequestSigner> {
        self.request_signer
    }

    #[must_use]
    pub const fn request_max_bytes(&self) -> u32 {
        self.request_max_bytes
    }

    #[must_use]
    pub const fn request_timeout_ms(&self) -> u32 {
        self.request_timeout_ms
    }

    #[must_use]
    pub const fn request_max_in_flight(&self) -> u16 {
        self.request_max_in_flight
    }

    #[must_use]
    pub const fn auth(&self) -> CompiledSourceAuth {
        self.auth
    }

    #[must_use]
    pub const fn selector(&self) -> &CompiledSelectorBinding {
        &self.selector
    }

    #[must_use]
    pub const fn projection(&self) -> &CompiledProjectionMechanism {
        &self.projection
    }

    #[must_use]
    pub const fn response(&self) -> &CompiledResponse {
        &self.response
    }

    pub(crate) const fn response_decoder(&self) -> &ClosedJsonDecoder {
        &self.response_decoder
    }

    pub(crate) const fn transport_template(&self) -> &DataDestinationRequestTemplate {
        &self.transport_template
    }
}

/// Frozen refresh class for a materialized snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledSnapshotRefreshClass {
    OperatorTriggered,
    Scheduled,
}

/// Private immutable SnapshotExact provider and narrowed refresh contract.
pub struct CompiledSnapshotBinding {
    table_provider: Box<str>,
    max_snapshot_age_ms: u64,
    max_source_records: u64,
    max_source_bytes: u64,
    max_refresh_data_exchanges: u8,
    max_refresh_credential_exchanges: u8,
    max_refresh_data_destinations: u8,
    snapshot_retention_generations: u16,
    refresh_class: CompiledSnapshotRefreshClass,
    immutable_generation: bool,
    digest_bound_active_pointer: bool,
}

impl fmt::Debug for CompiledSnapshotBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledSnapshotBinding")
            .field("table_provider", &"[REDACTED]")
            .field("max_snapshot_age_ms", &self.max_snapshot_age_ms)
            .field("max_source_records", &self.max_source_records)
            .field("max_source_bytes", &self.max_source_bytes)
            .field(
                "max_refresh_data_exchanges",
                &self.max_refresh_data_exchanges,
            )
            .field(
                "max_refresh_credential_exchanges",
                &self.max_refresh_credential_exchanges,
            )
            .field(
                "max_refresh_data_destinations",
                &self.max_refresh_data_destinations,
            )
            .field(
                "snapshot_retention_generations",
                &self.snapshot_retention_generations,
            )
            .field("refresh_class", &self.refresh_class)
            .finish_non_exhaustive()
    }
}

impl CompiledSnapshotBinding {
    pub(crate) fn table_provider(&self) -> &str {
        &self.table_provider
    }

    #[must_use]
    pub const fn max_snapshot_age_ms(&self) -> u64 {
        self.max_snapshot_age_ms
    }

    #[must_use]
    pub const fn max_source_records(&self) -> u64 {
        self.max_source_records
    }

    #[must_use]
    pub const fn max_source_bytes(&self) -> u64 {
        self.max_source_bytes
    }

    #[must_use]
    pub const fn max_refresh_data_exchanges(&self) -> u8 {
        self.max_refresh_data_exchanges
    }

    #[must_use]
    pub const fn max_refresh_credential_exchanges(&self) -> u8 {
        self.max_refresh_credential_exchanges
    }

    #[must_use]
    pub const fn max_refresh_data_destinations(&self) -> u8 {
        self.max_refresh_data_destinations
    }

    #[must_use]
    pub const fn snapshot_retention_generations(&self) -> u16 {
        self.snapshot_retention_generations
    }

    #[must_use]
    pub const fn refresh_class(&self) -> CompiledSnapshotRefreshClass {
        self.refresh_class
    }

    #[must_use]
    pub const fn immutable_generation(&self) -> bool {
        self.immutable_generation
    }

    #[must_use]
    pub const fn digest_bound_active_pointer(&self) -> bool {
        self.digest_bound_active_pointer
    }

    /// Snapshot consultations never receive a live destination capability.
    #[must_use]
    pub const fn consultation_live_destinations(&self) -> u8 {
        0
    }
}

struct RuntimePrivateBinding {
    data_destination: Option<DataDestinationPolicy>,
    credential_destination: Option<CredentialDestinationPolicy>,
    credential_reference: Option<CredentialReferenceId>,
    credential_generation: Option<u64>,
    deployment_parameters: Box<[Box<str>]>,
    oauth_cache: Option<OAuthCacheIdentityInputs>,
    snapshot: Option<CompiledSnapshotBinding>,
}

mod credential;
use credential::*;

/// Exact non-secret inputs that isolate one OAuth access-token cache entry.
///
/// The value has no public constructor and deliberately has no `Debug`
/// implementation because the binding hash and credential reference belong only
/// in restricted operational surfaces.
pub(crate) struct OAuthCacheIdentityInputs {
    integration_pack_hash: Box<str>,
    binding_hash: Box<str>,
    credential_reference: CredentialReferenceId,
    credential_generation: u64,
    credential_destination_id: SourceDestinationId,
    audience: Option<Box<str>>,
    scopes: Vec<Box<str>>,
    resource: Option<Box<str>>,
    max_token_lifetime_ms: u32,
    expiry_safety_skew_ms: u32,
}

/// Borrowed, read-only components of one OAuth cache key.
///
/// This view deliberately implements neither `Debug` nor serialization because
/// the binding hash and credential reference belong only in restricted runtime
/// cache plumbing.
pub(crate) struct OAuthCacheKeyParts<'a> {
    integration_pack_hash: &'a str,
    binding_hash: &'a str,
    credential_reference: &'a str,
    credential_generation: u64,
    credential_destination_id: &'a str,
    audience: Option<&'a str>,
    scopes: &'a [Box<str>],
    resource: Option<&'a str>,
    max_token_lifetime_ms: u32,
    expiry_safety_skew_ms: u32,
}

impl OAuthCacheKeyParts<'_> {
    pub(crate) const fn integration_pack_hash(&self) -> &str {
        self.integration_pack_hash
    }

    pub(crate) const fn binding_hash(&self) -> &str {
        self.binding_hash
    }

    pub(crate) const fn credential_reference(&self) -> &str {
        self.credential_reference
    }

    pub(crate) const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub(crate) const fn credential_destination_id(&self) -> &str {
        self.credential_destination_id
    }

    pub(crate) const fn audience(&self) -> Option<&str> {
        self.audience
    }

    pub(crate) fn scopes(&self) -> impl ExactSizeIterator<Item = &str> {
        self.scopes.iter().map(AsRef::as_ref)
    }

    pub(crate) const fn resource(&self) -> Option<&str> {
        self.resource
    }

    pub(crate) const fn max_token_lifetime_ms(&self) -> u32 {
        self.max_token_lifetime_ms
    }

    pub(crate) const fn expiry_safety_skew_ms(&self) -> u32 {
        self.expiry_safety_skew_ms
    }
}

impl OAuthCacheIdentityInputs {
    pub(crate) fn cache_key_parts(&self) -> OAuthCacheKeyParts<'_> {
        OAuthCacheKeyParts {
            integration_pack_hash: &self.integration_pack_hash,
            binding_hash: &self.binding_hash,
            credential_reference: self.credential_reference.as_str(),
            credential_generation: self.credential_generation,
            credential_destination_id: self.credential_destination_id.as_str(),
            audience: self.audience.as_deref(),
            scopes: &self.scopes,
            resource: self.resource.as_deref(),
            max_token_lifetime_ms: self.max_token_lifetime_ms,
            expiry_safety_skew_ms: self.expiry_safety_skew_ms,
        }
    }

    pub(crate) const fn max_token_lifetime_ms(&self) -> u32 {
        self.max_token_lifetime_ms
    }

    pub(crate) const fn expiry_safety_skew_ms(&self) -> u32 {
        self.expiry_safety_skew_ms
    }
}

/// The only source-plan value accepted by the consultation backend boundary.
///
/// All fields are private and there is no public constructor. Callers can only
/// obtain this capability from [`CompiledSourcePlanRegistry::compile`], which
/// proves strict parsing, artifact identities, minimization, binding narrowing,
/// credential shape, and hardened destinations together.
///
/// ```compile_fail
/// use registry_relay::source_plan::CompiledSourcePlan;
///
/// let forged = CompiledSourcePlan {};
/// ```
pub struct CompiledSourcePlan {
    runtime_profile: CompiledRuntimeProfile,
    contract: PublicContractArtifact,
    inputs: Vec<CompiledInputSlot>,
    operations: Vec<CompiledOperation>,
    credential_operation: Option<CompiledCredentialOperation>,
    steps: Vec<CompiledStep>,
    runtime_binding: RuntimePrivateBinding,
}

impl fmt::Debug for CompiledSourcePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledSourcePlan")
            .field("profile", self.profile())
            .field("integration_pack", self.integration_pack())
            .field("kind", &self.kind())
            .field("cardinality", &self.cardinality())
            .field("operation_count", &self.operations.len())
            .field("step_count", &self.steps.len())
            .finish_non_exhaustive()
    }
}

impl CompiledSourcePlan {
    /// Return the immutable, already typed runtime consultation facts.
    #[must_use]
    pub(crate) const fn runtime_profile(&self) -> &CompiledRuntimeProfile {
        &self.runtime_profile
    }

    /// Return the complete public profile identity.
    #[must_use]
    pub const fn profile(&self) -> &ProfileIdentity {
        self.runtime_profile.profile()
    }

    /// Return the complete reviewed pack identity.
    #[must_use]
    pub const fn integration_pack(&self) -> &IntegrationPackIdentity {
        self.runtime_profile.integration_pack()
    }

    /// Return the runtime-private, secret-free binding hash.
    #[must_use]
    pub(crate) fn binding_hash(&self) -> &str {
        self.runtime_profile.private_binding_hash()
    }

    /// Return the closed template kind.
    #[must_use]
    pub const fn kind(&self) -> SourcePlanKind {
        self.runtime_profile.kind()
    }

    /// Return the public acquisition class and numerical footprint.
    #[must_use]
    pub const fn footprint(&self) -> &DeclaredOperationFootprint {
        self.runtime_profile.footprint()
    }

    /// Return the singleton or ambiguity-probe contract.
    #[must_use]
    pub const fn cardinality(&self) -> SourceCardinality {
        self.runtime_profile.cardinality()
    }

    /// Return the effective, possibly narrowed deployment limits.
    #[must_use]
    pub const fn limits(&self) -> SourcePlanLimits {
        self.runtime_profile.effective_limits()
    }

    /// Return the fixed reviewed operation union.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = &CompiledOperation> {
        self.operations.iter()
    }

    pub(crate) const fn credential_operation(&self) -> Option<&CompiledCredentialOperation> {
        self.credential_operation.as_ref()
    }

    /// Iterate closed input slots in the same index order used by expressions.
    pub fn inputs(&self) -> impl ExactSizeIterator<Item = &CompiledInputSlot> {
        self.inputs.iter()
    }

    /// Return the fixed execution sequence as operation descriptors.
    pub fn steps(&self) -> impl ExactSizeIterator<Item = &CompiledOperation> {
        let steps = if self.kind() == SourcePlanKind::SandboxedRhai {
            &self.steps[..0]
        } else {
            &self.steps
        };
        steps
            .iter()
            .map(|step| &self.operations[step.operation_index])
    }

    /// Return immutable step and condition descriptors in fixed execution order.
    pub fn compiled_steps(&self) -> impl ExactSizeIterator<Item = &CompiledStep> {
        if self.kind() == SourcePlanKind::SandboxedRhai {
            self.steps[..0].iter()
        } else {
            self.steps.iter()
        }
    }

    /// Return exactly the RFC 8785 canonical public contract served as metadata.
    #[must_use]
    pub fn canonical_public_contract(&self) -> &[u8] {
        self.contract.canonical_json()
    }

    pub(crate) const fn data_destination(&self) -> Option<&DataDestinationPolicy> {
        self.runtime_binding.data_destination.as_ref()
    }

    pub(crate) const fn credential_destination(&self) -> Option<&CredentialDestinationPolicy> {
        self.runtime_binding.credential_destination.as_ref()
    }

    pub(crate) fn credential_reference(&self) -> Option<(&str, u64)> {
        self.runtime_binding
            .credential_reference
            .as_ref()
            .map(CredentialReferenceId::as_str)
            .zip(self.runtime_binding.credential_generation)
    }

    pub(crate) const fn oauth_cache_identity(&self) -> Option<&OAuthCacheIdentityInputs> {
        self.runtime_binding.oauth_cache.as_ref()
    }

    pub(crate) fn deployment_parameter_value(&self, index: usize) -> Option<&str> {
        self.runtime_binding
            .deployment_parameters
            .get(index)
            .map(AsRef::as_ref)
    }

    /// Return the compiled SnapshotExact backend capability, if this is a snapshot plan.
    #[must_use]
    pub const fn snapshot_binding(&self) -> Option<&CompiledSnapshotBinding> {
        self.runtime_binding.snapshot.as_ref()
    }
}

/// Immutable lookup registry produced from one closed startup bundle.
///
/// The registry has no mutation API. Reload compiles an entirely new registry
/// and the caller may swap it only after every artifact and cross-reference has
/// passed validation.
pub struct CompiledSourcePlanRegistry {
    plans: BTreeMap<(ProfileId, ProfileVersion), CompiledSourcePlan>,
}

impl fmt::Debug for CompiledSourcePlanRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledSourcePlanRegistry")
            .field("plan_count", &self.plans.len())
            .finish()
    }
}

impl CompiledSourcePlanRegistry {
    /// Strictly ingest and compile the complete startup artifact graph.
    pub fn compile(bundle: &SourcePlanArtifactBundle<'_>) -> Result<Self, SourcePlanCompileError> {
        let artifact_count = bundle
            .public_contracts
            .len()
            .checked_add(bundle.integration_packs.len())
            .and_then(|count| count.checked_add(bundle.private_bindings.len()))
            .and_then(|count| count.checked_add(bundle.evidence.len()))
            .ok_or(SourcePlanCompileError::TooManyArtifacts)?;
        if artifact_count > MAX_ARTIFACTS_PER_BUNDLE {
            return Err(SourcePlanCompileError::TooManyArtifacts);
        }
        // Preserve the normative generation and verification order: reviewed
        // integration pack, derived contract policy, public contract, then
        // runtime-private binding.
        let packs = parse_packs(bundle.integration_packs)?;
        let contracts = parse_contracts(bundle.public_contracts)?;
        let mut bindings = parse_bindings(bundle.private_bindings)?;

        let contract_keys = contracts.keys().cloned().collect::<BTreeSet<_>>();
        if bindings.keys().any(|key| !contract_keys.contains(key)) {
            return Err(SourcePlanCompileError::ExtraBinding);
        }

        let mut referenced_packs = BTreeSet::new();
        let mut plans = BTreeMap::new();
        for (key, contract) in contracts {
            let binding = bindings
                .remove(&key)
                .ok_or(SourcePlanCompileError::MissingBinding)?;
            let pack_key = (
                contract.integration_pack().id().clone(),
                contract.integration_pack().version(),
            );
            let pack = packs
                .get(&pack_key)
                .ok_or(SourcePlanCompileError::MissingPack)?;
            if pack.identity().hash() != contract.integration_pack().hash() {
                return Err(SourcePlanCompileError::ReferenceMismatch);
            }
            referenced_packs.insert(pack_key.clone());
            let plan = compile_one(contract, pack, binding, bundle.rhai_workers)?;
            plans.insert(key, plan);
        }
        if !bindings.is_empty() {
            return Err(SourcePlanCompileError::ExtraBinding);
        }
        if packs.keys().any(|key| !referenced_packs.contains(key)) {
            return Err(SourcePlanCompileError::ExtraPack);
        }
        validate_evidence_closure(packs.values(), bundle.evidence)?;
        Ok(Self { plans })
    }

    /// Return the number of compiled profile versions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plans.len()
    }

    /// Return whether the closed registry contains no profiles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }

    /// Look up one exact profile id and version.
    #[must_use]
    pub fn get(&self, id: &ProfileId, version: ProfileVersion) -> Option<&CompiledSourcePlan> {
        self.plans.get(&(id.clone(), version))
    }

    /// Iterate compiled plans in stable profile-id and version order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CompiledSourcePlan> {
        self.plans.values()
    }
}

fn validate_evidence_closure<'a>(
    packs: impl Iterator<Item = &'a IntegrationPackArtifact>,
    evidence: &[PinnedEvidenceArtifact<'_>],
) -> Result<(), SourcePlanCompileError> {
    let mut referenced = BTreeMap::new();
    for pack in packs {
        for class in [
            EvidenceClass::Conformance,
            EvidenceClass::NegativeSecurity,
            EvidenceClass::Minimization,
        ] {
            for hash in pack.document.spec.evidence.class_hashes(class) {
                if referenced
                    .insert(hash.as_str(), class)
                    .is_some_and(|prior| prior != class)
                {
                    return Err(SourcePlanCompileError::MisclassifiedEvidence);
                }
            }
        }
    }
    let mut supplied = BTreeMap::new();
    let mut class_counts = BTreeMap::<EvidenceClass, usize>::new();
    let mut class_bytes = BTreeMap::<EvidenceClass, usize>::new();
    for artifact in evidence {
        if sha256_label(artifact.bytes) != artifact.expected_hash {
            return Err(SourcePlanCompileError::EvidenceHashMismatch);
        }
        if artifact.bytes.len() > MAX_EVIDENCE_FILE_BYTES {
            return Err(SourcePlanCompileError::EvidenceBoundsExceeded);
        }
        if supplied
            .insert(artifact.expected_hash, artifact.class)
            .is_some()
        {
            return Err(SourcePlanCompileError::DuplicateEvidence);
        }
        let count = class_counts.entry(artifact.class).or_default();
        *count += 1;
        let bytes = class_bytes.entry(artifact.class).or_default();
        *bytes = bytes
            .checked_add(artifact.bytes.len())
            .ok_or(SourcePlanCompileError::EvidenceBoundsExceeded)?;
        if *count > MAX_EVIDENCE_FILES_PER_CLASS || *bytes > MAX_EVIDENCE_CLASS_BYTES {
            return Err(SourcePlanCompileError::EvidenceBoundsExceeded);
        }
    }
    if referenced.keys().any(|hash| !supplied.contains_key(hash)) {
        return Err(SourcePlanCompileError::MissingEvidence);
    }
    if supplied.keys().any(|hash| !referenced.contains_key(hash)) {
        return Err(SourcePlanCompileError::ExtraEvidence);
    }
    if referenced
        .iter()
        .any(|(hash, class)| supplied.get(hash).is_some_and(|supplied| supplied != class))
    {
        return Err(SourcePlanCompileError::MisclassifiedEvidence);
    }
    Ok(())
}

type ProfileKey = (ProfileId, ProfileVersion);
type PackKey = (IntegrationPackId, ProfileVersion);

fn parse_contracts(
    artifacts: &[PinnedSourcePlanArtifact<'_>],
) -> Result<BTreeMap<ProfileKey, PublicContractArtifact>, SourcePlanCompileError> {
    let mut parsed = BTreeMap::new();
    for artifact in artifacts {
        let contract = parse_public_contract(artifact.bytes, artifact.expected_hash)?;
        let key = (
            contract.identity().id().clone(),
            contract.identity().version(),
        );
        if parsed.insert(key, contract).is_some() {
            return Err(SourcePlanCompileError::DuplicateProfile);
        }
    }
    Ok(parsed)
}

fn parse_packs(
    artifacts: &[PinnedSourcePlanArtifact<'_>],
) -> Result<BTreeMap<PackKey, IntegrationPackArtifact>, SourcePlanCompileError> {
    let mut parsed = BTreeMap::new();
    for artifact in artifacts {
        let pack = parse_integration_pack(artifact.bytes, artifact.expected_hash)?;
        let key = (pack.identity().id().clone(), pack.identity().version());
        if parsed.insert(key, pack).is_some() {
            return Err(SourcePlanCompileError::DuplicatePack);
        }
    }
    Ok(parsed)
}

fn parse_bindings(
    artifacts: &[&[u8]],
) -> Result<BTreeMap<ProfileKey, PrivateBindingArtifact>, SourcePlanCompileError> {
    let mut parsed = BTreeMap::new();
    for bytes in artifacts {
        let binding = parse_private_binding(bytes)?;
        let key = (binding.profile_id.clone(), binding.profile_version);
        if parsed.insert(key, binding).is_some() {
            return Err(SourcePlanCompileError::DuplicateBinding);
        }
    }
    Ok(parsed)
}

fn compile_one(
    contract: PublicContractArtifact,
    pack: &IntegrationPackArtifact,
    binding: PrivateBindingArtifact,
    rhai_workers: &[RhaiWorkerCapability],
) -> Result<CompiledSourcePlan, SourcePlanCompileError> {
    validate_cross_references(&contract, pack, &binding)?;
    validate_contract_implementation(&contract, pack)?;
    validate_materialization_binding(&contract, pack, &binding)?;
    let binding_limits = validate_binding_narrowing(&contract, pack, &binding)?;
    validate_parameters(pack, &binding)?;
    validate_credential_shape(pack, &binding)?;
    let effective_token_lifetime_ms = effective_token_lifetime_ms(pack, &binding)?;

    let rhai_worker_limits = validate_capabilities(pack, &binding, rhai_workers)?;
    let limits = match rhai_worker_limits {
        Some(rhai_limits) => binding_limits
            .with_max_data_exchanges(rhai_limits.max_calls)
            .map_err(SourcePlanCompileError::Artifact)?,
        None => binding_limits,
    };
    validate_effective_source_bytes(pack, limits)?;
    let completion_seed_sizing = measure_completion_seed(
        &contract,
        pack,
        &binding,
        binding.hash().as_str(),
        limits,
        effective_token_lifetime_ms,
        rhai_worker_limits,
    )?;
    validate_completion_sizing(
        completion_seed_sizing.canonical_bytes_max,
        completion_seed_sizing.completion_audit_canonical_bytes_max,
    )?;

    let data_destination = match pack.document.spec.plan.kind {
        SourcePlanKind::SnapshotExact => None,
        SourcePlanKind::BoundedHttp | SourcePlanKind::SandboxedRhai => {
            Some(compile_data_destination(
                binding
                    .document
                    .data_destination
                    .as_ref()
                    .ok_or(SourcePlanCompileError::InvalidCredentialBinding)?,
            )?)
        }
    };
    let credential_destination = binding
        .document
        .credential_destination
        .as_ref()
        .map(compile_credential_destination)
        .transpose()?;
    reject_destination_overlap(&binding)?;

    let footprint = DeclaredOperationFootprint::try_new(
        &pack.document.spec.logical_operation,
        contract.acquisition_class,
        contract.acquired_fields.iter().map(AcquiredField::as_str),
        limits.operation(),
    )
    .map_err(|_| SourcePlanCompileError::CompilerInvariant)?;

    let inputs = compile_input_slots(pack, contract.identity().contract_hash())?;
    let input_indexes = pack
        .document
        .spec
        .input_slots
        .keys()
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let parameter_indexes = pack
        .document
        .spec
        .deployment_parameters
        .keys()
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let operation_indexes = pack
        .document
        .spec
        .plan
        .operations
        .iter()
        .enumerate()
        .map(|(index, operation)| (operation.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let prior_slot_indexes = pack
        .document
        .spec
        .plan
        .operations
        .iter()
        .map(|operation| {
            let slots = operation
                .response
                .prior_outputs
                .keys()
                .enumerate()
                .map(|(index, name)| (name.as_str(), index))
                .collect::<BTreeMap<_, _>>();
            (operation.id.as_str(), slots)
        })
        .collect::<BTreeMap<_, _>>();
    let compilation_indexes = OperationCompilationIndexes {
        inputs: &input_indexes,
        parameters: &parameter_indexes,
        operations: &operation_indexes,
        prior_slots: &prior_slot_indexes,
    };
    let data_application_base_path = binding
        .document
        .data_destination
        .as_ref()
        .map_or("/", |destination| {
            destination.application_base_path.as_str()
        });
    let operations = compile_operation_descriptors(
        pack,
        contract.acquisition_class,
        contract.cardinality,
        limits.operation().timeout_ms,
        data_application_base_path,
        &compilation_indexes,
    )?;
    let credential_application_base_path = binding
        .document
        .credential_destination
        .as_ref()
        .map_or("/", |destination| {
            destination.application_base_path.as_str()
        });
    let credential_operation = compile_credential_operation(
        pack,
        effective_token_lifetime_ms,
        credential_application_base_path,
    )?;
    let steps = compile_steps(
        &pack.document.spec.plan,
        &operation_indexes,
        &prior_slot_indexes,
    )?;

    let credential_reference = binding.credential_reference.clone();
    let credential_generation = binding
        .document
        .credential
        .as_ref()
        .map(|credential| credential.generation);
    let binding_hash = binding.hash().clone();
    let oauth_cache = pack
        .document
        .spec
        .plan
        .credential_operation
        .as_ref()
        .map(|operation| {
            let credential = binding
                .document
                .credential
                .as_ref()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            Ok::<_, SourcePlanCompileError>(OAuthCacheIdentityInputs {
                integration_pack_hash: pack.identity().hash().as_str().into(),
                binding_hash: binding_hash.as_str().into(),
                credential_reference: binding
                    .credential_reference
                    .as_ref()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?
                    .clone(),
                credential_generation: credential.generation,
                credential_destination_id: binding
                    .credential_destination_id
                    .as_ref()
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?
                    .clone(),
                audience: operation.request.audience.as_deref().map(Into::into),
                scopes: operation
                    .request
                    .scopes
                    .iter()
                    .map(|scope| scope.as_str().into())
                    .collect(),
                resource: operation.request.resource.as_deref().map(Into::into),
                max_token_lifetime_ms: effective_token_lifetime_ms
                    .ok_or(SourcePlanCompileError::CompilerInvariant)?,
                expiry_safety_skew_ms: operation.response.expiry_safety_skew_ms,
            })
        })
        .transpose()?;
    let deployment_parameters = pack
        .document
        .spec
        .deployment_parameters
        .keys()
        .map(|name| {
            binding
                .document
                .deployment_parameters
                .get(name)
                .map(|value| value.as_str().into())
                .ok_or(SourcePlanCompileError::CompilerInvariant)
        })
        .collect::<Result<Box<[_]>, _>>()?;
    let snapshot = compile_snapshot_binding(&contract, pack, &binding)?;
    let rhai_predicate_identity = pack
        .document
        .spec
        .plan
        .rhai
        .as_ref()
        .map(|rhai| {
            RhaiPredicateIdentity::from_validated_artifact(&rhai.script_hash, &rhai.entrypoint)
        })
        .transpose()?;
    let runtime_profile = CompiledRuntimeProfile::from_compiled_artifacts(
        &contract,
        pack.identity().clone(),
        binding_hash.clone(),
        binding.tenant.clone(),
        binding.registry_instance.clone(),
        footprint.clone(),
        limits,
        &operations,
        &steps,
        binding.data_destination_id.as_ref(),
        rhai_worker_limits,
        rhai_predicate_identity,
        completion_seed_sizing.template,
        completion_seed_sizing.canonical_bytes_max,
        completion_seed_sizing.completion_audit_canonical_bytes_max,
        &pack.document.spec.product_family,
        &pack.document.spec.supported_version_evidence,
        pack.logical_operation.clone(),
        pack.document.spec.plan.kind,
    )?;
    let runtime_binding = RuntimePrivateBinding {
        data_destination,
        credential_destination,
        credential_reference,
        credential_generation,
        deployment_parameters,
        oauth_cache,
        snapshot,
    };
    Ok(CompiledSourcePlan {
        runtime_profile,
        contract,
        inputs,
        operations,
        credential_operation,
        steps,
        runtime_binding,
    })
}

fn validate_completion_sizing(
    completion_seed_canonical_bytes: usize,
    completion_audit_canonical_bytes: usize,
) -> Result<(), SourcePlanCompileError> {
    if completion_seed_canonical_bytes > MAX_COMPLETION_SEED_CANONICAL_BYTES_V1 {
        return Err(SourcePlanCompileError::CompletionSeedTooLarge);
    }
    if completion_audit_canonical_bytes > MAX_COMPLETION_AUDIT_CANONICAL_BYTES_V1 {
        return Err(SourcePlanCompileError::CompletionAuditTooLarge);
    }
    Ok(())
}

fn compile_steps(
    plan: &super::artifact::PlanTemplateDocument,
    operation_indexes: &BTreeMap<&str, usize>,
    prior_slot_indexes: &BTreeMap<&str, BTreeMap<&str, usize>>,
) -> Result<Vec<CompiledStep>, SourcePlanCompileError> {
    plan.steps
        .iter()
        .map(|operation| {
            let operation_index = operation_indexes
                .get(operation.as_str())
                .copied()
                .ok_or(SourcePlanCompileError::CompilerInvariant)?;
            let (condition_source_index, condition_output_slot_index, condition) =
                match plan.step_conditions.get(operation) {
                    None => (None, None, None),
                    Some(condition) => {
                        let (source, output, predicate) = match condition {
                            StepConditionDocument::Exists { step, output } => {
                                (step, output, CompiledStepPredicate::Exists)
                            }
                            StepConditionDocument::StringEquals {
                                step,
                                output,
                                value,
                            } => (
                                step,
                                output,
                                CompiledStepPredicate::StringEquals(value.clone().into_boxed_str()),
                            ),
                            StepConditionDocument::BooleanEquals {
                                step,
                                output,
                                value,
                            } => (step, output, CompiledStepPredicate::BooleanEquals(*value)),
                            StepConditionDocument::IntegerEquals {
                                step,
                                output,
                                value,
                            } => (step, output, CompiledStepPredicate::IntegerEquals(*value)),
                        };
                        let source_index = operation_indexes
                            .get(source.as_str())
                            .copied()
                            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                        let output_slot_index = prior_slot_indexes
                            .get(source.as_str())
                            .and_then(|slots| slots.get(output.as_str()))
                            .copied()
                            .ok_or(SourcePlanCompileError::CompilerInvariant)?;
                        (Some(source_index), Some(output_slot_index), Some(predicate))
                    }
                };
            Ok(CompiledStep {
                operation_index,
                condition_source_index,
                condition_output_slot_index,
                condition,
            })
        })
        .collect()
}

mod binding;
use binding::*;

mod operation;
use operation::*;

fn destination_fixed_path(application_base_path: &str, pack_path: &str) -> Box<str> {
    if application_base_path == "/" {
        return pack_path.into();
    }
    let mut path = String::with_capacity(application_base_path.len() + pack_path.len());
    path.push_str(application_base_path);
    path.push_str(pack_path);
    path.into_boxed_str()
}

pub(in crate::source_plan) fn compile_runtime_response_schema(
    schema: &ResponseSchemaDocument,
) -> CompiledResponseSchema {
    operation::compile_response_schema(schema)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::{
    bounded_runtime_vector_plan_fixture, consent_runtime_vector_plan_fixture,
    dhis2_completion_seed_fixture, dhis2_duplicate_selector_runtime_vector_plan_fixture,
    dhis2_runtime_vector_plan_fixture, maximum_completion_seed_fixture,
    maximum_runtime_profile_fixture, normal_completion_seed_fixture,
    rhai_five_operation_two_slot_completion_seed_fixture, rhai_runtime_vector_plan_fixture,
    semantic_alias_completion_seed_fixture, snapshot_completion_seed_fixture,
};
