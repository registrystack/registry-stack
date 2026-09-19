// SPDX-License-Identifier: Apache-2.0

//! The product seams the delivery worker runs through: connection, identity
//! preflight, audit, operational events, activated destinations, and
//! runnable local handlers.
//!
//! Everything product-owned enters here, and it enters through one trait so a
//! product implements its side as a unit. The worker carries no product name
//! and no product policy: the signing scheme and its key material, the
//! idempotency domain, the audit vocabulary, the operational vocabulary, and
//! the identity check all stay with the product, expressed as the neutral
//! contracts below.

use std::ops::DerefMut;
use std::time::Duration;

use async_trait::async_trait;
use registry_platform_httputil::destination::{
    DestinationRequestError, DestinationSendError, EventDeliveryHeaders, EventDestinationRequest,
};
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{
    BoundedText, ErrorCategory, HookHandlerKind, MAX_REFUSAL_CODE_BYTES, MAX_REFUSAL_SUMMARY_BYTES,
};

/// One pooled product connection framed for the worker.
///
/// The worker opens its claim, material, and finalize transactions on
/// separate connections, exactly as the owning product's pool provided them
/// before the move.
pub type DeliveryConnection = Box<dyn DerefMut<Target = tokio_postgres::Client> + Send>;

/// Value-free refusal while doing delivery work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryError {
    #[error("hook delivery is unavailable")]
    Unavailable,
}

/// The product-owned surface the delivery worker runs through.
///
/// One trait, not several: a product binds its pool, its identity preflight,
/// its audit journal, its operational vocabulary, and its activated
/// destinations together, and the worker never sees any of them concretely.
#[async_trait]
pub trait DeliverySeams: Send + Sync + 'static {
    /// The product's activated destination for one compiled logical id.
    type Destination: HookDestination;

    /// The product's runnable handler for one local-kind delivery row.
    type Handler: HookHandler;

    /// One pooled connection for a worker transaction.
    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError>;

    /// The product's identity preflight, called inside every worker
    /// transaction at the point where the product verified its deployment
    /// identity before the move.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError>;

    /// The activated destination for a compiled logical destination id, or
    /// `None` when that id is not activated.
    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination>;

    /// The runnable handler for one local-kind delivery row, or `None` when
    /// this deployment holds no program under that binding.
    ///
    /// This is the second seam, and it is the reason the library runs local
    /// kinds without owning an executor: resolving the reviewed program from
    /// the package the delivery row names, and running it, stay with the
    /// product. The library supplies the binding the row recorded and reads
    /// back bytes and a failure category, so no script engine, module
    /// format, or executor type crosses into this crate.
    fn handler(&self, binding: HookHandlerBinding<'_>) -> Option<Self::Handler>;

    /// Apply one accepted proposal and report what became of it.
    ///
    /// This is the seam a proposal crosses from the library's delivery
    /// bookkeeping into the product's mutation path. The product validates
    /// the proposal document through the same path any other proposed change
    /// takes, authorizes it under the principal the hook declared, and
    /// applies it in a fresh transaction of its own, never inside this
    /// worker's claim, material, or finalize transactions.
    ///
    /// The application's identity is the event id and the compiled delivery
    /// id: stable across attempts, replay generations, and answer changes,
    /// so a redelivered answer resolves as the same application rather than
    /// a second one, and a changed answer after the commit surfaces as the
    /// product's stable conflict. The product's own idempotency mechanism
    /// holds that promise; the worker relies on it. Because an application
    /// can outlive its delivery lease, the product must serialize this call
    /// with [`Self::recover_proposal_receipt`] on that identity until the
    /// receipt decision is complete.
    ///
    /// Returning [`DeliveryError`] means the outcome is uncertain: the apply
    /// may or may not have committed. The worker fails closed. The delivery
    /// row is never marked delivered on an uncertain apply, and the lease is
    /// left to expire so the retry re-asks this seam and the idempotent
    /// replay resolves it.
    async fn apply_proposal(
        &self,
        application: ProposalApplication<'_>,
    ) -> Result<ProposalOutcome, DeliveryError>;

    /// Recover a proposal that may already have committed when the current
    /// accepted answer carries no proposal, the final attempt accepts no
    /// answer, or its lease expires before finalization.
    ///
    /// `None` means this delivery has no committed proposal receipt and the
    /// worker may settle the current non-proposal answer or exhausted failure
    /// normally. A returned outcome is recorded instead, so a proposal that
    /// committed before a failed finalize cannot later be hidden by a changed
    /// `none` or refusal answer, or by retries that all fail before accepting
    /// an answer. The product owns the receipt and the stable conflict
    /// outcome; the worker supplies only the delivery identity. This call
    /// must use the same serialization boundary as
    /// [`Self::apply_proposal`], including while an expired-lease application
    /// is still in flight.
    async fn recover_proposal_receipt(
        &self,
        recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError>;

    /// Recover a proposal while the worker already holds its delivery
    /// transaction.
    ///
    /// The product must use `transaction` for the serialized receipt lookup.
    /// In particular, it must not check out another pooled connection while
    /// the delivery row is locked: a valid single-connection deployment has
    /// no second connection to lend, and final lease recovery must still make
    /// progress there.
    async fn recover_proposal_receipt_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        recovery: ProposalReceiptRecovery<'_>,
    ) -> Result<Option<ProposalOutcome>, DeliveryError>;

    /// Record one neutral delivery-audit event in the product's audit
    /// journal, inside the transaction the worker is about to commit. Every
    /// audited occurrence and every audited field of the moved worker arrives
    /// here.
    async fn record_audit(
        &self,
        transaction: &Transaction<'_>,
        record: DeliveryAuditRecord<'_>,
    ) -> Result<(), DeliveryError>;

    /// Report one operational event through the product's vocabulary.
    fn operational_event(&self, event: DeliveryOperationalEvent);
}

/// One activated delivery destination, resolved by the product for a
/// compiled logical destination id.
///
/// Signing and sending stay with the product: the key material never leaves
/// the destination, and the product's mapping fills the signature's method,
/// request target, and content type from the same binding the transport
/// uses, so signing and transport cannot disagree.
#[async_trait]
pub trait HookDestination: Send + Sync {
    /// Digest of the exact binding this destination was activated under.
    fn binding_digest(&self) -> &str;

    /// Deployed per-attempt timeout.
    fn attempt_timeout(&self) -> Duration;

    /// Deployed maximum attempt count.
    fn maximum_attempts(&self) -> u8;

    /// Sign one delivery with the product's scheme and key material.
    fn sign_delivery(
        &self,
        fields: DeliverySignatureFields<'_>,
    ) -> Result<String, DeliverySignatureRefused>;

    /// Render the signed request for transport.
    fn render_delivery(
        &self,
        headers: EventDeliveryHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError>;

    /// Send the rendered request with the remaining attempt budget.
    async fn send_delivery(
        &self,
        request: EventDestinationRequest,
        remaining: Duration,
    ) -> Result<DestinationAnswer, DestinationSendError>;
}

/// The neutral signing input for one delivery attempt.
///
/// The product maps this onto its own scheme. The values are exactly the
/// ones the wire carries: changing any of them changes wire bytes.
#[derive(Clone, Copy, Debug)]
pub struct DeliverySignatureFields<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub event_type: &'a str,
    pub time: &'a str,
    pub data_schema: &'a str,
    pub generation: &'a str,
    pub attempt: &'a str,
    pub delivery_time: &'a str,
    pub idempotency_key: &'a str,
    pub body: &'a [u8],
}

/// The product's signing scheme refused the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliverySignatureRefused;

/// What the destination answered one attempt with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationAnswer {
    /// The destination answered 2xx, carrying the bounded response body it
    /// returned. The body is the handler message; an empty body is the
    /// `none` answer.
    Delivered {
        /// The bounded response body, exactly as received.
        body: Vec<u8>,
    },
    /// The destination answered, and not with 2xx.
    NonSuccess {
        /// The status the destination answered with.
        status: u16,
    },
    /// The destination answered 2xx and its body could not be taken under
    /// the handler output contract: over the ceiling, past the deadline, or
    /// cut off mid-read. The product classifies the reason with the same
    /// table a local run is classified by.
    AnswerRefused(HandlerRunFailure),
}

/// The binding a delivery row recorded for a local-kind handler.
///
/// Every value here comes from the row the worker claimed, so the product
/// resolves the program the row was written against and no other: the
/// package revision pins the deployed package, and the digest pins the exact
/// reviewed script or module inside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookHandlerBinding<'a> {
    /// The local kind the row recorded. Never [`HookHandlerKind::Url`].
    pub kind: HookHandlerKind,
    /// The compiled delivery this row belongs to.
    pub compiled_delivery_id: &'a str,
    /// The package revision the row was captured under.
    pub package_revision: &'a str,
    /// The `sha256:<hex>` digest of the reviewed script or module.
    pub handler_digest: &'a str,
}

/// One accepted proposal the worker hands the product to apply.
///
/// The library never opens the proposal document: validating it,
/// authorizing it under the principal the hook declared, and applying it
/// are the product's job, through the same path any other proposed change
/// takes. Everything here is identity and the exact bytes the row records,
/// so the product binds what was recorded, not what it reconstructs.
#[derive(Clone, Copy, Debug)]
pub struct ProposalApplication<'a> {
    /// The delivered event the proposal answers.
    pub event_id: Uuid,
    /// The compiled delivery the proposal was delivered under.
    pub compiled_delivery_id: &'a str,
    /// The replay generation this worker claimed.
    pub generation: i64,
    /// The attempt this worker claimed within the generation.
    pub attempt: i16,
    /// The exact lease this worker claimed. The product revalidates this
    /// after acquiring the proposal lock so an older worker cannot apply
    /// after a later attempt has settled the delivery.
    pub lease_token: Uuid,
    /// The package revision the delivery row was captured under.
    pub package_revision: &'a str,
    /// The canonical stored envelope bytes that were delivered.
    pub envelope: &'a [u8],
    /// The canonical handler message bytes that carried the proposal.
    pub answer: &'a [u8],
    /// The digest of exactly `answer`. It binds the accepted answer to the
    /// application without entering the application key: the product's
    /// binding reference carries it, so a retry with the same answer replays
    /// and a retry with a changed answer conflicts.
    pub answer_digest: &'a [u8; 32],
}

/// One non-proposal or exhausted no-answer attempt checked against any
/// proposal receipt the product may already have committed for the delivery.
#[derive(Clone, Copy, Debug)]
pub struct ProposalReceiptRecovery<'a> {
    /// The delivered event the current answer addresses.
    pub event_id: Uuid,
    /// The compiled delivery whose earlier proposal may have committed.
    pub compiled_delivery_id: &'a str,
}

/// A bounded refusal code on a proposal outcome, under the same ceiling a
/// handler refusal code carries so one bound governs every recorded reason.
pub type ProposalCode = BoundedText<MAX_REFUSAL_CODE_BYTES>;

/// A bounded summary on a proposal outcome, under the same ceiling a handler
/// refusal summary carries.
pub type ProposalSummary = BoundedText<MAX_REFUSAL_SUMMARY_BYTES>;

/// What became of one proposal the worker handed the product.
///
/// [`ProposalOutcome::Refused`] is a deterministic refusal: the proposal
/// failed validation or authorization, retrying the delivery cannot change
/// it, and the delivery row still completes as delivered. A hook that
/// declared no principal is not that case: it is a deployment defect, and
/// its proposal is [`ProposalOutcome::DeadLettered`] with the reason, so the
/// row is terminal without applying anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalOutcome {
    /// The proposal was applied; `resulting_revision` is the revision the
    /// applied mutation produced.
    Applied {
        /// The revision of the record the applied mutation produced.
        resulting_revision: i64,
    },
    /// The proposal was refused by validation or authorization, and nothing
    /// was applied.
    Refused {
        /// The product's stable refusal code.
        code: ProposalCode,
        /// A bounded, human-readable summary of the refusal.
        summary: ProposalSummary,
    },
    /// The proposal can never be applied, and the delivery is terminal.
    DeadLettered {
        /// The product's stable reason code.
        code: ProposalCode,
        /// A bounded, human-readable summary of the reason.
        summary: ProposalSummary,
    },
}

/// One runnable local handler, resolved by the product for a delivery row's
/// [`HookHandlerBinding`].
///
/// Execution stays with the product: the reviewed program, the engine, and
/// every budget it runs under belong to the product, and only bounded bytes
/// and a shared failure category come back.
#[async_trait]
pub trait HookHandler: Send + Sync {
    /// Digest of the exact program this handler was resolved under.
    fn handler_digest(&self) -> &str;

    /// Deployed per-attempt timeout.
    fn attempt_timeout(&self) -> Duration;

    /// Deployed maximum attempt count.
    fn maximum_attempts(&self) -> u8;

    /// Run the program over the stored envelope bytes with the remaining
    /// attempt budget, and answer with the handler message bytes it
    /// produced. An empty answer is the `none` answer.
    async fn run(&self, envelope: &[u8], remaining: Duration)
        -> Result<Vec<u8>, HandlerRunFailure>;
}

/// A local handler run failed, in the shared five-category taxonomy.
///
/// The product classifies: it is the side that knows whether its engine hit
/// a deadline, exhausted a budget, trapped, or answered outside the contract.
/// The library records the category it is given and never reinterprets it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerRunFailure {
    /// The failure's category in the taxonomy.
    pub category: ErrorCategory,
}

impl HandlerRunFailure {
    /// A run failure in `category`.
    #[must_use]
    pub const fn new(category: ErrorCategory) -> Self {
        Self { category }
    }
}

impl From<ErrorCategory> for HandlerRunFailure {
    fn from(category: ErrorCategory) -> Self {
        Self::new(category)
    }
}

/// The closed phase of a neutral delivery-audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditPhase {
    Attempt,
    Terminal,
    Replay,
}

/// The closed outcome of a neutral delivery-audit event: exactly the
/// outcomes the moved worker records, named for the mechanism they describe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditOutcome {
    AttemptStarted,
    Delivered,
    HttpNonSuccess,
    DestinationTimeout,
    DestinationResolutionRefused,
    DestinationTransportUnavailable,
    DestinationPolicyRefused,
    DestinationBindingRefused,
    HandlerBindingRefused,
    HandlerDeadline,
    HandlerResource,
    HandlerExecution,
    HandlerSource,
    HandlerUnavailable,
    PayloadRefused,
    PayloadExpired,
    WorkerInterrupted,
    ReplayRequested,
}

impl DeliveryAuditOutcome {
    /// The outcome recorded for a handler failure in `category`.
    ///
    /// Running a local program and reading a remote answer fail the same
    /// way, so both arrive here: the category is the taxonomy's, and the
    /// outcome names it.
    #[must_use]
    pub const fn handler_failure(category: ErrorCategory) -> Self {
        match category {
            ErrorCategory::Deadline => Self::HandlerDeadline,
            ErrorCategory::Resource => Self::HandlerResource,
            ErrorCategory::Execution => Self::HandlerExecution,
            ErrorCategory::Source => Self::HandlerSource,
            ErrorCategory::Unavailable => Self::HandlerUnavailable,
        }
    }
}

/// The closed disposition of a neutral delivery-audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditDisposition {
    Leased,
    Delivered,
    RetryPending,
    DeadLettered,
    Expired,
    ReplayPending,
}

/// One neutral delivery-audit event.
///
/// This is the complete audit surface of the worker: every occurrence the
/// moved worker audited arrives here once, with exactly these fields, and
/// the product maps it 1:1 onto its own audit vocabulary and journal.
#[derive(Clone, Copy, Debug)]
pub struct DeliveryAuditRecord<'a> {
    pub event_id: Uuid,
    pub compiled_delivery_id: &'a str,
    pub package_revision: &'a str,
    pub generation: i64,
    pub attempt: i16,
    pub phase: DeliveryAuditPhase,
    pub outcome: DeliveryAuditOutcome,
    pub disposition: DeliveryAuditDisposition,
}

/// The closed state-transition failure codes of the claim path. The codes
/// identify only the failed transition class and never carry destination or
/// event values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryTransitionCode {
    ClaimIdentityRefused,
    ClaimRecoveryFailed,
    ClaimSelectFailed,
    ClaimPolicyRefused,
    ClaimUpdateFailed,
    ClaimAuditFailed,
    ClaimCommitFailed,
}

/// The closed operational-event vocabulary of the worker: low-cardinality,
/// value-free process state, deliberately unrelated to audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOperationalEvent {
    /// One worker poll iteration failed.
    IterationFailed,
    /// One claim-path state transition failed.
    TransitionFailed(DeliveryTransitionCode),
}
