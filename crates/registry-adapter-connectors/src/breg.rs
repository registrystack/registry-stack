// SPDX-License-Identifier: Apache-2.0
//! The BReg connector: read and lookup, direct mutation, immediate
//! Action, Proposal Action, and batch and ingestion runs, over
//! `registry-breg-client` (`products/adapter/CONCEPT.md` section 17.3).
//!
//! Each family lands in its own module under `breg/`; [`BregConnector::catalog`]
//! advertises exactly the implemented, enabled operations.
//!
//! # Shape
//!
//! [`BregConnector::connect`] resolves the caller-filtered Registry Metadata
//! once and selects every binding the configured families need. The resulting
//! connector hands out one operation object per advertised descriptor; each
//! implements [`Operation`](crate::operation::Operation) with a prepared form
//! that is exact JSON bytes holding request material and the runner's command
//! key, never a bearer token. `send` performs the family's one client
//! exchange; `recover` applies the descriptor's rule with the same key. The
//! operation contract is synchronous, so the connector runs the client's
//! async exchanges on a private single-thread runtime: `send`, `recover`, and
//! observation block the calling thread, and any in-process counterpart (a
//! test service) must run on another thread.
//!
//! # Closed input shapes
//!
//! Every operation's `prepare` validates its input against the closed shape
//! its module documents (the descriptor's `ConnectorDefined` schema). Inputs
//! are refused before any I/O; a shape mismatch is
//! [`ConnectorFault::InvalidInput`], a missing runtime binding is
//! [`ConnectorFault::AuthorityAbsent`], and restored bytes that belong to
//! another operation or an earlier envelope version are
//! [`ConnectorFault::NotPrepared`].
//!
//! # The direct destination
//!
//! The connector implements more operations than an ingestion job may
//! send. A job sends an item directly to BReg only when the item maps to
//! exactly one BReg operation with no lookup: an immediate Action, or a
//! Proposal start and submit (`products/adapter/CONCEPT.md` sections 17.1
//! and 17.3). Record create, patch, and tombstone, batch, and the
//! ingestion run family stay out of a job's direct path: an item that
//! needs a lookup or a choice goes to Coordinator, and bulk ends in a
//! file for `bregctl data import`. The job's destination wiring admits a
//! configured operation only when [`job_direct_admits`] does, so the
//! credential it holds needs only the narrow grants those operations
//! use.

use std::sync::Arc;

use registry_breg_client::{
    BRegActionBinding, BRegActionMode, BRegBatchBinding, BRegCreateBinding, BRegDirectWrite,
    BRegPatchBinding, BRegProposalCollection, BRegProposalGetBinding, BRegTombstoneBinding,
    BaseRegistryClient, BaseRegistryClientConfig, BaseRegistryClientError, TokenProvider,
    DEFAULT_ATTEMPT_TIMEOUT,
};

use crate::operation::{ConnectorFault, OperationDescriptor, OutcomeCategory, SendOutcome};

pub mod action;
pub mod batch;
pub mod ingestion;
pub mod mutation;
pub mod proposal;
pub mod read;

use read::RouteReads;

/// The caller-supplied settings one [`BregConnector`] resolves at
/// construction. Credentials stay host-owned: the token provider is never
/// copied into a prepared form.
#[derive(Clone)]
pub struct BregConnectorConfig {
    /// The deployment origin, with any deployment prefix, for example
    /// `https://breg.example/institution-a`. Loopback HTTP is accepted the
    /// way the client accepts it.
    pub origin: String,
    /// The host-owned credential provider the client consults per call.
    pub token_provider: Arc<dyn TokenProvider>,
    /// The access profile every binding and call selects under.
    pub access_profile: String,
    /// The Action identifier behind `breg.action.invoke` and
    /// `breg.proposal.start`; its metadata-selected mode decides which of
    /// the two families is enabled.
    pub action_identifier: String,
    /// The record type identifier the write and batch families bind, for
    /// example `company`.
    pub record_type: String,
    /// The entity route reads and ingestion runs use, for example
    /// `companies`.
    pub record_route: String,
    /// Whether the host opened destructive tombstone authority. Default
    /// off: a disabled tombstone is absent from the catalog and `prepare`
    /// answers [`ConnectorFault::AuthorityAbsent`].
    pub allow_tombstone: bool,
    /// Whether the host opened the destination's operator-opened import
    /// authority that the ingestion family writes through. Default off:
    /// the ingestion operations stay out of the catalog and `prepare`
    /// answers [`ConnectorFault::AuthorityAbsent`].
    pub allow_import_profile: bool,
    /// The per-attempt timeout the client enforces; the client's own
    /// default applies when this stays unset.
    pub attempt_timeout: Option<std::time::Duration>,
}

impl BregConnectorConfig {
    /// Configure a connector for one origin, profile, action, and record
    /// type; destructive and operator-opened authority stay off.
    pub fn new(
        origin: impl Into<String>,
        token_provider: Arc<dyn TokenProvider>,
        access_profile: impl Into<String>,
        action_identifier: impl Into<String>,
        record_type: impl Into<String>,
        record_route: impl Into<String>,
    ) -> Self {
        Self {
            origin: origin.into(),
            token_provider,
            access_profile: access_profile.into(),
            action_identifier: action_identifier.into(),
            record_type: record_type.into(),
            record_route: record_route.into(),
            allow_tombstone: false,
            allow_import_profile: false,
            attempt_timeout: None,
        }
    }

    /// Record that the host opened destructive tombstone authority.
    #[must_use]
    pub fn with_tombstone(mut self, allow: bool) -> Self {
        self.allow_tombstone = allow;
        self
    }

    /// Record that the host opened the ingestion family's import authority.
    #[must_use]
    pub fn with_import_profile(mut self, allow: bool) -> Self {
        self.allow_import_profile = allow;
        self
    }

    /// Set the per-attempt timeout the client enforces on every exchange.
    #[must_use]
    pub fn with_attempt_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.attempt_timeout = Some(timeout);
        self
    }
}

/// One connected BReg connector: the client, the metadata-selected
/// bindings, and the private runtime the synchronous operation contract
/// runs the client's async exchanges on.
pub struct BregConnector {
    client: Arc<BaseRegistryClient>,
    // Held as an option so the drop path can move the shutdown off a
    // thread that may not block.
    runtime: Option<tokio::runtime::Runtime>,
    profile: String,
    route: String,
    record_type: String,
    import_opened: bool,
    action: BRegActionBinding,
    create: Option<BRegCreateBinding>,
    patch: Option<BRegPatchBinding>,
    tombstone: Option<BRegTombstoneBinding>,
    batch: Option<BRegBatchBinding>,
    proposal_get: Option<BRegProposalGetBinding>,
    proposal_collection: Option<BRegProposalCollection>,
}

impl BregConnector {
    /// Resolve the deployment's caller-filtered metadata and select every
    /// binding the configuration names. No mutation runs here; the read
    /// answers with the connector or with the fault the metadata refusal
    /// maps to. A named action the deployment does not disclose is
    /// [`ConnectorFault::AuthorityAbsent`]; write, batch, and Proposal
    /// families the deployment does not disclose simply stay absent from
    /// the catalog.
    pub async fn connect(config: BregConnectorConfig) -> Result<Self, ConnectorFault> {
        // The base URL type is the client configuration's own; parsing stays
        // through it, so this crate carries no URL dependency of its own.
        let client = Arc::new(
            BaseRegistryClient::new(
                BaseRegistryClientConfig::new(
                    config
                        .origin
                        .parse()
                        .map_err(|_| ConnectorFault::InvalidInput)?,
                )
                .with_token_provider(config.token_provider)
                .with_user_agent("registry-adapter-connector")
                .with_attempt_timeout(config.attempt_timeout.unwrap_or(DEFAULT_ATTEMPT_TIMEOUT)),
            )
            .map_err(|error| fault(&error))?,
        );
        let metadata = client
            .registry_contract(Some(&config.access_profile))
            .await
            .map_err(|error| fault(&error))?
            .value;
        let action = metadata
            .select_action(&config.action_identifier, &config.access_profile)
            .map_err(|_| ConnectorFault::AuthorityAbsent)?;
        let direct =
            |identifier: String| metadata.select_direct_write(&identifier, &config.access_profile);
        let create = direct(format!("records.{}.create", config.record_type))
            .ok()
            .and_then(|write| match write {
                BRegDirectWrite::Create(binding) => Some(binding),
                BRegDirectWrite::Patch(_) => None,
            });
        let patch = direct(format!("records.{}.patch", config.record_type))
            .ok()
            .and_then(|write| match write {
                BRegDirectWrite::Patch(binding) => Some(binding),
                BRegDirectWrite::Create(_) => None,
            });
        let tombstone = if config.allow_tombstone {
            metadata
                .select_tombstone(&config.record_type, &config.access_profile)
                .ok()
        } else {
            None
        };
        let batch = metadata
            .select_batch(&config.record_type, &config.access_profile)
            .ok();
        let proposal_get = metadata.select_proposal_get(&config.access_profile).ok();
        let proposal_collection = metadata.select_proposals(&config.access_profile).ok();
        // A runtime must not be built inside another runtime's context,
        // so the private runtime is born on its own short-lived thread.
        let runtime = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
        .join()
        .expect("the runtime thread joins")
        .map_err(|_| ConnectorFault::Native { code: None })?;
        Ok(Self {
            client,
            runtime: Some(runtime),
            profile: config.access_profile,
            route: config.record_route,
            record_type: config.record_type,
            import_opened: config.allow_import_profile,
            action,
            create,
            patch,
            tombstone,
            batch,
            proposal_get,
            proposal_collection,
        })
    }

    /// The descriptors this connected deployment advertises: exactly the
    /// implemented operations whose binding and authority are present.
    pub fn catalog(&self) -> Vec<&'static OperationDescriptor> {
        let mut descriptors = Vec::new();
        if self.create.is_some() {
            descriptors.push(&*mutation::CREATE);
        }
        if self.patch.is_some() {
            descriptors.push(&*mutation::PATCH);
        }
        if self.tombstone.is_some() {
            descriptors.push(&*mutation::TOMBSTONE);
        }
        if self.action_mode() == BRegActionMode::Immediate {
            descriptors.push(&*action::INVOKE);
        }
        if self.action_mode() == BRegActionMode::Proposal
            && self.proposal_get.is_some()
            && self.proposal_collection.is_some()
        {
            descriptors.push(&*proposal::START);
            descriptors.push(&*proposal::SUBMIT);
        }
        if self.batch.is_some() {
            descriptors.push(&*batch::RECORDS);
        }
        if self.import_opened {
            descriptors.push(&*ingestion::CREATE_RUN);
            descriptors.push(&*ingestion::SUBMIT_CHUNK);
        }
        descriptors
    }

    /// The operation objects, by family. Each advertises the descriptor
    /// [`BregConnector::catalog`] listed and refuses `prepare` with
    /// [`ConnectorFault::AuthorityAbsent`] when the runtime binding it
    /// needs is absent.
    pub fn record_create(self: &Arc<Self>) -> mutation::RecordCreate {
        mutation::RecordCreate {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn record_patch(self: &Arc<Self>) -> mutation::RecordPatch {
        mutation::RecordPatch {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn record_tombstone(self: &Arc<Self>) -> mutation::RecordTombstone {
        mutation::RecordTombstone {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn action_invoke(self: &Arc<Self>) -> action::ActionInvoke {
        action::ActionInvoke {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn proposal_start(self: &Arc<Self>) -> proposal::ProposalStart {
        proposal::ProposalStart {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn proposal_submit(self: &Arc<Self>) -> proposal::ProposalSubmit {
        proposal::ProposalSubmit {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn batch_records(self: &Arc<Self>) -> batch::BatchRecords {
        batch::BatchRecords {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn ingestion_create_run(self: &Arc<Self>) -> ingestion::IngestionCreateRun {
        ingestion::IngestionCreateRun {
            connector: Arc::clone(self),
        }
    }

    /// See [`BregConnector::record_create`].
    pub fn ingestion_submit_chunk(self: &Arc<Self>) -> ingestion::IngestionSubmitChunk {
        ingestion::IngestionSubmitChunk {
            connector: Arc::clone(self),
        }
    }

    /// The N1 read family: get, revisions, bounded list pages, lookup,
    /// and Proposal listing.
    #[must_use]
    pub fn reads(&self) -> RouteReads<'_> {
        RouteReads { connector: self }
    }

    pub(crate) fn client(&self) -> &BaseRegistryClient {
        &self.client
    }

    /// Run one async client exchange to completion on the connector's
    /// private runtime. The call is synchronous and blocks a short-lived
    /// worker, so a send may be made from any thread, including from
    /// inside another runtime.
    pub(crate) fn block<T: Send>(
        &self,
        exchange: impl std::future::Future<Output = T> + Send,
    ) -> T {
        let runtime = self
            .runtime
            .as_ref()
            .expect("the runtime lives as long as the connector");
        std::thread::scope(|scope| {
            scope
                .spawn(|| runtime.block_on(exchange))
                .join()
                .expect("the exchange worker joins")
        })
    }

    /// Move the runtime shutdown onto a worker, so a connector may be
    /// dropped from any thread, including inside another runtime.
    fn shutdown(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || drop(runtime));
        }
    }

    pub(crate) fn profile(&self) -> &str {
        &self.profile
    }

    pub(crate) fn route(&self) -> &str {
        &self.route
    }

    pub(crate) fn action_binding(&self) -> &BRegActionBinding {
        &self.action
    }

    pub(crate) fn action_mode(&self) -> BRegActionMode {
        self.action.mode()
    }

    pub(crate) fn create_binding(&self) -> Result<&BRegCreateBinding, ConnectorFault> {
        self.create.as_ref().ok_or(ConnectorFault::AuthorityAbsent)
    }

    pub(crate) fn patch_binding(&self) -> Result<&BRegPatchBinding, ConnectorFault> {
        self.patch.as_ref().ok_or(ConnectorFault::AuthorityAbsent)
    }

    pub(crate) fn tombstone_binding(&self) -> Result<&BRegTombstoneBinding, ConnectorFault> {
        self.tombstone
            .as_ref()
            .ok_or(ConnectorFault::AuthorityAbsent)
    }

    pub(crate) fn batch_binding(&self) -> Result<&BRegBatchBinding, ConnectorFault> {
        self.batch.as_ref().ok_or(ConnectorFault::AuthorityAbsent)
    }

    pub(crate) fn proposal_get_binding(&self) -> Result<&BRegProposalGetBinding, ConnectorFault> {
        self.proposal_get
            .as_ref()
            .ok_or(ConnectorFault::AuthorityAbsent)
    }

    pub(crate) fn proposal_collection(&self) -> Result<&BRegProposalCollection, ConnectorFault> {
        self.proposal_collection
            .as_ref()
            .ok_or(ConnectorFault::AuthorityAbsent)
    }

    /// Read one record through the deployment's route and profile; the
    /// mutation and action observations read the effect back this way.
    pub(crate) fn observe_record(
        &self,
        record_identifier: &str,
    ) -> Result<crate::operation::NativeState, ConnectorFault> {
        let reads = self.reads();
        let record = reads.get_record(record_identifier)?;
        Ok(crate::operation::NativeState {
            state: "present".to_owned(),
            details: vec![
                ("recordType".to_owned(), self.record_type.clone()),
                (
                    "revision".to_owned(),
                    record.value.data.revision_identifier.clone(),
                ),
            ],
        })
    }
}

impl Drop for BregConnector {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Map one client refusal to the connector fault vocabulary, for reads
/// and construction. Value-free: the fault carries the product's problem
/// code or transport kind, never a payload or selector value.
pub(crate) fn fault(error: &BaseRegistryClientError) -> ConnectorFault {
    match error {
        BaseRegistryClientError::Problem { code, .. } => ConnectorFault::Native {
            code: Some(code.code().to_owned()),
        },
        BaseRegistryClientError::UnrecognizedProblem { .. } => {
            ConnectorFault::Native { code: None }
        }
        BaseRegistryClientError::Transport { kind } => ConnectorFault::Native {
            code: Some(format!("transport.{}", kind.kind())),
        },
        // The client answers prepared evidence that no longer matches the
        // current binding with an invalid-request refusal.
        BaseRegistryClientError::InvalidRequest { .. } => ConnectorFault::BindingChanged,
        BaseRegistryClientError::Token(_) => ConnectorFault::AuthorityAbsent,
        BaseRegistryClientError::Configuration { .. }
        | BaseRegistryClientError::Protocol { .. } => ConnectorFault::Native { code: None },
        // The client's error set is non-exhaustive; an unseen variant is a
        // fault without a product word.
        _ => ConnectorFault::Native { code: None },
    }
}

/// Classify one mutation answer into the shared outcome vocabulary.
///
/// An outcome the product left unknown is [`OutcomeCategory::Uncertain`],
/// never an error, so the runner applies the recovery rule instead of
/// guessing. A typed refusal keeps the product's own problem code. A fault
/// that means the call could not be made or honored is an error.
pub(crate) fn classify(error: &BaseRegistryClientError) -> Result<SendOutcome, ConnectorFault> {
    if error.is_outcome_unknown() {
        return Ok(SendOutcome {
            category: OutcomeCategory::Uncertain,
            native_problem: native_word(error),
            correlation: None,
            note: Some(
                "recover under this operation's rule; success is never inferred from silence",
            ),
        });
    }
    match error {
        BaseRegistryClientError::Problem { code, .. } => Ok(refused(code.code())),
        BaseRegistryClientError::UnrecognizedProblem { .. } => Ok(refused_word(None)),
        BaseRegistryClientError::InvalidRequest { .. } => Err(ConnectorFault::BindingChanged),
        BaseRegistryClientError::Token(_) => Err(ConnectorFault::AuthorityAbsent),
        BaseRegistryClientError::Transport { kind } => Err(ConnectorFault::Native {
            code: Some(format!("transport.{}", kind.kind())),
        }),
        BaseRegistryClientError::Configuration { .. }
        | BaseRegistryClientError::Protocol { .. } => Err(ConnectorFault::Native {
            code: native_word(error),
        }),
        // The client's error set is non-exhaustive; an unseen variant is a
        // fault carrying whatever product word it exposes.
        _ => Err(ConnectorFault::Native {
            code: native_word(error),
        }),
    }
}

fn native_word(error: &BaseRegistryClientError) -> Option<String> {
    match error {
        BaseRegistryClientError::Problem { code, .. } => Some(code.code().to_owned()),
        _ => error.problem_code().map(|code| code.code().to_owned()),
    }
}

/// A typed refusal carrying the product's own problem code.
pub(crate) fn refused(code: &str) -> SendOutcome {
    refused_word(Some(code.to_owned()))
}

fn refused_word(code: Option<String>) -> SendOutcome {
    SendOutcome {
        category: OutcomeCategory::Refused,
        native_problem: code,
        correlation: None,
        note: Some("a refusal never falls back to another mutation mode"),
    }
}

/// The completed outcome for one committed effect.
pub(crate) fn completed(correlation: String) -> SendOutcome {
    SendOutcome {
        category: OutcomeCategory::Completed,
        native_problem: None,
        correlation: Some(correlation),
        note: None,
    }
}

/// The accepted outcome for work the destination now holds under its own
/// lifecycle.
pub(crate) fn accepted(correlation: String) -> SendOutcome {
    SendOutcome {
        category: OutcomeCategory::Accepted,
        native_problem: None,
        correlation: Some(correlation),
        note: None,
    }
}

/// A refusal the product answered with its own lifecycle word instead of
/// a problem code (the destination's state left the prepared transition
/// behind).
pub(crate) fn refused_state(state: &str) -> SendOutcome {
    SendOutcome {
        category: OutcomeCategory::Refused,
        native_problem: Some(state.to_owned()),
        correlation: None,
        note: Some("the destination's state left the prepared transition behind; re-prepare"),
    }
}

/// Whether an ingestion job may send this operation directly to BReg:
/// only an immediate Action or a Proposal start and submit, the one-
/// operation shapes the direct destination admits (see the module
/// documentation).
pub fn job_direct_admits(descriptor: &OperationDescriptor) -> bool {
    [
        action::INVOKE.name,
        proposal::START.name,
        proposal::SUBMIT.name,
    ]
    .contains(&descriptor.name)
}

/// Recovery's reading of a keyed exchange's answer.
///
/// Recovery repeats an attempt whose first answer was lost, so a
/// receipt-horizon answer no longer proves the attempt never ran. The
/// destination answers `idempotency.expired` to an exact retry whose
/// first attempt committed before the receipt horizon passed, and
/// `idempotency.key-reused` to a retry whose held response a retention
/// erase removed, whose first attempt committed under another package
/// activation, access profile, or claims, or (for a guarded Action) whose
/// body was rebuilt after the first attempt moved its target. Either
/// answer is [`OutcomeCategory::Uncertain`] on recovery, settled by reading
/// the destination and never by a resend under another key. A first send
/// keeps the refusal: its key carried no earlier attempt, so the answer
/// is a genuine collision.
pub(crate) fn recovered(
    answer: Result<SendOutcome, ConnectorFault>,
) -> Result<SendOutcome, ConnectorFault> {
    let outcome = answer?;
    if outcome.category != OutcomeCategory::Refused {
        return Ok(outcome);
    }
    let note = match outcome.native_problem.as_deref() {
        Some(problems::IDEMPOTENCY_EXPIRED) => {
            "the destination answered that the first attempt committed before its receipt \
             horizon; settle by reading the destination"
        }
        Some(problems::IDEMPOTENCY_KEY_REUSED) => {
            "the key is spent and the first attempt may have committed; settle by reading the \
             destination"
        }
        _ => return Ok(outcome),
    };
    Ok(SendOutcome {
        category: OutcomeCategory::Uncertain,
        note: Some(note),
        ..outcome
    })
}

/// The problem code words the connector surfaces verbatim.
pub mod problems {
    /// The key is bound to another request (409).
    pub const IDEMPOTENCY_KEY_REUSED: &str =
        registry_breg_client::BRegProblemCode::IdempotencyConflict.code();
    /// The key's held response expired; the key stays spent (410).
    pub const IDEMPOTENCY_EXPIRED: &str =
        registry_breg_client::BRegProblemCode::IdempotencyExpired.code();
    /// The lookup did not resolve exactly one record (404, kind `problem`).
    pub const LOOKUP_UNRESOLVED: &str =
        registry_breg_client::BRegProblemCode::LookupUnresolved.code();
}
