//! Evidence-owned authorization and input minimization around Adapter programs.

use crate::{
    bundle::{ArtifactFault, Bundle, RuntimeDocument, SourcePack},
    config::{AssuranceProfile, SchemaFault, SourceConfig, WALLET_PRESENTATION_PROTOCOL_ID},
    model::{ChannelKind, LookupResult},
    observability::{DependencyOutcome, SourceLookupOutcome, SourceObserver, UndeclaredNotFound},
    presented::PresentedFacts,
    secrets::SecretResolver,
    selector::{ResolvedAuthorization, ResolvedSubject},
};
use chrono::{DateTime, Utc};
use registry_adapter_core::{
    walk_steps, AdapterPack, EndpointAuthentication, EvidenceConnectionPolicy, SendComponent, Step,
};
use registry_adapter_engine::component::http::uri::PinnedOrigin;
use registry_adapter_engine::evidence::{
    compile_evidence_with_protocols, ConnectionPolicyReason, EvidenceBeginError,
    EvidenceCompileError, EvidenceCompileInputs, EvidenceExecutionError, EvidenceHostHooks,
    EvidenceLimits, EvidenceLookup, EvidenceProgram, EvidenceRuntimeBindings,
    EvidenceTerminalError,
};
use registry_adapter_engine::host_protocol::{HostProtocolAttachment, HostProtocolRegistry};
use registry_adapter_engine::route::{EvidenceHttpDiagnostic, RouteFailure};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use thiserror::Error;

/// Value-free failures at Evidence's pack boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PackSourceError {
    #[error("the reviewed pack source or connection binding is invalid")]
    Plan,
    #[error("authorized selectors do not satisfy the route input contract")]
    Inputs,
    #[error("source acquisition authority refused the operation")]
    Authority,
    #[error("source acquisition intent could not be audited")]
    Audit,
    #[error("the shared source acquisition budget is exhausted")]
    Budget,
    #[error("the source route violated its protocol or result contract")]
    Protocol,
    #[error("the source dependency is unavailable")]
    Dependency,
    #[error("the source extract is unavailable")]
    ExtractUnavailable,
    #[error("the source extract is stale")]
    ExtractStale,
    #[error("the reviewed source statement is invalid")]
    StatementRefused,
    #[error("the source statement parameters are invalid")]
    StatementParameter,
    #[error("the source statement budget is exhausted")]
    StatementBudget,
    #[error("the source statement result is invalid")]
    StatementResult,
    #[error("the source statement worker is unavailable")]
    StatementUnavailable,
    #[error("the source response exceeds its byte bound")]
    ResponseTooLarge,
    #[error("the source admission boundary is unavailable")]
    Concurrency,
    #[error("the source credential is unavailable")]
    Credential,
    #[error("the source operation timed out")]
    Timeout,
}

/// Why a pack source did not compile against its reviewed connection and
/// runtime binding. Each reason is a fixed sentence: it names the member to
/// change and never carries an origin, a secret reference or trust bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SourceBindingReason {
    #[error("the `sourceAcquisition` limits are invalid")]
    AcquisitionLimits,
    #[error("the Evidence host protocol registry is unavailable")]
    HostProtocols,
    #[error("the bundle carries no pack closure for this source")]
    PackMissing,
    #[error("the source's `connection` has no reviewed or runtime `sourceConnections` entry")]
    ConnectionUnbound,
    #[error("the reviewed connection names an endpoint the pack does not declare")]
    PackEndpointMissing,
    #[error(
        "the reviewed `baseUrl` is not a canonical source origin, or is not `https` outside the local assurance profile"
    )]
    BaseUrlRefused,
    #[error(
        "the pack endpoint has no authentication and the runtime binding no `mtlsIdentity`; only a loopback origin under the local assurance profile may"
    )]
    Unauthenticated,
    #[error("the route's static data-operation count is above `sourceAcquisition.maximumDataOperations`")]
    OperationBudget,
    #[error("the pack route does not compile; run `adapterctl check` on the pack")]
    Route,
    #[error(
        "a requirement Source is on the wrong acquisition channel: only `acquisition.holderPresented.source` may use the wallet presentation protocol, and it must"
    )]
    AcquisitionChannel,
    #[error("{0}")]
    Policy(ConnectionPolicyReason),
}

/// A pack source refused at compilation, naming the governed source and
/// endpoint ids an operator corrects, with the value-free rule it broke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBindingError {
    source_id: Option<String>,
    endpoint: Option<String>,
    reason: SourceBindingReason,
}

impl SourceBindingError {
    fn new(reason: SourceBindingReason) -> Self {
        Self {
            source_id: None,
            endpoint: None,
            reason,
        }
    }

    fn at_endpoint(endpoint: &str, reason: SourceBindingReason) -> Self {
        Self {
            endpoint: Some(endpoint.to_owned()),
            ..Self::new(reason)
        }
    }

    fn for_source(mut self, source_id: &str) -> Self {
        self.source_id = Some(source_id.to_owned());
        self
    }

    /// The bundle `sources` id, when the refusal belongs to one source.
    #[must_use]
    pub fn source_id(&self) -> Option<&str> {
        self.source_id.as_deref()
    }

    /// The pack endpoint id, when the refusal belongs to one endpoint.
    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    #[must_use]
    pub const fn reason(&self) -> SourceBindingReason {
        self.reason
    }
}

impl std::fmt::Display for SourceBindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.source_id, &self.endpoint) {
            (Some(source), Some(endpoint)) => write!(
                formatter,
                "source `{source}` endpoint `{endpoint}`: {}",
                self.reason
            ),
            (Some(source), None) => write!(formatter, "source `{source}`: {}", self.reason),
            (None, Some(endpoint)) => write!(formatter, "endpoint `{endpoint}`: {}", self.reason),
            (None, None) => std::fmt::Display::fmt(&self.reason, formatter),
        }
    }
}

impl std::error::Error for SourceBindingError {}

/// Keep the engine's endpoint and connection-policy rule; every other compile
/// failure becomes a fixed reason, because its detail can name pack-owned
/// strings that do not belong in a deployment diagnostic.
fn compile_refusal(error: &EvidenceCompileError) -> SourceBindingError {
    match error {
        EvidenceCompileError::ConnectionPolicy { endpoint, reason } => {
            SourceBindingError::at_endpoint(endpoint, SourceBindingReason::Policy(*reason))
        }
        EvidenceCompileError::EndpointUnbound => SourceBindingError::new(
            SourceBindingReason::Policy(ConnectionPolicyReason::EndpointUnbound),
        ),
        EvidenceCompileError::StaticOperationBudgetExceeded { .. }
        | EvidenceCompileError::StaticOperationBudgetUncountable => {
            SourceBindingError::new(SourceBindingReason::OperationBudget)
        }
        EvidenceCompileError::HostProtocol => {
            SourceBindingError::new(SourceBindingReason::HostProtocols)
        }
        _ => SourceBindingError::new(SourceBindingReason::Route),
    }
}

/// Why presented subjects could not become a Source's route inputs. Both are
/// [`PackSourceError::Inputs`] on the relying path; a public check answers a
/// schema refusal as the caller's malformed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubjectInputsError {
    /// The reviewed input bindings cannot project the subjects, a package
    /// fault.
    Projection,
    /// The projected inputs fail the route's inputs schema: the presented
    /// values lie outside what the Source accepts.
    Schema,
}

impl From<SubjectInputsError> for PackSourceError {
    fn from(_: SubjectInputsError) -> Self {
        Self::Inputs
    }
}

/// A categorical source failure plus an operator-only governed diagnosis.
/// Display and Debug intentionally retain only the request-safe category.
#[derive(Clone, Eq, PartialEq)]
pub struct PackSourceFailure {
    category: PackSourceError,
    artifact_fault: Option<ArtifactFault>,
    http_diagnostic: Option<Box<(String, EvidenceHttpDiagnostic)>>,
}

impl PackSourceFailure {
    fn categorical(category: PackSourceError) -> Self {
        Self {
            category,
            artifact_fault: None,
            http_diagnostic: None,
        }
    }

    fn sqlite(fault: registry_adapter_engine::evidence::EvidenceSqliteFault) -> Self {
        let category = sqlite_category(fault.code());
        Self {
            category,
            artifact_fault: Some(ArtifactFault::new(
                fault.artifact(),
                SchemaFault::because(fault.code()),
            )),
            http_diagnostic: None,
        }
    }

    fn http(
        category: PackSourceError,
        endpoint: impl Into<String>,
        diagnostic: EvidenceHttpDiagnostic,
    ) -> Self {
        Self {
            category,
            artifact_fault: None,
            http_diagnostic: Some(Box::new((endpoint.into(), diagnostic))),
        }
    }

    #[must_use]
    pub const fn category(&self) -> PackSourceError {
        self.category
    }

    /// The reviewed artifact or governed runtime binding an operator can fix.
    #[must_use]
    pub fn artifact_fault(&self) -> Option<&ArtifactFault> {
        self.artifact_fault.as_ref()
    }

    pub(crate) fn http_diagnostic(&self) -> Option<EvidenceHttpDiagnostic> {
        self.http_diagnostic
            .as_deref()
            .map(|(_, diagnostic)| *diagnostic)
    }
}

impl std::fmt::Debug for PackSourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackSourceFailure")
            .field("category", &self.category)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for PackSourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.category, formatter)
    }
}

impl std::error::Error for PackSourceFailure {}

/// A listener-free source program with its Evidence-owned input binding.
/// The program captures reviewed connection authority and never receives a
/// caller's complete selector object or unvalidated credential material.
pub struct PackSourceExecutor {
    program: EvidenceProgram,
    source: SourceConfig,
    closure: SourcePack,
    observer: Option<SourceObserver>,
    channel: ChannelKind,
}

/// Private facts plus trusted upstream validity and, for a holder-presented
/// protocol, the verified credential facts, retained outside provider code.
pub struct AcquiredLookup {
    pub lookup: LookupResult,
    pub valid_until: Option<DateTime<Utc>>,
    pub presented: Option<Arc<PresentedFacts>>,
    pub acquisition_deadline: tokio::time::Instant,
}

impl std::fmt::Debug for PackSourceExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackSourceExecutor")
            .field("pack", &self.source.pack.id)
            .field("route", &self.source.route)
            .finish_non_exhaustive()
    }
}

impl PackSourceExecutor {
    pub(crate) fn intent(&self) -> registry_adapter_engine::evidence::EvidenceAcquisitionIntent {
        registry_adapter_engine::evidence::EvidenceAcquisitionIntent {
            pack: self.source.pack.id.as_str().to_owned(),
            route: self.source.route.as_str().to_owned(),
        }
    }

    pub fn extract_is_stale(&self, instant: DateTime<Utc>) -> Result<bool, PackSourceError> {
        self.program
            .probe_extract_freshness(instant)
            .map_err(|_| PackSourceError::Dependency)
    }

    /// Operator-only freshness proof retaining a governed artifact diagnosis.
    pub fn diagnose_extract_freshness(
        &self,
        instant: DateTime<Utc>,
    ) -> Result<(), PackSourceFailure> {
        self.program
            .diagnose_extract_freshness(instant)
            .map_err(readiness_failure)
    }

    pub async fn credentials_ready(&self) -> Result<(), PackSourceError> {
        self.program
            .credentials_ready()
            .await
            .map_err(|error| readiness_failure(error).category())
    }

    pub fn compile(
        source: &SourceConfig,
        closure: &SourcePack,
        runtime: &EvidenceRuntimeBindings,
        policies: &[EvidenceConnectionPolicy],
        limits: EvidenceLimits,
    ) -> Result<Self, PackSourceError> {
        Self::compile_with_registry(
            source,
            closure,
            runtime,
            policies,
            limits,
            &crate::host_protocol::registry().map_err(|_| PackSourceError::Plan)?,
        )
    }

    /// [`Self::compile`] against a caller-supplied protocol registry. The
    /// production path always passes the Evidence host registry; tests pass one
    /// that installs a test double for a protocol.
    pub(crate) fn compile_with_registry(
        source: &SourceConfig,
        closure: &SourcePack,
        runtime: &EvidenceRuntimeBindings,
        policies: &[EvidenceConnectionPolicy],
        limits: EvidenceLimits,
        protocols: &HostProtocolRegistry,
    ) -> Result<Self, PackSourceError> {
        Self::compile_diagnosed_with_registry(source, closure, runtime, policies, limits, protocols)
            .map_err(|_| PackSourceError::Plan)
    }

    /// Compile while retaining the endpoint and value-free rule an operator
    /// corrects when the binding is refused.
    pub fn compile_diagnosed(
        source: &SourceConfig,
        closure: &SourcePack,
        runtime: &EvidenceRuntimeBindings,
        policies: &[EvidenceConnectionPolicy],
        limits: EvidenceLimits,
    ) -> Result<Self, SourceBindingError> {
        Self::compile_diagnosed_with_registry(
            source,
            closure,
            runtime,
            policies,
            limits,
            &crate::host_protocol::registry()
                .map_err(|_| SourceBindingError::new(SourceBindingReason::HostProtocols))?,
        )
    }

    fn compile_diagnosed_with_registry(
        source: &SourceConfig,
        closure: &SourcePack,
        runtime: &EvidenceRuntimeBindings,
        policies: &[EvidenceConnectionPolicy],
        limits: EvidenceLimits,
        protocols: &HostProtocolRegistry,
    ) -> Result<Self, SourceBindingError> {
        let pack = closure.pack();
        let artifacts = closure.artifacts();
        let program = compile_evidence_with_protocols(
            &EvidenceCompileInputs {
                pack: &pack,
                route: source.route.as_str(),
                runtime,
                connection_id: Some(source.connection.as_str()),
                connection: policies,
                pack_artifacts: &artifacts,
                limits,
            },
            protocols,
        )
        .map_err(|error| compile_refusal(&error))?;
        let channel = if route_reaches_protocol(
            &pack,
            source.route.as_str(),
            WALLET_PRESENTATION_PROTOCOL_ID,
        ) {
            ChannelKind::HolderPresented
        } else {
            ChannelKind::Source
        };
        Ok(Self {
            program,
            source: source.clone(),
            closure: closure.clone(),
            observer: None,
            channel,
        })
    }

    /// The channel this Source acquires through: holder-presented exactly when
    /// its route reaches the wallet presentation protocol.
    pub fn channel(&self) -> ChannelKind {
        self.channel
    }

    pub(crate) fn observe(&mut self, observer: Option<SourceObserver>) {
        self.observer = observer;
    }

    /// Validate and minimize before the engine can record access intent,
    /// resolve credentials or perform source effects.
    pub fn inputs(&self, resolved: &ResolvedAuthorization) -> Result<Value, PackSourceError> {
        self.inputs_for_subjects(&resolved.subjects)
            .map_err(PackSourceError::from)
    }

    /// Validate and minimize the presented subjects alone, before the engine
    /// can record access intent, resolve credentials or perform source
    /// effects. A public check reaches the Source through this with no
    /// authorization behind it.
    pub(crate) fn inputs_for_subjects(
        &self,
        subjects: &[ResolvedSubject],
    ) -> Result<Value, SubjectInputsError> {
        let inputs = route_inputs_for_subjects(&self.source, subjects)
            .map_err(|_| SubjectInputsError::Projection)?;
        if !self.program.input_schema().validate(&inputs) {
            return Err(SubjectInputsError::Schema);
        }
        Ok(inputs)
    }

    pub async fn execute(
        &self,
        inputs: Value,
        observed_at: DateTime<Utc>,
        hooks: Arc<dyn EvidenceHostHooks>,
    ) -> Result<LookupResult, PackSourceError> {
        self.execute_with_attribution(inputs, observed_at, hooks, None)
            .await
            .map_err(|failure| failure.category())
            .map(|outcome| outcome.lookup)
    }

    /// Execute while retaining an explicit operator-only artifact diagnosis.
    pub async fn execute_diagnosed(
        &self,
        inputs: Value,
        observed_at: DateTime<Utc>,
        hooks: Arc<dyn EvidenceHostHooks>,
    ) -> Result<LookupResult, PackSourceFailure> {
        self.execute_diagnosed_inner(inputs, observed_at, hooks, None)
            .await
            .map(|outcome| outcome.lookup)
    }

    pub(crate) fn requires_access_attribution(&self) -> bool {
        self.program.requires_access_attribution()
    }

    pub(crate) async fn execute_with_attribution(
        &self,
        inputs: Value,
        observed_at: DateTime<Utc>,
        hooks: Arc<dyn EvidenceHostHooks>,
        attribution: Option<Arc<registry_adapter_engine::host_protocol::HostAccessAttribution>>,
    ) -> Result<AcquiredLookup, PackSourceFailure> {
        let observation = self.observer.as_ref().map(SourceObserver::start);
        let diagnosed = self
            .execute_diagnosed_inner(inputs, observed_at, hooks, attribution)
            .await;
        if let Some(observation) = observation {
            observation.complete(match diagnosed.as_ref() {
                Ok(_) => DependencyOutcome::Success,
                Err(failure) => dependency_outcome(failure),
            });
        }
        if let (Some(observer), Ok(lookup)) = (&self.observer, &diagnosed) {
            observer.lookup(match &lookup.lookup {
                LookupResult::Match(_) => SourceLookupOutcome::Match,
                LookupResult::NoMatch => SourceLookupOutcome::NoMatch,
                LookupResult::Ambiguous => SourceLookupOutcome::Ambiguous,
                LookupResult::Unresolved => SourceLookupOutcome::Unresolved,
            });
        }
        if let (Some(observer), Err(failure)) = (&self.observer, &diagnosed) {
            if let Some(reason) = undeclared_not_found(failure.http_diagnostic()) {
                observer.undeclared_not_found(reason);
            }
            // A failure with an HTTP diagnostic is the source answering a
            // status, or a host protocol refusing it; neither is shape drift.
            if failure.category() == PackSourceError::Protocol
                && failure.http_diagnostic().is_none()
            {
                observer.shape_drift(&[format!(
                    "pack {}@{}; route {}; artifact {}/pack.yaml; result contract violated",
                    self.source.pack.id.as_str(),
                    self.source.pack.version,
                    self.source.route.as_str(),
                    self.source.pack.artifact_prefix.as_str()
                )]);
            }
        }
        diagnosed
    }

    async fn execute_diagnosed_inner(
        &self,
        inputs: Value,
        observed_at: DateTime<Utc>,
        hooks: Arc<dyn EvidenceHostHooks>,
        attribution: Option<Arc<registry_adapter_engine::host_protocol::HostAccessAttribution>>,
    ) -> Result<AcquiredLookup, PackSourceFailure> {
        if !self.program.input_schema().validate(&inputs) {
            return Err(PackSourceFailure::categorical(PackSourceError::Inputs));
        }
        let acquisition = match attribution {
            Some(attribution) => {
                self.program
                    .begin_acquisition_at_with_attribution(hooks, attribution, observed_at)
                    .await
            }
            None => self.program.begin_acquisition_at(hooks, observed_at).await,
        }
        .map_err(begin_failure)?;
        let native = self
            .program
            .execute(&acquisition, inputs)
            .await
            .map_err(execution_failure)?;
        let projected = self
            .closure
            .project_lookup(native, acquisition.deadline().into_std())
            .map_err(|failure| {
                PackSourceFailure::categorical(match failure {
                    registry_adapter_engine::project_transform::ProjectTransformError::Budget => {
                        PackSourceError::Budget
                    }
                    _ => PackSourceError::Protocol,
                })
            })?;
        let lookup = lookup_result(projected).map_err(PackSourceFailure::categorical)?;
        let mut valid_until = None;
        for metadata in acquisition.trusted_protocol_metadata().await {
            let expiry = DateTime::parse_from_rfc3339(&metadata.valid_until)
                .map_err(|_| PackSourceFailure::categorical(PackSourceError::Protocol))?
                .with_timezone(&Utc);
            valid_until =
                Some(valid_until.map_or(expiry, |current: DateTime<Utc>| current.min(expiry)));
        }
        let presented = presented_facts(acquisition.trusted_protocol_attachment().await)
            .map_err(PackSourceFailure::categorical)?;
        require_channel_facts(self.channel, presented.as_deref())
            .map_err(PackSourceFailure::categorical)?;
        Ok(AcquiredLookup {
            lookup,
            valid_until,
            presented,
            acquisition_deadline: acquisition.deadline(),
        })
    }
}

/// Read the host protocol's opaque attachment as the presented facts Evidence
/// defines. An attachment of any other type is a protocol refusal.
fn presented_facts(
    attachment: Option<HostProtocolAttachment>,
) -> Result<Option<Arc<PresentedFacts>>, PackSourceError> {
    attachment
        .map(|attachment| {
            attachment
                .downcast::<PresentedFacts>()
                .map_err(|_| PackSourceError::Protocol)
        })
        .transpose()
}

/// Tie the declared channel to the trusted attachment. A holder-presented
/// Source that returns no presented facts is a dependency failure, never a
/// `source` assertion; a source-channel Source that returns presented facts
/// violates its protocol. Neither releases a fact.
pub(crate) fn require_channel_facts(
    channel: ChannelKind,
    presented: Option<&PresentedFacts>,
) -> Result<(), PackSourceError> {
    match (channel, presented) {
        (ChannelKind::HolderPresented, None) => Err(PackSourceError::Dependency),
        (ChannelKind::Source, Some(_)) => Err(PackSourceError::Protocol),
        _ => Ok(()),
    }
}

/// Whether `route` can reach an endpoint that selects `protocol`, following
/// direct routes the way the engine does when it compiles the route.
fn route_reaches_protocol(pack: &AdapterPack, route: &str, protocol: &str) -> bool {
    let Some(source) = pack.source_routes.get(route) else {
        return false;
    };
    let routes: BTreeMap<_, _> = pack
        .routes
        .iter()
        .map(|route| (route.from.uri.id.as_str(), route.steps.as_slice()))
        .collect();
    let mut pending = vec![source.steps.as_slice()];
    let mut visited = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    while let Some(steps) = pending.pop() {
        let mut destinations = Vec::new();
        walk_steps(steps, &mut |step, _| match step {
            Step::To(send) => destinations.push(&send.uri),
            Step::Enrich(send) => destinations.push(&send.uri),
            _ => {}
        });
        for uri in destinations {
            if uri.component == SendComponent::Direct {
                if visited.insert(uri.id.as_str()) {
                    pending.extend(routes.get(uri.id.as_str()).copied());
                }
            } else {
                endpoints.insert(uri.id.as_str());
            }
        }
    }
    pack.endpoints.iter().any(|endpoint| {
        endpoints.contains(endpoint.id.as_str())
            && endpoint
                .host_protocol
                .as_ref()
                .is_some_and(|selected| selected.id.as_str() == protocol)
    })
}

/// A Source configured on the wrong acquisition channel, with the member of
/// the definition to repair. The pointer and cause carry no value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelSourceRefusal {
    pub pointer: String,
    pub cause: &'static str,
}

/// Every requirement Source whose protocol does not match its channel: the
/// holder-presented Source must reach the wallet presentation protocol, and a
/// source-channel Source never does.
pub fn channel_source_refusals(bundle: &Bundle) -> Vec<ChannelSourceRefusal> {
    let reaches_wallet = |source_id: &str| {
        bundle.config.sources.get(source_id).is_some_and(|source| {
            bundle.source_pack(source_id).is_some_and(|closure| {
                route_reaches_protocol(
                    &closure.pack(),
                    source.route.as_str(),
                    WALLET_PRESENTATION_PROTOCOL_ID,
                )
            })
        })
    };
    let mut refusals = Vec::new();
    for (index, requirement) in bundle.config.requirements.iter().enumerate() {
        let acquisition = &requirement.acquisition;
        if let Some(source_id) = acquisition.source_channel_source() {
            if reaches_wallet(source_id) {
                refusals.push(ChannelSourceRefusal {
                    pointer: format!("/requirements/{index}/acquisition/source"),
                    cause: "a source-channel Source must not use the wallet presentation protocol",
                });
            }
        }
        if let Some(source_id) = acquisition.holder_presented_source() {
            if !reaches_wallet(source_id) {
                refusals.push(ChannelSourceRefusal {
                    pointer: format!("/requirements/{index}/acquisition/holderPresented/source"),
                    cause: "a holder-presented Source must use the wallet presentation protocol",
                });
            }
        }
    }
    refusals
}

fn dependency_outcome(failure: &PackSourceFailure) -> DependencyOutcome {
    match failure.http_diagnostic() {
        Some(EvidenceHttpDiagnostic::Unauthorized) => return DependencyOutcome::Unauthorized,
        Some(EvidenceHttpDiagnostic::Forbidden) => return DependencyOutcome::Forbidden,
        Some(EvidenceHttpDiagnostic::RateLimited) => return DependencyOutcome::RateLimited,
        Some(EvidenceHttpDiagnostic::ServerError) => return DependencyOutcome::ServerError,
        Some(EvidenceHttpDiagnostic::Verification) => return DependencyOutcome::Verification,
        Some(
            EvidenceHttpDiagnostic::UndeclaredNotFound
            | EvidenceHttpDiagnostic::DeclaredNotFoundMismatch
            | EvidenceHttpDiagnostic::OtherClientStatus,
        )
        | None => {}
    }
    match failure.category() {
        PackSourceError::Credential => DependencyOutcome::Credential,
        PackSourceError::Concurrency => DependencyOutcome::Concurrency,
        PackSourceError::Timeout | PackSourceError::Budget => DependencyOutcome::Timeout,
        PackSourceError::Dependency => DependencyOutcome::Transport,
        PackSourceError::ExtractUnavailable
        | PackSourceError::ExtractStale
        | PackSourceError::StatementRefused
        | PackSourceError::StatementParameter
        | PackSourceError::StatementBudget
        | PackSourceError::StatementResult
        | PackSourceError::StatementUnavailable => DependencyOutcome::Statement,
        _ => DependencyOutcome::Protocol,
    }
}

fn undeclared_not_found(diagnostic: Option<EvidenceHttpDiagnostic>) -> Option<UndeclaredNotFound> {
    match diagnostic {
        Some(EvidenceHttpDiagnostic::UndeclaredNotFound) => Some(UndeclaredNotFound::NotDeclared),
        Some(EvidenceHttpDiagnostic::DeclaredNotFoundMismatch) => {
            Some(UndeclaredNotFound::NotMatched)
        }
        _ => None,
    }
}

pub(crate) fn lookup_result(lookup: EvidenceLookup) -> Result<LookupResult, PackSourceError> {
    match lookup {
        EvidenceLookup::Matched {
            facts: Value::Object(facts),
        } => Ok(LookupResult::Match(facts.into_iter().collect())),
        EvidenceLookup::Matched { .. } => Err(PackSourceError::Protocol),
        EvidenceLookup::NoMatch => Ok(LookupResult::NoMatch),
        EvidenceLookup::Ambiguous => Ok(LookupResult::Ambiguous),
        EvidenceLookup::Unresolved => Ok(LookupResult::Unresolved),
    }
}

/// Compile one captured connection allocation per name, then reuse it across
/// every Source that selects that name. Different connection names never
/// share by comparing URLs, secret references or secret values.
pub fn build_sources(
    bundle: &Bundle,
    document: &RuntimeDocument,
    secrets: &Arc<SecretResolver>,
) -> Result<BTreeMap<String, PackSourceExecutor>, SourceBindingError> {
    if !channel_source_refusals(bundle).is_empty() {
        return Err(SourceBindingError::new(
            SourceBindingReason::AcquisitionChannel,
        ));
    }
    let limits = document
        .config
        .source_acquisition
        .limits()
        .map_err(|_| SourceBindingError::new(SourceBindingReason::AcquisitionLimits))?;
    let snapshots = document
        .source_extracts
        .iter()
        .map(|(name, extract)| (name.clone(), extract.captured_snapshot()))
        .collect::<BTreeMap<_, _>>();
    let mut connections = BTreeMap::new();
    for (id, binding) in document.config.source_connections.iter() {
        if binding.id.as_str() != id {
            return Err(SourceBindingError::new(
                SourceBindingReason::ConnectionUnbound,
            ));
        }
        let ca = document
            .source_ca_bundles
            .get(id)
            .cloned()
            .unwrap_or_default();
        connections.insert(
            id.to_owned(),
            EvidenceRuntimeBindings::from_shared(
                binding.clone(),
                Arc::clone(secrets),
                snapshots.clone(),
                ca,
            ),
        );
    }
    let mut sources = BTreeMap::new();
    for (id, source) in bundle.config.sources.iter() {
        let refused = |reason| SourceBindingError::new(reason).for_source(id);
        let refused_at = |endpoint: &str, reason| {
            SourceBindingError::at_endpoint(endpoint, reason).for_source(id)
        };
        let closure = bundle
            .source_pack(id)
            .ok_or_else(|| refused(SourceBindingReason::PackMissing))?;
        let unbound = || refused(SourceBindingReason::ConnectionUnbound);
        let runtime = connections.get(source.connection()).ok_or_else(unbound)?;
        let policies = bundle
            .config
            .source_connections
            .get(source.connection())
            .ok_or_else(unbound)?;
        let binding = document
            .config
            .source_connections
            .get(source.connection())
            .ok_or_else(unbound)?;
        let pack = closure.pack();
        for policy in &policies.endpoints {
            let name = policy.endpoint.as_str();
            let endpoint = pack
                .endpoints
                .get(name)
                .ok_or_else(|| refused_at(name, SourceBindingReason::PackEndpointMissing))?;
            let actual = binding.endpoints.get(name).ok_or_else(|| {
                refused_at(
                    name,
                    SourceBindingReason::Policy(ConnectionPolicyReason::EndpointUnbound),
                )
            })?;
            if crate::config::validate_source_url(&policy.base_url, true).is_err()
                || PinnedOrigin::new(&policy.base_url).is_err()
                || (!policy.base_url.is_https()
                    && bundle.config.assurance_profile != AssuranceProfile::Local)
            {
                return Err(refused_at(name, SourceBindingReason::BaseUrlRefused));
            }
            if matches!(endpoint.authentication, EndpointAuthentication::None {})
                && actual.mtls_identity.is_none()
                && (bundle.config.assurance_profile != AssuranceProfile::Local
                    || crate::config::validate_local_unauthenticated_source_origin(
                        &policy.base_url,
                    )
                    .is_err())
            {
                return Err(refused_at(name, SourceBindingReason::Unauthenticated));
            }
        }
        sources.insert(
            id.to_owned(),
            PackSourceExecutor::compile_diagnosed(
                source,
                closure,
                runtime,
                &policies.endpoints,
                limits,
            )
            .map_err(|error| error.for_source(id))?,
        );
    }
    Ok(sources)
}

/// Project only reviewed route inputs from a completed authorization. Missing
/// optional subjects are omitted, then the route schema decides whether they
/// are required. Each present role selects its exact authorized reviewed profile;
/// entries for other reviewed profiles are omitted. Unknown profiles and scalar
/// coercion are refused.
pub fn authorized_route_inputs(
    source: &SourceConfig,
    resolved: &ResolvedAuthorization,
) -> Result<Value, PackSourceError> {
    route_inputs_for_subjects(source, &resolved.subjects)
}

/// Project only reviewed route inputs from the presented subjects, under the
/// rules of [`authorized_route_inputs`].
pub(crate) fn route_inputs_for_subjects(
    source: &SourceConfig,
    presented: &[ResolvedSubject],
) -> Result<Value, PackSourceError> {
    let mut result = Map::new();
    for (name, binding) in &source.inputs {
        let mut subjects = presented
            .iter()
            .filter(|subject| subject.role == binding.selector.role.as_str());
        let Some(subject) = subjects.next() else {
            continue;
        };
        if subjects.next().is_some() {
            return Err(PackSourceError::Inputs);
        }
        if subject.selector_profile != binding.selector.profile.as_str() {
            let reviewed_profile = source.inputs.values().any(|candidate| {
                candidate.selector.role == binding.selector.role
                    && candidate.selector.profile.as_str() == subject.selector_profile
            });
            if !reviewed_profile {
                return Err(PackSourceError::Inputs);
            }
            continue;
        }
        let mut fields = subject
            .fields
            .iter()
            .filter(|field| field.name == binding.selector.field.as_str());
        let field = fields.next().ok_or(PackSourceError::Inputs)?;
        if fields.next().is_some() {
            return Err(PackSourceError::Inputs);
        }
        result.insert(name.clone(), field.value.as_json());
    }
    Ok(Value::Object(result))
}

fn terminal(error: EvidenceTerminalError) -> PackSourceError {
    match error {
        EvidenceTerminalError::Authority => PackSourceError::Authority,
        EvidenceTerminalError::Audit => PackSourceError::Audit,
        EvidenceTerminalError::Budget => PackSourceError::Budget,
        EvidenceTerminalError::Protocol => PackSourceError::Protocol,
    }
}

fn sqlite_category(code: &'static str) -> PackSourceError {
    match code {
        "adapter.sqlite.extract-unavailable" => PackSourceError::ExtractUnavailable,
        "adapter.sqlite.extract-stale" => PackSourceError::ExtractStale,
        "adapter.sqlite.statement-refused" => PackSourceError::StatementRefused,
        "adapter.sqlite.statement-parameter" => PackSourceError::StatementParameter,
        "adapter.sqlite.statement-budget" => PackSourceError::StatementBudget,
        "adapter.sqlite.statement-result" => PackSourceError::StatementResult,
        "adapter.sqlite.statement-unavailable" => PackSourceError::StatementUnavailable,
        "adapter.sqlite.response-too-large" => PackSourceError::ResponseTooLarge,
        "adapter.sqlite.concurrency" => PackSourceError::Concurrency,
        _ => PackSourceError::Dependency,
    }
}

fn begin_failure(error: EvidenceBeginError) -> PackSourceFailure {
    match error {
        EvidenceBeginError::Terminal(error) => PackSourceFailure::categorical(terminal(error)),
        EvidenceBeginError::Endpoint => PackSourceFailure::categorical(PackSourceError::Dependency),
        EvidenceBeginError::Sqlite(fault) => PackSourceFailure::sqlite(fault),
    }
}

fn readiness_failure(
    error: registry_adapter_engine::evidence::EvidenceReadinessError,
) -> PackSourceFailure {
    use registry_adapter_engine::evidence::EvidenceReadinessError;
    match error {
        EvidenceReadinessError::Endpoint => {
            PackSourceFailure::categorical(PackSourceError::Dependency)
        }
        EvidenceReadinessError::Credential => {
            PackSourceFailure::categorical(PackSourceError::Credential)
        }
        EvidenceReadinessError::Budget => PackSourceFailure::categorical(PackSourceError::Budget),
        EvidenceReadinessError::Sqlite(fault) => PackSourceFailure::sqlite(fault),
    }
}

fn execution_failure(error: EvidenceExecutionError) -> PackSourceFailure {
    match error {
        EvidenceExecutionError::Sqlite(fault) => PackSourceFailure::sqlite(fault),
        EvidenceExecutionError::Route(error) => {
            let category = route_error(&error);
            if let Some((endpoint, diagnostic)) = error
                .evidence_diagnostic
                .as_ref()
                .and_then(|diagnostic| diagnostic.http_parts())
            {
                PackSourceFailure::http(category, endpoint, diagnostic)
            } else {
                PackSourceFailure::categorical(category)
            }
        }
        other => PackSourceFailure::categorical(execution_error(other)),
    }
}

fn execution_error(error: EvidenceExecutionError) -> PackSourceError {
    match error {
        EvidenceExecutionError::Terminal(error) => terminal(error),
        EvidenceExecutionError::InputsInvalid => PackSourceError::Inputs,
        EvidenceExecutionError::LookupInvalid | EvidenceExecutionError::FactsInvalid => {
            PackSourceError::Protocol
        }
        EvidenceExecutionError::Sqlite(fault) => sqlite_category(fault.code()),
        EvidenceExecutionError::Route(error) => route_error(&error),
    }
}

fn route_error(error: &RouteFailure) -> PackSourceError {
    match error.code {
        Some("adapter.sqlite.extract-unavailable") => PackSourceError::ExtractUnavailable,
        Some("adapter.sqlite.extract-stale") => PackSourceError::ExtractStale,
        Some("adapter.sqlite.statement-refused") => PackSourceError::StatementRefused,
        Some("adapter.sqlite.statement-parameter") => PackSourceError::StatementParameter,
        Some("adapter.sqlite.statement-budget") => PackSourceError::StatementBudget,
        Some("adapter.sqlite.statement-result") => PackSourceError::StatementResult,
        Some("adapter.sqlite.statement-unavailable") => PackSourceError::StatementUnavailable,
        Some("adapter.sqlite.response-too-large") => PackSourceError::ResponseTooLarge,
        Some("adapter.sqlite.concurrency") => PackSourceError::Concurrency,
        Some("evidence.authority-refused") => PackSourceError::Authority,
        Some("evidence.audit-failed") => PackSourceError::Audit,
        Some("evidence.budget-exhausted") => PackSourceError::Budget,
        _ if error.class == registry_adapter_core::ErrorClass::BudgetExhausted => {
            PackSourceError::Budget
        }
        _ if error.class == registry_adapter_core::ErrorClass::CredentialRejected => {
            PackSourceError::Credential
        }
        _ if error.class == registry_adapter_core::ErrorClass::UpstreamTimeout => {
            PackSourceError::Timeout
        }
        _ if error.class == registry_adapter_core::ErrorClass::UpstreamTooLarge => {
            PackSourceError::ResponseTooLarge
        }
        _ if error.class == registry_adapter_core::ErrorClass::UpstreamMalformed
            || error.class == registry_adapter_core::ErrorClass::UpstreamRedirect =>
        {
            PackSourceError::Protocol
        }
        _ if error
            .class
            .is_within(registry_adapter_core::ErrorClass::Upstream) =>
        {
            PackSourceError::Dependency
        }
        _ => PackSourceError::Protocol,
    }
}

#[cfg(test)]
mod binding_refusal_tests {
    use super::*;

    #[test]
    fn every_binding_reason_is_a_fixed_sentence_naming_where_it_is_corrected() {
        let cases = [
            (
                SourceBindingReason::AcquisitionLimits,
                "`sourceAcquisition`",
            ),
            (SourceBindingReason::HostProtocols, "host protocol"),
            (SourceBindingReason::PackMissing, "pack closure"),
            (
                SourceBindingReason::ConnectionUnbound,
                "`sourceConnections`",
            ),
            (
                SourceBindingReason::PackEndpointMissing,
                "pack does not declare",
            ),
            (SourceBindingReason::BaseUrlRefused, "`baseUrl`"),
            (SourceBindingReason::Unauthenticated, "`mtlsIdentity`"),
            (
                SourceBindingReason::OperationBudget,
                "`sourceAcquisition.maximumDataOperations`",
            ),
            (SourceBindingReason::Route, "`adapterctl check`"),
            (
                SourceBindingReason::AcquisitionChannel,
                "`acquisition.holderPresented.source`",
            ),
            (
                SourceBindingReason::Policy(ConnectionPolicyReason::BaseUrlMismatch),
                "the runtime `baseUrl` differs from the reviewed `baseUrl`",
            ),
        ];
        for (reason, names) in cases {
            let sentence = reason.to_string();
            assert!(sentence.contains(names), "{reason:?} reads: {sentence}");
            for withheld in ["://", "secret:", "BEGIN CERTIFICATE", ".pem"] {
                assert!(!sentence.contains(withheld), "{reason:?} reads: {sentence}");
            }
        }
    }

    #[test]
    fn a_binding_refusal_names_each_governed_id_it_knows() {
        let reason = SourceBindingReason::BaseUrlRefused;
        assert_eq!(
            SourceBindingError::at_endpoint("tracker", reason)
                .for_source("population")
                .to_string(),
            format!("source `population` endpoint `tracker`: {reason}")
        );
        assert_eq!(
            SourceBindingError::new(reason)
                .for_source("population")
                .to_string(),
            format!("source `population`: {reason}")
        );
        assert_eq!(
            SourceBindingError::at_endpoint("tracker", reason).to_string(),
            format!("endpoint `tracker`: {reason}")
        );
        assert_eq!(
            SourceBindingError::new(reason).to_string(),
            reason.to_string()
        );
    }

    #[test]
    fn engine_compile_failures_keep_only_the_endpoint_and_a_fixed_rule() {
        let policy = compile_refusal(&EvidenceCompileError::ConnectionPolicy {
            endpoint: "tracker".to_owned(),
            reason: ConnectionPolicyReason::TlsTrustProfileMismatch,
        });
        assert_eq!(policy.endpoint(), Some("tracker"));
        assert_eq!(
            policy.reason(),
            SourceBindingReason::Policy(ConnectionPolicyReason::TlsTrustProfileMismatch)
        );
        for (error, reason) in [
            (
                EvidenceCompileError::EndpointUnbound,
                SourceBindingReason::Policy(ConnectionPolicyReason::EndpointUnbound),
            ),
            (
                EvidenceCompileError::StaticOperationBudgetExceeded {
                    required: 9,
                    maximum: 1,
                },
                SourceBindingReason::OperationBudget,
            ),
            (
                EvidenceCompileError::StaticOperationBudgetUncountable,
                SourceBindingReason::OperationBudget,
            ),
            (
                EvidenceCompileError::HostProtocol,
                SourceBindingReason::HostProtocols,
            ),
            (
                EvidenceCompileError::RouteUnsupported("pack-owned detail".to_owned()),
                SourceBindingReason::Route,
            ),
        ] {
            let refusal = compile_refusal(&error);
            assert_eq!(refusal.reason(), reason, "{error:?}");
            assert_eq!(refusal.endpoint(), None, "{error:?}");
            assert!(!refusal.to_string().contains("pack-owned detail"));
        }
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    #[test]
    fn declared_unresolved_remains_distinct_from_absence_and_protocol_failure() {
        assert!(matches!(
            lookup_result(EvidenceLookup::Unresolved),
            Ok(LookupResult::Unresolved)
        ));
        assert!(matches!(
            lookup_result(EvidenceLookup::NoMatch),
            Ok(LookupResult::NoMatch)
        ));
        assert!(matches!(
            lookup_result(EvidenceLookup::Matched { facts: Value::Null }),
            Err(PackSourceError::Protocol)
        ));
    }

    #[test]
    fn every_http_diagnostic_has_one_closed_metric_and_not_found_reason() {
        let cases = [
            (
                PackSourceError::Dependency,
                EvidenceHttpDiagnostic::Unauthorized,
                "unauthorized",
                None,
            ),
            (
                PackSourceError::Dependency,
                EvidenceHttpDiagnostic::Forbidden,
                "forbidden",
                None,
            ),
            (
                PackSourceError::Dependency,
                EvidenceHttpDiagnostic::RateLimited,
                "rate-limited",
                None,
            ),
            (
                PackSourceError::Dependency,
                EvidenceHttpDiagnostic::ServerError,
                "server-error",
                None,
            ),
            (
                PackSourceError::Protocol,
                EvidenceHttpDiagnostic::OtherClientStatus,
                "protocol",
                None,
            ),
            (
                PackSourceError::Protocol,
                EvidenceHttpDiagnostic::Verification,
                "verification",
                None,
            ),
            (
                PackSourceError::Dependency,
                EvidenceHttpDiagnostic::UndeclaredNotFound,
                "transport",
                Some("not declared"),
            ),
            (
                PackSourceError::Protocol,
                EvidenceHttpDiagnostic::DeclaredNotFoundMismatch,
                "protocol",
                Some("not matched"),
            ),
        ];
        for (category, diagnostic, outcome, not_found) in cases {
            let failure = PackSourceFailure::http(category, "governed-endpoint", diagnostic);
            assert_eq!(dependency_outcome(&failure).label(), outcome);
            assert_eq!(
                undeclared_not_found(failure.http_diagnostic()).map(UndeclaredNotFound::as_str),
                not_found
            );
            let rendered = format!("{failure:?} {failure}");
            assert!(rendered.contains(&category.to_string()));
            assert!(!rendered.contains("governed-endpoint"));
        }
    }

    #[test]
    fn the_attachment_is_read_only_as_presented_facts() {
        use crate::model::{PresentedCredential, SubjectLinkMode};
        let facts = PresentedFacts::new(
            PresentedCredential::new(
                "national-id",
                "https://issuer.example",
                "https://credentials.example/identity",
                "2026-08-01T00:00:00Z".parse().expect("time"),
                SubjectLinkMode::Possession,
            )
            .expect("members are in contract"),
            "2026-08-02T00:00:00Z".parse().expect("time"),
        );
        let attachment: HostProtocolAttachment = Arc::new(facts.clone());

        assert_eq!(presented_facts(None), Ok(None));
        assert_eq!(
            presented_facts(Some(attachment))
                .expect("presented facts are accepted")
                .as_deref(),
            Some(&facts)
        );
        for foreign in [
            Arc::new(String::from("channel: holder-presented")) as HostProtocolAttachment,
            Arc::new(serde_json::json!({"channel": "holder-presented"})) as HostProtocolAttachment,
        ] {
            assert_eq!(
                presented_facts(Some(foreign)),
                Err(PackSourceError::Protocol),
                "an attachment of any other type is a protocol refusal"
            );
        }
    }
}
