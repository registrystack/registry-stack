//! Evidence-owned authorization and input minimization around Adapter programs.

use crate::{
    bundle::{ArtifactFault, Bundle, RuntimeDocument, SourcePack},
    config::{AssuranceProfile, SchemaFault, SourceConfig, WALLET_PRESENTATION_PROTOCOL_ID},
    model::{ChannelKind, LookupResult},
    observability::{DependencyOutcome, SourceLookupOutcome, SourceObserver, UndeclaredNotFound},
    presented::PresentedFacts,
    secrets::SecretResolver,
    selector::ResolvedAuthorization,
};
use chrono::{DateTime, Utc};
use registry_adapter_core::{
    walk_steps, AdapterPack, EndpointAuthentication, EvidenceConnectionPolicy, SendComponent, Step,
};
use registry_adapter_engine::component::http::uri::PinnedOrigin;
use registry_adapter_engine::evidence::{
    compile_evidence_with_protocols, EvidenceBeginError, EvidenceCompileInputs,
    EvidenceExecutionError, EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceProgram,
    EvidenceRuntimeBindings, EvidenceTerminalError,
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
        .map_err(|_| PackSourceError::Plan)?;
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
        let inputs = authorized_route_inputs(&self.source, resolved)?;
        if !self.program.input_schema().validate(&inputs) {
            return Err(PackSourceError::Inputs);
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
            if failure.category() == PackSourceError::Protocol
                && !matches!(
                    failure.http_diagnostic(),
                    Some(
                        EvidenceHttpDiagnostic::Verification
                            | EvidenceHttpDiagnostic::DeclaredNotFoundMismatch
                    )
                )
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
            | EvidenceHttpDiagnostic::DeclaredNotFoundMismatch,
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
) -> Result<BTreeMap<String, PackSourceExecutor>, PackSourceError> {
    if !channel_source_refusals(bundle).is_empty() {
        return Err(PackSourceError::Plan);
    }
    let limits = document
        .config
        .source_acquisition
        .limits()
        .map_err(|_| PackSourceError::Plan)?;
    let snapshots = document
        .source_extracts
        .iter()
        .map(|(name, extract)| (name.clone(), extract.captured_snapshot()))
        .collect::<BTreeMap<_, _>>();
    let mut connections = BTreeMap::new();
    for (id, binding) in document.config.source_connections.iter() {
        if binding.id.as_str() != id {
            return Err(PackSourceError::Plan);
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
        let closure = bundle.source_pack(id).ok_or(PackSourceError::Plan)?;
        let runtime = connections
            .get(source.connection())
            .ok_or(PackSourceError::Plan)?;
        let policies = bundle
            .config
            .source_connections
            .get(source.connection())
            .ok_or(PackSourceError::Plan)?;
        let binding = document
            .config
            .source_connections
            .get(source.connection())
            .ok_or(PackSourceError::Plan)?;
        let pack = closure.pack();
        for policy in &policies.endpoints {
            let endpoint = pack
                .endpoints
                .get(policy.endpoint.as_str())
                .ok_or(PackSourceError::Plan)?;
            let actual = binding
                .endpoints
                .get(policy.endpoint.as_str())
                .ok_or(PackSourceError::Plan)?;
            if crate::config::validate_source_url(&policy.base_url, true).is_err()
                || PinnedOrigin::new(&policy.base_url).is_err()
                || (!policy.base_url.is_https()
                    && bundle.config.assurance_profile != AssuranceProfile::Local)
            {
                return Err(PackSourceError::Plan);
            }
            if matches!(endpoint.authentication, EndpointAuthentication::None {})
                && actual.mtls_identity.is_none()
                && (bundle.config.assurance_profile != AssuranceProfile::Local
                    || crate::config::validate_local_unauthenticated_source_origin(
                        &policy.base_url,
                    )
                    .is_err())
            {
                return Err(PackSourceError::Plan);
            }
        }
        sources.insert(
            id.to_owned(),
            PackSourceExecutor::compile(source, closure, runtime, &policies.endpoints, limits)?,
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
    let mut result = Map::new();
    for (name, binding) in &source.inputs {
        let mut subjects = resolved
            .subjects
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
