//! Evidence-owned authorization and input minimization around Adapter programs.

use crate::{
    bundle::{ArtifactFault, Bundle, RuntimeDocument, SourcePack},
    config::{AssuranceProfile, SchemaFault, SourceConfig},
    model::LookupResult,
    observability::{DependencyOutcome, SourceLookupOutcome, SourceObserver, UndeclaredNotFound},
    secrets::SecretResolver,
    selector::ResolvedAuthorization,
};
use chrono::{DateTime, Utc};
use registry_adapter_core::{EndpointAuthentication, EvidenceConnectionPolicy};
use registry_adapter_engine::component::http::uri::PinnedOrigin;
use registry_adapter_engine::evidence::{
    compile_evidence_with_protocols, EvidenceBeginError, EvidenceCompileInputs,
    EvidenceExecutionError, EvidenceHostHooks, EvidenceLimits, EvidenceLookup, EvidenceProgram,
    EvidenceRuntimeBindings, EvidenceTerminalError,
};
use registry_adapter_engine::route::{EvidenceHttpDiagnostic, RouteFailure};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};
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
    observer: Option<SourceObserver>,
}

/// Private facts plus trusted upstream validity retained outside provider code.
pub struct AcquiredLookup {
    pub lookup: LookupResult,
    pub valid_until: Option<DateTime<Utc>>,
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
            &crate::host_protocol::registry().map_err(|_| PackSourceError::Plan)?,
        )
        .map_err(|_| PackSourceError::Plan)?;
        Ok(Self {
            program,
            source: source.clone(),
            observer: None,
        })
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
        let lookup = lookup_result(
            self.program
                .execute(&acquisition, inputs)
                .await
                .map_err(execution_failure)?,
        )
        .map_err(PackSourceFailure::categorical)?;
        let mut valid_until = None;
        for metadata in acquisition.trusted_protocol_metadata().await {
            let expiry = DateTime::parse_from_rfc3339(&metadata.valid_until)
                .map_err(|_| PackSourceFailure::categorical(PackSourceError::Protocol))?
                .with_timezone(&Utc);
            valid_until =
                Some(valid_until.map_or(expiry, |current: DateTime<Utc>| current.min(expiry)));
        }
        Ok(AcquiredLookup {
            lookup,
            valid_until,
            acquisition_deadline: acquisition.deadline(),
        })
    }
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
}
