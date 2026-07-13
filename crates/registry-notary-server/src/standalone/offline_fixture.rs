// SPDX-License-Identifier: Apache-2.0
//! Product-owned Notary evidence path for environment-free authoring fixtures.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_notary_core::{
    ClaimEvidenceMode, ClaimRef, ClaimResultView, EvaluateRequest, EvidenceAuthMode,
    EvidenceConfig, EvidenceConfigError, EvidenceError, RelayOutputContract, SourceBindingConfig,
    StandaloneRegistryNotaryConfig, SubjectRequest,
};
use registry_platform_audit::AuditKeyHasher;
use registry_platform_authcommon::fingerprint_api_key;
use serde_json::Value;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::cel_worker::{CelWorker, CelWorkerConfig, CelWorkerError};
use crate::relay_client::RelayClientError;
use crate::runtime::consultation::{
    ActivatedRelayConsultations, ConsultationGroupKeyV1, RuntimeRelayConsultationResult,
    RuntimeRelayMatchData, RuntimeRelayOutcome, RuntimeRelayOutputMap,
};
use crate::runtime::validate_cel_claims_for_startup;
use crate::{EvidenceStore, RegistryNotaryRuntime, SourceReader};

use super::{
    authenticate_static, collect_claim_required_scopes_for_claim, RequestCredentials,
    ResolvedCredential,
};

/// Closed authentication states accepted by the offline authoring harness.
///
/// Fixture-authored caller names, tokens, and scope strings never enter this
/// boundary. `Valid` receives the exact scope closure derived from the
/// production Notary config. Negative cases use fixed internal credentials.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineAuthentication {
    Valid,
    Missing,
    WrongCredential,
    InsufficientScope,
}

/// Closed Relay outcomes accepted after Relay's product-owned offline decoder
/// has validated the response bytes.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineRelayOutcome {
    Match,
    NoMatch,
    Ambiguous,
}

/// One exact, decoder-validated Relay result for an offline authoring run.
///
/// This is not a runtime output injection interface. It is accepted only by the
/// environment-free harness, must bind to a compiled Notary profile, contract,
/// purpose, complete input-name set, and canonical input values, and is
/// released through the same
/// request-scoped consultation planner used by production evaluation.
#[doc(hidden)]
pub struct OfflineRelayConsultation {
    profile_id: String,
    profile_contract_hash: String,
    purpose: String,
    inputs: BTreeMap<String, Zeroizing<String>>,
    outcome: OfflineRelayOutcome,
    outputs: BTreeMap<String, Value>,
}

impl OfflineRelayConsultation {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn decoded(
        profile_id: impl Into<String>,
        profile_contract_hash: impl Into<String>,
        purpose: impl Into<String>,
        input_name: impl Into<String>,
        input_value: impl Into<String>,
        outcome: OfflineRelayOutcome,
        outputs: BTreeMap<String, Value>,
    ) -> Self {
        Self::decoded_inputs(
            profile_id,
            profile_contract_hash,
            purpose,
            BTreeMap::from([(input_name.into(), input_value.into())]),
            outcome,
            outputs,
        )
    }

    /// Build a decoder-validated composite consultation fixture.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn decoded_inputs(
        profile_id: impl Into<String>,
        profile_contract_hash: impl Into<String>,
        purpose: impl Into<String>,
        inputs: BTreeMap<String, String>,
        outcome: OfflineRelayOutcome,
        outputs: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            profile_id: profile_id.into(),
            profile_contract_hash: profile_contract_hash.into(),
            purpose: purpose.into(),
            inputs: inputs
                .into_iter()
                .map(|(name, value)| (name, Zeroizing::new(value)))
                .collect(),
            outcome,
            outputs,
        }
    }
}

impl std::fmt::Debug for OfflineRelayConsultation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineRelayConsultation")
            .field("profile_id", &self.profile_id)
            .field("profile_contract_hash", &self.profile_contract_hash)
            .field("purpose", &self.purpose)
            .field("input_names", &self.inputs.keys().collect::<Vec<_>>())
            .field("input_values", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .field("outputs", &"[REDACTED]")
            .finish()
    }
}

/// One closed Notary evaluation request for the authoring harness.
#[doc(hidden)]
pub struct OfflineNotaryRequest {
    authentication: OfflineAuthentication,
    request: EvaluateRequest,
    header_purpose: Option<String>,
}

impl OfflineNotaryRequest {
    #[must_use]
    pub fn new(authentication: OfflineAuthentication, request: EvaluateRequest) -> Self {
        Self {
            authentication,
            request,
            header_purpose: None,
        }
    }

    #[must_use]
    pub fn with_header_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.header_purpose = Some(purpose.into());
        self
    }
}

impl std::fmt::Debug for OfflineNotaryRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineNotaryRequest")
            .field("authentication", &self.authentication)
            .field("request", &"[REDACTED]")
            .field("header_purpose", &self.header_purpose)
            .finish()
    }
}

/// Value-free stable error classes emitted by the offline Notary evidence path.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineNotaryErrorClass {
    AuthorizationDenied,
    PurposeDenied,
    InvalidInput,
    DisclosureDenied,
    NoMatch,
    Ambiguous,
    SourceUnavailable,
    EvaluationFailed,
}

impl OfflineNotaryErrorClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationDenied => "authorization.denied",
            Self::PurposeDenied => "authorization.purpose_denied",
            Self::InvalidInput => "request.invalid",
            Self::DisclosureDenied => "disclosure.denied",
            Self::NoMatch => "source.not_found",
            Self::Ambiguous => "source.ambiguous",
            Self::SourceUnavailable => "source.unavailable",
            Self::EvaluationFailed => "evaluation.failed",
        }
    }
}

/// Stable claim projection returned by the offline product evidence path.
#[doc(hidden)]
#[derive(Clone, PartialEq)]
pub struct OfflineClaimView {
    claim_id: String,
    value: Option<Value>,
    satisfied: Option<bool>,
    disclosure: String,
    redacted_fields: Vec<String>,
}

impl OfflineClaimView {
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.claim_id
    }

    #[must_use]
    pub const fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    #[must_use]
    pub const fn satisfied(&self) -> Option<bool> {
        self.satisfied
    }

    #[must_use]
    pub fn disclosure(&self) -> &str {
        &self.disclosure
    }

    #[must_use]
    pub fn redacted_fields(&self) -> &[String] {
        &self.redacted_fields
    }
}

impl From<ClaimResultView> for OfflineClaimView {
    fn from(claim: ClaimResultView) -> Self {
        Self {
            claim_id: claim.claim_id,
            value: claim.value,
            satisfied: claim.satisfied,
            disclosure: claim.disclosure,
            redacted_fields: claim.redacted_fields,
        }
    }
}

impl std::fmt::Debug for OfflineClaimView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineClaimView")
            .field("claim_id", &self.claim_id)
            .field("value", &"[REDACTED]")
            .field("satisfied", &self.satisfied)
            .field("disclosure", &self.disclosure)
            .field("redacted_fields", &self.redacted_fields)
            .finish()
    }
}

/// Result and value-free execution evidence for one offline evaluation.
#[doc(hidden)]
pub struct OfflineNotaryEvidence {
    claims: Vec<OfflineClaimView>,
    error_class: Option<OfflineNotaryErrorClass>,
    product_error_code: Option<&'static str>,
    relay_calls: u64,
    direct_source_calls: u64,
    consultation_count: usize,
}

impl OfflineNotaryEvidence {
    #[must_use]
    pub fn claims(&self) -> &[OfflineClaimView] {
        &self.claims
    }

    #[must_use]
    pub const fn error_class(&self) -> Option<OfflineNotaryErrorClass> {
        self.error_class
    }

    #[must_use]
    pub const fn product_error_code(&self) -> Option<&'static str> {
        self.product_error_code
    }

    #[must_use]
    pub const fn relay_calls(&self) -> u64 {
        self.relay_calls
    }

    #[must_use]
    pub const fn direct_source_calls(&self) -> u64 {
        self.direct_source_calls
    }

    #[must_use]
    pub const fn consultation_count(&self) -> usize {
        self.consultation_count
    }
}

impl std::fmt::Debug for OfflineNotaryEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineNotaryEvidence")
            .field(
                "claim_ids",
                &self
                    .claims
                    .iter()
                    .map(|claim| claim.claim_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("error_class", &self.error_class)
            .field("product_error_code", &self.product_error_code)
            .field("relay_calls", &self.relay_calls)
            .field("direct_source_calls", &self.direct_source_calls)
            .field("consultation_count", &self.consultation_count)
            .finish()
    }
}

#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum OfflineNotaryHarnessError {
    #[error("Notary config failed production validation")]
    InvalidConfig(#[source] EvidenceConfigError),
    #[error("Notary CEL policy failed production startup validation")]
    InvalidCelPolicy(#[source] EvidenceError),
    #[error("offline Notary evaluation requires static API-key authentication")]
    UnsupportedAuthentication,
    #[error("offline Notary evaluation requires one configured API-key principal")]
    MissingConfiguredPrincipal,
    #[error("offline Relay evidence does not bind to the compiled Notary contract")]
    InvalidRelayEvidence,
    #[error("offline CEL worker configuration is invalid")]
    InvalidCelWorker(#[source] CelWorkerError),
    #[error("OS randomness is unavailable")]
    RandomUnavailable,
}

/// Environment-free production Notary evaluation harness for project authoring.
#[doc(hidden)]
pub struct OfflineNotaryHarness {
    evidence: Arc<EvidenceConfig>,
    runtime: RegistryNotaryRuntime,
    source: Arc<CountingDeniedSource>,
    relay: Arc<OfflineActivatedRelay>,
    store: EvidenceStore,
    principal_id: String,
    api_key: Zeroizing<String>,
}

impl OfflineNotaryHarness {
    pub fn compile(
        config: StandaloneRegistryNotaryConfig,
        relay_evidence: Vec<OfflineRelayConsultation>,
        cel_worker_config: CelWorkerConfig,
    ) -> Result<Self, OfflineNotaryHarnessError> {
        config
            .validate()
            .map_err(OfflineNotaryHarnessError::InvalidConfig)?;
        if config.auth.mode != EvidenceAuthMode::ApiKey {
            return Err(OfflineNotaryHarnessError::UnsupportedAuthentication);
        }
        let principal_id = config
            .auth
            .api_keys
            .first()
            .map(|credential| credential.id.clone())
            .ok_or(OfflineNotaryHarnessError::MissingConfiguredPrincipal)?;
        validate_cel_claims_for_startup(&config.evidence, &config.cel)
            .map_err(OfflineNotaryHarnessError::InvalidCelPolicy)?;
        let cel_worker = CelWorker::lazy(cel_worker_config);
        cel_worker
            .validate_config()
            .map_err(OfflineNotaryHarnessError::InvalidCelWorker)?;
        let relay = Arc::new(OfflineActivatedRelay::new(
            &config.evidence,
            relay_evidence,
        )?);
        let source = Arc::new(CountingDeniedSource::default());
        let mut random = [0_u8; 48];
        getrandom::fill(&mut random).map_err(|_| OfflineNotaryHarnessError::RandomUnavailable)?;
        let api_key = Zeroizing::new(URL_SAFE_NO_PAD.encode(random));
        let runtime =
            RegistryNotaryRuntime::new_with_audit_hasher(AuditKeyHasher::unkeyed_dev_only())
                .with_activated_relay(Some(
                    Arc::clone(&relay) as Arc<dyn ActivatedRelayConsultations>
                ))
                .with_cel_worker(Some(Arc::new(cel_worker)))
                .with_cel_config(Arc::new(config.cel));
        Ok(Self {
            evidence: Arc::new(config.evidence),
            runtime,
            source,
            relay,
            store: EvidenceStore::default(),
            principal_id,
            api_key,
        })
    }

    pub async fn evaluate(&self, offline: OfflineNotaryRequest) -> OfflineNotaryEvidence {
        let relay_before = self.relay.calls.load(Ordering::SeqCst);
        let direct_before = self.source.calls.load(Ordering::SeqCst);
        let scopes = match offline.authentication {
            OfflineAuthentication::Valid => required_scopes(&self.evidence, &offline.request),
            OfflineAuthentication::InsufficientScope => {
                Ok(vec!["offline:insufficient-scope".to_string()])
            }
            OfflineAuthentication::Missing | OfflineAuthentication::WrongCredential => {
                Ok(Vec::new())
            }
        };
        let scopes = match scopes {
            Ok(scopes) => scopes,
            Err(error) => return self.evidence_from_error(error, relay_before, direct_before, 0),
        };
        let fingerprint = fingerprint_api_key(self.api_key.as_str());
        let credential = ResolvedCredential {
            id: self.principal_id.clone(),
            fingerprint,
            scopes,
            authorization_details: None,
        };
        let api_key = match offline.authentication {
            OfflineAuthentication::Valid | OfflineAuthentication::InsufficientScope => {
                Some(self.api_key.to_string())
            }
            OfflineAuthentication::WrongCredential => {
                Some("offline-invalid-credential-value".to_string())
            }
            OfflineAuthentication::Missing => None,
        };
        let principal = authenticate_static(
            &RequestCredentials {
                api_key,
                authorization_present: false,
                bearer_token: None,
                id_token: None,
            },
            &[credential],
            &[],
        );
        let principal = match principal {
            Ok(principal) => principal,
            Err(error) => return self.evidence_from_error(error, relay_before, direct_before, 0),
        };
        let (result, audit) = self
            .runtime
            .evaluate_for_api(
                Arc::clone(&self.evidence),
                Arc::clone(&self.source) as Arc<dyn SourceReader>,
                &self.store,
                &principal,
                offline.request,
                offline.header_purpose.as_deref(),
            )
            .await;
        let (_, consultation_ids) = audit.into_parts();
        match result {
            Ok(claims) => OfflineNotaryEvidence {
                claims: claims.into_iter().map(OfflineClaimView::from).collect(),
                error_class: None,
                product_error_code: None,
                relay_calls: self
                    .relay
                    .calls
                    .load(Ordering::SeqCst)
                    .saturating_sub(relay_before),
                direct_source_calls: self
                    .source
                    .calls
                    .load(Ordering::SeqCst)
                    .saturating_sub(direct_before),
                consultation_count: consultation_ids.len(),
            },
            Err(error) => {
                self.evidence_from_error(error, relay_before, direct_before, consultation_ids.len())
            }
        }
    }

    fn evidence_from_error(
        &self,
        error: EvidenceError,
        relay_before: u64,
        direct_before: u64,
        consultation_count: usize,
    ) -> OfflineNotaryEvidence {
        OfflineNotaryEvidence {
            claims: Vec::new(),
            error_class: Some(error_class(&error)),
            product_error_code: Some(error.code()),
            relay_calls: self
                .relay
                .calls
                .load(Ordering::SeqCst)
                .saturating_sub(relay_before),
            direct_source_calls: self
                .source
                .calls
                .load(Ordering::SeqCst)
                .saturating_sub(direct_before),
            consultation_count,
        }
    }
}

impl std::fmt::Debug for OfflineNotaryHarness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineNotaryHarness")
            .field("evidence", &"[COMPILED]")
            .field("runtime", &"[COMPILED]")
            .field("source", &self.source)
            .field("relay", &self.relay)
            .field("principal_id", &self.principal_id)
            .field("api_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn required_scopes(
    evidence: &EvidenceConfig,
    request: &EvaluateRequest,
) -> Result<Vec<String>, EvidenceError> {
    let mut scopes = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for claim in &request.claims {
        collect_required_scopes(evidence, claim, &mut visited, &mut scopes)?;
    }
    Ok(scopes.into_iter().collect())
}

fn collect_required_scopes(
    evidence: &EvidenceConfig,
    claim_ref: &ClaimRef,
    visited: &mut BTreeSet<String>,
    scopes: &mut BTreeSet<String>,
) -> Result<(), EvidenceError> {
    if !visited.insert(claim_ref.id.clone()) {
        return Ok(());
    }
    let claim = crate::find_claim(evidence, claim_ref.id.as_str())?;
    scopes.extend(claim.required_scopes.iter().cloned());
    let mut source_scopes = Vec::new();
    collect_claim_required_scopes_for_claim(evidence, claim, &mut source_scopes)?;
    scopes.extend(source_scopes);
    for dependency in &claim.depends_on {
        collect_required_scopes(
            evidence,
            &ClaimRef::from(dependency.as_str()),
            visited,
            scopes,
        )?;
    }
    Ok(())
}

fn error_class(error: &EvidenceError) -> OfflineNotaryErrorClass {
    match error {
        EvidenceError::MissingCredential
        | EvidenceError::MultipleCredentials
        | EvidenceError::ScopeDenied { .. } => OfflineNotaryErrorClass::AuthorizationDenied,
        EvidenceError::PurposeNotAllowed | EvidenceError::PurposeRequired => {
            OfflineNotaryErrorClass::PurposeDenied
        }
        EvidenceError::InvalidRequest
        | EvidenceError::TargetIdentifierMissing
        | EvidenceError::TargetAttributesInsufficient
        | EvidenceError::ProfileUnsupported => OfflineNotaryErrorClass::InvalidInput,
        EvidenceError::DisclosureNotAllowed => OfflineNotaryErrorClass::DisclosureDenied,
        EvidenceError::SourceNotFound => OfflineNotaryErrorClass::NoMatch,
        EvidenceError::SourceAmbiguous => OfflineNotaryErrorClass::Ambiguous,
        EvidenceError::SourceUnavailable => OfflineNotaryErrorClass::SourceUnavailable,
        _ => OfflineNotaryErrorClass::EvaluationFailed,
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OfflineRelayKey {
    profile_id: String,
    profile_contract_hash: String,
    purpose: String,
    inputs: BTreeMap<String, String>,
}

struct OfflineRelayEntry {
    outcome: OfflineRelayOutcome,
    outputs: BTreeMap<String, Value>,
    output_contracts: BTreeMap<String, RelayOutputContract>,
}

struct OfflineActivatedRelay {
    entries: BTreeMap<OfflineRelayKey, OfflineRelayEntry>,
    calls: AtomicU64,
}

impl OfflineActivatedRelay {
    fn new(
        evidence: &EvidenceConfig,
        consultations: Vec<OfflineRelayConsultation>,
    ) -> Result<Self, OfflineNotaryHarnessError> {
        let mut entries = BTreeMap::new();
        for consultation in consultations {
            if consultation.outcome != OfflineRelayOutcome::Match
                && !consultation.outputs.is_empty()
            {
                return Err(OfflineNotaryHarnessError::InvalidRelayEvidence);
            }
            if consultation.outcome == OfflineRelayOutcome::Match {
                RuntimeRelayOutputMap::from_json(consultation.outputs.clone())
                    .map_err(|_| OfflineNotaryHarnessError::InvalidRelayEvidence)?;
            }
            let output_contracts = configured_output_contracts(evidence, &consultation)
                .ok_or(OfflineNotaryHarnessError::InvalidRelayEvidence)?;
            let key = OfflineRelayKey {
                profile_id: consultation.profile_id,
                profile_contract_hash: consultation.profile_contract_hash,
                purpose: consultation.purpose,
                inputs: consultation
                    .inputs
                    .into_iter()
                    .map(|(name, value)| (name, value.to_string()))
                    .collect(),
            };
            if entries
                .insert(
                    key,
                    OfflineRelayEntry {
                        outcome: consultation.outcome,
                        outputs: consultation.outputs,
                        output_contracts,
                    },
                )
                .is_some()
            {
                return Err(OfflineNotaryHarnessError::InvalidRelayEvidence);
            }
        }
        if entries.is_empty() {
            return Err(OfflineNotaryHarnessError::InvalidRelayEvidence);
        }
        Ok(Self {
            entries,
            calls: AtomicU64::new(0),
        })
    }

    fn entry_for(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<&OfflineRelayEntry, RelayClientError> {
        self.entries
            .get(&OfflineRelayKey {
                profile_id: key.profile_id().to_string(),
                profile_contract_hash: key.profile_contract_hash().to_string(),
                purpose: key.canonical_purpose().to_string(),
                inputs: key
                    .canonical_inputs()
                    .iter()
                    .map(|(name, value)| (name.clone(), value.as_str().to_string()))
                    .collect(),
            })
            .filter(|entry| {
                key.expected_output_contracts()
                    .is_some_and(|contracts| contracts == &entry.output_contracts)
            })
            .ok_or(RelayClientError::InvalidRequest)
    }
}

impl std::fmt::Debug for OfflineActivatedRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfflineActivatedRelay")
            .field("entries", &"[REDACTED]")
            .field("calls", &self.calls.load(Ordering::Relaxed))
            .finish()
    }
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for OfflineActivatedRelay {
    async fn check_ready(&self) -> Result<(), RelayClientError> {
        Ok(())
    }

    fn profile_count(&self) -> usize {
        self.entries.len()
    }

    fn validate(&self, key: &ConsultationGroupKeyV1) -> Result<(), RelayClientError> {
        self.entry_for(key).map(|_| ())
    }

    async fn execute(
        &self,
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, RelayClientError> {
        let entry = self.entry_for(key)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (outcome, match_data) = match entry.outcome {
            OfflineRelayOutcome::Match => (
                RuntimeRelayOutcome::Match,
                Some(RuntimeRelayMatchData::OutputMap(
                    RuntimeRelayOutputMap::from_json(entry.outputs.clone())?,
                )),
            ),
            OfflineRelayOutcome::NoMatch => (RuntimeRelayOutcome::NoMatch, None),
            OfflineRelayOutcome::Ambiguous => (RuntimeRelayOutcome::Ambiguous, None),
        };
        RuntimeRelayConsultationResult::new(
            ulid::Ulid::new(),
            outcome,
            match_data,
            OffsetDateTime::now_utc(),
        )
    }
}

fn configured_output_contracts(
    evidence: &EvidenceConfig,
    offline: &OfflineRelayConsultation,
) -> Option<BTreeMap<String, RelayOutputContract>> {
    evidence.claims.iter().find_map(|claim| {
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            return None;
        };
        let (_, consultation) = consultations.first_key_value()?;
        (claim.purpose.as_deref() == Some(offline.purpose.as_str())
            && consultation.profile.id == offline.profile_id
            && consultation.profile.contract_hash == offline.profile_contract_hash
            && consultation.inputs.keys().eq(offline.inputs.keys())
            && !consultation.outputs.is_empty())
        .then(|| consultation.outputs.clone())
    })
}

#[derive(Default)]
struct CountingDeniedSource {
    calls: AtomicU64,
}

impl std::fmt::Debug for CountingDeniedSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CountingDeniedSource")
            .field("calls", &self.calls.load(Ordering::Relaxed))
            .finish()
    }
}

impl SourceReader for CountingDeniedSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        _subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(EvidenceError::SourceUnavailable)
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        let claim = crate::find_claim(evidence, claim_id)?;
        self.required_scopes_for_claim(evidence, claim)
    }

    fn required_scopes_for_claim(
        &self,
        evidence: &EvidenceConfig,
        claim: &registry_notary_core::ClaimDefinition,
    ) -> Result<Vec<String>, EvidenceError> {
        let mut scopes = Vec::new();
        collect_claim_required_scopes_for_claim(evidence, claim, &mut scopes)?;
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}
