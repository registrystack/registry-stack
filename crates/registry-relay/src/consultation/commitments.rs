// SPDX-License-Identifier: Apache-2.0
//! Exact v1 consultation commitment and ordinary-digest preimages.
//!
//! Raw canonical inputs and consent references enter only the transient keyed
//! commitment builders in this module. They are never retained in a runtime
//! profile, ordinary digest, serializable type, `Debug` output, or audit value.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use registry_platform_audit::pseudonym_keyring::{
    AuditPseudonymCommitment, AuditPseudonymKeyId, TransientPseudonymInput,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::source_plan::runtime_profile::{
    CompiledConsentProfile, CompiledPublicOutcome, CompiledRuntimeProfile,
};
use crate::source_plan::{
    CompiledInputValue, CompiledResponseSchema, CompiledScalarShape, CompiledSourcePlan,
    SourcePlanKind,
};
use crate::state_plane::QuotaGrant;

use super::policy::CompiledPolicyProof;
use super::pseudonym::PreparedConsultationPseudonyms;
use super::{
    AcquisitionClass, AuthenticatedConsultationWorkload, PreAuthorizationConsultationCore,
    SelectorProvenance,
};

const AUTHORIZATION_CONTEXT_DOMAIN_V1: &str = "registry.relay.consultation-authorization.v1";
const EXECUTION_PLAN_DOMAIN_V1: &str = "registry.relay.consultation-execution-plan.v1";
const AUTHORIZED_REQUEST_DOMAIN_V1: &str = "registry.relay.authorized-consultation.v1";
const EMPTY_OBLIGATIONS_DOMAIN_V1: &str = "registry.relay.consultation-obligations.v1";
const EXECUTE_ROUTE_V1: &str = "/v1/consultations/{profile_id}/versions/{profile_version}/execute";
const MAX_EXACT_JSON_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_CONSENT_REFERENCE_BYTES: usize = 4 * 1024;

/// Value-free failure taxonomy for sensitive commitment construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConsultationCommitmentError {
    #[error("consultation canonical inputs do not match the compiled profile")]
    CanonicalInputMismatch,
    #[error("consultation consent evidence does not match the compiled profile")]
    ConsentMismatch,
    #[error("consultation authorization facts do not match the compiled profile")]
    AuthorizationMismatch,
    #[error("consultation commitment time is outside the v1 representation")]
    InvalidTime,
    #[error("consultation commitment input is outside its v1 bound")]
    InputOutOfBounds,
    #[error("consultation commitment canonicalization failed")]
    Canonicalization,
}

macro_rules! consultation_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub(crate) struct $name(Box<str>);

        impl $name {
            pub(crate) fn as_str(&self) -> &str {
                &self.0
            }

            fn derive(domain: &str, value: &Value) -> Result<Self, ConsultationCommitmentError> {
                domain_separated_digest(domain, value).map(Self)
            }

            #[cfg(test)]
            pub(super) fn from_label_for_test(value: &str) -> Self {
                assert!(value.starts_with("sha256:") && value.len() == 71);
                Self(value.into())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"sha256:<redacted>")
                    .finish()
            }
        }
    };
}

consultation_digest!(
    /// Exact safe authorization-context digest frozen by the v1 contract.
    AuthorizationContextDigest
);
consultation_digest!(
    /// Exact compiled execution-plan digest frozen by the v1 contract.
    ExecutionPlanDigest
);
consultation_digest!(
    /// Exact authorized request digest used as the state-plane binding.
    AuthorizedRequestDigest
);
consultation_digest!(
    /// Domain-separated digest of v1's only supported obligation set, `[]`.
    EmptyObligationsDigest
);

/// Exact canonical input object after profile validation.
///
/// Values retain their zeroizing compiled owners and the type deliberately
/// implements neither `Clone`, `Debug`, nor serialization.
pub(crate) struct CanonicalConsultationInputs<'profile> {
    plan: &'profile CompiledSourcePlan,
    canonical_purpose: Box<str>,
    values: BTreeMap<Box<str>, CompiledInputValue>,
}

impl<'profile> CanonicalConsultationInputs<'profile> {
    /// Consume one resolved request core and validate every declared fact
    /// against the exact compiled plan before any commitment is possible.
    pub(crate) fn try_from_resolved_core(
        plan: &'profile CompiledSourcePlan,
        core: PreAuthorizationConsultationCore,
    ) -> Result<Self, ConsultationCommitmentError> {
        let profile = plan.runtime_profile();
        if core.profile() != profile.profile()
            || core.selector_provenance() != profile.subject().selector_provenance()
            || core.footprint() != profile.footprint()
        {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        let canonical_purpose = profile
            .purposes()
            .find(|purpose| *purpose == core.purpose().as_str())
            .ok_or(ConsultationCommitmentError::AuthorizationMismatch)?;
        let mut slots = plan.inputs();
        let slot = slots
            .next()
            .ok_or(ConsultationCommitmentError::CanonicalInputMismatch)?;
        if slots.next().is_some() || slot.name() != core.parsed_input().name() {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        let value = slot
            .canonicalize_and_validate(core.parsed_input().value_for_internal_use())
            .ok_or(ConsultationCommitmentError::CanonicalInputMismatch)?;
        if !value.binding_matches(profile.profile().contract_hash(), slot.name(), 0) {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        Ok(Self {
            plan,
            canonical_purpose: canonical_purpose.into(),
            values: BTreeMap::from([(slot.name().into(), value)]),
        })
    }

    const fn profile(&self) -> &CompiledRuntimeProfile {
        self.plan.runtime_profile()
    }

    fn transient_value(&self) -> Value {
        Value::Object(
            self.values
                .iter()
                .map(|(name, value)| (name.to_string(), Value::String(value.as_str().to_owned())))
                .collect(),
        )
    }

    fn only_input(&self) -> Result<(&str, &str), ConsultationCommitmentError> {
        let mut values = self.values.iter();
        let (name, value) = values
            .next()
            .ok_or(ConsultationCommitmentError::CanonicalInputMismatch)?;
        if values.next().is_some() {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        Ok((name, value.as_str()))
    }
}

/// The exact compiled plan and canonical input that produced one consultation's
/// keyed commitments.
///
/// This capability is move-only and has no independent plan or input
/// constructor. The strict backend executor receives the pair together after
/// durable attempt persistence, so request rendering cannot accept a selector
/// captured outside the committed authorization chain.
pub(crate) struct SealedConsultationExecution<'profile> {
    inner: SealedConsultationExecutionInner<'profile>,
}

/// The exact plan and canonical input released only by consuming a sealed
/// execution inside the concrete source executor.
pub(super) struct BoundConsultationExecution<'profile> {
    plan: &'profile CompiledSourcePlan,
    input: CompiledInputValue,
}

impl BoundConsultationExecution<'_> {
    pub(super) const fn plan(&self) -> &CompiledSourcePlan {
        self.plan
    }

    pub(super) const fn input(&self) -> &CompiledInputValue {
        &self.input
    }
}

enum SealedConsultationExecutionInner<'profile> {
    Bound {
        plan: &'profile CompiledSourcePlan,
        input: CompiledInputValue,
    },
    #[cfg(test)]
    StatePlaneOnly,
}

impl<'profile> SealedConsultationExecution<'profile> {
    fn try_from_canonical_inputs(
        plan: &'profile CompiledSourcePlan,
        mut values: BTreeMap<Box<str>, CompiledInputValue>,
    ) -> Result<Self, ConsultationCommitmentError> {
        let mut slots = plan.inputs();
        let slot = slots
            .next()
            .ok_or(ConsultationCommitmentError::CanonicalInputMismatch)?;
        if slots.next().is_some() || values.len() != 1 {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        let input = values
            .remove(slot.name())
            .filter(|value| value.binding_matches(plan.profile().contract_hash(), slot.name(), 0))
            .ok_or(ConsultationCommitmentError::CanonicalInputMismatch)?;
        if !values.is_empty() {
            return Err(ConsultationCommitmentError::CanonicalInputMismatch);
        }
        Ok(Self {
            inner: SealedConsultationExecutionInner::Bound { plan, input },
        })
    }

    /// Borrow the exact inseparable pair only for invariant tests. The concrete
    /// executor integration must add the sole production consume path inside
    /// the guarded dispatch boundary rather than expose these values generally.
    #[cfg(test)]
    pub(crate) fn bound_plan_and_input(&self) -> (&CompiledSourcePlan, &CompiledInputValue) {
        match &self.inner {
            SealedConsultationExecutionInner::Bound { plan, input } => (plan, input),
            #[cfg(test)]
            SealedConsultationExecutionInner::StatePlaneOnly => {
                panic!("state-plane-only test dispatch has no source execution")
            }
        }
    }

    pub(super) fn profile(&self) -> &CompiledRuntimeProfile {
        match &self.inner {
            SealedConsultationExecutionInner::Bound { plan, .. } => plan.runtime_profile(),
            #[cfg(test)]
            SealedConsultationExecutionInner::StatePlaneOnly => {
                panic!("state-plane-only test dispatch has no source execution")
            }
        }
    }

    /// Consume the authorization-bound plan/input pair into the only shape
    /// accepted by the concrete consultation executor.
    pub(super) fn into_bound(
        self,
    ) -> Result<BoundConsultationExecution<'profile>, ConsultationCommitmentError> {
        match self.inner {
            SealedConsultationExecutionInner::Bound { plan, input } => {
                Ok(BoundConsultationExecution { plan, input })
            }
            #[cfg(test)]
            SealedConsultationExecutionInner::StatePlaneOnly => {
                Err(ConsultationCommitmentError::CanonicalInputMismatch)
            }
        }
    }

    #[cfg(test)]
    pub(super) const fn state_plane_only_for_test() -> SealedConsultationExecution<'static> {
        SealedConsultationExecution {
            inner: SealedConsultationExecutionInner::StatePlaneOnly,
        }
    }
}

/// Raw evidence retained only inside the sealed verifier result until HMAC.
struct VerifiedRawConsentReference {
    value: Zeroizing<String>,
}

impl VerifiedRawConsentReference {
    fn try_new(value: Zeroizing<String>) -> Result<Self, ConsultationCommitmentError> {
        let valid = !value.is_empty()
            && value.len() <= MAX_CONSENT_REFERENCE_BYTES
            && !value.chars().any(char::is_control);
        valid
            .then_some(Self { value })
            .ok_or(ConsultationCommitmentError::InputOutOfBounds)
    }
}

/// Safe consent facts. Construction is sealed behind exact consent authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifiedConsentDecision(VerifiedConsentDecisionKind);

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifiedConsentDecisionKind {
    NotRequired,
    Verified {
        checked_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        revocation: VerifiedConsentRevocation,
    },
}

impl VerifiedConsentDecision {
    const fn not_required() -> Self {
        Self(VerifiedConsentDecisionKind::NotRequired)
    }

    fn verified(
        checked_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, ConsultationCommitmentError> {
        if !valid_unix_ms(checked_at_unix_ms)
            || !valid_unix_ms(expires_at_unix_ms)
            || checked_at_unix_ms > expires_at_unix_ms
        {
            return Err(ConsultationCommitmentError::InvalidTime);
        }
        Ok(Self(VerifiedConsentDecisionKind::Verified {
            checked_at_unix_ms,
            expires_at_unix_ms,
            revocation: VerifiedConsentRevocation::NotRevoked,
        }))
    }

    const fn kind(self) -> VerifiedConsentDecisionKind {
        self.0
    }

    #[cfg(test)]
    pub(super) const fn not_required_for_test() -> Self {
        Self::not_required()
    }
}

/// The only consent-revocation result that can authorize v1 access.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifiedConsentRevocation {
    NotRevoked,
}

impl VerifiedConsentRevocation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotRevoked => "not_revoked",
        }
    }
}

/// One move-only verifier result that owns the exact profile-validated inputs.
///
/// Required consent has no production constructor in this slice. The future
/// hash-pinned verifier adapter must mint it after consuming these same inputs
/// and the raw evidence reference. That keeps route activation impossible
/// until genuine verification exists.
pub(crate) struct VerifiedConsentAuthority<'profile> {
    inputs: CanonicalConsultationInputs<'profile>,
    decision: VerifiedConsentDecision,
    evidence: Option<VerifiedRawConsentReference>,
}

impl<'profile> VerifiedConsentAuthority<'profile> {
    pub(crate) fn consent_not_required(
        inputs: CanonicalConsultationInputs<'profile>,
    ) -> Result<Self, ConsultationCommitmentError> {
        if !matches!(
            inputs.profile().authorization().consent(),
            CompiledConsentProfile::NotRequired
        ) {
            return Err(ConsultationCommitmentError::ConsentMismatch);
        }
        Ok(Self {
            inputs,
            decision: VerifiedConsentDecision::not_required(),
            evidence: None,
        })
    }

    #[cfg(test)]
    pub(super) fn verified_for_test(
        inputs: CanonicalConsultationInputs<'profile>,
        raw_reference: Zeroizing<String>,
        checked_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> Result<Self, ConsultationCommitmentError> {
        if !matches!(
            inputs.profile().authorization().consent(),
            CompiledConsentProfile::Required { .. }
        ) {
            return Err(ConsultationCommitmentError::ConsentMismatch);
        }
        Ok(Self {
            inputs,
            decision: VerifiedConsentDecision::verified(checked_at_unix_ms, expires_at_unix_ms)?,
            evidence: Some(VerifiedRawConsentReference::try_new(raw_reference)?),
        })
    }
}

/// The exact profile-bound HMAC inputs consumed by one authority-bound commit.
pub(crate) struct ConsultationPseudonymInputs<'profile> {
    pub(super) execution: SealedConsultationExecution<'profile>,
    pub(super) canonical_purpose: Box<str>,
    pub(super) consent: VerifiedConsentDecision,
    pub(super) subject: TransientPseudonymInput,
    pub(super) input: TransientPseudonymInput,
    pub(super) predicate: TransientPseudonymInput,
    pub(super) consent_evidence: Option<TransientPseudonymInput>,
}

#[cfg(test)]
pub(super) struct RuntimePseudonymPreimagesForTest {
    pub(super) subject: Value,
    pub(super) input: Value,
    pub(super) predicate: Value,
    pub(super) consent_evidence: Option<Value>,
}

#[cfg(test)]
impl CanonicalConsultationInputs<'_> {
    pub(super) fn runtime_pseudonym_preimages_for_test(
        &self,
        raw_consent_reference: Option<&str>,
    ) -> Result<RuntimePseudonymPreimagesForTest, ConsultationCommitmentError> {
        let (identifier_type, canonical_subject) = self.only_input()?;
        Ok(RuntimePseudonymPreimagesForTest {
            subject: subject_pseudonym_value(self.profile(), identifier_type, canonical_subject),
            input: input_pseudonym_value(self.profile(), self),
            predicate: predicate_pseudonym_value(self.profile(), self),
            consent_evidence: consent_pseudonym_value(
                self.profile().authorization().consent(),
                raw_consent_reference,
            )?,
        })
    }
}

/// Consume one sealed consent authority into the four exact HMAC preimages.
pub(crate) fn build_pseudonym_inputs(
    authority: VerifiedConsentAuthority<'_>,
) -> Result<ConsultationPseudonymInputs<'_>, ConsultationCommitmentError> {
    let VerifiedConsentAuthority {
        inputs,
        decision,
        evidence,
    } = authority;
    let profile = inputs.profile();
    let (identifier_type, canonical_subject) = inputs.only_input()?;
    let subject = transient_input(subject_pseudonym_value(
        profile,
        identifier_type,
        canonical_subject,
    ))?;
    let input = transient_input(input_pseudonym_value(profile, &inputs))?;
    let predicate = transient_input(predicate_pseudonym_value(profile, &inputs))?;
    let consent_evidence = match (
        profile.authorization().consent(),
        decision.kind(),
        &evidence,
    ) {
        (CompiledConsentProfile::NotRequired, VerifiedConsentDecisionKind::NotRequired, None) => {
            None
        }
        (
            CompiledConsentProfile::Required { .. },
            VerifiedConsentDecisionKind::Verified { .. },
            Some(consent_reference),
        ) => Some(transient_input(
            consent_pseudonym_value(
                profile.authorization().consent(),
                Some(consent_reference.value.as_str()),
            )?
            .ok_or(ConsultationCommitmentError::ConsentMismatch)?,
        )?),
        _ => return Err(ConsultationCommitmentError::ConsentMismatch),
    };
    let CanonicalConsultationInputs {
        plan,
        canonical_purpose,
        values,
    } = inputs;
    let execution = SealedConsultationExecution::try_from_canonical_inputs(plan, values)?;
    Ok(ConsultationPseudonymInputs {
        execution,
        canonical_purpose,
        consent: decision,
        subject,
        input,
        predicate,
        consent_evidence,
    })
}

fn subject_pseudonym_value(
    profile: &CompiledRuntimeProfile,
    identifier_type: &str,
    canonical_subject: &str,
) -> Value {
    json!({
        "tenant": profile.tenant().as_str(),
        "registry_instance": profile.registry_instance().as_str(),
        "identifier_type": identifier_type,
        "canonical_subject": canonical_subject,
    })
}

fn input_pseudonym_value(
    profile: &CompiledRuntimeProfile,
    inputs: &CanonicalConsultationInputs<'_>,
) -> Value {
    json!({
        "profile_id": profile.profile().id().as_str(),
        "profile_version": profile.profile().version().to_string(),
        "canonical_inputs": inputs.transient_value(),
    })
}

fn predicate_pseudonym_value(
    profile: &CompiledRuntimeProfile,
    inputs: &CanonicalConsultationInputs<'_>,
) -> Value {
    json!({
        "binding_hash": profile.private_binding_hash(),
        "source_operation": profile.provenance().logical_operation().as_str(),
        "exact_predicate": {
            "canonical_inputs": inputs.transient_value(),
            "predicate_plan_digest": profile.predicate_plan_digest().as_str(),
            "authorized_operation_union": authorized_operation_union_value(profile),
        },
    })
}

fn consent_pseudonym_value(
    profile: &CompiledConsentProfile,
    raw_consent_reference: Option<&str>,
) -> Result<Option<Value>, ConsultationCommitmentError> {
    match (profile, raw_consent_reference) {
        (CompiledConsentProfile::NotRequired, None) => Ok(None),
        (CompiledConsentProfile::Required { verifier, .. }, Some(reference)) => Ok(Some(json!({
            "verifier_id": verifier.as_str(),
            "raw_consent_reference": reference,
        }))),
        _ => Err(ConsultationCommitmentError::ConsentMismatch),
    }
}

pub(super) struct ConsultationDigests {
    authorization_context: AuthorizationContextDigest,
    execution_plan: ExecutionPlanDigest,
    request: AuthorizedRequestDigest,
}

impl ConsultationDigests {
    pub(super) const fn authorization_context(&self) -> &AuthorizationContextDigest {
        &self.authorization_context
    }

    pub(super) const fn execution_plan(&self) -> &ExecutionPlanDigest {
        &self.execution_plan
    }

    pub(super) const fn request(&self) -> &AuthorizedRequestDigest {
        &self.request
    }

    #[cfg(test)]
    pub(super) fn from_labels_for_test(value: &str) -> Self {
        Self {
            authorization_context: AuthorizationContextDigest::from_label_for_test(value),
            execution_plan: ExecutionPlanDigest::from_label_for_test(value),
            request: AuthorizedRequestDigest::from_label_for_test(value),
        }
    }
}

/// One trusted wall-clock and monotonic observation sampled together.
///
/// Production callers cannot inject an integer timestamp. Tests receive a
/// separate constructor so expiry boundaries can be exercised deterministically.
#[derive(Clone, Copy)]
pub(crate) struct TrustedConsultationTime {
    unix_ms: i64,
    monotonic_before: Instant,
    monotonic_after: Instant,
}

impl TrustedConsultationTime {
    pub(crate) fn sample() -> Result<Self, ConsultationCommitmentError> {
        let monotonic_before = Instant::now();
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ConsultationCommitmentError::InvalidTime)?;
        let unix_ms = i64::try_from(elapsed.as_millis())
            .ok()
            .filter(|value| valid_unix_ms(*value))
            .ok_or(ConsultationCommitmentError::InvalidTime)?;
        let monotonic_after = Instant::now();
        Ok(Self {
            unix_ms,
            monotonic_before,
            monotonic_after,
        })
    }

    pub(super) const fn unix_ms(self) -> i64 {
        self.unix_ms
    }

    pub(super) fn conservative_not_after(
        self,
        expires_at_unix_ms: i64,
    ) -> Result<Instant, ConsultationCommitmentError> {
        if !valid_unix_ms(self.unix_ms)
            || self.monotonic_after < self.monotonic_before
            || !valid_unix_ms(expires_at_unix_ms)
            || self.unix_ms >= expires_at_unix_ms
        {
            return Err(ConsultationCommitmentError::InvalidTime);
        }
        let remaining_ms = u64::try_from(expires_at_unix_ms - self.unix_ms)
            .map_err(|_| ConsultationCommitmentError::InvalidTime)?;
        self.monotonic_before
            .checked_add(Duration::from_millis(remaining_ms))
            .ok_or(ConsultationCommitmentError::InvalidTime)
    }

    #[cfg(test)]
    const fn for_test(unix_ms: i64, monotonic_before: Instant, monotonic_after: Instant) -> Self {
        Self {
            unix_ms,
            monotonic_before,
            monotonic_after,
        }
    }
}

/// A move-only policy permit over the exact committed request facts.
///
/// Only the fixed compiled-policy adapter can construct this capability. It
/// must consume the prepared pseudonyms, exact authenticated workload, and
/// matching durable quota grant together.
pub(crate) struct VerifiedPolicyDecision<'profile, 'workload> {
    pseudonyms: PreparedConsultationPseudonyms<'profile>,
    workload: &'workload AuthenticatedConsultationWorkload,
    quota: QuotaGrant,
    checked_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    local_not_after: Instant,
}

impl VerifiedPolicyDecision<'_, '_> {
    pub(super) fn from_compiled_policy<'profile, 'workload>(
        proof: CompiledPolicyProof<'profile, 'workload>,
    ) -> Result<VerifiedPolicyDecision<'profile, 'workload>, ConsultationCommitmentError> {
        let (pseudonyms, workload, quota, checked_at_unix_ms, expires_at_unix_ms, local_not_after) =
            proof.into_parts();
        if !valid_unix_ms(checked_at_unix_ms)
            || !valid_unix_ms(expires_at_unix_ms)
            || checked_at_unix_ms >= expires_at_unix_ms
        {
            return Err(ConsultationCommitmentError::InvalidTime);
        }
        Ok(VerifiedPolicyDecision {
            pseudonyms,
            workload,
            quota,
            checked_at_unix_ms,
            expires_at_unix_ms,
            local_not_after,
        })
    }

    #[cfg(test)]
    fn from_verified_adapter_for_test<'profile, 'workload>(
        pseudonyms: PreparedConsultationPseudonyms<'profile>,
        workload: &'workload AuthenticatedConsultationWorkload,
        checked_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        local_not_after: Instant,
    ) -> Result<VerifiedPolicyDecision<'profile, 'workload>, ConsultationCommitmentError> {
        if !valid_unix_ms(checked_at_unix_ms)
            || !valid_unix_ms(expires_at_unix_ms)
            || checked_at_unix_ms > expires_at_unix_ms
        {
            return Err(ConsultationCommitmentError::InvalidTime);
        }
        Ok(VerifiedPolicyDecision {
            pseudonyms,
            workload,
            quota: QuotaGrant::for_consultation_test(),
            checked_at_unix_ms,
            expires_at_unix_ms,
            local_not_after,
        })
    }
}

struct AuthorizedDecisionFreshness {
    expires_at_unix_ms: i64,
    local_not_after: Instant,
}

impl AuthorizedDecisionFreshness {
    fn check(&self, now: TrustedConsultationTime) -> Result<(), ConsultationCommitmentError> {
        if !valid_unix_ms(now.unix_ms)
            || now.unix_ms >= self.expires_at_unix_ms
            || now.monotonic_after >= self.local_not_after
        {
            return Err(ConsultationCommitmentError::AuthorizationMismatch);
        }
        Ok(())
    }

    fn pending_persistence(&self) -> PendingConsultationPersistenceFreshness {
        PendingConsultationPersistenceFreshness {
            expires_at_unix_ms: self.expires_at_unix_ms,
            local_not_after: self.local_not_after,
        }
    }

    fn pending_dispatch(&self) -> PendingConsultationDispatchFreshness {
        PendingConsultationDispatchFreshness {
            expires_at_unix_ms: self.expires_at_unix_ms,
            local_not_after: self.local_not_after,
        }
    }
}

/// One move-only authorized consultation attempt.
///
/// The aggregate retains the exact profile, purpose, consent result,
/// authority-bound pseudonyms, and all derived digests. No public(crate) seed
/// or atomic-persistence API accepts those members separately, so callers
/// cannot cross-wire facts from two independently valid authorizations.
pub(crate) struct AuthorizedConsultationAttempt<'profile> {
    canonical_purpose: Box<str>,
    consent: VerifiedConsentDecision,
    pseudonyms: PreparedConsultationPseudonyms<'profile>,
    digests: ConsultationDigests,
    quota: QuotaGrant,
    freshness: AuthorizedDecisionFreshness,
}

impl<'profile> AuthorizedConsultationAttempt<'profile> {
    pub(super) fn profile(&self) -> &CompiledRuntimeProfile {
        self.pseudonyms.profile()
    }

    pub(super) fn canonical_purpose(&self) -> &str {
        &self.canonical_purpose
    }

    pub(super) const fn consent(&self) -> VerifiedConsentDecision {
        self.consent
    }

    pub(super) const fn pseudonyms(&self) -> &PreparedConsultationPseudonyms<'_> {
        &self.pseudonyms
    }

    pub(super) const fn digests(&self) -> &ConsultationDigests {
        &self.digests
    }

    pub(super) fn ensure_preparation_fresh(&self) -> Result<(), ConsultationCommitmentError> {
        self.freshness.check(TrustedConsultationTime::sample()?)
    }

    pub(super) fn into_pseudonyms_and_freshness_guards(
        self,
    ) -> (
        PreparedConsultationPseudonyms<'profile>,
        QuotaGrant,
        PendingConsultationPersistenceFreshness,
        PendingConsultationDispatchFreshness,
    ) {
        let persistence = self.freshness.pending_persistence();
        let dispatch = self.freshness.pending_dispatch();
        (self.pseudonyms, self.quota, persistence, dispatch)
    }
}

/// A one-shot policy deadline carried into the authoritative attempt CAS.
#[must_use = "decision freshness must be consumed by the atomic persistence boundary"]
pub(crate) struct PendingConsultationPersistenceFreshness {
    expires_at_unix_ms: i64,
    local_not_after: Instant,
}

impl PendingConsultationPersistenceFreshness {
    /// Return the safe absolute deadline that the SQL CAS must compare with
    /// database time. The guard itself must still be consumed by that CAS.
    pub(crate) const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }

    pub(crate) fn check_fresh_now(&self) -> Result<(), ConsultationCommitmentError> {
        AuthorizedDecisionFreshness {
            expires_at_unix_ms: self.expires_at_unix_ms,
            local_not_after: self.local_not_after,
        }
        .check(TrustedConsultationTime::sample()?)
    }

    #[cfg(test)]
    pub(super) fn for_state_test(expires_at_unix_ms: i64, local_not_after: Instant) -> Self {
        Self {
            expires_at_unix_ms,
            local_not_after,
        }
    }
}

/// A one-shot decision guard retained across the atomic attempt CAS.
#[must_use = "decision freshness must be rechecked immediately before backend dispatch"]
pub(crate) struct PendingConsultationDispatchFreshness {
    expires_at_unix_ms: i64,
    local_not_after: Instant,
}

impl PendingConsultationDispatchFreshness {
    pub(super) fn check_fresh_now(&self) -> Result<(), ConsultationCommitmentError> {
        AuthorizedDecisionFreshness {
            expires_at_unix_ms: self.expires_at_unix_ms,
            local_not_after: self.local_not_after,
        }
        .check(TrustedConsultationTime::sample()?)
    }

    #[cfg(test)]
    pub(super) fn for_state_test(expires_at_unix_ms: i64, local_not_after: Instant) -> Self {
        Self {
            expires_at_unix_ms,
            local_not_after,
        }
    }
}

/// Authorize and bind the one policy-owned commitment chain into an attempt.
pub(crate) fn authorize_consultation_attempt<'profile>(
    decision: VerifiedPolicyDecision<'profile, '_>,
) -> Result<AuthorizedConsultationAttempt<'profile>, ConsultationCommitmentError> {
    let now = TrustedConsultationTime::sample()?;
    authorize_consultation_attempt_at(decision, now)
}

fn authorize_consultation_attempt_at<'profile>(
    decision: VerifiedPolicyDecision<'profile, '_>,
    now: TrustedConsultationTime,
) -> Result<AuthorizedConsultationAttempt<'profile>, ConsultationCommitmentError> {
    let VerifiedPolicyDecision {
        pseudonyms,
        workload,
        quota,
        checked_at_unix_ms,
        expires_at_unix_ms,
        local_not_after,
    } = decision;
    let profile = pseudonyms.profile();
    let consent = pseudonyms.consent;
    let freshness = validate_decision_window(
        profile,
        workload.authentication_expires_at_unix_ms(),
        consent,
        checked_at_unix_ms,
        expires_at_unix_ms,
        local_not_after,
        now,
    )?;
    let decision_expires_at = AuthorizationDecisionExpiry(expires_at_unix_ms);
    let authorization_context = build_authorization_context_digest(
        profile,
        workload,
        &pseudonyms.canonical_purpose,
        consent,
        pseudonyms.consent_evidence_commitment.as_ref(),
        decision_expires_at,
    )?;
    let execution_plan = build_execution_plan_digest(profile, &pseudonyms.predicate_commitment)?;
    let request = build_authorized_request_digest(
        profile,
        &pseudonyms.key_id,
        &pseudonyms.input_commitment,
        &pseudonyms.subject_handle,
        &authorization_context,
        &execution_plan,
    )?;
    Ok(AuthorizedConsultationAttempt {
        canonical_purpose: pseudonyms.canonical_purpose.clone(),
        consent,
        pseudonyms,
        digests: ConsultationDigests {
            authorization_context,
            execution_plan,
            request,
        },
        quota,
        freshness,
    })
}

#[derive(Clone, Copy)]
struct AuthorizationDecisionExpiry(i64);

impl AuthorizationDecisionExpiry {
    const fn unix_ms(self) -> i64 {
        self.0
    }
}

fn validate_decision_window(
    profile: &CompiledRuntimeProfile,
    authentication_expires_at_unix_ms: i64,
    consent: VerifiedConsentDecision,
    decision_checked_at_unix_ms: i64,
    decision_expires_at_unix_ms: i64,
    policy_local_not_after: Instant,
    now: TrustedConsultationTime,
) -> Result<AuthorizedDecisionFreshness, ConsultationCommitmentError> {
    if !valid_unix_ms(now.unix_ms)
        || now.monotonic_after < now.monotonic_before
        || !valid_unix_ms(authentication_expires_at_unix_ms)
        || !valid_unix_ms(decision_checked_at_unix_ms)
        || !valid_unix_ms(decision_expires_at_unix_ms)
        || decision_checked_at_unix_ms > now.unix_ms
        || now.unix_ms >= decision_expires_at_unix_ms
        || decision_expires_at_unix_ms > authentication_expires_at_unix_ms
        || decision_expires_at_unix_ms - decision_checked_at_unix_ms
            > i64::from(profile.authorization().max_decision_age_ms())
    {
        return Err(ConsultationCommitmentError::AuthorizationMismatch);
    }
    validate_consent_window(
        profile.authorization().consent(),
        consent,
        decision_checked_at_unix_ms,
        decision_expires_at_unix_ms,
    )?;
    let remaining_ms = u64::try_from(decision_expires_at_unix_ms - now.unix_ms)
        .map_err(|_| ConsultationCommitmentError::InvalidTime)?;
    let wall_local_not_after = now
        .monotonic_before
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(ConsultationCommitmentError::InvalidTime)?;
    let freshness = AuthorizedDecisionFreshness {
        expires_at_unix_ms: decision_expires_at_unix_ms,
        local_not_after: policy_local_not_after.min(wall_local_not_after),
    };
    freshness.check(now)?;
    Ok(freshness)
}

fn validate_consent_window(
    profile: &CompiledConsentProfile,
    consent: VerifiedConsentDecision,
    decision_checked_at_unix_ms: i64,
    decision_expires_at_unix_ms: i64,
) -> Result<(), ConsultationCommitmentError> {
    match (profile, consent.kind()) {
        (CompiledConsentProfile::NotRequired, VerifiedConsentDecisionKind::NotRequired) => {}
        (
            CompiledConsentProfile::Required {
                max_age_ms,
                online_revocation_required: true,
                deny_when_unavailable: true,
                ..
            },
            VerifiedConsentDecisionKind::Verified {
                checked_at_unix_ms,
                expires_at_unix_ms,
                revocation: VerifiedConsentRevocation::NotRevoked,
            },
        ) if checked_at_unix_ms <= decision_checked_at_unix_ms
            && decision_checked_at_unix_ms - checked_at_unix_ms <= i64::from(*max_age_ms)
            && decision_expires_at_unix_ms <= expires_at_unix_ms => {}
        _ => return Err(ConsultationCommitmentError::ConsentMismatch),
    }
    Ok(())
}

/// Derive the exact ordinary authorization-context digest after a full permit.
#[allow(clippy::too_many_arguments)]
fn build_authorization_context_digest(
    profile: &CompiledRuntimeProfile,
    workload: &AuthenticatedConsultationWorkload,
    canonical_purpose: &str,
    consent: VerifiedConsentDecision,
    consent_evidence_commitment: Option<&AuditPseudonymCommitment>,
    decision_expires_at: AuthorizationDecisionExpiry,
) -> Result<AuthorizationContextDigest, ConsultationCommitmentError> {
    AuthorizationContextDigest::derive(
        AUTHORIZATION_CONTEXT_DOMAIN_V1,
        &authorization_context_value(
            profile,
            workload,
            canonical_purpose,
            consent,
            consent_evidence_commitment,
            decision_expires_at,
        )?,
    )
}

#[allow(clippy::too_many_arguments)]
fn authorization_context_value(
    profile: &CompiledRuntimeProfile,
    workload: &AuthenticatedConsultationWorkload,
    canonical_purpose: &str,
    consent: VerifiedConsentDecision,
    consent_evidence_commitment: Option<&AuditPseudonymCommitment>,
    decision_expires_at: AuthorizationDecisionExpiry,
) -> Result<Value, ConsultationCommitmentError> {
    if profile.workload_id() != workload.workload_id()
        || profile.tenant() != workload.tenant()
        || profile.registry_instance() != workload.registry_instance()
        || !profile
            .purposes()
            .any(|purpose| purpose == canonical_purpose)
        || !workload
            .checked_scopes()
            .any(|scope| scope == profile.required_scope().as_str())
    {
        return Err(ConsultationCommitmentError::AuthorizationMismatch);
    }
    let consent = verified_consent_value(
        profile.authorization().consent(),
        consent,
        consent_evidence_commitment,
    )?;
    Ok(json!({
        "auth_mode": workload.auth_mode().as_str(),
        "issuer": workload.issuer().as_str(),
        "audience": workload.audience().as_str(),
        "client_claim_selector": workload.client_claim_selector().as_str(),
        "client_value": workload.client_value().as_str(),
        "workload_id": workload.workload_id().as_str(),
        "principal_id": workload.principal_id(),
        "checked_scopes": workload.checked_scopes().collect::<Vec<_>>(),
        "tenant": workload.tenant().as_str(),
        "registry_instance": workload.registry_instance().as_str(),
        "canonical_purpose": canonical_purpose,
        "authorized_legal_basis": profile.legal_basis(),
        "verified_consent_decision": consent,
        "policy_id": profile.authorization().policy().id().as_str(),
        "policy_hash": profile.authorization().policy().hash().as_str(),
        "mandatory_obligations": [],
        "decision_expires_at": decision_expires_at.unix_ms(),
    }))
}

/// Derive the exact ordinary execution-plan digest. The predicate itself is
/// represented only by its keyed commitment.
fn build_execution_plan_digest(
    profile: &CompiledRuntimeProfile,
    predicate_commitment: &AuditPseudonymCommitment,
) -> Result<ExecutionPlanDigest, ConsultationCommitmentError> {
    ExecutionPlanDigest::derive(
        EXECUTION_PLAN_DOMAIN_V1,
        &execution_plan_value(profile, predicate_commitment)?,
    )
}

fn execution_plan_value(
    profile: &CompiledRuntimeProfile,
    predicate_commitment: &AuditPseudonymCommitment,
) -> Result<Value, ConsultationCommitmentError> {
    let bounds = profile.effective_limits().operation();
    if bounds.timeout_ms == 0 || bounds.timeout_ms > 20_000 {
        return Err(ConsultationCommitmentError::AuthorizationMismatch);
    }
    Ok(json!({
        "binding_hash": profile.private_binding_hash(),
        "integration_pack_hash": profile.integration_pack().hash().as_str(),
        "backend_kind": plan_kind_str(profile.kind()),
        "source_operation": profile.provenance().logical_operation().as_str(),
        "predicate_commitment": predicate_commitment.as_str(),
        "acquisition_class": acquisition_class_str(profile.footprint().acquisition_class()),
        "worst_case_acquisition_schema": acquisition_schema_value(profile),
        "physical_projection_digest": profile.physical_projection_digest().as_str(),
        "output_fields": profile.output().map(|field| field.name()).collect::<Vec<_>>(),
        "max_source_matches": bounds.max_source_matches,
        "max_disclosed_records": bounds.max_disclosed_records,
        "max_data_exchanges": bounds.max_data_exchanges,
        "max_credential_exchanges": bounds.max_credential_exchanges,
        "max_data_destinations": bounds.max_data_destinations,
        "max_source_bytes": bounds.max_source_bytes,
        "timeout_ms": bounds.timeout_ms,
        "dispatch_budget_ms": bounds.timeout_ms,
    }))
}

/// Derive the final request digest after all keyed and ordinary commitments
/// have been computed.
#[allow(clippy::too_many_arguments)]
fn build_authorized_request_digest(
    profile: &CompiledRuntimeProfile,
    commitment_key_id: &AuditPseudonymKeyId,
    input_commitment: &AuditPseudonymCommitment,
    subject_handle: &AuditPseudonymCommitment,
    authorization_context_digest: &AuthorizationContextDigest,
    execution_plan_digest: &ExecutionPlanDigest,
) -> Result<AuthorizedRequestDigest, ConsultationCommitmentError> {
    AuthorizedRequestDigest::derive(
        AUTHORIZED_REQUEST_DOMAIN_V1,
        &authorized_request_value(
            profile,
            commitment_key_id,
            input_commitment,
            subject_handle,
            authorization_context_digest,
            execution_plan_digest,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn authorized_request_value(
    profile: &CompiledRuntimeProfile,
    commitment_key_id: &AuditPseudonymKeyId,
    input_commitment: &AuditPseudonymCommitment,
    subject_handle: &AuditPseudonymCommitment,
    authorization_context_digest: &AuthorizationContextDigest,
    execution_plan_digest: &ExecutionPlanDigest,
) -> Value {
    json!({
        "route": EXECUTE_ROUTE_V1,
        "profile_id": profile.profile().id().as_str(),
        "profile_version": profile.profile().version().to_string(),
        "contract_hash": profile.profile().contract_hash().as_str(),
        "commitment_key_id": commitment_key_id.as_str(),
        "input_commitment": input_commitment.as_str(),
        "subject_handle": subject_handle.as_str(),
        "selector_provenance": selector_provenance_value(
            profile.subject().selector_provenance(),
        ),
        "authorization_context_digest": authorization_context_digest.as_str(),
        "execution_plan_digest": execution_plan_digest.as_str(),
    })
}

#[cfg(test)]
pub(super) struct RuntimeDigestChainForTest {
    pub(super) authorization_context_preimage: Value,
    pub(super) execution_plan_preimage: Value,
    pub(super) request_preimage: Value,
    pub(super) digests: ConsultationDigests,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn runtime_digest_chain_for_test(
    profile: &CompiledRuntimeProfile,
    workload: &AuthenticatedConsultationWorkload,
    canonical_purpose: &str,
    consent: VerifiedConsentDecision,
    consent_evidence_commitment: Option<&AuditPseudonymCommitment>,
    decision_expires_at_unix_ms: i64,
    commitment_key_id: &AuditPseudonymKeyId,
    input_commitment: &AuditPseudonymCommitment,
    subject_handle: &AuditPseudonymCommitment,
    predicate_commitment: &AuditPseudonymCommitment,
) -> Result<RuntimeDigestChainForTest, ConsultationCommitmentError> {
    let decision_expires_at = AuthorizationDecisionExpiry(decision_expires_at_unix_ms);
    let authorization_context_preimage = authorization_context_value(
        profile,
        workload,
        canonical_purpose,
        consent,
        consent_evidence_commitment,
        decision_expires_at,
    )?;
    let authorization_context = build_authorization_context_digest(
        profile,
        workload,
        canonical_purpose,
        consent,
        consent_evidence_commitment,
        decision_expires_at,
    )?;
    let execution_plan_preimage = execution_plan_value(profile, predicate_commitment)?;
    let execution_plan = build_execution_plan_digest(profile, predicate_commitment)?;
    let request_preimage = authorized_request_value(
        profile,
        commitment_key_id,
        input_commitment,
        subject_handle,
        &authorization_context,
        &execution_plan,
    );
    let request = build_authorized_request_digest(
        profile,
        commitment_key_id,
        input_commitment,
        subject_handle,
        &authorization_context,
        &execution_plan,
    )?;
    Ok(RuntimeDigestChainForTest {
        authorization_context_preimage,
        execution_plan_preimage,
        request_preimage,
        digests: ConsultationDigests {
            authorization_context,
            execution_plan,
            request,
        },
    })
}

pub(crate) fn empty_obligations_digest(
) -> Result<EmptyObligationsDigest, ConsultationCommitmentError> {
    EmptyObligationsDigest::derive(EMPTY_OBLIGATIONS_DOMAIN_V1, &json!([]))
}

pub(super) fn authorized_operation_union_value(profile: &CompiledRuntimeProfile) -> Vec<Value> {
    profile
        .authorized_operation_union()
        .map(|(kind, operation_id)| {
            json!({
                "kind": kind,
                "operation_id": operation_id,
            })
        })
        .collect()
}

pub(super) fn permit_bindings_value(profile: &CompiledRuntimeProfile) -> Vec<Value> {
    profile
        .permit_bindings()
        .map(|(kind, ordinal, allowed_operation_ids)| {
            json!({
                "kind": kind,
                "ordinal": ordinal,
                "allowed_operation_ids": allowed_operation_ids,
            })
        })
        .collect()
}

pub(super) fn acquisition_schema_value(profile: &CompiledRuntimeProfile) -> Value {
    let fields = profile
        .acquisition()
        .fields()
        .map(|field| {
            (
                field.name().to_owned(),
                compiled_response_schema_value(field.schema()),
            )
        })
        .collect::<Map<_, _>>();
    json!({"type": "acquisition_union", "fields": fields})
}

fn compiled_response_schema_value(schema: &CompiledResponseSchema) -> Value {
    match schema {
        CompiledResponseSchema::Object { nullable, fields } => {
            let fields = fields
                .iter()
                .map(|field| {
                    (
                        field.name().to_owned(),
                        json!({
                            "required": field.required(),
                            "schema": compiled_response_schema_value(field.schema()),
                        }),
                    )
                })
                .collect::<Map<_, _>>();
            json!({
                "type": "object",
                "nullable": nullable,
                "reject_unknown_fields": true,
                "fields": fields,
            })
        }
        CompiledResponseSchema::Array {
            nullable,
            max_items,
            items,
        } => json!({
            "type": "array",
            "nullable": nullable,
            "max_items": max_items,
            "items": compiled_response_schema_value(items),
        }),
        CompiledResponseSchema::Scalar(shape) => compiled_scalar_shape_value(shape),
    }
}

fn compiled_scalar_shape_value(shape: &CompiledScalarShape) -> Value {
    match shape {
        CompiledScalarShape::String {
            nullable,
            max_bytes,
        } => json!({"type": "string", "nullable": nullable, "max_bytes": max_bytes}),
        CompiledScalarShape::Boolean { nullable } => {
            json!({"type": "boolean", "nullable": nullable})
        }
        CompiledScalarShape::Integer {
            nullable,
            minimum,
            maximum,
        } => json!({
            "type": "integer",
            "nullable": nullable,
            "minimum": minimum,
            "maximum": maximum,
        }),
        CompiledScalarShape::Number {
            nullable,
            minimum,
            maximum,
        } => json!({
            "type": "number",
            "nullable": nullable,
            "minimum": minimum,
            "maximum": maximum,
        }),
    }
}

fn verified_consent_value(
    profile: &CompiledConsentProfile,
    decision: VerifiedConsentDecision,
    evidence: Option<&AuditPseudonymCommitment>,
) -> Result<Value, ConsultationCommitmentError> {
    match (profile, decision.kind(), evidence) {
        (CompiledConsentProfile::NotRequired, VerifiedConsentDecisionKind::NotRequired, None) => {
            Ok(json!({
                "required": false,
                "outcome": "not_required",
                "verifier_id": null,
                "verifier_revision": null,
                "evidence_commitment": null,
                "checked_at": null,
                "expires_at": null,
                "revocation_status": "not_applicable",
            }))
        }
        (
            CompiledConsentProfile::Required {
                verifier,
                contract_hash,
                ..
            },
            VerifiedConsentDecisionKind::Verified {
                checked_at_unix_ms,
                expires_at_unix_ms,
                revocation,
            },
            Some(evidence),
        ) => Ok(json!({
            "required": true,
            "outcome": "verified",
            "verifier_id": verifier.as_str(),
            "verifier_revision": contract_hash.as_str(),
            "evidence_commitment": evidence.as_str(),
            "checked_at": checked_at_unix_ms,
            "expires_at": expires_at_unix_ms,
            "revocation_status": revocation.as_str(),
        })),
        _ => Err(ConsultationCommitmentError::ConsentMismatch),
    }
}

fn selector_provenance_value(provenance: &SelectorProvenance) -> Value {
    match provenance {
        SelectorProvenance::TrustedNotaryAssertion(assertion) => json!({
            "type": "trusted_notary_assertion",
            "assertion_contract": {
                "id": assertion.id().as_str(),
                "hash": assertion.hash().as_str(),
            },
        }),
        SelectorProvenance::WorkloadSelected => json!({"type": "workload_selected"}),
    }
}

fn transient_input(value: Value) -> Result<TransientPseudonymInput, ConsultationCommitmentError> {
    TransientPseudonymInput::from_jcs_value(value)
        .map_err(|_| ConsultationCommitmentError::Canonicalization)
}

fn domain_separated_digest(
    domain: &str,
    value: &Value,
) -> Result<Box<str>, ConsultationCommitmentError> {
    use std::fmt::Write as _;

    let canonical =
        canonicalize_json(value).map_err(|_| ConsultationCommitmentError::Canonicalization)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut label = String::with_capacity(71);
    label.push_str("sha256:");
    for byte in digest {
        write!(label, "{byte:02x}").map_err(|_| ConsultationCommitmentError::Canonicalization)?;
    }
    Ok(label.into())
}

const fn valid_unix_ms(value: i64) -> bool {
    value >= 0 && value <= MAX_EXACT_JSON_INTEGER
}

const fn plan_kind_str(kind: SourcePlanKind) -> &'static str {
    match kind {
        SourcePlanKind::SnapshotExact => "snapshot_exact",
        SourcePlanKind::BoundedHttp => "bounded_http",
        SourcePlanKind::SandboxedRhai => "sandboxed_rhai",
    }
}

const fn acquisition_class_str(class: AcquisitionClass) -> &'static str {
    match class {
        AcquisitionClass::SourceProjectedExact => "source_projected_exact",
        AcquisitionClass::BoundedFullRecord => "bounded_full_record",
        AcquisitionClass::MaterializedSnapshot => "materialized_snapshot",
    }
}

pub(super) fn consent_seed_value(
    consent: &CompiledConsentProfile,
    decision: VerifiedConsentDecision,
) -> Result<Value, ConsultationCommitmentError> {
    match (consent, decision.kind()) {
        (CompiledConsentProfile::NotRequired, VerifiedConsentDecisionKind::NotRequired) => {
            Ok(json!({
                "required": false,
                "verifier_id": null,
                "contract_hash": null,
                "decision": "not_required",
            }))
        }
        (
            CompiledConsentProfile::Required {
                verifier,
                contract_hash,
                ..
            },
            VerifiedConsentDecisionKind::Verified { .. },
        ) => Ok(json!({
            "required": true,
            "verifier_id": verifier.as_str(),
            "contract_hash": contract_hash.as_str(),
            "decision": "verified",
        })),
        _ => Err(ConsultationCommitmentError::ConsentMismatch),
    }
}

pub(crate) fn public_outcome_str(outcome: CompiledPublicOutcome) -> &'static str {
    match outcome {
        CompiledPublicOutcome::Match => "match",
        CompiledPublicOutcome::NoMatch => "no_match",
        CompiledPublicOutcome::Ambiguous => "ambiguous",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consultation::{
        IntegrationPackHash, OperationId, ParsedPurpose, ParsedSingleStringInput,
    };
    use crate::source_plan::{
        bounded_runtime_vector_plan_fixture, maximum_runtime_profile_fixture,
    };

    #[test]
    fn digest_debug_is_redacted_and_domains_are_distinct() {
        let value = json!({"safe": "value"});
        let authorization =
            AuthorizationContextDigest::derive(AUTHORIZATION_CONTEXT_DOMAIN_V1, &value).unwrap();
        let execution = ExecutionPlanDigest::derive(EXECUTION_PLAN_DOMAIN_V1, &value).unwrap();
        assert_ne!(authorization.as_str(), execution.as_str());
        let diagnostic = format!("{authorization:?}");
        assert!(!diagnostic.contains(&authorization.as_str()[7..]));
        assert!(diagnostic.contains("sha256:<redacted>"));
    }

    #[test]
    fn decision_times_are_exact_json_integers_and_ordered() {
        assert!(VerifiedConsentDecision::verified(0, MAX_EXACT_JSON_INTEGER).is_ok());
        assert_eq!(
            VerifiedConsentDecision::verified(2, 1).err(),
            Some(ConsultationCommitmentError::InvalidTime)
        );
        assert_eq!(
            VerifiedConsentDecision::verified(-1, 1).err(),
            Some(ConsultationCommitmentError::InvalidTime)
        );
    }

    #[test]
    fn decision_window_caps_policy_age_authentication_and_both_clocks() {
        let profile = maximum_runtime_profile_fixture();
        let anchor = Instant::now();
        assert_eq!(
            TrustedConsultationTime::for_test(1_000, anchor, anchor + Duration::from_millis(400),)
                .conservative_not_after(1_500)
                .expect("policy deadline uses the conservative side of the sampling bracket"),
            anchor + Duration::from_millis(500),
        );
        let now = TrustedConsultationTime::for_test(1_000, anchor, anchor);
        let freshness = validate_decision_window(
            &profile,
            2_000,
            VerifiedConsentDecision::not_required(),
            900,
            1_500,
            anchor + Duration::from_millis(600),
            now,
        )
        .expect("fresh exact decision");
        assert!(freshness
            .check(TrustedConsultationTime::for_test(1_499, anchor, anchor))
            .is_ok());
        assert!(freshness
            .check(TrustedConsultationTime::for_test(
                1_001,
                anchor + Duration::from_millis(499),
                anchor + Duration::from_millis(500),
            ))
            .is_err());

        for (checked_at, expires_at, auth_expires, observed_at) in [
            (1_001, 1_500, 2_000, 1_000),
            (900, 1_000, 2_000, 1_000),
            (900, 1_501, 1_500, 1_000),
            (
                0,
                i64::from(profile.authorization().max_decision_age_ms()) + 1,
                2_000,
                1,
            ),
        ] {
            assert!(validate_decision_window(
                &profile,
                auth_expires,
                VerifiedConsentDecision::not_required(),
                checked_at,
                expires_at,
                anchor + Duration::from_millis(1_000),
                TrustedConsultationTime::for_test(observed_at, anchor, anchor),
            )
            .is_err());
        }

        let bracketed = validate_decision_window(
            &profile,
            2_000,
            VerifiedConsentDecision::not_required(),
            900,
            1_500,
            anchor + Duration::from_millis(600),
            TrustedConsultationTime::for_test(1_000, anchor, anchor + Duration::from_millis(400)),
        )
        .expect("sampling gap consumes but never extends monotonic lifetime");
        assert!(bracketed
            .check(TrustedConsultationTime::for_test(
                1_001,
                anchor + Duration::from_millis(499),
                anchor + Duration::from_millis(500),
            ))
            .is_err());

        let rollback_safe = validate_decision_window(
            &profile,
            3_000,
            VerifiedConsentDecision::not_required(),
            1_000,
            2_000,
            anchor + Duration::from_millis(1_000),
            TrustedConsultationTime::for_test(
                1_100,
                anchor + Duration::from_millis(900),
                anchor + Duration::from_millis(900),
            ),
        )
        .expect("slow or rolled-back wall time cannot refresh the original policy deadline");
        assert!(rollback_safe
            .check(TrustedConsultationTime::for_test(
                1_101,
                anchor + Duration::from_millis(999),
                anchor + Duration::from_millis(1_000),
            ))
            .is_err());
    }

    #[test]
    fn required_consent_cannot_be_cross_wired_or_outlive_its_freshness() {
        const HASH: &str =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let required = CompiledConsentProfile::Required {
            verifier: OperationId::try_from("verify-consent").unwrap(),
            contract_hash: IntegrationPackHash::try_from(HASH).unwrap(),
            max_age_ms: 100,
            online_revocation_required: true,
            deny_when_unavailable: true,
        };
        let consent = VerifiedConsentDecision::verified(900, 1_500).unwrap();
        assert!(validate_consent_window(&required, consent, 1_000, 1_400).is_ok());
        for (decision_checked, decision_expires) in [(1_001, 1_400), (1_000, 1_501)] {
            assert!(validate_consent_window(
                &required,
                consent,
                decision_checked,
                decision_expires,
            )
            .is_err());
        }
        assert!(validate_consent_window(
            &CompiledConsentProfile::NotRequired,
            consent,
            1_000,
            1_400,
        )
        .is_err());
    }

    #[test]
    fn empty_obligations_digest_has_a_frozen_golden_value() {
        assert_eq!(
            empty_obligations_digest().unwrap().as_str(),
            "sha256:e348b8325589cd381ed10b7ae06034fbc66c7eac928f5b5b191982ab6d1a229b"
        );
    }

    #[test]
    fn raw_consent_reference_is_zeroizing_and_bounded() {
        assert!(VerifiedRawConsentReference::try_new(Zeroizing::new("evidence-1".into())).is_ok());
        assert_eq!(
            VerifiedRawConsentReference::try_new(Zeroizing::new(String::new())).err(),
            Some(ConsultationCommitmentError::InputOutOfBounds)
        );
        assert_eq!(
            VerifiedRawConsentReference::try_new(Zeroizing::new(
                "x".repeat(MAX_CONSENT_REFERENCE_BYTES + 1)
            ))
            .err(),
            Some(ConsultationCommitmentError::InputOutOfBounds)
        );
    }

    #[test]
    fn pseudonym_preimages_retain_the_exact_plan_and_canonical_input_for_execution() {
        let plan = bounded_runtime_vector_plan_fixture();
        let equivalent_but_distinct_plan = bounded_runtime_vector_plan_fixture();
        let core = PreAuthorizationConsultationCore::new_for_test(
            plan.profile().clone(),
            plan.runtime_profile()
                .subject()
                .selector_provenance()
                .clone(),
            ParsedPurpose::try_parse("benefit-verification").expect("fixture purpose"),
            ParsedSingleStringInput::try_parse("subject_id", "Person-42")
                .expect("fixture selector"),
            plan.footprint().clone(),
        );
        let inputs = CanonicalConsultationInputs::try_from_resolved_core(&plan, core)
            .expect("resolved core binds to its exact plan");
        let committed_preimages = inputs
            .runtime_pseudonym_preimages_for_test(None)
            .expect("commitment preimages");
        let authority = VerifiedConsentAuthority::consent_not_required(inputs)
            .expect("fixture requires no consent");
        let pseudonym_inputs = build_pseudonym_inputs(authority).expect("sealed pseudonym inputs");
        let (retained_plan, retained_input) = pseudonym_inputs.execution.bound_plan_and_input();

        assert!(std::ptr::eq(retained_plan, &plan));
        assert!(!std::ptr::eq(retained_plan, &equivalent_but_distinct_plan));
        assert_eq!(retained_input.as_str(), "Person-42");
        assert!(retained_input.binding_matches(plan.profile().contract_hash(), "subject_id", 0,));
        assert_eq!(
            committed_preimages
                .input
                .pointer("/canonical_inputs/subject_id")
                .and_then(Value::as_str),
            Some(retained_input.as_str()),
            "the executor selector must be the exact value used by the input commitment",
        );
        assert_eq!(
            committed_preimages
                .predicate
                .pointer("/exact_predicate/canonical_inputs/subject_id")
                .and_then(Value::as_str),
            Some(retained_input.as_str()),
            "the executor selector must be the exact value used by the predicate commitment",
        );
    }
}
