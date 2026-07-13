// SPDX-License-Identifier: Apache-2.0
//! Exact local evaluator for the compiler-generated consultation policy v1.
//!
//! The public contract cannot author executable policy. Startup derives and
//! verifies one fixed policy preimage whose permit rule is the conjunction of
//! the already typed workload, scope, tenant, registry, purpose, consent, and
//! empty-obligation facts. Evaluating that closed rule locally avoids a second
//! policy language or network dependency for the first product journey.

use std::time::Instant;

use crate::consultation::{AuthenticatedConsultationWorkload, ConsultationWorkloadRole};
use crate::source_plan::runtime_profile::CompiledRuntimeProfile;
use crate::state_plane::QuotaGrant;

use super::commitments::{
    ConsultationCommitmentError, TrustedConsultationTime, VerifiedPolicyDecision,
};
use super::pseudonym::PreparedConsultationPseudonyms;

/// Unforgeable proof that the fixed policy conjunction and exact quota binding
/// were evaluated together. Its fields and constructor stay private to this
/// module; other consultation modules can only consume a proof already minted
/// here.
pub(super) struct CompiledPolicyProof<'profile, 'workload> {
    pseudonyms: PreparedConsultationPseudonyms<'profile>,
    workload: &'workload AuthenticatedConsultationWorkload,
    quota: QuotaGrant,
    checked_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    local_not_after: Instant,
}

impl<'profile, 'workload> CompiledPolicyProof<'profile, 'workload> {
    pub(super) fn into_parts(
        self,
    ) -> (
        PreparedConsultationPseudonyms<'profile>,
        &'workload AuthenticatedConsultationWorkload,
        QuotaGrant,
        i64,
        i64,
        Instant,
    ) {
        (
            self.pseudonyms,
            self.workload,
            self.quota,
            self.checked_at_unix_ms,
            self.expires_at_unix_ms,
            self.local_not_after,
        )
    }
}

/// Consume the exact prepared commitments into one short-lived policy permit.
///
/// Capacity and quota waits must complete before this function is called. The
/// resulting window is therefore minted as late as possible and is still
/// rechecked before persistence and immediately before source dispatch.
pub(crate) fn evaluate_compiled_policy<'profile, 'workload>(
    pseudonyms: PreparedConsultationPseudonyms<'profile>,
    workload: &'workload AuthenticatedConsultationWorkload,
    quota: QuotaGrant,
) -> Result<VerifiedPolicyDecision<'profile, 'workload>, ConsultationCommitmentError> {
    let profile = pseudonyms.profile();
    let now = TrustedConsultationTime::sample()?;
    let checked_at_unix_ms = now.unix_ms();
    let expires_at_unix_ms = compiled_policy_window(profile, workload, &quota, checked_at_unix_ms)?;
    let local_not_after = now.conservative_not_after(expires_at_unix_ms)?;
    VerifiedPolicyDecision::from_compiled_policy(CompiledPolicyProof {
        pseudonyms,
        workload,
        quota,
        checked_at_unix_ms,
        expires_at_unix_ms,
        local_not_after,
    })
}

fn compiled_policy_window(
    profile: &CompiledRuntimeProfile,
    workload: &AuthenticatedConsultationWorkload,
    quota: &QuotaGrant,
    now_unix_ms: i64,
) -> Result<i64, ConsultationCommitmentError> {
    let authorization = profile.authorization();
    let exact_scope = workload
        .checked_scopes()
        .eq(std::iter::once(profile.required_scope().as_str()));
    if workload.role() != ConsultationWorkloadRole::Authorized
        || workload.workload_id() != profile.workload_id()
        || workload.tenant() != profile.tenant()
        || workload.registry_instance() != profile.registry_instance()
        || !exact_scope
        || !authorization.decision_cache_disabled()
        || !authorization.deny_when_unavailable()
        || !authorization.mandatory_obligations().is_empty()
        || !quota.binding_matches(
            workload,
            profile.profile(),
            profile.effective_limits().quota_per_minute(),
            profile.effective_limits().quota_burst(),
        )
    {
        return Err(ConsultationCommitmentError::AuthorizationMismatch);
    }

    let policy_not_after = now_unix_ms
        .checked_add(i64::from(authorization.max_decision_age_ms()))
        .ok_or(ConsultationCommitmentError::InvalidTime)?;
    let expires_at = policy_not_after.min(workload.authentication_expires_at_unix_ms());
    (now_unix_ms < expires_at)
        .then_some(expires_at)
        .ok_or(ConsultationCommitmentError::AuthorizationMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_plan::bounded_runtime_vector_plan_fixture;

    #[test]
    fn compiled_policy_window_is_late_short_and_authentication_bounded() {
        let plan = bounded_runtime_vector_plan_fixture();
        let profile = plan.runtime_profile();
        let now = 1_700_000_000_000;
        let exact_grant = || {
            QuotaGrant::for_test_binding(
                "registry-notary",
                profile.profile().id().as_str(),
                profile.profile().version().get(),
                u16::try_from(profile.effective_limits().quota_per_minute()).unwrap(),
                u8::try_from(profile.effective_limits().quota_burst()).unwrap(),
            )
        };

        let policy_bounded =
            AuthenticatedConsultationWorkload::for_runtime_vector_test(now + 5_000);
        assert_eq!(
            compiled_policy_window(profile, &policy_bounded, &exact_grant(), now),
            Ok(now + i64::from(profile.authorization().max_decision_age_ms()))
        );

        let authentication_bounded =
            AuthenticatedConsultationWorkload::for_runtime_vector_test(now + 500);
        assert_eq!(
            compiled_policy_window(profile, &authentication_bounded, &exact_grant(), now),
            Ok(now + 500)
        );

        let expired = AuthenticatedConsultationWorkload::for_runtime_vector_test(now);
        assert_eq!(
            compiled_policy_window(profile, &expired, &exact_grant(), now),
            Err(ConsultationCommitmentError::AuthorizationMismatch)
        );

        let rate = u16::try_from(profile.effective_limits().quota_per_minute()).unwrap();
        let burst = u8::try_from(profile.effective_limits().quota_burst()).unwrap();
        for cross_wired in [
            QuotaGrant::for_test_binding(
                "another-workload",
                profile.profile().id().as_str(),
                profile.profile().version().get(),
                rate,
                burst,
            ),
            QuotaGrant::for_test_binding(
                "registry-notary",
                "synthetic.person-status.other",
                profile.profile().version().get(),
                rate,
                burst,
            ),
            QuotaGrant::for_test_binding(
                "registry-notary",
                profile.profile().id().as_str(),
                profile.profile().version().get() + 1,
                rate,
                burst,
            ),
            QuotaGrant::for_test_binding(
                "registry-notary",
                profile.profile().id().as_str(),
                profile.profile().version().get(),
                rate - 1,
                burst,
            ),
            QuotaGrant::for_test_binding(
                "registry-notary",
                profile.profile().id().as_str(),
                profile.profile().version().get(),
                rate,
                burst - 1,
            ),
        ] {
            assert_eq!(
                compiled_policy_window(profile, &policy_bounded, &cross_wired, now),
                Err(ConsultationCommitmentError::AuthorizationMismatch)
            );
        }
    }
}
