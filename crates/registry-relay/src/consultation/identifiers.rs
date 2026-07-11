// SPDX-License-Identifier: Apache-2.0
//! Stable identifiers used by the consultation HTTP and service boundaries.

use std::fmt;

use thiserror::Error;
use ulid::Ulid;

use crate::source_plan::CompiledSourcePlan;

use super::{IntegrationPackHash, ProfileContractHash, ProfileId, ProfileVersion};

/// A value-free reason that a consultation identifier was rejected.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ConsultationIdentifierError {
    /// A profile path key is outside the closed v1 grammar.
    #[error("invalid consultation profile key")]
    InvalidProfileKey,
    /// A Notary evaluation id is not one canonical uppercase ULID.
    #[error("invalid Notary evaluation identifier")]
    InvalidNotaryEvaluationId,
}

/// The public profile id and version selected by the fixed v1 route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConsultationKey {
    id: ProfileId,
    version: ProfileVersion,
}

/// Proof that an authenticated workload resolved this key through its
/// workload-visible compiled profile registry.
///
/// The proof binds the public route key and every artifact identity that can
/// change the activated behavior: public contract, integration pack, and
/// runtime-private binding. Its only production constructor accepts an exact
/// compiled plan and is called by the authenticated registry lookup. The
/// artifact identities remain opaque to request-path callers.
///
/// ```compile_fail
/// use registry_relay::consultation::{
///     ConsultationKey, ResolvedConsultationProfile,
/// };
/// let key = ConsultationKey::try_parse("example.person", "1").unwrap();
/// let _forged = ResolvedConsultationProfile { key };
/// ```
pub struct ResolvedConsultationProfile {
    key: ConsultationKey,
    public_contract_hash: ProfileContractHash,
    integration_pack_hash: IntegrationPackHash,
    private_binding_hash: Box<str>,
}

impl ResolvedConsultationProfile {
    /// Mint a proof from the exact plan returned by the authenticated registry
    /// lookup. No route-supplied artifact identity is accepted here.
    #[allow(
        dead_code,
        reason = "consumed by the consultation service activation slice"
    )]
    pub(crate) fn from_authenticated_registry_plan(plan: &CompiledSourcePlan) -> Self {
        Self {
            key: ConsultationKey {
                id: plan.profile().id().clone(),
                version: plan.profile().version(),
            },
            public_contract_hash: plan.profile().contract_hash().clone(),
            integration_pack_hash: plan.integration_pack().hash().clone(),
            private_binding_hash: plan.binding_hash().into(),
        }
    }

    /// Return the authenticated workload-visible profile key.
    #[must_use]
    pub const fn key(&self) -> &ConsultationKey {
        &self.key
    }

    pub(super) fn matches_exact_plan(&self, plan: &CompiledSourcePlan) -> bool {
        self.key.id() == plan.profile().id()
            && self.key.version() == plan.profile().version()
            && &self.public_contract_hash == plan.profile().contract_hash()
            && &self.integration_pack_hash == plan.integration_pack().hash()
            && self.private_binding_hash.as_ref() == plan.binding_hash()
    }

    #[cfg(test)]
    pub(crate) fn for_wire_test(plan: &CompiledSourcePlan) -> Self {
        Self::from_authenticated_registry_plan(plan)
    }
}

impl ConsultationKey {
    /// Strictly parse the two path segments without normalization.
    pub fn try_parse(id: &str, version: &str) -> Result<Self, ConsultationIdentifierError> {
        let id =
            ProfileId::try_from(id).map_err(|_| ConsultationIdentifierError::InvalidProfileKey)?;
        let version = ProfileVersion::try_from(version)
            .map_err(|_| ConsultationIdentifierError::InvalidProfileKey)?;
        Ok(Self { id, version })
    }

    /// Return the exact profile id from the path.
    #[must_use]
    pub const fn id(&self) -> &ProfileId {
        &self.id
    }

    /// Return the canonical positive profile version from the path.
    #[must_use]
    pub const fn version(&self) -> ProfileVersion {
        self.version
    }
}

/// Relay's server-generated correlation id for one consultation attempt.
///
/// The constructor is crate-private so an inbound request cannot select or
/// reuse Relay's operation identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConsultationId(Ulid);

impl ConsultationId {
    /// Mint a fresh Relay-owned id for a consultation attempt.
    #[must_use]
    pub(crate) fn generate() -> Self {
        Self(Ulid::new())
    }

    /// Return the canonical uppercase ULID text used on the wire and in audit.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for ConsultationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// A typed Notary evaluation id accepted only from the authenticated Notary
/// workload boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NotaryEvaluationId(Ulid);

impl NotaryEvaluationId {
    /// Strictly parse one canonical uppercase ULID without normalization.
    pub fn try_parse(value: &str) -> Result<Self, ConsultationIdentifierError> {
        let id = Ulid::from_string(value)
            .map_err(|_| ConsultationIdentifierError::InvalidNotaryEvaluationId)?;
        if id.to_string() != value {
            return Err(ConsultationIdentifierError::InvalidNotaryEvaluationId);
        }
        Ok(Self(id))
    }

    /// Return the canonical uppercase ULID text.
    #[must_use]
    pub fn to_canonical_string(self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for NotaryEvaluationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_key_uses_the_exact_v1_path_grammar() {
        let key = ConsultationKey::try_parse("example.person-status_exact", "9999999999")
            .expect("valid key");
        assert_eq!(key.id().as_str(), "example.person-status_exact");
        assert_eq!(key.version().get(), 9_999_999_999);

        for (id, version) in [
            ("Example.person", "1"),
            ("example/person", "1"),
            ("example.person", "0"),
            ("example.person", "01"),
            ("example.person", "10000000000"),
        ] {
            assert_eq!(
                ConsultationKey::try_parse(id, version),
                Err(ConsultationIdentifierError::InvalidProfileKey)
            );
        }
    }

    #[test]
    fn notary_evaluation_id_requires_canonical_uppercase_ulid() {
        const CANONICAL: &str = "01JYZZZZZZZZZZZZZZZZZZZZZZ";
        let id = NotaryEvaluationId::try_parse(CANONICAL).expect("canonical ULID");
        assert_eq!(id.to_canonical_string(), CANONICAL);
        assert_eq!(id.to_string(), CANONICAL);

        for invalid in [
            "01jyzzzzzzzzzzzzzzzzzzzzzz",
            "1JYZZZZZZZZZZZZZZZZZZZZZZ",
            "01JYZZZZZZZZZZZZZZZZZZZZZ!",
            "",
        ] {
            assert_eq!(
                NotaryEvaluationId::try_parse(invalid),
                Err(ConsultationIdentifierError::InvalidNotaryEvaluationId)
            );
        }
    }

    #[test]
    fn relay_consultation_id_is_server_generated_and_canonical() {
        let first = ConsultationId::generate();
        let second = ConsultationId::generate();
        assert_ne!(first, second);
        for id in [first, second] {
            let text = id.to_canonical_string();
            assert_eq!(text.len(), 26);
            assert_eq!(Ulid::from_string(&text).unwrap().to_string(), text);
        }
    }

    #[test]
    fn resolved_profile_test_capability_retains_the_exact_plan_identity() {
        let plan = crate::source_plan::bounded_runtime_vector_plan_fixture();
        let resolved = ResolvedConsultationProfile::for_wire_test(&plan);
        assert_eq!(
            resolved.key().id().as_str(),
            "synthetic.person-status.exact"
        );
        assert_eq!(resolved.key().version().get(), 1);
        assert!(resolved.matches_exact_plan(&plan));
    }
}
