// SPDX-License-Identifier: Apache-2.0
//! Compiler-generated consultation authorization policy commitment.

use super::*;

const POLICY_SCHEMA: &str = "registry.relay.consultation-policy.v1";
const POLICY_ENFORCEMENT_PROFILE: &str = "registry.relay.consultation-pdp/v1";
const POLICY_RULE_SET: &str = "registry.relay.consultation-policy-rules.v1";
const POLICY_ACTION: &str = "consultation_execute";
const POLICY_PERMIT: &str = "unqualified";
const POLICY_HASH_DOMAIN: &[u8] = b"registry.relay.consultation-policy.v1\0";

#[derive(Serialize)]
struct ConsultationPolicyPreimage<'a> {
    schema: &'static str,
    enforcement_profile: &'static str,
    rule_set: &'static str,
    id: &'a str,
    action: &'static str,
    target: ConsultationPolicyTarget<'a>,
    authorization: ConsultationPolicyAuthorization<'a>,
    decision: ConsultationPolicyDecision<'a>,
}

#[derive(Serialize)]
struct ConsultationPolicyTarget<'a> {
    profile: ConsultationPolicyProfileTarget<'a>,
    integration_pack: ConsultationPolicyPackTarget<'a>,
}

#[derive(Serialize)]
struct ConsultationPolicyProfileTarget<'a> {
    id: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct ConsultationPolicyPackTarget<'a> {
    id: &'a str,
    version: &'a str,
    hash: &'a str,
}

#[derive(Serialize)]
struct ConsultationPolicyAuthorization<'a> {
    workload: &'a str,
    required_scope: &'a str,
    purposes: &'a [String],
    legal_basis: &'a str,
    consent: &'a ConsentDocument,
    mandatory_obligations: &'a [MandatoryObligationDocument],
}

#[derive(Serialize)]
struct ConsultationPolicyDecision<'a> {
    permit: &'static str,
    decision_cache: &'a PolicyCacheDocument,
    max_decision_age_ms: u32,
    unavailable: &'a UnavailableDocument,
}

pub(in super::super) struct DerivedConsultationPolicy {
    pub(in super::super) canonical_json: Vec<u8>,
    pub(in super::super) hash: PolicyHash,
}

/// Derive the sole v1 policy commitment from an already normalized contract.
///
/// This function accepts no external policy artifact or selector. Every
/// authored policy semantic except the declared hash is represented in the
/// closed preimage, alongside the fixed v1 enforcement semantics.
pub(in super::super) fn derive_consultation_policy(
    document: &PublicContractDocument,
) -> Result<DerivedConsultationPolicy, SourcePlanArtifactError> {
    let authorization = &document.spec.authorization;
    let policy = &authorization.policy;
    let pack = &document.spec.integration_pack;
    let preimage = ConsultationPolicyPreimage {
        schema: POLICY_SCHEMA,
        enforcement_profile: POLICY_ENFORCEMENT_PROFILE,
        rule_set: POLICY_RULE_SET,
        id: &policy.id,
        action: POLICY_ACTION,
        target: ConsultationPolicyTarget {
            profile: ConsultationPolicyProfileTarget {
                id: &document.id,
                version: &document.version,
            },
            integration_pack: ConsultationPolicyPackTarget {
                id: &pack.id,
                version: &pack.version,
                hash: &pack.hash,
            },
        },
        authorization: ConsultationPolicyAuthorization {
            workload: &authorization.workload,
            required_scope: &authorization.required_scope,
            purposes: &authorization.purposes,
            legal_basis: &authorization.legal_basis,
            consent: &authorization.consent,
            mandatory_obligations: &authorization.mandatory_obligations,
        },
        decision: ConsultationPolicyDecision {
            permit: POLICY_PERMIT,
            decision_cache: &policy.decision_cache,
            max_decision_age_ms: policy.max_decision_age_ms,
            unavailable: &policy.unavailable,
        },
    };
    let (canonical_json, digest) = hash_document(POLICY_HASH_DOMAIN, &preimage)?;
    let hash = PolicyHash::try_from(digest.as_str())
        .map_err(|_| SourcePlanArtifactError::Canonicalization)?;
    Ok(DerivedConsultationPolicy {
        canonical_json,
        hash,
    })
}
