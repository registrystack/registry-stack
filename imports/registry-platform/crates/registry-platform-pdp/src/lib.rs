//! Native policy decision primitives for Registry services.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const PURPOSE_NOT_PERMITTED: &str = "pdp.purpose_not_permitted";
pub const ASSURANCE_INSUFFICIENT: &str = "pdp.assurance_insufficient";
pub const EVIDENCE_STALE: &str = "pdp.evidence_stale";
pub const LEGAL_BASIS_REQUIRED: &str = "pdp.legal_basis_required";
pub const CONSENT_REQUIRED: &str = "pdp.consent_required";
pub const JURISDICTION_NOT_PERMITTED: &str = "pdp.jurisdiction_not_permitted";
pub const UNSUPPORTED_POLICY_TERM: &str = "pdp.unsupported_policy_term";
pub const POLICY_ID_REQUIRED: &str = "pdp.policy_id_required";
pub const POLICY_HASH_INVALID: &str = "pdp.policy_hash_invalid";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRequestContext {
    pub purpose: String,
    #[serde(default)]
    pub legal_basis_ref: Option<String>,
    #[serde(default)]
    pub consent_ref: Option<String>,
    #[serde(default)]
    pub asserted_assurance: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub source_observed_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub policy_id: String,
    pub policy_hash: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub purpose_constraints: Vec<Vec<String>>,
    #[serde(default)]
    pub permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    pub allowed_assurance: Vec<String>,
    #[serde(default)]
    pub minimum_assurance: Option<String>,
    #[serde(default)]
    pub max_source_age_seconds: Option<u64>,
    #[serde(default)]
    pub require_legal_basis: bool,
    #[serde(default)]
    pub require_consent: bool,
    #[serde(default)]
    pub redaction_fields: BTreeSet<String>,
    #[serde(default)]
    pub unsupported_odrl_terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Permit(DecisionAudit),
    PermitWithRedaction {
        audit: DecisionAudit,
        field_set: BTreeSet<String>,
        max_age_seconds: Option<u64>,
    },
    Deny {
        audit: DecisionAudit,
        stable_problem_code: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAudit {
    pub policy_id: String,
    pub policy_hash: String,
    pub evaluated_rule_ids: Vec<String>,
}

pub fn decide(context: &EvidenceRequestContext, policy: &PolicyInput) -> Decision {
    let audit = DecisionAudit {
        policy_id: policy.policy_id.clone(),
        policy_hash: policy.policy_hash.clone(),
        evaluated_rule_ids: policy.rule_ids.clone(),
    };
    if policy.policy_id.trim().is_empty() {
        return deny(audit, POLICY_ID_REQUIRED);
    }
    if !is_sha256_digest(&policy.policy_hash) {
        return deny(audit, POLICY_HASH_INVALID);
    }
    if !policy.unsupported_odrl_terms.is_empty() {
        return deny(audit, UNSUPPORTED_POLICY_TERM);
    }
    if !policy.purpose_constraints.is_empty()
        && !policy
            .purpose_constraints
            .iter()
            .all(|constraint| constraint.iter().any(|purpose| purpose == &context.purpose))
    {
        return deny(audit, PURPOSE_NOT_PERMITTED);
    }
    if !policy.permitted_jurisdictions.is_empty() {
        let Some(jurisdiction) = context.jurisdiction.as_deref() else {
            return deny(audit, JURISDICTION_NOT_PERMITTED);
        };
        if !policy
            .permitted_jurisdictions
            .iter()
            .any(|permitted| permitted == jurisdiction)
        {
            return deny(audit, JURISDICTION_NOT_PERMITTED);
        }
    }
    if !policy.allowed_assurance.is_empty() {
        let Some(asserted_assurance) = context.asserted_assurance.as_deref() else {
            return deny(audit, ASSURANCE_INSUFFICIENT);
        };
        let normalized_asserted = normalized_assurance(asserted_assurance);
        if !policy
            .allowed_assurance
            .iter()
            .any(|allowed| normalized_assurance(allowed) == normalized_asserted)
        {
            return deny(audit, ASSURANCE_INSUFFICIENT);
        }
    }
    if let Some(minimum_assurance) = policy.minimum_assurance.as_deref() {
        let Some(minimum_rank) = assurance_rank(minimum_assurance) else {
            return deny(audit, UNSUPPORTED_POLICY_TERM);
        };
        let Some(asserted_assurance) = context.asserted_assurance.as_deref() else {
            return deny(audit, ASSURANCE_INSUFFICIENT);
        };
        let Some(asserted_rank) = assurance_rank(asserted_assurance) else {
            return deny(audit, ASSURANCE_INSUFFICIENT);
        };
        if asserted_rank < minimum_rank {
            return deny(audit, ASSURANCE_INSUFFICIENT);
        }
    }
    if let Some(max_age) = policy.max_source_age_seconds {
        let Some(observed_age) = context.source_observed_age_seconds else {
            return deny(audit, EVIDENCE_STALE);
        };
        if observed_age > max_age {
            return deny(audit, EVIDENCE_STALE);
        }
    }
    if policy.require_legal_basis && is_blank(context.legal_basis_ref.as_deref()) {
        return deny(audit, LEGAL_BASIS_REQUIRED);
    }
    if policy.require_consent && is_blank(context.consent_ref.as_deref()) {
        return deny(audit, CONSENT_REQUIRED);
    }
    if policy.redaction_fields.is_empty() {
        Decision::Permit(audit)
    } else {
        Decision::PermitWithRedaction {
            audit,
            field_set: policy.redaction_fields.clone(),
            max_age_seconds: policy.max_source_age_seconds,
        }
    }
}

fn deny(audit: DecisionAudit, stable_problem_code: &str) -> Decision {
    Decision::Deny {
        audit,
        stable_problem_code: stable_problem_code.to_string(),
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn assurance_rank(level: &str) -> Option<u8> {
    let compact = normalized_assurance(level);
    match compact.as_str() {
        "low" | "ial1" | "loa1" => Some(1),
        "substantial" | "ial2" | "loa2" => Some(2),
        "high" | "ial3" | "loa3" => Some(3),
        _ => None,
    }
}

fn normalized_assurance(level: &str) -> String {
    level
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> EvidenceRequestContext {
        EvidenceRequestContext {
            purpose: "benefits".to_string(),
            legal_basis_ref: Some("law:benefits-act".to_string()),
            consent_ref: Some("consent:123".to_string()),
            asserted_assurance: Some("substantial".to_string()),
            jurisdiction: Some("RW".to_string()),
            source_observed_age_seconds: Some(30),
        }
    }

    fn policy() -> PolicyInput {
        PolicyInput {
            policy_id: "policy-1".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            rule_ids: vec!["rule-purpose".to_string()],
            purpose_constraints: vec![
                vec!["benefits".to_string(), "research".to_string()],
                vec!["benefits".to_string()],
            ],
            permitted_jurisdictions: vec!["RW".to_string()],
            allowed_assurance: Vec::new(),
            minimum_assurance: Some("substantial".to_string()),
            max_source_age_seconds: Some(60),
            require_legal_basis: true,
            require_consent: true,
            redaction_fields: BTreeSet::new(),
            unsupported_odrl_terms: Vec::new(),
        }
    }

    fn deny_code(decision: Decision) -> Option<String> {
        match decision {
            Decision::Deny {
                stable_problem_code,
                ..
            } => Some(stable_problem_code),
            _ => None,
        }
    }

    #[test]
    fn permits_when_purpose_is_in_intersection() {
        let decision = decide(&context(), &policy());
        assert!(matches!(decision, Decision::Permit(_)));
    }

    #[test]
    fn denies_when_purpose_is_not_in_intersection() {
        let mut context = context();
        context.purpose = "research".to_string();

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn denies_when_assurance_is_insufficient() {
        let mut context = context();
        context.asserted_assurance = Some("low".to_string());

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );
    }

    #[test]
    fn minimum_assurance_accepts_standard_separator_bearing_labels() {
        let mut policy = policy();
        policy.minimum_assurance = Some("IAL-2".to_string());
        let mut context = context();
        context.asserted_assurance = Some("LOA 2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));

        policy.minimum_assurance = Some("LOA 2".to_string());
        context.asserted_assurance = Some("loa-1".to_string());
        assert_eq!(
            deny_code(decide(&context, &policy)),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );
    }

    #[test]
    fn nonstandard_substantial_low_minimum_fails_closed() {
        let mut policy = policy();
        policy.minimum_assurance = Some("substantial-low".to_string());

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn denies_when_assurance_is_not_in_allowed_set() {
        let mut policy = policy();
        policy.allowed_assurance = vec!["urn:example:loa:high".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );

        policy.allowed_assurance = vec!["Substantial".to_string()];
        assert!(matches!(decide(&context(), &policy), Decision::Permit(_)));
    }

    #[test]
    fn allowed_assurance_accepts_standard_separator_bearing_labels() {
        let mut policy = policy();
        policy.minimum_assurance = None;
        policy.allowed_assurance = vec!["IAL2".to_string()];

        let mut context = context();
        context.asserted_assurance = Some("IAL-2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));

        policy.allowed_assurance = vec!["LOA 2".to_string()];
        context.asserted_assurance = Some("loa_2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));
    }

    #[test]
    fn unknown_assurance_levels_fail_closed() {
        let mut unknown_asserted = context();
        unknown_asserted.asserted_assurance = Some("pilot".to_string());
        assert_eq!(
            deny_code(decide(&unknown_asserted, &policy())),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );

        let mut unknown_minimum = policy();
        unknown_minimum.minimum_assurance = Some("pilot".to_string());
        assert_eq!(
            deny_code(decide(&context(), &unknown_minimum)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn denies_stale_source_observation() {
        let mut context = context();
        context.source_observed_age_seconds = Some(61);

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(EVIDENCE_STALE.to_string())
        );
    }

    #[test]
    fn denies_missing_legal_basis_or_consent() {
        let mut no_legal_basis = context();
        no_legal_basis.legal_basis_ref = None;
        assert_eq!(
            deny_code(decide(&no_legal_basis, &policy())),
            Some(LEGAL_BASIS_REQUIRED.to_string())
        );

        let mut no_consent = context();
        no_consent.consent_ref = None;
        assert_eq!(
            deny_code(decide(&no_consent, &policy())),
            Some(CONSENT_REQUIRED.to_string())
        );
    }

    #[test]
    fn denies_disallowed_jurisdiction() {
        let mut context = context();
        context.jurisdiction = Some("FR".to_string());

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(JURISDICTION_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn unsupported_odrl_terms_fail_closed() {
        let mut policy = policy();
        policy.unsupported_odrl_terms = vec!["odrl:unknownOperand".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn denies_blank_or_malformed_policy_identity() {
        let mut blank_id = policy();
        blank_id.policy_id = " ".to_string();
        assert_eq!(
            deny_code(decide(&context(), &blank_id)),
            Some(POLICY_ID_REQUIRED.to_string())
        );

        let mut bad_hash = policy();
        bad_hash.policy_hash = "sha256:not-a-digest".to_string();
        assert_eq!(
            deny_code(decide(&context(), &bad_hash)),
            Some(POLICY_HASH_INVALID.to_string())
        );

        let mut uppercase_hash = policy();
        uppercase_hash.policy_hash =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_eq!(
            deny_code(decide(&context(), &uppercase_hash)),
            Some(POLICY_HASH_INVALID.to_string())
        );
    }

    #[test]
    fn permits_with_redaction_when_policy_has_field_set() {
        let mut policy = policy();
        policy
            .redaction_fields
            .insert("target.birthdate".to_string());

        match decide(&context(), &policy) {
            Decision::PermitWithRedaction { field_set, .. } => {
                assert!(field_set.contains("target.birthdate"));
            }
            other => panic!("expected PermitWithRedaction, got {other:?}"),
        }
    }
}
