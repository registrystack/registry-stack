// SPDX-License-Identifier: Apache-2.0
//! Evaluations API tests.

use super::*;

#[test]
fn pdp_policy_denials_keep_public_stable_problem_codes() {
    let error = EvidenceError::PolicyDenied {
        code: "pdp.assurance_insufficient",
        policy_id: None,
        policy_hash: None,
        evaluated_rule_ids: Vec::new(),
    };

    assert_eq!(error.code(), "pdp.assurance_insufficient");
    assert_eq!(error.audit_code(), "pdp.assurance_insufficient");
    assert_eq!(evidence_status(&error), StatusCode::FORBIDDEN);
    assert_eq!(evidence_title(&error), "Policy decision denied");
    assert_eq!(
        evidence_detail(&error),
        "the configured policy denied the evidence request"
    );
}

#[test]
fn evaluation_access_uses_stored_claim_version_scope() {
    let mut evidence = evidence_config();
    let mut older_claim = evidence.claims[0].clone();
    older_claim.version = "1.0".to_string();
    let mut newer_claim = older_claim.clone();
    newer_claim.version = "2.0".to_string();
    evidence.claims = vec![older_claim, newer_claim];
    let evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: vec![ClaimRef::with_version("person-is-alive", "2.0")],
        disclosure: "predicate".to_string(),
        format: FORMAT_SD_JWT_VC.to_string(),
        results: Vec::new(),
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        self_attestation: None,
    };
    let source = VersionScopedSource;
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "caseworker".to_string(),
        scopes: vec!["person-is-alive:1.0".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };

    let err = require_evaluation_access(&evidence, &source, &principal, &evaluation)
        .expect_err("version 1 scope must not authorize stored version 2 evaluation");
    assert!(matches!(
        err,
        EvidenceError::ScopeDenied { required } if required == "person-is-alive:2.0"
    ));

    let principal = EvidencePrincipal {
        scopes: vec!["person-is-alive:2.0".to_string()],
        ..principal
    };
    require_evaluation_access(&evidence, &source, &principal, &evaluation)
        .expect("version 2 scope authorizes stored version 2 evaluation");
}
