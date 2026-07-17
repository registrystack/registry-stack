// SPDX-License-Identifier: Apache-2.0
//! Evaluations API tests.

use super::*;

#[derive(Debug)]
struct AmbiguousApiRelay {
    calls: std::sync::atomic::AtomicU64,
}

#[derive(Debug)]
struct MatchingApiRelay {
    calls: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl crate::runtime::ActivatedRelayConsultations for MatchingApiRelay {
    async fn check_ready(&self) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    fn validate(
        &self,
        _key: &crate::runtime::consultation::ConsultationGroupKeyV1,
    ) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    async fn execute(
        &self,
        _key: &crate::runtime::consultation::ConsultationGroupKeyV1,
    ) -> Result<
        crate::runtime::consultation::RuntimeRelayConsultationResult,
        crate::relay_client::RelayClientError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let outputs = crate::runtime::consultation::RuntimeRelayOutputMap::from_json(
            BTreeMap::from([("registration_status".to_string(), json!("ACTIVE"))]),
        )?;
        crate::runtime::consultation::RuntimeRelayConsultationResult::new(
            ulid::Ulid::from_parts(3, 1),
            crate::runtime::consultation::RuntimeRelayOutcome::Match,
            Some(crate::runtime::consultation::RuntimeRelayMatchData::OutputMap(outputs)),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

fn registry_backed_api_evidence() -> EvidenceConfig {
    let mut evidence = evidence_config();
    evidence.allowed_purposes = vec!["test".to_string()];
    let claim = evidence.claims.first_mut().expect("claim exists");
    claim.evidence_mode = registry_notary_core::ClaimEvidenceMode::RegistryBacked {
        consultations: BTreeMap::from([(
            "enrollment".to_string(),
            registry_notary_core::RelayConsultationConfig {
                profile: registry_notary_core::RelayConsultationProfileRef {
                    id: "example.enrollment-status.exact".to_string(),
                    contract_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                },
                inputs: BTreeMap::from([(
                    "tracked_entity".to_string(),
                    registry_notary_core::RelayConsultationInput::TargetId,
                )]),
                outputs: BTreeMap::from([(
                    "registration_status".to_string(),
                    registry_notary_core::RelayOutputContract::String {
                        nullable: true,
                        max_bytes: 64,
                    },
                )]),
            },
        )]),
    };
    claim.purpose = Some("test".to_string());
    claim.required_scopes = vec!["registry:evidence".to_string()];
    claim.value.value_type = "string".to_string();
    claim.value.nullable = true;
    claim.rule = registry_notary_core::RuleConfig::ConsultationOutput {
        consultation: "enrollment".to_string(),
        output: "registration_status".to_string(),
    };
    evidence
}

#[async_trait::async_trait]
impl crate::runtime::ActivatedRelayConsultations for AmbiguousApiRelay {
    async fn check_ready(&self) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    fn validate(
        &self,
        _key: &crate::runtime::consultation::ConsultationGroupKeyV1,
    ) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    async fn execute(
        &self,
        _key: &crate::runtime::consultation::ConsultationGroupKeyV1,
    ) -> Result<
        crate::runtime::consultation::RuntimeRelayConsultationResult,
        crate::relay_client::RelayClientError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::runtime::consultation::RuntimeRelayConsultationResult::new(
            ulid::Ulid::from_parts(2, 1),
            crate::runtime::consultation::RuntimeRelayOutcome::Ambiguous,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[tokio::test]
async fn ambiguous_relay_response_keeps_ids_only_in_restricted_audit_context() {
    let evidence = registry_backed_api_evidence();
    let state = Arc::new(RegistryNotaryApiState::new(
        Arc::new(evidence),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    ));
    let relay = Arc::new(AmbiguousApiRelay {
        calls: std::sync::atomic::AtomicU64::new(0),
    });
    state
        .install_activated_relay(relay.clone())
        .expect("test Relay activates once");
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "machine".to_string(),
        scopes: vec![
            "registry:evidence".to_string(),
            "person-is-alive:1".to_string(),
        ],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };
    let mut request = evaluate_request("subject-1");
    request.target = Some(EvidenceEntity::from_subject_request(
        "Person",
        SubjectRequest {
            id: "subject-1".to_string(),
            id_type: None,
        },
    ));
    request.purpose = Some("test".to_string());

    let response = evaluate(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        None,
        Ok(Json(request)),
    )
    .await;

    assert!(!response.status().is_success());
    assert_eq!(
        response
            .extensions()
            .get::<EvidenceErrorCodeContext>()
            .expect("problem code context is attached")
            .0,
        "evidence.not_available"
    );
    assert_eq!(relay.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("denial audit context is attached");
    let evaluation_id = audit
        .verification_id
        .clone()
        .expect("post-preflight evaluation id is restricted-audited");
    assert!(ulid::Ulid::from_string(&evaluation_id).is_ok());
    let consultation_id = ulid::Ulid::from_parts(2, 1).to_string();
    assert_eq!(audit.relay_consultation_ids, vec![consultation_id.clone()]);
    assert_eq!(audit.relay_consultation_count, Some(1));
    assert_eq!(audit.forwarded, Some(true));
    let audit_debug = format!("{audit:?}");
    assert!(!audit_debug.contains(&evaluation_id));
    assert!(!audit_debug.contains(&consultation_id));

    let public_body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("public problem body reads");
    let public_body = String::from_utf8(public_body.to_vec()).expect("problem body is UTF-8");
    assert!(!public_body.contains(&evaluation_id));
    assert!(!public_body.contains(&consultation_id));
}

#[tokio::test]
async fn machine_quota_is_atomic_at_the_handler_boundary_and_isolated_by_principal() {
    let mut evidence = registry_backed_api_evidence();
    evidence.machine_quota = registry_notary_core::MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 1,
    };
    let state = Arc::new(RegistryNotaryApiState::new(
        Arc::new(evidence),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    ));
    let relay = Arc::new(MatchingApiRelay {
        calls: std::sync::atomic::AtomicU64::new(0),
    });
    state
        .install_activated_relay(relay.clone())
        .expect("test Relay activates once");

    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "machine-a".to_string(),
        scopes: vec!["registry:evidence".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };
    let request = || {
        let mut request = evaluate_request("subject-1");
        request.target = Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "subject-1".to_string(),
                id_type: None,
            },
        ));
        request.purpose = Some("test".to_string());
        request
    };
    let invoke = || {
        evaluate(
            HeaderMap::new(),
            Some(Extension(Arc::clone(&state))),
            Some(Extension(principal.clone())),
            None,
            Ok(Json(request())),
        )
    };
    let (first, second) = tokio::join!(invoke(), invoke());
    let statuses = [first.status(), second.status()];
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        1
    );
    assert_eq!(relay.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let other_principal = EvidencePrincipal {
        principal_id: "machine-b".to_string(),
        ..principal
    };
    let response = evaluate(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(other_principal)),
        None,
        Ok(Json(request())),
    )
    .await;
    assert!(response.status().is_success());
    assert_eq!(relay.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

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
    older_claim.required_scopes = vec!["person-is-alive:1.0".to_string()];
    let mut newer_claim = older_claim.clone();
    newer_claim.version = "2.0".to_string();
    newer_claim.required_scopes = vec!["person-is-alive:2.0".to_string()];
    evidence.claims = vec![older_claim, newer_claim];
    let evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: vec![ClaimRef::with_version("person-is-alive", "2.0")],
        disclosure: "predicate".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: Vec::new(),
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        issuance_provenance: None,
        subject_access: None,
    };
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "caseworker".to_string(),
        scopes: vec!["person-is-alive:1.0".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };

    let err = require_evaluation_access(&evidence, &principal, &evaluation)
        .expect_err("version 1 scope must not authorize stored version 2 evaluation");
    assert!(matches!(
        err,
        EvidenceError::ScopeDenied { required } if required == "person-is-alive:2.0"
    ));

    let principal = EvidencePrincipal {
        scopes: vec!["person-is-alive:2.0".to_string()],
        ..principal
    };
    require_evaluation_access(&evidence, &principal, &evaluation)
        .expect("version 2 scope authorizes stored version 2 evaluation");
}
