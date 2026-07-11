// SPDX-License-Identifier: Apache-2.0
//! Credentials API tests.

use super::*;

#[tokio::test]
async fn issue_credential_fails_closed_when_status_record_write_fails() {
    std::env::set_var(
        "TEST_CREDENTIAL_STATUS_UNREACHABLE_REDIS_URL",
        "redis://127.0.0.1:1",
    );
    let evidence = credential_issue_evidence_config();
    let store = Arc::new(EvidenceStore::default());
    store.insert(registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_SD_JWT_VC.to_string(),
        results: vec![claim_result_view(
            "eval-status-write-fails",
            "person-is-alive",
        )],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        self_attestation: None,
    });
    let credential_status = CredentialStatusStore::from_config(&CredentialStatusConfig {
        enabled: true,
        base_url: "https://issuer.example".to_string(),
        storage: CREDENTIAL_STATUS_STORAGE_REDIS.to_string(),
        retention_seconds: 60,
        redis: CredentialStatusRedisConfig {
            url_env: "TEST_CREDENTIAL_STATUS_UNREACHABLE_REDIS_URL".to_string(),
            key_prefix: "registry-notary-status-fail-test".to_string(),
            connect_timeout_ms: 10,
            operation_timeout_ms: 10,
        },
    })
    .expect("status store builds without connecting");
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SelfAttestationConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            credential_status,
            Arc::new(AppMetrics::default()),
            Arc::new(CountingSource::default()),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
            None,
        )
        .expect("state builds"),
    );
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "caseworker".to_string(),
        scopes: vec!["civil_registry:evidence_verification".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };

    let response = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(CredentialIssueRequest {
            evaluation_id: "eval-status-write-fails".to_string(),
            credential_profile: Some("civil_status_sd_jwt".to_string()),
            format: Some(FORMAT_SD_JWT_VC.to_string()),
            claims: Some(vec!["person-is-alive".to_string()]),
            disclosure: Some("predicate".to_string()),
            purpose: None,
            holder: Some(HolderRequest {
                binding: Some("did".to_string()),
                id: Some(holder_did_jwk()),
                proof: None,
            }),
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("problem body parses");
    assert_eq!(body["code"], json!("credential.issuance_failed"));
}

#[tokio::test]
async fn issue_credential_rejects_purpose_mismatch() {
    let evidence = credential_issue_evidence_config();
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    store.insert(registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "benefits".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_SD_JWT_VC.to_string(),
        results: vec![claim_result_view(
            "eval-purpose-mismatch",
            "person-is-alive",
        )],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        self_attestation: None,
    });
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SelfAttestationConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            Arc::new(CountingSource::default()),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
            None,
        )
        .expect("state builds"),
    );
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "caseworker".to_string(),
        scopes: vec!["civil_registry:evidence_verification".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };

    let response = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(CredentialIssueRequest {
            evaluation_id: "eval-purpose-mismatch".to_string(),
            credential_profile: Some("civil_status_sd_jwt".to_string()),
            format: Some(FORMAT_SD_JWT_VC.to_string()),
            claims: Some(vec!["person-is-alive".to_string()]),
            disclosure: Some("predicate".to_string()),
            purpose: Some("appeals".to_string()),
            holder: None,
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("problem body parses");
    assert_eq!(body["code"], json!("evaluation.binding_mismatch"));
    assert_eq!(
        sign_count.load(Ordering::SeqCst),
        0,
        "purpose mismatch must be denied before credential signing"
    );
}

#[test]
fn strict_credential_issue_rejects_oid4vci_proof_shape() {
    let holder_id = holder_did_jwk();
    let proof = sign_oid4vci_proof("registry-notary", "nonce-1");
    let request = issue_request();
    let evaluation = evaluation_for_proof();
    let holder = HolderRequest {
        binding: Some("did".to_string()),
        id: Some(holder_id),
        proof: Some(proof),
    };

    let err = validate_holder_request(
        &holder_required_profile(),
        "profile-a",
        &request,
        &evaluation,
        Some(&holder),
        "registry-notary",
    )
    .expect_err("OID4VCI proof must not relax the strict credential endpoint proof");

    assert!(matches!(err, EvidenceError::HolderProofRequired));
}
