// SPDX-License-Identifier: Apache-2.0
//! Credentials API tests.

use super::*;
use async_trait::async_trait;
use registry_platform_cache::{
    CacheCompareAndSetOutcome, CacheKey, CacheSetOutcome, CacheStore, CacheStoreError,
};

struct UnavailableCredentialStatusStore;

fn unavailable_status_error() -> CacheStoreError {
    CacheStoreError::Operation {
        message: "test store unavailable".to_string(),
    }
}

#[async_trait]
impl CacheStore for UnavailableCredentialStatusStore {
    async fn get(&self, _key: &CacheKey) -> Result<Option<Vec<u8>>, CacheStoreError> {
        Err(unavailable_status_error())
    }

    async fn set(
        &self,
        _key: &CacheKey,
        _value: &[u8],
        _expires_at: OffsetDateTime,
    ) -> Result<(), CacheStoreError> {
        Err(unavailable_status_error())
    }

    async fn set_if_absent(
        &self,
        _key: &CacheKey,
        _value: &[u8],
        _expires_at: OffsetDateTime,
    ) -> Result<CacheSetOutcome, CacheStoreError> {
        Err(unavailable_status_error())
    }

    async fn compare_and_set(
        &self,
        _key: &CacheKey,
        _expected: &[u8],
        _value: &[u8],
        _expires_at: OffsetDateTime,
    ) -> Result<CacheCompareAndSetOutcome, CacheStoreError> {
        Err(unavailable_status_error())
    }

    async fn delete(&self, _key: &CacheKey) -> Result<bool, CacheStoreError> {
        Err(unavailable_status_error())
    }

    async fn check_ready(&self) -> Result<(), CacheStoreError> {
        Err(unavailable_status_error())
    }
}

#[tokio::test]
async fn registry_backed_evaluation_with_exact_provenance_issues_directly() {
    let evidence = credential_issue_evidence_with_dependency();
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    let evaluation_id = "eval-registry-direct";
    let mut result = claim_result_view(evaluation_id, "person-is-alive");
    result.provenance.used.relay_consultation_count = 2;
    let mut evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: vec![result],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        issuance_provenance: Some(issuance_provenance_with_dependency(
            "person-is-alive",
            "civil-record-active",
            "test",
            evaluation_id,
        )),
        subject_access: None,
    };
    store
        .insert(evaluation.clone())
        .await
        .expect("registry-backed evaluation inserts");
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
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

    let request = CredentialIssueRequest {
        evaluation_id: evaluation_id.to_string(),
        credential_profile: Some("civil_status_sd_jwt".to_string()),
        format: Some(FORMAT_SD_JWT_VC.to_string()),
        claims: Some(vec!["person-is-alive".to_string()]),
        disclosure: Some("predicate".to_string()),
        purpose: Some("test".to_string()),
        holder: Some(HolderRequest {
            binding: Some("did".to_string()),
            id: Some(holder_did_jwk()),
            proof: None,
        }),
    };
    let response = issue_credential(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal.clone())),
        Ok(Json(request.clone())),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("credential body reads");
    let body: Value = serde_json::from_slice(&body).expect("credential response parses");
    assert_eq!(body["credential_profile"], "civil_status_sd_jwt");
    assert!(body["credential"]
        .as_str()
        .is_some_and(|credential| credential.contains('~')));
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);

    evaluation
        .issuance_provenance
        .as_mut()
        .expect("private closure exists")
        .claims
        .retain(|claim| claim.claim_id != "civil-record-active");
    store
        .insert(evaluation.clone())
        .await
        .expect("missing dependency fixture inserts");
    let missing = issue_credential(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal.clone())),
        Ok(Json(request.clone())),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);

    evaluation.issuance_provenance = Some(issuance_provenance_with_dependency(
        "person-is-alive",
        "civil-record-active",
        "test",
        evaluation_id,
    ));
    evaluation
        .issuance_provenance
        .as_mut()
        .expect("private closure exists")
        .consultations
        .push(registry_notary_core::StoredIssuanceConsultationProvenance {
            consultation_id: "01J00000000000000000000002".to_string(),
            acquired_at: "2026-05-23T00:00:00Z".to_string(),
        });
    store
        .insert(evaluation)
        .await
        .expect("extra dependency execution fixture inserts");
    let extra = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(request)),
    )
    .await;
    assert_eq!(extra.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn direct_dependency_execution_tampering_is_denied_before_signing() {
    let evidence = credential_issue_evidence_with_dependency();
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    let evaluation_id = "eval-registry-direct-tamper";
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
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
    let request = CredentialIssueRequest {
        evaluation_id: evaluation_id.to_string(),
        credential_profile: Some("civil_status_sd_jwt".to_string()),
        format: Some(FORMAT_SD_JWT_VC.to_string()),
        claims: Some(vec!["person-is-alive".to_string()]),
        disclosure: Some("predicate".to_string()),
        purpose: Some("test".to_string()),
        holder: Some(HolderRequest {
            binding: Some("did".to_string()),
            id: Some(holder_did_jwk()),
            proof: None,
        }),
    };
    let mut result = claim_result_view(evaluation_id, "person-is-alive");
    result.provenance.used.relay_consultation_count = 2;
    let baseline = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: vec![result],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        issuance_provenance: Some(issuance_provenance_with_dependency(
            "person-is-alive",
            "civil-record-active",
            "test",
            evaluation_id,
        )),
        subject_access: None,
    };

    let mut acquired_at_tampered = baseline.clone();
    acquired_at_tampered
        .issuance_provenance
        .as_mut()
        .expect("private closure exists")
        .consultations[1]
        .acquired_at = "2026-05-23T00:00:01Z".to_string();
    store
        .insert(acquired_at_tampered)
        .await
        .expect("acquired-at tamper fixture inserts");
    let acquired_at_denial = issue_credential(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal.clone())),
        Ok(Json(request.clone())),
    )
    .await;
    assert_eq!(acquired_at_denial.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);

    let mut ids_swapped = baseline;
    let claims = &mut ids_swapped
        .issuance_provenance
        .as_mut()
        .expect("private closure exists")
        .claims;
    let dependency_id = claims[0].consultation_id.clone();
    claims[0].consultation_id = claims[1].consultation_id.clone();
    claims[1].consultation_id = dependency_id;
    store
        .insert(ids_swapped)
        .await
        .expect("execution-id swap fixture inserts");
    let swapped_denial = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(request)),
    )
    .await;
    assert_eq!(swapped_denial.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegated_evaluation_cannot_issue_directly_even_with_registry_provenance() {
    let evidence = Arc::new(registry_backed_oid4vci_evidence_with_dependency());
    let subject_access = Arc::new(subject_access_config());
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
            None,
        )
        .expect("state builds"),
    );
    let mut principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    let classified = classify_subject_access_principal(&subject_access, &principal)
        .expect("subject-access principal classifies");
    let mut context = prepare_subject_access_evaluate(
        &state,
        &evidence,
        &classified,
        &evaluate_request("NAT-123"),
    )
    .expect("subject-access metadata prepares");
    context.metadata.access_mode = AccessMode::DelegatedAttestation;
    principal.authorization_details = Some(registry_notary_core::EvidenceAuthorizationDetails {
        access_mode: Some(AccessMode::DelegatedAttestation),
        ..Default::default()
    });
    let evaluation_id = "eval-delegated-direct-retired";
    let mut result = claim_result_view(evaluation_id, "person-is-alive");
    result.provenance.used.relay_consultation_count = 2;
    store
        .insert(registry_notary_core::StoredEvaluation {
            client_id: context.metadata.principal_hash.as_str().to_string(),
            purpose: "citizen_subject_access".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            claim_refs: Vec::new(),
            disclosure: "predicate".to_string(),
            format: FORMAT_CLAIM_RESULT_JSON.to_string(),
            results: vec![result],
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            issuance_provenance: Some(issuance_provenance_with_dependency(
                "person-is-alive",
                "civil-record-active",
                "citizen_subject_access",
                evaluation_id,
            )),
            subject_access: Some(context.metadata),
        })
        .await
        .expect("delegated evaluation fixture inserts");

    let response = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(CredentialIssueRequest {
            evaluation_id: evaluation_id.to_string(),
            credential_profile: Some("civil_status_sd_jwt".to_string()),
            format: Some(FORMAT_SD_JWT_VC.to_string()),
            claims: Some(vec!["person-is-alive".to_string()]),
            disclosure: Some("predicate".to_string()),
            purpose: Some("citizen_subject_access".to_string()),
            holder: Some(HolderRequest {
                binding: Some("did".to_string()),
                id: Some(holder_did_jwk()),
                proof: None,
            }),
        })),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_credential_fails_closed_when_status_record_write_fails() {
    let evidence = credential_issue_evidence_config();
    let store = Arc::new(EvidenceStore::default());
    store
        .insert(registry_notary_core::StoredEvaluation {
            client_id: "caseworker".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            claim_refs: Vec::new(),
            disclosure: "predicate".to_string(),
            format: FORMAT_CLAIM_RESULT_JSON.to_string(),
            results: vec![claim_result_view(
                "eval-status-write-fails",
                "person-is-alive",
            )],
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            issuance_provenance: Some(issuance_provenance(
                "person-is-alive",
                "test",
                "eval-status-write-fails",
            )),
            subject_access: None,
        })
        .await
        .expect("evaluation inserts");
    let credential_status = CredentialStatusStore::with_test_store(
        &CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            retention_seconds: 60,
        },
        Arc::new(UnavailableCredentialStatusStore),
    );
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            credential_status,
            Arc::new(AppMetrics::default()),
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
    store
        .insert(registry_notary_core::StoredEvaluation {
            client_id: "caseworker".to_string(),
            purpose: "benefits".to_string(),
            claim_ids: vec!["person-is-alive".to_string()],
            claim_refs: Vec::new(),
            disclosure: "predicate".to_string(),
            format: FORMAT_CLAIM_RESULT_JSON.to_string(),
            results: vec![claim_result_view(
                "eval-purpose-mismatch",
                "person-is-alive",
            )],
            created_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
            request_hash: "request-hash".to_string(),
            issuance_provenance: Some(issuance_provenance(
                "person-is-alive",
                "benefits",
                "eval-purpose-mismatch",
            )),
            subject_access: None,
        })
        .await
        .expect("evaluation inserts");
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
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

#[tokio::test]
async fn issuance_provenance_denial_precedes_signer_status_and_holder_replay() {
    let mut evidence = credential_issue_evidence_config();
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .holder_binding = holder_required_profile().holder_binding;
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    let evaluation_id = "eval-provenance-denied";
    let mut evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: vec![claim_result_view(evaluation_id, "person-is-alive")],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        issuance_provenance: None,
        subject_access: None,
    };
    store
        .insert(evaluation.clone())
        .await
        .expect("legacy evaluation inserts");
    let credential_status = CredentialStatusStore::with_test_store(
        &CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            retention_seconds: 60,
        },
        Arc::new(UnavailableCredentialStatusStore),
    );
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            credential_status,
            Arc::new(AppMetrics::default()),
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
    let holder_id = holder_did_jwk();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let proof = sign_holder_proof(
        &holder_id,
        json!({
            "sub": holder_id,
            "aud": "registry-notary",
            "iat": now,
            "exp": now + 60,
            "jti": "provenance-denial-proof",
            "evaluation_id": evaluation_id,
            "credential_profile": "civil_status_sd_jwt",
            "disclosure": holder_proof_disclosure("predicate"),
            "claims": ["person-is-alive"],
        }),
    );
    let request = CredentialIssueRequest {
        evaluation_id: evaluation_id.to_string(),
        credential_profile: Some("civil_status_sd_jwt".to_string()),
        format: Some(FORMAT_SD_JWT_VC.to_string()),
        claims: Some(vec!["person-is-alive".to_string()]),
        disclosure: Some("predicate".to_string()),
        purpose: Some("test".to_string()),
        holder: Some(HolderRequest {
            binding: Some("did".to_string()),
            id: Some(holder_id),
            proof: Some(proof),
        }),
    };

    let denied = issue_credential(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal.clone())),
        Ok(Json(request.clone())),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);

    evaluation.issuance_provenance = Some(issuance_provenance(
        "person-is-alive",
        "test",
        evaluation_id,
    ));
    store
        .insert(evaluation)
        .await
        .expect("re-evaluated record replaces legacy test record");
    let after_reevaluation = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(request)),
    )
    .await;
    assert_eq!(
        after_reevaluation.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "the same holder proof reaches status persistence after re-evaluation, so the denial did not consume replay state"
    );
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
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
