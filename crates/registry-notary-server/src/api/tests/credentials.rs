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

fn structured_direct_credential_evidence() -> EvidenceConfig {
    let mut evidence = credential_issue_evidence_config();
    let claim = evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "person-is-alive")
        .expect("credential claim exists");
    claim.value = registry_notary_core::ClaimValueConfig {
        value_type: "object".to_string(),
        nullable: true,
        max_bytes: None,
        unit: None,
    };
    claim.disclosure.default = "value".to_string();
    claim.disclosure.allowed = vec!["value".to_string()];
    claim.disclosure.downgrade = "deny".to_string();
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("credential claim is registry backed");
    };
    let consultation = consultations
        .get_mut("person_status")
        .expect("credential consultation exists");
    consultation.outputs = BTreeMap::from([(
        "record".to_string(),
        registry_notary_core::RelayOutputContract::Object {
            nullable: false,
            max_bytes: 4_096,
            fields: BTreeMap::from([
                (
                    "name".to_string(),
                    registry_notary_core::RelayOutputObjectFieldContract {
                        required: true,
                        schema: Box::new(registry_notary_core::RelayOutputContract::String {
                            nullable: false,
                            max_bytes: 128,
                        }),
                    },
                ),
                (
                    "parents".to_string(),
                    registry_notary_core::RelayOutputObjectFieldContract {
                        required: true,
                        schema: Box::new(registry_notary_core::RelayOutputContract::Array {
                            nullable: false,
                            max_bytes: 2_048,
                            max_items: 4,
                            items: Box::new(registry_notary_core::RelayOutputContract::Object {
                                nullable: false,
                                max_bytes: 512,
                                fields: BTreeMap::from([
                                    (
                                        "identifier".to_string(),
                                        registry_notary_core::RelayOutputObjectFieldContract {
                                            required: true,
                                            schema: Box::new(
                                                registry_notary_core::RelayOutputContract::String {
                                                    nullable: false,
                                                    max_bytes: 64,
                                                },
                                            ),
                                        },
                                    ),
                                    (
                                        "name".to_string(),
                                        registry_notary_core::RelayOutputObjectFieldContract {
                                            required: true,
                                            schema: Box::new(
                                                registry_notary_core::RelayOutputContract::String {
                                                    nullable: false,
                                                    max_bytes: 128,
                                                },
                                            ),
                                        },
                                    ),
                                ]),
                            }),
                        }),
                    },
                ),
            ]),
        },
    )]);
    claim.rule = RuleConfig::ConsultationOutput {
        consultation: "person_status".to_string(),
        output: "record".to_string(),
    };
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .disclosure
        .allowed = vec!["value".to_string()];
    evidence
}

fn bind_exact_stored_result(evaluation: &mut registry_notary_core::StoredEvaluation) {
    let result_content_binding =
        crate::runtime::issuance_result_content_binding(&evaluation.results[0])
            .expect("structured result content binding hashes");
    let issuance = evaluation
        .issuance_provenance
        .as_mut()
        .expect("private issuance provenance exists");
    let claim = issuance
        .claims
        .iter_mut()
        .find(|claim| claim.claim_id == evaluation.results[0].claim_id)
        .expect("selected claim provenance exists");
    claim.result_content_binding = result_content_binding;
    let consultation = issuance
        .consultations
        .iter()
        .find(|consultation| consultation.consultation_id == claim.consultation_id)
        .expect("selected consultation provenance exists");
    claim.execution_binding = crate::runtime::issuance_execution_binding(
        claim,
        consultation,
        &evaluation.results[0].evaluation_id,
        &evaluation.results[0].issued_at,
        &evaluation.results[0].provenance,
    )
    .expect("structured execution binding hashes");
}

#[tokio::test]
async fn structured_result_issues_as_one_verifiable_direct_sd_jwt_disclosure() {
    let evidence = Arc::new(structured_direct_credential_evidence());
    let store = Arc::new(EvidenceStore::default());
    let sign_count = Arc::new(AtomicUsize::new(0));
    let evaluation_id = "eval-structured-direct";
    let structured_value = json!({
        "name": "Ada",
        "parents": [
            { "identifier": "PARENT-2", "name": "Grace" },
            { "identifier": "PARENT-1", "name": "Charles" }
        ]
    });
    let mut result = claim_result_view(evaluation_id, "person-is-alive");
    result.value = Some(structured_value.clone());
    result.satisfied = None;
    result.disclosure = "value".to_string();
    let mut evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "value".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: vec![result],
        created_at: "2026-05-23T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        request_hash: "request-hash".to_string(),
        issuance_provenance: Some(issuance_provenance(
            "person-is-alive",
            "test",
            evaluation_id,
        )),
        subject_access: None,
    };
    bind_exact_stored_result(&mut evaluation);
    store
        .insert(evaluation.clone())
        .await
        .expect("structured evaluation inserts");
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::clone(&evidence),
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
        disclosure: Some("value".to_string()),
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
    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("credential response carries value-free audit context");
    let audit_debug = format!("{audit:?}");
    for secret in ["Ada", "Grace", "Charles", "PARENT-1", "PARENT-2"] {
        assert!(
            !audit_debug.contains(secret),
            "credential audit Debug must not expose {secret}"
        );
    }
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("credential body reads");
    let body: Value = serde_json::from_slice(&body).expect("credential response parses");
    let disclosures = body["disclosures"]
        .as_array()
        .expect("response disclosures are an array");
    assert_eq!(
        disclosures.len(),
        1,
        "the complete structured claim is one top-level disclosure unit"
    );
    let encoded_disclosure = disclosures[0]
        .as_str()
        .expect("encoded disclosure is a string");
    let decoded_disclosure: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_disclosure)
            .expect("disclosure is base64url"),
    )
    .expect("disclosure is JSON");
    assert_eq!(decoded_disclosure[1], json!("person-is-alive"));
    assert_eq!(decoded_disclosure[2]["value"], structured_value);

    let issuer_signed_jwt = body["issuer_signed_jwt"]
        .as_str()
        .expect("issuer-signed JWT exists");
    let payload = decode_jwt_payload(issuer_signed_jwt);
    let disclosure_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded_disclosure.as_bytes()));
    assert!(
        payload["_sd"]
            .as_array()
            .is_some_and(|digests| digests.contains(&json!(disclosure_digest))),
        "the disclosed recursive value verifies against the issuer-signed _sd digest"
    );
    let withheld_presentation = format!("{issuer_signed_jwt}~");
    assert!(!withheld_presentation.contains(encoded_disclosure));
    assert!(!withheld_presentation.contains("Ada"));
    let disclosed_presentation = format!("{issuer_signed_jwt}~{encoded_disclosure}~");
    assert_eq!(
        disclosed_presentation
            .split('~')
            .filter(|part| !part.is_empty())
            .count(),
        2,
        "presenting the claim adds exactly one complete disclosure"
    );
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);

    evaluation.results[0].value.as_mut().unwrap()["parents"][0]["name"] = json!("Mallory");
    store
        .insert(evaluation)
        .await
        .expect("tampered structured evaluation inserts");
    let tampered_status_store = CredentialStatusStore::with_test_store(
        &CredentialStatusConfig {
            enabled: true,
            base_url: "https://issuer.example".to_string(),
            retention_seconds: 60,
        },
        Arc::new(UnavailableCredentialStatusStore),
    );
    let tamper_state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            evidence,
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(Oid4vciConfig::default()),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            ReplayStores::memory(),
            tampered_status_store,
            Arc::new(AppMetrics::default()),
            store,
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
            None,
        )
        .expect("tamper-check state builds"),
    );
    let denied = issue_credential(
        HeaderMap::new(),
        Some(Extension(tamper_state)),
        Some(Extension(principal)),
        Ok(Json(request)),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        sign_count.load(Ordering::SeqCst),
        1,
        "altered nested stored values are rejected before signing or the unavailable status store"
    );
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
    context.metadata.access_mode = AccessMode::DelegatedSubjectAccess;
    principal.authorization_details = Some(registry_notary_core::EvidenceAuthorizationDetails {
        access_mode: Some(AccessMode::DelegatedSubjectAccess),
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

#[tokio::test]
async fn replayed_holder_proof_does_not_consume_machine_evaluation_lineage() {
    let mut evidence = credential_issue_evidence_config();
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .holder_binding = holder_required_profile().holder_binding;
    let store = Arc::new(EvidenceStore::default());
    let evaluation_id = "eval-replayed-proof";
    let evaluation_expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let evaluation = registry_notary_core::StoredEvaluation {
        client_id: "caseworker".to_string(),
        purpose: "test".to_string(),
        claim_ids: vec!["person-is-alive".to_string()],
        claim_refs: Vec::new(),
        disclosure: "predicate".to_string(),
        format: FORMAT_CLAIM_RESULT_JSON.to_string(),
        results: vec![claim_result_view(evaluation_id, "person-is-alive")],
        created_at: format_time(OffsetDateTime::now_utc()),
        expires_at: format_time(evaluation_expires_at),
        request_hash: "request-hash".to_string(),
        issuance_provenance: Some(issuance_provenance(
            "person-is-alive",
            "test",
            evaluation_id,
        )),
        subject_access: None,
    };
    store
        .insert(evaluation.clone())
        .await
        .expect("evaluation inserts");
    let replay = ReplayStores::memory();
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let oid4vci = Oid4vciConfig {
        enabled: true,
        ..Oid4vciConfig::default()
    };
    let state = Arc::new(
        RegistryNotaryApiState::new_with_federation(
            Arc::new(evidence),
            Arc::new(SubjectAccessConfig::default()),
            Arc::new(oid4vci),
            Arc::new(FederationConfig::default()),
            AuditKeyHasher::unkeyed_dev_only(),
            None,
            replay.clone(),
            CredentialStatusStore::disabled(),
            Arc::new(AppMetrics::default()),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::new(AtomicUsize::new(0)),
            }),
            None,
        )
        .expect("state builds")
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
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
            "jti": "already-used-holder-proof",
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
    let binding = validate_holder_request(
        &state.evidence.credential_profiles["civil_status_sd_jwt"],
        "civil_status_sd_jwt",
        &request,
        &evaluation,
        request.holder.as_ref(),
        &state.evidence.service_id,
    )
    .expect("holder proof validates")
    .expect("holder proof has a replay binding");
    require_replay_insert(
        replay.store().as_ref(),
        &binding.scope,
        &binding.key,
        binding.expires_at,
    )
    .await
    .expect("test pre-consumes holder proof");

    let denied = issue_credential(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(principal)),
        Ok(Json(request)),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::CONFLICT);
    preauth
        .preauthorization_state()
        .reserve_evaluation_issuance(evaluation_id, "caseworker", evaluation_expires_at)
        .await
        .expect("proof replay denial must leave evaluation lineage available");
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
