// SPDX-License-Identifier: Apache-2.0
//! Attestation API tests.

use super::*;

#[test]
fn self_attestation_authorization_details_allow_exact_transaction() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classified_transaction_principal(&config, &evidence);
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect("exact transaction details authorize request");
}

#[test]
fn self_attestation_authorization_details_required_for_transaction_token() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    principal.authorization_details = None;
    let claims = principal
        .verified_claims
        .as_mut()
        .expect("classified principal carries verified claims");
    claims.token_type = Some(bounded(
        registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
    ));
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("transaction tokens must carry authorization_details");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_reject_omitted_claim_version() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classified_transaction_principal(&config, &evidence);
    let request = evaluate_request("NAT-123");

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("omitting a versioned authorized claim broadens the request");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_reject_broadened_claims() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classified_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .expect("details exist")
        .claims
        .push(ClaimRef::with_version("date-of-birth", "1"));
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("broadened transaction claims must be denied");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_reject_duplicate_action() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classified_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .expect("details exist")
        .actions
        .push("evaluate".to_string());
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("duplicate transaction action must be denied");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_reject_empty_claims_without_panic() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classified_transaction_principal(&config, &evidence);
    let mut request = evaluate_request("NAT-123");
    request.claims = Vec::new();

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("empty claim array must deny instead of panicking");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::ClaimDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_tolerate_future_fields() {
    let details: EvidenceAuthorizationDetails = serde_json::from_value(serde_json::json!({
        "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
        "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
        "actions": ["evaluate"],
        "locations": ["registry-notary:test"],
        "claims": [{"id": "person-is-alive", "version": "1"}],
        "subject": {
            "binding_claim": SUBJECT_BINDING_CLAIM,
            "id_type": "national_id",
            "future_subject_metadata": true
        },
        "assisted_access_context": {
            "channel": "citizen_self_service",
            "future_context_metadata": true
        },
        "future_authorization_metadata": true
    }))
    .expect("authorization_details should ignore future metadata fields");

    assert_eq!(
        details.subject.as_ref().unwrap().binding_claim,
        SUBJECT_BINDING_CLAIM
    );
    assert_eq!(
        details.assisted_access_context.as_ref().unwrap().channel,
        "citizen_self_service"
    );
}

#[test]
fn self_attestation_authorization_details_reject_wrong_notary_location() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classified_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .expect("details exist")
        .locations = vec!["other-notary".to_string()];
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("wrong Notary audience broadens the transaction");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied
        }
    ));
}

#[test]
fn self_attestation_authorization_details_reject_wrong_subject_binding_metadata() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classified_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .and_then(|details| details.subject.as_mut())
        .expect("subject details exist")
        .id_type = "other_id".to_string();
    let mut request = evaluate_request("NAT-123");
    request.claims = vec![ClaimRef::with_version("person-is-alive", "1")];

    let err = require_self_attestation_evaluate(&evidence, &config, &principal, &request)
        .expect_err("wrong subject binding metadata broadens the transaction");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectMismatch
        }
    ));
}

#[test]
fn self_attestation_classification_requires_citizen_client_and_scope() {
    let config = self_attestation_config();

    let classified = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen client and scope classify");
    assert!(classified.is_self_attestation());

    let missing_scope = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &[]),
    )
    .expect_err("citizen client without scope fails closed");
    assert!(matches!(
        missing_scope,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::InvalidToken
        }
    ));

    let mut no_citizen_client_or_audience =
        oidc_principal(Some("client_id:other"), &["self_attestation"]);
    no_citizen_client_or_audience
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .audiences
        .clear();
    let missing_client =
        classify_self_attestation_principal(&config, &no_citizen_client_or_audience)
            .expect_err("scope without citizen client or audience fails closed");
    assert!(matches!(
        missing_client,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::InvalidToken
        }
    ));
}

#[test]
fn self_attestation_optional_scope_policy_allows_absent_scope_only() {
    let mut config = self_attestation_config();
    config.scope_policy = SelfAttestationScopePolicy::Optional;

    let no_scope = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &[]),
    )
    .expect("optional policy accepts a scoped-out citizen token when no scope claim is present");
    assert!(no_scope.is_self_attestation());

    let wrong_scope = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &["openid"]),
    )
    .expect_err("optional policy still rejects a present but insufficient scope claim");
    assert!(matches!(
        wrong_scope,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::InvalidToken
        }
    ));
}

#[test]
fn self_attestation_disabled_scope_policy_uses_client_and_audience_only() {
    let mut config = self_attestation_config();
    config.scope_policy = SelfAttestationScopePolicy::Disabled;
    config.required_scopes.clear();

    let classified = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &[]),
    )
    .expect("disabled policy classifies by verified citizen client and audience");
    assert!(classified.is_self_attestation());

    let mut wrong_client = oidc_principal(Some("client_id:other"), &[]);
    wrong_client
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .audiences
        .clear();
    let denied = classify_self_attestation_principal(&config, &wrong_client)
        .expect("non-citizen token remains a machine-client candidate");
    assert!(!denied.is_self_attestation());
}

#[test]
fn self_attestation_scope_without_verified_claims_fails_closed() {
    let config = self_attestation_config();
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
        principal_id: "citizen-subject".to_string(),
        scopes: vec!["self_attestation".to_string()],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };

    let err = classify_self_attestation_principal(&config, &principal)
        .expect_err("citizen scope without verified claims must not fall back to machine mode");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::InvalidToken
        }
    ));
}

#[test]
fn self_attestation_evaluate_guard_rejects_subject_mismatch() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");

    let err = require_self_attestation_evaluate(
        &evidence,
        &config,
        &principal,
        &evaluate_request("NAT-999"),
    )
    .expect_err("mismatched subject must be denied before runtime");
    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectMismatch
        }
    ));
}

#[test]
fn self_attestation_derives_missing_request_identity_from_token_binding() {
    let config = self_attestation_config();
    let principal = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let mut request = EvaluateRequest {
        requester: None,
        target: None,
        relationship: None,
        on_behalf_of: None,
        variables: Default::default(),
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: None,
    };

    derive_self_attestation_request_context(&config, &principal, &mut request)
        .expect("request identity is derived");

    let target_subject = request
        .target_subject()
        .expect("derived target maps to subject");
    assert_eq!(target_subject.id, "NAT-123");
    assert_eq!(target_subject.id_type.as_deref(), Some("national_id"));
    assert_eq!(
        request
            .requester
            .as_ref()
            .and_then(EvidenceEntity::to_subject_request)
            .expect("derived requester maps to subject")
            .id,
        "NAT-123"
    );
    assert_eq!(
        request
            .relationship
            .as_ref()
            .map(|relationship| relationship.relationship_type.as_str()),
        Some("self")
    );
}

#[test]
fn self_attestation_derivation_rejects_conflicting_request_identity() {
    let config = self_attestation_config();
    let principal = classify_self_attestation_principal(
        &config,
        &oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let mut request = evaluate_request("NAT-999");

    let err = derive_self_attestation_request_context(&config, &principal, &mut request)
        .expect_err("conflicting target must be denied before runtime");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::SubjectMismatch
        }
    ));
}

#[test]
fn self_attestation_prepare_pins_claim_purpose_and_metadata() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );

    let context = prepare_self_attestation_evaluate(
        &state,
        &evidence,
        &principal,
        &evaluate_request("NAT-123"),
    )
    .expect("self-attestation evaluate context prepares");

    assert_eq!(context.purpose, "citizen_self_attestation");
    assert_eq!(context.metadata.access_mode, AccessMode::SelfAttestation);
    assert_eq!(context.metadata.subject_id_type.as_str(), "national_id");
    assert!(context.metadata.policy_hash.is_some());
    assert!(
        context.metadata.evaluation_expires_at.is_some(),
        "self-attestation evaluation must carry its capped expiry"
    );
    assert!(matches!(
        context.evaluation_capability,
        EvaluationCapability::SelfAttestation { .. }
    ));
}

#[test]
fn self_attestation_external_standard_at_jwt_uses_scope_without_notary_details() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let claims = principal
        .verified_claims
        .as_mut()
        .expect("classified principal carries verified claims");
    claims.issuer = bounded("https://id.example.gov");
    claims.token_type = Some(bounded(
        registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
    ));
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    )
    .with_runtime_config(Arc::new(runtime_config_with_custom_access_token_typ()));

    prepare_self_attestation_evaluate(&state, &evidence, &principal, &evaluate_request("NAT-123"))
        .expect("external standard at+jwt can rely on configured self-attestation scope");
}

#[test]
fn self_attestation_notary_standard_at_jwt_still_requires_transaction_details() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let claims = principal
        .verified_claims
        .as_mut()
        .expect("classified principal carries verified claims");
    claims.issuer = bounded("https://notary.example.test");
    claims.token_type = Some(bounded(
        registry_notary_core::tokens::NOTARY_TRANSACTION_TOKEN_JWT_TYP,
    ));
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    )
    .with_runtime_config(Arc::new(runtime_config_with_custom_access_token_typ()));

    let err = prepare_self_attestation_evaluate(
        &state,
        &evidence,
        &principal,
        &evaluate_request("NAT-123"),
    )
    .expect_err("Notary-issued standard at+jwt must carry transaction details");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::OperationDenied
        }
    ));
}

#[test]
fn delegated_attestation_derives_requester_and_pins_metadata() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let principal = delegated_transaction_principal(&config, &evidence);
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();

    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("delegated request context derives");
    let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
        .expect("delegated evaluate context prepares");

    assert_eq!(
        request
            .requester
            .as_ref()
            .and_then(EvidenceEntity::to_subject_request)
            .expect("requester is derived")
            .id,
        "NAT-123"
    );
    assert_eq!(
        request
            .relationship
            .as_ref()
            .map(|relationship| relationship.relationship_type.as_str()),
        Some("guardian")
    );
    assert!(
        request
            .on_behalf_of
            .as_ref()
            .map(|delegation| delegation.actor.id_hash.starts_with("hmac-sha256:"))
            .unwrap_or(false),
        "delegated actor is stored as a keyed hash"
    );
    assert_eq!(context.purpose, "dependent_attestation");
    assert_eq!(
        context.metadata.access_mode,
        AccessMode::DelegatedAttestation
    );
    assert_eq!(
        context
            .metadata
            .relationship_type
            .as_ref()
            .map(ConfigMetadata::as_str),
        Some("guardian")
    );
    assert_eq!(
        context
            .metadata
            .proof_claim_id
            .as_ref()
            .map(BoundedClaimId::as_str),
        Some("guardian-link-established")
    );
    assert!(context
        .metadata
        .dependent_target_hash
        .as_ref()
        .map(|hash| hash.as_str().starts_with("hmac-sha256:"))
        .unwrap_or(false));
    assert!(matches!(
        context.evaluation_capability,
        EvaluationCapability::DelegatedAttestation { .. }
    ));
}

#[test]
fn delegated_attestation_rejects_spoofed_requester_context() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let principal = delegated_transaction_principal(&config, &evidence);
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();
    request.requester = Some(EvidenceEntity::from_subject_request(
        "Person",
        SubjectRequest {
            id: "ATTACKER".to_string(),
            id_type: Some("national_id".to_string()),
        },
    ));

    let err = derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect_err("caller-supplied requester must not be trusted");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
        }
    ));
}

#[test]
fn delegated_attestation_canonicalizes_target_to_validated_subject() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let principal = delegated_transaction_principal(&config, &evidence);
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    // Caller pins the validated subject CHILD-123 via the configured id_type,
    // but smuggles a divergent canonical id (VICTIM-A) plus an extra
    // identifier and attribute that the binding hash would never see.
    let mut request = delegated_request();
    let target = request
        .target
        .as_mut()
        .expect("delegated target is present");
    target.id = Some("VICTIM-A".to_string());
    target
        .identifiers
        .push(registry_notary_core::EvidenceIdentifier {
            scheme: "national_id".to_string(),
            value: "DIVERGENT-NID".to_string(),
            issuer: None,
            country: None,
        });
    target
        .attributes
        .insert("given_name".to_string(), json!("smuggled"));
    target.profile = Some("smuggled-profile".to_string());

    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("delegated request context derives");

    let canonical_target = request.target.as_ref().expect("target survives derivation");
    // The canonical id field must be collapsed so an arbitrary lookup keyed on
    // target.id can never read the smuggled VICTIM-A value.
    assert!(
        canonical_target.id.is_none(),
        "divergent canonical id must be dropped"
    );
    assert!(
        canonical_target.attributes.is_empty(),
        "caller-supplied target attributes must be dropped"
    );
    assert!(
        canonical_target.profile.is_none(),
        "caller-supplied target profile must be dropped"
    );
    // The only surviving identifier is the validated (id_type, id) pair, so
    // to_subject_request() and every configured lookup path resolve the same
    // subject.
    let subject = canonical_target
        .to_subject_request()
        .expect("canonical target resolves a subject");
    assert_eq!(subject.id, "CHILD-123");
    assert_eq!(subject.id_type.as_deref(), Some("civil_registration_id"));

    let context = request
        .request_context()
        .expect("delegated request yields a context");
    assert_eq!(
        context.lookup_value("target.identifiers.civil_registration_id"),
        Some(json!("CHILD-123"))
    );
    // The binding-hash projection and the proof/dependent lookups now agree:
    // no path can observe VICTIM-A or DIVERGENT-NID.
    assert_eq!(context.lookup_value("target.id"), None);
    assert_eq!(context.lookup_value("target.identifiers.national_id"), None);
}

#[test]
fn delegated_attestation_requires_transaction_details_to_cover_proof_claim() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let mut principal = delegated_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .expect("delegated details exist")
        .claims = vec![ClaimRef::with_version("dependent-person-is-alive", "1")];
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();
    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("relationship context still derives");

    let err = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
        .expect_err("missing proof claim authorization must fail closed");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedClaimDenied
        }
    ));
}

#[test]
fn delegated_attestation_requires_transaction_details_target() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let mut principal = delegated_transaction_principal(&config, &evidence);
    principal
        .authorization_details
        .as_mut()
        .expect("delegated details exist")
        .target = None;
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();
    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("relationship context still derives before target-scoped authorization check");

    let err = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
        .expect_err("delegated target must be explicit in authorization_details");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
        }
    ));
}

#[test]
fn stored_delegated_attestation_rechecks_current_authorization_details() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let principal = delegated_transaction_principal(&config, &evidence);
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();
    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("delegated request context derives");
    let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
        .expect("delegated context prepares");
    let mut evaluation = evaluation_for_proof();
    evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
    evaluation.purpose = context.purpose.clone();
    evaluation.claim_ids = vec!["dependent-person-is-alive".to_string()];
    evaluation.claim_refs = request.claims.clone();
    evaluation.disclosure = context.metadata.disclosure.as_str().to_string();
    evaluation.format = context.metadata.result_format.as_str().to_string();
    evaluation.self_attestation = Some(context.metadata);
    let mut narrowed = principal.clone();
    narrowed
        .authorization_details
        .as_mut()
        .expect("delegated authorization details exist")
        .claims = vec![ClaimRef::with_version("dependent-person-is-alive", "1")];

    let err = require_self_attestation_stored_access(
        &state,
        &evidence,
        &narrowed,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        None,
    )
    .expect_err("stored delegated access must re-check current proof coverage");

    assert!(matches!(
        err,
        EvidenceError::SelfAttestationDenied {
            reason: SelfAttestationDenialCode::DelegatedClaimDenied
        }
    ));
}

#[test]
fn stored_delegated_attestation_rechecks_current_target_binding() {
    let config = delegated_self_attestation_config();
    let evidence = delegated_evidence_config();
    let principal = delegated_transaction_principal(&config, &evidence);
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        delegated_test_audit_hasher(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut request = delegated_request();
    derive_delegated_attestation_request_context(
        &state.self_attestation,
        &state.self_attestation_rate_keys,
        &principal,
        &mut request,
    )
    .expect("delegated request context derives");
    let context = prepare_self_attestation_evaluate(&state, &evidence, &principal, &request)
        .expect("delegated context prepares");
    let mut evaluation = evaluation_for_proof();
    evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
    evaluation.purpose = context.purpose.clone();
    evaluation.claim_ids = vec!["dependent-person-is-alive".to_string()];
    evaluation.claim_refs = request.claims.clone();
    evaluation.disclosure = context.metadata.disclosure.as_str().to_string();
    evaluation.format = context.metadata.result_format.as_str().to_string();
    evaluation.self_attestation = Some(context.metadata);
    let mut different_target = principal.clone();
    different_target
        .authorization_details
        .as_mut()
        .and_then(|details| details.target.as_mut())
        .expect("delegated authorization target exists")
        .id = "OTHER-CHILD".to_string();

    let err = require_self_attestation_stored_access(
        &state,
        &evidence,
        &different_target,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        None,
    )
    .expect_err("stored delegated access must re-check current target binding");

    assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
}

#[test]
fn self_attestation_token_policy_fails_closed_without_auth_time() {
    let config = self_attestation_config();
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .auth_time = None;

    let err = require_self_attestation_token_policy(&config, &principal)
        .expect_err("missing auth_time fails closed");

    assert!(matches!(err, EvidenceError::SelfAttestationAssuranceDenied));
}

#[test]
fn self_attestation_token_policy_fails_closed_without_required_acr() {
    let mut config = self_attestation_config();
    config.token_policy.required_acr_values = vec!["urn:example:loa:substantial".to_string()];
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .acr = None;

    let err = require_self_attestation_token_policy(&config, &principal)
        .expect_err("missing acr fails closed when required");

    assert!(matches!(err, EvidenceError::SelfAttestationAssuranceDenied));
}

#[test]
fn self_attestation_token_policy_rejects_stale_auth_time() {
    let config = self_attestation_config();
    let mut principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .auth_time = Some(
        now - config.token_policy.max_auth_age_seconds as i64
            - config.token_policy.max_clock_leeway_seconds as i64
            - 1,
    );

    let err = require_self_attestation_token_policy(&config, &principal)
        .expect_err("stale auth_time fails closed");

    assert!(matches!(err, EvidenceError::SelfAttestationAssuranceDenied));
}

#[test]
fn self_attestation_token_policy_rejects_future_iat_and_auth_time() {
    let config = self_attestation_config();
    let principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");

    let mut future_auth_time = principal.clone();
    future_auth_time
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .auth_time = Some(OffsetDateTime::now_utc().unix_timestamp() + 3_600);
    assert!(matches!(
        require_self_attestation_token_policy(&config, &future_auth_time),
        Err(EvidenceError::SelfAttestationAssuranceDenied)
    ));

    let mut future_iat = principal;
    future_iat
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .iat = Some(OffsetDateTime::now_utc().unix_timestamp() + 3_600);
    assert!(matches!(
        require_self_attestation_token_policy(&config, &future_iat),
        Err(EvidenceError::SelfAttestationAssuranceDenied)
    ));
}

#[test]
fn stored_self_attestation_rechecks_issuer_client_and_audience() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let context = prepare_self_attestation_evaluate(
        &state,
        &evidence,
        &principal,
        &evaluate_request("NAT-123"),
    )
    .expect("self-attestation context prepares");
    let mut evaluation = evaluation_for_proof();
    evaluation.client_id = principal.principal_id.clone();
    evaluation.claim_ids = vec!["person-is-alive".to_string()];
    evaluation.disclosure = "predicate".to_string();
    evaluation.format = FORMAT_CLAIM_RESULT_JSON.to_string();
    evaluation.self_attestation = Some(context.metadata);

    let mut changed_client = principal.clone();
    changed_client
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .client_id = Some(bounded("client_id:other-portal"));

    let err = require_self_attestation_stored_access(
        &state,
        &evidence,
        &changed_client,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        None,
    )
    .expect_err("changed client id must not access stored evaluation");

    assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
}

#[test]
fn stored_self_attestation_rejects_expired_metadata_even_with_future_store_ttl() {
    let config = self_attestation_config();
    let evidence = evidence_config();
    let principal = classify_self_attestation_principal(
        &config,
        &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
    )
    .expect("citizen principal classifies");
    let state = RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence.clone()),
        Arc::new(config),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );
    let mut context = prepare_self_attestation_evaluate(
        &state,
        &evidence,
        &principal,
        &evaluate_request("NAT-123"),
    )
    .expect("self-attestation context prepares");
    context.metadata.evaluation_expires_at = Some("1970-01-01T00:00:00Z".to_string());
    let mut evaluation = evaluation_for_proof();
    evaluation.client_id = context.metadata.principal_hash.as_str().to_string();
    evaluation.claim_ids = vec!["person-is-alive".to_string()];
    evaluation.disclosure = "predicate".to_string();
    evaluation.format = FORMAT_CLAIM_RESULT_JSON.to_string();
    evaluation.expires_at = "2999-01-01T00:00:00Z".to_string();
    evaluation.self_attestation = Some(context.metadata);

    let err = require_self_attestation_stored_access(
        &state,
        &evidence,
        &principal,
        &evaluation,
        &evaluation.claim_ids,
        &evaluation.disclosure,
        &evaluation.format,
        None,
    )
    .expect_err("expired self-attestation metadata must fail closed");

    assert!(matches!(err, EvidenceError::EvaluationNotFound));
}

#[test]
fn self_attestation_public_problem_codes_remain_generic() {
    assert_eq!(
        EvidenceError::SelfAttestationInvalidToken.code(),
        "self_attestation.denied"
    );
    assert_eq!(
        EvidenceError::SelfAttestationInvalidToken.audit_code(),
        "self_attestation.invalid_token"
    );
    assert_eq!(
        evidence_status(&EvidenceError::SelfAttestationInvalidToken),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        EvidenceError::SelfAttestationAssuranceDenied.code(),
        "self_attestation.denied"
    );
    assert_eq!(
        EvidenceError::SelfAttestationAssuranceDenied.audit_code(),
        "self_attestation.assurance_denied"
    );
    assert_eq!(
        evidence_status(&EvidenceError::SelfAttestationAssuranceDenied),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn self_attestation_policy_hash_includes_credential_profile_policy() {
    let config = self_attestation_config();
    let mut evidence = evidence_config();
    evidence.credential_profiles.insert(
        "civil_status_sd_jwt".to_string(),
        serde_json::from_value(json!({
            "format": FORMAT_SD_JWT_VC,
            "issuer": "did:web:issuer.example",
            "signing_key": "issuer-key",
            "vct": "https://issuer.example/credentials/civil-status",
            "validity_seconds": 600,
            "holder_binding": {
                "mode": "did",
                "proof_of_possession": "required",
                "allowed_did_methods": ["did:jwk"]
            },
            "allowed_claims": ["person-is-alive"],
            "disclosure": { "allowed": ["predicate"] }
        }))
        .expect("profile parses"),
    );
    let claims = vec!["person-is-alive".to_string()];
    let original = self_attestation_policy_hash(
        &evidence,
        &config,
        &claims,
        "predicate",
        FORMAT_CLAIM_RESULT_JSON,
    )
    .expect("policy hashes");

    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("profile exists")
        .holder_binding
        .proof_of_possession = None;
    let changed = self_attestation_policy_hash(
        &evidence,
        &config,
        &claims,
        "predicate",
        FORMAT_CLAIM_RESULT_JSON,
    )
    .expect("changed policy hashes");

    assert_ne!(original, changed);
}

#[tokio::test]
async fn self_attestation_batch_evaluate_is_rejected_before_evaluation() {
    let state = Arc::new(RegistryNotaryApiState::new_with_self_attestation(
        Arc::new(evidence_config()),
        Arc::new(self_attestation_config()),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    ));
    let request = BatchEvaluateRequest {
        items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
            registry_notary_core::BatchSubjectRequest {
                id: "NAT-123".to_string(),
                id_type: Some("national_id".to_string()),
                purpose: None,
            },
        )],
        claims: vec![ClaimRef::from("person-is-alive")],
        disclosure: Some("predicate".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: None,
    };

    let response = batch_evaluate(
        HeaderMap::new(),
        Some(Extension(state)),
        Some(Extension(oidc_principal(
            Some("client_id:citizen-portal"),
            &["self_attestation"],
        ))),
        None,
        Ok(Json(request)),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let audit = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("self-attestation denial audit context is attached");
    assert_eq!(audit.access_mode, Some(AccessMode::SelfAttestation));
    assert_eq!(
        audit.denial_code,
        Some(SelfAttestationDenialCode::BatchDenied)
    );
}
