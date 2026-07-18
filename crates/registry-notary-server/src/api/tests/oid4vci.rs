// SPDX-License-Identifier: Apache-2.0
//! Oid4Vci API tests.

use super::*;

#[test]
fn token_client_address_ignores_forwarded_headers_from_untrusted_peer() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    let connect_info =
        axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());

    assert_eq!(
        token_client_address_with_trusted_proxy_ips(&headers, Some(&connect_info), &[]),
        "198.51.100.10"
    );
}

#[test]
fn token_client_address_trusts_forwarded_for_from_configured_proxy() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
    );
    let connect_info =
        axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());
    let trusted_proxy = "198.51.100.10".parse::<IpAddr>().unwrap();

    assert_eq!(
        token_client_address_with_trusted_proxy_ips(
            &headers,
            Some(&connect_info),
            &[trusted_proxy]
        ),
        "203.0.113.10"
    );
}

#[test]
fn token_client_address_trusts_real_ip_from_configured_proxy() {
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.11"));
    let connect_info =
        axum::extract::ConnectInfo("198.51.100.10:443".parse::<SocketAddr>().unwrap());
    let trusted_proxy = "198.51.100.10".parse::<IpAddr>().unwrap();

    assert_eq!(
        token_client_address_with_trusted_proxy_ips(
            &headers,
            Some(&connect_info),
            &[trusted_proxy]
        ),
        "203.0.113.11"
    );
}

#[test]
fn oid4vci_requested_url_ignores_forwarded_host_from_untrusted_peer() {
    let config = Oid4vciConfig {
        credential_issuer: "https://issuer.example".to_string(),
        ..Oid4vciConfig::default()
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    headers.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
    headers.insert(header::HOST, HeaderValue::from_static("host.example"));
    let uri = "/credentials/identity".parse::<Uri>().unwrap();

    // Untrusted peer: forwarded scheme/host are ignored, Host header wins.
    assert_eq!(
        oid4vci_requested_absolute_url_for_path(
            &config,
            &headers,
            &uri,
            "/credentials/identity",
            false,
        ),
        Some("https://host.example/credentials/identity".to_string())
    );
}

#[test]
fn oid4vci_requested_url_trusts_forwarded_host_from_trusted_peer() {
    let config = Oid4vciConfig {
        credential_issuer: "https://issuer.example".to_string(),
        ..Oid4vciConfig::default()
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    headers.insert(
        "x-forwarded-host",
        HeaderValue::from_static("proxy.example"),
    );
    headers.insert(header::HOST, HeaderValue::from_static("host.example"));
    let uri = "/credentials/identity".parse::<Uri>().unwrap();

    // Trusted peer: forwarded scheme/host are honored.
    assert_eq!(
        oid4vci_requested_absolute_url_for_path(
            &config,
            &headers,
            &uri,
            "/credentials/identity",
            true,
        ),
        Some("http://proxy.example/credentials/identity".to_string())
    );
}

#[test]
fn oid4vci_metadata_is_public_but_not_operationally_leaky() {
    let evidence = oid4vci_evidence_config();
    let metadata = serde_json::to_value(
        oid4vci_metadata(&oid4vci_config(), &evidence).expect("metadata builds"),
    )
    .expect("metadata serializes");

    assert_eq!(
        metadata["credential_endpoint"],
        "http://127.0.0.1:4325/oid4vci/credential"
    );
    assert_eq!(
        metadata["nonce_endpoint"],
        "http://127.0.0.1:4325/oid4vci/nonce"
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
            ["name"],
        "Person is alive"
    );
    assert_eq!(metadata["display"][0]["name"], "Civil Registry Notary");
    assert_eq!(
        metadata["display"][0]["logo"]["uri"],
        "https://issuer.example/assets/notary-logo.png"
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
            ["description"],
        "Proof that the civil registry currently records this person as alive."
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
            ["background_color"],
        "#0057B8"
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
            ["logo"]["uri"],
        "https://issuer.example/assets/person-is-alive.png"
    );
    assert!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"][0]
            ["logo"]
            .get("url")
            .is_none()
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["scope"],
        "person_is_alive"
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
            ["credential_signing_alg_values_supported"][0],
        "EdDSA"
    );
    assert_eq!(
        metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]
            ["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"][0],
        "EdDSA"
    );
    let mut without_nonce = oid4vci_config();
    without_nonce.nonce.enabled = false;
    let without_nonce =
        serde_json::to_value(oid4vci_metadata(&without_nonce, &evidence).expect("metadata builds"))
            .expect("metadata serializes");
    assert!(without_nonce.get("nonce_endpoint").is_none());
    let text = metadata.to_string();
    assert!(!text.contains("token_env"));
    assert!(!text.contains("source_connections"));
    assert!(!text.contains("NAT-123"));
}

#[test]
fn oid4vci_metadata_advertises_configured_credential_signing_alg() {
    let oid4vci = oid4vci_config();
    let mut evidence = oid4vci_evidence_config();
    evidence
        .signing_keys
        .get_mut("issuer-key")
        .expect("issuer key exists")
        .alg = "ES256".to_string();

    let metadata =
        serde_json::to_value(oid4vci_metadata(&oid4vci, &evidence).expect("metadata builds"))
            .expect("metadata serializes");
    let configuration = &metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"];

    assert_eq!(
        configuration["credential_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(
        configuration["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
        json!(["EdDSA"]),
        "holder proof algorithms stay independent from issuer signing algorithms"
    );
}

#[tokio::test]
async fn oid4vci_credential_rejects_delegated_transaction_token() {
    let store = Arc::new(EvidenceStore::default());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::new(oid4vci_evidence_config()),
        Arc::new(delegated_subject_access_config()),
        Arc::new(oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(TestIssuerResolver),
    ));
    let mut principal = fresh_oidc_principal(Some("client_id:citizen-portal"), &["subject_access"]);
    principal.authorization_details =
        Some(delegated_authorization_details(&delegated_evidence_config()));
    let nonce = "delegated-oid4vci-nonce";
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal)),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn oid4vci_source_free_bypass_denies_before_nonce_or_signer_access() {
    let store = Arc::new(EvidenceStore::default());
    let evidence = Arc::new(oid4vci_evidence_config());
    assert!(evidence.claims[0].evidence_mode.is_self_attested());
    let subject_access = Arc::new(subject_access_config());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let oid4vci = Arc::new(oid4vci);
    let sign_count = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(CountingIssuerResolver {
            sign_count: Arc::clone(&sign_count),
        }),
    ));
    let nonce = "source-free-bypass-nonce";
    let (nonce_scope, nonce_key) =
        reserve_oid4vci_test_nonce(&state, "person_is_alive_sd_jwt", nonce).await;
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(oid4vci_authorized_principal(
            &evidence,
            &subject_access,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["subject_access", "person_is_alive"],
        ))),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&nonce_scope, &nonce_key)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::Inserted
    ));
}

#[tokio::test]
async fn oid4vci_credential_scope_prevents_cross_configuration_issuance_before_nonce_consume() {
    let store = Arc::new(EvidenceStore::default());
    let evidence = Arc::new(oid4vci_evidence_config());
    let subject_access = Arc::new(subject_access_config());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let mut other_configuration = oid4vci
        .credential_configurations
        .get("person_is_alive_sd_jwt")
        .expect("base configuration exists")
        .clone();
    other_configuration.scope = "date_of_birth".to_string();
    other_configuration.vct = "https://issuer.example/credentials/date-of-birth".to_string();
    oid4vci
        .credential_configurations
        .insert("date_of_birth_sd_jwt".to_string(), other_configuration);
    let principal = oid4vci_authorized_principal(
        &evidence,
        &subject_access,
        &oid4vci,
        "person_is_alive_sd_jwt",
        &["subject_access", "person_is_alive"],
    );
    let oid4vci = Arc::new(oid4vci);
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(TestIssuerResolver),
    ));
    let nonce = "cross-configuration-nonce";
    let (nonce_scope, nonce_key) =
        reserve_oid4vci_test_nonce(&state, "date_of_birth_sd_jwt", nonce).await;
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal)),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("date_of_birth_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");
    assert_eq!(body["error"], "access_denied");
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&nonce_scope, &nonce_key)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::Inserted
    ));
}

#[tokio::test]
async fn oid4vci_credential_requires_authorization_details_before_nonce_consume() {
    let store = Arc::new(EvidenceStore::default());
    let evidence = Arc::new(oid4vci_evidence_config());
    let subject_access = Arc::new(subject_access_config());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let oid4vci = Arc::new(oid4vci);
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(TestIssuerResolver),
    ));
    let nonce = "missing-authz-nonce";
    let (nonce_scope, nonce_key) =
        reserve_oid4vci_test_nonce(&state, "person_is_alive_sd_jwt", nonce).await;
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
    let mut principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    let claims = principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims");
    claims.token_type = Some(bounded(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
    ));

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal)),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");
    assert_eq!(body["error"], "access_denied");
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&nonce_scope, &nonce_key)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::Inserted
    ));
}

#[tokio::test]
async fn oid4vci_credential_requires_custom_notary_typ_details_before_nonce_consume() {
    let store = Arc::new(EvidenceStore::default());
    let evidence = Arc::new(oid4vci_evidence_config());
    let subject_access = Arc::new(subject_access_config());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let oid4vci = Arc::new(oid4vci);
    let runtime_config = Arc::new(runtime_config_with_custom_access_token_typ());
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
        )
        .with_runtime_config(runtime_config),
    );
    let nonce = "custom-typ-missing-authz-nonce";
    let (nonce_scope, nonce_key) =
        reserve_oid4vci_test_nonce(&state, "person_is_alive_sd_jwt", nonce).await;
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
    let mut principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    let claims = principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims");
    claims.issuer = bounded("https://notary.example.test");
    claims.token_type = Some(bounded("custom-notary-access+jwt"));

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(principal)),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");
    assert_eq!(body["error"], "access_denied");
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&nonce_scope, &nonce_key)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::Inserted
    ));
}

#[test]
fn oid4vci_type_metadata_defaults_display_locale_when_unconfigured() {
    let mut oid4vci = oid4vci_config();
    let configuration = oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("configuration exists");
    configuration.display.locale = None;

    let evidence = evidence_config();
    let metadata = oid4vci_type_metadata_document(&evidence, configuration);

    assert_eq!(metadata["display"][0]["locale"], "en-US");
    assert_eq!(metadata["claims"][0]["display"][0]["locale"], "en-US");
}

#[test]
fn oid4vci_type_metadata_advertises_claim_semantics_extension() {
    let oid4vci = oid4vci_config();
    let configuration = oid4vci
        .credential_configurations
        .get("person_is_alive_sd_jwt")
        .expect("configuration exists");
    let mut evidence = oid4vci_evidence_config();
    evidence.claims.first_mut().expect("claim exists").semantics = Some(
        serde_json::from_value(json!({
            "concept": "https://publicschema.org/Person",
            "predicate": "urn:registry-notary:predicate:person-is-alive",
            "derived_from": ["https://publicschema.org/date_of_death"]
        }))
        .expect("claim semantics parses"),
    );

    let metadata = oid4vci_type_metadata_document(&evidence, configuration);

    assert_eq!(
        metadata["claims"][0]["registry_notary_semantics"]["concept"],
        json!("https://publicschema.org/Person")
    );
    assert_eq!(
        metadata["claims"][0]["registry_notary_semantics"]["predicate"],
        json!("urn:registry-notary:predicate:person-is-alive")
    );
    assert_eq!(
        metadata["claims"][0]["registry_notary_semantics"]["derived_from"],
        json!(["https://publicschema.org/date_of_death"])
    );
}

#[test]
fn oid4vci_metadata_advertises_token_endpoint_only_when_preauth_enabled() {
    // Pre-auth disabled (the default): no token endpoint is advertised, so a
    // wallet sees an authorization_code-only issuer.
    let disabled = oid4vci_config();
    assert!(!disabled.pre_authorized_code.enabled);
    let evidence = oid4vci_evidence_config();
    let disabled_metadata =
        serde_json::to_value(oid4vci_metadata(&disabled, &evidence).expect("metadata builds"))
            .expect("metadata serializes");
    assert!(
        disabled_metadata.get("token_endpoint").is_none(),
        "disabled pre-auth must not advertise a token endpoint"
    );

    // Pre-auth enabled: the Notary's own token endpoint is advertised,
    // derived from the credential-issuer base like the credential endpoint.
    let mut enabled = oid4vci_config();
    enabled.pre_authorized_code.enabled = true;
    let enabled_metadata =
        serde_json::to_value(oid4vci_metadata(&enabled, &evidence).expect("metadata builds"))
            .expect("metadata serializes");
    assert_eq!(
        enabled_metadata["token_endpoint"],
        json!("http://127.0.0.1:4325/oid4vci/token"),
        "enabled pre-auth advertises the Notary token endpoint"
    );
    // The credential-configuration metadata is otherwise unchanged: the
    // pre-authorized-code grant is advertised per-offer in `grants`, not on
    // the credential configuration.
    assert_eq!(
        enabled_metadata["credential_configurations_supported"]["person_is_alive_sd_jwt"]["scope"],
        json!("person_is_alive")
    );
}

#[tokio::test]
async fn oid4vci_wire_errors_use_oauth_codes_and_keep_internal_audit_code() {
    let response = oid4vci_error_response(Oid4vciWireError::InvalidProof);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .extensions()
            .get::<EvidenceErrorCodeContext>()
            .map(|context| context.0.as_str()),
        Some("oid4vci.invalid_proof")
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");

    assert_eq!(body["error"], "invalid_proof");
    assert!(body.get("code").is_none());
}

#[test]
fn oid4vci_token_denial_audit_records_public_token_path() {
    let audit = token_error_audit_event(
        "/oid4vci/token",
        StatusCode::BAD_REQUEST.as_u16(),
        Some("person_is_alive_sd_jwt"),
        SubjectAccessDenialCode::OperationDenied,
    );

    assert_eq!(audit.method, "POST");
    assert_eq!(audit.path, "/oid4vci/token");
    assert_eq!(audit.status, StatusCode::BAD_REQUEST.as_u16());
    assert_eq!(audit.decision, "denied");
    assert_eq!(
        audit.denial_code,
        Some(SubjectAccessDenialCode::OperationDenied)
    );
    assert_eq!(
        audit.protocol.as_ref().map(|value| value.as_str()),
        Some("openid4vci")
    );
    assert_eq!(
        audit
            .credential_configuration_id
            .as_ref()
            .map(|value| value.as_str()),
        Some("person_is_alive_sd_jwt")
    );
}

#[tokio::test]
async fn oid4vci_token_error_fails_closed_when_denial_audit_fails() {
    let response =
        token_error_after_audit_result(token_error_response(TokenWireError::InvalidRequest), true);

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("error body parses");
    assert_eq!(body["error"], "server_error");
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_projected_registry_credential_issues_and_rejects_nonce_replay() {
    let store = Arc::new(EvidenceStore::default());
    let mut subject_access = subject_access_config();
    subject_access
        .allowed_claims
        .push("person-is-registered".to_string());
    let mut evidence = registry_backed_oid4vci_evidence_with_dependency();
    let mut registered = evidence.claims[0].clone();
    registered.id = "person-is-registered".to_string();
    registered.title = "Person is registered".to_string();
    evidence.claims.push(registered);
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .allowed_claims
        .push("person-is-registered".to_string());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let configuration = oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists");
    configuration.claim_id = None;
    configuration.claims = vec![
        registry_notary_core::Oid4vciCredentialClaimConfig {
            id: "person-is-alive".to_string(),
            output_path: vec!["person_alive".to_string()],
            display_name: "Person is alive".to_string(),
            sd: "always".to_string(),
        },
        registry_notary_core::Oid4vciCredentialClaimConfig {
            id: "person-is-registered".to_string(),
            output_path: vec!["person_registered".to_string()],
            display_name: "Person is registered".to_string(),
            sd: "always".to_string(),
        },
    ];
    let evidence = Arc::new(evidence);
    let subject_access = Arc::new(subject_access);
    let oid4vci = Arc::new(oid4vci);
    require_registry_backed_credential_claims(
        &evidence,
        &oid4vci
            .credential_configurations
            .get("person_is_alive_sd_jwt")
            .unwrap()
            .credential_claim_ids(),
    )
    .expect("positive fixture has registry-backed credential roots and dependency");
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(StaticIssuerResolver),
    ));
    let relay = Arc::new(RegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("registry credential Relay activates once");
    let missing_nonce = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(fresh_oidc_principal(
            Some("client_id:citizen-portal"),
            &["subject_access"],
        ))),
        None,
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer),
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;
    assert_eq!(missing_nonce.status(), StatusCode::BAD_REQUEST);
    let missing_nonce_body = axum::body::to_bytes(missing_nonce.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let missing_nonce_body: Value =
        serde_json::from_slice(&missing_nonce_body).expect("error body parses");
    assert_eq!(missing_nonce_body["error"], "invalid_proof");

    let proof_without_nonce = sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer);
    let missing_validated_nonce = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(oid4vci_authorized_principal(
            &evidence,
            &subject_access,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["subject_access", "person_is_alive"],
        ))),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof_without_nonce,
            None,
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof_without_nonce,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;
    assert_eq!(missing_validated_nonce.status(), StatusCode::BAD_REQUEST);
    let missing_validated_nonce_body =
        axum::body::to_bytes(missing_validated_nonce.into_body(), usize::MAX)
            .await
            .expect("body reads");
    let missing_validated_nonce_body: Value =
        serde_json::from_slice(&missing_validated_nonce_body).expect("error body parses");
    assert_eq!(missing_validated_nonce_body["error"], "invalid_proof");

    let nonce = "nonce-1";
    let nonce_key = state
        .subject_access_rate_keys
        .oid4vci_nonce(
            &state.oid4vci.credential_issuer,
            "person_is_alive_sd_jwt",
            nonce,
        )
        .expect("nonce hashes");
    let nonce_scope =
        oid4vci_nonce_replay_scope(&state, "person_is_alive_sd_jwt").expect("nonce scope");
    let nonce_key = ReplayKey::new(nonce_key).expect("nonce replay key");
    state
        .replay
        .nonce_store()
        .reserve_nonce(
            &nonce_scope,
            &nonce_key,
            OffsetDateTime::now_utc() + time::Duration::seconds(60),
        )
        .await
        .expect("nonce reserves");
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
    let request = Oid4vciCredentialRequest {
        format: SD_JWT_VC_FORMAT.to_string(),
        credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
        credential_configuration_id: None,
        vct: None,
        proof: registry_platform_oid4vci::CredentialRequestProof {
            proof_type: PROOF_TYPE_JWT.to_string(),
            jwt: proof.clone(),
        },
        proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
    };
    let validated_proof = validated_oid4vci_proof(&state, &proof, Some(nonce));
    let authorized_principal = oid4vci_authorized_principal(
        &evidence,
        &subject_access,
        &oid4vci,
        "person_is_alive_sd_jwt",
        &["subject_access", "person_is_alive"],
    );
    let classified_principal =
        classify_subject_access_principal(&subject_access, &authorized_principal)
            .expect("OIDC principal classifies as subject access");
    let stored_client_id =
        stored_evaluation_client_id(&state, &classified_principal).expect("stored owner resolves");

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(authorized_principal.clone())),
        Some(Extension(validated_proof.clone())),
        Json(request.clone()),
    )
    .await;

    let denial = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .and_then(|audit| audit.denial_code)
        .map(|code| code.as_str().to_string());
    assert_eq!(
        relay.calls.load(Ordering::SeqCst),
        2,
        "registry Relay must execute before issuance response: {}, denial={denial:?}",
        response.status(),
    );
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body: Value = serde_json::from_slice(&body).expect("credential body parses");
    assert_eq!(body["format"], SD_JWT_VC_FORMAT);
    assert!(
        body["credential"]
            .as_str()
            .is_some_and(|credential| credential.contains('~')),
        "expected compact SD-JWT credential: {body}"
    );
    let evaluation_id = relay
        .evaluation_ids
        .lock()
        .expect("evaluation id lock is not poisoned")
        .first()
        .cloned()
        .expect("Relay observed the projected evaluation id");
    let stored = store
        .get(&evaluation_id, &stored_client_id)
        .await
        .expect("stored evaluation read succeeds")
        .expect("projected registry evaluation is stored");
    let issuance = stored
        .issuance_provenance
        .expect("projected evaluation stores private issuance provenance");
    assert_eq!(issuance.claims.len(), 3);
    assert_eq!(issuance.consultations.len(), 2);
    let claim_ids = issuance
        .claims
        .iter()
        .map(|entry| entry.claim_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_ids,
        BTreeSet::from([
            "civil-record-active",
            "person-is-alive",
            "person-is-registered",
        ])
    );
    assert!(issuance.claims.iter().all(|entry| {
        let expected_pin = if entry.claim_id == "civil-record-active" {
            (
                "example.civil-record.exact",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        } else {
            (
                "example.person-status.exact",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        };
        entry.claim_version == "1"
            && entry.relay_profile_id == expected_pin.0
            && entry.relay_contract_hash == expected_pin.1
            && entry.canonical_purpose == "citizen_subject_access"
            && ulid::Ulid::from_string(&entry.consultation_id).is_ok()
            && entry.execution_binding.starts_with("sha256:")
    }));
    assert!(issuance.consultations.iter().all(|execution| {
        ulid::Ulid::from_string(&execution.consultation_id).is_ok()
            && OffsetDateTime::parse(&execution.acquired_at, &Rfc3339).is_ok()
    }));
    assert!(stored
        .results
        .iter()
        .all(|result| { result.provenance.used.relay_consultation_count == 2 }));

    let replay = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(authorized_principal)),
        Some(Extension(validated_proof)),
        Json(request),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let replay_body = axum::body::to_bytes(replay.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let replay_body: Value = serde_json::from_slice(&replay_body).expect("error body parses");
    assert_eq!(replay_body["error"], "invalid_proof");
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_rejects_tampered_dependency_catalog_before_signing() {
    let store = Arc::new(EvidenceStore::default());
    let subject_access = Arc::new(subject_access_config());
    let mut evidence = registry_backed_oid4vci_evidence_with_dependency();
    let duplicate_dependency = evidence
        .claims
        .iter()
        .find(|claim| claim.id == "civil-record-active")
        .cloned()
        .expect("dependency exists");
    evidence.claims.push(duplicate_dependency);
    let evidence = Arc::new(evidence);
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    oid4vci.nonce.enabled = false;
    let oid4vci = Arc::new(oid4vci);
    let sign_count = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        store,
        Arc::new(CountingIssuerResolver {
            sign_count: Arc::clone(&sign_count),
        }),
    ));
    let relay = Arc::new(RegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("registry credential Relay activates once");
    let proof = sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer);
    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(oid4vci_authorized_principal(
            &evidence,
            &subject_access,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["subject_access", "person_is_alive"],
        ))),
        Some(Extension(validated_oid4vci_proof(&state, &proof, None))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_dependency_execution_tampering_is_denied_before_signing() {
    for tamper_acquired_at in [true, false] {
        let store = Arc::new(EvidenceStore::default());
        let subject_access = Arc::new(subject_access_config());
        let evidence = Arc::new(registry_backed_oid4vci_evidence_with_dependency());
        let mut oid4vci = oid4vci_config();
        oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
        oid4vci.nonce.enabled = false;
        let oid4vci = Arc::new(oid4vci);
        let sign_count = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
        ));
        let relay = Arc::new(RegistryCredentialRelay::default());
        state
            .install_activated_relay(relay.clone())
            .expect("registry credential Relay activates once");
        store.tamper_next_read(move |evaluation| {
            let issuance = evaluation
                .issuance_provenance
                .as_mut()
                .expect("OID evaluation retained a credential-capable closure");
            if tamper_acquired_at {
                let dependency_execution_id = issuance
                    .claims
                    .iter()
                    .find(|claim| claim.claim_id == "civil-record-active")
                    .expect("dependency pin exists")
                    .consultation_id
                    .clone();
                issuance
                    .consultations
                    .iter_mut()
                    .find(|execution| execution.consultation_id == dependency_execution_id)
                    .expect("dependency execution exists")
                    .acquired_at = "2026-05-23T00:00:01Z".to_string();
            } else {
                let dependency_index = issuance
                    .claims
                    .iter()
                    .position(|claim| claim.claim_id == "civil-record-active")
                    .expect("dependency pin exists");
                let root_index = issuance
                    .claims
                    .iter()
                    .position(|claim| claim.claim_id == "person-is-alive")
                    .expect("root pin exists");
                let dependency_id = issuance.claims[dependency_index].consultation_id.clone();
                issuance.claims[dependency_index].consultation_id =
                    issuance.claims[root_index].consultation_id.clone();
                issuance.claims[root_index].consultation_id = dependency_id;
            }
        });
        let proof = sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer);
        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(oid4vci_authorized_principal(
                &evidence,
                &subject_access,
                &oid4vci,
                "person_is_alive_sd_jwt",
                &["subject_access", "person_is_alive"],
            ))),
            Some(Extension(validated_oid4vci_proof(&state, &proof, None))),
            Json(Oid4vciCredentialRequest {
                format: SD_JWT_VC_FORMAT.to_string(),
                credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
                credential_configuration_id: None,
                vct: None,
                proof: registry_platform_oid4vci::CredentialRequestProof {
                    proof_type: PROOF_TYPE_JWT.to_string(),
                    jwt: proof,
                },
                proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
        assert_eq!(sign_count.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn oid4vci_rejects_holder_key_equal_to_issuer_key_after_registry_evaluation() {
    let store = Arc::new(EvidenceStore::default());
    let subject_access = subject_access_config();
    let evidence = registry_backed_oid4vci_evidence_config();
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let evidence = Arc::new(evidence);
    let subject_access = Arc::new(subject_access);
    let oid4vci = Arc::new(oid4vci);
    let state = Arc::new(RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
        Arc::clone(&evidence),
        Arc::clone(&subject_access),
        Arc::clone(&oid4vci),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::clone(&store),
        Arc::new(HolderIssuerResolver),
    ));
    let relay = Arc::new(RegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("registry credential Relay activates once");
    let nonce = "nonce-equal-key";
    let nonce_key = state
        .subject_access_rate_keys
        .oid4vci_nonce(
            &state.oid4vci.credential_issuer,
            "person_is_alive_sd_jwt",
            nonce,
        )
        .expect("nonce hashes");
    let nonce_scope =
        oid4vci_nonce_replay_scope(&state, "person_is_alive_sd_jwt").expect("nonce scope");
    let nonce_key = ReplayKey::new(nonce_key).expect("nonce replay key");
    state
        .replay
        .nonce_store()
        .reserve_nonce(
            &nonce_scope,
            &nonce_key,
            OffsetDateTime::now_utc() + time::Duration::seconds(60),
        )
        .await
        .expect("nonce reserves");
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(oid4vci_authorized_principal(
            &evidence,
            &subject_access,
            &oid4vci,
            "person_is_alive_sd_jwt",
            &["subject_access", "person_is_alive"],
        ))),
        Some(Extension(validated_oid4vci_proof(
            &state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
            credential_configuration_id: None,
            vct: None,
            proof: registry_platform_oid4vci::CredentialRequestProof {
                proof_type: PROOF_TYPE_JWT.to_string(),
                jwt: proof,
            },
            proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
        }),
    )
    .await;

    let denial = response
        .extensions()
        .get::<EvidenceAuditContext>()
        .and_then(|audit| audit.denial_code)
        .map(|code| code.as_str().to_string());
    assert_eq!(
        relay.calls.load(Ordering::SeqCst),
        1,
        "registry Relay must execute before holder and issuer keys are compared: {}, denial={denial:?}",
        response.status(),
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&nonce_scope, &nonce_key)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::AlreadySeen
    ));
}

#[test]
fn oid4vci_single_proof_jwt_accepts_proofs_array() {
    let mut request = Oid4vciCredentialRequest {
        format: SD_JWT_VC_FORMAT.to_string(),
        credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
        credential_configuration_id: None,
        vct: None,
        proof: registry_platform_oid4vci::CredentialRequestProof {
            proof_type: String::new(),
            jwt: String::new(),
        },
        proofs: registry_platform_oid4vci::CredentialRequestProofs {
            jwt: vec!["array-proof.jwt.sig".to_string()],
        },
    };

    assert_eq!(
        oid4vci_single_proof_jwt(&request).expect("single array proof is accepted"),
        "array-proof.jwt.sig"
    );

    request.proofs.jwt.push("second-proof.jwt.sig".to_string());
    assert_eq!(
        oid4vci_single_proof_jwt(&request),
        Err(Oid4vciWireError::InvalidProof)
    );
}

#[test]
fn oid4vci_credential_request_rejects_ambiguous_configuration_ids() {
    let mut request = Oid4vciCredentialRequest {
        format: SD_JWT_VC_FORMAT.to_string(),
        credential_identifier: Some("person_is_alive_sd_jwt".to_string()),
        credential_configuration_id: Some("other_sd_jwt".to_string()),
        vct: None,
        proof: registry_platform_oid4vci::CredentialRequestProof {
            proof_type: PROOF_TYPE_JWT.to_string(),
            jwt: "a.b.c".to_string(),
        },
        proofs: registry_platform_oid4vci::CredentialRequestProofs::default(),
    };

    assert_eq!(
        oid4vci_configuration_for_request(&oid4vci_config(), &request),
        Err(Oid4vciWireError::InvalidRequest)
    );

    request.credential_configuration_id = Some("person_is_alive_sd_jwt".to_string());
    request.vct = Some("https://issuer.example/credentials/other".to_string());
    assert_eq!(
        oid4vci_configuration_for_request(&oid4vci_config(), &request),
        Err(Oid4vciWireError::InvalidRequest)
    );
}

#[test]
fn oid4vci_issuance_authorization_details_bind_selected_configuration() {
    let evidence = oid4vci_evidence_config();
    let config = subject_access_config();
    let oid4vci = oid4vci_config();
    let configuration = oid4vci
        .credential_configurations
        .get("person_is_alive_sd_jwt")
        .expect("configuration exists");

    let details = oid4vci_issuance_authorization_details(&evidence, &config, configuration)
        .expect("details build");

    assert_eq!(details.actions, vec!["evaluate"]);
    assert_eq!(details.locations, vec![evidence.service_id.clone()]);
    assert_eq!(details.claims, vec![ClaimRef::from("person-is-alive")]);
    assert_eq!(details.disclosure.as_deref(), Some("predicate"));
    assert_eq!(details.format.as_deref(), Some(FORMAT_CLAIM_RESULT_JSON));
    assert_eq!(details.purpose.as_deref(), Some("citizen_subject_access"));
    assert_eq!(details.access_mode, Some(AccessMode::SubjectBound));
    let subject = details.subject.as_ref().expect("subject binding is set");
    assert_eq!(subject.binding_claim, SUBJECT_BINDING_CLAIM);
    assert_eq!(subject.id_type, "national_id");

    let principal = oid4vci_authorized_principal(
        &evidence,
        &config,
        &oid4vci,
        "person_is_alive_sd_jwt",
        &["subject_access", "person_is_alive"],
    );
    require_oid4vci_issuance_authorization_details(
        &evidence,
        &config,
        configuration,
        &principal,
        true,
    )
    .expect("matching details authorize issuance");

    let direct_esignet_principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    require_oid4vci_issuance_authorization_details(
        &evidence,
        &config,
        configuration,
        &direct_esignet_principal,
        false,
    )
    .expect("direct eSignet tokens can rely on scope without RAR details");
}

#[test]
fn oid4vci_issuance_authorization_details_fail_closed_for_empty_notary_details() {
    let evidence = oid4vci_evidence_config();
    let config = subject_access_config();
    let oid4vci = oid4vci_config();
    let configuration = oid4vci
        .credential_configurations
        .get("person_is_alive_sd_jwt")
        .expect("configuration exists");
    let mut principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    principal.authorization_details = Some(EvidenceAuthorizationDetails {
        detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
            .to_string(),
        legal_basis_ref: Some("wallet-compat-context".to_string()),
        ..EvidenceAuthorizationDetails::default()
    });

    require_oid4vci_issuance_authorization_details(
        &evidence,
        &config,
        configuration,
        &principal,
        false,
    )
    .expect("direct eSignet/OIDC tokens can carry context-only details");

    let err = require_oid4vci_issuance_authorization_details(
        &evidence,
        &config,
        configuration,
        &principal,
        true,
    )
    .expect_err("Notary-issued tokens must carry transaction-scoped details");

    assert!(matches!(
        err,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::OperationDenied
        }
    ));
}

#[test]
fn oid4vci_requires_authorization_details_for_custom_notary_access_typ() {
    let runtime_config = runtime_config_with_custom_access_token_typ();
    let mut principal = fresh_oidc_principal(
        Some("client_id:citizen-portal"),
        &["subject_access", "person_is_alive"],
    );
    {
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.issuer = bounded("https://notary.example.test");
        claims.token_type = Some(bounded("custom-notary-access+jwt"));
    }

    assert!(oid4vci_requires_authorization_details(
        &principal,
        Some(&runtime_config),
        None
    ));

    principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .issuer = bounded("https://id.example.gov");

    assert!(!oid4vci_requires_authorization_details(
        &principal,
        Some(&runtime_config),
        None
    ));

    {
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.issuer = bounded("https://notary.example.test");
        claims.token_type = Some(bounded(
            registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        ));
    }

    assert!(oid4vci_requires_authorization_details(
        &principal,
        Some(&runtime_config),
        None
    ));

    principal
        .verified_claims
        .as_mut()
        .expect("test principal has claims")
        .issuer = bounded("https://id.example.gov");

    assert!(!oid4vci_requires_authorization_details(
        &principal,
        Some(&runtime_config),
        None
    ));
}

#[test]
fn oid4vci_rejects_holder_key_equal_to_issuer_key() {
    let issuer = registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
        &issuer_private_jwk(),
        "did:web:issuer.example#key-1".to_string(),
    )
    .expect("issuer parses");
    let issuer_public =
        PublicJwk::parse(&issuer.public_jwk().to_string()).expect("issuer public parses");
    let holder_public = PrivateJwk::parse(&holder_private_jwk())
        .expect("holder parses")
        .public();

    assert!(holder_key_matches_issuer_key(
        &issuer_public,
        &issuer.public_jwk()
    ));
    assert!(!holder_key_matches_issuer_key(
        &holder_public,
        &issuer.public_jwk()
    ));
}

#[test]
fn holder_proof_audience_must_match_configured_service_id() {
    // Aim: the holder proof JWT's `aud` is bound to the configured
    // service_id, not the hard-coded literal "registry-notary".
    let holder_id = holder_did_jwk();
    let service_id = "my.notary.example";
    let request = issue_request();
    let evaluation = evaluation_for_proof();

    let proof_matching = sign_holder_proof(&holder_id, proof_payload(&holder_id, service_id));
    validate_holder_proof_payload(
        &proof_matching,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect("proof signed with aud=service_id must be accepted");

    let proof_legacy_literal =
        sign_holder_proof(&holder_id, proof_payload(&holder_id, "registry-notary"));
    let err = validate_holder_proof_payload(
        &proof_legacy_literal,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect_err("proof with aud=\"registry-notary\" must be rejected when service_id differs");
    assert!(matches!(err, EvidenceError::HolderProofRequired));
}

#[test]
fn holder_proof_exp_window_is_bounded_below_and_above() {
    // The accepted lifetime is a strictly positive interval up to 300s.
    // Anything outside that window must be rejected before reaching the
    // replay-key path.
    let holder_id = holder_did_jwk();
    let service_id = "my.notary.example";
    let request = issue_request();
    let evaluation = evaluation_for_proof();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let proof_zero_window = sign_holder_proof(
        &holder_id,
        windowed_proof_payload(&holder_id, service_id, now, now),
    );
    let err = validate_holder_proof_payload(
        &proof_zero_window,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect_err("exp == iat must be rejected");
    assert!(matches!(err, EvidenceError::HolderProofRequired));

    let proof_backdated = sign_holder_proof(
        &holder_id,
        windowed_proof_payload(&holder_id, service_id, now, now - 60),
    );
    let err = validate_holder_proof_payload(
        &proof_backdated,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect_err("exp < iat must be rejected");
    assert!(matches!(err, EvidenceError::HolderProofRequired));

    let proof_over_ceiling = sign_holder_proof(
        &holder_id,
        windowed_proof_payload(&holder_id, service_id, now, now + 301),
    );
    let err = validate_holder_proof_payload(
        &proof_over_ceiling,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect_err("exp > iat + 300 must be rejected");
    assert!(matches!(err, EvidenceError::HolderProofRequired));

    let valid_now = OffsetDateTime::now_utc().unix_timestamp() + 20;
    let proof_just_positive = sign_holder_proof(
        &holder_id,
        windowed_proof_payload(&holder_id, service_id, valid_now, valid_now + 1),
    );
    validate_holder_proof_payload(
        &proof_just_positive,
        &holder_id,
        "profile-a",
        &request,
        &evaluation,
        service_id,
    )
    .expect("exp = iat + 1 must be accepted");
}
