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
    assert!(metadata.get("nonce_endpoint").is_none());
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
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::new(oid4vci_evidence_config()),
            Arc::new(delegated_subject_access_config()),
            Arc::new(oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
        )
        .with_preauth_runtime(Some(oid4vci_test_preauth_runtime(
            registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        ))),
    );
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
async fn oid4vci_source_free_bypass_denies_before_offer_or_signer_access() {
    let store = Arc::new(EvidenceStore::default());
    let evidence = Arc::new(oid4vci_evidence_config());
    assert!(evidence.claims[0].evidence_mode.is_self_attested());
    let subject_access = Arc::new(subject_access_config());
    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let oid4vci = Arc::new(oid4vci);
    let sign_count = Arc::new(AtomicUsize::new(0));
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            oid4vci_test_audit_hasher(),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let transaction_id = ulid::Ulid::new().to_string();
    let err = prepare_registry_backed_issuance_transaction(
        &state,
        &preauth,
        &BoundSubject {
            subject: "citizen-subject".to_string(),
            subject_binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
            subject_binding_value: "NAT-123".to_string(),
            client_id: "citizen-portal".to_string(),
            scopes: vec!["subject_access".to_string()],
            acr: Some("urn:example:loa:substantial".to_string()),
            auth_time: Some(now),
        },
        "person_is_alive_sd_jwt",
        &transaction_id,
        None,
    )
    .await
    .expect_err("source-free configuration is credential-ineligible");

    assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
    assert_eq!(sign_count.load(Ordering::SeqCst), 0);
    assert!(preauth
        .preauthorization_state()
        .transaction(&transaction_id)
        .await
        .expect("transaction state is available")
        .is_none());
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
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
        )
        .with_preauth_runtime(Some(oid4vci_test_preauth_runtime(
            registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        ))),
    );
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
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
        )
        .with_preauth_runtime(Some(oid4vci_test_preauth_runtime(
            registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        ))),
    );
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
        .with_runtime_config(runtime_config)
        .with_preauth_runtime(Some(oid4vci_test_preauth_runtime(
            "custom-notary-access+jwt",
        ))),
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
#[derive(Debug, Default)]
struct StructuredRegistryCredentialRelay {
    calls: AtomicUsize,
}

#[cfg(feature = "registry-notary-cel")]
#[async_trait::async_trait]
impl crate::runtime::ActivatedRelayConsultations for StructuredRegistryCredentialRelay {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        let outputs =
            crate::runtime::consultation::RuntimeRelayOutputMap::from_json(BTreeMap::from([(
                "record".to_string(),
                json!({
                    "name": "Ada",
                    "parents": [
                        { "identifier": "PARENT-2", "name": "Grace" },
                        { "identifier": "PARENT-1", "name": "Charles" }
                    ]
                }),
            )]))?;
        crate::runtime::consultation::RuntimeRelayConsultationResult::new(
            ulid::Ulid::new(),
            crate::runtime::consultation::RuntimeRelayOutcome::Match,
            Some(crate::runtime::consultation::RuntimeRelayMatchData::OutputMap(outputs)),
            OffsetDateTime::now_utc(),
        )
    }
}

#[cfg(feature = "registry-notary-cel")]
fn structured_oid4vci_configs() -> (SubjectAccessConfig, EvidenceConfig, Oid4vciConfig) {
    let mut subject_access = subject_access_config();
    subject_access.allowed_disclosures = vec!["value".to_string()];

    let mut evidence = registry_backed_oid4vci_evidence_config();
    let claim = evidence
        .claims
        .iter_mut()
        .find(|claim| claim.id == "person-is-alive")
        .expect("OID4VCI claim exists");
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
        panic!("OID4VCI claim is registry backed");
    };
    let consultation = consultations
        .get_mut("person_status")
        .expect("OID4VCI consultation exists");
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
        .expect("OID4VCI credential profile exists")
        .disclosure
        .allowed = vec!["value".to_string()];

    let mut oid4vci = oid4vci_config();
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let configuration = oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("OID4VCI credential configuration exists");
    configuration.claim_id = None;
    configuration.claims = vec![registry_notary_core::Oid4vciCredentialClaimConfig {
        id: "person-is-alive".to_string(),
        output_path: vec!["person_record".to_string()],
        display_name: "Person record".to_string(),
        sd: "always".to_string(),
    }];
    (subject_access, evidence, oid4vci)
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_preserves_structured_result_as_one_verifiable_sd_jwt_disclosure() {
    let store = Arc::new(EvidenceStore::default());
    let (subject_access, evidence, oid4vci) = structured_oid4vci_configs();
    let evidence = Arc::new(evidence);
    let subject_access = Arc::new(subject_access);
    let oid4vci = Arc::new(oid4vci);
    let sign_count = Arc::new(AtomicUsize::new(0));
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            oid4vci_test_audit_hasher(),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
    let relay = Arc::new(StructuredRegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("structured Registry Relay activates once");
    let nonce = "structured-oid4vci-nonce";
    let test_transaction = reserve_registry_backed_oid4vci_test_transaction(
        &state,
        &preauth,
        "person_is_alive_sd_jwt",
        nonce,
    )
    .await;
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);

    let stored = store
        .get(
            &test_transaction.transaction.evaluation_id,
            &test_transaction.transaction.evaluation_client_id,
        )
        .await
        .expect("structured evaluation reads")
        .expect("structured evaluation is stored");
    let expected_value = json!({
        "name": "Ada",
        "parents": [
            { "identifier": "PARENT-2", "name": "Grace" },
            { "identifier": "PARENT-1", "name": "Charles" }
        ]
    });
    assert_eq!(stored.results[0].value, Some(expected_value.clone()));
    assert_eq!(stored.results[0].disclosure, "value");

    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(test_transaction.principal)),
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OID4VCI credential body reads");
    let body: Value = serde_json::from_slice(&body).expect("OID4VCI credential body parses");
    let compact = body["credential"]
        .as_str()
        .expect("OID4VCI returns compact SD-JWT");
    let parts = compact
        .split('~')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        parts.len(),
        2,
        "OID4VCI presents the complete structured result as one disclosure"
    );
    let decoded: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("OID4VCI disclosure is base64url"),
    )
    .expect("OID4VCI disclosure is JSON");
    assert_eq!(decoded[1], json!("person_record"));
    assert_eq!(decoded[2], expected_value);
    let payload = decode_jwt_payload(parts[0]);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(parts[1].as_bytes()));
    assert!(payload["_sd"]
        .as_array()
        .is_some_and(|digests| digests.contains(&json!(digest))));
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_projected_registry_credential_issues_and_caches_exact_retry() {
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
    let sign_count = Arc::new(AtomicUsize::new(0));
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            oid4vci_test_audit_hasher(),
            Arc::clone(&store),
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
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

    let nonce = "nonce-1";
    let test_transaction = reserve_registry_backed_oid4vci_test_transaction(
        &state,
        &preauth,
        "person_is_alive_sd_jwt",
        nonce,
    )
    .await;
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);

    let proof_without_nonce = sign_oid4vci_proof_without_nonce(&state.oid4vci.credential_issuer);
    let missing_validated_nonce = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(test_transaction.principal.clone())),
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
    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(test_transaction.principal.clone())),
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
    let stored = store
        .get(
            &test_transaction.transaction.evaluation_id,
            &test_transaction.transaction.evaluation_client_id,
        )
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

    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
    assert!(matches!(
        state
            .replay
            .nonce_store()
            .consume_nonce(&test_transaction.nonce_scope, &test_transaction.nonce_key,)
            .await
            .expect("nonce store is available"),
        ReplayInsertOutcome::AlreadySeen
    ));

    let retry = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(test_transaction.principal)),
        Some(Extension(validated_proof)),
        Json(request),
    )
    .await;
    assert_eq!(retry.status(), StatusCode::OK);
    let retry_body = axum::body::to_bytes(retry.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let retry_body: Value = serde_json::from_slice(&retry_body).expect("credential body parses");
    assert_eq!(retry_body, body);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
    assert_eq!(sign_count.load(Ordering::SeqCst), 1);
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
    let oid4vci = Arc::new(oid4vci);
    let sign_count = Arc::new(AtomicUsize::new(0));
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            AuditKeyHasher::unkeyed_dev_only(),
            store,
            Arc::new(CountingIssuerResolver {
                sign_count: Arc::clone(&sign_count),
            }),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
    let relay = Arc::new(RegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("registry credential Relay activates once");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let err = prepare_registry_backed_issuance_transaction(
        &state,
        &preauth,
        &BoundSubject {
            subject: "citizen-subject".to_string(),
            subject_binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
            subject_binding_value: "NAT-123".to_string(),
            client_id: "citizen-portal".to_string(),
            scopes: vec!["subject_access".to_string()],
            acr: Some("urn:example:loa:substantial".to_string()),
            auth_time: Some(now),
        },
        "person_is_alive_sd_jwt",
        &ulid::Ulid::new().to_string(),
        None,
    )
    .await
    .expect_err("duplicate dependency catalog is rejected before an offer");

    assert!(matches!(err, EvidenceError::EvaluationBindingMismatch));
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
        let oid4vci = Arc::new(oid4vci);
        let sign_count = Arc::new(AtomicUsize::new(0));
        let preauth =
            oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
        let state = Arc::new(
            RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
                Arc::clone(&evidence),
                Arc::clone(&subject_access),
                Arc::clone(&oid4vci),
                oid4vci_test_audit_hasher(),
                Arc::clone(&store),
                Arc::new(CountingIssuerResolver {
                    sign_count: Arc::clone(&sign_count),
                }),
            )
            .with_preauth_runtime(Some(Arc::clone(&preauth))),
        );
        let relay = Arc::new(RegistryCredentialRelay::default());
        state
            .install_activated_relay(relay.clone())
            .expect("registry credential Relay activates once");
        let nonce = if tamper_acquired_at {
            "tampered-acquired-at-nonce"
        } else {
            "tampered-consultation-binding-nonce"
        };
        let test_transaction = reserve_registry_backed_oid4vci_test_transaction(
            &state,
            &preauth,
            "person_is_alive_sd_jwt",
            nonce,
        )
        .await;
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
        let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);
        let response = oid4vci_credential(
            Some(Extension(Arc::clone(&state))),
            Some(Extension(test_transaction.principal)),
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
    let preauth =
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP);
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::clone(&subject_access),
            Arc::clone(&oid4vci),
            oid4vci_test_audit_hasher(),
            Arc::clone(&store),
            Arc::new(HolderIssuerResolver),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
    let relay = Arc::new(RegistryCredentialRelay::default());
    state
        .install_activated_relay(relay.clone())
        .expect("registry credential Relay activates once");
    let nonce = "nonce-equal-key";
    let test_transaction = reserve_registry_backed_oid4vci_test_transaction(
        &state,
        &preauth,
        "person_is_alive_sd_jwt",
        nonce,
    )
    .await;
    let proof = sign_oid4vci_proof(&state.oid4vci.credential_issuer, nonce);

    let response = oid4vci_credential(
        Some(Extension(Arc::clone(&state))),
        Some(Extension(test_transaction.principal)),
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
            .consume_nonce(&test_transaction.nonce_scope, &test_transaction.nonce_key,)
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

const REGISTRY_OFFER_CONFIGURATION_ID: &str = "person_is_alive_sd_jwt";
#[cfg(feature = "registry-notary-cel")]
const REGISTRY_OFFER_EVALUATE_SCOPE: &str = "registry:evidence";
#[cfg(feature = "registry-notary-cel")]
const REGISTRY_OFFER_PRINCIPAL_ID: &str = "registrar-a";
#[cfg(feature = "registry-notary-cel")]
const REGISTRY_OFFER_PURPOSE: &str = "citizen_subject_access";

#[cfg(feature = "registry-notary-cel")]
struct RegistryOfferTestFixture {
    state: Arc<RegistryNotaryApiState>,
    preauth: Arc<PreAuthRuntime>,
    principal: EvidencePrincipal,
    store: Arc<EvidenceStore>,
}

#[cfg(feature = "registry-notary-cel")]
fn registry_offer_test_evidence() -> EvidenceConfig {
    let mut evidence = registry_backed_oid4vci_evidence_config();
    evidence.allowed_purposes = vec![REGISTRY_OFFER_PURPOSE.to_string()];
    let claim = evidence.claims.first_mut().expect("claim exists");
    claim.required_scopes = vec![REGISTRY_OFFER_EVALUATE_SCOPE.to_string()];
    claim.disclosure.default = DisclosureProfile::Value.as_str().to_string();
    claim.disclosure.allowed = vec![DisclosureProfile::Value.as_str().to_string()];
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .disclosure
        .allowed = vec![DisclosureProfile::Value.as_str().to_string()];
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
    evidence
}

#[cfg(feature = "registry-notary-cel")]
fn registry_offer_test_oid4vci() -> Oid4vciConfig {
    let mut oid4vci = oid4vci_config();
    oid4vci.pre_authorized_code.enabled = true;
    oid4vci.accepted_token_audiences = vec!["registry-notary-citizen".to_string()];
    let configuration = oid4vci
        .credential_configurations
        .get_mut(REGISTRY_OFFER_CONFIGURATION_ID)
        .expect("registry offer credential configuration exists");
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
    oid4vci
}

#[cfg(feature = "registry-notary-cel")]
fn registry_offer_machine_principal(
    state: &RegistryNotaryApiState,
    principal_id: &str,
) -> EvidencePrincipal {
    let configuration = &state.oid4vci.credential_configurations[REGISTRY_OFFER_CONFIGURATION_ID];
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: principal_id.to_string(),
        scopes: vec![
            REGISTRY_OFFER_EVALUATE_SCOPE.to_string(),
            REGISTRY_OFFER_CREATE_SCOPE.to_string(),
            configuration.scope.clone(),
        ],
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    }
}

#[cfg(feature = "registry-notary-cel")]
fn registry_offer_authorization_details(
    state: &RegistryNotaryApiState,
    target_id: &str,
) -> EvidenceAuthorizationDetails {
    EvidenceAuthorizationDetails {
        detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE.to_string(),
        schema_version: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
            .to_string(),
        actions: vec!["create_credential_offer".to_string()],
        locations: vec![state.evidence.service_id.clone()],
        // Deliberately reverse configuration order. Authorization is an exact
        // set; configuration order is authoritative only for projection.
        claims: vec![
            ClaimRef::from("person-is-registered"),
            ClaimRef::from("person-is-alive"),
        ],
        disclosure: Some(DisclosureProfile::Value.as_str().to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some(REGISTRY_OFFER_PURPOSE.to_string()),
        target: Some(registry_notary_core::EvidenceAuthorizationTarget {
            id_type: "national_id".to_string(),
            id: target_id.to_string(),
        }),
        access_mode: Some(AccessMode::MachineClient),
        ..Default::default()
    }
}

#[cfg(feature = "registry-notary-cel")]
fn registry_offer_headers(idempotency_key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        IDEMPOTENCY_KEY_HEADER,
        HeaderValue::from_str(idempotency_key).expect("test idempotency key is a valid header"),
    );
    headers
}

#[cfg(feature = "registry-notary-cel")]
async fn registry_offer_fixture() -> RegistryOfferTestFixture {
    registry_offer_fixture_with(
        registry_offer_test_evidence(),
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP),
    )
    .await
}

#[cfg(feature = "registry-notary-cel")]
async fn registry_offer_fixture_with(
    evidence: EvidenceConfig,
    preauth: Arc<PreAuthRuntime>,
) -> RegistryOfferTestFixture {
    let evidence = Arc::new(evidence);
    let oid4vci = Arc::new(registry_offer_test_oid4vci());
    let store = Arc::new(EvidenceStore::default());
    let mut subject_access = subject_access_config();
    subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 5;
    let state = Arc::new(
        RegistryNotaryApiState::new_with_subject_access_and_oid4vci(
            Arc::clone(&evidence),
            Arc::new(subject_access),
            oid4vci,
            oid4vci_test_audit_hasher(),
            Arc::clone(&store),
            Arc::new(TestIssuerResolver),
        )
        .with_preauth_runtime(Some(Arc::clone(&preauth))),
    );
    state
        .install_activated_relay(Arc::new(RegistryCredentialRelay::default()))
        .expect("registry offer test Relay activates once");
    let principal = registry_offer_machine_principal(&state, REGISTRY_OFFER_PRINCIPAL_ID);
    RegistryOfferTestFixture {
        state,
        preauth,
        principal,
        store,
    }
}

#[cfg(feature = "registry-notary-cel")]
async fn registry_offer_evaluate(fixture: &RegistryOfferTestFixture, target_id: &str) -> String {
    let mut request = evaluate_request(target_id);
    request.claims = vec![
        ClaimRef::from("person-is-registered"),
        ClaimRef::from("person-is-alive"),
    ];
    let target = request.target.as_mut().expect("evaluation target exists");
    target.id = Some(format!("registry-record:{target_id}"));
    target
        .identifiers
        .push(registry_notary_core::EvidenceIdentifier {
            scheme: "registry_file_number".to_string(),
            value: format!("FILE-{target_id}"),
            issuer: Some("civil-registry".to_string()),
            country: Some("ZZ".to_string()),
        });
    target
        .attributes
        .insert("registry_region".to_string(), json!("central"));
    request.disclosure = Some(DisclosureProfile::Value.as_str().to_string());
    request.purpose = Some(REGISTRY_OFFER_PURPOSE.to_string());
    let response = evaluate(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(fixture.principal.clone())),
        None,
        Ok(Json(request)),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "registry-client evaluation succeeds"
    );
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("evaluation body reads");
    let body: Value = serde_json::from_slice(&body).expect("evaluation body parses");
    body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id is returned")
        .to_string()
}

#[cfg(feature = "registry-notary-cel")]
async fn registry_offer_create(
    fixture: &RegistryOfferTestFixture,
    principal: EvidencePrincipal,
    evaluation_id: &str,
    idempotency_key: &str,
) -> Response {
    oid4vci_create_registry_offer(
        registry_offer_headers(idempotency_key),
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(principal)),
        Ok(Json(Oid4vciRegistryOfferRequest {
            evaluation_id: evaluation_id.to_string(),
            credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
        })),
    )
    .await
}

#[cfg(feature = "registry-notary-cel")]
async fn registry_offer_response_json(response: Response) -> Value {
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("offer body reads");
    serde_json::from_slice(&body).expect("offer body parses")
}

#[cfg(feature = "registry-notary-cel")]
fn percent_decode_query_value(encoded: &str) -> String {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                decoded.push((high << 4) | low);
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).expect("offer query is UTF-8")
}

#[cfg(feature = "registry-notary-cel")]
fn credential_offer_from_uri(uri: &str) -> Value {
    let encoded = uri
        .strip_prefix("openid-credential-offer://?credential_offer=")
        .expect("credential offer URI uses the registered scheme");
    serde_json::from_str(&percent_decode_query_value(encoded)).expect("credential offer parses")
}

#[cfg(feature = "registry-notary-cel")]
fn form_encoded_token_request(pre_authorized_code: &str, tx_code: &str) -> Bytes {
    Bytes::from(format!(
        "grant_type={}&pre-authorized_code={}&tx_code={}",
        url_percent_encode(PRE_AUTHORIZED_CODE_GRANT_TYPE),
        url_percent_encode(pre_authorized_code),
        url_percent_encode(tx_code),
    ))
}

#[cfg(feature = "registry-notary-cel")]
fn principal_from_registry_offer_access_token(
    fixture: &RegistryOfferTestFixture,
    access_token: &str,
) -> EvidencePrincipal {
    let verified = verify_notary_token(
        access_token,
        fixture.preauth.access_token_verification_keys()[0].public_jwk(),
        fixture.preauth.access_token_typ(),
        fixture.preauth.notary_issuer(),
        fixture.preauth.notary_audiences(),
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .expect("access token verifies");
    let payload = &verified.payload;
    let audiences = match &payload["aud"] {
        Value::String(audience) => vec![bounded(audience)],
        Value::Array(audiences) => audiences
            .iter()
            .map(|audience| bounded(audience.as_str().expect("audience is a string")))
            .collect(),
        _ => panic!("access token has a string or array audience"),
    };
    let authorization_details = payload["authorization_details"]
        .as_array()
        .and_then(|details| details.first())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .expect("authorization details parse");
    EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::NotaryAccessToken,
        principal_id: payload["sub"]
            .as_str()
            .expect("access token subject")
            .to_string(),
        scopes: verified.scopes(),
        access_mode: AccessMode::MachineClient,
        verified_claims: Some(BoundedVerifiedClaims {
            issuer: bounded(payload["iss"].as_str().expect("access token issuer")),
            audiences,
            client_id: payload["client_id"]
                .as_str()
                .map(|client_id| bounded(&format!("client_id:{client_id}"))),
            token_type: payload["token_type"].as_str().map(bounded),
            credential_configuration_id: payload["credential_configuration_id"]
                .as_str()
                .map(bounded),
            issuance_transaction_id: payload["issuance_transaction_id"].as_str().map(bounded),
            issuance_transaction_commitment: payload["issuance_transaction_commitment"]
                .as_str()
                .map(bounded),
            scopes: verified
                .scopes()
                .iter()
                .map(|scope| bounded(scope))
                .collect(),
            subject: payload["sub"].as_str().map(bounded),
            subject_binding_claim: Some(
                VerifiedClaimName::new(&fixture.state.subject_access.subject_binding.token_claim)
                    .expect("subject-binding claim is bounded"),
            ),
            subject_binding_value: payload
                [&fixture.state.subject_access.subject_binding.token_claim]
                .as_str()
                .map(bounded),
            acr: None,
            auth_time: None,
            exp: payload["exp"].as_i64(),
            iat: payload["iat"].as_i64(),
            nbf: payload["nbf"].as_i64(),
        }),
        authorization_details,
    }
}

#[test]
fn oid4vci_registry_offer_request_has_a_closed_minimal_wire_shape() {
    let valid = json!({
        "evaluation_id": "01KTEST",
        "credential_configuration_id": REGISTRY_OFFER_CONFIGURATION_ID,
    });
    serde_json::from_value::<Oid4vciRegistryOfferRequest>(valid.clone())
        .expect("the two-field request parses");

    let mut missing_evaluation = valid.clone();
    missing_evaluation
        .as_object_mut()
        .expect("request is an object")
        .remove("evaluation_id");
    assert!(serde_json::from_value::<Oid4vciRegistryOfferRequest>(missing_evaluation).is_err());

    let mut extra_target = valid;
    extra_target["target_id"] = json!("NAT-SECRET");
    assert!(serde_json::from_value::<Oid4vciRegistryOfferRequest>(extra_target).is_err());
}

#[test]
fn oid4vci_registry_offer_unavailable_response_is_explicitly_retryable() {
    let response = registry_offer_problem(StatusCode::SERVICE_UNAVAILABLE, "offer_unavailable");
    assert_eq!(
        response.headers()[header::RETRY_AFTER],
        HeaderValue::from_static(REGISTRY_OFFER_OPERATION_RETRY_AFTER_SECONDS)
    );
}

#[test]
fn oid4vci_token_audit_mode_follows_issuance_authority_without_exposing_values() {
    assert_eq!(
        issuance_authority_access_mode(&IssuanceAuthority::SubjectAccess),
        AccessMode::SubjectBound
    );
    let authority = IssuanceAuthority::RegistryClient {
        initiating_client_id: "registrar-audit-secret".to_string(),
        initiating_client_id_hash: "hmac-sha256:registrar".to_string(),
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        authorized_scopes: vec![REGISTRY_OFFER_CREATE_SCOPE.to_string()],
        target_ref: TargetRefView {
            entity_type: "Person".to_string(),
            handle: "hmac-sha256:target-secret".to_string(),
            identifier_schemes: vec!["national_id".to_string()],
            profile: None,
        },
        service_id: "https://notary.example.test".to_string(),
        purpose: "audit-purpose-secret".to_string(),
    };
    assert_eq!(
        issuance_authority_access_mode(&authority),
        AccessMode::MachineClient
    );
    let debug = format!("{authority:?}");
    assert!(!debug.contains("registrar-audit-secret"));
    assert!(!debug.contains("target-secret"));
    assert!(!debug.contains("audit-purpose-secret"));
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_completes_machine_evaluation_to_wallet_credential() {
    let fixture = registry_offer_fixture().await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-REGISTRAR-001").await;
    let mut short_evaluation = fixture
        .store
        .get(&evaluation_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists");
    short_evaluation.expires_at =
        format_time(OffsetDateTime::now_utc() + time::Duration::seconds(90));
    fixture
        .store
        .insert(short_evaluation)
        .await
        .expect("short evaluation lifetime fixture writes");
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-REGISTRAR-001",
    ));

    let offer_response = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-offer-journey",
    )
    .await;
    assert_eq!(offer_response.status(), StatusCode::OK);
    assert_eq!(
        offer_response.headers()[header::CACHE_CONTROL],
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        offer_response.headers()[header::PRAGMA],
        HeaderValue::from_static("no-cache")
    );
    let offer_body = registry_offer_response_json(offer_response).await;
    let offer_uri = offer_body["credential_offer_uri"]
        .as_str()
        .expect("offer URI is returned");
    let tx_code = offer_body["tx_code"]
        .as_str()
        .expect("transaction code is delivered separately");
    assert_eq!(tx_code.len(), 6);
    assert!(tx_code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(
        !offer_uri.contains(tx_code),
        "out-of-band transaction code must not enter the offer URI"
    );
    let offer = credential_offer_from_uri(offer_uri);
    let grant = &offer["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE];
    let pre_authorized_code = grant["pre-authorized_code"]
        .as_str()
        .expect("offer carries a pre-authorized code");
    assert_eq!(grant["tx_code"]["length"], 6);
    let verified_code = verify_notary_token(
        pre_authorized_code,
        fixture.preauth.access_token_verification_keys()[0].public_jwk(),
        PRE_AUTHORIZED_CODE_JWT_TYP,
        fixture.preauth.notary_issuer(),
        &[],
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .expect("pre-authorized code verifies");
    assert!(
        !verified_code.payload.to_string().contains(tx_code),
        "the signed bearer grant must not disclose its second factor"
    );

    let mut token_headers = HeaderMap::new();
    token_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let wrong_tx_code = if tx_code == "000000" {
        "111111"
    } else {
        "000000"
    };
    let wrong_pin_response = oid4vci_token(
        Some(Extension(Arc::clone(&fixture.state))),
        None,
        token_headers.clone(),
        form_encoded_token_request(pre_authorized_code, wrong_tx_code),
    )
    .await;
    assert_eq!(wrong_pin_response.status(), StatusCode::BAD_REQUEST);
    let wrong_pin_body = to_bytes(wrong_pin_response.into_body(), 64 * 1024)
        .await
        .expect("wrong-PIN response reads");
    let wrong_pin_body: Value =
        serde_json::from_slice(&wrong_pin_body).expect("wrong-PIN response parses");
    assert_eq!(wrong_pin_body["error"], "invalid_grant");
    assert!(!wrong_pin_body.to_string().contains(tx_code));
    assert_eq!(
        token_error_audit_event_with_access_mode(
            "/oid4vci/token",
            StatusCode::BAD_REQUEST.as_u16(),
            Some(REGISTRY_OFFER_CONFIGURATION_ID),
            SubjectAccessDenialCode::InvalidToken,
            AccessMode::MachineClient,
        )
        .access_mode,
        Some(AccessMode::MachineClient),
        "the wrong-PIN audit path retains the loaded registry transaction mode",
    );

    let token_response = oid4vci_token(
        Some(Extension(Arc::clone(&fixture.state))),
        None,
        token_headers.clone(),
        form_encoded_token_request(pre_authorized_code, tx_code),
    )
    .await;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body = to_bytes(token_response.into_body(), 64 * 1024)
        .await
        .expect("token response reads");
    let token_body: Value = serde_json::from_slice(&token_body).expect("token response parses");
    let expires_in = token_body["expires_in"]
        .as_u64()
        .expect("access token lifetime is returned");
    assert!(
        (1..=90).contains(&expires_in),
        "access token lifetime is capped to the authoritative transaction remainder",
    );
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token is returned");
    let nonce = token_body["c_nonce"]
        .as_str()
        .expect("credential nonce is returned");
    let wallet_principal = principal_from_registry_offer_access_token(&fixture, access_token);
    assert_eq!(wallet_principal.access_mode(), AccessMode::MachineClient);
    assert_ne!(wallet_principal.principal_id, "NAT-REGISTRAR-001");
    let verified_access = verify_notary_token(
        access_token,
        fixture.preauth.access_token_verification_keys()[0].public_jwk(),
        fixture.preauth.access_token_typ(),
        fixture.preauth.notary_issuer(),
        fixture.preauth.notary_audiences(),
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .expect("access token verifies");
    assert_eq!(
        u64::try_from(
            verified_access.payload["exp"]
                .as_i64()
                .expect("access token exp exists")
                - verified_access.payload["iat"]
                    .as_i64()
                    .expect("access token iat exists"),
        )
        .expect("access token lifetime is positive"),
        expires_in,
    );
    let access_payload = verified_access.payload.to_string();
    assert!(!access_payload.contains(REGISTRY_OFFER_PRINCIPAL_ID));
    assert!(!access_payload.contains("NAT-REGISTRAR-001"));
    assert_eq!(
        verified_access.payload["act"]["type"],
        json!("registry_client")
    );
    let code_replay = oid4vci_token(
        Some(Extension(Arc::clone(&fixture.state))),
        None,
        token_headers,
        form_encoded_token_request(pre_authorized_code, tx_code),
    )
    .await;
    assert_eq!(code_replay.status(), StatusCode::BAD_REQUEST);
    let code_replay_body = to_bytes(code_replay.into_body(), 64 * 1024)
        .await
        .expect("code replay response reads");
    let code_replay_body: Value =
        serde_json::from_slice(&code_replay_body).expect("code replay response parses");
    assert_eq!(code_replay_body["error"], "invalid_grant");
    assert!(!code_replay_body.to_string().contains(tx_code));

    let proof = sign_oid4vci_proof(&fixture.state.oid4vci.credential_issuer, nonce);
    let credential_response = oid4vci_credential(
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(wallet_principal)),
        Some(Extension(validated_oid4vci_proof(
            &fixture.state,
            &proof,
            Some(nonce),
        ))),
        Json(Oid4vciCredentialRequest {
            format: SD_JWT_VC_FORMAT.to_string(),
            credential_identifier: Some(REGISTRY_OFFER_CONFIGURATION_ID.to_string()),
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
    assert_eq!(credential_response.status(), StatusCode::OK);
    let audit = credential_response
        .extensions()
        .get::<EvidenceAuditContext>()
        .expect("credential audit context is attached");
    assert_eq!(audit.access_mode, Some(AccessMode::MachineClient));
    let audit_debug = format!("{audit:?}");
    assert!(!audit_debug.contains("NAT-REGISTRAR-001"));
    assert!(!audit_debug.contains(tx_code));
    let credential_body = to_bytes(credential_response.into_body(), 256 * 1024)
        .await
        .expect("credential response reads");
    let credential_body: Value =
        serde_json::from_slice(&credential_body).expect("credential response parses");
    assert_eq!(credential_body["format"], SD_JWT_VC_FORMAT);
    assert!(credential_body["credential"]
        .as_str()
        .is_some_and(|credential| credential.contains('~')));
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_rejects_elapsed_credential_validity_before_signing() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let preauth = oid4vci_test_preauth_runtime_with_limited_signer(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        0,
    );
    let fixture = registry_offer_fixture_with(registry_offer_test_evidence(), preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-EXPIRED-CREDENTIAL").await;
    let mut evaluation = fixture
        .store
        .get(&evaluation_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists");
    let expired_issued_at = format_time(OffsetDateTime::now_utc() - time::Duration::days(1));
    for result in &mut evaluation.results {
        result.issued_at.clone_from(&expired_issued_at);
    }
    fixture
        .store
        .insert(evaluation)
        .await
        .expect("expired credential-validity fixture writes");
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-EXPIRED-CREDENTIAL",
    ));

    let response = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-expired-credential",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        0,
        "elapsed credential validity rejects before quota or signer work"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_caps_signer_deadline_to_remaining_validity() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let preauth = oid4vci_test_preauth_runtime_with_limited_signer(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        1,
    );
    let mut evidence = registry_offer_test_evidence();
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("registry offer credential profile exists")
        .validity_seconds = 20;
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-SIGNER-DEADLINE").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-SIGNER-DEADLINE",
    ));

    let response = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-signer-deadline",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "the signer runs with a deadline capped to the remaining validity",
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_caps_code_and_transaction_to_credential_validity() {
    const VALIDITY_SECONDS: i64 = 60;
    let mut evidence = registry_offer_test_evidence();
    evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("registry offer credential profile exists")
        .validity_seconds = VALIDITY_SECONDS;
    let fixture = registry_offer_fixture_with(
        evidence,
        oid4vci_test_preauth_runtime(registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP),
    )
    .await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-SHORT-CREDENTIAL").await;
    let evaluation = fixture
        .store
        .get(&evaluation_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists");
    let credential_expires_at = earliest_issued_at(&evaluation.results)
        .expect("registry results have an issuance time")
        + time::Duration::seconds(VALIDITY_SECONDS);
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-SHORT-CREDENTIAL",
    ));

    let response = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-short-credential",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = registry_offer_response_json(response).await;
    let response_expires_at = OffsetDateTime::parse(
        body["expires_at"]
            .as_str()
            .expect("offer response has an expiry"),
        &Rfc3339,
    )
    .expect("offer response expiry parses");
    assert_eq!(
        response_expires_at.unix_timestamp(),
        credential_expires_at.unix_timestamp()
    );
    let offer = credential_offer_from_uri(
        body["credential_offer_uri"]
            .as_str()
            .expect("offer URI is returned"),
    );
    let pre_authorized_code = offer["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]
        ["pre-authorized_code"]
        .as_str()
        .expect("offer carries a pre-authorized code");
    let verified_code = verify_notary_token(
        pre_authorized_code,
        fixture.preauth.access_token_verification_keys()[0].public_jwk(),
        PRE_AUTHORIZED_CODE_JWT_TYP,
        fixture.preauth.notary_issuer(),
        &[],
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .expect("pre-authorized code verifies");
    assert_eq!(
        verified_code.payload["exp"].as_i64(),
        Some(credential_expires_at.unix_timestamp())
    );
    let transaction_id = verified_code.payload["jti"]
        .as_str()
        .expect("pre-authorized code has a transaction ID");
    let live_transaction = fixture
        .preauth
        .preauthorization_state()
        .transaction(transaction_id)
        .await
        .expect("transaction lookup succeeds")
        .expect("transaction remains live");
    assert_eq!(
        live_transaction.expires_at.unix_timestamp(),
        credential_expires_at.unix_timestamp()
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_is_atomic_for_retry_conflict_and_consumption() {
    let fixture = registry_offer_fixture().await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-IDEMPOTENCY-001").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-IDEMPOTENCY-001",
    ));

    let invoke = || {
        registry_offer_create(
            &fixture,
            principal.clone(),
            &evaluation_id,
            "registrar-idempotency",
        )
    };
    let (first, second) = tokio::join!(invoke(), invoke());
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        first.headers()[header::CACHE_CONTROL],
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        second.headers()[header::CACHE_CONTROL],
        HeaderValue::from_static("no-store")
    );
    let first_body = registry_offer_response_json(first).await;
    let second_body = registry_offer_response_json(second).await;
    assert_eq!(
        first_body, second_body,
        "concurrent exact retries return the one persisted offer and PIN"
    );

    let exact_retry = registry_offer_create(
        &fixture,
        principal.clone(),
        &evaluation_id,
        "registrar-idempotency",
    )
    .await;
    assert_eq!(exact_retry.status(), StatusCode::OK);
    assert_eq!(
        registry_offer_response_json(exact_retry).await,
        first_body,
        "later exact retry returns byte-for-byte equivalent response data"
    );

    let consumed = registry_offer_create(
        &fixture,
        principal.clone(),
        &evaluation_id,
        "registrar-new-operation",
    )
    .await;
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_eq!(
        consumed.headers()[header::CACHE_CONTROL],
        HeaderValue::from_static("no-store")
    );
    let consumed_body = registry_offer_response_json(consumed).await;
    assert_eq!(consumed_body["code"], "offer_conflict");
    assert!(!consumed_body.to_string().contains("NAT-IDEMPOTENCY-001"));

    let other_evaluation_id = registry_offer_evaluate(&fixture, "NAT-IDEMPOTENCY-002").await;
    let mut other_principal = principal;
    other_principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-IDEMPOTENCY-002",
    ));
    let key_reuse = registry_offer_create(
        &fixture,
        other_principal,
        &other_evaluation_id,
        "registrar-idempotency",
    )
    .await;
    assert_eq!(key_reuse.status(), StatusCode::CONFLICT);
    assert_eq!(
        registry_offer_response_json(key_reuse).await["code"],
        "offer_conflict"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_exact_retry_canonicalizes_authorized_claim_order() {
    let fixture = registry_offer_fixture().await;
    let target_id = "NAT-IDEMPOTENCY-CLAIM-ORDER";
    let evaluation_id = registry_offer_evaluate(&fixture, target_id).await;
    let mut initial_principal = fixture.principal.clone();
    initial_principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        target_id,
    ));

    let initial = registry_offer_create(
        &fixture,
        initial_principal,
        &evaluation_id,
        "registrar-claim-order",
    )
    .await;
    assert_eq!(initial.status(), StatusCode::OK);
    let initial_body = registry_offer_response_json(initial).await;

    let mut reordered_principal = fixture.principal.clone();
    let mut reordered_details = registry_offer_authorization_details(&fixture.state, target_id);
    reordered_details.claims.reverse();
    reordered_principal.authorization_details = Some(reordered_details);
    let reordered = registry_offer_create(
        &fixture,
        reordered_principal,
        &evaluation_id,
        "registrar-claim-order",
    )
    .await;
    assert_eq!(
        reordered.status(),
        StatusCode::OK,
        "claim order does not change the authorized request identity",
    );
    assert_eq!(
        registry_offer_response_json(reordered).await,
        initial_body,
        "equivalent claim sets replay the exact persisted offer",
    );

    let mut version_changed_principal = fixture.principal.clone();
    let mut version_changed_details =
        registry_offer_authorization_details(&fixture.state, target_id);
    version_changed_details.claims[0].version = Some("different-version".to_string());
    version_changed_principal.authorization_details = Some(version_changed_details);
    let version_changed = registry_offer_create(
        &fixture,
        version_changed_principal,
        &evaluation_id,
        "registrar-claim-order",
    )
    .await;
    assert_eq!(
        version_changed.status(),
        StatusCode::FORBIDDEN,
        "claim versions remain authorization-sensitive",
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_concurrent_exact_retry_debits_last_quota_unit_once() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(FirstSigningAttemptGate::new());
    let preauth = oid4vci_test_preauth_runtime_with_first_signing_attempt_gate(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        Arc::clone(&gate),
    );
    let mut evidence = registry_offer_test_evidence();
    evidence.machine_quota = registry_notary_core::MachineQuotaConfig {
        enabled: true,
        // Evaluation consumes the first unit. Both concurrent exact offer
        // attempts must share the one remaining operation debit.
        subjects_per_minute: 2,
    };
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-CONCURRENT-QUOTA").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-CONCURRENT-QUOTA",
    ));

    let first_state = Arc::clone(&fixture.state);
    let first_principal = principal.clone();
    let first_evaluation_id = evaluation_id.clone();
    let first = tokio::spawn(async move {
        oid4vci_create_registry_offer(
            registry_offer_headers("registrar-concurrent-quota"),
            Some(Extension(first_state)),
            Some(Extension(first_principal)),
            Ok(Json(Oid4vciRegistryOfferRequest {
                evaluation_id: first_evaluation_id,
                credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
            })),
        )
        .await
    });
    gate.wait_until_entered().await;

    let second_state = Arc::clone(&fixture.state);
    let second_evaluation_id = evaluation_id;
    let second = tokio::spawn(async move {
        oid4vci_create_registry_offer(
            registry_offer_headers("registrar-concurrent-quota"),
            Some(Extension(second_state)),
            Some(Extension(principal)),
            Ok(Json(Oid4vciRegistryOfferRequest {
                evaluation_id: second_evaluation_id,
                credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
            })),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "the exact contender must wait without entering the signer"
    );
    assert!(
        !second.is_finished(),
        "the exact contender waits for the authoritative reservation"
    );
    gate.release();
    let first = first.await.expect("first offer task joins");
    let second = second.await.expect("second offer task joins");

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        registry_offer_response_json(first).await,
        registry_offer_response_json(second).await,
        "both exact attempts replay the one authoritative offer"
    );
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "one leased quota-operation owner performs signer work"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_concurrent_exact_retry_is_serialized_when_quota_is_disabled() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(FirstSigningAttemptGate::new());
    let preauth = oid4vci_test_preauth_runtime_with_first_signing_attempt_gate(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        Arc::clone(&gate),
    );
    let mut evidence = registry_offer_test_evidence();
    evidence.machine_quota.enabled = false;
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-DISABLED-QUOTA-LEASE").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-DISABLED-QUOTA-LEASE",
    ));

    let first_state = Arc::clone(&fixture.state);
    let first_principal = principal.clone();
    let first_evaluation_id = evaluation_id.clone();
    let first = tokio::spawn(async move {
        oid4vci_create_registry_offer(
            registry_offer_headers("registrar-disabled-quota-lease"),
            Some(Extension(first_state)),
            Some(Extension(first_principal)),
            Ok(Json(Oid4vciRegistryOfferRequest {
                evaluation_id: first_evaluation_id,
                credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
            })),
        )
        .await
    });
    gate.wait_until_entered().await;

    let second_state = Arc::clone(&fixture.state);
    let second = tokio::spawn(async move {
        oid4vci_create_registry_offer(
            registry_offer_headers("registrar-disabled-quota-lease"),
            Some(Extension(second_state)),
            Some(Extension(principal)),
            Ok(Json(Oid4vciRegistryOfferRequest {
                evaluation_id,
                credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
            })),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);
    assert!(!second.is_finished());
    gate.release();
    let first = first.await.expect("first offer task joins");
    let second = second.await.expect("second offer task joins");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        registry_offer_response_json(first).await,
        registry_offer_response_json(second).await,
    );
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_concurrent_request_conflict_never_reaches_second_signer() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(FirstSigningAttemptGate::new());
    let preauth = oid4vci_test_preauth_runtime_with_first_signing_attempt_gate(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        Arc::clone(&gate),
    );
    let mut evidence = registry_offer_test_evidence();
    evidence.machine_quota = registry_notary_core::MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 4,
    };
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let first_evaluation =
        registry_offer_evaluate(&fixture, "NAT-CONCURRENT-REQUEST-CONFLICT").await;
    let second_evaluation =
        registry_offer_evaluate(&fixture, "NAT-CONCURRENT-REQUEST-CONFLICT").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-CONCURRENT-REQUEST-CONFLICT",
    ));

    let first_state = Arc::clone(&fixture.state);
    let first_principal = principal.clone();
    let first = tokio::spawn(async move {
        oid4vci_create_registry_offer(
            registry_offer_headers("registrar-request-conflict"),
            Some(Extension(first_state)),
            Some(Extension(first_principal)),
            Ok(Json(Oid4vciRegistryOfferRequest {
                evaluation_id: first_evaluation,
                credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
            })),
        )
        .await
    });
    gate.wait_until_entered().await;

    let conflict = oid4vci_create_registry_offer(
        registry_offer_headers("registrar-request-conflict"),
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(principal)),
        Ok(Json(Oid4vciRegistryOfferRequest {
            evaluation_id: second_evaluation,
            credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
        })),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "the different request shape conflicts on the shared idempotency operation",
    );
    gate.release();
    assert_eq!(
        first.await.expect("first offer task joins").status(),
        StatusCode::OK,
    );
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_signer_failure_releases_lease_without_refunding_quota() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let preauth = oid4vci_test_preauth_runtime_with_first_signing_attempt_failure(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
    );
    let mut evidence = registry_offer_test_evidence();
    evidence.machine_quota = registry_notary_core::MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 2,
    };
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-QUOTA-TAKEOVER").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-QUOTA-TAKEOVER",
    ));

    let failed = registry_offer_create(
        &fixture,
        principal.clone(),
        &evaluation_id,
        "registrar-quota-takeover",
    )
    .await;
    assert!(failed.status().is_server_error());
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);

    let takeover = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-quota-takeover",
    )
    .await;
    assert_eq!(takeover.status(), StatusCode::OK);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        2,
        "released lease is taken over without a second quota debit"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_preflight_skips_signer_for_sequential_denials_and_replay() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let preauth = oid4vci_test_preauth_runtime_with_limited_signer(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        1,
    );
    let fixture = registry_offer_fixture_with(registry_offer_test_evidence(), preauth).await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-PREFLIGHT-001").await;
    let mut principal = fixture.principal.clone();
    principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-PREFLIGHT-001",
    ));

    let created = registry_offer_create(
        &fixture,
        principal.clone(),
        &evaluation_id,
        "registrar-preflight",
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created_body = registry_offer_response_json(created).await;
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);

    let exact_replay = registry_offer_create(
        &fixture,
        principal.clone(),
        &evaluation_id,
        "registrar-preflight",
    )
    .await;
    assert_eq!(exact_replay.status(), StatusCode::OK);
    assert_eq!(
        registry_offer_response_json(exact_replay).await,
        created_body
    );
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "exact replay must return before signer work"
    );

    let other_evaluation_id = registry_offer_evaluate(&fixture, "NAT-PREFLIGHT-002").await;
    let mut other_principal = fixture.principal.clone();
    other_principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-PREFLIGHT-002",
    ));
    let idempotency_conflict = registry_offer_create(
        &fixture,
        other_principal,
        &other_evaluation_id,
        "registrar-preflight",
    )
    .await;
    assert_eq!(idempotency_conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "idempotency-key conflict must return before signer work"
    );

    let consumed = registry_offer_create(
        &fixture,
        principal,
        &evaluation_id,
        "registrar-preflight-new-operation",
    )
    .await;
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "consumed evaluation must return before signer work"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_charges_quota_before_signer_work() {
    let sign_attempt_count = Arc::new(AtomicUsize::new(0));
    let preauth = oid4vci_test_preauth_runtime_with_limited_signer(
        registry_notary_core::tokens::NOTARY_ACCESS_TOKEN_JWT_TYP,
        Arc::clone(&sign_attempt_count),
        0,
    );
    let mut evidence = registry_offer_test_evidence();
    evidence.machine_quota = registry_notary_core::MachineQuotaConfig {
        enabled: true,
        // The two evaluations consume two units. The first offer consumes the
        // third before its signer failure, leaving the second offer over quota.
        subjects_per_minute: 3,
    };
    let fixture = registry_offer_fixture_with(evidence, preauth).await;
    let first_evaluation_id = registry_offer_evaluate(&fixture, "NAT-QUOTA-SIGN-001").await;
    let second_evaluation_id = registry_offer_evaluate(&fixture, "NAT-QUOTA-SIGN-002").await;

    let mut first_principal = fixture.principal.clone();
    first_principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-QUOTA-SIGN-001",
    ));
    let signer_failure = registry_offer_create(
        &fixture,
        first_principal,
        &first_evaluation_id,
        "registrar-quota-sign-1",
    )
    .await;
    assert!(signer_failure.status().is_server_error());
    assert_eq!(sign_attempt_count.load(Ordering::SeqCst), 1);

    let mut second_principal = fixture.principal.clone();
    second_principal.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-QUOTA-SIGN-002",
    ));
    let quota_denial = registry_offer_create(
        &fixture,
        second_principal,
        &second_evaluation_id,
        "registrar-quota-sign-2",
    )
    .await;
    assert_eq!(quota_denial.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        sign_attempt_count.load(Ordering::SeqCst),
        1,
        "over-quota offer must return before signer work"
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_denies_unbound_authority_and_mutated_evidence() {
    let fixture = registry_offer_fixture().await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-001").await;
    let correct_details = registry_offer_authorization_details(&fixture.state, "NAT-BOUNDARY-001");

    let missing_idempotency = oid4vci_create_registry_offer(
        HeaderMap::new(),
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(fixture.principal.clone())),
        Ok(Json(Oid4vciRegistryOfferRequest {
            evaluation_id: evaluation_id.clone(),
            credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
        })),
    )
    .await;
    assert_eq!(missing_idempotency.status(), StatusCode::BAD_REQUEST);

    let missing_authentication = oid4vci_create_registry_offer(
        registry_offer_headers("missing-authentication"),
        Some(Extension(Arc::clone(&fixture.state))),
        None,
        Ok(Json(Oid4vciRegistryOfferRequest {
            evaluation_id: evaluation_id.clone(),
            credential_configuration_id: REGISTRY_OFFER_CONFIGURATION_ID.to_string(),
        })),
    )
    .await;
    assert_eq!(missing_authentication.status(), StatusCode::UNAUTHORIZED);

    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(correct_details.clone());
    let unknown_configuration = oid4vci_create_registry_offer(
        registry_offer_headers("unknown-configuration"),
        Some(Extension(Arc::clone(&fixture.state))),
        Some(Extension(authorized)),
        Ok(Json(Oid4vciRegistryOfferRequest {
            evaluation_id: evaluation_id.clone(),
            credential_configuration_id: "unknown_configuration".to_string(),
        })),
    )
    .await;
    assert_eq!(unknown_configuration.status(), StatusCode::NOT_FOUND);

    let mut missing_create_scope = fixture.principal.clone();
    missing_create_scope
        .scopes
        .retain(|scope| scope != REGISTRY_OFFER_CREATE_SCOPE);
    let response = registry_offer_create(
        &fixture,
        missing_create_scope,
        &evaluation_id,
        "missing-create-scope",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut missing_configuration_scope = fixture.principal.clone();
    let configuration_scope = fixture.state.oid4vci.credential_configurations
        [REGISTRY_OFFER_CONFIGURATION_ID]
        .scope
        .clone();
    missing_configuration_scope
        .scopes
        .retain(|scope| scope != &configuration_scope);
    let response = registry_offer_create(
        &fixture,
        missing_configuration_scope,
        &evaluation_id,
        "missing-configuration-scope",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut wallet_token_principal = fixture.principal.clone();
    wallet_token_principal.auth_profile_id =
        registry_notary_core::EvidenceAuthProfileId::NotaryAccessToken;
    let response = registry_offer_create(
        &fixture,
        wallet_token_principal,
        &evaluation_id,
        "wallet-cannot-create",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut wrong_rar = fixture.principal.clone();
    let mut wrong_details = correct_details.clone();
    wrong_details.actions = vec!["issue_credential".to_string()];
    wrong_rar.authorization_details = Some(wrong_details);
    let response = registry_offer_create(&fixture, wrong_rar, &evaluation_id, "wrong-rar").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut wrong_target_rar = fixture.principal.clone();
    let mut wrong_target_details = correct_details.clone();
    wrong_target_details
        .target
        .as_mut()
        .expect("offer RAR has a target")
        .id = "NAT-BOUNDARY-OTHER".to_string();
    wrong_target_rar.authorization_details = Some(wrong_target_details);
    let response = registry_offer_create(
        &fixture,
        wrong_target_rar,
        &evaluation_id,
        "wrong-rar-target",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut foreign_principal =
        registry_offer_machine_principal(&fixture.state, "registrar-foreign");
    foreign_principal.authorization_details = Some(correct_details.clone());
    let response = registry_offer_create(
        &fixture,
        foreign_principal,
        &evaluation_id,
        "foreign-evaluation",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let stale_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-STALE").await;
    let mut stale = fixture
        .store
        .get(&stale_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists");
    stale.expires_at = "2020-01-01T00:00:00Z".to_string();
    fixture
        .store
        .insert(stale)
        .await
        .expect("stale fixture writes");
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-STALE",
    ));
    let response = registry_offer_create(&fixture, authorized, &stale_id, "stale-evaluation").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let wrong_purpose_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-PURPOSE").await;
    let mut wrong_purpose = fixture
        .store
        .get(&wrong_purpose_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists");
    wrong_purpose.purpose = "different-purpose".to_string();
    fixture
        .store
        .insert(wrong_purpose)
        .await
        .expect("purpose mutation fixture writes");
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-PURPOSE",
    ));
    let response =
        registry_offer_create(&fixture, authorized, &wrong_purpose_id, "wrong-purpose").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let value_tamper_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-VALUE").await;
    fixture.store.tamper_next_read(|evaluation| {
        evaluation.results[0].value = Some(json!("mutated-after-evaluation"));
    });
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-VALUE",
    ));
    let response =
        registry_offer_create(&fixture, authorized, &value_tamper_id, "value-mutated").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let provenance_tamper_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-PROVENANCE").await;
    fixture.store.tamper_next_read(|evaluation| {
        evaluation
            .issuance_provenance
            .as_mut()
            .expect("issuance provenance exists")
            .claims[0]
            .relay_contract_hash =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
    });
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-PROVENANCE",
    ));
    let response = registry_offer_create(
        &fixture,
        authorized,
        &provenance_tamper_id,
        "provenance-mutated",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_rejects_non_exact_claim_and_target_authority() {
    let fixture = registry_offer_fixture().await;
    let evaluation_id = registry_offer_evaluate(&fixture, "NAT-EXACT-AUTHORITY").await;
    let correct_details =
        registry_offer_authorization_details(&fixture.state, "NAT-EXACT-AUTHORITY");

    let mut wrong_scheme_rar = fixture.principal.clone();
    let mut wrong_scheme_details = correct_details.clone();
    wrong_scheme_details
        .target
        .as_mut()
        .expect("offer RAR has a target")
        .id_type = "registry_file_number".to_string();
    wrong_scheme_rar.authorization_details = Some(wrong_scheme_details);
    let response = registry_offer_create(
        &fixture,
        wrong_scheme_rar,
        &evaluation_id,
        "wrong-rar-target-scheme",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut duplicate_claim_rar = fixture.principal.clone();
    let mut duplicate_claim_details = correct_details.clone();
    duplicate_claim_details.claims[1] = duplicate_claim_details.claims[0].clone();
    duplicate_claim_rar.authorization_details = Some(duplicate_claim_details);
    let response = registry_offer_create(
        &fixture,
        duplicate_claim_rar,
        &evaluation_id,
        "duplicate-rar-claim",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut version_substitution_rar = fixture.principal.clone();
    let mut version_substitution_details = correct_details;
    version_substitution_details.claims[0].version = Some("1".to_string());
    version_substitution_rar.authorization_details = Some(version_substitution_details);
    let response = registry_offer_create(
        &fixture,
        version_substitution_rar,
        &evaluation_id,
        "version-substitution-rar-claim",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn oid4vci_registry_offer_rejects_missing_or_cross_evaluation_target_binding() {
    let fixture = registry_offer_fixture().await;
    let legacy_binding_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-LEGACY").await;
    fixture.store.tamper_next_read(|evaluation| {
        evaluation
            .issuance_provenance
            .as_mut()
            .expect("issuance provenance exists")
            .authorization_target_binding
            .clear();
    });
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-LEGACY",
    ));
    let response = registry_offer_create(
        &fixture,
        authorized,
        &legacy_binding_id,
        "legacy-target-binding",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let first_binding_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-BINDING-A").await;
    let second_binding_id = registry_offer_evaluate(&fixture, "NAT-BOUNDARY-BINDING-B").await;
    let second_binding = fixture
        .store
        .get(&second_binding_id, REGISTRY_OFFER_PRINCIPAL_ID)
        .await
        .expect("stored evaluation read succeeds")
        .expect("stored evaluation exists")
        .issuance_provenance
        .expect("issuance provenance exists")
        .authorization_target_binding;
    fixture.store.tamper_next_read(move |evaluation| {
        evaluation
            .issuance_provenance
            .as_mut()
            .expect("issuance provenance exists")
            .authorization_target_binding = second_binding.clone();
    });
    let mut authorized = fixture.principal.clone();
    authorized.authorization_details = Some(registry_offer_authorization_details(
        &fixture.state,
        "NAT-BOUNDARY-BINDING-A",
    ));
    let response = registry_offer_create(
        &fixture,
        authorized,
        &first_binding_id,
        "cross-evaluation-target-binding",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
