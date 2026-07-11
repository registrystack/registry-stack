// SPDX-License-Identifier: Apache-2.0
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use registry_notary_core::{
        BoundedVerifiedClaims, CredentialStatusConfig, CredentialStatusRedisConfig,
        EvidenceAuthorizationDetails, SourceBindingConfig, SubjectRequest, VerifiedClaimName,
        VerifiedClaimValue, CREDENTIAL_STATUS_STORAGE_REDIS,
    };
    use registry_platform_crypto::{did_jwk_from_public_jwk, sign, LocalJwkSigner, PrivateJwk};
    use registry_platform_replay::ReplayInsertOutcome;
    use registry_platform_testing::{assert_json_absent_strings, sign_openid4vci_proof_jwt};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    // Ed25519 keypair: `d` is the seed, `x` is the corresponding public key,
    // both base64url (no padding). Identical to the key in
    // registry-notary-core::sd_jwt tests so behavior is consistent.
    const HOLDER_PRIV_D_B64: &str = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw";
    const HOLDER_PUB_X_B64: &str = "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc";
    const ISSUER_PRIV_D_B64: &str = "f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys";
    const ISSUER_PUB_X_B64: &str = "pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec";
    const SUBJECT_BINDING_CLAIM: &str = "https://id.example.gov/claims/national_id";

    fn classifier_config() -> StandaloneRegistryNotaryConfig {
        serde_json::from_value(json!({
            "evidence": {
                "enabled": true
            },
            "auth": {
                "mode": "api_key",
                "api_keys": [{
                    "id": "primary-api-key",
                    "fingerprint": {
                        "provider": "env",
                        "name": "PRIMARY_API_KEY_HASH"
                    },
                    "scopes": ["claims:read"]
                }],
                "bearer_tokens": [{
                    "id": "primary-bearer-token",
                    "fingerprint": {
                        "provider": "env",
                        "name": "PRIMARY_BEARER_TOKEN_HASH"
                    },
                    "scopes": ["claims:write"]
                }]
            }
        }))
        .expect("classifier config parses")
    }

    fn holder_did_jwk() -> String {
        let holder = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": HOLDER_PRIV_D_B64,
                "x": HOLDER_PUB_X_B64,
                "alg": "EdDSA"
            })
            .to_string(),
        )
        .expect("holder JWK parses");
        did_jwk_from_public_jwk(&holder.public()).expect("did:jwk encodes")
    }

    fn bounded(value: &str) -> VerifiedClaimValue {
        VerifiedClaimValue::new(value).expect("test claim value is bounded")
    }

    fn self_attestation_config() -> SelfAttestationConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "requires_auth_mode": "oidc",
            "subject_binding": {
                "token_claim": SUBJECT_BINDING_CLAIM,
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact",
                "allow_sub_as_civil_id": false
            },
            "citizen_clients": {
                "allowed_client_ids": ["citizen-portal"],
                "allowed_audiences": ["registry-notary-citizen"]
            },
            "token_policy": {
                "required_acr_values": ["urn:example:loa:substantial"],
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 600,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": true,
                "batch_evaluate": false
            },
            "allowed_purposes": ["citizen_self_attestation"],
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["self_attestation"],
            "allowed_wallet_origins": ["https://wallet.example.gov"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "mode": "in_process",
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("self-attestation config parses")
    }

    fn evidence_config() -> EvidenceConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "claims": [{
                "id": "person-is-alive",
                "title": "Person is alive",
                "version": "1",
                "subject_type": "person",
                "purpose": "citizen_self_attestation",
                "rule": { "type": "cel", "expression": "true" },
                "operations": {
                    "evaluate": { "enabled": true },
                    "batch_evaluate": { "enabled": true, "max_subjects": 5 }
                },
                "disclosure": {
                    "default": "predicate",
                    "allowed": ["predicate"],
                    "downgrade": "deny"
                },
                "formats": [FORMAT_CLAIM_RESULT_JSON]
            }]
        }))
        .expect("evidence config parses")
    }

    fn delegated_self_attestation_config() -> SelfAttestationConfig {
        let mut config = self_attestation_config();
        config.delegation = registry_notary_core::SelfAttestationDelegationConfig {
            enabled: true,
            allowed_relationships: vec![SelfAttestationDelegatedRelationshipConfig {
                relationship_type: "guardian".to_string(),
                proof_claim: "guardian-link-established".to_string(),
                target_id_type: Some("civil_registration_id".to_string()),
                allowed_claims: vec!["dependent-person-is-alive".to_string()],
                allowed_purposes: vec!["dependent_attestation".to_string()],
                allowed_formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
                allowed_disclosures: vec!["predicate".to_string()],
                credential_profiles: vec!["dependent_status_sd_jwt".to_string()],
            }],
        };
        config
    }

    fn delegated_evidence_config() -> EvidenceConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "service_id": "https://notary.example.test",
            "claims": [
                {
                    "id": "guardian-link-established",
                    "title": "Guardian link is established",
                    "version": "1",
                    "subject_type": "relationship",
                    "purpose": "dependent_attestation",
                    "source_bindings": {
                        "link": {
                            "connector": "registry_data_api",
                            "dataset": "guardian_registry",
                            "entity": "guardian_link",
                            "lookup": {
                                "input": "target.identifiers.civil_registration_id",
                                "field": "dependent_id",
                                "op": "eq",
                                "cardinality": "one"
                            },
                            "query_fields": [{
                                "input": "requester.identifiers.national_id",
                                "field": "guardian_id",
                                "op": "eq"
                            }],
                            "fields": {
                                "value": {
                                    "field": "value",
                                    "type": "boolean",
                                    "required": true
                                }
                            }
                        }
                    },
                    "rule": { "type": "extract", "source": "link", "field": "value" },
                    "operations": {
                        "evaluate": { "enabled": true },
                        "batch_evaluate": { "enabled": false, "max_subjects": 1 }
                    },
                    "disclosure": {
                        "default": "predicate",
                        "allowed": ["predicate"],
                        "downgrade": "deny"
                    },
                    "formats": [FORMAT_CLAIM_RESULT_JSON]
                },
                {
                    "id": "dependent-person-is-alive",
                    "title": "Dependent person is alive",
                    "version": "1",
                    "subject_type": "person",
                    "purpose": "dependent_attestation",
                    "depends_on": ["guardian-link-established"],
                    "rule": { "type": "cel", "expression": "claims.guardian.satisfied", "bindings": { "claims": { "guardian": { "claim": "guardian-link-established" } } } },
                    "operations": {
                        "evaluate": { "enabled": true },
                        "batch_evaluate": { "enabled": false, "max_subjects": 1 }
                    },
                    "disclosure": {
                        "default": "predicate",
                        "allowed": ["predicate"],
                        "downgrade": "deny"
                    },
                    "formats": [FORMAT_CLAIM_RESULT_JSON],
                    "credential_profiles": ["dependent_status_sd_jwt"]
                }
            ],
            "credential_profiles": {
                "dependent_status_sd_jwt": {
                    "format": FORMAT_SD_JWT_VC,
                    "issuer": "did:web:issuer.example",
                    "signing_key": "issuer-key",
                    "vct": "https://issuer.example/credentials/dependent-status",
                    "validity_seconds": 600,
                    "holder_binding": {
                        "mode": "did",
                        "proof_of_possession": "required",
                        "allowed_did_methods": ["did:jwk"]
                    },
                    "allowed_claims": ["dependent-person-is-alive"],
                    "disclosure": { "allowed": ["predicate"] }
                }
            }
        }))
        .expect("delegated evidence config parses")
    }

    fn delegated_request() -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "CHILD-123".to_string(),
                    id_type: Some("civil_registration_id".to_string()),
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::with_version("dependent-person-is-alive", "1")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        }
    }

    fn delegated_authorization_details(evidence: &EvidenceConfig) -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec![evidence.service_id.clone()],
            claims: vec![
                ClaimRef::with_version("dependent-person-is-alive", "1"),
                ClaimRef::with_version("guardian-link-established", "1"),
            ],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("dependent_attestation".to_string()),
            legal_basis_ref: None,
            consent_ref: None,
            jurisdiction: None,
            assurance_level: None,
            subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
                binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
                id_type: "national_id".to_string(),
            }),
            target: Some(registry_notary_core::EvidenceAuthorizationTarget {
                id_type: "civil_registration_id".to_string(),
                id: "CHILD-123".to_string(),
            }),
            relationship: Some(registry_notary_core::EvidenceAuthorizationRelationship {
                relationship_type: "guardian".to_string(),
                proof_claim: "guardian-link-established".to_string(),
            }),
            access_mode: Some(AccessMode::DelegatedAttestation),
            assisted_access_context: None,
        }
    }

    fn delegated_transaction_principal(
        config: &SelfAttestationConfig,
        evidence: &EvidenceConfig,
    ) -> EvidencePrincipal {
        let mut principal = classify_self_attestation_principal(
            config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal.authorization_details = Some(delegated_authorization_details(evidence));
        principal.access_mode = AccessMode::DelegatedAttestation;
        principal
    }

    fn delegated_test_audit_hasher() -> AuditKeyHasher {
        const ENV: &str = "TEST_DELEGATED_AUDIT_HASH_SECRET";
        std::env::set_var(ENV, "0123456789abcdef0123456789abcdef");
        AuditKeyHasher::from_env(ENV).expect("delegated test audit hasher loads")
    }

    fn oid4vci_config() -> Oid4vciConfig {
        serde_json::from_value(json!({
            "enabled": true,
            "credential_issuer": "http://127.0.0.1:4325",
            "authorization_servers": ["http://localhost:8088/v1/esignet"],
            "accepted_token_audiences": ["http://127.0.0.1:4325"],
            "credential_endpoint": "http://127.0.0.1:4325/oid4vci/credential",
            "offer_endpoint": "http://127.0.0.1:4325/oid4vci/credential-offer",
            "nonce_endpoint": "http://127.0.0.1:4325/oid4vci/nonce",
            "nonce": { "enabled": true, "ttl_seconds": 300 },
            "display": [{
                "name": "Civil Registry Notary",
                "locale": "en-US",
                "logo": {
                    "uri": "https://issuer.example/assets/notary-logo.png",
                    "alt_text": "Civil Registry Notary logo"
                }
            }],
            "credential_configurations": {
                "person_is_alive_sd_jwt": {
                    "claim_id": "person-is-alive",
                    "credential_profile": "civil_status_sd_jwt",
                    "format": "dc+sd-jwt",
                    "scope": "person_is_alive",
                    "vct": "https://issuer.example/credentials/civil-status",
                    "display_name": "Person is alive",
                    "display": {
                        "locale": "en-US",
                        "description": "Proof that the civil registry currently records this person as alive.",
                        "background_color": "#0057B8",
                        "text_color": "#FFFFFF",
                        "logo": {
                            "url": "https://issuer.example/assets/person-is-alive.png",
                            "alt_text": "Person is alive credential logo"
                        }
                    }
                }
            }
        }))
        .expect("oid4vci config parses")
    }

    fn oid4vci_evidence_config() -> EvidenceConfig {
        let mut evidence = evidence_config();
        let claim = evidence.claims.first_mut().expect("claim exists");
        claim.formats.push(FORMAT_SD_JWT_VC.to_string());
        claim
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.signing_keys.insert(
            "issuer-key".to_string(),
            serde_json::from_value(json!({
                "provider": "local_jwk_env",
                "private_jwk_env": "ISSUER_KEY",
                "alg": "EdDSA",
                "kid": "did:web:issuer.example#key-1",
                "status": "active"
            }))
            .expect("signing key parses"),
        );
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
            .expect("credential profile parses"),
        );
        evidence
    }

    fn runtime_config_with_custom_access_token_typ() -> StandaloneRegistryNotaryConfig {
        let mut config = classifier_config();
        config.auth.access_token_signing.enabled = true;
        config.auth.access_token_signing.issuer = "https://notary.example.test".to_string();
        config.auth.access_token_signing.token_typ = "custom-notary-access+jwt".to_string();
        config
    }

    fn oidc_principal(client_id: Option<&str>, scopes: &[&str]) -> EvidencePrincipal {
        EvidencePrincipal {
            principal_id: "citizen-subject".to_string(),
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
            access_mode: AccessMode::MachineClient,
            verified_claims: Some(BoundedVerifiedClaims {
                issuer: bounded("https://id.example.gov"),
                audiences: vec![bounded("registry-notary-citizen")],
                client_id: client_id.map(bounded),
                token_type: Some(bounded("JWT")),
                scopes: scopes.iter().map(|scope| bounded(scope)).collect(),
                subject: Some(bounded("login-subject")),
                subject_binding_claim: Some(
                    VerifiedClaimName::new(SUBJECT_BINDING_CLAIM)
                        .expect("subject claim name is bounded"),
                ),
                subject_binding_value: Some(bounded("NAT-123")),
                acr: Some(bounded("urn:example:loa:substantial")),
                auth_time: Some(1_700_000_000),
                exp: Some(1_700_000_900),
                iat: Some(1_700_000_000),
                nbf: None,
            }),
            authorization_details: None,
        }
    }

    fn fresh_oidc_principal(client_id: Option<&str>, scopes: &[&str]) -> EvidencePrincipal {
        let mut principal = oidc_principal(client_id, scopes);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = principal
            .verified_claims
            .as_mut()
            .expect("test principal has claims");
        claims.auth_time = Some(now);
        claims.iat = Some(now);
        claims.exp = Some(now + 600);
        principal
    }

    fn oid4vci_authorized_principal(
        evidence: &EvidenceConfig,
        config: &SelfAttestationConfig,
        oid4vci: &Oid4vciConfig,
        configuration_id: &str,
        scopes: &[&str],
    ) -> EvidencePrincipal {
        let mut principal = fresh_oidc_principal(Some("client_id:citizen-portal"), scopes);
        let configuration = oid4vci
            .credential_configurations
            .get(configuration_id)
            .expect("credential configuration exists");
        principal.authorization_details = Some(
            oid4vci_issuance_authorization_details(evidence, config, configuration)
                .expect("authorization details build"),
        );
        principal
    }

    async fn reserve_oid4vci_test_nonce(
        state: &RegistryNotaryApiState,
        configuration_id: &str,
        nonce: &str,
    ) -> (ReplayScope, ReplayKey) {
        let nonce_key = state
            .self_attestation_rate_keys
            .oid4vci_nonce(&state.oid4vci.credential_issuer, configuration_id, nonce)
            .expect("nonce hashes");
        let nonce_scope = oid4vci_nonce_replay_scope(state, configuration_id).expect("nonce scope");
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
        (nonce_scope, nonce_key)
    }

    fn evaluate_request(subject_id: &str) -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: subject_id.to_string(),
                    id_type: Some("national_id".to_string()),
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from("person-is-alive")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: None,
        }
    }

    fn transaction_authorization_details(
        evidence: &EvidenceConfig,
    ) -> EvidenceAuthorizationDetails {
        EvidenceAuthorizationDetails {
            detail_type: registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE
                .to_string(),
            schema_version:
                registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION
                    .to_string(),
            actions: vec!["evaluate".to_string()],
            locations: vec![evidence.service_id.clone()],
            claims: vec![ClaimRef::with_version("person-is-alive", "1")],
            disclosure: Some("predicate".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("citizen_self_attestation".to_string()),
            legal_basis_ref: None,
            consent_ref: None,
            jurisdiction: None,
            assurance_level: None,
            subject: Some(registry_notary_core::EvidenceAuthorizationSubject {
                binding_claim: SUBJECT_BINDING_CLAIM.to_string(),
                id_type: "national_id".to_string(),
            }),
            target: None,
            relationship: None,
            access_mode: Some(AccessMode::SelfAttestation),
            assisted_access_context: None,
        }
    }

    fn classified_transaction_principal(
        config: &SelfAttestationConfig,
        evidence: &EvidenceConfig,
    ) -> EvidencePrincipal {
        let mut principal = classify_self_attestation_principal(
            config,
            &fresh_oidc_principal(Some("client_id:citizen-portal"), &["self_attestation"]),
        )
        .expect("citizen principal classifies");
        principal.authorization_details = Some(transaction_authorization_details(evidence));
        principal
    }

    #[derive(Default)]
    struct CountingSource {
        reads: Arc<AtomicUsize>,
    }

    impl SourceReader for CountingSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Err(EvidenceError::SourceUnavailable)
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec!["civil_registry:evidence_verification".to_string()])
        }
    }

    struct ReadinessSource {
        ready: Arc<AtomicBool>,
    }

    impl SourceReader for ReadinessSource {
        fn has_readiness_check(&self) -> bool {
            true
        }

        fn check_ready<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move { self.ready.load(Ordering::SeqCst) })
        }

        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async { Err(EvidenceError::SourceUnavailable) })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec!["civil_registry:evidence_verification".to_string()])
        }
    }

    #[derive(Default)]
    struct VersionScopedSource;

    impl SourceReader for VersionScopedSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async { Err(EvidenceError::SourceUnavailable) })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{claim_id}:1.0")])
        }

        fn required_scopes_for_claim(
            &self,
            _evidence: &EvidenceConfig,
            claim: &registry_notary_core::ClaimDefinition,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{}:{}", claim.id, claim.version)])
        }
    }

    struct NoopIssuerResolver;

    impl EvidenceIssuerResolver for NoopIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            Err(EvidenceError::CredentialIssuerNotConfigured)
        }
    }

    struct TestIssuerResolver;

    impl EvidenceIssuerResolver for TestIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &issuer_private_jwk(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    struct CountingSigningProvider {
        inner: LocalJwkSigner,
        sign_count: Arc<AtomicUsize>,
    }

    impl CountingSigningProvider {
        fn new(sign_count: Arc<AtomicUsize>) -> Self {
            let mut jwk = PrivateJwk::parse(&issuer_private_jwk()).expect("issuer key parses");
            jwk.kid = Some("did:web:issuer.example#key-1".to_string());
            let inner = LocalJwkSigner::new(jwk).expect("local signer builds");
            Self { inner, sign_count }
        }
    }

    #[async_trait::async_trait]
    impl SigningProvider for CountingSigningProvider {
        fn algorithm(&self) -> registry_platform_crypto::SigningAlgorithm {
            self.inner.algorithm()
        }

        fn key_id(&self) -> &str {
            self.inner.key_id()
        }

        fn public_jwk(&self) -> PublicJwk {
            self.inner.public_jwk()
        }

        async fn sign(
            &self,
            payload: &[u8],
        ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
            self.sign_count.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(payload).await
        }
    }

    struct CountingIssuerResolver {
        sign_count: Arc<AtomicUsize>,
    }

    impl EvidenceIssuerResolver for CountingIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_signing_provider(Arc::new(
                CountingSigningProvider::new(Arc::clone(&self.sign_count)),
            ))
        }
    }

    #[cfg(feature = "registry-notary-cel")]
    struct StaticIssuerResolver;

    #[cfg(feature = "registry-notary-cel")]
    impl EvidenceIssuerResolver for StaticIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "d": ISSUER_PRIV_D_B64,
                    "x": ISSUER_PUB_X_B64,
                    "alg": "EdDSA"
                })
                .to_string(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    struct HolderIssuerResolver;

    impl EvidenceIssuerResolver for HolderIssuerResolver {
        fn issuer(
            &self,
            _profile_id: &str,
        ) -> Result<registry_notary_core::sd_jwt::EvidenceIssuer, EvidenceError> {
            registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
                &holder_private_jwk(),
                "did:web:issuer.example#key-1".to_string(),
            )
        }
    }

    fn sign_holder_proof(holder_id: &str, payload: Value) -> String {
        let holder = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": HOLDER_PRIV_D_B64,
                "x": HOLDER_PUB_X_B64,
                "alg": "EdDSA",
                "kid": holder_id,
            })
            .to_string(),
        )
        .expect("holder JWK parses");
        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA",
                "typ": "kb+jwt",
                "kid": holder_id,
            }))
            .expect("header serializes"),
        );
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload serializes"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = sign(signing_input.as_bytes(), &holder).expect("sign holder proof");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn sign_oid4vci_proof(audience: &str, nonce: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sign_openid4vci_proof_jwt(&holder_private_jwk(), audience, Some(nonce), now)
    }

    fn validated_oid4vci_proof(
        state: &RegistryNotaryApiState,
        proof: &str,
        nonce: Option<&str>,
    ) -> ValidatedProof {
        validate_proof_jwt(
            proof,
            &ProofValidationPolicy::credential_endpoint(
                &state.oid4vci.credential_issuer,
                nonce,
                Duration::from_secs(state.oid4vci.proof.max_age_seconds),
                Duration::from_secs(state.oid4vci.proof.max_clock_skew_seconds),
            ),
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .expect("proof validates")
    }

    #[cfg(feature = "registry-notary-cel")]
    fn sign_oid4vci_proof_without_nonce(audience: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        sign_openid4vci_proof_jwt(&holder_private_jwk(), audience, None, now)
    }

    fn holder_private_jwk() -> String {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": HOLDER_PRIV_D_B64,
            "x": HOLDER_PUB_X_B64,
            "alg": "EdDSA"
        })
        .to_string()
    }

    fn issuer_private_jwk() -> String {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": ISSUER_PRIV_D_B64,
            "x": ISSUER_PUB_X_B64,
            "alg": "EdDSA"
        })
        .to_string()
    }

    fn test_federation_runtime(generation: &str) -> Arc<crate::federation::FederationRuntimeState> {
        let secret_env = format!(
            "TEST_ATOMIC_FEDERATION_SECRET_{}",
            generation.to_uppercase()
        );
        std::env::set_var(&secret_env, format!("{generation}-pairwise-secret"));
        let federation: FederationConfig = serde_norway::from_str(&format!(
            r#"
enabled: true
node_id: did:web:{generation}.notary.example
issuer: https://{generation}.notary.example
jwks_uri: https://{generation}.notary.example/federation/jwks.json
federation_api: https://{generation}.notary.example/federation/v1
supported_protocol_versions:
  - registry-notary-federation/v0.1
signing:
  signing_key: federation-key
pairwise_subject_hash:
  secret_env: {secret_env}
replay:
  storage: in_process_single_instance_only
  max_entries: 100
  eviction: expire_oldest
response_shaping:
  minimum_denial_latency_ms: 1
peers:
  - node_id: did:web:peer.{generation}.example
    issuer: https://peer.{generation}.example
    jwks_uri: http://127.0.0.1:9/{generation}/jwks.json
    allow_insecure_localhost: true
    allowed_protocol_versions:
      - registry-notary-federation/v0.1
    allowed_purposes:
      - https://purpose.example.test/eligibility
    allowed_profiles:
      - person_alive
    source_scopes:
      - civil_registry:evidence_verification
evaluation_profiles:
  - id: person_alive
    ruleset: person-alive-v1
    claim_id: person-is-alive
    subject_id_type: national_id
"#
        ))
        .expect("federation config parses");
        let signer_jwk = PrivateJwk::parse(
            &json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": format!("{generation}-federation-key"),
                "d": ISSUER_PRIV_D_B64,
                "x": ISSUER_PUB_X_B64,
                "alg": "EdDSA"
            })
            .to_string(),
        )
        .expect("federation signer JWK parses");
        let signer: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(signer_jwk).expect("federation signer builds"));
        Arc::new(
            crate::federation::FederationRuntimeState::from_config(
                &federation,
                signer,
                None,
                ReplayStores::memory().store(),
                Arc::new(AppMetrics::default()),
            )
            .expect("federation runtime builds"),
        )
    }

    fn evaluation_for_proof() -> registry_notary_core::StoredEvaluation {
        registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: Vec::new(),
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        }
    }

    fn claim_result_view(
        evaluation_id: &str,
        claim_id: &str,
    ) -> registry_notary_core::ClaimResultView {
        registry_notary_core::ClaimResultView {
            evaluation_id: evaluation_id.to_string(),
            claim_id: claim_id.to_string(),
            claim_version: "1".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: registry_notary_core::TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:subject-hash".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            matching: None,
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_SD_JWT_VC.to_string(),
            issued_at: "2026-05-23T00:00:00Z".to_string(),
            expires_at: None,
            provenance: registry_notary_core::ClaimProvenance::new(
                "test".to_string(),
                "eval-test".to_string(),
                "claim".to_string(),
                "1".to_string(),
                registry_notary_core::ProvenanceUsed {
                    source_count: 0,
                    source_versions: std::collections::BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
        }
    }

    fn credential_issue_evidence_config() -> EvidenceConfig {
        let mut evidence = evidence_config();
        evidence.service_id = "registry-notary".to_string();
        evidence
            .claims
            .first_mut()
            .expect("person-is-alive claim exists")
            .credential_profiles
            .push("civil_status_sd_jwt".to_string());
        evidence.credential_profiles.insert(
            "civil_status_sd_jwt".to_string(),
            serde_json::from_value(json!({
                "format": FORMAT_SD_JWT_VC,
                "issuer": "did:web:issuer.example",
                "signing_key": "issuer-key",
                "vct": "https://issuer.example/credentials/civil-status",
                "validity_seconds": 600,
                "allowed_claims": ["person-is-alive"],
                "disclosure": { "allowed": ["predicate"] }
            }))
            .expect("credential profile parses"),
        );
        evidence
    }

    fn decode_jwt_header(jwt: &str) -> Value {
        decode_jwt_segment(jwt, 0)
    }

    fn decode_jwt_payload(jwt: &str) -> Value {
        decode_jwt_segment(jwt, 1)
    }

    fn decode_jwt_segment(jwt: &str, index: usize) -> Value {
        let segment = jwt.split('.').nth(index).expect("jwt segment exists");
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segment)
                .expect("jwt segment is base64url"),
        )
        .expect("jwt segment is JSON")
    }

    fn issue_request() -> CredentialIssueRequest {
        CredentialIssueRequest {
            evaluation_id: "eval-1".to_string(),
            credential_profile: Some("profile-a".to_string()),
            format: None,
            claims: None,
            disclosure: None,
            purpose: None,
            holder: None,
        }
    }

    fn holder_required_profile() -> CredentialProfileConfig {
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
            "allowed_claims": ["claim-a"],
            "disclosure": { "allowed": ["redacted"] }
        }))
        .expect("profile parses")
    }

    fn proof_payload(holder_id: &str, aud: &str) -> Value {
        let now = OffsetDateTime::now_utc().unix_timestamp() + 10;
        json!({
            "sub": holder_id,
            "aud": aud,
            "iat": now,
            "exp": now + 60,
            "jti": "jti-1",
            "evaluation_id": "eval-1",
            "credential_profile": "profile-a",
            "disclosure": holder_proof_disclosure("redacted"),
            "claims": ["claim-a"],
        })
    }

    fn windowed_proof_payload(holder_id: &str, aud: &str, iat: i64, exp: i64) -> Value {
        json!({
            "sub": holder_id,
            "aud": aud,
            "iat": iat,
            "exp": exp,
            "jti": "jti-window",
            "evaluation_id": "eval-1",
            "credential_profile": "profile-a",
            "disclosure": holder_proof_disclosure("redacted"),
            "claims": ["claim-a"],
        })
    }

    fn holder_proof_disclosure(disclosure: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes()))
    }
