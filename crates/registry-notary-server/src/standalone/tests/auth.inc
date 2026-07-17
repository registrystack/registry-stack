    // SPDX-License-Identifier: Apache-2.0

    #[tokio::test]
    async fn notary_token_auth_rejects_expired_verification_key() {
        let signer =
            LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("private jwk"))
                .expect("local signer builds");
        let public_jwk = PublicJwk::parse(TEST_OLD_ISSUER_PUBLIC_JWK).expect("public jwk parses");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = mint_access_token(
            &signer,
            "registry-notary-access+jwt",
            &AccessTokenClaims {
                issuer: "https://notary.example".to_string(),
                jti: None,
                audiences: vec!["registry-notary".to_string()],
                token_type: "Bearer".to_string(),
                credential_configuration_id: "identity_credential".to_string(),
                subject: BoundSubject {
                    subject: "subject-1".to_string(),
                    subject_binding_claim: "civil_id".to_string(),
                    subject_binding_value: "civil-1".to_string(),
                    client_id: "wallet-demo".to_string(),
                    scopes: vec!["openid".to_string()],
                    acr: None,
                    auth_time: None,
                },
                authorization_details: Vec::new(),
                confirmation: None,
                actor: None,
                iat: now - 1,
                exp: now + 300,
            },
        )
        .await
        .expect("token mints");

        let mut anchor = NotaryTokenAnchor {
            verification_keys: vec![AccessTokenVerificationKey {
                public_jwk: public_jwk.clone(),
                publish_until_unix_seconds: Some(1),
            }],
            issuer: "https://notary.example".to_string(),
            token_typ: "registry-notary-access+jwt".to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        assert!(matches!(
            authenticate_notary_token(&token.compact, &anchor, &ReplayStores::memory()).await,
            Err(EvidenceError::MissingCredential)
        ));

        anchor.verification_keys[0] = AccessTokenVerificationKey {
            public_jwk,
            publish_until_unix_seconds: Some(u64::try_from(now + 300).expect("future is positive")),
        };
        let principal = authenticate_notary_token(
            &token.compact,
            &anchor,
            &ReplayStores::memory(),
        )
        .await
        .expect("current verification key succeeds");
        assert_eq!(
            principal.auth_profile_id,
            EvidenceAuthProfileId::NotaryAccessToken
        );
    }

    #[tokio::test]
    async fn notary_transaction_token_auth_consumes_jti_once() {
        let signer =
            LocalJwkSigner::new(PrivateJwk::parse(TEST_ISSUER_JWK_WITH_KID).expect("private jwk"))
                .expect("local signer builds");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = mint_access_token(
            &signer,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
            &AccessTokenClaims {
                issuer: "https://notary.example".to_string(),
                jti: Some("txn-jti-1".to_string()),
                audiences: vec!["registry-notary".to_string()],
                token_type: "Bearer".to_string(),
                credential_configuration_id: "identity_credential".to_string(),
                subject: BoundSubject {
                    subject: "subject-1".to_string(),
                    subject_binding_claim: "civil_id".to_string(),
                    subject_binding_value: "civil-1".to_string(),
                    client_id: "assisted-access".to_string(),
                    scopes: vec!["registry_notary:subject_access".to_string()],
                    acr: None,
                    auth_time: None,
                },
                authorization_details: vec![json!({
                    "type": NOTARY_AUTHORIZATION_DETAILS_TYPE,
                    "schema_version": NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                    "actions": ["evaluate"],
                    "locations": ["registry-notary"],
                })],
                confirmation: None,
                actor: Some(json!({"actor_id_hash": "hmac-sha256:actor"})),
                iat: now - 1,
                exp: now + 300,
            },
        )
        .await
        .expect("transaction token mints");
        let anchor = NotaryTokenAnchor {
            verification_keys: vec![AccessTokenVerificationKey {
                public_jwk: signer.public_jwk(),
                publish_until_unix_seconds: None,
            }],
            issuer: "https://notary.example".to_string(),
            token_typ: NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        let replay = ReplayStores::memory();

        authenticate_notary_token(&token.compact, &anchor, &replay)
            .await
            .expect("first token use succeeds");
        let replay_error = authenticate_notary_token(&token.compact, &anchor, &replay)
            .await
            .expect_err("second token use is replay");

        assert!(matches!(replay_error, EvidenceError::MissingCredential));
    }

    #[tokio::test]
    async fn consume_notary_token_jti_rejects_missing_jti_for_transaction_typ() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let payload = json!({
            "iss": "https://notary.example",
            "exp": now + 300,
        });
        let anchor = NotaryTokenAnchor {
            verification_keys: Vec::new(),
            issuer: "https://notary.example".to_string(),
            token_typ: NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string(),
            audiences: vec!["registry-notary".to_string()],
            principal_claim: "sub".to_string(),
            subject_binding_claim: Some("civil_id".to_string()),
        };
        let replay = ReplayStores::memory();

        // A single-use transaction-typ token without `jti` must fail closed
        // rather than silently skip replay protection.
        let error = consume_notary_token_jti(&payload, &anchor, &replay)
            .await
            .expect_err("missing jti for single-use typ fails closed");
        assert!(matches!(error, EvidenceError::MissingCredential));

        // A non-single-use typ legitimately has no `jti` and is accepted.
        let other_anchor = NotaryTokenAnchor {
            token_typ: "registry-notary-access+jwt".to_string(),
            ..anchor
        };
        consume_notary_token_jti(&payload, &other_anchor, &replay)
            .await
            .expect("missing jti for non-single-use typ is accepted");
    }
    fn auth_state(audit: AuditPipeline) -> Arc<AuthAuditState> {
        Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator {
                api_keys: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: Vec::new(),
                    authorization_details: None,
                }],
                bearer_tokens: Vec::new(),
                oidc: None,
            })),
            audit,
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            subject_access_invalid_token_limiter: None,
            subject_access_rate_keys: None,
        })
    }

    #[test]
    fn evidence_service_discovery_is_not_auth_exempt() {
        let protected_openapi = AuthExemptionPolicy {
            openapi_requires_auth: true,
        };
        assert!(
            !is_auth_exempt_path("/.well-known/evidence-service", protected_openapi),
            "service discovery exposes configured capability metadata and must stay authenticated"
        );
        assert!(is_auth_exempt_path("/healthz", protected_openapi));
        assert!(is_auth_exempt_path(
            "/.well-known/evidence/jwks.json",
            protected_openapi
        ));
        assert!(!is_auth_exempt_path("/openapi.json", protected_openapi));

        let public_openapi = AuthExemptionPolicy {
            openapi_requires_auth: false,
        };
        assert!(is_auth_exempt_path("/openapi.json", public_openapi));
        assert!(
            !is_auth_exempt_path("/.well-known/evidence-service", public_openapi),
            "server.openapi_requires_auth only affects /openapi.json"
        );
    }
    #[tokio::test]
    async fn invalid_bearer_tokens_are_rate_limited_when_subject_access_is_enabled() {
        let rate_limits = SubjectAccessRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 1,
            per_principal_per_minute: 1,
            subject_mismatch_per_principal_per_hour: 1,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 1,
            ..SubjectAccessRateLimitsConfig::default()
        };
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new()));
        let state = Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator {
                api_keys: Vec::new(),
                bearer_tokens: Vec::new(),
                oidc: None,
            })),
            audit: audit.clone(),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            subject_access_invalid_token_limiter: Some(Arc::new(
                SubjectAccessRateLimiter::new(rate_limits),
            )),
            subject_access_rate_keys: Some(Arc::new(SubjectAccessRateLimitKeys::new(
                audit.profile.key_hasher(),
            ))),
        });
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state, auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let first = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        first.assert_status(StatusCode::UNAUTHORIZED);

        let second = server
            .get("/ok")
            .add_header(header::AUTHORIZATION, "Bearer invalid-token")
            .await;
        second.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: Value = second.json();
        assert_eq!(body["code"], json!("subject_access.rate_limited"));
    }

    #[tokio::test]
    async fn missing_credentials_are_rate_limited_when_subject_access_is_enabled() {
        let rate_limits = SubjectAccessRateLimitsConfig {
            invalid_token_per_client_address_per_minute: 1,
            per_principal_per_minute: 1,
            subject_mismatch_per_principal_per_hour: 1,
            per_holder_per_hour: 1,
            credential_issuance_per_principal_per_hour: 1,
            ..SubjectAccessRateLimitsConfig::default()
        };
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new()));
        let state = Arc::new(AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator {
                api_keys: Vec::new(),
                bearer_tokens: Vec::new(),
                oidc: None,
            })),
            audit: audit.clone(),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            subject_access_invalid_token_limiter: Some(Arc::new(
                SubjectAccessRateLimiter::new(rate_limits),
            )),
            subject_access_rate_keys: Some(Arc::new(SubjectAccessRateLimitKeys::new(
                audit.profile.key_hasher(),
            ))),
        });
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(state, auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let first = server.get("/ok").await;
        first.assert_status(StatusCode::UNAUTHORIZED);

        let second = server.get("/ok").await;
        second.assert_status(StatusCode::TOO_MANY_REQUESTS);
        let body: Value = second.json();
        assert_eq!(body["code"], json!("subject_access.rate_limited"));
    }

    #[tokio::test]
    async fn auth_state_accepts_case_insensitive_bearer_scheme() {
        let state = AuthAuditState {
            authenticator: RwLock::new(Arc::new(Authenticator {
                api_keys: Vec::new(),
                bearer_tokens: vec![ResolvedCredential {
                    id: "caseworker".to_string(),
                    fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                    scopes: vec!["farmer_registry:evidence_verification".to_string()],
                    authorization_details: None,
                }],
                oidc: None,
            })),
            audit: AuditPipeline::for_sink_dev_only(Arc::new(JsonlStdoutSink::new())),
            replay: ReplayStores::memory(),
            metrics: Arc::new(AppMetrics::default()),
            openapi_requires_auth: AtomicBool::new(true),
            subject_access_invalid_token_limiter: None,
            subject_access_rate_keys: None,
        };
        let request = Request::builder()
            .uri("/v1/claims")
            .header(header::AUTHORIZATION, "BEARER api-token")
            .body(Body::empty())
            .expect("request builds");

        let principal = state
            .authenticate(request_credentials(&request))
            .await
            .expect("bearer auth succeeds");

        assert_eq!(
            principal.auth_profile_id,
            EvidenceAuthProfileId::StaticBearer
        );
        assert_eq!(principal.principal_id, "caseworker");
    }

    #[tokio::test]
    async fn static_auth_rejects_multiple_credential_headers() {
        let authenticator = Authenticator {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            bearer_tokens: vec![ResolvedCredential {
                id: "bearer-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("bearer-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            oidc: None,
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };

        let err = authenticator
            .authenticate(request, &ReplayStores::memory())
            .await
            .expect_err("multiple credentials must fail");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[tokio::test]
    async fn static_auth_rejects_api_key_with_malformed_authorization_header() {
        let authenticator = Authenticator {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            bearer_tokens: Vec::new(),
            oidc: None,
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        let err = authenticator
            .authenticate(request, &ReplayStores::memory())
            .await
            .expect_err("ambiguous credentials must not fall back to api key");

        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[tokio::test]
    async fn request_credentials_counts_non_utf8_authorization_header_presence() {
        let authenticator = Authenticator {
            api_keys: vec![ResolvedCredential {
                id: "api-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            bearer_tokens: Vec::new(),
            oidc: None,
        };
        let mut request = Request::builder()
            .uri("/v1/claims")
            .header("x-api-key", "api-token")
            .body(Body::empty())
            .expect("request builds");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_bytes(b"\xff").expect("opaque header value is valid"),
        );

        let credentials = request_credentials(&request);
        assert!(credentials.authorization_present);
        assert!(credentials.api_key_present);
        assert!(credentials.bearer_token.is_none());
        assert_eq!(credentials.api_key.as_deref(), Some("api-token"));
        assert_eq!(credentials.credential_type_count(), 2);

        let err = authenticator
            .authenticate(credentials, &ReplayStores::memory())
            .await
            .expect_err("raw credential channel presence must reject ambiguity");
        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[tokio::test]
    async fn request_credentials_counts_non_utf8_api_key_header_presence() {
        let authenticator = Authenticator {
            api_keys: Vec::new(),
            bearer_tokens: vec![ResolvedCredential {
                id: "bearer-client".to_string(),
                fingerprint: registry_platform_authcommon::fingerprint_api_key("bearer-token"),
                scopes: vec!["farmer_registry:evidence_verification".to_string()],
                authorization_details: None,
            }],
            oidc: None,
        };
        let mut request = Request::builder()
            .uri("/v1/claims")
            .header(header::AUTHORIZATION, "Bearer bearer-token")
            .body(Body::empty())
            .expect("request builds");
        request.headers_mut().insert(
            "x-api-key",
            axum::http::HeaderValue::from_bytes(b"\xff").expect("opaque header value is valid"),
        );

        let credentials = request_credentials(&request);
        assert!(credentials.api_key_present);
        assert!(credentials.api_key.is_none());
        assert!(credentials.authorization_present);
        assert_eq!(credentials.bearer_token.as_deref(), Some("bearer-token"));
        assert_eq!(credentials.credential_type_count(), 2);

        let err = authenticator
            .authenticate(credentials, &ReplayStores::memory())
            .await
            .expect_err("raw credential channel presence must reject ambiguity");
        assert!(matches!(err, EvidenceError::MultipleCredentials));
    }

    #[test]
    fn oidc_id_token_is_supplemental_not_a_separate_auth_mode() {
        let oidc_request = RequestCredentials {
            api_key: None,
            api_key_present: false,
            authorization_present: true,
            bearer_token: Some("access-token".to_string()),
            id_token: Some("id-token".to_string()),
        };
        let api_key_and_bearer = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: true,
            bearer_token: Some("bearer-token".to_string()),
            id_token: None,
        };
        let api_key_and_malformed_authorization = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: true,
            bearer_token: None,
            id_token: None,
        };

        assert_eq!(oidc_request.credential_type_count(), 1);
        assert_eq!(api_key_and_bearer.credential_type_count(), 2);
        assert_eq!(
            api_key_and_malformed_authorization.credential_type_count(),
            2
        );
    }

    #[test]
    fn static_credentials_have_machine_access_and_no_verified_claims() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: None,
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };

        let authenticated =
            authenticate_static(&request, &[credential], &[]).expect("static auth succeeds");

        assert_eq!(
            authenticated.auth_profile_id,
            EvidenceAuthProfileId::StaticApiKey
        );
        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "caseworker");
        assert_eq!(
            authenticated.scopes,
            vec!["farmer_registry:evidence_verification".to_string()]
        );
        assert!(authenticated.verified_claims.is_none());
        assert!(authenticated.authorization_details.is_none());
    }

    #[test]
    fn static_credentials_can_carry_configured_authorization_details() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: Some(EvidenceAuthorizationDetails {
                detail_type: "registry-notary/evidence-authorization/v1".to_string(),
                schema_version: "v1".to_string(),
                legal_basis_ref: Some("demo:casework".to_string()),
                consent_ref: Some("demo:consent".to_string()),
                jurisdiction: Some("ZZ".to_string()),
                assurance_level: Some("substantial".to_string()),
                ..EvidenceAuthorizationDetails::default()
            }),
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };

        let authenticated =
            authenticate_static(&request, &[credential], &[]).expect("static auth succeeds");
        let details = authenticated
            .authorization_details
            .expect("configured authorization details are trusted context");

        assert_eq!(details.legal_basis_ref.as_deref(), Some("demo:casework"));
        assert_eq!(details.consent_ref.as_deref(), Some("demo:consent"));
        assert_eq!(details.jurisdiction.as_deref(), Some("ZZ"));
        assert_eq!(details.assurance_level.as_deref(), Some("substantial"));
    }

    fn verified_token_with_extra(extra: Map<String, Value>) -> VerifiedToken {
        VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("registry-notary".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: Some("fallback-client".to_string()),
                extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "evidence:self_attest".to_string()],
        }
    }

    #[test]
    fn oidc_principal_carries_bounded_verified_claims() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let mut extra = Map::new();
        extra.insert("scope".to_string(), json!("openid evidence:self_attest"));
        extra.insert(subject_binding_claim.to_string(), json!("NAT-123"));
        extra.insert("acr".to_string(), json!("loa3"));
        extra.insert("auth_time".to_string(), json!(1_700_000_000_i64));
        extra.insert("auth_profile_id".to_string(), json!("static_api_key"));
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::Many(vec![
                    "registry-notary".to_string(),
                    "citizen-portal".to_string(),
                ])),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: Some("fallback-client".to_string()),
                extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "evidence:self_attest".to_string()],
        };

        let authenticated = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            subject_binding_claim,
            Some(subject_binding_claim),
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(
            authenticated.auth_profile_id,
            EvidenceAuthProfileId::ExternalOidc,
            "attacker-controlled claims cannot choose the authentication profile"
        );
        assert_eq!(authenticated.access_mode, AccessMode::MachineClient);
        assert_eq!(authenticated.principal_id, "NAT-123");
        assert_eq!(
            verified_claims.issuer.as_str(),
            "https://issuer.example.test"
        );
        assert_eq!(
            verified_claims
                .audiences
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["registry-notary", "citizen-portal"]
        );
        assert_eq!(
            verified_claims
                .client_id
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("azp:citizen-client")
        );
        assert_eq!(
            verified_claims
                .token_type
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("JWT")
        );
        assert_eq!(
            verified_claims
                .scopes
                .iter()
                .map(VerifiedClaimValue::as_str)
                .collect::<Vec<_>>(),
            vec!["openid", "evidence:self_attest"]
        );
        assert_eq!(
            verified_claims
                .subject
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("login-subject-123")
        );
        assert_eq!(
            verified_claims
                .subject_binding_claim
                .as_ref()
                .map(VerifiedClaimName::as_str),
            Some(subject_binding_claim)
        );
        assert_eq!(
            verified_claims
                .subject_binding_value
                .as_ref()
                .map(VerifiedClaimValue::as_str),
            Some("NAT-123")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("loa3")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_000));
        assert_eq!(verified_claims.exp, Some(1_700_003_600));
        assert_eq!(verified_claims.iat, Some(1_700_000_000));
        assert_eq!(verified_claims.nbf, Some(1_699_999_900));
    }

    #[test]
    fn oidc_principal_requires_configured_principal_claim() {
        let verified = verified_token_with_extra(Map::new());

        let error = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "national_id",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect_err("missing configured principal claim must not fall back to matched client");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_matched_client_id_when_default_sub_is_missing() {
        let mut verified = verified_token_with_extra(Map::new());
        verified.claims.sub = None;
        verified.claims.azp = None;
        verified.claims.client_id = Some("service-client".to_string());
        verified.matched_client = Some("client_id:service-client".to_string());

        let error = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect_err("matched client_id must not replace a missing sub principal");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_matched_azp_when_default_sub_is_missing() {
        let mut verified = verified_token_with_extra(Map::new());
        verified.claims.sub = None;
        verified.claims.azp = Some("service-client".to_string());
        verified.claims.client_id = None;
        verified.matched_client = Some("azp:service-client".to_string());

        let error = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect_err("matched azp alone is not a client-credentials principal");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_malformed_matching_authorization_details() {
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([{
                "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
                "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                "actions": "evaluate"
            }]),
        );
        let verified = verified_token_with_extra(extra);

        let error = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect_err("malformed matching authorization_details must fail auth");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_rejects_duplicate_matching_authorization_details() {
        let detail = json!({
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["registry-notary"]
        });
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([detail.clone(), detail]),
        );
        let verified = verified_token_with_extra(extra);

        let error = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect_err("duplicate matching authorization_details must fail auth");

        assert!(matches!(error, EvidenceError::MissingCredential));
    }

    #[test]
    fn oidc_principal_ignores_context_only_matching_authorization_details() {
        let mut extra = Map::new();
        extra.insert(
            "authorization_details".to_string(),
            json!([{
                "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
                "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
                "legal_basis_ref": "demo:casework",
                "consent_ref": "demo:consent",
                "jurisdiction": "ZZ",
                "assurance_level": "substantial"
            }]),
        );
        let verified = verified_token_with_extra(extra);

        let principal = principal_from_oidc(
            &verified,
            EvidenceAuthProfileId::ExternalOidc,
            None,
            None,
            verified_claim_value("JWT"),
            "sub",
            None,
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .expect("context-only OIDC authorization_details fall back to scope checks");

        assert!(principal.authorization_details.is_none());
    }

    #[test]
    fn oidc_principal_can_bind_userinfo_claims_and_id_token_assurance() {
        let mut access_extra = Map::new();
        access_extra.insert("scope".to_string(), json!("openid subject_access"));
        let access_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: None,
                azp: Some("citizen-client".to_string()),
                client_id: Some("citizen-client".to_string()),
                extra: access_extra,
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["openid".to_string(), "subject_access".to_string()],
        };
        let mut userinfo_extra = Map::new();
        userinfo_extra.insert("individual_id".to_string(), json!("NID-1001"));
        let userinfo = registry_platform_oidc::Claims {
            sub: Some("pairwise-subject".to_string()),
            iss: Some("https://issuer.example.test".to_string()),
            aud: None,
            exp: None,
            iat: None,
            nbf: None,
            azp: None,
            client_id: None,
            extra: userinfo_extra,
        };
        let mut id_token_extra = Map::new();
        id_token_extra.insert("acr".to_string(), json!("mosip:idp:acr:generated-code"));
        id_token_extra.insert("auth_time".to_string(), json!(1_700_000_010_i64));
        let id_token = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("pairwise-subject".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("citizen-client".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_010),
                nbf: None,
                azp: None,
                client_id: None,
                extra: id_token_extra,
            },
            matched_client: None,
            scopes: Vec::new(),
        };

        let authenticated = principal_from_oidc(
            &access_token,
            EvidenceAuthProfileId::ExternalOidc,
            Some(&userinfo),
            Some(&id_token),
            verified_claim_value("JWT"),
            "sub",
            Some("individual_id"),
            SubjectAccessClaimSource::Userinfo,
            SubjectAccessAssuranceClaimSource::IdToken,
        )
        .expect("OIDC principal is derived");
        let verified_claims = authenticated
            .verified_claims
            .expect("verified claims are transported");

        assert_eq!(authenticated.principal_id, "pairwise-subject");
        assert_eq!(
            verified_claims.subject_binding_value("individual_id"),
            Some("NID-1001")
        );
        assert_eq!(
            verified_claims.acr.as_ref().map(VerifiedClaimValue::as_str),
            Some("mosip:idp:acr:generated-code")
        );
        assert_eq!(verified_claims.auth_time, Some(1_700_000_010));
    }

    #[test]
    fn oidc_verified_claims_fail_closed_without_string_subject_binding_claim() {
        let subject_binding_claim = "https://id.example.gov/claims/national_id";
        let verified = VerifiedToken {
            claims: registry_platform_oidc::Claims {
                sub: Some("login-subject-123".to_string()),
                iss: Some("https://issuer.example.test".to_string()),
                aud: Some(Audience::One("registry-notary".to_string())),
                exp: Some(1_700_003_600),
                iat: Some(1_700_000_000),
                nbf: Some(1_699_999_900),
                azp: Some("citizen-client".to_string()),
                client_id: None,
                extra: Map::new(),
            },
            matched_client: Some("azp:citizen-client".to_string()),
            scopes: vec!["evidence:self_attest".to_string()],
        };

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .is_none());

        let mut verified = verified;
        verified
            .claims
            .extra
            .insert(subject_binding_claim.to_string(), json!(12345));

        assert!(bounded_verified_claims_from_oidc(
            &verified,
            None,
            None,
            verified_claim_value("JWT"),
            Some(subject_binding_claim),
            SubjectAccessClaimSource::AccessToken,
            SubjectAccessAssuranceClaimSource::AccessToken,
        )
        .is_none());
    }

    #[test]
    fn oidc_validation_errors_are_internal_invalid_token_auth_failures() {
        assert_eq!(
            oidc_internal_error_code(&OidcError::TokenExpired),
            "auth.invalid_token"
        );
        assert!(matches!(
            oidc_auth_error(OidcError::TokenExpired),
            EvidenceError::MissingCredential
        ));
    }

    #[test]
    fn credential_principal_debug_and_auth_errors_do_not_expose_secrets() {
        let credential = ResolvedCredential {
            id: "caseworker".to_string(),
            fingerprint: registry_platform_authcommon::fingerprint_api_key("api-token"),
            scopes: vec!["farmer_registry:evidence_verification".to_string()],
            authorization_details: Some(EvidenceAuthorizationDetails {
                detail_type: "registry-notary/evidence-authorization/v1".to_string(),
                schema_version: "v1".to_string(),
                legal_basis_ref: Some("demo:casework".to_string()),
                consent_ref: Some("demo:consent".to_string()),
                jurisdiction: Some("ZZ".to_string()),
                assurance_level: Some("substantial".to_string()),
                ..EvidenceAuthorizationDetails::default()
            }),
        };
        let request = RequestCredentials {
            api_key: Some("api-token".to_string()),
            api_key_present: true,
            authorization_present: false,
            bearer_token: None,
            id_token: None,
        };
        let principal = authenticate_static(&request, std::slice::from_ref(&credential), &[])
            .expect("static auth succeeds");
        let rejected_secret = "rejected-api-token";
        let error = authenticate_static(
            &RequestCredentials {
                api_key: Some(rejected_secret.to_string()),
                api_key_present: true,
                authorization_present: false,
                bearer_token: None,
                id_token: None,
            },
            std::slice::from_ref(&credential),
            &[],
        )
        .expect_err("unknown API key is rejected");
        let debug = format!("{credential:?} {principal:?}");
        let error_output = format!("{error:?} {error}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("api-token"));
        assert!(!error_output.contains(rejected_secret));
    }
