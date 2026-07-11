    // SPDX-License-Identifier: Apache-2.0

    #[test]
    fn access_token_verification_key_enforces_publish_until_boundary() {
        let public_jwk = PublicJwk::parse(TEST_OLD_ISSUER_PUBLIC_JWK).expect("public jwk parses");
        let active_key = AccessTokenVerificationKey {
            public_jwk: public_jwk.clone(),
            publish_until_unix_seconds: None,
        };
        assert!(active_key.may_verify_at(i64::MAX));

        let expiring_key = AccessTokenVerificationKey {
            public_jwk,
            publish_until_unix_seconds: Some(1_000),
        };
        assert!(expiring_key.may_verify_at(999));
        assert!(expiring_key.may_verify_at(1_000));
        assert!(!expiring_key.may_verify_at(1_001));
        assert!(!expiring_key.may_verify_at(-1));
    }

    #[test]
    fn esignet_verifier_config_does_not_require_userinfo_exp() {
        // MOSIP eSignet signs its userinfo JWS without an `exp` claim, which the
        // OpenID Connect Core spec permits for UserInfo responses. The RP verifier
        // must therefore not require one, or every userinfo-sourced binding fails.
        let config = esignet_token_verifier_config("https://esignet.example", "rp-client");

        assert!(!config.userinfo_requires_exp);
        assert_eq!(config.issuer, "https://esignet.example");
        assert_eq!(config.audiences, vec!["rp-client".to_string()]);
        assert_eq!(config.allowed_userinfo_typ, vec!["JWT".to_string()]);
    }
