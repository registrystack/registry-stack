// SPDX-License-Identifier: Apache-2.0

    #[test]
    fn value_disclosure_rejects_object_redaction_when_configured_field_is_absent() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "selected",
            json!({"name": "Ada"}),
            BTreeSet::from(["ssn".to_string()]),
        );

        let err = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("missing redaction field must fail value disclosure");

        assert!(matches!(err, EvidenceError::DisclosureNotAllowed));
    }

    #[test]
    fn value_disclosure_removes_every_configured_object_redaction_field() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "selected",
            json!({"name": "Ada", "ssn": "123", "case_id": "c-1"}),
            BTreeSet::from(["case_id".to_string(), "ssn".to_string()]),
        );

        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("configured fields are redacted");

        assert_eq!(view.value, Some(json!({"name": "Ada"})));
    }

    #[test]
    fn predicate_disclosure_rejects_redacted_claim_result() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.disclosure.allowed.push("predicate".to_string());
        let result = test_claim_result(
            "selected",
            json!(true),
            BTreeSet::from(["value".to_string()]),
        );

        let err = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Predicate,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect_err("predicate disclosure must not bypass redaction");

        assert!(matches!(err, EvidenceError::DisclosureNotAllowed));
    }

    #[test]
    fn redacted_scalar_disclosure_reports_redacted_claim_id() {
        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let claim = test_claim("opencrvs-age-band", Vec::new(), false);
        let result = test_claim_result("opencrvs-age-band", json!("child"), BTreeSet::new());

        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Redacted,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("scalar claim can be redacted");

        assert_eq!(view.value, None);
        assert_eq!(view.redacted_fields, vec!["opencrvs-age-band".to_string()]);
    }

    #[tokio::test]
    async fn issued_sd_jwt_disclosure_uses_view_claim_redacted_object_value() {
        const RAW_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

        let keys = SelfAttestationRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());
        let mut claim = test_claim("household-summary", Vec::new(), false);
        claim.value.value_type = "object".to_string();
        let result = test_claim_result(
            "household-summary",
            json!({
                "name": "Ada",
                "household_id": "hh-1",
                "ssn": "123-45-6789"
            }),
            BTreeSet::from(["ssn".to_string()]),
        );
        let view = view_claim(
            &keys,
            &result,
            &claim,
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON,
        )
        .expect("configured object field is redacted before issuance");
        assert_eq!(
            view.value,
            Some(json!({
                "name": "Ada",
                "household_id": "hh-1"
            }))
        );

        let issuer = registry_notary_core::sd_jwt::EvidenceIssuer::from_jwk_str(
            RAW_JWK,
            "did:web:issuer.test#key-1".to_string(),
        )
        .expect("test issuer builds");
        let profile = CredentialProfileConfig {
            format: FORMAT_SD_JWT_VC.to_string(),
            issuer: "did:web:issuer.test".to_string(),
            signing_key: "issuer-key".to_string(),
            vct: "https://vct.example/test".to_string(),
            validity_seconds: 60,
            holder_binding: registry_notary_core::HolderBindingConfig {
                mode: "none".to_string(),
                proof_of_possession: None,
                allowed_did_methods: Vec::new(),
            },
            allowed_claims: Vec::new(),
            disclosure: Default::default(),
        };
        let signed = registry_notary_core::sd_jwt::issue(
            &profile,
            &issuer,
            &[view],
            "subject-ref",
            None,
            OffsetDateTime::UNIX_EPOCH,
            registry_notary_core::sd_jwt::IssueOptions::default(),
        )
        .await
        .expect("credential issues");
        let disclosures = signed
            .disclosures
            .iter()
            .map(|disclosure| {
                serde_json::from_slice::<Value>(
                    &URL_SAFE_NO_PAD
                        .decode(disclosure)
                        .expect("disclosure decodes as base64url"),
                )
                .expect("disclosure decodes as JSON")
            })
            .collect::<Vec<_>>();
        let disclosure = disclosures
            .iter()
            .find(|disclosure| disclosure.get(1) == Some(&json!("household-summary")))
            .expect("household-summary disclosure exists");
        let disclosure_json = serde_json::to_string(&disclosures).expect("disclosures serialize");

        assert_eq!(disclosure[2]["value"]["name"], json!("Ada"));
        assert_eq!(disclosure[2]["value"]["household_id"], json!("hh-1"));
        assert!(disclosure[2]["value"].get("ssn").is_none());
        assert!(!disclosure_json.contains("ssn"), "{disclosure_json}");
        assert!(
            !disclosure_json.contains("123-45-6789"),
            "{disclosure_json}"
        );
    }
