// SPDX-License-Identifier: Apache-2.0

    #[test]
    fn render_cccev_uses_result_claim_version_for_requirement() {
        let mut older_claim = test_claim("selected", Vec::new(), true);
        older_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v1".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.oots = Some(registry_notary_core::OotsConfig {
            enabled: true,
            requirement: Some("https://requirements.example/v2".to_string()),
            ..registry_notary_core::OotsConfig::default()
        });
        let evidence = test_evidence(vec![older_claim, newer_claim]);
        let result = ClaimResultView {
            evaluation_id: "evaluation".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "2.0".to_string(),
            subject_type: "person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:target".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "value".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "runtime.test".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "2.0".to_string(),
                ProvenanceUsed {
                    relay_consultation_count: 0,
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert_eq!(
            rendered["@graph"][0]["cccev:supportsRequirement"]["@id"],
            json!("https://requirements.example/v2")
        );
    }

    #[test]
    fn render_cccev_maps_provider_agent_from_generated_by_service_id() {
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let result = ClaimResultView {
            evaluation_id: "eval-test".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "1".to_string(),
            subject_type: "Person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:test".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            value: Some(json!(true)),
            satisfied: Some(true),
            disclosure: "predicate".to_string(),
            redacted_fields: Vec::new(),
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "registry-notary".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "1".to_string(),
                ProvenanceUsed {
                    relay_consultation_count: 0,
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert_eq!(
            rendered["@graph"][0]["cccev:isProvidedBy"]["dcterms:identifier"],
            json!("registry-notary"),
            "CCCEV provider agent must map from generated_by.service_id"
        );
    }

    #[test]
    fn render_cccev_omits_conformance_for_redacted_result() {
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let result = ClaimResultView {
            evaluation_id: "eval-test".to_string(),
            claim_id: "selected".to_string(),
            claim_version: "1".to_string(),
            subject_type: "Person".to_string(),
            requester_ref: None,
            target_ref: TargetRefView {
                entity_type: "Person".to_string(),
                handle: "rnref:v1:test".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            value: None,
            satisfied: None,
            disclosure: "redacted".to_string(),
            redacted_fields: vec!["selected".to_string()],
            format: FORMAT_CCCEV_JSONLD.to_string(),
            issued_at: "2026-06-08T00:00:00Z".to_string(),
            expires_at: None,
            provenance: ClaimProvenance::new(
                "registry-notary".to_string(),
                "eval-test".to_string(),
                "selected".to_string(),
                "1".to_string(),
                ProvenanceUsed {
                    relay_consultation_count: 0,
                },
            ),
        };

        let rendered =
            render_results(&evidence, &[result], FORMAT_CCCEV_JSONLD).expect("CCCEV renders");

        assert!(
            rendered["@graph"][0].get("cccev:isConformantTo").is_none(),
            "redacted CCCEV evidence must not reveal a false outcome"
        );
    }

    #[test]
    fn credential_profile_for_rejects_profile_not_listed_in_claim() {
        // A caller-supplied credential_profile must be in the requested claim's
        // own credential_profiles allow-list. Otherwise a client could mint a
        // credential against a profile the claim never opted in to.
        let evidence: EvidenceConfig = serde_norway::from_str(
            r#"
enabled: true
service_id: test.notary
claims:
  - id: claim-a
    title: A
    version: "1.0"
    subject_type: person
    evidence_mode:
      type: self_attested
    rule:
      type: cel
      expression: "true"
    credential_profiles:
      - profile_a
signing_keys:
  issuer-key:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY
    alg: EdDSA
    kid: did:web:issuer.example#key-1
    status: active
  issuer-key-b:
    provider: local_jwk_env
    private_jwk_env: ISSUER_KEY_B
    alg: EdDSA
    kid: did:web:issuer.example#key-2
    status: active
credential_profiles:
  profile_a:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key
    vct: https://vct.example/a
    allowed_claims:
      - claim-a
  profile_b:
    format: application/dc+sd-jwt
    issuer: https://issuer.example
    signing_key: issuer-key-b
    vct: https://vct.example/b
    allowed_claims:
      - claim-a
"#,
        )
        .expect("evidence config is valid YAML");

        let evaluation = registry_notary_core::StoredEvaluation {
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
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect_err("profile_b is not listed on claim-a");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect("profile_a is listed on claim-a");
        assert_eq!(profile_id, "profile_a");
    }

    #[test]
    fn credential_profile_for_uses_stored_claim_version() {
        let mut older_claim = test_claim("claim-a", Vec::new(), true);
        older_claim.credential_profiles = vec!["profile_a".to_string()];
        let mut newer_claim = test_claim("claim-a", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        newer_claim.credential_profiles = vec!["profile_b".to_string()];
        let mut evidence = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence.credential_profiles = serde_norway::from_str(
            r#"
profile_a:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/a
  allowed_claims: [claim-a]
profile_b:
  format: application/dc+sd-jwt
  issuer: https://issuer.example
  signing_key: issuer-key
  vct: https://vct.example/b
  allowed_claims: [claim-a]
"#,
        )
        .expect("credential profiles parse");
        let evaluation = registry_notary_core::StoredEvaluation {
            client_id: "client".to_string(),
            purpose: "test".to_string(),
            claim_ids: vec!["claim-a".to_string()],
            claim_refs: vec![ClaimRef::with_version("claim-a", "2.0")],
            disclosure: "redacted".to_string(),
            format: FORMAT_SD_JWT_VC.to_string(),
            results: Vec::new(),
            created_at: "1970-01-01T00:00:00Z".to_string(),
            expires_at: "1970-01-01T00:00:00Z".to_string(),
            request_hash: "h".to_string(),
            self_attestation: None,
        };

        let err = credential_profile_for(&evidence, &evaluation, Some("profile_a"))
            .expect_err("profile_a is not listed on claim-a version 2.0");
        assert!(matches!(err, EvidenceError::CredentialIssuerNotConfigured));

        let (profile_id, _) = credential_profile_for(&evidence, &evaluation, Some("profile_b"))
            .expect("profile_b is listed on claim-a version 2.0");
        assert_eq!(profile_id, "profile_b");
        let (profile_id, _) =
            credential_profile_for(&evidence, &evaluation, None).expect("default profile resolves");
        assert_eq!(profile_id, "profile_b");
    }
