// SPDX-License-Identifier: Apache-2.0

    #[test]
    fn runtime_claim_closure_defends_v1_node_and_edge_bounds() {
        let mut node_claims = Vec::new();
        for index in 0..=MAX_CLAIM_DEPENDENCY_NODES_V1 {
            let dependency = (index > 0).then(|| format!("claim-{}", index - 1));
            let mut claim = test_claim(&format!("claim-{index}"), Vec::new(), false);
            claim.depends_on = dependency.into_iter().collect();
            node_claims.push(claim);
        }
        let node_evidence = test_evidence(node_claims);
        let requested = vec![ClaimRef::from(format!(
            "claim-{}",
            MAX_CLAIM_DEPENDENCY_NODES_V1
        ))];
        let versions = requested_claim_versions(&requested).expect("selection is valid");
        assert!(matches!(
            build_claim_levels(&node_evidence, &requested, &versions),
            Err(EvidenceError::RuleEvaluationFailed)
        ));

        let mut edge_claims = Vec::new();
        for index in 0..24 {
            let mut claim = test_claim(&format!("edge-{index}"), Vec::new(), false);
            claim.depends_on = (0..index)
                .map(|dependency| format!("edge-{dependency}"))
                .collect();
            edge_claims.push(claim);
        }
        let edge_evidence = test_evidence(edge_claims);
        let requested = vec![ClaimRef::from("edge-23")];
        let versions = requested_claim_versions(&requested).expect("selection is valid");
        assert!(matches!(
            build_claim_levels(&edge_evidence, &requested, &versions),
            Err(EvidenceError::RuleEvaluationFailed)
        ));
    }

    #[test]
    fn claim_summary_advertises_cccev_evidence_type_metadata() {
        let mut claim = test_claim("civil-child-status", Vec::new(), false);
        claim.cccev = Some(registry_notary_core::CccevConfig {
            requirement_type: Some("InformationRequirement".to_string()),
            evidence_type: Some("civil_child_status_evidence".to_string()),
            evidence_type_iri: Some(
                "https://demo.example.gov/evidence-types/civil-child-status".to_string(),
            ),
        });

        let summary = claim_summary(&claim);

        assert_eq!(summary["evidence_type"], "civil_child_status_evidence");
        assert_eq!(
            summary["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
        assert_eq!(
            summary["cccev"]["evidence_type_iri"],
            "https://demo.example.gov/evidence-types/civil-child-status"
        );
    }

    #[test]
    fn claim_summary_advertises_safe_target_inputs_from_relay_consultation() {
        let mut claim = registry_claim(
            "birth-record-exists",
            RuleConfig::ConsultationMatched {
                consultation: "enrollment".to_string(),
            },
            "boolean",
        );
        let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
            panic!("claim is registry-backed")
        };
        let consultation = consultations
            .get_mut("enrollment")
            .expect("consultation exists");
        consultation.inputs = BTreeMap::from([(
            "national_id".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.national_id".to_string(),
            ),
        )]);

        let summary = claim_summary(&claim);

        let target_inputs = summary["target_inputs"]
            .as_array()
            .expect("target inputs are advertised");
        assert_eq!(target_inputs.len(), 1);
        let method = &target_inputs[0];
        assert_eq!(method["method"], "relay_consultation");
        assert_eq!(method["target_type"], "person");
        assert_eq!(method["confidence"], "contract_pinned");
        assert_eq!(
            method["groups"][0]["inputs"],
            json!([
                {
                    "path": "target.identifiers.national_id",
                    "kind": "identifier",
                    "name": "national_id",
                    "label": "National id",
                }
            ])
        );
    }

    #[test]
    fn claim_summary_omits_target_inputs_without_relay_consultation() {
        let claim = test_claim("date-of-birth", Vec::new(), false);

        let summary = claim_summary(&claim);

        assert!(summary.get("target_inputs").is_none());
    }

    #[test]
    fn subject_access_evaluation_capability_uses_keyed_subject_binding_hash() {
        const ENV: &str = "TEST_RUNTIME_AUDIT_HASH_SECRET";
        std::env::set_var(ENV, "0123456789abcdef0123456789abcdef");
        let keys = SubjectAccessRateLimitKeys::new(
            AuditKeyHasher::from_env(ENV).expect("test audit hasher loads"),
        );
        let mut principal = subject_access_principal();
        principal.verified_claims = Some(
            serde_json::from_value(json!({
                "issuer": "https://id.example.gov",
                "audiences": ["registry-notary"],
                "subject_binding_claim": "national_id",
                "subject_binding_value": "12345678901"
            }))
            .expect("verified claims parse"),
        );

        let capability =
            evaluation_capability_for_principal(&keys, &principal, &["selected".to_string()])
                .expect("evaluation capability builds");
        let EvaluationCapability::SubjectBound {
            subject_binding_hash,
            ..
        } = capability
        else {
            panic!("expected subject-access capability");
        };

        assert!(subject_binding_hash.as_str().starts_with("hmac-sha256:"));
        assert!(!subject_binding_hash.as_str().contains("12345678901"));
    }

    #[test]
    fn service_document_advertises_api_key_and_bearer_auth() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);

        assert_eq!(document["auth"]["methods"], json!(["api_key", "bearer"]));
        assert_eq!(document["auth"]["api_key"]["header"], json!("X-Api-Key"));
        assert_eq!(document["auth"]["bearer"]["header"], json!("Authorization"));
        assert_eq!(document["auth"]["bearer"]["scheme"], json!("bearer"));
        assert_eq!(
            document["auth"]["bearer"]["format"],
            json!("Bearer <token>")
        );
        assert_eq!(document["auth"]["audience"], json!("evidence.test"));
    }

    #[test]
    fn service_document_advertises_sd_jwt_vc_conformance_capabilities() {
        let mut credential_profiles = BTreeMap::new();
        credential_profiles.insert(
            "profile-a".to_string(),
            CredentialProfileConfig {
                format: FORMAT_SD_JWT_VC.to_string(),
                issuer: "did:web:issuer.test".to_string(),
                signing_key: "issuer-key".to_string(),
                vct: "https://issuer.test/credentials/profile-a".to_string(),
                validity_seconds: 600,
                holder_binding: registry_notary_core::HolderBindingConfig {
                    mode: "did".to_string(),
                    proof_of_possession: Some("required".to_string()),
                    allowed_did_methods: vec![SD_JWT_VC_HOLDER_BINDING_METHOD.to_string()],
                },
                allowed_claims: vec!["claim-a".to_string()],
                disclosure: registry_notary_core::CredentialDisclosureConfig {
                    allowed: vec!["predicate".to_string()],
                },
            },
        );
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            credential_profiles,
            signing_keys: BTreeMap::from([(
                "issuer-key".to_string(),
                serde_json::from_value(json!({
                    "provider": "local_jwk_env",
                    "private_jwk_env": "ISSUER_KEY",
                    "alg": "ES256",
                    "kid": "did:web:issuer.test#key-1",
                    "status": "active"
                }))
                .expect("signing key parses"),
            )]),
            ..EvidenceConfig::default()
        };

        let document = RegistryNotaryRuntime::service_document(&evidence);
        let capabilities = &document["credential_capabilities"]["sd_jwt_vc"];

        assert_eq!(capabilities["media_type"], json!(FORMAT_SD_JWT_VC));
        assert_eq!(capabilities["jwt_typ"], json!(SD_JWT_VC_JWT_TYP));
        assert_eq!(capabilities["signing_algs"], json!(["ES256"]));
        assert_eq!(
            capabilities["issuer_key_types"],
            json!([SD_JWT_VC_P256_ISSUER_KEY_TYPE])
        );
        assert_eq!(
            capabilities["holder_binding_methods"],
            json!([SD_JWT_VC_HOLDER_BINDING_METHOD])
        );
        assert_eq!(capabilities["status_methods"], json!([]));
        assert_eq!(capabilities["openid4vci"]["support"], "not_full_issuer");
        assert_eq!(capabilities["credential_profiles"][0]["id"], "profile-a");
        assert_eq!(
            capabilities["credential_profiles"][0]["format"],
            FORMAT_SD_JWT_VC
        );
        assert_eq!(
            document["credential_capabilities"]["unsupported_features"],
            json!([
                "application/vc+sd-jwt",
                "json_ld_vc_issuance",
                "data_integrity_proofs",
                "credential_status",
                "delegated_credential_issuance",
                "mso_mdoc",
                "openid4vci_full_issuer"
            ])
        );
    }

    #[test]
    fn service_document_preserves_output_when_subject_access_disabled() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };

        assert_eq!(
            RegistryNotaryRuntime::service_document_with_subject_access(
                &evidence,
                &SubjectAccessConfig::default(),
                false,
            ),
            RegistryNotaryRuntime::service_document(&evidence),
        );
    }

    #[test]
    fn claim_summary_exposes_claim_and_consultation_output_semantics() {
        let mut claim = test_claim("date-of-birth", Vec::new(), true);
        claim.semantics = Some(registry_notary_core::ClaimSemanticConfig {
            concept: Some("https://publicschema.org/Person".to_string()),
            property: Some("https://publicschema.org/date_of_birth".to_string()),
            vocabulary: None,
            predicate: None,
            derived_from: Vec::new(),
            value_mapping: Some("publicschema".to_string()),
        });
        let summary = claim_summary(&claim);
        assert_eq!(
            summary["semantics"]["concept"],
            json!("https://publicschema.org/Person")
        );
        assert_eq!(
            summary["semantics"]["property"],
            json!("https://publicschema.org/date_of_birth")
        );
        assert_eq!(summary["semantics"]["value_mapping"], json!("publicschema"));

    }

    #[test]
    fn service_document_redacts_subject_access_details_when_not_authorized() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let subject_access: SubjectAccessConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["subject_access"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("subject-access config parses");

        let document = RegistryNotaryRuntime::service_document_with_subject_access(
            &evidence,
            &subject_access,
            false,
        );

        assert_eq!(document["subject_access"]["enabled"], json!(true));
        assert!(document["subject_access"]["subject_id_type"].is_null());
        assert!(document["subject_access"]["token_claim_name"].is_null());
        assert!(document["subject_access"]["allowed_claim_ids"].is_null());
        assert!(document["subject_access"]["credential_profile_ids"].is_null());
    }

    #[test]
    fn service_document_advertises_enabled_subject_access_capabilities() {
        let evidence = EvidenceConfig {
            enabled: true,
            service_id: "evidence.test".to_string(),
            ..EvidenceConfig::default()
        };
        let subject_access: SubjectAccessConfig = serde_json::from_value(json!({
            "enabled": true,
            "subject_binding": {
                "token_claim": "https://id.example.gov/claims/national_id",
                "request_field": "SubjectId",
                "id_type": "national_id",
                "normalize": "exact"
            },
            "token_policy": {
                "max_auth_age_seconds": 900,
                "max_access_token_lifetime_seconds": 900,
                "max_evaluation_age_seconds": 600,
                "max_credential_validity_seconds": 300,
                "max_clock_leeway_seconds": 60
            },
            "allowed_operations": {
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            },
            "allowed_claims": ["person-is-alive"],
            "allowed_formats": [FORMAT_CLAIM_RESULT_JSON],
            "allowed_disclosures": ["predicate"],
            "required_scopes": ["subject_access"],
            "credential_profiles": ["civil_status_sd_jwt"],
            "rate_limits": {
                "invalid_token_per_client_address_per_minute": 20,
                "per_principal_per_minute": 10,
                "subject_mismatch_per_principal_per_hour": 5,
                "per_holder_per_hour": 10,
                "credential_issuance_per_principal_per_hour": 5
            }
        }))
        .expect("subject-access config parses");

        let document = RegistryNotaryRuntime::service_document_with_subject_access(
            &evidence,
            &subject_access,
            true,
        );

        assert_eq!(document["subject_access"]["enabled"], json!(true));
        assert_eq!(
            document["subject_access"]["allowed_operations"],
            json!({
                "evaluate": true,
                "render": true,
                "issue_credential": false,
                "batch_evaluate": false
            })
        );
        assert_eq!(
            document["subject_access"]["allowed_claim_ids"],
            json!(["person-is-alive"])
        );
        assert_eq!(
            document["subject_access"]["allowed_formats"],
            json!([FORMAT_CLAIM_RESULT_JSON])
        );
        assert_eq!(
            document["subject_access"]["allowed_disclosures"],
            json!(["predicate"])
        );
        assert_eq!(
            document["subject_access"]["credential_profile_ids"],
            json!(["civil_status_sd_jwt"])
        );
        assert_eq!(
            document["subject_access"]["subject_id_type"],
            json!("national_id")
        );
        assert_eq!(
            document["subject_access"]["token_claim_name"],
            json!("https://id.example.gov/claims/national_id")
        );
        assert_eq!(
            document["subject_access"]["required_scopes"],
            json!(["subject_access"])
        );
        assert_eq!(
            document["subject_access"]["scope_policy"],
            json!("required")
        );
        assert_eq!(
            document["subject_access"]["max_evaluation_age_seconds"],
            json!(600)
        );
        assert_eq!(
            document["subject_access"]["max_credential_validity_seconds"],
            json!(300)
        );
        assert!(document["subject_access"]["rate_limit_mode"].is_null());
        assert!(document["subject_access"]["rate_limits"].is_null());
        assert!(document["subject_access"]["allowed_wallet_origins"].is_null());
        assert!(document["subject_access"]["citizen_clients"].is_null());
        assert!(document["subject_access"]["token_policy"].is_null());
    }
