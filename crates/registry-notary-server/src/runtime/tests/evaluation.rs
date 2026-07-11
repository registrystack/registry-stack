// SPDX-License-Identifier: Apache-2.0

    #[tokio::test]
    async fn evaluate_refuses_extract_result_that_violates_declared_value_type() {
        let source = Arc::new(WrongTypeSource);
        let mut evidence_config =
            (*test_evidence(vec![test_claim("selected", Vec::new(), true)])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err("extract result of the wrong JSON shape must be refused");

        assert!(matches!(err, EvidenceError::RuleEvaluationFailed));
    }

    #[tokio::test]
    async fn evaluate_refuses_exists_result_that_violates_declared_value_type() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.rule = RuleConfig::Exists {
            source: "src".to_string(),
        };
        claim.value.value_type = "string".to_string();
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err(
                "exists result of boolean shape must be refused against a declared string type",
            );

        assert!(matches!(err, EvidenceError::RuleEvaluationFailed));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evaluate_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config =
            (*test_evidence(vec![test_claim("selected", Vec::new(), true)])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.target = Some(registry_notary_core::EvidenceEntity::with_identifier(
            "Person",
            "national_id",
            "person-1",
        ));

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("evaluate succeeds");
        let target_ref =
            serde_json::to_value(&results[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn batch_item_target_ref_serializes_as_opaque_handle() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: Some("national_id".to_string()),
                    purpose: None,
                },
            )],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        };

        let response = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect("batch evaluate succeeds");
        let target_ref =
            serde_json::to_value(&response.items[0].target_ref).expect("target_ref serializes");

        assert!(target_ref["handle"].as_str().is_some());
        assert!(target_ref["handle"]
            .as_str()
            .unwrap()
            .starts_with("rnref:v1:"));
        assert!(target_ref.get("id_type").is_none());
        assert!(!target_ref.to_string().contains("person-1"));
    }

    #[tokio::test]
    async fn evaluate_uses_requested_claim_version() {
        let source = Arc::new(CountingSource::default());
        let older_claim = test_claim("selected", Vec::new(), false);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let mut evidence_config = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect("versioned evaluate succeeds");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(results[0].value, Some(json!(true)));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    /// REQ-SEC-G-005: the direct `evaluate` path must refuse a principal that
    /// lacks a claim's required scope, and must do so before any source read
    /// happens (`require_claim_access` runs ahead of `load_sources`). This
    /// mirrors the scope-denial coverage that already exists for federation
    /// and Relay call sites, using a counting fake source as the read probe.
    #[tokio::test]
    async fn evaluate_denies_missing_scope_before_reading_source() {
        let source = Arc::new(VersionScopedSource::default());
        let claim = test_claim("selected", Vec::new(), true);
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = test_request("selected");
        let principal = EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect_err("principal without the claim's required scope must be denied");

        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "selected:1.0"
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn evaluate_authorizes_required_scope_from_requested_claim_version() {
        let source = Arc::new(VersionScopedSource::default());
        let older_claim = test_claim("selected", Vec::new(), true);
        let mut newer_claim = test_claim("selected", Vec::new(), true);
        newer_claim.version = "2.0".to_string();
        let mut evidence_config = (*test_evidence(vec![older_claim, newer_claim])).clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];
        let principal = EvidencePrincipal {
            principal_id: "machine".to_string(),
            scopes: vec!["selected:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                Arc::clone(&evidence),
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request.clone(),
                None,
            )
            .await
            .expect_err("version 1 scope must not authorize version 2");

        assert!(matches!(
            err,
            EvidenceError::ScopeDenied { required } if required == "selected:2.0"
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);

        let principal = EvidencePrincipal {
            scopes: vec!["selected:2.0".to_string()],
            ..principal
        };
        let results = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect("version 2 scope authorizes version 2");

        assert_eq!(results[0].claim_version, "2.0");
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn evaluate_rejects_missing_claim_version() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
        let store = EvidenceStore::default();
        let mut request = test_request("selected");
        request.claims = vec![ClaimRef::with_version("selected", "2.0")];

        let err = RegistryNotaryRuntime::new()
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                None,
            )
            .await
            .expect_err("unknown version is rejected");

        assert!(matches!(err, EvidenceError::ClaimVersionNotFound));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn requested_claim_versions_accepts_duplicate_same_version() {
        let versions = requested_claim_versions(&[
            ClaimRef::with_version("selected", "2.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect("duplicate matching version is accepted");

        assert_eq!(
            versions.get("selected").and_then(Option::as_deref),
            Some("2.0")
        );
    }

    #[test]
    fn requested_claim_versions_rejects_duplicate_conflicting_version() {
        let err = requested_claim_versions(&[
            ClaimRef::with_version("selected", "1.0"),
            ClaimRef::with_version("selected", "2.0"),
        ])
        .expect_err("conflicting versions are rejected");

        assert!(matches!(err, EvidenceError::InvalidRequest));
    }

    #[test]
    fn batch_input_validation_deduplicates_purposes() {
        let subjects = vec![
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-2".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
            registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-3".to_string(),
                    id_type: None,
                    purpose: None,
                },
            ),
        ];
        let purposes = vec![
            "benefits".to_string(),
            "benefits".to_string(),
            "appeals".to_string(),
        ];

        let unique = validate_batch_inputs_and_collect_purposes(&subjects, &purposes)
            .expect("batch inputs are valid");

        assert_eq!(unique, BTreeSet::from(["appeals", "benefits"]));
    }

    #[tokio::test]
    async fn evaluate_claim_provenance_carries_selected_pack_identity() {
        let mut claim = test_claim("birth.certificate_summary", Vec::new(), true);
        claim.disclosure.default = "value".to_string();
        claim.disclosure.allowed = vec!["value".to_string(), "predicate".to_string()];
        let matching = &mut claim
            .source_bindings
            .get_mut("src")
            .expect("test source binding exists")
            .matching;
        matching.allowed_purposes = vec!["benefits".to_string()];
        matching.ecosystem_binding = Some(registry_notary_core::EcosystemBindingSelectorConfig {
            id: Some("oots-birth-evidence/v1".to_string()),
            pack_id: Some("oots-birth-evidence/v1".to_string()),
            pack_version: Some("v1".to_string()),
            ..registry_notary_core::EcosystemBindingSelectorConfig::default()
        });

        let mut evidence = EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims: vec![claim],
            ..EvidenceConfig::default()
        };
        evidence.ecosystem_bindings.insert(
            "oots-birth-evidence/v1".to_string(),
            registry_notary_core::EvidenceEcosystemBindingConfig {
                profile: Some("registry-notary/source-policy/v1".to_string()),
                policy_id: "lab.oots-birth-evidence.governed-evidence.v1".to_string(),
                policy_hash:
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                        .to_string(),
                unsupported_odrl_terms: Vec::new(),
            },
        );

        let principal = EvidencePrincipal {
            principal_id: "caseworker".to_string(),
            scopes: vec!["birth.certificate_summary:1.0".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };
        let results = crate::RegistryNotaryRuntime::new()
            .evaluate(
                Arc::new(evidence),
                Arc::new(VersionScopedSource::default()),
                &EvidenceStore::default(),
                &principal,
                EvaluateRequest {
                    requester: None,
                    target: Some(EvidenceEntity::from_subject_request(
                        "Person",
                        SubjectRequest {
                            id: "person-123".to_string(),
                            id_type: None,
                        },
                    )),
                    relationship: None,
                    on_behalf_of: None,
                    claims: vec![ClaimRef::from("birth.certificate_summary")],
                    disclosure: Some("value".to_string()),
                    format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
                    purpose: Some("benefits".to_string()),
                },
                None,
            )
            .await
            .expect("claim evaluates");

        let generated_by = &results[0].provenance.generated_by;
        assert_eq!(
            generated_by.pack_id.as_deref(),
            Some("oots-birth-evidence/v1")
        );
        assert_eq!(generated_by.pack_version.as_deref(), Some("v1"));
        assert_eq!(results[0].disclosure, "value");
    }
