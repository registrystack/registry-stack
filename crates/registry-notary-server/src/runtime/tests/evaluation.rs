// SPDX-License-Identifier: Apache-2.0

    #[derive(Debug)]
    struct FixedRelayConsultation {
        calls: AtomicU64,
        outcome: RuntimeRelayOutcome,
    }

    #[async_trait::async_trait]
    impl ActivatedRelayConsultations for FixedRelayConsultation {
        async fn check_ready(&self) -> Result<(), crate::relay_client::RelayClientError> {
            Ok(())
        }

        fn validate(
            &self,
            _key: &ConsultationGroupKeyV1,
        ) -> Result<(), crate::relay_client::RelayClientError> {
            Ok(())
        }

        async fn execute(
            &self,
            _key: &ConsultationGroupKeyV1,
        ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let match_data = matches!(self.outcome, RuntimeRelayOutcome::Match)
                .then(|| {
                    RuntimeRelayOutput::new("registration_status", Zeroizing::new("ACTIVE".to_string()))
                        .map(RuntimeRelayMatchData::ProjectedString)
                })
                .transpose()?;
            RuntimeRelayConsultationResult::new(
                Ulid::from_parts(2, 1),
                self.outcome,
                match_data,
                OffsetDateTime::UNIX_EPOCH,
            )
        }
    }

    fn registry_claim(id: &str, rule: RuleConfig, value_type: &str) -> ClaimDefinition {
        let mut claim = test_claim(id, Vec::new(), false);
        claim.evidence_mode = ClaimEvidenceMode::RegistryBacked {
            consultations: BTreeMap::from([(
                "enrollment".to_string(),
                registry_notary_core::RelayConsultationConfig {
                    profile: registry_notary_core::RelayConsultationProfileRef {
                        id: "dhis2.tracker.enrollment-status.exact".to_string(),
                        version: "1".to_string(),
                        contract_hash:
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string(),
                    },
                    inputs: BTreeMap::from([(
                        "tracked_entity".to_string(),
                        RelayConsultationInput::TargetId,
                    )]),
                },
            )]),
        };
        claim.purpose = Some("test".to_string());
        claim.required_scopes = vec!["registry:evidence".to_string()];
        claim.rule = rule;
        claim.value.value_type = value_type.to_string();
        claim
    }

    async fn audited_registry_evaluation(
        claim: ClaimDefinition,
        outcome: RuntimeRelayOutcome,
    ) -> (
        Result<Vec<ClaimResultView>, EvidenceError>,
        EvaluationAuditSnapshot,
        Arc<FixedRelayConsultation>,
        Arc<CountingSource>,
    ) {
        let mut evidence = (*test_evidence(vec![claim])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let mut principal = machine_principal();
        principal.scopes = vec!["registry:evidence".to_string()];
        let result = runtime
            .evaluate_for_api(
                Arc::new(evidence),
                source.clone() as Arc<dyn SourceReader>,
                &EvidenceStore::default(),
                &principal,
                test_request("enrollment-status"),
                None,
            )
            .await;
        (result.0, result.1, activated, source)
    }

    fn assert_relay_audit(snapshot: EvaluationAuditSnapshot) -> String {
        let (evaluation_id, consultation_ids) = snapshot.into_parts();
        let evaluation_id = evaluation_id.expect("post-preflight evaluation id is retained");
        assert!(Ulid::from_string(&evaluation_id).is_ok());
        assert_eq!(consultation_ids, vec![Ulid::from_parts(2, 1).to_string()]);
        evaluation_id
    }

    #[tokio::test]
    async fn relay_match_correlation_survives_success_without_public_relay_ids() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::Match).await;
        let results = result.expect("match evaluates");
        let evaluation_id = assert_relay_audit(audit);

        assert_eq!(results[0].evaluation_id, evaluation_id);
        assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
        let public = serde_json::to_string(&results).expect("public results serialize");
        assert!(!public.contains(&Ulid::from_parts(2, 1).to_string()));
    }

    #[test]
    fn relay_exists_match_materializes_presence_without_source_output() {
        let claim = registry_claim(
            "enrollment-known",
            RuleConfig::Exists {
                source: "enrollment".to_string(),
            },
            "boolean",
        );
        let result = RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            RuntimeRelayOutcome::Match,
            Some(RuntimeRelayMatchData::PresenceOnly),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("valid Relay match");

        let sources = materialize_relay_match(&claim, &result)
            .expect("exists match materializes only a presence sentinel");
        let wire = serde_json::to_string(&sources).expect("presence sentinel serializes");

        assert_eq!(sources.get("enrollment"), Some(&json!({})));
        assert!(!wire.contains("registration_status"));
    }

    #[tokio::test]
    async fn relay_no_match_extract_is_source_not_found_with_restricted_correlation() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::NoMatch).await;

        assert!(matches!(result, Err(EvidenceError::SourceNotFound)));
        assert_relay_audit(audit);
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn relay_no_match_exists_remains_false_with_restricted_correlation() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Exists {
                source: "enrollment".to_string(),
            },
            "boolean",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::NoMatch).await;
        let results = result.expect("no-match existence evaluates to false");

        assert_eq!(results[0].value, Some(Value::Bool(false)));
        assert_relay_audit(audit);
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn relay_ambiguous_failure_retains_restricted_correlation() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::Ambiguous).await;

        assert!(matches!(result, Err(EvidenceError::SourceAmbiguous)));
        assert_relay_audit(audit);
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn relay_ambiguous_exists_remains_fail_closed() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Exists {
                source: "enrollment".to_string(),
            },
            "boolean",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::Ambiguous).await;

        assert!(matches!(result, Err(EvidenceError::SourceAmbiguous)));
        assert_relay_audit(audit);
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn post_relay_type_failure_retains_restricted_correlation() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "boolean",
        );
        let (result, audit, activated, source) =
            audited_registry_evaluation(claim, RuntimeRelayOutcome::Match).await;

        assert!(matches!(result, Err(EvidenceError::RuleEvaluationFailed)));
        assert_relay_audit(audit);
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn registry_backed_claims_share_one_relay_consultation_without_source_reader_fallback() {
        let exists = registry_claim(
            "enrollment-known",
            RuleConfig::Exists {
                source: "enrollment".to_string(),
            },
            "boolean",
        );
        let extract = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let mut evidence = (*test_evidence(vec![exists, extract])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence);
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let store = EvidenceStore::default();
        let mut request = test_request("enrollment-known");
        request.claims.push(ClaimRef::from("enrollment-status"));
        let mut principal = machine_principal();
        principal.scopes = vec!["registry:evidence".to_string()];

        let results = runtime
            .evaluate(
                Arc::clone(&evidence),
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request.clone(),
                None,
            )
            .await
            .expect("the coalesced Registry-backed evaluation succeeds");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, Some(Value::Bool(true)));
        assert_eq!(results[1].value, Some(Value::String("ACTIVE".to_string())));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
        assert!(results
            .iter()
            .all(|result| result.provenance.used.source_count == 1));
        let stored = store
            .get(&results[0].evaluation_id)
            .expect("restricted evaluation record is stored");
        let stored_wire = serde_json::to_string(&stored).expect("stored evaluation serializes");
        assert!(!stored_wire.contains("relay_consultation_ids"));
        let public_wire = serde_json::to_string(&results).expect("public results serialize");
        assert!(!public_wire.contains("relay_consultation_ids"));

        runtime
            .evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &principal,
                request,
                None,
            )
            .await
            .expect("a new evaluation performs a new consultation");
        assert_eq!(activated.calls.load(Ordering::SeqCst), 2);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn relay_group_key_ignores_unrelated_principal_scopes() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let mut evidence = (*test_evidence(vec![claim])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let mut principal = machine_principal();
        principal.scopes = std::iter::once("registry:evidence".to_string())
            .chain((0..32).map(|index| format!("unrelated:{index}")))
            .collect();

        let results = runtime
            .evaluate(
                Arc::new(evidence),
                source.clone() as Arc<dyn SourceReader>,
                &EvidenceStore::default(),
                &principal,
                test_request("enrollment-status"),
                None,
            )
            .await
            .expect("unrelated principal scopes do not widen the consultation key");

        assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn relay_plan_uses_the_explicitly_selected_claim_version() {
        let mut transitional = test_claim("enrollment-status", Vec::new(), false);
        transitional.version = "1".to_string();
        let mut registry = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        registry.version = "2".to_string();
        let mut evidence = (*test_evidence(vec![transitional, registry])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let mut request = test_request("enrollment-status");
        request.claims = vec![ClaimRef::with_version("enrollment-status", "2")];
        let mut principal = machine_principal();
        principal.scopes = vec!["registry:evidence".to_string()];

        let results = runtime
            .evaluate(
                Arc::new(evidence),
                source.clone() as Arc<dyn SourceReader>,
                &EvidenceStore::default(),
                &principal,
                request,
                None,
            )
            .await
            .expect("the selected Registry-backed version is planned and evaluated");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_version, "2");
        assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn registry_backed_preflight_denial_makes_zero_relay_and_source_calls() {
        let claim = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let mut evidence = (*test_evidence(vec![claim])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));

        let (result, audit) = runtime
            .evaluate_for_api(
                Arc::new(evidence),
                source.clone() as Arc<dyn SourceReader>,
                &EvidenceStore::default(),
                &machine_principal(),
                test_request("enrollment-status"),
                None,
            )
            .await;
        let error = result.expect_err("missing required scope is denied before Relay");

        assert!(matches!(error, EvidenceError::ScopeDenied { .. }));
        let (evaluation_id, consultation_ids) = audit.into_parts();
        assert!(evaluation_id.is_none());
        assert!(consultation_ids.is_empty());
        assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn transitional_dependency_cannot_compose_a_registry_backed_result() {
        let registry = registry_claim(
            "enrollment-status",
            RuleConfig::Extract {
                source: "enrollment".to_string(),
                field: "registration_status".to_string(),
            },
            "string",
        );
        let mut transitional = test_claim("legacy-derived", vec!["enrollment-status"], false);
        transitional.rule = RuleConfig::Cel {
            expression: "claims.enrollment_status == 'ACTIVE'".to_string(),
            bindings: CelBindingsConfig::default(),
        };
        let mut evidence = (*test_evidence(vec![registry, transitional])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        let source = Arc::new(CountingSource::default());
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let mut principal = machine_principal();
        principal.scopes = vec!["registry:evidence".to_string()];

        let error = runtime
            .evaluate(
                Arc::new(evidence),
                source.clone() as Arc<dyn SourceReader>,
                &EvidenceStore::default(),
                &principal,
                test_request("legacy-derived"),
                None,
            )
            .await
            .expect_err("cross-mode claim composition must fail before either source path");

        assert!(matches!(error, EvidenceError::InvalidRequest));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

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
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
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
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
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
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
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
    #[test]
    fn internal_claim_result_debug_redacts_relay_correlation_and_value() {
        let mut result = test_claim_result(
            "registry-backed-claim",
            serde_json::json!("registry-value-SENSITIVE"),
            BTreeSet::new(),
        );
        result
            .relay_consultation_ids
            .insert("01JRELAYCORRELATIONSENSITIVE".to_string());

        let rendered = format!("{result:?}");

        assert!(!rendered.contains("01JRELAYCORRELATIONSENSITIVE"));
        assert!(!rendered.contains("registry-value-SENSITIVE"));
        assert!(rendered.contains("relay_consultation_ids: \"[REDACTED]\""));
    }
