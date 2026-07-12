// SPDX-License-Identifier: Apache-2.0

    #[test]
    fn claim_scopes_are_enforced_without_delegating_to_the_source_reader() {
        let source = CountingSource::default();
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.required_scopes = vec!["registry:consult:dhis2".to_string()];
        let evidence = test_evidence(vec![claim.clone()]);
        let denied = machine_principal();

        assert!(!principal_can_see_claim(
            &evidence, &source, &denied, &claim
        ));
        assert!(matches!(
            require_claim_access(&evidence, &source, &denied, &claim),
            Err(EvidenceError::ScopeDenied { required })
                if required == "registry:consult:dhis2"
        ));

        let mut allowed = denied;
        allowed.scopes.push("registry:consult:dhis2".to_string());
        assert!(principal_can_see_claim(
            &evidence, &source, &allowed, &claim
        ));
        require_claim_access(&evidence, &source, &allowed, &claim)
            .expect("claim scope grants access independently of source bindings");
    }

    #[tokio::test]
    async fn authorized_self_attestation_preserves_transitional_direct_source_reads() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![test_claim(
            "selected",
            Vec::new(),
            true,
        )]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("the explicit transitional lane preserves its governed self-service read");

        assert_eq!(results.len(), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn batch_subject_purpose_conflict_rejects_batch_default() {
        let source = Arc::new(CountingSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 2;
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 2;
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let request = BatchEvaluateRequest {
            items: vec![
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-1".to_string(),
                        id_type: None,
                        purpose: Some("program-a".to_string()),
                    },
                ),
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: "person-2".to_string(),
                        id_type: None,
                        purpose: None,
                    },
                ),
            ],
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("program-b".to_string()),
        };

        let error = RegistryNotaryRuntime::new()
            .batch_evaluate(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("batch item purpose must not conflict with batch default");

        assert_eq!(error.code(), "request.invalid");
        assert!(source
            .purposes
            .lock()
            .expect("purposes mutex is not poisoned")
            .is_empty());
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_dependency_source_read_before_connector() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependency source read is not selected claim");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_rejects_context_hash_mismatch_before_source_read() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                delegated_attestation_capability(&keys, "NAT-123", "OTHER-CHILD"),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependent target hash must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_unproven_relationship_does_not_read_dependent_sources() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), false),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("false proof claim must deny delegated dependent evaluation");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedRelationshipUnproven
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_binds_target_id_type_not_just_value() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        // The capability pins the dependent target value CHILD-123 under the
        // national_id scheme, but the live request presents the same value under
        // civil_registration_id. Value-only hashing would have collided and let
        // the request through; binding the (id_type, id) pair fails closed before
        // any source read.
        let capability = delegated_attestation_capability_with_id_types(
            &keys,
            "national_id",
            "NAT-123",
            "national_id",
            "CHILD-123",
        );

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                capability,
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("dependent target id_type must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn delegated_attestation_binds_requester_id_type_not_just_value() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["guardian-link"], true),
            test_claim("guardian-link", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let keys = Arc::new(SelfAttestationRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let runtime = RegistryNotaryRuntime::new_with_self_attestation_rate_keys(Arc::clone(&keys));

        // Mirror of the dependent-target test for the requester binding. The
        // capability pins the requester value NAT-123 under the civil_registration_id
        // scheme, but the live request presents the same value under national_id (and
        // the dependent target matches). Value-only hashing would have collided and
        // let the request through; binding the (id_type, id) pair fails closed before
        // any source read.
        let capability = delegated_attestation_capability_with_id_types(
            &keys,
            "civil_registration_id",
            "NAT-123",
            "civil_registration_id",
            "CHILD-123",
        );

        let err = runtime
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &delegated_principal(),
                capability,
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("requester id_type must bind the delegated request context");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn self_attestation_capability_rejects_arbitrary_requested_claim() {
        let source = Arc::new(CountingSource::default());
        let evidence = test_evidence(vec![
            test_claim("selected", Vec::new(), false),
            test_claim("other", Vec::new(), false),
        ]);
        let store = EvidenceStore::default();

        let err = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &self_attestation_principal(),
                self_attestation_capability("selected"),
                test_request("other"),
                None,
                None,
                None,
            )
            .await
            .expect_err("self-attestation cannot switch claims after guard selection");

        assert!(matches!(
            err,
            EvidenceError::SelfAttestationDenied {
                reason: SelfAttestationDenialCode::ClaimDenied
            }
        ));
        assert_eq!(source.read_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn machine_capability_preserves_dependency_source_read() {
        let source = Arc::new(CountingSource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                SourceCapability::Machine {
                    scopes: BTreeSet::new(),
                },
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("machine source reads keep existing behavior");

        assert_eq!(results.len(), 1);
        assert_eq!(source.read_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn derived_claim_provenance_preserves_dependency_source_runtime() {
        let source = Arc::new(RuntimeSummarySource::default());
        let mut evidence_config = (*test_evidence(vec![
            test_claim("selected", vec!["dependency"], false),
            test_claim("dependency", Vec::new(), true),
        ]))
        .clone();
        evidence_config.allowed_purposes = vec!["test".to_string()];
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();

        let results = RegistryNotaryRuntime::new()
            .evaluate_with_source_capability(
                evidence,
                source.clone() as Arc<dyn SourceReader>,
                &store,
                &machine_principal(),
                SourceCapability::Machine {
                    scopes: BTreeSet::new(),
                },
                test_request("selected"),
                None,
                None,
                None,
            )
            .await
            .expect("derived claim evaluates");

        assert_eq!(results.len(), 1);
        assert_eq!(source.inner.read_count.load(Ordering::SeqCst), 1);
        let runtimes = &results[0].provenance.used.source_runtimes;
        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].kind, SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR);
        assert_eq!(
            runtimes[0].config_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(runtimes[0].assurance.pinned);
        assert!(runtimes[0].assurance.runtime_verified);
    }
