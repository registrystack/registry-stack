// SPDX-License-Identifier: Apache-2.0

    #[tokio::test]
    async fn bulk_prefetch_does_not_cache_rows_missing_required_fields() {
        let source = Arc::new(BulkInvalidThenDirectSource::default());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding")
            .connection = Some("bulk-source".to_string());
        claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding")
            .matching
            .allowed_purposes = vec!["test".to_string()];
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        evidence_config.source_connections =
            BTreeMap::from([("bulk-source".to_string(), bulk_source_connection())]);
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let memo = Arc::new(MemoState::new());
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
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
                BatchEvaluateOptions {
                    memo_observer: Some(&memo),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await
            .expect("batch evaluate succeeds after direct retry");

        assert_eq!(response.summary.succeeded, 1);
        assert_eq!(response.summary.failed, 0);
        assert!(matches!(
            response.items[0].status,
            BatchItemStatus::Succeeded
        ));
        assert_eq!(response.items[0].claim_results[0].value, Some(json!(true)));
        assert_eq!(source.bulk_count.load(Ordering::SeqCst), 1);
        assert_eq!(source.direct_count.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 0);
        assert_eq!(memo.misses(), 1);
    }

    #[tokio::test]
    async fn bulk_prefetch_stale_row_is_not_disclosed() {
        let source = Arc::new(BulkStaleFreshnessSource::new());
        let mut claim = test_claim("selected", Vec::new(), true);
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = 1;
        let binding = claim
            .source_bindings
            .get_mut("src")
            .expect("test claim has source binding");
        binding.connection = Some("bulk-source".to_string());
        binding.matching.allowed_purposes = vec!["test".to_string()];
        binding.matching.max_source_age_seconds = Some(60);
        binding.matching.source_observed_at_field = Some("observed_at".to_string());
        let mut evidence_config = (*test_evidence(vec![claim])).clone();
        evidence_config.inline_batch_limit = 1;
        evidence_config.source_connections =
            BTreeMap::from([("bulk-source".to_string(), bulk_source_connection())]);
        let evidence = Arc::new(evidence_config);
        let store = EvidenceStore::default();
        let memo = Arc::new(MemoState::new());
        let request = BatchEvaluateRequest {
            items: vec![registry_notary_core::BatchEvaluateItemRequest::from(
                registry_notary_core::BatchSubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
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
                BatchEvaluateOptions {
                    memo_observer: Some(&memo),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await
            .expect("batch evaluate reports per-item stale failure");

        assert_eq!(response.summary.succeeded, 0);
        assert_eq!(response.summary.failed, 1);
        assert!(matches!(response.items[0].status, BatchItemStatus::Failed));
        assert!(
            response.items[0].claim_results.is_empty(),
            "stale bulk values must not be disclosed"
        );
        assert!(
            response.items[0]
                .errors
                .iter()
                .any(|error| error.code == "pdp.evidence_stale"
                    && error.audit_code.as_deref() == Some("pdp.evidence_stale")),
            "expected stable stale freshness error, got {:?}",
            response.items[0].errors
        );
        assert_eq!(source.bulk_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            source.direct_count.load(Ordering::SeqCst),
            0,
            "stale preflight on cache miss must deny before direct protected row read"
        );
        assert_eq!(source.preflight_count.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 0);
    }

    #[tokio::test]
    async fn source_binding_lookup_can_use_prior_source_row_field() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let (sources, _, _, _) = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect("dependent source lookup succeeds");

        assert_eq!(sources["birth_event"]["id"], json!("birth-123"));
        let reads = source.reads.lock().expect("reads mutex is not poisoned");
        assert_eq!(
            reads.as_slice(),
            &[
                ("civil_status_record".to_string(), json!("person-1")),
                ("birth_event".to_string(), json!("birth-123")),
            ]
        );
    }

    #[tokio::test]
    async fn source_binding_lookup_missing_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row field fails");

        assert_collapsed_matching_error(error, "target.not_found");
    }

    #[tokio::test]
    async fn source_binding_lookup_missing_prior_field_preserves_error_when_collapse_disabled() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event =
            dependent_source_binding("birth_event", "sources.civil_status.birth_event_id", "id");
        birth_event.matching.collapse_matching_errors = false;
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row field fails");

        assert!(matches!(error, EvidenceError::SourceNotFound));
    }

    #[tokio::test]
    async fn source_binding_lookup_ambiguous_prior_rows_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!([
            {
                "person_id": "person-1",
                "birth_event_id": "birth-123"
            },
            {
                "person_id": "person-1",
                "birth_event_id": "birth-456"
            }
        ])));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("ambiguous source rows fail");

        assert_collapsed_matching_error(error, "target.match_ambiguous");
    }

    #[tokio::test]
    async fn source_binding_lookup_non_scalar_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": {
                "id": "birth-123"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row field fails");

        assert_collapsed_matching_error(error, "request.invalid");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_non_scalar_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": [
                "birth-123"
            ],
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row query field fails");

        assert_collapsed_matching_error(error, "request.invalid");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_missing_prior_field_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("missing source row query field fails");

        assert_collapsed_matching_error(error, "target.not_found");
    }

    #[tokio::test]
    async fn source_binding_query_field_lookup_ambiguous_prior_rows_collapses_matching_error() {
        let source = Arc::new(DependentLookupSource::new(json!([
            {
                "person_id": "person-1",
                "birth_event_id": "birth-123"
            },
            {
                "person_id": "person-1",
                "birth_event_id": "birth-456"
            }
        ])));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event = dependent_source_binding("birth_event", "target.id", "person_id");
        birth_event.query_fields = vec![registry_notary_core::SourceQueryFieldConfig {
            input: "sources.civil_status.birth_event_id".to_string(),
            field: "id".to_string(),
            op: "eq".to_string(),
        }];
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("ambiguous source rows query field fails");

        assert_collapsed_matching_error(error, "target.match_ambiguous");
    }

    #[tokio::test]
    async fn source_binding_lookup_non_scalar_prior_field_preserves_error_when_collapse_disabled() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": {
                "id": "birth-123"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        let mut birth_event =
            dependent_source_binding("birth_event", "sources.civil_status.birth_event_id", "id");
        birth_event.matching.collapse_matching_errors = false;
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            ("birth_event".to_string(), birth_event),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("non-scalar source row field fails");

        assert!(matches!(error, EvidenceError::InvalidRequest));
    }

    #[tokio::test]
    async fn source_binding_ready_layer_materializes_before_spawning_reads() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
            "invalid_event_id": {
                "id": "birth-456"
            },
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "a_birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.birth_event_id",
                    "id",
                ),
            ),
            (
                "b_invalid_birth_event".to_string(),
                dependent_source_binding(
                    "birth_event",
                    "sources.civil_status.invalid_event_id",
                    "id",
                ),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("invalid sibling materialization fails the ready layer");

        assert_collapsed_matching_error(error, "request.invalid");
        let reads = source.reads.lock().expect("reads mutex is not poisoned");
        assert_eq!(
            reads.as_slice(),
            &[("civil_status_record".to_string(), json!("person-1"))],
            "dependent sibling reads must not start until the whole ready layer materializes"
        );
    }

    #[tokio::test]
    async fn source_binding_lookup_unknown_dependency_is_invalid_request() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "civil_status".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
            (
                "birth_event".to_string(),
                dependent_source_binding("birth_event", "sources.missing.birth_event_id", "id"),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("unknown dependency source binding fails");

        assert!(matches!(error, EvidenceError::InvalidRequest));
        assert!(
            source
                .reads
                .lock()
                .expect("reads mutex is not poisoned")
                .is_empty(),
            "dependency discovery must fail before upstream reads"
        );
    }

    #[tokio::test]
    async fn source_binding_dependency_cycle_is_invalid_before_unrelated_reads() {
        let source = Arc::new(DependentLookupSource::new(json!({
            "person_id": "person-1",
            "birth_event_id": "birth-123",
        })));
        let mut claim = test_claim("selected", Vec::new(), false);
        claim.source_bindings = BTreeMap::from([
            (
                "a_cycle".to_string(),
                dependent_source_binding("birth_event", "sources.b_cycle.birth_event_id", "id"),
            ),
            (
                "b_cycle".to_string(),
                dependent_source_binding("birth_event", "sources.a_cycle.birth_event_id", "id"),
            ),
            (
                "unrelated".to_string(),
                dependent_source_binding("civil_status_record", "target.id", "person_id"),
            ),
        ]);
        let evidence = test_evidence(vec![claim.clone()]);
        let context = test_request("selected")
            .request_context()
            .expect("test request has target context");

        let error = load_sources(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            Arc::new(claim),
            machine_capability(&[]),
            context,
            TrustedPolicyContext::default(),
            "test".to_string(),
            DisclosureProfile::Value,
            FORMAT_CLAIM_RESULT_JSON.to_string(),
            Arc::new(Semaphore::new(4)),
            None,
        )
        .await
        .expect_err("source binding dependency cycle fails before source reads");

        assert!(matches!(error, EvidenceError::InvalidRequest));
        assert!(
            source
                .reads
                .lock()
                .expect("reads mutex is not poisoned")
                .is_empty(),
            "dependency graph validation must fail before unrelated ready reads"
        );
    }

    #[test]
    fn source_observed_at_from_row_trims_timestamp_before_parse() {
        let mut binding = test_source_binding();
        binding.matching.source_observed_at_field = Some("observed_at".to_string());

        let observed_at = source_observed_at_from_row(
            &binding,
            &json!({"observed_at": " 2026-05-24T12:00:00Z\n"}),
        )
        .expect("trimmed observed_at parses")
        .expect("observed_at is present");

        assert_eq!(
            observed_at
                .format(&Rfc3339)
                .expect("observed_at formats as RFC3339"),
            "2026-05-24T12:00:00Z"
        );
    }
