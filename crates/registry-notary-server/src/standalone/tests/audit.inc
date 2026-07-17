    // SPDX-License-Identifier: Apache-2.0

    #[test]
    fn request_identifier_hashes_are_deterministic_and_non_raw() {
        let hasher = AuditKeyHasher::unkeyed_dev_only();

        let first = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-1"));
        let again = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-1"));
        let other = Hashed::<RequestIdentifier>::from_hash(hasher.hash("request-jti-2"));

        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_ne!(first.as_str(), "request-jti-1");
    }

    #[test]
    fn relay_consultation_ids_are_preserved_in_restricted_audit() {
        let consultation_id = "01HX0000000000000000000001".to_string();
        let mut response = StatusCode::OK.into_response();
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_decision: Some("evaluate".to_string()),
            relay_consultation_count: Some(1),
            relay_consultation_ids: vec![consultation_id.clone()],
            forwarded: Some(true),
            ..EvidenceAuditContext::default()
        });

        let event = build_audit_event(
            None,
            &AuditKeyHasher::unkeyed_dev_only(),
            "POST",
            "/v1/evaluations",
            BoundedCorrelationId::new("req-relay-1")
                .expect("test correlation id is bounded"),
            &response,
        );

        assert_eq!(event.relay_consultation_ids, vec![consultation_id]);
        assert_eq!(event.relay_consultation_count, Some(1));
        assert_eq!(event.forwarded, Some(true));
    }

    fn audit_event() -> EvidenceAuditEvent {
        EvidenceAuditEvent {
            event_id: "01HX0000000000000000000000".to_string(),
            occurred_at: "2026-05-22T00:00:00Z".to_string(),
            principal_id_hash: Some(Hashed::from_hash("sha256:caseworker")),
            scopes_used: vec!["registry_notary:admin".to_string()],
            decision: "allowed".to_string(),
            method: "GET".to_string(),
            path: "/v1/claims".to_string(),
            status: 200,
            verification_id: None,
            claim_hash: None,
            purposes: None,
            row_count: None,
            relay_consultation_count: None,
            relay_consultation_ids: Vec::new(),
            forwarded: None,
            error_code: None,
            access_mode: Some(AccessMode::MachineClient),
            federation_peer_id_hash: None,
            federation_issuer: None,
            federation_profile: None,
            federation_purpose: None,
            federation_request_jti_hash: None,
            federation_subject_ref_hash: None,
            denial_code: None,
            token_claim_name: None,
            correlation_id_hash: None,
            credential_profile: None,
            protocol: None,
            credential_configuration_id: None,
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_version: None,
            policy_hash: None,
            target_type: None,
            target_ref_hash: None,
            requester_type: None,
            requester_ref_hash: None,
            redacted_fields: None,
            batch_items: None,
            config: None,
        }
    }

    fn test_audit_config(sink: &str) -> registry_notary_core::EvidenceAuditConfig {
        std::env::set_var(
            TEST_AUDIT_HASH_SECRET_ENV,
            "0123456789abcdef0123456789abcdef",
        );
        registry_notary_core::EvidenceAuditConfig {
            sink: sink.to_string(),
            hash_secret_env: Some(TEST_AUDIT_HASH_SECRET_ENV.to_string()),
            ..registry_notary_core::EvidenceAuditConfig::default()
        }
    }

    #[test]
    fn audit_event_carries_subject_access_context_fields() {
        let principal = EvidencePrincipal {
            auth_profile_id: EvidenceAuthProfileId::ExternalOidc,
            principal_id: "citizen".to_string(),
            scopes: vec!["subject_access".to_string()],
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        };
        let mut response = StatusCode::FORBIDDEN.into_response();
        response.extensions_mut().insert(EvidenceAuditContext {
            verification_id: None,
            verification_decision: Some("evaluate_denied".to_string()),
            claim_hash: Some("sha256:claim-hash".to_string()),
            purposes: None,
            row_count: None,
            relay_consultation_count: None,
            relay_consultation_ids: Vec::new(),
            forwarded: None,
            access_mode: Some(AccessMode::SubjectBound),
            denial_code: Some(SubjectAccessDenialCode::SubjectMismatch),
            token_claim_name: Some(
                registry_notary_core::ConfigMetadata::new("national_id").expect("bounded"),
            ),
            credential_profile: None,
            protocol: Some(
                registry_notary_core::ConfigMetadata::new("openid4vci").expect("bounded"),
            ),
            credential_configuration_id: Some(
                registry_notary_core::ConfigMetadata::new("person_is_alive_sd_jwt")
                    .expect("bounded"),
            ),
            holder_binding_mode: None,
            rate_limit_bucket: None,
            policy_hash: None,
            target_type: Some("person".to_string()),
            target_ref_hash: Some(Hashed::from_hash("sha256:target")),
            requester_type: Some("person".to_string()),
            requester_ref_hash: Some(Hashed::from_hash("sha256:requester")),
            batch_items: None,
            ..EvidenceAuditContext::default()
        });

        let event = build_audit_event(
            Some(&principal),
            &AuditKeyHasher::unkeyed_dev_only(),
            "POST",
            "/v1/evaluations",
            BoundedCorrelationId::new("req-123").expect("test correlation id is bounded"),
            &response,
        );

        assert_eq!(event.decision, "evaluate_denied");
        assert_eq!(event.claim_hash.as_deref(), Some("sha256:claim-hash"));
        assert_eq!(event.access_mode, Some(AccessMode::SubjectBound));
        assert!(event.principal_id_hash.is_some());
        let expected_correlation_hash = AuditKeyHasher::unkeyed_dev_only().hash("req-123");
        assert_eq!(
            event.correlation_id_hash.as_ref().map(Hashed::as_str),
            Some(expected_correlation_hash.as_str())
        );
        assert_eq!(
            event.denial_code,
            Some(SubjectAccessDenialCode::SubjectMismatch)
        );
        assert_eq!(
            event.protocol.as_ref().map(|value| value.as_str()),
            Some("openid4vci")
        );
        assert_eq!(
            event
                .credential_configuration_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("person_is_alive_sd_jwt")
        );
        assert_eq!(event.target_type.as_deref(), Some("person"));
        assert_eq!(
            event.target_ref_hash.as_ref().map(Hashed::as_str),
            Some("sha256:target")
        );
        assert_eq!(event.requester_type.as_deref(), Some("person"));
        assert_eq!(
            event.requester_ref_hash.as_ref().map(Hashed::as_str),
            Some("sha256:requester")
        );
    }

    #[tokio::test]
    async fn audit_pipeline_emits_chained_jsonl() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let output = std::fs::read_to_string(path).expect("audit output is readable");
        assert!(output.ends_with('\n'));
        assert_eq!(output.lines().count(), 1);

        let line: Value = serde_json::from_str(output.trim_end()).expect("audit line is JSON");
        assert!(line["envelope_id"].as_str().is_some());
        assert_eq!(
            line["record"]["event_id"],
            json!("01HX0000000000000000000000")
        );
        assert!(line["record"]["principal_id_hash"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(line["record"].get("principal_id").is_none());
        assert!(line["record"].get("fields").is_none());
        assert!(line["record"].get("audit").is_none());
    }

    #[tokio::test]
    async fn eager_audit_verification_accepts_valid_retained_chain() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        {
            let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));
            audit.emit(&audit_event()).await.expect("audit write succeeds");
        }

        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));
        audit
            .verify_chain_eager()
            .await
            .expect("valid retained chain verifies");
        assert!(audit.chain_healthy());
    }

    #[tokio::test]
    async fn integrity_failure_latches_audit_readiness_monotonically() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        {
            let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));
            audit.emit(&audit_event()).await.expect("audit write succeeds");
        }
        let original = std::fs::read_to_string(&path).expect("audit reads");
        std::fs::write(&path, original.replace("allowed", "tampered"))
            .expect("audit is tampered");

        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(&path)));
        let error = audit
            .verify_chain_eager()
            .await
            .expect_err("tampered chain fails verification");
        assert!(matches!(error, AuditError::ChainVerification(_)));
        assert!(!audit.chain_healthy());

        std::fs::write(&path, original).expect("valid retained chain is restored");
        audit
            .verify_chain_eager()
            .await
            .expect("restored chain verifies");
        assert!(
            !audit.chain_healthy(),
            "integrity failure remains latched until process restart"
        );
    }

    #[derive(Default)]
    struct TransientTailFailureSink {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl PlatformAuditSink for TransientTailFailureSink {
        async fn write(
            &self,
            _envelope: &registry_platform_audit::AuditEnvelope,
        ) -> Result<(), AuditError> {
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &registry_platform_audit::AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(AuditError::Io(std::io::Error::other(
                    "transient retained-chain read failure",
                )));
            }
            Ok(None)
        }
    }

    #[tokio::test]
    async fn transient_eager_verification_failure_recovers_without_poisoning_readiness() {
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(TransientTailFailureSink::default()));

        let error = audit
            .verify_chain_eager()
            .await
            .expect_err("first retained-chain read fails");
        assert!(matches!(error, AuditError::Io(_)));
        assert!(
            audit.chain_healthy(),
            "I/O failure must not poison audit readiness"
        );

        audit
            .verify_chain_eager()
            .await
            .expect("later retained-chain read recovers");
        assert!(audit.chain_healthy());
    }

    #[derive(Default)]
    struct TransientJsonWriteFailureSink {
        writes: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl PlatformAuditSink for TransientJsonWriteFailureSink {
        async fn write(
            &self,
            _envelope: &registry_platform_audit::AuditEnvelope,
        ) -> Result<(), AuditError> {
            if self.writes.fetch_add(1, Ordering::SeqCst) == 0 {
                let error = serde_json::from_str::<Value>("{")
                    .expect_err("malformed JSON creates a test error");
                return Err(AuditError::Json(error));
            }
            Ok(())
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &registry_platform_audit::AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn transient_json_audit_failure_recovers_without_poisoning_readiness() {
        let audit =
            AuditPipeline::for_sink_dev_only(Arc::new(TransientJsonWriteFailureSink::default()));

        let error = audit
            .emit(&audit_event())
            .await
            .expect_err("first audit write reports a JSON failure");
        assert!(matches!(error, AuditError::Json(_)));
        assert!(audit.chain_healthy());

        audit
            .emit(&audit_event())
            .await
            .expect("later audit write recovers");
        assert!(audit.chain_healthy());
    }

    struct ForkFailureSink;

    #[async_trait]
    impl PlatformAuditSink for ForkFailureSink {
        async fn write(
            &self,
            _envelope: &registry_platform_audit::AuditEnvelope,
        ) -> Result<(), AuditError> {
            Err(AuditError::ChainForkDetected {
                expected: registry_platform_audit::OptionalHashHex(None),
                found: registry_platform_audit::OptionalHashHex(Some([7; 32])),
            })
        }

        async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }

        async fn tail_hash_with_hasher(
            &self,
            _hasher: &registry_platform_audit::AuditChainHasher,
        ) -> Result<Option<[u8; 32]>, AuditError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn write_time_chain_fork_latches_audit_readiness() {
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(ForkFailureSink));
        audit
            .emit(&audit_event())
            .await
            .expect_err("forked append is rejected");
        assert!(!audit.chain_healthy());
    }

    #[tokio::test]
    async fn audit_pipeline_file_sink_uses_configured_rotation() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let mut config = test_audit_config("file");
        config.path = Some(path.display().to_string());
        config.max_size_mb = Some(1);
        config.max_files = Some(2);
        let audit = AuditPipeline::from_config(&config).expect("audit config builds");

        for _ in 0..2_500 {
            audit
                .emit(&audit_event())
                .await
                .expect("audit write succeeds");
        }

        assert!(path.exists(), "active audit file should exist");
        assert!(
            tmp.path().join("audit.jsonl.1").exists(),
            "rotated audit file should exist"
        );
        assert!(
            !tmp.path().join("audit.jsonl.2").exists(),
            "rotation should retain only the configured number of files"
        );
    }

    #[test]
    fn audit_pipeline_file_sink_is_single_writer() {
        // #211: a second notary audit pipeline over the same file path must fail
        // loudly at construction (the single-writer advisory lock) rather than
        // silently forking the audit chain.
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("audit.jsonl");
        let mut config = test_audit_config("file");
        config.path = Some(path.display().to_string());

        let _first = AuditPipeline::from_config(&config).expect("first audit pipeline builds");
        let second = AuditPipeline::from_config(&config);
        assert!(
            matches!(
                second,
                Err(StandaloneServerError::Audit(AuditError::SinkLocked { .. }))
            ),
            "second writer must be rejected, got {second:?}"
        );
    }

    #[test]
    fn audit_pipeline_accepts_syslog_sink_config() {
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some("/tmp/registry-notary-test-syslog.sock".to_string());

        AuditPipeline::from_config(&config).expect("syslog audit config builds");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn audit_pipeline_syslog_sink_writes_to_configured_socket() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let socket_path = tmp.path().join("audit.sock");
        let socket = tokio::net::UnixDatagram::bind(&socket_path).expect("bind syslog socket");
        let mut config = test_audit_config("syslog");
        config.syslog_socket_path = Some(socket_path.display().to_string());
        let audit = AuditPipeline::from_config(&config).expect("syslog audit config builds");

        audit
            .emit(&audit_event())
            .await
            .expect("audit write succeeds");

        let mut buffer = vec![0; 8192];
        let bytes = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("syslog datagram is received")
            .expect("syslog socket receives datagram");
        let frame = std::str::from_utf8(&buffer[..bytes]).expect("syslog frame is UTF-8");
        assert!(frame.starts_with("<134>1 "));
        assert!(frame.contains("registry-platform-audit"));
        assert!(frame.contains(r#""event_id":"01HX0000000000000000000000""#));
    }

    #[test]
    fn audit_pipeline_rejects_zero_file_retention() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut config = test_audit_config("file");
        config.path = Some(tmp.path().join("audit.jsonl").display().to_string());
        config.max_files = Some(0);

        let error = AuditPipeline::from_config(&config).expect_err("zero retention is rejected");

        assert!(matches!(
            error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
        assert!(
            error.to_string().contains("max_files"),
            "error should name the invalid field"
        );
    }

    #[test]
    fn audit_pipeline_rejects_sink_specific_fields_on_wrong_sink() {
        let mut stdout_config = test_audit_config("stdout");
        stdout_config.max_size_mb = Some(1);
        let stdout_error = AuditPipeline::from_config(&stdout_config)
            .expect_err("stdout cannot accept file rotation");
        assert!(matches!(
            stdout_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));

        let mut file_config = test_audit_config("file");
        file_config.path = Some("/tmp/audit.jsonl".to_string());
        file_config.syslog_socket_path = Some("/tmp/syslog.sock".to_string());
        let file_error =
            AuditPipeline::from_config(&file_config).expect_err("file cannot accept syslog path");
        assert!(matches!(
            file_error,
            StandaloneServerError::InvalidAuditConfig(_)
        ));
    }

    #[tokio::test]
    async fn audit_sink_emit_surfaces_file_write_errors() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));

        let error = audit
            .emit(&audit_event())
            .await
            .expect_err("file write error is returned");

        assert!(matches!(error, AuditError::Io(_)));
    }

    #[tokio::test]
    async fn audit_write_failure_replaces_authorized_response_with_request_error() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let blocked_parent = tmp.path().join("blocked");
        std::fs::write(&blocked_parent, b"not a directory").expect("blocked parent is file");
        let audit = AuditPipeline::for_sink_dev_only(Arc::new(JsonlFileSink::new(
            blocked_parent.join("audit.jsonl"),
        )));
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(auth_state(audit), auth_audit_middleware));
        let server = TestServer::builder().http_transport().build(app);

        let response = server.get("/ok").add_header("x-api-key", "api-token").await;

        response.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = response.json();
        assert_eq!(body["code"], json!("audit.write_failed"));
    }
