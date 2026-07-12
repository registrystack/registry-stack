// SPDX-License-Identifier: Apache-2.0


    #[derive(Debug, Default)]
    struct CountingSource {
        read_count: AtomicU64,
        purposes: Mutex<Vec<String>>,
    }

    impl SourceReader for CountingSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                self.purposes
                    .lock()
                    .expect("purposes mutex is not poisoned")
                    .push(purpose.to_string());
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    /// Returns a `value` field of the wrong JSON shape (a string) so tests
    /// can exercise `validate_claim_value_type` refusing an extract result
    /// that does not conform to the claim's declared `value.type`.
    #[derive(Debug, Default)]
    struct WrongTypeSource;

    impl SourceReader for WrongTypeSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": "not-a-boolean",
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct DependentLookupSource {
        first_row: Value,
        reads: Mutex<Vec<(String, Value)>>,
    }

    impl DependentLookupSource {
        fn new(first_row: Value) -> Self {
            Self {
                first_row,
                reads: Mutex::new(Vec::new()),
            }
        }
    }

    impl SourceReader for DependentLookupSource {
        fn read_one<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let context = EvidenceRequestContext {
                    requester: None,
                    target: EvidenceEntity::from_subject_request("Person", subject.clone()),
                    relationship: None,
                    on_behalf_of: None,
                };
                self.read_one_for_context(binding, &context, purpose).await
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let lookup_value = context
                    .lookup_value(&binding.lookup.input)
                    .ok_or_else(|| missing_context_error(&binding.lookup.input))?;
                self.reads
                    .lock()
                    .expect("reads mutex is not poisoned")
                    .push((binding.entity.clone(), lookup_value.clone()));
                match binding.entity.as_str() {
                    "civil_status_record" => Ok(self.first_row.clone()),
                    "birth_event" => Ok(json!({
                        "id": lookup_value,
                        "certificate_id": "certificate-456",
                        "value": true,
                    })),
                    _ => Err(EvidenceError::SourceNotFound),
                }
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct RuntimeSummarySource {
        inner: CountingSource,
    }

    impl SourceReader for RuntimeSummarySource {
        fn observed_source_runtimes<'a>(
            &'a self,
            _evidence: &'a EvidenceConfig,
            claim_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<SourceRuntimeSummary>> + Send + 'a>> {
            Box::pin(async move {
                if claim_id != "dependency" {
                    return Vec::new();
                }
                vec![SourceRuntimeSummary {
                    kind: SOURCE_RUNTIME_KIND_SOURCE_ADAPTER_SIDECAR.to_string(),
                    config_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    assurance: registry_notary_core::SourceRuntimeAssurance {
                        pinned: true,
                        expression_hashes_verified: true,
                        runtime_verified: true,
                        smoke_verified: true,
                    },
                }]
            })
        }

        fn read_one<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            self.inner.read_one(binding, subject, purpose)
        }

        fn required_scopes(
            &self,
            evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            self.inner.required_scopes(evidence, claim_id)
        }
    }

    #[derive(Debug, Default)]
    struct VersionScopedSource {
        read_count: AtomicU64,
    }

    impl SourceReader for VersionScopedSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.read_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{claim_id}:1.0")])
        }

        fn required_scopes_for_claim(
            &self,
            _evidence: &EvidenceConfig,
            claim: &ClaimDefinition,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(vec![format!("{}:{}", claim.id, claim.version)])
        }
    }

    #[derive(Debug, Default)]
    struct BulkInvalidThenDirectSource {
        bulk_count: AtomicU64,
        direct_count: AtomicU64,
    }

    impl SourceReader for BulkInvalidThenDirectSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.direct_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                }))
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let subject = context
                    .target_subject()
                    .ok_or(EvidenceError::TargetAttributesInsufficient)?;
                self.read_one(binding, &subject, purpose).await
            })
        }

        fn read_many_context<'a>(
            &'a self,
            bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
            Box::pin(async move {
                self.bulk_count.fetch_add(1, Ordering::SeqCst);
                bindings
                    .into_iter()
                    .map(|(_, context)| {
                        let id = context
                            .target_subject()
                            .map(|subject| subject.id)
                            .unwrap_or_default();
                        Ok(json!({ "id": id }))
                    })
                    .collect()
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug)]
    struct BulkStaleFreshnessSource {
        stale_observed_at: OffsetDateTime,
        bulk_count: AtomicU64,
        direct_count: AtomicU64,
        preflight_count: AtomicU64,
    }

    impl BulkStaleFreshnessSource {
        fn new() -> Self {
            Self {
                stale_observed_at: OffsetDateTime::now_utc() - time::Duration::seconds(61),
                bulk_count: AtomicU64::new(0),
                direct_count: AtomicU64::new(0),
                preflight_count: AtomicU64::new(0),
            }
        }

        fn stale_observed_at_value(&self) -> Value {
            json!(self
                .stale_observed_at
                .format(&Rfc3339)
                .expect("stale observed_at formats"))
        }
    }

    impl SourceReader for BulkStaleFreshnessSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                self.direct_count.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "id": subject.id.clone(),
                    "value": true,
                    "observed_at": self.stale_observed_at_value(),
                }))
            })
        }

        fn read_one_for_context<'a>(
            &'a self,
            binding: &'a SourceBindingConfig,
            context: &'a EvidenceRequestContext,
            purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            Box::pin(async move {
                let subject = context
                    .target_subject()
                    .ok_or(EvidenceError::TargetAttributesInsufficient)?;
                self.read_one(binding, &subject, purpose).await
            })
        }

        fn source_observed_at_for_context<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            _context: &'a EvidenceRequestContext,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.preflight_count.fetch_add(1, Ordering::SeqCst);
                Ok(Some(self.stale_observed_at))
            })
        }

        fn read_many_context<'a>(
            &'a self,
            bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
            Box::pin(async move {
                self.bulk_count.fetch_add(1, Ordering::SeqCst);
                bindings
                    .into_iter()
                    .map(|(_, context)| {
                        let id = context
                            .target_subject()
                            .map(|subject| subject.id)
                            .unwrap_or_default();
                        Ok(json!({
                            "id": id,
                            "value": true,
                            "observed_at": self.stale_observed_at_value(),
                        }))
                    })
                    .collect()
            })
        }

        fn required_scopes(
            &self,
            _evidence: &EvidenceConfig,
            _claim_id: &str,
        ) -> Result<Vec<String>, EvidenceError> {
            Ok(Vec::new())
        }
    }

    fn test_source_binding() -> SourceBindingConfig {
        SourceBindingConfig {
            connector: registry_notary_core::SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "people".to_string(),
            entity: "person".to_string(),
            lookup: registry_notary_core::SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::from([(
                "value".to_string(),
                registry_notary_core::SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("boolean".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
            matching: registry_notary_core::SourceMatchingConfig::default(),
        }
    }

    fn dependent_source_binding(
        entity: &str,
        lookup_input: &str,
        lookup_field: &str,
    ) -> SourceBindingConfig {
        let mut binding = test_source_binding();
        binding.entity = entity.to_string();
        binding.lookup.input = lookup_input.to_string();
        binding.lookup.field = lookup_field.to_string();
        binding.fields.clear();
        binding.matching.allowed_purposes = vec!["test".to_string()];
        binding.matching.allowed_target_inputs = vec!["target.id".to_string()];
        binding
    }

    fn machine_capability(scopes: &[&str]) -> SourceCapability {
        SourceCapability::Machine {
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    fn test_purpose_constraints(purpose: &str) -> Vec<Vec<String>> {
        vec![vec![purpose.to_string()]]
    }

    fn expect_pdp_denial(
        result: Result<BindingPolicyEffect, EvidenceError>,
        expected_code: &'static str,
    ) {
        let error = result.expect_err("PDP must deny");
        let EvidenceError::PolicyDenied {
            code,
            policy_id,
            policy_hash,
            evaluated_rule_ids,
        } = error
        else {
            panic!("expected PolicyDenied, got {error:?}");
        };
        assert_eq!(code, expected_code);
        assert!(policy_id.is_some(), "PDP denial must carry policy id");
        assert!(policy_hash.is_some(), "PDP denial must carry policy hash");
        assert!(
            !evaluated_rule_ids.is_empty(),
            "PDP denial must carry evaluated rule ids"
        );
    }

    fn expect_pdp_permit(
        result: Result<BindingPolicyEffect, EvidenceError>,
    ) -> BindingPolicyEffect {
        result.expect("PDP must permit")
    }

    fn assert_collapsed_matching_error(error: EvidenceError, expected_audit_code: &'static str) {
        assert_eq!(error.code(), "evidence.not_available");
        assert_eq!(error.audit_code(), expected_audit_code);
        assert!(
            matches!(
                &error,
                EvidenceError::MatchingEvidenceNotAvailable { audit_code }
                    if *audit_code == expected_audit_code
            ),
            "expected collapsed matching error with audit code {expected_audit_code}, got {error:?}"
        );
    }

    fn matching_gate_rule_ids(extra_gates: &[&str], redacted: bool) -> Vec<String> {
        let mut rule_ids = vec![registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[0]];
        if extra_gates
            .iter()
            .any(|gate| matches!(*gate, "pdp.purpose" | "pdp.jurisdiction"))
        {
            rule_ids.push(registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[1]);
        }
        rule_ids.extend_from_slice(extra_gates);
        rule_ids.extend_from_slice(&registry_notary_core::MATCHING_POLICY_BASE_RULE_SUFFIXES[2..]);
        if redacted {
            rule_ids.push("redaction");
        }
        rule_ids
            .into_iter()
            .map(|rule_id| {
                format!(
                    "source-binding-policy:person.{}",
                    rule_id.strip_prefix("pdp.").unwrap_or(rule_id)
                )
            })
            .collect()
    }

    fn test_claim(id: &str, depends_on: Vec<&str>, has_source: bool) -> ClaimDefinition {
        let source_bindings = if has_source {
            BTreeMap::from([("src".to_string(), test_source_binding())])
        } else {
            BTreeMap::new()
        };
        ClaimDefinition {
            id: id.to_string(),
            title: id.to_string(),
            version: "1.0".to_string(),
            subject_type: "person".to_string(),
            evidence_mode: registry_notary_core::ClaimEvidenceMode::TransitionalDirect,
            value: registry_notary_core::ClaimValueConfig {
                value_type: "boolean".to_string(),
                unit: None,
            },
            semantics: None,
            inputs: Vec::new(),
            depends_on: depends_on.into_iter().map(str::to_string).collect(),
            purpose: None,
            required_scopes: Vec::new(),
            source_bindings,
            rule: if has_source {
                RuleConfig::Extract {
                    source: "src".to_string(),
                    field: "value".to_string(),
                }
            } else {
                RuleConfig::Exists {
                    source: "src".to_string(),
                }
            },
            operations: registry_notary_core::ClaimOperationsConfig::default(),
            disclosure: registry_notary_core::DisclosureConfig {
                default: "value".to_string(),
                allowed: vec!["value".to_string(), "redacted".to_string()],
                downgrade: "redacted".to_string(),
            },
            formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
            credential_profiles: Vec::new(),
            cccev: None,
            oots: None,
        }
    }

    fn test_evidence(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
        Arc::new(EvidenceConfig {
            enabled: true,
            service_id: "runtime.test".to_string(),
            claims,
            ..EvidenceConfig::default()
        })
    }

    fn test_claim_result(
        claim_id: &str,
        value: Value,
        redaction_fields: BTreeSet<String>,
    ) -> ClaimResultInternal {
        ClaimResultInternal {
            evaluation_id: "eval-test".to_string(),
            claim_id: claim_id.to_string(),
            claim_version: "1.0".to_string(),
            subject_type: "person".to_string(),
            target: EvidenceEntity::new("Person"),
            requester: None,
            matching: None,
            value,
            redaction_fields,
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
            provenance: ClaimProvenance::new(
                "runtime.test".to_string(),
                "eval-test".to_string(),
                claim_id.to_string(),
                "1.0".to_string(),
                ProvenanceUsed {
                    source_count: 0,
                    source_versions: BTreeMap::new(),
                    source_runtimes: Vec::new(),
                },
            ),
            relay_consultation_ids: BTreeSet::new(),
        }
    }

    fn bulk_source_connection() -> registry_notary_core::SourceConnectionConfig {
        registry_notary_core::SourceConnectionConfig {
            base_url: "https://source.test".to_string(),
            allow_insecure_localhost: false,
            allow_insecure_private_network: false,
            token_env: String::new(),
            source_auth: None,
            expected_sidecar: None,
            dci: registry_notary_core::DciSourceConnectionConfig::default(),
            max_in_flight: 1,
            retry_on_5xx: false,
            bulk_mode: BulkMode::SourceAdapterSidecarBatch,
            bulk_mode_lookup_unique: true,
            bulk_timeout_max_ms: 1_000,
        }
    }

    fn test_request(claim: &str) -> EvaluateRequest {
        EvaluateRequest {
            requester: None,
            target: Some(registry_notary_core::EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "person-1".to_string(),
                    id_type: None,
                },
            )),
            relationship: None,
            on_behalf_of: None,
            claims: vec![ClaimRef::from(claim)],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        }
    }

    fn machine_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
            principal_id: "machine".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::MachineClient,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn self_attestation_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
            principal_id: "citizen".to_string(),
            scopes: vec!["self_attestation".to_string()],
            access_mode: AccessMode::SelfAttestation,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn self_attestation_capability(claim_id: &str) -> SourceCapability {
        SourceCapability::SelfAttestation {
            claim_id: Some(BoundedClaimId::new(claim_id).expect("claim id is bounded")),
            allowed_claim_ids: BTreeSet::new(),
            subject_binding_hash: Hashed::from_hash("sha256:test"),
        }
    }

    fn delegated_attestation_capability(
        keys: &SelfAttestationRateLimitKeys,
        requester_subject: &str,
        dependent_subject: &str,
    ) -> SourceCapability {
        delegated_attestation_capability_with_id_types(
            keys,
            "national_id",
            requester_subject,
            "civil_registration_id",
            dependent_subject,
        )
    }

    fn delegated_attestation_capability_with_id_types(
        keys: &SelfAttestationRateLimitKeys,
        requester_id_type: &str,
        requester_subject: &str,
        dependent_id_type: &str,
        dependent_subject: &str,
    ) -> SourceCapability {
        SourceCapability::DelegatedAttestation {
            proof_claim_id: BoundedClaimId::new("guardian-link")
                .expect("proof claim id is bounded"),
            allowed_claim_ids: BTreeSet::from([
                BoundedClaimId::new("selected").expect("delegated claim id is bounded")
            ]),
            requester_subject_binding_hash: keys
                .delegated_subject_binding(requester_id_type, requester_subject)
                .expect("requester hashes"),
            dependent_target_hash: keys
                .delegated_subject_binding(dependent_id_type, dependent_subject)
                .expect("dependent hashes"),
            relationship_type: registry_notary_core::ConfigMetadata::new("guardian")
                .expect("relationship type is bounded"),
        }
    }

    fn delegated_principal() -> EvidencePrincipal {
        EvidencePrincipal {
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
            principal_id: "guardian".to_string(),
            scopes: Vec::new(),
            access_mode: AccessMode::DelegatedAttestation,
            verified_claims: None,
            authorization_details: None,
        }
    }

    fn delegated_runtime_request() -> EvaluateRequest {
        EvaluateRequest {
            requester: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "NAT-123".to_string(),
                    id_type: Some("national_id".to_string()),
                },
            )),
            target: Some(EvidenceEntity::from_subject_request(
                "Person",
                SubjectRequest {
                    id: "CHILD-123".to_string(),
                    id_type: Some("civil_registration_id".to_string()),
                },
            )),
            relationship: Some(registry_notary_core::EvidenceRelationship {
                relationship_type: "guardian".to_string(),
                attributes: BTreeMap::new(),
            }),
            on_behalf_of: None,
            claims: vec![ClaimRef::from("selected")],
            disclosure: Some("value".to_string()),
            format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
            purpose: Some("test".to_string()),
        }
    }
