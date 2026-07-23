// SPDX-License-Identifier: Apache-2.0

#[test]
fn request_context_scalars_preserve_supported_types() {
    assert_eq!(canonical_request_scalar(&json!("Ada")), Some("Ada".to_string()));
    assert_eq!(canonical_request_scalar(&json!(true)), Some("true".to_string()));
    assert_eq!(canonical_request_scalar(&json!(-42)), Some("-42".to_string()));
    assert_eq!(canonical_request_scalar(&json!(1.5)), None);
    assert_eq!(canonical_request_scalar(&Value::Null), None);
    assert_eq!(canonical_request_scalar(&json!(["Ada"])), None);
    assert_eq!(canonical_request_scalar(&json!({ "name": "Ada" })), None);
    assert_eq!(canonical_request_scalar(&json!(u64::MAX)), None);
}

#[derive(Debug)]
struct FixedRelayConsultation {
    calls: AtomicU64,
    outcome: RuntimeRelayOutcome,
}

fn status_match_data() -> Result<RuntimeRelayMatchData, crate::relay_client::RelayClientError> {
    RuntimeRelayOutputMap::from_json(BTreeMap::from([(
        "registration_status".to_string(),
        json!("ACTIVE"),
    )]))
    .map(RuntimeRelayMatchData::OutputMap)
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
            .then(status_match_data)
            .transpose()?;
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 1),
            self.outcome,
            match_data,
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug)]
struct MixedCompletionRelay {
    calls: AtomicU64,
    failed_target: &'static str,
    error: crate::relay_client::RelayClientError,
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for MixedCompletionRelay {
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
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let target = key
            .canonical_inputs()
            .get("tracked_entity")
            .map(|value| value.as_str())
            .ok_or(crate::relay_client::RelayClientError::InvalidRequest)?;
        if target == self.failed_target {
            return Err(self.error);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(2, 2),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug, Default)]
struct UniqueRelayConsultation {
    calls: AtomicU64,
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for UniqueRelayConsultation {
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
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(call, 1),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug)]
struct DelegatedRelayConsultation {
    calls: AtomicU64,
    outcome: RuntimeRelayOutcome,
    proof_value: bool,
    validation_error: Option<crate::relay_client::RelayClientError>,
    execution_error: Option<crate::relay_client::RelayClientError>,
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for DelegatedRelayConsultation {
    async fn check_ready(&self) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    fn validate(
        &self,
        _key: &ConsultationGroupKeyV1,
    ) -> Result<(), crate::relay_client::RelayClientError> {
        self.validation_error.map_or(Ok(()), Err)
    }

    async fn execute(
        &self,
        _key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.execution_error {
            return Err(error);
        }
        let match_data = matches!(self.outcome, RuntimeRelayOutcome::Match)
            .then(|| {
                RuntimeRelayOutputMap::from_json(BTreeMap::from([(
                    "relationship_proven".to_string(),
                    Value::Bool(self.proof_value),
                )]))
                .map(RuntimeRelayMatchData::OutputMap)
            })
            .transpose()?;
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(7, 1),
            self.outcome,
            match_data,
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug, Default)]
struct BatchIdentityRelay {
    child_identities: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for BatchIdentityRelay {
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
        panic!("registry-backed batch must use the child-identity execution boundary")
    }

    async fn execute_batch(
        &self,
        _key: &ConsultationGroupKeyV1,
        child_identity: &consultation::BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        self.child_identities
            .lock()
            .expect("child identity lock is not poisoned")
            .push(child_identity.as_str().to_string());
        RuntimeRelayConsultationResult::new(
            Ulid::new(),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug, Default)]
struct TypedInputRelay {
    single_inputs: Mutex<Vec<BTreeMap<String, String>>>,
    batch_inputs: Mutex<Vec<BTreeMap<String, String>>>,
}

fn observed_inputs(key: &ConsultationGroupKeyV1) -> BTreeMap<String, String> {
    key.canonical_inputs()
        .iter()
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect()
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for TypedInputRelay {
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
        key: &ConsultationGroupKeyV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        self.single_inputs
            .lock()
            .expect("single input lock is not poisoned")
            .push(observed_inputs(key));
        RuntimeRelayConsultationResult::new(
            Ulid::new(),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    async fn execute_batch(
        &self,
        key: &ConsultationGroupKeyV1,
        _child_identity: &consultation::BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        self.batch_inputs
            .lock()
            .expect("batch input lock is not poisoned")
            .push(observed_inputs(key));
        RuntimeRelayConsultationResult::new(
            Ulid::new(),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[derive(Debug, Default)]
struct CrashRetryBatchRelay {
    attempts: AtomicU64,
    observations: Mutex<Vec<(String, String)>>,
    first_dispatch: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl ActivatedRelayConsultations for CrashRetryBatchRelay {
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
        panic!("registry-backed batch must use the child-identity execution boundary")
    }

    async fn execute_batch(
        &self,
        key: &ConsultationGroupKeyV1,
        child_identity: &consultation::BatchChildIdentityV1,
    ) -> Result<RuntimeRelayConsultationResult, crate::relay_client::RelayClientError> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        self.observations
            .lock()
            .expect("retry observation lock is not poisoned")
            .push((
                child_identity.as_str().to_string(),
                key.evaluation_id().to_string(),
            ));
        if attempt == 0 {
            self.first_dispatch.notify_one();
            std::future::pending::<()>().await;
        }
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(5, 1),
            RuntimeRelayOutcome::Match,
            Some(status_match_data()?),
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

#[cfg(feature = "registry-notary-cel")]
#[derive(Debug)]
struct TypedOutputRelay {
    calls: AtomicU64,
    outcome: RuntimeRelayOutcome,
}

#[cfg(feature = "registry-notary-cel")]
#[async_trait::async_trait]
impl ActivatedRelayConsultations for TypedOutputRelay {
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
        let match_data = (self.outcome == RuntimeRelayOutcome::Match)
            .then(|| {
                RuntimeRelayOutputMap::from_json(BTreeMap::from([(
                    "date_of_birth".to_string(),
                    json!("2010-06-15"),
                )]))
                .map(RuntimeRelayMatchData::OutputMap)
            })
            .transpose()?;
        RuntimeRelayConsultationResult::new(
            Ulid::from_parts(3, 1),
            self.outcome,
            match_data,
            OffsetDateTime::UNIX_EPOCH,
        )
    }
}

fn registry_claim(id: &str, rule: RuleConfig, value_type: &str) -> ClaimDefinition {
    let nullable = matches!(&rule, RuleConfig::ConsultationOutput { .. });
    let mut claim = test_claim(id, Vec::new(), false);
    claim.evidence_mode = ClaimEvidenceMode::RegistryBacked {
        consultations: BTreeMap::from([(
            "enrollment".to_string(),
            registry_notary_core::RelayConsultationConfig {
                profile: registry_notary_core::RelayConsultationProfileRef {
                    id: "dhis2.tracker.enrollment-status.exact".to_string(),
                    contract_hash:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                },
                inputs: BTreeMap::from([(
                    "tracked_entity".to_string(),
                    RelayConsultationInput::TargetId,
                )]),
                outputs: BTreeMap::from([(
                    "registration_status".to_string(),
                    registry_notary_core::RelayOutputContract::String {
                        nullable: true,
                        max_bytes: 64,
                    },
                )]),
            },
        )]),
    };
    claim.purpose = Some("test".to_string());
    claim.required_scopes = vec!["registry:evidence".to_string()];
    claim.rule = rule;
    claim.value.value_type = value_type.to_string();
    claim.value.nullable = nullable;
    claim
}

fn delegated_relay_proof_claim() -> ClaimDefinition {
    let mut claim = registry_claim(
        "guardian-link",
        RuleConfig::ConsultationOutput {
            consultation: "relationship".to_string(),
            output: "relationship_proven".to_string(),
        },
        "boolean",
    );
    claim.required_scopes = vec!["subject_access".to_string()];
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("delegated proof claim is Registry-backed")
    };
    let mut consultation = consultations
        .remove("enrollment")
        .expect("proof consultation exists");
    consultation.profile.id = "example.guardian-link.exact".to_string();
    consultation.inputs = BTreeMap::from([
        (
            "requester_id".to_string(),
            RelayConsultationInput::RequesterIdentifier(
                "request.requester.identifiers.national_id".to_string(),
            ),
        ),
        (
            "target_id".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.civil_registration_id".to_string(),
            ),
        ),
    ]);
    consultation.outputs = BTreeMap::from([(
        "relationship_proven".to_string(),
        registry_notary_core::RelayOutputContract::Boolean { nullable: false },
    )]);
    consultations.insert("relationship".to_string(), consultation);
    claim
}

fn delegated_selected_claim(dependencies: Vec<&str>) -> ClaimDefinition {
    let mut claim = test_claim("selected", dependencies, false);
    claim.evidence_mode = ClaimEvidenceMode::SelfAttested;
    claim.purpose = Some("test".to_string());
    claim
}

fn delegated_relay_principal() -> EvidencePrincipal {
    let mut principal = delegated_principal();
    principal.scopes = vec!["subject_access".to_string()];
    principal
}

fn delegated_evidence(claims: Vec<ClaimDefinition>) -> Arc<EvidenceConfig> {
    let mut evidence = (*test_evidence(claims)).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    Arc::new(evidence)
}

fn delegated_runtime_with_relay(
    keys: &Arc<SubjectAccessRateLimitKeys>,
    outcome: RuntimeRelayOutcome,
    proof_value: bool,
    validation_error: Option<crate::relay_client::RelayClientError>,
    execution_error: Option<crate::relay_client::RelayClientError>,
) -> (RegistryNotaryRuntime, Arc<DelegatedRelayConsultation>) {
    let activated = Arc::new(DelegatedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome,
        proof_value,
        validation_error,
        execution_error,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    (
        RegistryNotaryRuntime::new_with_subject_access_rate_keys(Arc::clone(keys))
            .with_activated_relay(Some(bound)),
        activated,
    )
}

fn subject_bound_capability(
    keys: &SubjectAccessRateLimitKeys,
    claim_id: &str,
) -> EvaluationCapability {
    let claim_id = BoundedClaimId::new(claim_id).expect("claim id is bounded");
    EvaluationCapability::SubjectBound {
        claim_id: Some(claim_id.clone()),
        allowed_claim_ids: BTreeSet::from([claim_id]),
        subject_binding_hash: keys
            .subject_binding("person-1")
            .expect("subject binding hashes"),
    }
}

#[tokio::test]
async fn subject_bound_capability_consults_only_its_exact_registry_claim() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    claim.required_scopes = vec!["subject_access".to_string()];
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("subject-bound claim is registry backed")
    };
    consultations
        .get_mut("enrollment")
        .expect("subject-bound consultation exists")
        .inputs
        .insert(
            "tracked_entity".to_string(),
            RelayConsultationInput::TargetIdentifier(
                "request.target.identifiers.national_id".to_string(),
            ),
        );
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let relay = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = relay.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let keys = SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());

    let results = runtime
        .evaluate_with_capability(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &subject_access_principal(),
            subject_bound_capability(&keys, "enrollment-status"),
            {
                let mut request = test_request("enrollment-status");
                request.target = Some(EvidenceEntity::with_identifier(
                    "Person",
                    "national_id",
                    "person-1",
                ));
                request
            },
            None,
            None,
            None,
        )
        .await
        .expect("the exact subject-bound registry claim evaluates");

    assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn subject_bound_capability_denies_an_unlisted_registry_claim_before_relay() {
    let mut claim = registry_claim(
        "other-registry-claim",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    claim.required_scopes.clear();
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let relay = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = relay.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let keys = SubjectAccessRateLimitKeys::new(AuditKeyHasher::unkeyed_dev_only());

    let error = runtime
        .evaluate_with_capability(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &subject_access_principal(),
            subject_bound_capability(&keys, "allowed-registry-claim"),
            test_request("other-registry-claim"),
            None,
            None,
            None,
        )
        .await
        .expect_err("an unlisted registry claim must fail before Relay");

    assert!(matches!(
        error,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::ClaimDenied
        }
    ));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegated_exact_relay_proof_runs_once_before_the_dependent_claim() {
    let evidence = delegated_evidence(vec![
        delegated_relay_proof_claim(),
        delegated_selected_claim(vec!["guardian-link"]),
    ]);
    let keys = Arc::new(SubjectAccessRateLimitKeys::new(
        AuditKeyHasher::unkeyed_dev_only(),
    ));
    let (runtime, relay) = delegated_runtime_with_relay(
        &keys,
        RuntimeRelayOutcome::Match,
        true,
        None,
        None,
    );

    let results = runtime
        .evaluate_with_capability(
            evidence,
            &EvidenceStore::default(),
            &delegated_relay_principal(),
            delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
            delegated_runtime_request(),
            None,
            None,
            None,
        )
        .await
        .expect("the exact Relay proof permits its configured delegated claim");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].claim_id, "selected");
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delegated_capability_denies_an_unrelated_registry_backed_dependency_before_relay() {
    let mut unrelated = registry_claim(
        "unrelated-registry-claim",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    unrelated.required_scopes.clear();
    let evidence = delegated_evidence(vec![
        delegated_relay_proof_claim(),
        unrelated,
        delegated_selected_claim(vec!["guardian-link", "unrelated-registry-claim"]),
    ]);
    let keys = Arc::new(SubjectAccessRateLimitKeys::new(
        AuditKeyHasher::unkeyed_dev_only(),
    ));
    let (runtime, relay) = delegated_runtime_with_relay(
        &keys,
        RuntimeRelayOutcome::Match,
        true,
        None,
        None,
    );

    let error = runtime
        .evaluate_with_capability(
            evidence,
            &EvidenceStore::default(),
            &delegated_relay_principal(),
            delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
            delegated_runtime_request(),
            None,
            None,
            None,
        )
        .await
        .expect_err("delegation grants only the exact configured Relay proof claim");

    assert!(matches!(
        error,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::DelegatedSubjectNotPermitted
        }
    ));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegated_proof_claim_scope_denial_makes_zero_relay_calls() {
    let evidence = delegated_evidence(vec![
        delegated_relay_proof_claim(),
        delegated_selected_claim(vec!["guardian-link"]),
    ]);
    let keys = Arc::new(SubjectAccessRateLimitKeys::new(
        AuditKeyHasher::unkeyed_dev_only(),
    ));
    let (runtime, relay) = delegated_runtime_with_relay(
        &keys,
        RuntimeRelayOutcome::Match,
        true,
        None,
        None,
    );

    let error = runtime
        .evaluate_with_capability(
            evidence,
            &EvidenceStore::default(),
            &delegated_principal(),
            delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
            delegated_runtime_request(),
            None,
            None,
            None,
        )
        .await
        .expect_err("the delegated caller must satisfy the proof claim scope gate");

    assert!(matches!(
        error,
        EvidenceError::ScopeDenied { required } if required == "subject_access"
    ));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegated_requester_or_target_binding_mismatch_makes_zero_relay_calls() {
    for (requester, target) in [
        ("OTHER-REQUESTER", "CHILD-123"),
        ("NAT-123", "OTHER-TARGET"),
    ] {
        let evidence = delegated_evidence(vec![
            delegated_relay_proof_claim(),
            delegated_selected_claim(vec!["guardian-link"]),
        ]);
        let keys = Arc::new(SubjectAccessRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let (runtime, relay) = delegated_runtime_with_relay(
            &keys,
            RuntimeRelayOutcome::Match,
            true,
            None,
            None,
        );

        let error = runtime
            .evaluate_with_capability(
                evidence,
                &EvidenceStore::default(),
                &delegated_relay_principal(),
                delegated_attestation_capability(&keys, requester, target),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("delegated requester and target bindings fail closed before Relay");

        assert!(matches!(
            error,
            EvidenceError::SubjectAccessDenied {
                reason: SubjectAccessDenialCode::DelegatedSubjectNotPermitted
            }
        ));
        assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn delegated_false_or_no_match_relay_proof_is_relationship_unproven() {
    for (outcome, proof_value) in [
        (RuntimeRelayOutcome::Match, false),
        (RuntimeRelayOutcome::NoMatch, false),
    ] {
        let evidence = delegated_evidence(vec![
            delegated_relay_proof_claim(),
            delegated_selected_claim(vec!["guardian-link"]),
        ]);
        let keys = Arc::new(SubjectAccessRateLimitKeys::new(
            AuditKeyHasher::unkeyed_dev_only(),
        ));
        let (runtime, relay) =
            delegated_runtime_with_relay(&keys, outcome, proof_value, None, None);

        let error = runtime
            .evaluate_with_capability(
                evidence,
                &EvidenceStore::default(),
                &delegated_relay_principal(),
                delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
                delegated_runtime_request(),
                None,
                None,
                None,
            )
            .await
            .expect_err("a false or absent relationship proof denies its dependent claim");

        assert!(matches!(
            error,
            EvidenceError::SubjectAccessDenied {
                reason: SubjectAccessDenialCode::DelegatedRelationshipUnproven
            }
        ));
        assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn delegated_relay_execution_failure_is_proof_denied() {
    let evidence = delegated_evidence(vec![
        delegated_relay_proof_claim(),
        delegated_selected_claim(vec!["guardian-link"]),
    ]);
    let keys = Arc::new(SubjectAccessRateLimitKeys::new(
        AuditKeyHasher::unkeyed_dev_only(),
    ));
    let (runtime, relay) = delegated_runtime_with_relay(
        &keys,
        RuntimeRelayOutcome::Match,
        true,
        None,
        Some(crate::relay_client::RelayClientError::TransportUnavailable),
    );

    let error = runtime
        .evaluate_with_capability(
            evidence,
            &EvidenceStore::default(),
            &delegated_relay_principal(),
            delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
            delegated_runtime_request(),
            None,
            None,
            None,
        )
        .await
        .expect_err("Relay execution failure fails closed as delegated proof denial");

    assert!(matches!(
        error,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::DelegatedProofDenied
        }
    ));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delegated_relay_contract_mismatch_is_proof_denied_before_execution() {
    let evidence = delegated_evidence(vec![
        delegated_relay_proof_claim(),
        delegated_selected_claim(vec!["guardian-link"]),
    ]);
    let keys = Arc::new(SubjectAccessRateLimitKeys::new(
        AuditKeyHasher::unkeyed_dev_only(),
    ));
    let (runtime, relay) = delegated_runtime_with_relay(
        &keys,
        RuntimeRelayOutcome::Match,
        true,
        Some(crate::relay_client::RelayClientError::ContractMismatch),
        None,
    );

    let error = runtime
        .evaluate_with_capability(
            evidence,
            &EvidenceStore::default(),
            &delegated_relay_principal(),
            delegated_attestation_capability(&keys, "NAT-123", "CHILD-123"),
            delegated_runtime_request(),
            None,
            None,
            None,
        )
        .await
        .expect_err("pinned Relay contract mismatch fails closed as proof denial");

    assert!(matches!(
        error,
        EvidenceError::SubjectAccessDenied {
            reason: SubjectAccessDenialCode::DelegatedProofDenied
        }
    ));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "registry-notary-cel")]
fn typed_registry_claim(id: &str, rule: RuleConfig, value_type: &str) -> ClaimDefinition {
    let mut claim = registry_claim(id, rule, value_type);
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("registry-backed claim")
    };
    consultations
        .get_mut("enrollment")
        .expect("consultation exists")
        .outputs = BTreeMap::from([(
        "date_of_birth".to_string(),
        registry_notary_core::RelayOutputContract::Date { nullable: true },
    )]);
    claim.value.nullable = true;
    claim
}

async fn audited_registry_evaluation(
    claim: ClaimDefinition,
    outcome: RuntimeRelayOutcome,
) -> (
    Result<Vec<ClaimResultView>, EvidenceError>,
    EvaluationAuditSnapshot,
    Arc<FixedRelayConsultation>,
) {
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
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
            &EvidenceStore::default(),
            &principal,
            test_request("enrollment-status"),
            None,
        )
        .await;
    (result.0, result.1, activated)
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
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::Match).await;
    let results = result.expect("match evaluates");
    let evaluation_id = assert_relay_audit(audit);

    assert_eq!(results[0].evaluation_id, evaluation_id);
    assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
    let public = serde_json::to_string(&results).expect("public results serialize");
    assert!(!public.contains(&Ulid::from_parts(2, 1).to_string()));
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn typed_output_map_is_reused_for_direct_output_and_date_age_claims() {
    let date = typed_registry_claim(
        "date-of-birth",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "date_of_birth".to_string(),
        },
        "date",
    );
    let age_band = typed_registry_claim(
            "age-band",
            RuleConfig::Cel {
                expression: "enrollment.matched && enrollment.date_of_birth != null ? (date.age_on(enrollment.date_of_birth, as_of_date) < 18 ? \"child\" : \"adult\") : null".to_string(),
                bindings: Default::default(),
            },
            "string",
        );
    let mut evidence = (*test_evidence(vec![date, age_band])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.variables.insert(
        "as_of_date".to_string(),
        registry_notary_core::RequestVariableConfig {
            from: "request.variables.as_of_date".to_string(),
            value_type: registry_notary_core::RequestVariableType::Date,
        },
    );
    let activated = Arc::new(TypedOutputRelay {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = test_request("date-of-birth");
    request.claims.push(ClaimRef::from("age-band"));
    request.variables = registry_notary_core::RequestVariables::try_new(BTreeMap::from([(
        "as_of_date".to_string(),
        "2026-01-01".to_string(),
    )]))
    .expect("valid full-date variable");

    let results = runtime
        .evaluate_for_api(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await
        .0
        .expect("typed outputs evaluate");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].value, Some(json!("2010-06-15")));
    assert_eq!(results[1].value, Some(json!("child")));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn missing_declared_cel_variable_is_denied_before_relay() {
    let age_band = typed_registry_claim(
            "age-band",
            RuleConfig::Cel {
                expression: "enrollment.matched && enrollment.date_of_birth != null ? date.age_on(enrollment.date_of_birth, as_of_date) : null".to_string(),
                bindings: Default::default(),
            },
            "integer",
        );
    let mut evidence = (*test_evidence(vec![age_band])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.variables.insert(
        "as_of_date".to_string(),
        registry_notary_core::RequestVariableConfig {
            from: "request.variables.as_of_date".to_string(),
            value_type: registry_notary_core::RequestVariableType::Date,
        },
    );
    let activated = Arc::new(TypedOutputRelay {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];

    let (result, audit) = runtime
        .evaluate_for_api(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            test_request("age-band"),
            None,
        )
        .await;

    assert!(matches!(result, Err(EvidenceError::InvalidRequest)));
    let (evaluation_id, consultation_ids) = audit.into_parts();
    assert!(evaluation_id.is_none());
    assert!(consultation_ids.is_empty());
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);

    let mut request = test_request("age-band");
    request.variables = registry_notary_core::RequestVariables::try_new(BTreeMap::from([(
        "attacker_selected".to_string(),
        "2026-01-01".to_string(),
    )]))
    .expect("generic request-variable bounds accept the name");
    let (result, audit) = runtime
        .evaluate_for_api(
            test_evidence(vec![typed_registry_claim(
                "age-band",
                RuleConfig::Cel {
                    expression: "enrollment.matched".to_string(),
                    bindings: Default::default(),
                },
                "boolean",
            )]),
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await;
    assert!(matches!(result, Err(EvidenceError::InvalidRequest)));
    let (evaluation_id, consultation_ids) = audit.into_parts();
    assert!(evaluation_id.is_none());
    assert!(consultation_ids.is_empty());
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "registry-notary-cel")]
#[test]
fn no_match_builds_only_presence_and_nullable_absence_outputs() {
    let claim = typed_registry_claim(
        "age-band",
        RuleConfig::Cel {
            expression: "enrollment.matched ? \"known\" : null".to_string(),
            bindings: Default::default(),
        },
        "string",
    );
    let sources = materialize_relay_absence(&claim).expect("absence map materializes");
    assert_eq!(
        sources.get("enrollment"),
        Some(&json!({
            "date_of_birth": null,
            "matched": false,
            "outcome": "no_match"
        }))
    );
}

#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
async fn no_match_reuses_typed_absence_for_presence_and_nullable_direct_claims() {
    let mut exists = typed_registry_claim(
        "birth-record-exists",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    exists.value.nullable = false;
    let date = typed_registry_claim(
        "date-of-birth",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "date_of_birth".to_string(),
        },
        "date",
    );
    let mut evidence = (*test_evidence(vec![exists, date])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let activated = Arc::new(TypedOutputRelay {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::NoMatch,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = test_request("birth-record-exists");
    request.claims.push(ClaimRef::from("date-of-birth"));

    let results = runtime
        .evaluate_for_api(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await
        .0
        .expect("typed absence claims evaluate");

    assert_eq!(results[0].value, Some(json!(false)));
    assert_eq!(results[1].value, Some(Value::Null));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn relay_consultation_matched_materializes_declared_outputs_and_outcome() {
    let claim = registry_claim(
        "enrollment-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let result = RuntimeRelayConsultationResult::new(
        Ulid::from_parts(2, 1),
        RuntimeRelayOutcome::Match,
        Some(RuntimeRelayMatchData::OutputMap(
            RuntimeRelayOutputMap::from_json(BTreeMap::from([(
                "registration_status".to_string(),
                json!("ACTIVE"),
            )]))
            .expect("valid output map"),
        )),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("valid Relay match");

    let sources = materialize_relay_match(&claim, &result)
        .expect("exists match materializes the declared output namespace");

    assert_eq!(
        sources.get("enrollment"),
        Some(&json!({
            "registration_status": "ACTIVE",
            "matched": true,
            "outcome": "match"
        }))
    );
}

#[tokio::test]
async fn relay_no_match_consultation_output_materializes_null_with_restricted_correlation() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::NoMatch).await;

    let results = result.expect("no-match extraction evaluates to its explicit null view");
    assert_eq!(results[0].value, Some(Value::Null));
    assert_relay_audit(audit);
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_no_match_consultation_matched_remains_false_with_restricted_correlation() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::NoMatch).await;
    let results = result.expect("no-match existence evaluates to false");

    assert_eq!(results[0].value, Some(Value::Bool(false)));
    assert_relay_audit(audit);
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_ambiguous_failure_retains_restricted_correlation() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::Ambiguous).await;

    assert!(matches!(result, Err(EvidenceError::EvidenceNotAvailable)));
    assert_relay_audit(audit);
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_ambiguous_consultation_matched_remains_fail_closed() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::Ambiguous).await;

    assert!(matches!(result, Err(EvidenceError::EvidenceNotAvailable)));
    assert_relay_audit(audit);
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn post_relay_type_failure_retains_restricted_correlation() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "boolean",
    );
    let (result, audit, activated) =
        audited_registry_evaluation(claim, RuntimeRelayOutcome::Match).await;

    assert!(matches!(result, Err(EvidenceError::RuleEvaluationFailed)));
    assert_relay_audit(audit);
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn registry_backed_claims_share_one_relay_consultation_without_fallback() {
    let exists = registry_claim(
        "enrollment-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let extract = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let mut evidence = (*test_evidence(vec![exists, extract])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let evidence = Arc::new(evidence);
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
    assert!(results
        .iter()
        .all(|result| result.provenance.used.relay_consultation_count == 1));
    let stored = store
        .get(&results[0].evaluation_id, &principal.principal_id)
        .await
        .expect("stored evaluation read succeeds")
        .expect("restricted evaluation record is stored");
    assert!(
        stored.issuance_provenance.is_none(),
        "registry-backed evaluation-only claims must not retain private Relay identifiers"
    );
    let stored_wire = serde_json::to_string(&stored).expect("stored evaluation serializes");
    assert!(!stored_wire.contains("relay_consultation_ids"));
    assert!(!stored_wire.contains(&Ulid::from_parts(2, 1).to_string()));
    let public_wire = serde_json::to_string(&results).expect("public results serialize");
    assert!(!public_wire.contains("relay_consultation_ids"));

    runtime
        .evaluate(
            evidence,
            &store,
            &principal,
            request,
            None,
        )
        .await
        .expect("a new evaluation performs a new consultation");
    assert_eq!(activated.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn registry_credential_root_persists_exact_dependency_execution_closure() {
    let mut dependency = registry_claim(
        "civil-record-active",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut dependency.evidence_mode else {
        panic!("dependency is registry backed");
    };
    consultations
        .get_mut("enrollment")
        .expect("dependency consultation exists")
        .profile
        .id = "dhis2.tracker.civil-record.exact".to_string();
    let mut root = registry_claim(
        "credential-eligible",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    root.depends_on = vec![dependency.id.clone()];
    root.credential_profiles = vec!["credential-profile".to_string()];
    let mut evidence = (*test_evidence(vec![dependency, root])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.credential_profiles.insert(
        "credential-profile".to_string(),
        serde_json::from_value(json!({
            "format": FORMAT_SD_JWT_VC,
            "issuer": "did:web:issuer.example",
            "signing_key": "issuer-key",
            "vct": "https://issuer.example/credentials/test",
            "allowed_claims": ["credential-eligible"]
        }))
        .expect("credential profile parses"),
    );
    let evidence = Arc::new(evidence);
    let activated = Arc::new(UniqueRelayConsultation::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let store = EvidenceStore::default();
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];

    let results = runtime
        .evaluate(
            Arc::clone(&evidence),
            &store,
            &principal,
            test_request("credential-eligible"),
            None,
        )
        .await
        .expect("root and dependency execute");

    assert_eq!(activated.calls.load(Ordering::SeqCst), 2);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].provenance.used.relay_consultation_count, 2);
    let stored = store
        .get(&results[0].evaluation_id, &principal.principal_id)
        .await
        .expect("stored evaluation reads")
        .expect("stored evaluation exists");
    let issuance = stored
        .issuance_provenance
        .as_ref()
        .expect("registry closure provenance is retained");
    assert_eq!(
        issuance
            .claims
            .iter()
            .map(|claim| claim.claim_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["civil-record-active", "credential-eligible"])
    );
    assert_eq!(issuance.consultations.len(), 2);
    assert!(issuance
        .claims
        .iter()
        .all(|claim| claim.execution_binding.starts_with("sha256:")));
    require_issuable_evaluation_provenance(&evidence, &results[0].evaluation_id, &stored)
        .expect("the exact dependency closure is issuable");
}

fn registry_batch_request(claims: Vec<ClaimRef>) -> BatchEvaluateRequest {
    BatchEvaluateRequest {
        items: ["person-1", "person-1"]
            .into_iter()
            .map(|id| {
                registry_notary_core::BatchEvaluateItemRequest::from(
                    registry_notary_core::BatchSubjectRequest {
                        id: id.to_string(),
                        id_type: None,
                        purpose: None,
                    },
                )
            })
            .collect(),
        claims,
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    }
}

fn enable_registry_batch(claim: &mut ClaimDefinition) {
    claim.operations.batch_evaluate.enabled = true;
    claim.operations.batch_evaluate.max_subjects = 4;
}

fn enrollment_status_batch_evidence() -> Arc<EvidenceConfig> {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    Arc::new(evidence)
}

fn registry_evidence_principal() -> EvidencePrincipal {
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    principal
}

fn runtime_with_test_relay<T>(relay: Arc<T>) -> RegistryNotaryRuntime
where
    T: ActivatedRelayConsultations + 'static,
{
    let relay: Arc<dyn ActivatedRelayConsultations> = relay;
    RegistryNotaryRuntime::new().with_activated_relay(Some(relay))
}

#[tokio::test]
async fn typed_target_attributes_are_canonical_in_single_and_batch_plans() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("claim is registry backed")
    };
    let inputs = &mut consultations
        .get_mut("enrollment")
        .expect("consultation exists")
        .inputs;
    inputs.insert(
        "include_inactive".to_string(),
        RelayConsultationInput::TargetAttribute(
            "request.target.attributes.include_inactive".to_string(),
        ),
    );
    inputs.insert(
        "person_sequence".to_string(),
        RelayConsultationInput::TargetAttribute(
            "request.target.attributes.person_sequence".to_string(),
        ),
    );

    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let evidence = Arc::new(evidence);
    let activated = Arc::new(TypedInputRelay::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];

    let mut single = test_request("enrollment-status");
    let single_target = single.target.as_mut().expect("single target exists");
    single_target
        .attributes
        .insert("include_inactive".to_string(), json!(true));
    single_target
        .attributes
        .insert("person_sequence".to_string(), json!(42));
    runtime
        .evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &principal,
            single,
            None,
        )
        .await
        .expect("single evaluation preserves typed target scalars");

    let mut batch = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    for (index, item) in batch.items.iter_mut().enumerate() {
        item.target
            .attributes
            .insert("include_inactive".to_string(), json!(index == 0));
        item.target
            .attributes
            .insert("person_sequence".to_string(), json!(index + 1));
    }
    runtime
        .batch_evaluate(
            evidence,
            &EvidenceStore::default(),
            &principal,
            batch,
            BatchEvaluateOptions {
                idempotency_key: Some("typed-target-attributes"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("batch evaluation preserves typed target scalars");

    assert_eq!(
        *activated
            .single_inputs
            .lock()
            .expect("single input lock is not poisoned"),
        vec![BTreeMap::from([
            ("include_inactive".to_string(), "true".to_string()),
            ("person_sequence".to_string(), "42".to_string()),
            ("tracked_entity".to_string(), "person-1".to_string()),
        ])]
    );
    let mut batch_inputs = activated
        .batch_inputs
        .lock()
        .expect("batch input lock is not poisoned")
        .clone();
    batch_inputs.sort_by(|left, right| left["person_sequence"].cmp(&right["person_sequence"]));
    assert_eq!(
        batch_inputs,
        vec![
            BTreeMap::from([
                ("include_inactive".to_string(), "true".to_string()),
                ("person_sequence".to_string(), "1".to_string()),
                ("tracked_entity".to_string(), "person-1".to_string()),
            ]),
            BTreeMap::from([
                ("include_inactive".to_string(), "false".to_string()),
                ("person_sequence".to_string(), "2".to_string()),
                ("tracked_entity".to_string(), "person-1".to_string()),
            ]),
        ]
    );
}

#[tokio::test]
async fn registry_batch_requires_outer_key_before_relay_work() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];

    let error = runtime
        .batch_evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            registry_batch_request(vec![ClaimRef::from("enrollment-status")]),
            BatchEvaluateOptions::default(),
        )
        .await
        .expect_err("registry batch without an outer idempotency key is rejected");

    assert!(matches!(error, EvidenceError::ConsultationInvalidRequest));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registry_batch_hard_ceiling_rejects_before_quota_idempotency_relay_or_state() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    // Bypass the config loader deliberately. The runtime ceiling must still be
    // authoritative if an EvidenceConfig is assembled directly in-process.
    claim.operations.batch_evaluate.max_subjects =
        registry_notary_core::MAX_BATCH_EVALUATION_MEMBERS_V1 + 1;
    let disabled_claim = registry_claim(
        "disabled-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let mut evidence = (*test_evidence(vec![claim, disabled_claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = registry_notary_core::MAX_BATCH_EVALUATION_MEMBERS_V1 + 1;
    let evidence = Arc::new(evidence);
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let store = EvidenceStore::default();
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let quota = crate::MachineQuotaLimiter::new(registry_notary_core::MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 1,
    });
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    request.items = vec![
        request.items[0].clone();
        registry_notary_core::MAX_BATCH_EVALUATION_MEMBERS_V1 + 1
    ];

    for claim in ["missing-claim", "disabled-status"] {
        let mut invalid_claim_request = request.clone();
        invalid_claim_request.claims = vec![ClaimRef::from(claim)];
        let error = runtime
            .batch_evaluate(
                Arc::clone(&evidence),
                &store,
                &principal,
                invalid_claim_request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("the hard ceiling precedes claim lookup and operation checks");
        assert!(matches!(error, EvidenceError::BatchTooLarge));
    }

    let error_without_key = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &store,
            &principal,
            request.clone(),
            BatchEvaluateOptions {
                owner_quota: Some((&quota, request.items.len() as u32)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect_err("the size rejection precedes registry idempotency-key validation");
    assert!(matches!(error_without_key, EvidenceError::BatchTooLarge));

    let error = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &store,
            &principal,
            request.clone(),
            BatchEvaluateOptions {
                idempotency_key: Some("hard-ceiling-key"),
                owner_quota: Some((&quota, request.items.len() as u32)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect_err("the platform ceiling cannot be raised by runtime config");

    assert!(matches!(error, EvidenceError::BatchTooLarge));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);

    request.items.truncate(1);
    let response = runtime
        .batch_evaluate(
            evidence,
            &store,
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("hard-ceiling-key"),
                owner_quota: Some((&quota, 1)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("rejection neither consumes quota nor binds the idempotency key");

    assert!(matches!(response.items[0].status, BatchItemStatus::Succeeded));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn registry_batch_effective_limit_uses_the_lowest_operator_override() {
    for (inline_limit, claim_limit) in [(2, 4), (4, 2)] {
        let mut claim = registry_claim(
            "enrollment-status",
            RuleConfig::ConsultationOutput {
                consultation: "enrollment".to_string(),
                output: "registration_status".to_string(),
            },
            "string",
        );
        enable_registry_batch(&mut claim);
        claim.operations.batch_evaluate.max_subjects = claim_limit;
        let mut evidence = (*test_evidence(vec![claim])).clone();
        evidence.allowed_purposes = vec!["test".to_string()];
        evidence.inline_batch_limit = inline_limit;
        let activated = Arc::new(FixedRelayConsultation {
            calls: AtomicU64::new(0),
            outcome: RuntimeRelayOutcome::Match,
        });
        let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
        let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
        let mut principal = machine_principal();
        principal.scopes = vec!["registry:evidence".to_string()];
        let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
        request.items.push(request.items[0].clone());

        let error = runtime
            .batch_evaluate(
                Arc::new(evidence),
                &EvidenceStore::default(),
                &principal,
                request,
                BatchEvaluateOptions::default(),
            )
            .await
            .expect_err("the lowest configured limit rejects three members");

        assert!(matches!(error, EvidenceError::BatchTooLarge));
        assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn registry_batch_preflights_every_item_before_first_relay_call() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    request.items[1].target = EvidenceEntity::new("Person");

    let error = runtime
        .batch_evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("batch-key"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect_err("an invalid later item fails the whole pure preflight");

    assert!(matches!(error, EvidenceError::InvalidRequest));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registry_batch_rejects_more_than_256_aggregate_groups_before_dispatch() {
    let mut claims = Vec::new();
    let mut claim_refs = Vec::new();
    for index in 0..16 {
        let claim_id = format!("grouped-claim-{index}");
        let mut claim = registry_claim(
            &claim_id,
            RuleConfig::ConsultationOutput {
                consultation: "enrollment".to_string(),
                output: "registration_status".to_string(),
            },
            "string",
        );
        enable_registry_batch(&mut claim);
        claim.operations.batch_evaluate.max_subjects = 17;
        let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
            panic!("claim is registry backed")
        };
        consultations
            .get_mut("enrollment")
            .expect("consultation exists")
            .profile
            .id = format!("test.batch.profile-{index}");
        claim_refs.push(ClaimRef::from(claim_id.as_str()));
        claims.push(claim);
    }
    let mut evidence = (*test_evidence(claims)).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 17;
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(claim_refs);
    request.items = vec![request.items[0].clone(); 17];

    let error = runtime
        .batch_evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("too-many-aggregate-groups"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect_err("17 items with 16 groups each exceed the aggregate bound");

    assert!(matches!(error, EvidenceError::ConsultationInvalidRequest));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registry_batch_returns_ordered_mixed_member_outcomes_after_admission() {
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let activated = Arc::new(MixedCompletionRelay {
        calls: AtomicU64::new(0),
        failed_target: "person-2",
        error: crate::relay_client::RelayClientError::TransportUnavailable,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    request.items[1] = registry_notary_core::BatchEvaluateItemRequest::from(
        registry_notary_core::BatchSubjectRequest {
            id: "person-2".to_string(),
            id_type: None,
            purpose: None,
        },
    );

    let response = runtime
        .batch_evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("mixed-completion-key"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("admitted member failures stay in the ordered response");

    assert_eq!(activated.calls.load(Ordering::SeqCst), 2);
    assert_eq!(response.summary.succeeded, 1);
    assert_eq!(response.summary.failed, 1);
    assert_eq!(response.items[0].input_index, 0);
    assert!(matches!(
        response.items[0].status,
        BatchItemStatus::Succeeded
    ));
    assert_eq!(response.items[1].input_index, 1);
    assert!(matches!(
        response.items[1].status,
        BatchItemStatus::Failed
    ));
    assert_eq!(response.items[1].errors.len(), 1);
    assert_eq!(response.items[1].errors[0].code, "evidence.not_available");
    assert!(response.items[1].claim_results.is_empty());
    assert_eq!(
        response.items[1].runtime_audit.relay_forwarded_count,
        1
    );
    assert!(response.items[1]
        .runtime_audit
        .relay_consultation_ids
        .is_empty());
}

async fn assert_registry_batch_mixed_closed_failure(
    failed_target: &'static str,
    relay_error: crate::relay_client::RelayClientError,
    idempotency_key: &'static str,
) {
    let evidence = enrollment_status_batch_evidence();
    let activated = Arc::new(MixedCompletionRelay {
        calls: AtomicU64::new(0),
        failed_target,
        error: relay_error,
    });
    let runtime = runtime_with_test_relay(Arc::clone(&activated));
    let principal = registry_evidence_principal();
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    request.items[1] = registry_notary_core::BatchEvaluateItemRequest::from(
        registry_notary_core::BatchSubjectRequest {
            id: failed_target.to_string(),
            id_type: None,
            purpose: None,
        },
    );

    let response = runtime
        .batch_evaluate(
            evidence,
            &EvidenceStore::default(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some(idempotency_key),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("an admitted Relay failure remains a member-level outcome");

    assert_eq!(activated.calls.load(Ordering::SeqCst), 2);
    assert_eq!(response.summary.succeeded, 1);
    assert_eq!(response.summary.failed, 1);
    assert_eq!(response.items[0].input_index, 0);
    assert!(matches!(
        response.items[0].status,
        BatchItemStatus::Succeeded
    ));
    assert_eq!(response.items[1].input_index, 1);
    assert!(matches!(
        response.items[1].status,
        BatchItemStatus::Failed
    ));
    assert_eq!(response.items[1].errors.len(), 1);
    assert_eq!(response.items[1].errors[0].code, "evidence.not_available");
    assert_eq!(
        response.items[1].errors[0].audit_code.as_deref(),
        Some("evidence.not_available")
    );
    assert!(!response.items[1].errors[0].retryable);
    assert!(response.items[1].claim_results.is_empty());
    assert_eq!(
        response.items[1].runtime_audit.relay_forwarded_count,
        1
    );
    assert!(response.items[1]
        .runtime_audit
        .relay_consultation_ids
        .is_empty());

    let public_response = serde_json::to_string(&response).expect("batch response serializes");
    assert!(!public_response.contains(failed_target));
    assert!(!public_response.contains("runtime_audit"));
}

#[tokio::test]
async fn registry_batch_preserves_mixed_policy_denial_as_ordered_value_free_item_error() {
    assert_registry_batch_mixed_closed_failure(
        "person-policy-denied",
        crate::relay_client::RelayClientError::Denied,
        "mixed-policy-denial-key",
    )
    .await;
}

#[tokio::test]
async fn registry_batch_preserves_mixed_relay_timeout_as_ordered_value_free_item_error() {
    assert_registry_batch_mixed_closed_failure(
        "person-relay-timeout",
        crate::relay_client::RelayClientError::TransportUnavailable,
        "mixed-relay-timeout-key",
    )
    .await;
}

#[tokio::test]
async fn single_and_batch_equivalence_matrix_pins_security_and_disclosure_surfaces() {
    let evidence = enrollment_status_batch_evidence();
    let authorization_relay = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let authorization_runtime = runtime_with_test_relay(Arc::clone(&authorization_relay));
    let unauthorized_principal = machine_principal();
    let single_authorization = authorization_runtime
        .evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &unauthorized_principal,
            test_request("enrollment-status"),
            None,
        )
        .await;
    let mut authorization_batch =
        registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    authorization_batch.items.truncate(1);
    let batch_authorization = authorization_runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &unauthorized_principal,
            authorization_batch,
            BatchEvaluateOptions {
                idempotency_key: Some("equivalence-authorization"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await;
    let authorization_equivalent = matches!(
        single_authorization,
        Err(EvidenceError::ScopeDenied { required }) if required == "registry:evidence"
    ) && matches!(
        batch_authorization,
        Err(EvidenceError::ScopeDenied { required }) if required == "registry:evidence"
    ) && authorization_relay.calls.load(Ordering::SeqCst) == 0;

    // Consent and policy enforcement remain Relay-owned. Notary must preserve
    // the same closed denial boundary in single and batch transport shapes.
    let consent_relay = Arc::new(MixedCompletionRelay {
        calls: AtomicU64::new(0),
        failed_target: "person-1",
        error: crate::relay_client::RelayClientError::Denied,
    });
    let consent_runtime = runtime_with_test_relay(Arc::clone(&consent_relay));
    let authorized_principal = registry_evidence_principal();
    let (single_consent, single_consent_audit) = consent_runtime
        .evaluate_for_api(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &authorized_principal,
            test_request("enrollment-status"),
            None,
        )
        .await;
    let mut consent_batch = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    consent_batch.items.truncate(1);
    let batch_consent = consent_runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &authorized_principal,
            consent_batch,
            BatchEvaluateOptions {
                idempotency_key: Some("equivalence-consent"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("Relay policy or consent denial is a closed batch member outcome");
    let consent_equivalent = matches!(
        single_consent,
        Err(EvidenceError::EvidenceNotAvailable)
    ) && matches!(batch_consent.items[0].status, BatchItemStatus::Failed)
        && batch_consent.items[0].errors[0].code == "evidence.not_available"
        && single_consent_audit.relay_forwarded_count() == 1
        && batch_consent.items[0]
            .runtime_audit
            .relay_forwarded_count
            == 1
        && consent_relay.calls.load(Ordering::SeqCst) == 2;

    let success_relay = Arc::new(UniqueRelayConsultation::default());
    let success_runtime = runtime_with_test_relay(Arc::clone(&success_relay));
    let (single_result, single_audit) = success_runtime
        .evaluate_for_api(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &authorized_principal,
            test_request("enrollment-status"),
            None,
        )
        .await;
    let single_result = single_result.expect("single evaluation succeeds");
    let mut success_batch = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    success_batch.items.truncate(1);
    let batch_result = success_runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &authorized_principal,
            success_batch,
            BatchEvaluateOptions {
                idempotency_key: Some("equivalence-success"),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("batch evaluation succeeds");
    let single_claim = &single_result[0];
    let batch_claim = &batch_result.items[0].claim_results[0];

    let mut single_provenance =
        serde_json::to_value(&single_claim.provenance).expect("single provenance serializes");
    let mut batch_provenance =
        serde_json::to_value(&batch_claim.provenance).expect("batch provenance serializes");
    single_provenance["generated_by"]
        .as_object_mut()
        .expect("single generated_by is an object")
        .remove("evaluation_id");
    batch_provenance["generated_by"]
        .as_object_mut()
        .expect("batch generated_by is an object")
        .remove("evaluation_id");
    let provenance_equivalent = single_provenance == batch_provenance
        && single_claim.provenance.used.relay_consultation_count == 1
        && batch_claim.provenance.used.relay_consultation_count == 1;

    let public_single =
        serde_json::to_string(&single_result).expect("single response serializes");
    let public_batch = serde_json::to_string(&batch_result).expect("batch response serializes");
    let minimization_equivalent = single_claim.value == batch_claim.value
        && single_claim.satisfied == batch_claim.satisfied
        && single_claim.disclosure == batch_claim.disclosure
        && !public_single.contains("person-1")
        && !public_single.contains("tracked_entity")
        && !public_batch.contains("person-1")
        && !public_batch.contains("tracked_entity")
        && !public_batch.contains("runtime_audit")
        && !public_batch.contains("relay_consultation_ids");

    let single_forwarded_count = single_audit.relay_forwarded_count();
    let (_, single_consultation_ids) = single_audit.into_parts();
    let batch_runtime_audit = &batch_result.items[0].runtime_audit;
    let audit_equivalent = single_forwarded_count == 1
        && single_consultation_ids.len() == 1
        && batch_runtime_audit.relay_consultation_ids.len() == 1
        && batch_runtime_audit.relay_forwarded_count == 1
        && success_relay.calls.load(Ordering::SeqCst) == 2;

    let equivalence_matrix = BTreeMap::from([
        ("authorization", authorization_equivalent),
        ("consent", consent_equivalent),
        ("provenance", provenance_equivalent),
        ("minimization", minimization_equivalent),
        ("audit", audit_equivalent),
    ]);
    assert!(
        equivalence_matrix.values().all(|equivalent| *equivalent),
        "single/batch equivalence matrix failed: {equivalence_matrix:?}"
    );
}

#[tokio::test]
async fn registry_batch_quota_denial_does_not_bind_a_fresh_idempotency_key() {
    let mut claim = registry_claim(
        "enrollment-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let evidence = Arc::new(evidence);
    let activated = Arc::new(BatchIdentityRelay::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let store = EvidenceStore::default();
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-known")]);
    request.items.truncate(1);
    let exhausted_quota = crate::MachineQuotaLimiter::new(
        registry_notary_core::MachineQuotaConfig {
            enabled: true,
            subjects_per_minute: 1,
        },
    );
    exhausted_quota
        .check_and_consume(&principal.principal_id, 1)
        .await
        .unwrap();

    assert!(matches!(
        runtime
            .batch_evaluate(
                Arc::clone(&evidence),
                &store,
                &principal,
                request.clone(),
                BatchEvaluateOptions {
                    idempotency_key: Some("quota-denied-key"),
                    owner_quota: Some((&exhausted_quota, 1)),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await,
        Err(EvidenceError::MachineQuotaExceeded { .. })
    ));

    let disabled_quota = crate::MachineQuotaLimiter::new(
        registry_notary_core::MachineQuotaConfig {
            enabled: false,
            subjects_per_minute: 1,
        },
    );
    let mut changed_scope_principal = principal;
    changed_scope_principal
        .scopes
        .push("registry:catalog".to_string());
    let retry = runtime
        .batch_evaluate(
            evidence,
            &store,
            &changed_scope_principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("quota-denied-key"),
                owner_quota: Some((&disabled_quota, 1)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("an uncharged quota denial does not bind the idempotency key");

    assert!(matches!(retry.items[0].status, BatchItemStatus::Succeeded));
    assert_eq!(
        activated
            .child_identities
            .lock()
            .expect("child identity lock is not poisoned")
            .len(),
        1
    );
}

#[tokio::test]
async fn registry_batch_disabled_quota_accepts_an_unbounded_oidc_subject() {
    let mut claim = registry_claim(
        "enrollment-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let activated = Arc::new(BatchIdentityRelay::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.auth_profile_id = registry_notary_core::EvidenceAuthProfileId::ExternalOidc;
    principal.principal_id = "s".repeat(129);
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-known")]);
    request.items.truncate(1);
    let disabled_quota = crate::MachineQuotaLimiter::new(
        registry_notary_core::MachineQuotaConfig {
            enabled: false,
            subjects_per_minute: 1,
        },
    );

    let response = runtime
        .batch_evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("disabled-quota-key"),
                owner_quota: Some((&disabled_quota, u32::MAX)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("disabled quota performs no principal validation or quota hashing");

    assert!(matches!(response.items[0].status, BatchItemStatus::Succeeded));
    assert_eq!(
        activated
            .child_identities
            .lock()
            .expect("child identity lock is not poisoned")
            .len(),
        1
    );
}

#[tokio::test]
async fn registry_batch_coalesces_within_items_never_across_duplicates_and_replays_outer_key() {
    let mut exists = registry_claim(
        "enrollment-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let mut extract = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut exists);
    enable_registry_batch(&mut extract);
    let mut evidence = (*test_evidence(vec![exists, extract])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let evidence = Arc::new(evidence);
    let activated = Arc::new(BatchIdentityRelay::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let store = EvidenceStore::default();
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let request = registry_batch_request(vec![
        ClaimRef::from("enrollment-known"),
        ClaimRef::from("enrollment-status"),
    ]);
    let quota = crate::MachineQuotaLimiter::new(registry_notary_core::MachineQuotaConfig {
        enabled: true,
        subjects_per_minute: 2,
    });
    let options = BatchEvaluateOptions {
        idempotency_key: Some("batch-key"),
        owner_quota: Some((&quota, 2)),
        ..BatchEvaluateOptions::default()
    };

    let first = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &store,
            &principal,
            request.clone(),
            options,
        )
        .await
        .expect("duplicate subjects complete independently");
    assert_eq!(first.items.len(), 2);
    assert!(first
        .items
        .iter()
        .all(|item| matches!(item.status, BatchItemStatus::Succeeded)));
    assert!(first.items.iter().all(|item| {
        item.runtime_audit.relay_forwarded_count == 1
            && item.runtime_audit.relay_consultation_ids.len() == 1
    }));
    let public_response = serde_json::to_string(&first).expect("batch response serializes");
    assert!(!public_response.contains("runtime_audit"));
    assert!(!first.items[0]
        .runtime_audit
        .relay_consultation_ids
        .iter()
        .any(|id| public_response.contains(id)));
    assert_ne!(first.items[0].evaluation_id, first.items[1].evaluation_id);
    for item in &first.items {
        let evaluation_id = item
            .evaluation_id
            .as_deref()
            .expect("successful registry batch item has an evaluation id");
        let stored = store
            .get(evaluation_id, &principal.principal_id)
            .await
            .expect("batch evaluation store read succeeds")
            .expect("batch evaluation is stored");
        let stored_at = OffsetDateTime::parse(&stored.created_at, &Rfc3339)
            .expect("stored_at is canonical RFC3339");
        let expires_at = OffsetDateTime::parse(&stored.expires_at, &Rfc3339)
            .expect("expires_at is canonical RFC3339");
        assert_eq!(
            expires_at - stored_at,
            time::Duration::minutes(15),
            "registry batch retention starts when Notary stores the evaluation"
        );
        assert_ne!(
            stored.created_at, "1970-01-01T00:00:00Z",
            "Relay acquisition time must not become Notary storage time"
        );
        assert!(
            stored.issuance_provenance.is_none(),
            "evaluation-only registry batch claims must not retain private Relay identifiers"
        );
    }
    let first_children = activated
        .child_identities
        .lock()
        .expect("child identity lock is not poisoned")
        .clone();
    assert_eq!(first_children.len(), 2);
    assert_ne!(first_children[0], first_children[1]);

    assert!(matches!(
        runtime
            .batch_evaluate(
                Arc::clone(&evidence),
                &store,
                &principal,
                request.clone(),
                BatchEvaluateOptions {
                    idempotency_key: Some("new-batch-key"),
                    owner_quota: Some((&quota, 2)),
                    ..BatchEvaluateOptions::default()
                },
            )
            .await,
        Err(EvidenceError::MachineQuotaExceeded { .. })
    ));

    let replay = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            &store,
            &principal,
            request.clone(),
            options,
        )
        .await
        .expect("the exact outer-key replay returns the stored response");
    assert_eq!(replay.batch_id, first.batch_id);
    assert!(replay.items.iter().all(|item| {
        item.runtime_audit.relay_forwarded_count == 0
            && item.runtime_audit.relay_consultation_ids.is_empty()
    }));
    assert_eq!(
        activated
            .child_identities
            .lock()
            .expect("child identity lock is not poisoned")
            .len(),
        2
    );

    let mut changed_scope_principal = principal.clone();
    changed_scope_principal
        .scopes
        .push("registry:catalog".to_string());
    assert!(matches!(
        runtime
            .batch_evaluate(
                Arc::clone(&evidence),
                &store,
                &changed_scope_principal,
                request.clone(),
                options,
            )
            .await,
        Err(EvidenceError::IdempotencyConflict)
    ));

    let mut changed_config = (*evidence).clone();
    changed_config.concurrency.subjects = changed_config.concurrency.subjects.saturating_add(1);
    assert!(matches!(
        runtime
            .batch_evaluate(
                Arc::new(changed_config),
                &store,
                &principal,
                request,
                options,
            )
            .await,
        Err(EvidenceError::IdempotencyConflict)
    ));
}

#[tokio::test]
async fn registry_batch_retry_after_ambiguous_dispatch_reuses_identity_and_quota_charge()
{
    let mut claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    enable_registry_batch(&mut claim);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    evidence.inline_batch_limit = 4;
    let evidence = Arc::new(evidence);
    let activated = Arc::new(CrashRetryBatchRelay::default());
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let store = Arc::new(EvidenceStore::default());
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = registry_batch_request(vec![ClaimRef::from("enrollment-status")]);
    request.items.truncate(1);
    let quota = Arc::new(crate::MachineQuotaLimiter::new(
        registry_notary_core::MachineQuotaConfig {
            enabled: true,
            subjects_per_minute: 1,
        },
    ));

    let first = {
        let runtime = runtime.clone();
        let evidence = Arc::clone(&evidence);
        let store = Arc::clone(&store);
        let principal = principal.clone();
        let request = request.clone();
        let quota = Arc::clone(&quota);
        tokio::spawn(async move {
            runtime
                .batch_evaluate(
                    evidence,
                    store.as_ref(),
                    &principal,
                    request,
                    BatchEvaluateOptions {
                        idempotency_key: Some("crash-retry-key"),
                        owner_quota: Some((quota.as_ref(), 1)),
                        ..BatchEvaluateOptions::default()
                    },
                )
                .await
        })
    };
    activated.first_dispatch.notified().await;
    first.abort();
    assert!(first
        .await
        .expect_err("first owner is cancelled")
        .is_cancelled());

    let retry = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            store.as_ref(),
            &principal,
            request.clone(),
            BatchEvaluateOptions {
                idempotency_key: Some("crash-retry-key"),
                owner_quota: Some((quota.as_ref(), 1)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("same outer request takes over after the ambiguous dispatch");
    assert!(matches!(retry.items[0].status, BatchItemStatus::Succeeded));

    let observations = activated
        .observations
        .lock()
        .expect("retry observation lock is not poisoned")
        .clone();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].0, observations[1].0);
    assert_ne!(observations[0].1, observations[1].1);
    assert!(observations
        .iter()
        .all(|(_, evaluation_id)| Ulid::from_string(evaluation_id).is_ok()));
    assert_eq!(
        retry.items[0].evaluation_id.as_deref(),
        Some(observations[1].1.as_str())
    );

    let replay = runtime
        .batch_evaluate(
            Arc::clone(&evidence),
            store.as_ref(),
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("crash-retry-key"),
                owner_quota: Some((quota.as_ref(), 1)),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("completed outer request replays without another child dispatch");
    assert_eq!(replay.batch_id, retry.batch_id);
    assert_eq!(replay.items[0].evaluation_id, retry.items[0].evaluation_id);
    assert_eq!(activated.attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn registry_backed_consultation_reads_a_named_target_identifier() {
    let mut claim = registry_claim(
        "birth-record-known",
        RuleConfig::ConsultationMatched {
            consultation: "enrollment".to_string(),
        },
        "boolean",
    );
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut claim.evidence_mode else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("enrollment")
        .expect("consultation")
        .inputs = BTreeMap::from([(
        "uin".to_string(),
        RelayConsultationInput::TargetIdentifier("request.target.identifiers.UIN".to_string()),
    )]);
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = test_request("birth-record-known");
    request.target = Some(registry_notary_core::EvidenceEntity::with_identifier(
        "Person",
        "UIN",
        "1234567890",
    ));

    let results = runtime
        .evaluate(
            Arc::new(evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await
        .expect("named target identifier plans the consultation");

    assert_eq!(results[0].value, Some(Value::Bool(true)));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn registry_backed_profiles_enforce_purpose_and_scope_independently() {
    let mut first = registry_claim(
        "programme-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    first.purpose = Some("programme-verification".to_string());
    first.required_scopes = vec!["registry:programme".to_string()];
    let mut second = registry_claim(
        "civil-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    second.purpose = Some("civil-verification".to_string());
    second.required_scopes = vec!["registry:civil".to_string()];
    let ClaimEvidenceMode::RegistryBacked { consultations } = &mut second.evidence_mode else {
        panic!("registry-backed mode")
    };
    consultations
        .get_mut("enrollment")
        .expect("consultation")
        .profile
        .id = "opencrvs.birth-record.exact".to_string();
    let mut evidence = (*test_evidence(vec![first, second])).clone();
    evidence.allowed_purposes = vec![
        "programme-verification".to_string(),
        "civil-verification".to_string(),
    ];
    let evidence = Arc::new(evidence);
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));
    let mut principal = machine_principal();
    principal.scopes = vec!["registry:programme".to_string()];
    let mut request = test_request("programme-status");
    request.purpose = Some("programme-verification".to_string());

    runtime
        .evaluate(
            Arc::clone(&evidence),
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await
        .expect("the independently authorized profile evaluates");
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);

    let mut denied = test_request("civil-status");
    denied.purpose = Some("civil-verification".to_string());
    let error = runtime
        .evaluate(
            evidence,
            &EvidenceStore::default(),
            &principal,
            denied,
            None,
        )
        .await
        .expect_err("the other profile's scope is not inherited");

    assert!(matches!(error, EvidenceError::ScopeDenied { .. }));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_group_key_ignores_unrelated_principal_scopes() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
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
            &EvidenceStore::default(),
            &principal,
            test_request("enrollment-status"),
            None,
        )
        .await
        .expect("unrelated principal scopes do not widen the consultation key");

    assert_eq!(results[0].value, Some(Value::String("ACTIVE".to_string())));
    assert_eq!(activated.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn relay_plan_uses_the_explicitly_selected_claim_version() {
    let mut transitional = test_claim("enrollment-status", Vec::new(), false);
    transitional.version = "1".to_string();
    let mut registry = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    registry.version = "2".to_string();
    let mut evidence = (*test_evidence(vec![transitional, registry])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
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
}

#[tokio::test]
async fn registry_backed_preflight_denial_makes_zero_relay_calls() {
    let claim = registry_claim(
        "enrollment-status",
        RuleConfig::ConsultationOutput {
            consultation: "enrollment".to_string(),
            output: "registration_status".to_string(),
        },
        "string",
    );
    let mut evidence = (*test_evidence(vec![claim])).clone();
    evidence.allowed_purposes = vec!["test".to_string()];
    let activated = Arc::new(FixedRelayConsultation {
        calls: AtomicU64::new(0),
        outcome: RuntimeRelayOutcome::Match,
    });
    let bound: Arc<dyn ActivatedRelayConsultations> = activated.clone();
    let runtime = RegistryNotaryRuntime::new().with_activated_relay(Some(bound));

    let evidence = Arc::new(evidence);
    let (result, audit) = runtime
        .evaluate_for_api(
            Arc::clone(&evidence),
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

    let mut principal = machine_principal();
    principal.scopes = vec!["registry:evidence".to_string()];
    let mut request = test_request("enrollment-status");
    request.purpose = Some("wrong-purpose".to_string());
    let (result, audit) = runtime
        .evaluate_for_api(
            evidence,
            &EvidenceStore::default(),
            &principal,
            request,
            None,
        )
        .await;
    assert!(matches!(result, Err(EvidenceError::PurposeNotAllowed)));
    let (evaluation_id, consultation_ids) = audit.into_parts();
    assert!(evaluation_id.is_none());
    assert!(consultation_ids.is_empty());
    assert_eq!(activated.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn evaluate_refuses_consultation_matched_result_with_wrong_value_type() {
    let mut claim = test_claim("selected", Vec::new(), true);
    claim.rule = RuleConfig::ConsultationMatched {
        consultation: "src".to_string(),
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
}

#[tokio::test]
async fn evaluate_target_ref_serializes_as_opaque_handle() {
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
            &store,
            &machine_principal(),
            request,
            None,
        )
        .await
        .expect("evaluate succeeds");
    let target_ref = serde_json::to_value(&results[0].target_ref).expect("target_ref serializes");

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
    let mut claim = test_claim("selected", Vec::new(), true);
    claim.operations.batch_evaluate.enabled = true;
    claim.operations.batch_evaluate.max_subjects = 1;
    let mut evidence_config = (*test_evidence(vec![claim])).clone();
    evidence_config.inline_batch_limit = 1;
    let evidence = Arc::new(evidence_config);
    let store = EvidenceStore::default();
    let principal = machine_principal();
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
            &store,
            &principal,
            request,
            BatchEvaluateOptions {
                idempotency_key: Some("retained-batch"),
                ..BatchEvaluateOptions::default()
            },
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
    let evaluation_id = response.items[0]
        .evaluation_id
        .as_deref()
        .expect("successful item has an evaluation id");
    let stored = store
        .get(evaluation_id, &principal.principal_id)
        .await
        .expect("completed batch evaluation read succeeds")
        .expect("completed source-free batch evaluation is retained");
    assert!(stored.issuance_provenance.is_none());
    let stored_at = OffsetDateTime::parse(&stored.created_at, &Rfc3339)
        .expect("stored_at is canonical RFC3339");
    let expires_at = OffsetDateTime::parse(&stored.expires_at, &Rfc3339)
        .expect("expires_at is canonical RFC3339");
    assert_eq!(expires_at - stored_at, time::Duration::minutes(15));
}

#[tokio::test]
async fn evaluate_uses_requested_claim_version() {
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
            &store,
            &machine_principal(),
            request,
            None,
        )
        .await
        .expect("versioned evaluate succeeds");

    assert_eq!(results[0].claim_version, "2.0");
}

/// REQ-SEC-G-005: the direct `evaluate` path must refuse a principal that
/// lacks a claim's required scope.
#[tokio::test]
async fn evaluate_denies_missing_scope() {
    let mut claim = test_claim("selected", Vec::new(), true);
    claim.required_scopes = vec!["selected:1.0".to_string()];
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
}

#[tokio::test]
async fn evaluate_authorizes_required_scope_from_requested_claim_version() {
    let mut older_claim = test_claim("selected", Vec::new(), true);
    older_claim.required_scopes = vec!["selected:1.0".to_string()];
    let mut newer_claim = test_claim("selected", Vec::new(), true);
    newer_claim.version = "2.0".to_string();
    newer_claim.required_scopes = vec!["selected:2.0".to_string()];
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

    let principal = EvidencePrincipal {
        scopes: vec!["selected:2.0".to_string()],
        ..principal
    };
    let results = RegistryNotaryRuntime::new()
        .evaluate(
            evidence,
            &store,
            &principal,
            request,
            None,
        )
        .await
        .expect("version 2 scope authorizes version 2");

    assert_eq!(results[0].claim_version, "2.0");
}

#[tokio::test]
async fn evaluate_rejects_missing_claim_version() {
    let evidence = test_evidence(vec![test_claim("selected", Vec::new(), true)]);
    let store = EvidenceStore::default();
    let mut request = test_request("selected");
    request.claims = vec![ClaimRef::with_version("selected", "2.0")];

    let err = RegistryNotaryRuntime::new()
        .evaluate(
            evidence,
            &store,
            &machine_principal(),
            request,
            None,
        )
        .await
        .expect_err("unknown version is rejected");

    assert!(matches!(err, EvidenceError::ClaimVersionNotFound));
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
