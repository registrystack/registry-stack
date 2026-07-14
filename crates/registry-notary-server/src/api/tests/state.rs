// SPDX-License-Identifier: Apache-2.0
//! State API tests.

use super::*;

#[derive(Debug)]
struct ReadinessRelay {
    calls: AtomicUsize,
    ready: AtomicBool,
}

impl ReadinessRelay {
    fn new(ready: bool) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            ready: AtomicBool::new(ready),
        }
    }
}

#[async_trait::async_trait]
impl crate::runtime::ActivatedRelayConsultations for ReadinessRelay {
    async fn check_ready(&self) -> Result<(), crate::relay_client::RelayClientError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(crate::relay_client::RelayClientError::Unavailable)
        }
    }

    fn validate(
        &self,
        _key: &crate::runtime::consultation::ConsultationGroupKeyV1,
    ) -> Result<(), crate::relay_client::RelayClientError> {
        Ok(())
    }

    async fn execute(
        &self,
        _key: &crate::runtime::ConsultationGroupKeyV1,
    ) -> Result<crate::runtime::RuntimeRelayConsultationResult, crate::relay_client::RelayClientError>
    {
        Err(crate::relay_client::RelayClientError::InvalidRequest)
    }
}

fn relay_readiness_state() -> RegistryNotaryApiState {
    let mut evidence = evidence_config();
    evidence.claims[0].evidence_mode = registry_notary_core::ClaimEvidenceMode::RegistryBacked {
        consultations: BTreeMap::new(),
    };
    RegistryNotaryApiState::new(
        Arc::new(evidence),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    )
}

#[tokio::test]
async fn source_free_state_does_not_require_relay_readiness() {
    let state = RegistryNotaryApiState::new(
        Arc::new(evidence_config()),
        AuditKeyHasher::unkeyed_dev_only(),
        Arc::new(EvidenceStore::default()),
        Arc::new(NoopIssuerResolver),
    );

    assert!(!state.relay_required());
    assert!(!state.relay_activated());
    assert!(state.relay_ready().await);
}

#[tokio::test]
async fn registry_backed_state_is_not_ready_before_relay_activation() {
    let state = Arc::new(relay_readiness_state());

    assert!(state.relay_required());
    assert!(!state.relay_activated());
    assert!(!state.relay_ready().await);

    let response = ready(Some(Extension(state))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("ready body reads");
    let value: Value = serde_json::from_slice(&body).expect("ready body is JSON");
    assert_eq!(value["checks"]["total"], json!(2));
    assert_eq!(value["checks"]["ok"], json!(0));
    assert_eq!(value["checks"]["degraded"], json!(1));
    assert_eq!(value["checks"]["failed"], json!(1));
    assert_eq!(value["checks"]["relay"]["total"], json!(1));
    assert_eq!(value["checks"]["relay"]["ok"], json!(0));
    assert_eq!(value["checks"]["relay"]["failed"], json!(1));
}

#[tokio::test]
async fn relay_readiness_is_singleflight_cached_and_recovers() {
    let state = Arc::new(relay_readiness_state());
    let relay = Arc::new(ReadinessRelay::new(false));
    let activated: Arc<dyn crate::runtime::ActivatedRelayConsultations> = relay.clone();
    state
        .install_activated_relay(activated)
        .expect("Relay activation succeeds once");

    let (first, second, third) = tokio::join!(
        state.relay_ready(),
        state.relay_ready(),
        state.relay_ready()
    );
    assert!(!first && !second && !third);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);

    relay.ready.store(true, Ordering::SeqCst);
    assert!(!state.relay_ready().await, "failure is briefly cached");
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);

    state.expire_relay_readiness_cache().await;
    assert!(state.relay_ready().await);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn readiness_reports_each_relay_profile_without_hiding_partial_availability() {
    let state = Arc::new(relay_readiness_state());
    let ready_profile: Arc<dyn crate::runtime::ActivatedRelayConsultations> =
        Arc::new(ReadinessRelay::new(true));
    let unavailable: Arc<dyn crate::runtime::ActivatedRelayConsultations> =
        Arc::new(ReadinessRelay::new(false));
    let contract_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let expected_result = || {
        crate::runtime::RuntimeRelayExpectedResult::output_map(BTreeMap::from([(
            "status".to_string(),
            registry_notary_core::RelayOutputContract::String {
                nullable: false,
                max_bytes: 64,
            },
        )]))
        .expect("output contract is valid")
    };
    let clients = crate::runtime::ActivatedRelayClientSet::new([
        (
            crate::runtime::RelayClientSelectionV1::new(
                "example.live-status.exact",
                contract_hash,
                "benefit-verification",
                "subject_id",
                expected_result(),
            )
            .expect("ready profile selection is valid"),
            ready_profile,
        ),
        (
            crate::runtime::RelayClientSelectionV1::new(
                "example.snapshot-status.exact",
                contract_hash,
                "benefit-verification",
                "subject_id",
                expected_result(),
            )
            .expect("unavailable profile selection is valid"),
            unavailable,
        ),
    ])
    .expect("both exact profile selections are retained");
    state
        .install_activated_relay(Arc::new(clients))
        .expect("Relay activation succeeds once");

    let response = ready(Some(Extension(state))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("ready body reads");
    let value: Value = serde_json::from_slice(&body).expect("ready body is JSON");

    assert_eq!(value["checks"]["relay"]["total"], json!(2));
    assert_eq!(value["checks"]["relay"]["ok"], json!(1));
    assert_eq!(value["checks"]["relay"]["failed"], json!(1));
    assert_eq!(value["checks"]["total"], json!(3));
    assert_eq!(value["checks"]["ok"], json!(1));
    assert_eq!(value["checks"]["failed"], json!(1));
}

#[test]
fn runtime_snapshot_read_never_observes_torn_issuer_federation_generation() {
    let old_issuers: Arc<dyn EvidenceIssuerResolver> = Arc::new(NoopIssuerResolver);
    let new_issuers: Arc<dyn EvidenceIssuerResolver> = Arc::new(TestIssuerResolver);
    let old_federation = test_federation_runtime("old");
    let new_federation = test_federation_runtime("new");
    let old_snapshot = Arc::new(ApiRuntimeSnapshot {
        federation_runtime: Some(Arc::clone(&old_federation)),
        issuer_runtime: Arc::new(IssuerRuntimeBundle {
            issuers: Arc::clone(&old_issuers),
            signer_readiness: SignerReadiness::default(),
        }),
        config_governance: ConfigGovernanceContext::default(),
        runtime_config: None,
        preauth: None,
    });
    let new_snapshot = Arc::new(ApiRuntimeSnapshot {
        federation_runtime: Some(Arc::clone(&new_federation)),
        issuer_runtime: Arc::new(IssuerRuntimeBundle {
            issuers: Arc::clone(&new_issuers),
            signer_readiness: SignerReadiness::default(),
        }),
        config_governance: ConfigGovernanceContext::default(),
        runtime_config: None,
        preauth: None,
    });
    let state = Arc::new(RegistryNotaryApiState::new_with_runtime_blocks(
        Arc::new(EvidenceConfig::default()),
        Arc::new(SelfAttestationConfig::default()),
        Arc::new(Oid4vciConfig::default()),
        Arc::new(FederationConfig::default()),
        Some(Arc::clone(&old_federation)),
        AuditKeyHasher::unkeyed_dev_only(),
        ReplayStores::memory(),
        CredentialStatusStore::disabled(),
        Arc::new(AppMetrics::default()),
        Arc::new(EvidenceStore::default()),
        Arc::clone(&old_issuers),
        SignerReadiness::default(),
    ));
    state.publish_runtime_snapshot(Arc::clone(&old_snapshot));

    let worker_count = 8;
    let start = Arc::new(Barrier::new(worker_count + 1));
    let done = Arc::new(AtomicBool::new(false));
    let torn = Arc::new(AtomicBool::new(false));
    let observed_old = Arc::new(AtomicBool::new(false));
    let observed_new = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let state = Arc::clone(&state);
        let start = Arc::clone(&start);
        let done = Arc::clone(&done);
        let torn = Arc::clone(&torn);
        let observed_old = Arc::clone(&observed_old);
        let observed_new = Arc::clone(&observed_new);
        let old_issuers = Arc::clone(&old_issuers);
        let new_issuers = Arc::clone(&new_issuers);
        let old_federation = Arc::clone(&old_federation);
        let new_federation = Arc::clone(&new_federation);
        workers.push(thread::spawn(move || {
            start.wait();
            while !done.load(Ordering::SeqCst) {
                let snapshot = state.runtime_snapshot();
                let issuer_is_old = Arc::ptr_eq(&snapshot.issuer_runtime.issuers, &old_issuers);
                let issuer_is_new = Arc::ptr_eq(&snapshot.issuer_runtime.issuers, &new_issuers);
                let federation_is_old = snapshot
                    .federation_runtime
                    .as_ref()
                    .is_some_and(|runtime| Arc::ptr_eq(runtime, &old_federation));
                let federation_is_new = snapshot
                    .federation_runtime
                    .as_ref()
                    .is_some_and(|runtime| Arc::ptr_eq(runtime, &new_federation));
                if issuer_is_old && federation_is_old {
                    observed_old.store(true, Ordering::SeqCst);
                } else if issuer_is_new && federation_is_new {
                    observed_new.store(true, Ordering::SeqCst);
                } else {
                    torn.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }));
    }

    start.wait();
    // The reader threads race a publisher that does nothing but atomic swaps, so on
    // an oversubscribed runner every publish can complete before any reader executes
    // its loop body even once. A fixed iteration count therefore isn't a reliable way
    // to guarantee both generations get observed; keep alternating publishes until
    // they actually have been, bounded by a generous wall-clock deadline so a genuine
    // regression (e.g. readers never getting scheduled at all) still fails the test
    // instead of hanging.
    let coverage_deadline_duration = Duration::from_secs(15);
    let coverage_deadline = Instant::now() + coverage_deadline_duration;
    let mut publish_pairs: u64 = 0;
    loop {
        state.publish_runtime_snapshot(Arc::clone(&new_snapshot));
        state.publish_runtime_snapshot(Arc::clone(&old_snapshot));
        publish_pairs += 1;

        if torn.load(Ordering::SeqCst) {
            break;
        }
        if observed_old.load(Ordering::SeqCst) && observed_new.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() >= coverage_deadline {
            break;
        }
    }
    done.store(true, Ordering::SeqCst);
    for worker in workers {
        worker.join().expect("observer thread joins");
    }

    // The real correctness property: a reader must never see a snapshot with an old
    // issuer paired with a new federation runtime (or vice versa).
    assert!(!torn.load(Ordering::SeqCst));
    // Coverage is a test-harness concern, not a correctness one: it just confirms the
    // race above actually exercised both generations before the deadline elapsed.
    assert!(
        observed_old.load(Ordering::SeqCst) && observed_new.load(Ordering::SeqCst),
        "reader threads never observed both snapshot generations after {publish_pairs} \
             publish pairs and a {:?} coverage deadline (observed_old={}, observed_new={}); \
             this is a scheduling coverage failure, not a torn read (the torn invariant above \
             already holds)",
        coverage_deadline_duration,
        observed_old.load(Ordering::SeqCst),
        observed_new.load(Ordering::SeqCst),
    );
}

#[tokio::test]
async fn readiness_fails_when_signer_readiness_fails() {
    let state = Arc::new(
        RegistryNotaryApiState::new(
            Arc::new(evidence_config()),
            AuditKeyHasher::unkeyed_dev_only(),
            Arc::new(EvidenceStore::default()),
            Arc::new(NoopIssuerResolver),
        )
        .with_signer_readiness(SignerReadiness::from_provider_flags(vec![Arc::new(
            AtomicBool::new(false),
        )])),
    );

    let response = ready(Some(Extension(state))).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("ready body reads");
    let value: Value = serde_json::from_slice(&body).expect("ready body is JSON");

    assert_eq!(value["status"], json!(503));
    assert_eq!(value["code"], "readiness.not_ready");
    assert_eq!(value["readiness_status"], "not_ready");
    assert_eq!(value["checks"]["signing_providers"]["total"], json!(1));
    assert_eq!(value["checks"]["signing_providers"]["ok"], json!(0));
    assert_eq!(value["checks"]["signing_providers"]["failed"], json!(1));
}

#[test]
fn access_token_issuance_signer_is_in_custody_counts() {
    let mut config = classifier_config();
    config.auth.access_token_signing.enabled = true;
    config.auth.access_token_signing.signing_key_id = "access-token-key".to_string();
    config.evidence.signing_keys.insert(
        "access-token-key".to_string(),
        serde_norway::from_str(
            r#"
provider: local_jwk_env
private_jwk_env: ACCESS_TOKEN_JWK
alg: EdDSA
kid: access-token-key
status: active
"#,
        )
        .expect("signing key parses"),
    );

    let access_token = access_token_issuance_signer_counts(&config);
    assert_eq!(access_token.total, 1);
    assert_eq!(access_token.local_software, 1);
    let scoped = custody_scoped_signer_counts(&config);
    assert_eq!(scoped.total, 1);
    assert_eq!(scoped.local_software, 1);
}
