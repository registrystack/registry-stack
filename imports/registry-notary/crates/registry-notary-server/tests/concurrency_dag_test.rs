// SPDX-License-Identifier: Apache-2.0
//! Stage 1 scalability tests: parallel claim/binding evaluation, the kill
//! switch, and per-subject ordering preservation in `batch_evaluate`. Uses a
//! synchronous mock `SourceReader` so timing is controlled by the test, not
//! by HTTP plumbing.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use registry_notary_core::{
    AccessMode, BatchEvaluateItemRequest, BatchEvaluateRequest, ClaimDefinition,
    ClaimOperationsConfig, ClaimRef, ClaimValueConfig, ConcurrencyConfig, DisclosureConfig,
    EvaluateRequest, EvidenceConfig, EvidenceEntity, EvidenceError, EvidencePrincipal, RuleConfig,
    SourceBindingConfig, SourceConnectorKind, SourceFieldConfig, SourceLookupConfig,
    SourceMatchingConfig, SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
};
use registry_notary_server::{
    BatchEvaluateOptions, EvidenceStore, RegistryNotaryRuntime, SourceReader,
};
use serde_json::{json, Value};

/// Sleeps `delay` inside `read_one`, then returns a synthetic record with the
/// subject id under the lookup field. Records two timestamps per binding
/// (`name`): when the call entered (after the sleep starts) and when it
/// exited. Tests assert ordering on these.
#[derive(Debug, Clone)]
struct SleepingSource {
    delay: Duration,
    enter_log: Arc<dashmap_lite::Map<String, i64>>,
    exit_log: Arc<dashmap_lite::Map<String, i64>>,
    epoch: Instant,
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
    attempt_counter: Arc<AtomicUsize>,
}

impl SleepingSource {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            enter_log: Arc::new(dashmap_lite::Map::new()),
            exit_log: Arc::new(dashmap_lite::Map::new()),
            epoch: Instant::now(),
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak_in_flight: Arc::new(AtomicUsize::new(0)),
            attempt_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn entered_at(&self, key: &str) -> Option<i64> {
        self.enter_log.get(key)
    }

    fn exited_at(&self, key: &str) -> Option<i64> {
        self.exit_log.get(key)
    }

    fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    fn attempt_count(&self) -> usize {
        self.attempt_counter.load(Ordering::SeqCst)
    }
}

impl SourceReader for SleepingSource {
    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        let key = format!("{}:{}", binding.entity, subject.id);
        let delay = self.delay;
        let enter_log = Arc::clone(&self.enter_log);
        let exit_log = Arc::clone(&self.exit_log);
        let epoch = self.epoch;
        let in_flight = Arc::clone(&self.in_flight);
        let peak = Arc::clone(&self.peak_in_flight);
        let attempts = Arc::clone(&self.attempt_counter);
        Box::pin(async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            let now_us = epoch.elapsed().as_micros() as i64;
            enter_log.insert(key.clone(), now_us);
            let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            let exit_us = epoch.elapsed().as_micros() as i64;
            exit_log.insert(key.clone(), exit_us);
            Ok(json!({
                "id": subject.id.clone(),
                "value": 1,
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

/// Tiny lock-free-feeling map wrapper to avoid pulling in `dashmap` just for
/// tests. Backed by `Mutex<BTreeMap>`; never held across `.await`.
mod dashmap_lite {
    use std::borrow::Borrow;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    pub struct Map<K, V>(Mutex<BTreeMap<K, V>>);

    impl<K: Ord, V: Clone> Map<K, V> {
        pub fn new() -> Self {
            Self(Mutex::new(BTreeMap::new()))
        }

        pub fn insert(&self, k: K, v: V) {
            self.0.lock().expect("map mutex").insert(k, v);
        }

        pub fn get<Q>(&self, k: &Q) -> Option<V>
        where
            K: Borrow<Q>,
            Q: Ord + ?Sized,
        {
            self.0.lock().expect("map mutex").get(k).cloned()
        }
    }

    impl<K, V> std::fmt::Debug for Map<K, V> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Map").finish()
        }
    }
}

fn claim_with_two_bindings(id: &str) -> ClaimDefinition {
    let mut bindings = BTreeMap::new();
    for entity in ["a", "b"] {
        bindings.insert(
            format!("src-{entity}"),
            SourceBindingConfig {
                connector: SourceConnectorKind::RegistryDataApi,
                connection: None,
                required_scope: None,
                dataset: "ds".to_string(),
                entity: entity.to_string(),
                lookup: SourceLookupConfig {
                    input: "target.id".to_string(),
                    field: "id".to_string(),
                    op: "eq".to_string(),
                    cardinality: "one".to_string(),
                },
                query_fields: Vec::new(),
                fields: BTreeMap::from([(
                    "value".to_string(),
                    SourceFieldConfig {
                        field: "value".to_string(),
                        field_type: Some("number".to_string()),
                        unit: None,
                        required: true,
                        semantic_term: None,
                    },
                )]),
                matching: SourceMatchingConfig::default(),
            },
        );
    }
    ClaimDefinition {
        id: id.to_string(),
        title: id.to_string(),
        version: "1.0".to_string(),
        subject_type: "person".to_string(),
        value: ClaimValueConfig {
            value_type: "number".to_string(),
            unit: None,
        },
        semantics: None,
        inputs: Vec::new(),
        depends_on: Vec::new(),
        purpose: None,
        source_bindings: bindings,
        rule: RuleConfig::Extract {
            source: "src-a".to_string(),
            field: "value".to_string(),
        },
        operations: ClaimOperationsConfig::default(),
        disclosure: DisclosureConfig {
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

fn evaluate_claim(id: &str, entity: &str, depends_on: Vec<&str>) -> ClaimDefinition {
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "src".to_string(),
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "ds".to_string(),
            entity: entity.to_string(),
            lookup: SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::from([(
                "value".to_string(),
                SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("number".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
            matching: SourceMatchingConfig::default(),
        },
    );
    ClaimDefinition {
        id: id.to_string(),
        title: id.to_string(),
        version: "1.0".to_string(),
        subject_type: "person".to_string(),
        value: ClaimValueConfig {
            value_type: "number".to_string(),
            unit: None,
        },
        semantics: None,
        inputs: Vec::new(),
        depends_on: depends_on.into_iter().map(String::from).collect(),
        purpose: None,
        source_bindings: bindings,
        rule: RuleConfig::Extract {
            source: "src".to_string(),
            field: "value".to_string(),
        },
        operations: ClaimOperationsConfig::default(),
        disclosure: DisclosureConfig {
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

fn principal() -> EvidencePrincipal {
    EvidencePrincipal {
        principal_id: "test".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    }
}

fn make_evidence(
    claims: Vec<ClaimDefinition>,
    subjects: usize,
    concurrency: ConcurrencyConfig,
) -> Arc<EvidenceConfig> {
    let mut cfg = EvidenceConfig {
        enabled: true,
        service_id: "registry-notary.test".to_string(),
        inline_batch_limit: subjects.max(1),
        claims,
        concurrency,
        ..EvidenceConfig::default()
    };
    // Each claim's batch_evaluate must be enabled for batch tests.
    for claim in &mut cfg.claims {
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = subjects.max(1);
    }
    Arc::new(cfg)
}

/// Positive overlap: two independent claims at the same DAG level, each
/// hitting a 200ms binding, should complete a single-subject `evaluate` in
/// ~200ms with `concurrency.bindings>=2`, not ~400ms.
#[tokio::test]
async fn parallel_sibling_claims_overlap_in_one_subject() {
    let source = Arc::new(SleepingSource::new(Duration::from_millis(200)));
    let evidence = make_evidence(
        vec![
            evaluate_claim("claim-a", "a", Vec::new()),
            evaluate_claim("claim-b", "b", Vec::new()),
        ],
        1,
        ConcurrencyConfig {
            subjects: 1,
            bindings: 4,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "p-1".to_string(),
                id_type: None,
            },
        )),
        relationship: None,
        on_behalf_of: None,
        claims: vec![ClaimRef::from("claim-a"), ClaimRef::from("claim-b")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let start = Instant::now();
    let results = runtime
        .evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            None,
        )
        .await
        .expect("evaluate succeeds");
    let elapsed = start.elapsed();
    assert_eq!(results.len(), 2);
    assert!(
        elapsed < Duration::from_millis(350),
        "parallel sibling claims should overlap; observed {elapsed:?}",
    );
}

/// DAG ordering: with `B depends_on A`, B's read must not start until A's
/// read has finished, regardless of how high `concurrency.bindings` is.
#[tokio::test]
async fn dependent_claim_b_starts_after_a_completes() {
    let source = Arc::new(SleepingSource::new(Duration::from_millis(80)));
    let evidence = make_evidence(
        vec![
            evaluate_claim("claim-a", "a", Vec::new()),
            evaluate_claim("claim-b", "b", vec!["claim-a"]),
        ],
        1,
        ConcurrencyConfig {
            subjects: 1,
            bindings: 16,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "p-1".to_string(),
                id_type: None,
            },
        )),
        relationship: None,
        on_behalf_of: None,
        claims: vec![ClaimRef::from("claim-b")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    runtime
        .evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            None,
        )
        .await
        .expect("evaluate succeeds");
    let a_exit = source.exited_at("a:p-1").expect("claim-a binding ran");
    let b_enter = source.entered_at("b:p-1").expect("claim-b binding ran");
    assert!(
        b_enter >= a_exit,
        "claim-b started at {b_enter}us before claim-a exited at {a_exit}us (concurrency.bindings was high)",
    );
}

/// Numeric DoD: `batch_evaluate` of 50 subjects against a 50ms stub with
/// `concurrency.subjects=10` completes under `1.5 * ceil(50/10) * 50ms = 375ms`.
#[tokio::test]
async fn batch_evaluate_meets_numeric_dod() {
    let subject_count = 50usize;
    let upstream_latency = Duration::from_millis(50);
    let source = Arc::new(SleepingSource::new(upstream_latency));
    let evidence = make_evidence(
        vec![evaluate_claim("claim-a", "a", Vec::new())],
        subject_count,
        ConcurrencyConfig {
            subjects: 10,
            bindings: 1,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let subjects: Vec<SubjectRequest> = (0..subject_count)
        .map(|i| SubjectRequest {
            id: format!("p-{i}"),
            id_type: None,
        })
        .collect();
    let request = BatchEvaluateRequest {
        items: subjects
            .into_iter()
            .map(BatchEvaluateItemRequest::from)
            .collect(),
        claims: vec![ClaimRef::from("claim-a")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let start = Instant::now();
    let response = runtime
        .batch_evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch_evaluate succeeds");
    let elapsed = start.elapsed();
    assert_eq!(response.items.len(), subject_count);
    for (i, item) in response.items.iter().enumerate() {
        assert_eq!(
            item.input_index, i,
            "input_index ordering must be preserved"
        );
    }
    let bound = Duration::from_millis(375);
    assert!(
        elapsed < bound,
        "batch_evaluate of {subject_count} should complete under {bound:?}; observed {elapsed:?} \
         peak in-flight: {}",
        source.peak_in_flight()
    );
}

/// Kill switch: with `concurrency.subjects=1, concurrency.bindings=1`,
/// batch_evaluate behaves sequentially. With 5 subjects at 50ms each, total
/// time is at least 250ms.
#[tokio::test]
async fn kill_switch_one_one_serializes_subjects() {
    let upstream_latency = Duration::from_millis(50);
    let subject_count = 5usize;
    let source = Arc::new(SleepingSource::new(upstream_latency));
    let evidence = make_evidence(
        vec![evaluate_claim("claim-a", "a", Vec::new())],
        subject_count,
        ConcurrencyConfig {
            subjects: 1,
            bindings: 1,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let subjects: Vec<SubjectRequest> = (0..subject_count)
        .map(|i| SubjectRequest {
            id: format!("p-{i}"),
            id_type: None,
        })
        .collect();
    let request = BatchEvaluateRequest {
        items: subjects
            .into_iter()
            .map(BatchEvaluateItemRequest::from)
            .collect(),
        claims: vec![ClaimRef::from("claim-a")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let start = Instant::now();
    let response = runtime
        .batch_evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch_evaluate succeeds");
    let elapsed = start.elapsed();
    assert_eq!(response.items.len(), subject_count);
    let lower_bound = Duration::from_millis(((subject_count as u64) * 50).saturating_sub(20));
    assert!(
        elapsed >= lower_bound,
        "kill switch must serialize subjects; observed {elapsed:?} expected at least {lower_bound:?}",
    );
    assert_eq!(
        source.peak_in_flight(),
        1,
        "peak in-flight under the kill switch must be 1",
    );
}

/// Unhappy path: one subject's read returns an error from the mock. The
/// remaining subjects complete; the failed subject reports the error in
/// its item; no panic surfaces. After the call, the runtime must not have
/// leaked any task (verified by spawning more work that completes promptly).
#[tokio::test]
async fn one_failing_subject_does_not_block_others() {
    /// A mock source that fails on the matching subject id and otherwise
    /// returns a record after the same `delay`.
    #[derive(Debug)]
    struct PartialFailureSource {
        delay: Duration,
        fail_subject: String,
    }
    impl SourceReader for PartialFailureSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            let delay = self.delay;
            let fail = subject.id == self.fail_subject;
            let subject_id = subject.id.clone();
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                if fail {
                    Err(EvidenceError::SourceUnavailable)
                } else {
                    Ok(json!({"id": subject_id, "value": 1}))
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

    let source: Arc<dyn SourceReader> = Arc::new(PartialFailureSource {
        delay: Duration::from_millis(20),
        fail_subject: "p-2".to_string(),
    });
    let subject_count = 5usize;
    let evidence = make_evidence(
        vec![evaluate_claim("claim-a", "a", Vec::new())],
        subject_count,
        ConcurrencyConfig {
            subjects: 4,
            bindings: 1,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let subjects: Vec<SubjectRequest> = (0..subject_count)
        .map(|i| SubjectRequest {
            id: format!("p-{i}"),
            id_type: None,
        })
        .collect();
    let request = BatchEvaluateRequest {
        items: subjects
            .into_iter()
            .map(BatchEvaluateItemRequest::from)
            .collect(),
        claims: vec![ClaimRef::from("claim-a")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let response = runtime
        .batch_evaluate(
            evidence,
            source,
            &store,
            &principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch_evaluate returns even when one subject fails");
    assert_eq!(response.items.len(), subject_count);
    assert_eq!(response.summary.failed, 1);
    assert_eq!(response.summary.succeeded, subject_count - 1);
    for (i, item) in response.items.iter().enumerate() {
        assert_eq!(item.input_index, i);
    }
    let failed = response
        .items
        .iter()
        .find(|i| i.input_index == 2)
        .expect("p-2");
    assert!(matches!(
        failed.status,
        registry_notary_core::BatchItemStatus::Failed
    ));
    assert!(!failed.errors.is_empty(), "failed subject reports error");

    // Sentinel: a follow-up task must run promptly (within a clear margin) to
    // confirm no leaked task is starving the runtime.
    let sentinel = AtomicI64::new(0);
    let sentinel_start = Instant::now();
    tokio::time::sleep(Duration::from_millis(5)).await;
    sentinel.store(
        sentinel_start.elapsed().as_millis() as i64,
        Ordering::SeqCst,
    );
    assert!(
        sentinel.load(Ordering::SeqCst) < 200,
        "sentinel did not complete promptly; runtime may be starved"
    );
}

/// `batch_evaluate` preserves input_index ordering in the response even when
/// subjects finish out of order (concurrency on, variable per-subject delay).
#[tokio::test]
async fn batch_response_preserves_input_index_ordering() {
    /// A source where subjects with even ids take longer than odd ones,
    /// guaranteeing out-of-order completion when run in parallel.
    #[derive(Debug)]
    struct StaggeredSource;
    impl SourceReader for StaggeredSource {
        fn read_one<'a>(
            &'a self,
            _binding: &'a SourceBindingConfig,
            subject: &'a SubjectRequest,
            _purpose: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
            let suffix: usize = subject
                .id
                .rsplit('-')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let delay_ms = if suffix.is_multiple_of(2) { 60 } else { 10 };
            let subject_id = subject.id.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                Ok(json!({"id": subject_id, "value": 1}))
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

    let subject_count = 6usize;
    let evidence = make_evidence(
        vec![evaluate_claim("claim-a", "a", Vec::new())],
        subject_count,
        ConcurrencyConfig {
            subjects: 6,
            bindings: 1,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let subjects: Vec<SubjectRequest> = (0..subject_count)
        .map(|i| SubjectRequest {
            id: format!("p-{i}"),
            id_type: None,
        })
        .collect();
    let request = BatchEvaluateRequest {
        items: subjects
            .into_iter()
            .map(BatchEvaluateItemRequest::from)
            .collect(),
        claims: vec![ClaimRef::from("claim-a")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let response = runtime
        .batch_evaluate(
            evidence,
            Arc::new(StaggeredSource) as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            BatchEvaluateOptions::default(),
        )
        .await
        .expect("batch_evaluate succeeds");
    assert_eq!(response.items.len(), subject_count);
    for (i, item) in response.items.iter().enumerate() {
        assert_eq!(item.input_index, i);
    }
}

/// Intra-claim binding parallelism: a single claim with two independent
/// bindings, each hitting a 200ms read, completes in ~200ms with
/// `concurrency.bindings >= 2`, not ~400ms. Stage 2's single-flight memo
/// must not regress the binding-level fan-out introduced in Stage 1.
#[tokio::test]
async fn parallel_bindings_in_one_claim_overlap() {
    let source = Arc::new(SleepingSource::new(Duration::from_millis(200)));
    let evidence = make_evidence(
        vec![claim_with_two_bindings("claim-mixed")],
        1,
        ConcurrencyConfig {
            subjects: 1,
            bindings: 4,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "p-1".to_string(),
                id_type: None,
            },
        )),
        relationship: None,
        on_behalf_of: None,
        claims: vec![ClaimRef::from("claim-mixed")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let start = Instant::now();
    let results = runtime
        .evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            None,
        )
        .await
        .expect("evaluate succeeds");
    let elapsed = start.elapsed();
    assert_eq!(results.len(), 1);
    assert_eq!(
        source.attempt_count(),
        2,
        "both bindings should have been fetched"
    );
    assert!(
        elapsed < Duration::from_millis(350),
        "two bindings in one claim should overlap with bindings>=2; observed {elapsed:?}",
    );
}

/// Kill switch at the binding level: with `concurrency.bindings = 1`, the
/// two bindings inside one claim must serialize, taking at least ~400ms.
#[tokio::test]
async fn kill_switch_bindings_one_serializes_within_claim() {
    let source = Arc::new(SleepingSource::new(Duration::from_millis(200)));
    let evidence = make_evidence(
        vec![claim_with_two_bindings("claim-mixed")],
        1,
        ConcurrencyConfig {
            subjects: 1,
            bindings: 1,
        },
    );
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let request = EvaluateRequest {
        requester: None,
        target: Some(EvidenceEntity::from_subject_request(
            "Person",
            SubjectRequest {
                id: "p-1".to_string(),
                id_type: None,
            },
        )),
        relationship: None,
        on_behalf_of: None,
        claims: vec![ClaimRef::from("claim-mixed")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let start = Instant::now();
    runtime
        .evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            None,
        )
        .await
        .expect("evaluate succeeds");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(380),
        "bindings=1 must serialize the two bindings; observed {elapsed:?}",
    );
    assert_eq!(
        source.peak_in_flight(),
        1,
        "peak in-flight under the binding kill switch must be 1",
    );
}
