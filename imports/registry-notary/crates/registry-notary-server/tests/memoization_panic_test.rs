// SPDX-License-Identifier: Apache-2.0
//! Regression test for the single-flight panic-deadlock window in the
//! per-batch fetch memo.
//!
//! Before the fix in `fetch_and_signal`, an Owner task that panicked between
//! "insert Pending slot" and "add_permits" left waiting siblings parked on
//! the semaphore forever; the panic only surfaced on the Owner's JoinHandle.
//! The drop guard now removes the slot and signals waiters on unwind, so the
//! request completes in bounded time regardless of the panic.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use registry_notary_core::{
    AccessMode, BatchEvaluateRequest, BatchSubjectRequest, ClaimDefinition, ClaimOperationsConfig,
    ClaimRef, ClaimValueConfig, ConcurrencyConfig, DisclosureConfig, EvidenceConfig, EvidenceError,
    EvidencePrincipal, RuleConfig, SourceBindingConfig, SourceConnectorKind, SourceFieldConfig,
    SourceLookupConfig, SourceMatchingConfig, SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
};
use registry_notary_server::{
    BatchEvaluateOptions, EvidenceStore, RegistryNotaryRuntime, SourceReader,
};
use serde_json::{json, Value};

/// SourceReader stub that panics on the first `read_one` call and succeeds
/// thereafter. Used to drive the Owner task into a panic while a sibling
/// subject is waiting on the same memo key.
#[derive(Debug, Default)]
struct PanickingSource {
    calls: AtomicUsize,
}

impl SourceReader for PanickingSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let subject_id = subject.id.clone();
        Box::pin(async move {
            if n == 0 {
                // Yield once so the second subject task can park on the
                // Pending semaphore before we unwind.
                tokio::task::yield_now().await;
                panic!("intentional panic from PanickingSource (call #1)");
            }
            Ok(json!({ "id": subject_id, "value": 1 }))
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

fn evaluate_claim() -> ClaimDefinition {
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "src".to_string(),
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "ds".to_string(),
            entity: "ent".to_string(),
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
        id: "claim".to_string(),
        title: "claim".to_string(),
        version: "1.0".to_string(),
        subject_type: "person".to_string(),
        value: ClaimValueConfig {
            value_type: "number".to_string(),
            unit: None,
        },
        inputs: Vec::new(),
        depends_on: Vec::new(),
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

fn evidence_for_batch(subject_count: usize) -> Arc<EvidenceConfig> {
    let mut cfg = EvidenceConfig {
        enabled: true,
        service_id: "registry-notary.test".to_string(),
        inline_batch_limit: subject_count.max(1),
        claims: vec![evaluate_claim()],
        concurrency: ConcurrencyConfig {
            subjects: 8,
            bindings: 4,
        },
        ..EvidenceConfig::default()
    };
    for claim in &mut cfg.claims {
        claim.operations.batch_evaluate.enabled = true;
        claim.operations.batch_evaluate.max_subjects = subject_count.max(1);
    }
    Arc::new(cfg)
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

#[tokio::test]
async fn owner_panic_does_not_deadlock_waiters() {
    // Two subjects with the SAME id hash to the SAME memo cache key, so one
    // becomes the Owner and the other parks as a Waiter on the Pending
    // semaphore. The Owner panics mid-fetch; without the drop guard the
    // Waiter would block on `acquire().await` forever and `batch_evaluate`
    // would hang.
    let source = Arc::new(PanickingSource::default());
    let evidence = evidence_for_batch(2);
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let request = BatchEvaluateRequest {
        items: vec![
            BatchSubjectRequest {
                id: "shared-id".to_string(),
                id_type: None,
                purpose: None,
            }
            .into(),
            BatchSubjectRequest {
                id: "shared-id".to_string(),
                id_type: None,
                purpose: None,
            }
            .into(),
        ],
        claims: vec![ClaimRef::from("claim")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };

    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.batch_evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal(),
            request,
            BatchEvaluateOptions::default(),
        ),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "batch_evaluate must complete within 2s even when the memo Owner panics; \
         a timeout here means waiters are blocked on a Pending semaphore that was \
         never signalled (single-flight deadlock).",
    );
    // The result itself is allowed to be Err; the panic legitimately fails the
    // batch. The point of this test is that we did not hang.
    let _ = outcome.unwrap();
}
