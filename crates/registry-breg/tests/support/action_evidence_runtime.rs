// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate as breg;
use crate::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
};
use std::time::Duration;

#[allow(dead_code)]
#[path = "action_evidence_provider.rs"]
mod provider;

fn action() -> CompiledAction {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/farmer-landholding-evidence");
    let project = parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    let assets = [
        "scripts/register-landholding.rhai",
        "scripts/check-procedure.rhai",
        "evidence/farmer-contracts.json",
    ]
    .map(|path| ModuleAssetSource {
        module: None,
        path: path.into(),
        bytes: std::fs::read(root.join(path)).unwrap(),
    });
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .unwrap()
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-landholding")
        .unwrap()
        .clone()
}

fn inputs() -> Map<String, Value> {
    serde_json::json!({"farmer-prefix":" FR ", "farmer-number":" 123 ", "parcel-code":"P-1", "include-category":false})
        .as_object().unwrap().clone()
}

async fn wait_capacity(evaluator: &ActionEvidenceEvaluator, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while evaluator.capacity.available_permits() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("blocking worker releases its permit");
}

#[test]
fn queued_worker_retains_capacity_after_request_cancellation() {
    // Occupying the sole blocking thread makes the worker-exit boundary
    // deterministic: aborting its async waiter cannot release its owned permit.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release, blocked) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        running.await.unwrap();
        let evaluator = Arc::new(ActionEvidenceEvaluator {
            client: Arc::new(EvidenceActionClient::new(BTreeMap::new())),
            capacity: Arc::new(Semaphore::new(1)),
        });
        let first = evaluator.clone();
        let compiled = action();
        let first_action = compiled.clone();
        let task = tokio::spawn(async move {
            first
                .evaluate(
                    first_action,
                    inputs(),
                    Instant::now() + Duration::from_secs(3),
                )
                .await
        });
        wait_capacity(&evaluator, 0).await;
        let saturated = evaluator
            .evaluate(
                compiled,
                inputs(),
                Instant::now() + Duration::from_millis(30),
            )
            .await;
        assert_eq!(saturated.outcome, Err(MutationError::Unavailable));
        assert!(saturated.acquisitions.is_empty());
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert_eq!(
            evaluator.capacity.available_permits(),
            0,
            "queued worker still owns capacity after waiter cancellation"
        );
        release.send(()).unwrap();
        blocker.await.unwrap();
        wait_capacity(&evaluator, 1).await;
    });
}

#[tokio::test(flavor = "current_thread")]
async fn paused_provider_cancellation_and_deadline_release_workers() {
    let provider = provider::EvidenceProvider::start().await;
    provider.pause();
    let evaluator = Arc::new(ActionEvidenceEvaluator {
        client: provider.client(),
        capacity: Arc::new(Semaphore::new(1)),
    });
    let compiled = action();
    let running = evaluator.clone();
    let first_action = compiled.clone();
    let task = tokio::spawn(async move {
        running
            .evaluate(
                first_action,
                inputs(),
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    // The server and timer run on this sole async executor thread. Reaching
    // this point while remote acquisition is paused proves the bridge yields.
    provider.wait_for_calls(1).await;
    assert_eq!(evaluator.capacity.available_permits(), 0);
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    wait_capacity(&evaluator, 1).await;
    assert_eq!(provider.calls(), 1);

    let expired = evaluator
        .evaluate(
            compiled.clone(),
            inputs(),
            Instant::now() + Duration::from_millis(100),
        )
        .await;
    assert!(expired.outcome.is_err());
    assert!(expired.acquisitions.is_empty());
    wait_capacity(&evaluator, 1).await;
    assert_eq!(
        provider.calls(),
        2,
        "timeout makes no automatic remote retry"
    );
    provider.resume();
    let successful = evaluator
        .evaluate(compiled, inputs(), Instant::now() + Duration::from_secs(3))
        .await;
    assert!(
        matches!(successful.outcome, Ok(ActionHandlerOutcome::Effects(_))),
        "synthetic resumed evaluation: {:?}",
        successful.outcome
    );
    assert_eq!(successful.acquisitions.len(), 1);
    assert_eq!(provider.calls(), 3);
    assert_eq!(evaluator.capacity.available_permits(), 1);
}

#[test]
fn dependency_diagnostics_preserve_only_first_declared_capability() {
    let compiled = action();
    let known = crate::action_handler::evaluate_action_with_evidence(
        &compiled,
        &inputs(),
        Instant::now() + Duration::from_secs(2),
        |_, _| Err(ActionHandlerError::Evidence),
    )
    .unwrap_err();
    assert_eq!(known.evidence_capability.as_deref(), Some("farmer-status"));
    assert!(!format!("{known:?}").contains("123"));

    for (source, expected) in [
        (
            r#"fn handle(ctx) { try { evidence::resolve("unknown-selector-canary", #{farmer: #{"farmer-number":"private-selector-canary"}}); } catch (error) {} try { evidence::resolve("farmer-status", #{}); } catch (error) {} #{effects: []} }"#,
            None,
        ),
        (
            r#"fn handle(ctx) { try { evidence::resolve(42, #{}); } catch (error) {} #{effects: []} }"#,
            None,
        ),
        (
            r#"fn handle(ctx) { try { evidence::resolve("farmer-status", "private-selector-canary"); } catch (error) {} try { evidence::resolve("farmer-category", #{}); } catch (error) {} #{effects: []} }"#,
            Some("farmer-status"),
        ),
    ] {
        assert!(
            crate::action_handler::compile_source(source).is_ok(),
            "synthetic helper-failure script must reach runtime evaluation"
        );
        let mut compiled = compiled.clone();
        compiled.handler.as_mut().unwrap().script_bytes = source.as_bytes().to_vec();
        let diagnostic = crate::action_handler::evaluate_action_with_evidence(
            &compiled,
            &inputs(),
            Instant::now() + Duration::from_secs(2),
            |_, _| panic!("invalid or poisoned call cannot reach the resolver"),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, ActionHandlerError::Evidence);
        assert_eq!(diagnostic.evidence_capability.as_deref(), expected);
        let rendered = format!("{diagnostic:?}");
        assert!(!rendered.contains("private-selector-canary"));
        assert!(!rendered.contains("unknown-selector-canary"));
    }
}

#[tokio::test]
async fn runtime_dependency_failure_carries_the_verified_alias_only() {
    let evaluator =
        ActionEvidenceEvaluator::new(Arc::new(EvidenceActionClient::new(BTreeMap::new())));
    let result = evaluator
        .evaluate(action(), inputs(), Instant::now() + Duration::from_secs(2))
        .await;
    assert!(matches!(result.outcome,
        Err(MutationError::ActionEvidenceFailure { capability: Some(ref id) }) if id == "farmer-status"));
    assert!(result.acquisitions.is_empty());
}
