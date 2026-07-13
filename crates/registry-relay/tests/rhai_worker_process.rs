// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use registry_relay::rhai_worker::{
    HostFailure, OutputSchema, OutputType, ScriptFailure, SourceCall, SourceHost, SourceResponse,
    TypedValue, WorkerError, WorkerLimits, WorkerOutcome, WorkerOutput, WorkerProcess,
    WorkerRequest,
};
use serde_json::json;

fn relay_worker() -> WorkerProcess {
    WorkerProcess::with_program(env!("CARGO_BIN_EXE_registry-relay-rhai-worker"))
}

fn request(script: impl Into<String>) -> WorkerRequest {
    let limits = WorkerLimits {
        wall_time_ms: 5_000,
        ..WorkerLimits::default()
    };
    let mut request = WorkerRequest::v1(script, "consult", limits);
    request.output_schema.insert(
        "active".to_string(),
        OutputSchema {
            output_type: OutputType::Boolean,
            nullable: false,
            max_bytes: None,
            minimum: None,
            maximum: None,
        },
    );
    request
}

const DETERMINISTIC_SCRIPT: &str = "fn consult(ctx) { result.match(#{ active: true }) }";
const MIB: u64 = 1024 * 1024;

struct QueueHost {
    responses: VecDeque<Result<SourceResponse, HostFailure>>,
    calls: Arc<Mutex<Vec<SourceCall>>>,
}

impl QueueHost {
    fn new(responses: impl IntoIterator<Item = SourceResponse>) -> Self {
        Self {
            responses: responses.into_iter().map(Ok).collect(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl SourceHost for QueueHost {
    async fn call(&mut self, call: SourceCall) -> Result<SourceResponse, HostFailure> {
        self.calls.lock().expect("calls lock").push(call);
        self.responses
            .pop_front()
            .unwrap_or(Err(HostFailure::ContractViolation))
    }
}

fn matched(output: WorkerOutput) -> BTreeMap<String, TypedValue> {
    match output {
        WorkerOutput::Success {
            outcome: WorkerOutcome::Match,
            outputs,
        } => outputs,
        other => panic!("expected a match, got {other:?}"),
    }
}

#[tokio::test]
async fn fresh_workers_return_the_same_closed_result() {
    let worker = relay_worker();
    let request = request(DETERMINISTIC_SCRIPT);
    let first = worker.evaluate(&request).await.expect("first worker");
    let second = worker.evaluate(&request).await.expect("second worker");
    assert_eq!(first, second);
    assert_eq!(
        matched(first).get("active"),
        Some(&TypedValue::Boolean { value: Some(true) })
    );
}

#[tokio::test]
async fn one_worker_interactively_orchestrates_multiple_bounded_source_calls() {
    let script = r#"
        fn consult(ctx) {
            let target = source.path("/records/{id}", #{ id: ctx.input.id });
            let first = source.get(target, #{ query: #{ fields: "id,active,next" } });
            if first.status == 404 { return result.no_match(); }
            if first.status != 200 { return result.fail(failure.source_rejected); }
            if first.body.id != ctx.input.id {
                return result.fail(failure.subject_mismatch);
            }
            let detail = source.post_json("/details", #{ id: first.body.id }, #{
                headers: #{ "X-Profile": "reviewed" }
            });
            if detail.status != 200 { return result.fail(failure.source_rejected); }
            result.match(#{ active: first.body.active && detail.body.enabled })
        }
    "#;
    let worker = relay_worker();
    let mut request = request(script);
    request.input.insert(
        "id".to_string(),
        TypedValue::String {
            value: Some("A/B C".to_string()),
        },
    );
    let mut host = QueueHost::new([
        SourceResponse {
            status: 200,
            body: json!({"id": "A/B C", "active": true}),
            headers: BTreeMap::new(),
        },
        SourceResponse {
            status: 200,
            body: json!({"enabled": true}),
            headers: BTreeMap::new(),
        },
    ]);

    let output = worker
        .evaluate_with_host(&request, &mut host)
        .await
        .expect("interactive worker");
    assert_eq!(
        matched(output).get("active"),
        Some(&TypedValue::Boolean { value: Some(true) })
    );
    let calls = host.calls.lock().expect("calls lock");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].call_id(), 0);
    assert_eq!(calls[1].call_id(), 1);
    assert!(matches!(
        &calls[0],
        SourceCall::Get { target, options, .. }
            if target == "/records/A%2FB%20C"
                && options.query.get("fields") == Some(&json!("id,active,next"))
    ));
    assert!(matches!(
        &calls[1],
        SourceCall::PostJson { target, body, options, .. }
            if target == "/details"
                && body == &json!({"id": "A/B C"})
                && options.headers.get("X-Profile") == Some(&"reviewed".to_string())
    ));
}

#[tokio::test]
async fn post_form_is_an_explicit_host_call_and_results_remain_natural_maps() {
    let script = r#"
        fn consult(ctx) {
            let response = source.post_form("/search", #{ identifier: ctx.input.id });
            if response.body.matches == 0 { return result.no_match(); }
            if response.body.matches > 1 { return result.ambiguous(); }
            result.match(#{ active: response.body.active })
        }
    "#;
    let worker = relay_worker();
    let mut request = request(script);
    request.input.insert(
        "id".to_string(),
        TypedValue::String {
            value: Some("123".to_string()),
        },
    );
    let mut host = QueueHost::new([SourceResponse {
        status: 200,
        body: json!({"matches": 1, "active": true}),
        headers: BTreeMap::new(),
    }]);
    let output = worker
        .evaluate_with_host(&request, &mut host)
        .await
        .expect("form worker");
    assert_eq!(
        matched(output).get("active"),
        Some(&TypedValue::Boolean { value: Some(true) })
    );
    assert!(matches!(
        &host.calls.lock().expect("calls lock")[0],
        SourceCall::PostForm { fields, .. }
            if fields.get("identifier") == Some(&json!("123"))
    ));
}

#[tokio::test]
async fn script_failure_codes_are_closed_and_free_form_values_are_rejected() {
    let worker = relay_worker();
    let closed = request("fn consult(ctx) { result.fail(failure.source_unavailable) }");
    assert_eq!(
        worker.evaluate(&closed).await,
        Ok(WorkerOutput::Failure {
            failure: ScriptFailure::SourceUnavailable
        })
    );

    let free_form = request("fn consult(ctx) { result.fail(\"source_unavailable\") }");
    assert_eq!(
        worker.evaluate(&free_form).await,
        Err(WorkerError::ScriptRejected)
    );
}

#[tokio::test]
async fn host_failures_terminate_without_becoming_script_values() {
    let worker = relay_worker();
    let request = request(
        "fn consult(ctx) { let response = source.get(\"/records\"); result.match(#{ active: true }) }",
    );
    let mut host = QueueHost {
        responses: VecDeque::from([Err(HostFailure::SourceAuth)]),
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    assert_eq!(
        worker.evaluate_with_host(&request, &mut host).await,
        Err(WorkerError::HostFailed(HostFailure::SourceAuth))
    );
}

#[tokio::test]
async fn scrubbed_worker_has_no_environment_clock_or_direct_effect_api() {
    let worker = relay_worker();
    for expression in [
        "env_var(\"HOME\")",
        "timestamp()",
        "open(\"/etc/passwd\")",
        "exec(\"true\")",
    ] {
        let script = format!("fn consult(ctx) {{ {expression} }}");
        assert_eq!(
            worker.evaluate(&request(script)).await,
            Err(WorkerError::ScriptRejected),
            "{expression} must be unavailable"
        );
    }
}

#[tokio::test]
async fn process_denies_instruction_depth_output_call_and_wall_time_overruns() {
    let worker = relay_worker();

    let mut instruction = request("fn consult(ctx) { while true {} }");
    instruction.limits.max_operations = 100;
    assert_eq!(
        worker.evaluate(&instruction).await,
        Err(WorkerError::BudgetExceeded)
    );

    let mut depth = request("fn recurse(n) { recurse(n + 1) } fn consult(ctx) { recurse(0) }");
    depth.limits.max_call_levels = 4;
    assert_eq!(
        worker.evaluate(&depth).await,
        Err(WorkerError::BudgetExceeded)
    );

    let payload = "x".repeat(400);
    let mut output = WorkerRequest::v1(
        format!(r#"fn consult(ctx) {{ result.match(#{{ payload: "{payload}" }}) }}"#),
        "consult",
        WorkerLimits::default(),
    );
    output.output_schema.insert(
        "payload".to_string(),
        OutputSchema {
            output_type: OutputType::String,
            nullable: false,
            max_bytes: Some(512),
            minimum: None,
            maximum: None,
        },
    );
    output.limits.max_output_bytes = 256;
    output.limits.wall_time_ms = 5_000;
    assert_eq!(
        worker.evaluate(&output).await,
        Err(WorkerError::BudgetExceeded)
    );

    let mut calls = request(
        "fn consult(ctx) { source.get(\"/1\"); source.get(\"/2\"); result.match(#{ active: true }) }",
    );
    calls.limits.max_source_calls = 1;
    let mut host = QueueHost::new([SourceResponse {
        status: 200,
        body: json!({}),
        headers: BTreeMap::new(),
    }]);
    assert_eq!(
        worker.evaluate_with_host(&calls, &mut host).await,
        Err(WorkerError::BudgetExceeded)
    );

    let mut wall = request("fn consult(ctx) { while true {} }");
    wall.limits.max_operations = 5_000_000;
    wall.limits.wall_time_ms = 1;
    assert_eq!(
        worker.evaluate(&wall).await,
        Err(WorkerError::BudgetExceeded)
    );
}

#[tokio::test]
async fn process_rejects_oversized_ipc_frames_and_host_responses() {
    let worker = relay_worker();
    let mut oversized = request(format!("{DETERMINISTIC_SCRIPT}{}", " ".repeat(512)));
    oversized.limits.max_ipc_frame_bytes = 256;
    assert_eq!(
        worker.evaluate(&oversized).await,
        Err(WorkerError::RequestTooLarge)
    );

    let source =
        request("fn consult(ctx) { source.get(\"/record\"); result.match(#{ active: true }) }");
    let mut host = QueueHost::new([SourceResponse {
        status: 200,
        body: json!({"payload": "x".repeat(200_000)}),
        headers: BTreeMap::new(),
    }]);
    assert_eq!(
        worker.evaluate_with_host(&source, &mut host).await,
        Err(WorkerError::BudgetExceeded)
    );
}

#[tokio::test]
async fn worker_memory_configuration_cannot_exceed_128_mib() {
    let worker = relay_worker();
    let mut oversized = request(DETERMINISTIC_SCRIPT);
    oversized.limits.max_memory_bytes = 128 * MIB + 1;
    assert_eq!(
        worker.evaluate(&oversized).await,
        Err(WorkerError::ContractViolation)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_worker_memory_exhaustion_is_contained_by_process_ceiling() {
    let worker = relay_worker();
    let payload = "x".repeat(32 * 1024);
    let mut memory = request(format!(
        r#"
            fn consult(ctx) {{
                let payload = "{payload}";
                let values = [];
                let index = 0;
                while index < 4096 {{
                    values.push(payload + index);
                    index += 1;
                }}
                result.match(#{{ active: true }})
            }}
        "#
    ));
    memory.limits.max_operations = 5_000_000;
    memory.limits.max_string_bytes = 64 * 1024;
    memory.limits.max_array_items = 4_096;
    memory.limits.max_memory_bytes = 128 * MIB;
    memory.limits.max_ipc_frame_bytes = 128 * 1024;
    memory.limits.wall_time_ms = 5_000;
    assert!(matches!(
        worker.evaluate(&memory).await,
        Err(WorkerError::BudgetExceeded | WorkerError::IpcFailed)
    ));
}
