// SPDX-License-Identifier: Apache-2.0

use registry_relay::rhai_worker::{
    OutputSchema, OutputType, TypedValue, WorkerLimits, WorkerOutcome, WorkerOutput, WorkerProcess,
    WorkerRequest,
};

#[tokio::test]
async fn first_product_worker_invocation_keeps_cold_start_outside_script_budget() {
    let worker = WorkerProcess::with_program(env!("CARGO_BIN_EXE_registry-relay-rhai-worker"));
    let mut request = WorkerRequest::v1(
        "fn consult(ctx) { result.match(#{ active: false }) }",
        "consult",
        WorkerLimits {
            wall_time_ms: 250,
            ..WorkerLimits::default()
        },
    );
    request.output_schema.insert(
        "active".to_owned(),
        OutputSchema {
            output_type: OutputType::Boolean,
            nullable: false,
            max_bytes: None,
            minimum: None,
            maximum: None,
        },
    );
    let output = worker
        .evaluate(&request)
        .await
        .expect("first cold worker invocation");
    assert_eq!(
        output,
        WorkerOutput::Success {
            outcome: WorkerOutcome::Match,
            outputs: [(
                "active".to_string(),
                TypedValue::Boolean { value: Some(false) }
            )]
            .into_iter()
            .collect()
        }
    );
}
