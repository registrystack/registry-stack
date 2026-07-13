// SPDX-License-Identifier: Apache-2.0

use registry_relay::rhai_worker::{
    FactSchema, FactType, TypedValue, WorkerLimits, WorkerProcess, WorkerRequest,
};

#[tokio::test]
async fn first_product_worker_invocation_keeps_cold_start_outside_script_budget() {
    let worker = WorkerProcess::with_program(env!("CARGO_BIN_EXE_registry-relay-rhai-worker"));
    let mut request = WorkerRequest::v1(
        r#"
            fn consult(input, prior) {
                #{ operations: [], outputs: #{
                    exists: #{ type: "presence", value: false }
                }}
            }
        "#,
        "consult",
        WorkerLimits {
            wall_time_ms: 250,
            ..WorkerLimits::default()
        },
    );
    request.fact_schema.insert(
        "exists".to_owned(),
        FactSchema {
            fact_type: FactType::Presence,
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
        output.outputs.get("exists"),
        Some(&TypedValue::Presence { value: false })
    );
}
