// SPDX-License-Identifier: Apache-2.0

use registry_relay::rhai_worker::{
    FactSchema, FactType, TypedValue, WorkerError, WorkerLimits, WorkerProcess, WorkerRequest,
};

fn relay_worker() -> WorkerProcess {
    WorkerProcess::with_program(env!("CARGO_BIN_EXE_registry-relay-rhai-worker"))
}

fn request(script: impl Into<String>) -> WorkerRequest {
    let limits = WorkerLimits {
        wall_time_ms: 5_000,
        ..WorkerLimits::default()
    };
    // Keep the process-level test ceiling at the worker hard maximum while
    // individual timeout tests narrow it explicitly.
    let mut request = WorkerRequest::v1(script, "consult", limits);
    request.allowed_operations.insert("lookup".to_string());
    request.fact_schema.insert(
        "active".to_string(),
        FactSchema {
            fact_type: FactType::Boolean,
            nullable: false,
            max_bytes: None,
            minimum: None,
            maximum: None,
        },
    );
    request
}

const DETERMINISTIC_SCRIPT: &str = r#"
    fn consult(input, prior) {
        #{ operations: [], facts: #{
            active: #{ type: "boolean", value: true }
        }}
    }
"#;

const MIB: u64 = 1024 * 1024;

#[tokio::test]
async fn fresh_workers_return_the_same_closed_result() {
    let worker = relay_worker();
    let request = request(DETERMINISTIC_SCRIPT);
    let first = worker.evaluate(&request).await.expect("first worker");
    let second = worker.evaluate(&request).await.expect("second worker");
    assert_eq!(first, second);
    assert!(first.operation_choices.is_empty());
}

#[tokio::test]
async fn iterative_fresh_workers_choose_a_named_operation_then_return_exact_facts() {
    let script = r#"
        fn consult(input, prior) {
            if !prior.contains("lookup") {
                return #{ operations: ["lookup"], facts: #{} };
            }
            #{ operations: [], facts: #{
                active: #{ type: "boolean", value: prior.lookup.active },
                birth_date: #{ type: "date", value: prior.lookup.birth_date },
                exists: #{ type: "presence", value: prior.lookup.presence }
            }}
        }
    "#;
    let worker = relay_worker();
    let mut first = request(script);
    first.fact_schema.insert(
        "birth_date".to_string(),
        FactSchema {
            fact_type: FactType::Date,
            nullable: false,
            max_bytes: None,
            minimum: None,
            maximum: None,
        },
    );
    first.fact_schema.insert(
        "exists".to_string(),
        FactSchema {
            fact_type: FactType::Presence,
            nullable: false,
            max_bytes: None,
            minimum: None,
            maximum: None,
        },
    );
    let selected = worker.evaluate(&first).await.expect("selection round");
    assert_eq!(selected.operation_choices, ["lookup"]);
    assert!(selected.facts.is_empty());

    first.allowed_operations.clear();
    first.prior_outputs.insert(
        "lookup".to_string(),
        [
            (
                "active".to_string(),
                TypedValue::Boolean { value: Some(true) },
            ),
            (
                "birth_date".to_string(),
                TypedValue::Date {
                    value: Some("2020-02-29".to_string()),
                },
            ),
            ("presence".to_string(), TypedValue::Presence { value: true }),
        ]
        .into_iter()
        .collect(),
    );
    let terminal = worker.evaluate(&first).await.expect("terminal fact round");
    assert!(terminal.operation_choices.is_empty());
    assert_eq!(
        terminal.facts.get("active"),
        Some(&TypedValue::Boolean { value: Some(true) })
    );
    assert_eq!(
        terminal.facts.get("birth_date"),
        Some(&TypedValue::Date {
            value: Some("2020-02-29".to_string())
        })
    );
    assert_eq!(
        terminal.facts.get("exists"),
        Some(&TypedValue::Presence { value: true })
    );
}

#[tokio::test]
async fn scrubbed_worker_has_no_environment_or_clock_api() {
    let worker = relay_worker();
    for expression in ["env_var(\"HOME\")", "timestamp()"] {
        let script = format!("fn consult(input, prior) {{ {expression} }}");
        assert_eq!(
            worker.evaluate(&request(script)).await,
            Err(WorkerError::ScriptRejected),
            "{expression} must be unavailable"
        );
    }
}

#[tokio::test]
async fn process_denies_instruction_depth_output_and_wall_time_overruns() {
    let worker = relay_worker();

    let mut instruction = request("fn consult(input, prior) { while true {} }");
    instruction.limits.max_operations = 100;
    assert_eq!(
        worker.evaluate(&instruction).await,
        Err(WorkerError::BudgetExceeded)
    );

    let mut depth =
        request("fn recurse(n) { recurse(n + 1) } fn consult(input, prior) { recurse(0) }");
    depth.limits.max_call_levels = 4;
    assert_eq!(
        worker.evaluate(&depth).await,
        Err(WorkerError::BudgetExceeded)
    );

    let payload = "x".repeat(400);
    let mut output = WorkerRequest::v1(
        format!(
            r#"fn consult(input, prior) {{ #{{ operations: [], facts: #{{ payload:
                #{{ type: "string", value: "{payload}" }}
            }} }} }}"#
        ),
        "consult",
        WorkerLimits::default(),
    );
    output.fact_schema.insert(
        "payload".to_string(),
        FactSchema {
            fact_type: FactType::String,
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

    let mut wall = request("fn consult(input, prior) { while true {} }");
    wall.limits.max_operations = 5_000_000;
    wall.limits.wall_time_ms = 1;
    // Parent startup grace lets the child report its own exact engine budget
    // exhaustion instead of conflating it with process startup timeout.
    assert_eq!(
        worker.evaluate(&wall).await,
        Err(WorkerError::BudgetExceeded)
    );
}

#[tokio::test]
async fn process_rejects_an_oversized_ipc_frame_before_worker_dispatch() {
    let worker = relay_worker();
    let mut oversized = request(format!("{DETERMINISTIC_SCRIPT}{}", " ".repeat(512)));
    oversized.limits.max_ipc_frame_bytes = 256;

    assert_eq!(
        worker.evaluate(&oversized).await,
        Err(WorkerError::RequestTooLarge)
    );
}

#[tokio::test]
async fn dedicated_process_enforces_runtime_string_and_collection_bounds() {
    let worker = relay_worker();

    let mut string = request(
        r#"
            fn consult(input, prior) {
                let value = input.seed;
                value += "5";
                #{ operations: [], facts: #{
                    active: #{ type: "boolean", value: true }
                }}
            }
        "#,
    );
    string.input.insert(
        "seed".to_string(),
        TypedValue::String {
            value: Some("12345678".to_string()),
        },
    );
    worker
        .evaluate(&string)
        .await
        .expect("the control string program is valid");
    string.limits.max_string_bytes = 8;
    assert_eq!(
        worker.evaluate(&string).await,
        Err(WorkerError::BudgetExceeded)
    );

    let mut array = request(
        r#"
            fn consult(input, prior) {
                let values = [1, 2];
                values.push(3);
                #{ operations: [], facts: #{
                    active: #{ type: "boolean", value: true }
                }}
            }
        "#,
    );
    worker
        .evaluate(&array)
        .await
        .expect("the control array program is valid");
    array.limits.max_array_items = 2;
    assert!(
        matches!(
            worker.evaluate(&array).await,
            Err(WorkerError::BudgetExceeded | WorkerError::ScriptRejected)
        ),
        "an array cannot grow beyond its closed collection bound"
    );

    let mut map = request(
        r#"
            fn consult(input, prior) {
                let values = #{ first: 1, second: 2 };
                values.third = 3;
                #{ operations: [], facts: #{
                    active: #{ type: "boolean", value: true }
                }}
            }
        "#,
    );
    worker
        .evaluate(&map)
        .await
        .expect("the control map program is valid");
    map.limits.max_map_entries = 2;
    assert!(
        matches!(
            worker.evaluate(&map).await,
            Err(WorkerError::BudgetExceeded | WorkerError::ScriptRejected)
        ),
        "a map cannot grow beyond its closed collection bound"
    );
}

#[tokio::test]
async fn cpu_bound_worker_is_terminated_within_the_os_cpu_ceiling() {
    let worker = relay_worker();
    let mut cpu = request("fn consult(input, prior) { while true {} }");
    cpu.limits.max_operations = 5_000_000;
    cpu.limits.wall_time_ms = 1_000;

    assert!(
        matches!(
            worker.evaluate(&cpu).await,
            Err(WorkerError::BudgetExceeded | WorkerError::IpcFailed)
        ),
        "the engine or the OS CPU rlimit must terminate a CPU-bound child"
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
async fn linux_worker_memory_exhaustion_is_contained_by_the_128_mib_process_ceiling() {
    let worker = relay_worker();
    let payload = "x".repeat(32 * 1024);
    let mut memory = request(format!(
        r#"
            fn consult(input, prior) {{
                let payload = "{payload}";
                let values = [];
                let index = 0;
                while index < 4096 {{
                    values.push(payload + index);
                    index += 1;
                }}
                #{{ operations: [], facts: #{{
                    active: #{{ type: "boolean", value: true }}
                }} }}
            }}
        "#
    ));
    memory.limits.max_operations = 5_000_000;
    memory.limits.max_string_bytes = 64 * 1024;
    memory.limits.max_array_items = 4_096;
    memory.limits.max_memory_bytes = 128 * MIB;
    memory.limits.max_ipc_frame_bytes = 128 * 1024;
    memory.limits.wall_time_ms = 5_000;

    assert!(
        matches!(
            worker.evaluate(&memory).await,
            Err(WorkerError::BudgetExceeded | WorkerError::IpcFailed)
        ),
        "allocation growth must not escape the Linux 128 MiB child-process ceiling"
    );
}
