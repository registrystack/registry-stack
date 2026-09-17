// SPDX-License-Identifier: Apache-2.0
//! Coverage for the crate-private AST-cached Rhai benchmark variant.
//!
//! The cached-program seam (`CachedActionHandlerProgram` plus
//! `evaluate_with_cached_program`) exists so an in-crate benchmark can reuse a
//! compiled handler program across calls while every other per-call property
//! stays identical to `evaluate_with_engine`: fresh engine per call, the same
//! admission checks, the same context construction, limits, resolver
//! registration path shape, and result decoding. The database-free tests here
//! drive the v1-style path without a resolver, matching what the
//! characterization suite covers. The timing test at the bottom is a benchmark
//! variant only: it is ignored by default and must be run explicitly with a
//! release-equivalent profile and `--nocapture`.

use std::time::{Duration, Instant};

use super::{
    compile_source_for_abi, evaluate_admitted_action_detailed, evaluate_with_cached_program,
    ActionHandlerError, ActionHandlerOutcome, CachedActionHandlerProgram,
};
use crate::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, parse_project_yaml, ModuleAssetSource},
    model::{CompiledAction, CompiledActionMutation, CompiledActionValue},
    rhai_planner,
};
use serde_json::{json, Map, Value};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// The register-person handler from the unchanged Rhai acceptance fixture.
fn acceptance_action() -> CompiledAction {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai");
    let project = parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    let assets = project
        .actions
        .iter()
        .filter_map(|action| action.handler.as_ref())
        .map(|handler| ModuleAssetSource {
            module: None,
            path: handler.script.clone(),
            bytes: std::fs::read(root.join(&handler.script)).unwrap(),
        })
        .collect::<Vec<_>>();
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .unwrap()
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-person")
        .cloned()
        .expect("register-person action")
}

/// An acceptance example pair as (inputs, expected outcome JSON).
fn acceptance_example(name: &str) -> (Map<String, Value>, Value) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai/examples");
    let inputs: Value =
        serde_json::from_slice(&std::fs::read(root.join(format!("{name}.input.json"))).unwrap())
            .unwrap();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(root.join(format!("{name}.expect.json"))).unwrap())
            .unwrap();
    (inputs.as_object().expect("object inputs").clone(), expected)
}

/// The handler shape the characterization suite compiles: the same synthetic
/// project and write slots as `tests/script_baseline.rs`.
fn characterization_action(script: &str) -> CompiledAction {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"script-baseline","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"record","primaryDataset":"baseline","route":"records","mutationMode":"mutable","fields":[
            {"id":"label","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"classification":"restricted"}
        ]}],
        "actions":[{"id":"register-record","inputs":[
            {"id":"label","apiName":"displayLabel","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"count","type":"int64","required":true,"classification":"restricted"},
            {"id":"amount","type":"decimal","precision":20,"scale":2,"required":true,"classification":"restricted"},
            {"id":"note","type":"string","maxLength":80,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/baseline.rhai","abi":"registry.action-handler/v1",
            "refusals":[{"code":"blank-label","label":"A label is required."}],
            "writes":[{"id":"record","target":{"entity":"record"},"operation":"create","fields":["label","count","amount"]}]
        }}],
        "accessProfiles":[{"id":"writer","default":true,"principalClaim":"principal","permissions":[
            {"action":"register-record","operations":["invoke"],"targets":[{"entity":"record","rowBoundaries":[]}],"results":["record"]}
        ]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/baseline.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
    .actions()
    .actions[0]
        .clone()
}

fn characterization_inputs() -> Map<String, Value> {
    json!({"label":" Alpha ","count":7,"amount":"123456789012345678.90"})
        .as_object()
        .unwrap()
        .clone()
}

fn assert_matches_expectation(outcome: &ActionHandlerOutcome, expected: &Value, case: &str) {
    match outcome {
        ActionHandlerOutcome::Effects(effects) => {
            assert_eq!(effects.len(), 1, "{case}");
            assert_eq!(effects[0].id, "person", "{case}");
            let mut set = Map::new();
            for mutation in &effects[0].mutations {
                match mutation {
                    CompiledActionMutation::Set {
                        field,
                        value: CompiledActionValue::Literal { value },
                    } => {
                        set.insert(field.clone(), value.clone());
                    }
                    _ => panic!("{case}: fixture expects literal set mutations"),
                }
            }
            assert_eq!(
                json!({"effects": [{"id": "person", "set": set}]}),
                *expected,
                "{case}: verified effects differ from fixture expectation"
            );
        }
        ActionHandlerOutcome::Refusal(refusal) => {
            assert_eq!(
                json!({"refusal": {"code": refusal.code, "field": refusal.field}}),
                *expected,
                "{case}: verified refusal differs from fixture expectation"
            );
        }
    }
}

/// Differential proof for the benchmark variant: reusing one compiled program
/// across repeated calls produces outcomes identical to the fresh-compile
/// path on the acceptance handler, including its declared refusal cases.
#[test]
fn cached_program_outcomes_match_fresh_evaluation_on_the_acceptance_handler() {
    let action = acceptance_action();
    let program = CachedActionHandlerProgram::compile(&action).unwrap();
    for case in [
        "blank-name",
        "family-only",
        "full-name",
        "given-only",
        "internal-spaces",
        "null-family",
        "null-given",
        "null-name",
        "omitted-name",
    ] {
        let (inputs, expected) = acceptance_example(case);
        let fresh = super::evaluate_action_detailed(&action, &inputs, deadline()).unwrap();
        assert_matches_expectation(&fresh, &expected, case);
        for _ in 0..3 {
            let cached =
                evaluate_with_cached_program(&action, &program, &inputs, deadline(), None, None)
                    .unwrap_or_else(|error| panic!("{case}: cached evaluation failed: {error:?}"));
            let admitted = evaluate_admitted_action_detailed(&action, &inputs, deadline())
                .unwrap_or_else(|error| panic!("{case}: fresh evaluation failed: {error:?}"));
            assert_eq!(cached, fresh, "{case}: cached outcome drifted from fresh");
            assert_eq!(
                admitted, fresh,
                "{case}: admitted outcome drifted from public"
            );
        }
    }
}

/// The same differential equality over the handler shapes the characterization
/// suite uses, plus identical static error classification on failure paths.
#[test]
fn cached_program_outcomes_match_fresh_evaluation_on_characterization_handler_shapes() {
    let scripts = [
        // Helpers, collections, conditionals, and scalar arithmetic.
        r#"private fn clean(value) { value.trim(); value }
        fn handle(ctx) {
            let parts = [clean(ctx.inputs.label), "record"];
            let label = "";
            for part in parts {
                if label != "" { label += "-"; }
                label += part;
            }
            #{effects:[#{id:"record",set:#{label:label,count:ctx.inputs.count / 2 + 1,amount:ctx.inputs.amount}}]}
        }"#,
        // A declared refusal is a successful business outcome.
        r#"fn handle(ctx) { #{refusal:#{code:"blank-label",field:"label"}} }"#,
    ];
    for script in scripts {
        let action = characterization_action(script);
        let program = CachedActionHandlerProgram::compile(&action).unwrap();
        let mut inputs = characterization_inputs();
        inputs.remove("note");
        let fresh = evaluate_admitted_action_detailed(&action, &inputs, deadline()).unwrap();
        for _ in 0..3 {
            let cached =
                evaluate_with_cached_program(&action, &program, &inputs, deadline(), None, None)
                    .unwrap();
            assert_eq!(cached, fresh, "cached outcome drifted from fresh");
        }
    }
    for (script, expected) in [
        (
            "fn handle(ctx) { throw ctx.inputs.label; }",
            ActionHandlerError::Execution,
        ),
        ("fn handle(ctx) { 42 }", ActionHandlerError::Result),
    ] {
        let action = characterization_action(script);
        let program = CachedActionHandlerProgram::compile(&action).unwrap();
        let inputs = characterization_inputs();
        let fresh = evaluate_admitted_action_detailed(&action, &inputs, deadline()).unwrap_err();
        let cached =
            evaluate_with_cached_program(&action, &program, &inputs, deadline(), None, None)
                .unwrap_err();
        assert_eq!(cached, fresh, "cached error classification drifted");
        assert_eq!(cached.kind, expected);
    }
}

/// The program is bound to the handler it was compiled from: offering a
/// program compiled for one source against a different handler source is a
/// source error, never a silent evaluation of the wrong program.
#[test]
fn cached_program_refuses_evaluation_for_a_different_handler_source() {
    let compiled = characterization_action(
        r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:"compiled"}}]} }"#,
    );
    let other = characterization_action(
        r#"fn handle(ctx) { #{effects:[#{id:"record",set:#{label:"other"}}]} }"#,
    );
    let program = CachedActionHandlerProgram::compile(&compiled).unwrap();
    let error = evaluate_with_cached_program(
        &other,
        &program,
        &characterization_inputs(),
        deadline(),
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, ActionHandlerError::Source);
    // The matching source still evaluates through the cached program.
    assert!(evaluate_with_cached_program(
        &compiled,
        &program,
        &characterization_inputs(),
        deadline(),
        None,
        None
    )
    .is_ok());
}

/// A fixed action without a handler has no program to cache.
#[test]
fn cached_program_compile_requires_a_declared_handler() {
    let mut action = characterization_action("fn handle(ctx) { 42 }");
    action.handler = None;
    assert!(matches!(
        CachedActionHandlerProgram::compile(&action),
        Err(ActionHandlerError::Source)
    ));
}

struct PhaseStatistics {
    count: usize,
    p50_us: f64,
    p99_us: f64,
}

/// Nearest-rank percentiles over pooled per-call samples, in microseconds.
fn summarize_micros(samples: &[u128]) -> PhaseStatistics {
    assert!(!samples.is_empty(), "at least one sample is required");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let nearest_rank = |percentile: u128| -> u128 {
        let index = percentile
            .checked_mul(sorted.len() as u128)
            .and_then(|value| value.checked_add(99))
            .map(|value| value / 100)
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(0);
        sorted[index.min((sorted.len() - 1) as u128) as usize]
    };
    PhaseStatistics {
        count: sorted.len(),
        p50_us: nearest_rank(50) as f64 / 1_000.0,
        p99_us: nearest_rank(99) as f64 / 1_000.0,
    }
}

#[test]
fn phase_statistics_use_nearest_rank_percentiles() {
    let statistics = summarize_micros(&[1_000, 100, 400, 200]);
    assert_eq!(statistics.count, 4);
    assert_eq!(statistics.p50_us, 0.2);
    assert_eq!(statistics.p99_us, 1.0);
    let singleton = summarize_micros(&[7]);
    assert_eq!(singleton.p50_us, 0.007);
    assert_eq!(singleton.p99_us, 0.007);
    let ramp = summarize_micros(
        &(1..=10_000u128)
            .map(|value| value * 100)
            .collect::<Vec<_>>(),
    );
    assert_eq!(ramp.count, 10_000);
    assert_eq!(ramp.p50_us, 500.0);
    assert_eq!(ramp.p99_us, 990.0);
}

/// Benchmark variant timing. Not part of the ordinary suite: run explicitly
/// with the pinned toolchain and a release-equivalent profile, for example
/// (workspace `[profile.release]`: codegen-units 1, thin LTO, stripped
/// symbols):
///
/// ```text
/// CARGO_INCREMENTAL=0 cargo test --release --locked -p registry-breg --lib \
///     action_handler_benchmark_tests -- --ignored --nocapture --test-threads=1
/// ```
///
/// Times, for the unchanged acceptance handler and the `full-name` inputs:
/// engine construction alone, `compile_source_for_abi` alone (the per-call
/// work the cached variant replaces with its bound-program check plus a
/// one-time preparation), and the admitted evaluation call for both variants.
/// Every evaluation goes through the same admission checks as a real call:
/// a far-future deadline and no resolver.
#[test]
#[ignore = "timing benchmark: run explicitly with --release and --nocapture"]
fn benchmark_variant_times_engine_construction_compilation_and_evaluation() {
    const WARMUP_CALLS: usize = 500;
    const REPETITIONS: usize = 3;
    const CONSTRUCTION_CALLS: usize = 10_000;
    const COMPILATION_CALLS: usize = 2_000;
    const BINDING_CALLS: usize = 10_000;
    const PREPARATION_CALLS: usize = 200;
    const EVALUATION_CALLS: usize = 10_000;

    fn measure(repetitions: usize, calls: usize, mut operation: impl FnMut()) -> Vec<u128> {
        let mut samples = Vec::with_capacity(repetitions * calls);
        for _ in 0..repetitions {
            for _ in 0..calls {
                let start = Instant::now();
                operation();
                samples.push(start.elapsed().as_nanos());
            }
        }
        samples
    }

    fn report(phase: &str, variant: &str, samples: &[u128]) {
        let statistics = summarize_micros(samples);
        println!(
            "phase={phase} variant={variant} p50_us={:.1} p99_us={:.1} calls={}",
            statistics.p50_us, statistics.p99_us, statistics.count
        );
    }

    let far_future = || Instant::now() + Duration::from_secs(3_600);
    let action = acceptance_action();
    let (inputs, _) = acceptance_example("full-name");
    let handler = action.handler.as_ref().expect("declared handler");
    let source = std::str::from_utf8(&handler.script_bytes).unwrap();

    // Warm both variants so lazy allocator and Rhai state fall outside the samples.
    for _ in 0..WARMUP_CALLS {
        evaluate_admitted_action_detailed(&action, &inputs, far_future()).unwrap();
    }
    let program = CachedActionHandlerProgram::compile(&action).unwrap();
    for _ in 0..WARMUP_CALLS {
        evaluate_with_cached_program(&action, &program, &inputs, far_future(), None, None).unwrap();
    }

    // (a) Engine construction alone: identical fresh-engine-per-call work in
    // both variants; the cached variant does not change this phase.
    let deadline = far_future();
    report(
        "engine_construction",
        "current",
        &measure(REPETITIONS, CONSTRUCTION_CALLS, || {
            drop(rhai_planner::engine(Some(deadline)));
        }),
    );
    let deadline = far_future();
    report(
        "engine_construction",
        "cached",
        &measure(REPETITIONS, CONSTRUCTION_CALLS, || {
            drop(rhai_planner::engine(Some(deadline)));
        }),
    );

    // (b) Compilation alone: the current variant compiles the validated
    // source on every call; the cached variant replaces that per-call work
    // with the bound-program check and pays compilation once at preparation.
    report(
        "compilation",
        "current",
        &measure(REPETITIONS, COMPILATION_CALLS, || {
            drop(compile_source_for_abi(source, &handler.abi).unwrap());
        }),
    );
    report(
        "compilation",
        "cached",
        &measure(REPETITIONS, BINDING_CALLS, || {
            let _ = program.bound_ast(handler).unwrap();
        }),
    );
    report(
        "program_preparation",
        "cached",
        &measure(REPETITIONS, PREPARATION_CALLS, || {
            drop(CachedActionHandlerProgram::compile(&action).unwrap());
        }),
    );

    // (c) The evaluation call alone, through the admitted evaluation entry of
    // each variant: admission, program (compiled or cached), fresh engine,
    // call, and result decoding. Input-shape validation is identical for both
    // variants and excluded from both.
    report(
        "evaluation_call",
        "current",
        &measure(REPETITIONS, EVALUATION_CALLS, || {
            drop(evaluate_admitted_action_detailed(&action, &inputs, far_future()).unwrap());
        }),
    );
    report(
        "evaluation_call",
        "cached",
        &measure(REPETITIONS, EVALUATION_CALLS, || {
            drop(
                evaluate_with_cached_program(&action, &program, &inputs, far_future(), None, None)
                    .unwrap(),
            )
        }),
    );

    let fresh = evaluate_admitted_action_detailed(&action, &inputs, far_future()).unwrap();
    let cached =
        evaluate_with_cached_program(&action, &program, &inputs, far_future(), None, None).unwrap();
    assert_eq!(cached, fresh, "benchmark loop changed the cached outcome");
}
