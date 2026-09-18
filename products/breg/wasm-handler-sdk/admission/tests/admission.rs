// SPDX-License-Identifier: Apache-2.0
//! The admission proof over the built template modules.
//!
//! Part 1 proves authoring admission: each `artifacts/*.wasm` module compiles
//! into the handler inventory with its bytes and hash captured, exactly the
//! way `crates/registry-breg/tests/wasm_handler_admission.rs` compiles its
//! fixtures (through `compile_project_with_assets`, whose compiler validates
//! the module against the platform guest ABI before accepting it).
//!
//! Part 2 proves the ordinary module's fixture outcomes through the
//! registry's real evaluation entry: `evaluate_action_detailed` admits the
//! inputs, builds the `{"inputs": ...}` envelope, runs the module through
//! the process runtime (default budgets and backend), and decodes the
//! outcome bytes through the same shared validator the Rhai path uses.
//! Every corpus case must produce its exact outcome: accepted effects with
//! the exact E.164 literal, or the declared refusal with its catalogue
//! label. The byte-level sibling pins the same documents straight from the
//! platform executor under both execution backends.
//!
//! Part 3 covers the pre-initialized variant, which sits between the 2 MiB
//! default execution ceiling and the 5 MiB structural admission ceiling on
//! purpose: it is admitted (part 1), refused typed by the default-budget
//! runtime, and exact under the operator-configured 5 MiB module ceiling at
//! the executor. That is the two-tier ceiling story demonstrated from the
//! guest side; it only runs when `scripts/build.sh --preinit` produced the
//! artifact.
//!
//! The proof needs built modules: run `scripts/build.sh` first (the script
//! runs this proof itself unless `--skip-proof` is given). The module
//! artifacts are generated outputs, never committed; `scripts/build.sh` is
//! their documented generator, and `artifacts/module-sizes.tsv` records the
//! bytes and sha256 of each run.

use std::time::{Duration, Instant};

use breg_wasm_admission_proof as proof;
use registry_breg::action_handler::{
    ActionHandlerError, ActionHandlerOutcome, ActionHandlerRefusal, evaluate_action_detailed,
};
use registry_breg::model::{CompiledAction, CompiledActionMutation, CompiledActionValue};
use registry_platform_script::wasm::Backend;
use serde_json::Value;

use breg_wasm_admission_proof::{
    DEFAULT_MODULE_CEILING, PREINIT_MODULE_CEILING as STRUCTURAL_MODULE_CEILING,
};

const ORDINARY_MODULE: &str = "breg_wasm_handler_template.wasm";
const PREINIT_MODULE: &str = "breg_wasm_handler_template.preinit.wasm";

/// The one module named `name`, when the build produced it.
fn built_module(name: &str) -> Option<Vec<u8>> {
    proof::built_modules()
        .into_iter()
        .find(|(file, _)| file == name)
        .map(|(_, bytes)| bytes)
}

fn compiled_action(registry: &registry_breg::CompiledRegistry) -> CompiledAction {
    registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "normalize-phone")
        .expect("the phone action compiled")
        .clone()
}

#[test]
fn the_built_modules_pass_authoring_admission() {
    for (name, bytes) in proof::built_modules() {
        assert!(
            bytes.len() <= STRUCTURAL_MODULE_CEILING,
            "{name}: over the structural admission ceiling"
        );
        let registry = proof::compile_with_module(bytes.clone())
            .unwrap_or_else(|failure| panic!("{name}: admission refused the module: {failure:?}"));
        let handler = compiled_action(&registry)
            .handler
            .expect("the action declares a handler");
        assert_eq!(
            handler.kind,
            registry_breg::model::CompiledActionHandlerKind::Wasm,
            "{name}: the handler compiled as wasm"
        );
        assert_eq!(handler.module_path, "wasm/handler.wasm");
        assert_eq!(handler.module_bytes, bytes, "{name}: the bytes traveled");
        assert_eq!(
            handler.module_sha256.as_deref(),
            Some(proof::sha256(&bytes).as_str()),
            "{name}: the hash matches the bytes"
        );
        assert!(
            handler.writes.iter().any(|write| write.id == "phone"),
            "{name}: the declared write slot compiled"
        );
        // The refusal catalogue compiled with the labels the proof pins.
        for (code, label) in [
            (
                "invalid-phone",
                "The phone number is not a valid phone number.",
            ),
            ("invalid-region", "The region is not a usable phone region."),
        ] {
            assert_eq!(
                handler.refusals.get(code).map(String::as_str),
                Some(label),
                "{name}: the {code} refusal label compiled"
            );
        }
    }
}

#[test]
fn the_ordinary_module_produces_its_exact_registry_outcomes() {
    proof::install_runtime_once();
    let bytes = built_module(ORDINARY_MODULE).expect("the ordinary module was built");
    assert!(
        bytes.len() <= DEFAULT_MODULE_CEILING,
        "the ordinary module must fit the default execution ceiling"
    );
    let registry =
        proof::compile_with_module(bytes).expect("admission accepts the ordinary module");
    let action = compiled_action(&registry);
    for case in &proof::corpus() {
        let inputs = case.inputs.as_object().expect("inputs is an object");
        let outcome =
            evaluate_action_detailed(&action, inputs, Instant::now() + Duration::from_secs(60))
                .unwrap_or_else(|diagnostic| {
                    panic!("{}: evaluation refused: {diagnostic:?}", case.name)
                });
        let expected = &case.expected;
        if let Some(refusal) = expected.get("refusal") {
            let outcome = match outcome {
                ActionHandlerOutcome::Refusal(refusal) => refusal,
                other => panic!("{}: expected a refusal, got {other:?}", case.name),
            };
            assert_eq!(
                outcome,
                ActionHandlerRefusal {
                    code: refusal["code"].as_str().unwrap().to_owned(),
                    label: catalogue_label(refusal["code"].as_str().unwrap()),
                    field: refusal
                        .get("field")
                        .map(|field| field.as_str().unwrap().to_owned()),
                },
                "{}: the refusal outcome differs",
                case.name
            );
        } else {
            let effects = match outcome {
                ActionHandlerOutcome::Effects(effects) => effects,
                other => panic!("{}: expected effects, got {other:?}", case.name),
            };
            assert_eq!(
                set_literals(&effects),
                expected["effects"][0]["set"],
                "{}: the effects differ",
                case.name
            );
        }
    }
}

#[test]
fn the_ordinary_module_outcome_documents_are_exact_at_the_byte_level() {
    let bytes = built_module(ORDINARY_MODULE).expect("the ordinary module was built");
    // The ordinary module runs under the default budgets: no operator
    // configuration required. Both execution backends must agree.
    for backend in [Backend::Native, Backend::Pulley] {
        let prepared = proof::executor(backend, DEFAULT_MODULE_CEILING)
            .prepare(&bytes)
            .unwrap_or_else(|error| panic!("[{backend:?}]: prepare refused: {error}"));
        for case in &proof::corpus() {
            let invoked = proof::executor(backend, DEFAULT_MODULE_CEILING)
                .invoke(&prepared, &proof::envelope(case))
                .unwrap_or_else(|error| {
                    panic!("{} [{backend:?}]: invoke failed: {error}", case.name)
                });
            let document: Value = serde_json::from_slice(&invoked.output)
                .unwrap_or_else(|error| panic!("{}: outcome bytes: {error}", case.name));
            assert_eq!(
                document, case.expected,
                "{} [{backend:?}]: the outcome document differs",
                case.name
            );
        }
    }
}

#[test]
fn the_preinitialized_module_needs_the_configured_ceiling_and_is_exact_under_it() {
    let Some(bytes) = built_module(PREINIT_MODULE) else {
        // --preinit is optional; without it there is nothing to prove here.
        return;
    };
    assert!(
        bytes.len() > DEFAULT_MODULE_CEILING,
        "a pre-initialized library module is expected past the default ceiling"
    );

    // Under the default execution budgets, the process runtime refuses it
    // typed: admission accepted the module (structural ceiling), execution
    // holds the operator's default. That boundary is the two-tier ceiling.
    proof::install_runtime_once();
    let registry =
        proof::compile_with_module(bytes.clone()).expect("admission accepts the preinit module");
    let action = compiled_action(&registry);
    let case = &proof::corpus()[0];
    let diagnostic = evaluate_action_detailed(
        &action,
        case.inputs.as_object().unwrap(),
        Instant::now() + Duration::from_secs(60),
    )
    .expect_err("the default-budget runtime must refuse an over-ceiling module");
    assert_eq!(diagnostic.kind, ActionHandlerError::Resource);

    // Under the operator-configured 5 MiB module ceiling, the executor
    // prepares it and every corpus case is exact, on both backends.
    for backend in [Backend::Native, Backend::Pulley] {
        let prepared = proof::executor(backend, STRUCTURAL_MODULE_CEILING)
            .prepare(&bytes)
            .unwrap_or_else(|error| panic!("[{backend:?}]: prepare refused: {error}"));
        for case in &proof::corpus() {
            let invoked = proof::executor(backend, STRUCTURAL_MODULE_CEILING)
                .invoke(&prepared, &proof::envelope(case))
                .unwrap_or_else(|error| {
                    panic!("{} [{backend:?}]: invoke failed: {error}", case.name)
                });
            let document: Value = serde_json::from_slice(&invoked.output)
                .unwrap_or_else(|error| panic!("{}: outcome bytes: {error}", case.name));
            assert_eq!(
                document, case.expected,
                "{} [{backend:?}]: the outcome document differs",
                case.name
            );
        }
    }
}

/// The label the catalogue carries for this refusal's code.
fn catalogue_label(code: &str) -> String {
    match code {
        "invalid-phone" => "The phone number is not a valid phone number.".to_owned(),
        "invalid-region" => "The region is not a usable phone region.".to_owned(),
        other => panic!("no catalogue label pinned for {other}"),
    }
}

/// The set literals of an accepted effects outcome, as a JSON object keyed by
/// field, so an expected document compares field by field.
fn set_literals(effects: &[registry_breg::model::CompiledActionEffect]) -> Value {
    assert_eq!(effects.len(), 1, "one effect against the phone slot");
    assert_eq!(effects[0].id, "phone");
    let mut set = serde_json::Map::new();
    for mutation in &effects[0].mutations {
        let CompiledActionMutation::Set { field, value } = mutation else {
            panic!("the phone create sets fields, it never clears");
        };
        let CompiledActionValue::Literal { value } = value else {
            panic!("the reference-free phone slot takes literals only");
        };
        set.insert(field.clone(), value.clone());
    }
    Value::Object(set)
}
