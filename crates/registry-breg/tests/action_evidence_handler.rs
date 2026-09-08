// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    action_handler::{evaluate_action_with_evidence, ActionHandlerError},
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn action(script: &str) -> registry_breg::model::CompiledAction {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/farmer-landholding-evidence");
    let project = parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    let mut assets: Vec<_> = project
        .actions
        .iter()
        .filter_map(|action| action.handler.as_ref())
        .map(|handler| ModuleAssetSource {
            module: None,
            path: handler.script.clone(),
            bytes: if handler.script.ends_with("register-landholding.rhai") {
                script.as_bytes().to_vec()
            } else {
                std::fs::read(root.join(&handler.script)).unwrap()
            },
        })
        .collect();
    assets.extend(
        project
            .evidence_providers
            .iter()
            .map(|provider| ModuleAssetSource {
                module: None,
                path: provider.contracts.clone(),
                bytes: std::fs::read(root.join(&provider.contracts)).unwrap(),
            }),
    );
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .unwrap()
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-landholding")
        .unwrap()
        .clone()
}
fn inputs() -> serde_json::Map<String, Value> {
    json!({"farmer-prefix":"TH", "farmer-number":"00042", "parcel-code":"P42", "include-category":false}).as_object().unwrap().clone()
}

#[test]
fn invalid_helper_types_poison_caught_calls_before_resolver_and_effects() {
    for call in [
        "evidence::resolve(42, #{})",
        "evidence::resolve(\"farmer-status\", 42)",
        "evidence::resolve(\"unknown\", #{})",
        "evidence::resolve(\"farmer-status\", #{farmer: #{\"farmer-number\": 42}})",
    ] {
        let script = format!("fn handle(ctx) {{ try {{ {call}; }} catch (error) {{ }} try {{ evidence::resolve(\"farmer-status\", #{{farmer: #{{\"farmer-number\": \"TH-00042\"}}}}); }} catch (error) {{ }} #{{effects: [#{{id: \"landholding\", set: #{{\"farmer-number\": \"TH-00042\", \"parcel-code\": \"P42\"}}}}]}} }}");
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let result = evaluate_action_with_evidence(
            &action(&script),
            &inputs(),
            Instant::now() + Duration::from_secs(2),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"active":true}))
            },
        );
        assert_eq!(result.unwrap_err().kind, ActionHandlerError::Evidence);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn repeated_capability_and_invalid_mock_output_poison_the_whole_evaluation() {
    let script = "fn handle(ctx) { let subjects = #{farmer: #{\"farmer-number\": \"TH-00042\"}}; try { evidence::resolve(\"farmer-status\", subjects); evidence::resolve(\"farmer-status\", subjects); } catch (error) {} #{effects: [#{id: \"landholding\", set: #{\"farmer-number\": \"TH-00042\", \"parcel-code\": \"P42\"}}]} }";
    for response in [json!({"active":true}), json!({"active":"canary-value"})] {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let result = evaluate_action_with_evidence(
            &action(script),
            &inputs(),
            Instant::now() + Duration::from_secs(2),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(response.clone())
            },
        );
        assert_eq!(result.unwrap_err().kind, ActionHandlerError::Evidence);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
