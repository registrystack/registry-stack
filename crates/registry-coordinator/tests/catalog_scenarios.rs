// SPDX-License-Identifier: Apache-2.0
//! Synthetic authoring journeys. Product-policy and remote-acceptance proof
//! remains in client/service tests; this runner never constructs live adapters.

use registry_coordinator::{
    definition::Definition,
    protocol::Operation,
    runtime::RuntimeConfig,
    scenarios::{self, Recovery, Reply, ScenarioDocument},
};
use serde_json::json;
use std::path::{Path, PathBuf};

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples")
        .join(name)
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> (Definition, ScenarioDocument) {
    let root = example(name);
    (
        Definition::load(&root).unwrap(),
        scenarios::load(&root.join("scenarios.yaml")).unwrap(),
    )
}

#[test]
fn governed_action_example_covers_refusal_unknown_and_exact_command_recovery() {
    let (definition, document) = fixture("governed-action-follow-up");
    let reports = scenarios::check(&definition, &document).unwrap();
    assert_eq!(reports.len(), 6);
    assert!(matches!(
        &definition.workflow.steps["request-information"],
        registry_coordinator::definition::Step::Call {call, ..}
            if call.operation == Operation::InvokeBregAction
    ));
    let recovered = reports
        .iter()
        .find(|report| report.name == "action-response-loss-reuses-original-command")
        .unwrap();
    assert_eq!(recovered.call_attempts["request-information"], 2);
    assert_eq!(recovered.call_attempts["notify"], 1);
    assert_eq!(recovered.frozen_commands, 2);
    let stopped = reports
        .iter()
        .find(|report| report.name == "notice-refused-after-accepted-action")
        .unwrap();
    assert_eq!(stopped.state, "refused");
    assert_eq!(stopped.call_attempts["request-information"], 1);
    assert_eq!(stopped.call_attempts["notify"], 1);
    assert_eq!(stopped.frozen_commands, 2);

    let output = json!({"data":{"domainData":{"missingField":"proof of address"}}});
    let arguments = std::collections::BTreeMap::from([("read-application".into(), output)]);
    let request = definition
        .evaluate("request-information", &document.cases[0].input, &arguments)
        .unwrap();
    assert_eq!(request["action"], "request-information");
    assert_eq!(
        request["input"]["reason"],
        "Please provide proof of address"
    );
    assert!(request.get("profile").is_none());
    assert!(request.get("idempotencyKey").is_none());
}

#[test]
fn action_scenarios_cannot_invent_a_read_only_receipt() {
    let (definition, mut document) = fixture("governed-action-follow-up");
    let case = document
        .cases
        .iter_mut()
        .find(|case| case.name == "action-response-loss-reuses-original-command")
        .unwrap();
    case.recovery
        .insert("request-information".into(), Recovery::Reconcile);
    let error = scenarios::run(&definition, case)
        .err()
        .expect("the action client has no authoritative receipt-read contract");
    assert_eq!(error.code, "scenario.recovery");
}

#[test]
fn directory_examples_follow_the_configured_response_contract_offline() {
    let root = example("external-directory");
    let (definition, document) = fixture("external-directory");
    let checked = RuntimeConfig::check_file(&root.join("runtime.yaml"), false);
    assert!(
        checked
            .diagnostics
            .iter()
            .all(|finding| finding.severity != registry_platform_yaml::Severity::Error),
        "{:?}",
        checked.diagnostics
    );
    let loaded = checked.loaded.unwrap();
    let external = &loaded.config.external_http_connections["directory"];
    assert!(external.authorization.is_none());
    assert_eq!(external.attempt_timeout_milliseconds.get(), 2000);
    assert_eq!(external.maximum_response_bytes.get(), 65536);
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&external.response_schema.0)
        .unwrap();
    for case in &document.cases {
        for reply in &case.replies["lookup"] {
            if let Reply::Success { success } = reply {
                assert!(schema.is_valid(success));
            }
        }
    }
    let reports = scenarios::check(&definition, &document).unwrap();
    assert_eq!(reports.len(), 5);
    assert!(reports.iter().all(|report| report.frozen_commands == 0));
    assert_eq!(
        definition
            .evaluate("lookup", &json!({"district":"north"}), &Default::default())
            .unwrap(),
        json!({"path":"offices", "query":{"district":"north"}})
    );
}

#[test]
fn missing_synthetic_directory_reply_stops_without_live_fallback() {
    let (definition, mut document) = fixture("external-directory");
    document.cases[0].replies.clear();
    let error = scenarios::run(&definition, &document.cases[0])
        .err()
        .expect("a live configured endpoint must not fill a missing fixture");
    assert_eq!(error.code, "scenario.reply");
}

#[test]
fn scenario_recovery_and_reply_names_must_resolve_to_call_steps() {
    let (definition, mut document) = fixture("external-directory");
    let case = &mut document.cases[0];
    case.recovery.insert("lookup".into(), Recovery::Reconcile);
    assert_eq!(
        scenarios::run(&definition, case).err().unwrap().code,
        "scenario.recovery"
    );
    case.recovery.clear();
    case.replies.insert(
        "unregistered-step".into(),
        vec![Reply::Success { success: json!({}) }],
    );
    assert_eq!(
        scenarios::run(&definition, case).err().unwrap().code,
        "scenario.reply-step"
    );
}

#[test]
fn both_example_deployments_check_without_resolving_credentials() {
    for name in ["governed-action-follow-up", "external-directory"] {
        let checked = RuntimeConfig::check_file(&example(name).join("runtime.yaml"), false);
        assert!(
            checked
                .diagnostics
                .iter()
                .all(|finding| finding.severity != registry_platform_yaml::Severity::Error),
            "{:?}",
            checked.diagnostics
        );
        let definition = Definition::load(&example(name)).unwrap();
        checked
            .loaded
            .unwrap()
            .config
            .validate_workflow(&definition.workflow)
            .unwrap();
    }
}
