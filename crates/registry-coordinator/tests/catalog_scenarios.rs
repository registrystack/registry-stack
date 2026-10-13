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

const SCENARIOS_MODELINE: &str = "# yaml-language-server: $schema=https://id.registrystack.org/schemas/coordinator/scenarios/scenarios.v1alpha1.schema.json";

#[test]
fn every_example_has_editor_checked_scenarios_covering_its_outcomes_and_a_stopped_run() {
    let examples =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/coordinator/examples");
    let mut checked = 0;
    for entry in std::fs::read_dir(examples).unwrap() {
        let root = entry.unwrap().path().canonicalize().unwrap();
        if !root.join("workflow.yaml").is_file() {
            continue;
        }
        let file = root.join("scenarios.yaml");
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|_| panic!("{} has no scenarios.yaml", root.display()));
        assert_eq!(
            text.lines().next(),
            Some(SCENARIOS_MODELINE),
            "{}",
            file.display()
        );
        let definition = Definition::load(&root).unwrap();
        let document = scenarios::load(&file).unwrap();
        let reports = scenarios::check(&definition, &document)
            .unwrap_or_else(|error| panic!("{}: {error:?}", file.display()));
        let reached = reports
            .iter()
            .filter_map(|report| report.outcome.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        for outcome in definition.workflow.outcomes.keys() {
            assert!(
                reached.contains(outcome.as_str()),
                "{}: no case ends with outcome {outcome}",
                file.display()
            );
        }
        assert!(
            reports.iter().any(|report| report.state != "completed"),
            "{}: no case stops on a refusal or failure",
            file.display()
        );
        checked += 1;
    }
    assert!(checked >= 7, "found {checked} example projects");
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
    assert_eq!(reports.len(), 8);
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
    let declared = reports
        .iter()
        .find(|report| report.name == "action-declared-refusal")
        .unwrap();
    assert_eq!(declared.state, "completed");
    assert_eq!(
        declared.outcome.as_deref(),
        Some("information-request-refused")
    );
    assert_eq!(
        declared.output,
        Some(json!({"refusalCode": "already-requested"}))
    );
    assert!(!declared.call_attempts.contains_key("notify"));
    let still_unknown = reports
        .iter()
        .find(|report| report.name == "action-response-loss-then-declared-refusal-stays-unknown")
        .unwrap();
    assert_eq!(still_unknown.state, "uncertain");
    assert_eq!(still_unknown.call_attempts["request-information"], 2);
    assert!(!still_unknown.call_attempts.contains_key("notify"));

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
fn declared_refusal_without_an_authored_edge_preserves_refused_behavior() {
    let source = example("governed-action-follow-up");
    let root = tempfile::tempdir().unwrap();
    let workflow = std::fs::read_to_string(source.join("workflow.yaml")).unwrap();
    let workflow = workflow.replace("    onDeclaredRefusal: action-refused\n", "");
    let workflow = workflow.replace(
        "  action-refused:\n    type: finish\n    outcome: information-request-refused\n    output:\n      type: fields\n      fields:\n        refusalCode: {type: step, step: request-information, path: /refusalCode}\n",
        "",
    );
    let workflow = workflow.replace(
        "  information-request-refused:\n    type: object\n    additionalProperties: false\n    required: [refusalCode]\n    properties:\n      refusalCode: {type: string, minLength: 1, maxLength: 128}\n",
        "",
    );
    assert!(!workflow.contains("onDeclaredRefusal"));
    assert!(!workflow.contains("information-request-refused"));
    std::fs::write(root.path().join("workflow.yaml"), workflow).unwrap();
    std::fs::copy(
        source.join("functions.rhai"),
        root.path().join("functions.rhai"),
    )
    .unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let mut document = scenarios::load(&source.join("scenarios.yaml")).unwrap();
    let scenario = document
        .cases
        .iter_mut()
        .find(|scenario| scenario.name == "action-declared-refusal")
        .unwrap();
    scenario.expect.path = vec![
        "read-application".into(),
        "needs-information".into(),
        "request-information".into(),
    ];
    scenario.expect.state = "refused".into();
    scenario.expect.outcome = None;
    scenario.expect.skip_outcome_check = false;
    scenario.expect.output = None;

    let report = scenarios::run(&definition, scenario).unwrap();
    assert_eq!(report.state, "refused");
    assert_eq!(report.outcome, None);
}

#[test]
fn bounded_poll_example_rereads_a_fixed_number_of_times_and_returns_control() {
    use registry_coordinator::definition::Step;
    let (definition, document) = fixture("bounded-poll");
    // A finite, acyclic graph polls by unrolling: one timed wait before each read.
    let steps = definition.workflow.steps.values();
    let reads = steps
        .clone()
        .filter(|step| matches!(step, Step::Call { call, .. } if call.operation == Operation::ReadRecord))
        .count();
    let waits = steps
        .filter(|step| matches!(step, Step::WaitUntil { .. }))
        .count();
    assert_eq!((waits, reads), (3, 3));

    let reports = scenarios::check(&definition, &document).unwrap();
    let report = |name: &str| {
        reports
            .iter()
            .find(|report| report.name == name)
            .unwrap_or_else(|| panic!("no case {name}"))
    };
    let first = report("decided-at-first-check");
    assert_eq!(first.path, ["wait-1", "read-1", "check-1", "decided-1"]);
    assert_eq!(first.output, Some(json!({"decision": "approved"})));
    let third = report("decided-at-third-check");
    assert_eq!(third.outcome.as_deref(), Some("decided"));
    assert_eq!(third.output, Some(json!({"decision": "rejected"})));
    assert_eq!(third.call_attempts["read-3"], 1);
    // After the last read the run finishes and the caller decides what is next.
    let pending = report("still-pending-after-three-checks");
    assert_eq!(pending.state, "completed");
    assert_eq!(pending.outcome.as_deref(), Some("still-pending"));
    assert_eq!(
        pending.path.last().map(String::as_str),
        Some("still-pending")
    );
    assert_eq!(pending.elapsed_seconds, 3 * 86_400);
    for read in ["read-1", "read-2", "read-3"] {
        assert_eq!(pending.call_attempts[read], 1, "{read}");
    }
    let refused = report("refused-read-ends-the-poll");
    assert_eq!(refused.state, "refused");
    assert!(!refused.call_attempts.contains_key("read-3"));
    // A wait that would end after the run deadline expires the run instead.
    let late = report("late-first-check-reaches-the-deadline");
    assert_eq!(late.state, "deadline-exceeded");
    assert_eq!(late.elapsed_seconds, 7 * 86_400);
    assert!(reports.iter().all(|report| report.frozen_commands == 0));
}

#[test]
fn reviewed_notice_example_settles_each_review_route_and_withdraws_at_timeout() {
    let (definition, document) = fixture("reviewed-notice");
    let reports = scenarios::check(&definition, &document).unwrap();
    let report = |name: &str| {
        reports
            .iter()
            .find(|report| report.name == name)
            .unwrap_or_else(|| panic!("no case {name}"))
    };
    let approved = report("approved-unchanged-and-notice-accepted");
    assert_eq!(
        approved.path,
        [
            "read-for-review",
            "verify-review-subject",
            "submit-review",
            "await-review",
            "decide",
            "read-for-notice",
            "verify-notice",
            "notify",
            "notice-accepted"
        ]
    );
    assert_eq!(approved.state, "completed");
    assert_eq!(approved.call_attempts["notify"], 1);
    let rejected = report("rejected-without-notice");
    assert_eq!(
        rejected.path,
        [
            "read-for-review",
            "verify-review-subject",
            "submit-review",
            "await-review",
            "decide",
            "review-rejected"
        ]
    );
    assert_eq!(rejected.outcome.as_deref(), Some("review-rejected"));
    assert!(!rejected.call_attempts.contains_key("notify"));
    let changes = report("changes-requested-is-not-approval");
    assert_eq!(changes.outcome.as_deref(), Some("review-not-approved"));
    assert_eq!(changes.output, Some(json!({"status": "changes-requested"})));
    // A wait that times out withdraws the request instead of failing the run.
    let withdrawn = report("no-decision-within-fourteen-days");
    assert_eq!(
        withdrawn.path,
        [
            "read-for-review",
            "verify-review-subject",
            "submit-review",
            "await-review",
            "withdraw-timeout",
            "confirm-timeout-withdrawal",
            "timeout-withdrawn"
        ]
    );
    assert_eq!(
        withdrawn.output,
        Some(json!({"resultId": "00000000-0000-4000-8000-000000000011"}))
    );
    assert_eq!(withdrawn.elapsed_seconds, 14 * 86_400);
    // A decision that lands between the last result check and the withdrawal
    // stays decided: Casework answers already-terminal and keeps the result,
    // and the run reports that decision without acting on it.
    let raced = report("decided-just-before-timeout-withdrawal");
    assert_eq!(raced.outcome.as_deref(), Some("decided-late"));
    assert_eq!(
        raced.output,
        Some(json!({"status": "approved", "resultId": "00000000-0000-4000-8000-000000000011"}))
    );
    assert!(!raced.call_attempts.contains_key("notify"));
    let refused = report("messaging-policy-refuses-approved-notice");
    assert_eq!(refused.state, "refused");
    assert_eq!(refused.outcome, None);
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
    // A busy or failing gateway reaches the workflow on the final attempt
    // with an empty body, so the schema must permit it for the workflow to
    // decide what it means. Any other status stays outside the contract.
    for status in [404, 429, 502, 503, 504] {
        assert!(
            schema.is_valid(&json!({"status": status, "body": null})),
            "status {status}"
        );
    }
    assert!(!schema.is_valid(&json!({"status": 500, "body": null})));
    let reports = scenarios::check(&definition, &document).unwrap();
    assert_eq!(reports.len(), 8);
    assert!(reports.iter().all(|report| report.frozen_commands == 0));
    for status in [429, 502, 503, 504] {
        let case = document
            .cases
            .iter()
            .position(|case| {
                case.replies["lookup"].iter().any(|reply| {
                    matches!(reply, Reply::Success { success } if success["status"] == status)
                })
            })
            .unwrap_or_else(|| panic!("no scenario delivers status {status}"));
        assert_eq!(
            reports[case].outcome.as_deref(),
            Some("directory-unavailable"),
            "status {status}"
        );
    }
    // Ten attempts of at most ten seconds and nine waits of at most the
    // 300-second backoff cap, which a Retry-After never exceeds, fit in the
    // run deadline, so a directory that stays busy reaches the workflow.
    let admitted = chrono::Utc::now();
    let deadline = definition.deadline_at(admitted).unwrap() - admitted;
    assert!(
        deadline.num_seconds() >= 10 * 10 + 9 * 300,
        "the run deadline is shorter than the full retry budget"
    );
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

#[test]
fn decision_scenarios_allow_only_proven_non_dispatch_retries() {
    let (definition, mut document) = fixture("decision-follow-up");
    let case = &mut document.cases[1];
    case.recovery.insert("assess".into(), Recovery::RetrySame);
    case.replies.get_mut("assess").unwrap().insert(
        0,
        Reply::Retryable {
            retryable: "decision-unavailable".into(),
        },
    );
    let report = scenarios::run(&definition, case).unwrap();
    assert_eq!(report.call_attempts["assess"], 2);
    assert_eq!(report.frozen_commands, 1);
    case.replies.get_mut("assess").unwrap()[0] = Reply::Uncertain {
        uncertain: "decision-uncertain".into(),
    };
    assert_eq!(
        scenarios::run(&definition, case).err().unwrap().code,
        "scenario.recovery"
    );
    case.recovery.insert("assess".into(), Recovery::Reconcile);
    assert_eq!(
        scenarios::run(&definition, case).err().unwrap().code,
        "scenario.recovery"
    );
    case.recovery.clear();
    case.replies.get_mut("assess").unwrap().truncate(1);
    case.replies.get_mut("assess").unwrap()[0] = Reply::ReceiptExpired {
        receipt_expired: true,
    };
    assert_eq!(
        scenarios::run(&definition, case).err().unwrap().code,
        "scenario.reply"
    );
    case.replies.get_mut("assess").unwrap()[0] = Reply::Uncertain {
        uncertain: "decision-uncertain".into(),
    };
    case.expect.path = vec!["assess".into()];
    case.expect.state = "uncertain".into();
    case.expect.outcome = None;
    case.expect.output = None;
    let report = scenarios::run(&definition, case).unwrap();
    assert_eq!(report.state, "uncertain");
    assert_eq!(report.call_attempts["assess"], 1);
}
