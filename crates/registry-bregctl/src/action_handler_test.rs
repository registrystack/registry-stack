// SPDX-License-Identifier: Apache-2.0
//! Synthetic action handler evaluation and value-free exact assertions.
use super::*;
use registry_breg::action_handler::{
    evaluate_action_detailed, ActionHandlerError, ActionHandlerOutcome,
};
use registry_breg::model::{
    CompiledActionEffect, CompiledActionMutation, CompiledActionTargetBinding, CompiledActionValue,
};

pub(super) fn run(
    args: &ProjectPlannerTestArgs,
    compiled: &CompiledRegistry,
) -> Result<PlannerTestSuccessReport, FailureReport> {
    let id = args
        .action
        .as_deref()
        .ok_or_else(|| failure("action", "select a compiled action"))?;
    let action = compiled
        .actions()
        .actions
        .iter()
        .find(|action| action.id == id)
        .ok_or_else(|| failure("action", "select a compiled action"))?;
    let handler = action
        .handler
        .as_ref()
        .ok_or_else(|| failure("action", "select an action with a Rhai handler"))?;
    let path = args
        .input
        .as_ref()
        .ok_or_else(|| failure("input", "provide a synthetic input file"))?;
    let input = read_json(path, "input")?;
    let input = input
        .as_object()
        .ok_or_else(|| {
            failure(
                "input",
                "the synthetic input must be one JSON object keyed by declared action input IDs, without an HTTP input envelope",
            )
        })?;
    let outcome = evaluate_action_detailed(action, input, Instant::now() + PLANNER_TEST_DEADLINE)
        .map_err(|error| {
        let input_error = error.kind == ActionHandlerError::Input;
        let mut path = format!("actions[{}]", action.id);
        if input_error {
            path.push_str(".inputs");
            if let Some(field) = &error.field {
                path.push_str(&format!("[{field}]"));
            }
        } else {
            path.push_str(".handler");
            if let Some(slot) = &error.slot {
                path.push_str(&format!(".writes[{slot}]"));
            }
            if let Some(field) = &error.field {
                path.push_str(&format!(".fields[{field}]"));
            }
        }
        let message = if input_error && error.field.is_none() {
            format!(
                "{} Declared input IDs: {}.",
                error.message,
                action
                    .inputs
                    .iter()
                    .map(|input| input.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            error.message.to_owned()
        };
        source_failure(
            "project planner-test",
            diagnostic(error.kind.code(), &path, &message),
            DiagnosticArtifact::PlannerTest,
            if input_error {
                SuggestedAction::CorrectPlannerTestInput
            } else {
                SuggestedAction::CorrectActionHandler
            },
        )
    })?;
    let (effects, refusal, actual) = match outcome {
        ActionHandlerOutcome::Effects(effects) => {
            let actual = exact_effects(&effects);
            (effects, None, actual)
        }
        ActionHandlerOutcome::Refusal(refusal) => {
            let mut expected = json!({"code": refusal.code});
            if let Some(field) = &refusal.field {
                expected["field"] = json!(field);
            }
            let actual = json!({"refusal": expected});
            let mut report = expected;
            report["label"] = json!(refusal.label);
            (Vec::new(), Some(report), actual)
        }
    };
    let assertions_passed = if let Some(path) = &args.expect {
        let mut expected = read_json(path, "expect")?;
        normalize(&mut expected);
        if let Some(path) = mismatch_path(&actual, &expected, "expect") {
            return Err(planner_test_failure(
                "planner_test.expect.mismatch",
                &path,
                "the computed outcome differs from the expected outcome",
            ));
        }
        Some(true)
    } else {
        None
    };
    let reports = effects
        .iter()
        .map(|effect| {
            let fields = effect
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    CompiledActionMutation::Set { field, .. }
                    | CompiledActionMutation::Clear { field } => field.clone(),
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            PlannerTestEffectReport {
                id: effect.id.clone(),
                target_kind: match effect.target.binding {
                    CompiledActionTargetBinding::Create => "reserved_create",
                    CompiledActionTargetBinding::Existing { .. } => "existing",
                },
                operation: operation_wire_name(effect.operation),
                fields,
                depends_on: effect.depends_on.iter().cloned().collect(),
            }
        })
        .collect::<Vec<_>>();
    Ok(PlannerTestSuccessReport {
        ok: true,
        command: "project planner-test",
        compiled_revision: compiled.revision().to_owned(),
        request_entity: String::new(),
        action: Some(action.id.clone()),
        refusal,
        assertions_passed,
        planner: None,
        handler: Some(PlannerTestIdentityReport {
            kind: "rhai",
            abi: handler.abi.clone(),
            script_sha256: handler.script_sha256.clone(),
        }),
        disposition: None,
        queue_reason: None,
        counts: PlannerTestCountReport {
            effects: effects.len(),
            field_mutations: effects.iter().map(|e| e.mutations.len()).sum(),
            dependencies: effects.iter().map(|e| e.depends_on.len()).sum(),
        },
        effects: reports,
    })
}

fn read_json(path: &Path, location: &str) -> Result<Value, FailureReport> {
    let bytes = read_bounded_regular_file(
        path,
        "planner_test.file.unavailable",
        MAX_PLANNER_TEST_REQUEST_BYTES,
    )
    .map_err(|error| {
        let message = if error.code == "source.file.bounds" {
            "the synthetic JSON file exceeds its fixed size bound"
        } else {
            "provide a bounded readable regular JSON file at a physical path with no symbolic-link components; on macOS use /private/tmp instead of /tmp"
        };
        failure(location, message)
    })?;
    let value = parse_json_strict(&bytes).map_err(|_| failure(location, "provide strict JSON"))?;
    if !bounded_planner_test_value(&value, 0) {
        return Err(failure(
            location,
            "the fixture exceeds the closed value bounds",
        ));
    }
    Ok(value)
}

fn failure(path: &str, message: &str) -> FailureReport {
    planner_test_failure("planner_test.action.invalid", path, message)
}

fn exact_effects(effects: &[CompiledActionEffect]) -> Value {
    let effects = effects
        .iter()
        .map(|effect| {
            let mut set = serde_json::Map::new();
            let mut clear = Vec::new();
            for mutation in &effect.mutations {
                match mutation {
                    CompiledActionMutation::Clear { field } => clear.push(field.clone()),
                    CompiledActionMutation::Set { field, value } => {
                        let value = match value {
                            CompiledActionValue::Literal { value } => value.clone(),
                            CompiledActionValue::FromInput { input } => json!({"fromField": input}),
                            CompiledActionValue::FromEffect { effect, .. } => {
                                json!({"fromEffect": effect})
                            }
                        };
                        set.insert(field.clone(), value);
                    }
                }
            }
            let mut value = json!({"id": effect.id});
            if !set.is_empty() {
                value["set"] = json!(set);
            }
            if !clear.is_empty() {
                value["clear"] = json!(clear);
            }
            value
        })
        .collect::<Vec<_>>();
    let mut result = json!({"effects": effects});
    normalize(&mut result);
    result
}

// Order has no meaning for slot selection or optional clears. All values and
// membership are otherwise compared exactly, including omitted slots.
fn normalize(value: &mut Value) {
    if let Some(effects) = value.get_mut("effects").and_then(Value::as_array_mut) {
        for effect in effects.iter_mut() {
            if let Some(clear) = effect.get_mut("clear").and_then(Value::as_array_mut) {
                clear.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            }
        }
        effects.sort_by(|a, b| {
            a.get("id")
                .and_then(Value::as_str)
                .cmp(&b.get("id").and_then(Value::as_str))
        });
    }
}

// Locations come only from the verified actual outcome. Never echo an arbitrary
// expected key, fixture value, runtime identifier, or script-provided message.
fn mismatch_path(actual: &Value, expected: &Value, path: &str) -> Option<String> {
    if path.contains("/set/") {
        return (actual != expected).then(|| path.to_owned());
    }
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            if actual.len() != expected.len() {
                return Some(path.to_owned());
            }
            for (key, value) in actual {
                let Some(other) = expected.get(key) else {
                    return Some(path.to_owned());
                };
                if let Some(path) = mismatch_path(value, other, &format!("{path}/{key}")) {
                    return Some(path);
                }
            }
            None
        }
        (Value::Array(actual), Value::Array(expected)) => {
            if actual.len() != expected.len() {
                return Some(path.to_owned());
            }
            actual
                .iter()
                .zip(expected)
                .enumerate()
                .find_map(|(index, (a, b))| mismatch_path(a, b, &format!("{path}/{index}")))
        }
        _ if actual == expected => None,
        _ => Some(path.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acceptance_project() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/person-registration-rhai")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn action_handler_cli_requires_one_complete_context_form() {
        for flags in [
            vec!["--action", "register-person"],
            vec!["--input", "input.json"],
            vec![
                "--action",
                "register-person",
                "--input",
                "input.json",
                "--request",
                "request.json",
            ],
            vec![
                "--action",
                "register-person",
                "--input",
                "input.json",
                "--entity",
                "request",
                "--request",
                "request.json",
            ],
            vec![
                "--entity",
                "request",
                "--request",
                "request.json",
                "--expect",
                "expect.json",
            ],
        ] {
            let mut arguments = vec!["bregctl", "project", "planner-test", "project"];
            arguments.extend(flags);
            assert!(Cli::try_parse_from(arguments).is_err());
        }
        assert!(Cli::try_parse_from([
            "bregctl",
            "project",
            "planner-test",
            "project",
            "--action",
            "register-person",
            "--input",
            "input.json",
            "--expect",
            "expect.json"
        ])
        .is_ok());
        let help = Cli::try_parse_from(["bregctl", "project", "planner-test", "--help"])
            .unwrap_err()
            .to_string();
        for guidance in [
            "pair with --request",
            "pair with --input",
            "With --action and --input",
            "without an HTTP envelope",
        ] {
            assert!(help.contains(guidance), "{help}");
        }
    }

    #[test]
    fn action_handler_cli_asserts_computation_and_refusal_with_safe_reports() {
        let project = acceptance_project();
        let compiled = compile(&project, ProfileArg::Authoring, "project planner-test")
            .unwrap_or_else(|failure| {
                panic!(
                    "fixture compilation failed: {}",
                    failure.diagnostics[0].code
                )
            });
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let input = root.join("input.json");
        let expect = root.join("expect.json");
        fs::write(&input, serde_json::to_vec(&json!({"identifier":"0123456789012","given-name":"  Mina  ","family-name":" Example "})).unwrap()).unwrap();
        fs::write(&expect, serde_json::to_vec(&json!({"effects":[{"id":"person","set":{"identifier":"0123456789012","display-name":"Mina Example"}}]})).unwrap()).unwrap();
        let args = ProjectPlannerTestArgs {
            project,
            action: Some("register-person".into()),
            input: Some(input.clone()),
            expect: Some(expect.clone()),
            entity: None,
            request: None,
        };
        let report = run(&args, &compiled)
            .unwrap_or_else(|failure| panic!("evaluation failed: {}", failure.diagnostics[0].code));
        assert_eq!(report.assertions_passed, Some(true));
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(serde_json::to_value(&report)
            .unwrap()
            .get("disposition")
            .is_none());
        for canary in ["Mina", "Example", "0123456789012", "fn handle", "scripts/"] {
            assert!(!rendered.contains(canary));
        }
        fs::write(&expect, br#"{"effects":[]}"#).unwrap();
        let failure = run(&args, &compiled).expect_err("omitted expected effect is a mismatch");
        assert_eq!(failure.diagnostics[0].code, "planner_test.expect.mismatch");
        fs::write(
            &input,
            br#"{"identifier":"0123456789012","given-name":"   ","family-name":" "}"#,
        )
        .unwrap();
        fs::write(
            &expect,
            br#"{"refusal":{"code":"blank-name","field":"given-name"}}"#,
        )
        .unwrap();
        let mut report = run(&args, &compiled).unwrap_or_else(|failure| {
            panic!("expected refusal failed: {}", failure.diagnostics[0].code)
        });
        assert_eq!(report.disposition, None);
        assert_eq!(report.counts.effects, 0);
        assert_eq!(report.assertions_passed, Some(true));
        assert!(serde_json::to_value(&report)
            .unwrap()
            .get("disposition")
            .is_none());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_planner_test_success(&report, OutputFormat::Human, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let human = String::from_utf8(stdout).unwrap();
        let human = anstream::adapter::strip_str(&human).to_string();
        let aligned = human.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(human.starts_with("Ran the handler. Returned a declared refusal.\n"));
        assert!(aligned.contains("refusal blank-name (At least one name part is required.)"));
        assert!(aligned.contains("refusal input given-name"));
        assert!(!human.contains("disposition"));
        assert!(!human.contains("0123456789012"));

        report.refusal.as_mut().unwrap()["label"] = json!("safe\nFORGED\u{1b}[2J");
        let mut stdout = Vec::new();
        assert_eq!(
            write_planner_test_success(&report, OutputFormat::Human, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        let human = String::from_utf8(stdout).unwrap();
        let human = anstream::adapter::strip_str(&human).to_string();
        assert!(human.contains("safe\\nFORGED"));
        assert!(!human.contains("\nFORGED"));
    }

    #[test]
    fn action_handler_input_errors_identify_declared_inputs_and_safe_repair() {
        let project = acceptance_project();
        let compiled = compile(&project, ProfileArg::Authoring, "project planner-test")
            .unwrap_or_else(|failure| panic!("fixture failed: {}", failure.diagnostics[0].code));
        let directory = tempfile::tempdir().unwrap();
        let input_path = directory.path().canonicalize().unwrap().join("input.json");
        let args = ProjectPlannerTestArgs {
            project,
            action: Some("register-person".into()),
            input: Some(input_path.clone()),
            expect: None,
            entity: None,
            request: None,
        };
        for (input, expected_path) in [
            (
                json!({"input": {"identifier": "private-value-canary"}}),
                "actions[register-person].inputs",
            ),
            (
                json!({"private-key-canary": "private-value-canary"}),
                "actions[register-person].inputs",
            ),
            (
                json!({"given-name": "private-value-canary"}),
                "actions[register-person].inputs[identifier]",
            ),
            (
                json!({"identifier": 42}),
                "actions[register-person].inputs[identifier]",
            ),
        ] {
            fs::write(&input_path, serde_json::to_vec(&input).unwrap()).unwrap();
            let failure =
                run(&args, &compiled).expect_err("bad inputs are refused before execution");
            let diagnostic = &failure.diagnostics[0];
            assert_eq!(diagnostic.code, "action.input.invalid");
            assert_eq!(diagnostic.path, expected_path);
            assert_eq!(
                diagnostic.suggested_action,
                SuggestedAction::CorrectPlannerTestInput
            );
            let rendered = serde_json::to_string(&failure).unwrap();
            assert!(!rendered.contains("private-key-canary"));
            assert!(!rendered.contains("private-value-canary"));
            if expected_path.ends_with(".inputs") {
                assert!(diagnostic.message.contains("Declared input IDs:"));
                assert!(diagnostic.message.contains("given-name"));
                assert!(diagnostic.message.contains("HTTP request body"));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn action_handler_input_and_expect_paths_explain_parent_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let real = root.join("physical");
        let alias = root.join("alias");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("fixture.json"), br#"{}"#).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        for location in ["input", "expect"] {
            let report = read_json(&alias.join("fixture.json"), location)
                .expect_err("a symlink in a parent path is refused");
            let diagnostic = &report.diagnostics[0];
            assert_eq!(diagnostic.path, location);
            assert!(diagnostic.message.contains("symbolic-link components"));
            assert!(diagnostic.message.contains("/private/tmp instead of /tmp"));
            assert!(!diagnostic.message.contains(alias.to_str().unwrap()));
            assert!(read_json(&real.join("fixture.json"), location).is_ok());
        }
    }

    #[test]
    fn assertions_cover_exact_values_omissions_and_refusal_without_value_disclosure() {
        let actual =
            json!({"effects":[{"id":"person","set":{"display-name":"computed-secret-canary"}}]});
        let mismatch =
            json!({"effects":[{"id":"person","set":{"display-name":"expected-secret-canary"}}]});
        assert_eq!(mismatch_path(&actual, &actual, "expect"), None);
        assert_eq!(
            mismatch_path(&actual, &mismatch, "expect").as_deref(),
            Some("expect/effects/0/set/display-name")
        );
        assert_eq!(
            mismatch_path(&actual, &json!({"effects":[]}), "expect").as_deref(),
            Some("expect/effects")
        );
        assert_eq!(
            mismatch_path(
                &json!({"refusal":{"code":"blank-name"}}),
                &json!({"refusal":{"code":"different"}}),
                "expect"
            )
            .as_deref(),
            Some("expect/refusal/code")
        );
        assert_eq!(
            mismatch_path(&actual, &json!({"untrusted-secret-key":true}), "expect").as_deref(),
            Some("expect")
        );
        let structured =
            json!({"effects":[{"id":"record","set":{"data":{"private-key-canary":"secret"}}}]});
        let changed =
            json!({"effects":[{"id":"record","set":{"data":{"private-key-canary":"different"}}}]});
        assert_eq!(
            mismatch_path(&structured, &changed, "expect").as_deref(),
            Some("expect/effects/0/set/data")
        );
    }
}
