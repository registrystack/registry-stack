// SPDX-License-Identifier: Apache-2.0

use registry_breg::{
    action_handler::{
        compile_source, evaluate_action, evaluate_action_detailed, ActionHandlerError,
        ActionHandlerOutcome,
    },
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_json, ModuleAssetSource},
    model::{CompiledAction, CompiledActionMutation, CompiledActionValue},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn project() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"action-handler-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
        "entities":[{"id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","fields":[
            {"id":"name","type":"string","maxLength":160,"required":true,"classification":"restricted"},
            {"id":"friend","type":"reference","target":"person","classification":"restricted"}
        ]}],
        "actions":[{"id":"register-person","inputs":[
            {"id":"given-name","apiName":"givenName","type":"string","maxLength":80,"required":true,"classification":"restricted"},
            {"id":"family-name","type":"string","maxLength":80,"classification":"restricted"},
            {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}
        ],"handler":{"kind":"rhai","script":"handlers/register.rhai","abi":"registry.action-handler/v1","refusals":[{"code":"blank-name","label":"A name is required."}],"writes":[
            {"id":"person","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"friend","target":{"entity":"person"},"operation":"create","fields":["name","friend"]},
            {"id":"existing","target":{"fromField":"person"},"operation":"patch","fields":["name","friend"]}
        ]}}],
        "accessProfiles":[{"id":"registrar","default":true,"principalClaim":"principal","permissions":[{"action":"register-person","operations":["invoke"],"targets":[{"entity":"person","rowBoundaries":[]}],"results":["person","friend","existing"]}]}]
    })
}
fn compile(source: Value, script: &str) -> Result<CompiledAction, registry_breg::CompileFailure> {
    let source = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project_with_assets(
        &source,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "handlers/register.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .map(|registry| registry.actions().actions[0].clone())
}
fn inputs() -> Value {
    json!({"given-name":" Mina ","person":"550e8400-e29b-41d4-a716-446655440000"})
}
fn evaluate(script: &str) -> Result<ActionHandlerOutcome, ActionHandlerError> {
    let action = compile(project(), script).unwrap();
    evaluate_action(
        &action,
        inputs().as_object().unwrap(),
        Instant::now() + Duration::from_secs(5),
    )
}
fn result(expression: &str) -> String {
    format!("fn handle(ctx) {{ {expression} }}")
}

#[test]
fn handler_computes_from_authored_input_ids_and_omits_slots() {
    let outcome = evaluate(r#"fn handle(ctx) { let name = ctx.inputs["given-name"]; name.trim(); #{effects:[#{id:"person",set:#{name:name,friend:#{fromField:"person"}}}]} }"#).unwrap();
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("effects expected")
    };
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].id, "person");
    assert!(effects[0].mutations.contains(&CompiledActionMutation::Set {
        field: "name".into(),
        value: CompiledActionValue::Literal {
            value: json!("Mina")
        }
    }));
    assert!(effects[0].mutations.contains(&CompiledActionMutation::Set {
        field: "friend".into(),
        value: CompiledActionValue::FromInput {
            input: "person".into()
        }
    }));
    let action = compile(
        project(),
        &result("#{effects:[#{id:\"person\",set:#{name:\"Mina\"}}]}"),
    )
    .unwrap();
    assert_eq!(action.effects.len(), 3);
    assert!(action
        .target_uses
        .iter()
        .any(|target| target.condition_required));
}

#[test]
fn handler_business_refusal_is_exclusive_bounded_and_governed() {
    let outcome = evaluate(&result(
        r#"#{refusal:#{code:"blank-name",field:"given-name"}}"#,
    ))
    .unwrap();
    let ActionHandlerOutcome::Refusal(refusal) = outcome else {
        panic!("refusal expected")
    };
    assert_eq!(refusal.label, "A name is required.");
    assert_eq!(refusal.field.as_deref(), Some("given-name"));
    assert!(matches!(
        evaluate(&result(r#"#{refusal:#{code:"blank-name"}}"#)),
        Ok(ActionHandlerOutcome::Refusal(_))
    ));
    for expression in [
        r#"#{effects:[],refusal:#{code:"blank-name"}}"#,
        r#"#{refusal:#{code:"unknown"}}"#,
        r#"#{refusal:#{code:"blank-name",field:"givenName"}}"#,
        r#"#{refusal:#{code:"blank-name",message:"private-canary"}}"#,
        r#"#{refusal:#{code:"blank-name",data:#{value:"private-canary"}}}"#,
    ] {
        assert_eq!(
            evaluate(&result(expression)).unwrap_err(),
            ActionHandlerError::Result,
            "{expression}"
        );
    }
    let error = evaluate("fn handle(ctx) { throw ctx.inputs; }").unwrap_err();
    assert_eq!(error, ActionHandlerError::Execution);
    assert!(!error.problem_detail().contains("Mina"));
}

#[test]
fn handler_rejects_slot_and_value_contract_violations() {
    for expression in [
        r#"#{effects:[]}"#,
        r#"#{effects:[#{id:"unknown",set:#{name:"Mina"}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina"}},#{id:"person",set:#{name:"Mina"}}]}"#,
        r#"#{effects:[#{id:"person",target:#{entity:"person"},set:#{name:"Mina"}}]}"#,
        r#"#{effects:[#{id:"person",operation:"create",set:#{name:"Mina"}}]}"#,
        r#"#{effects:[#{id:"person",set:#{unknown:"Mina"}}]}"#,
        r#"#{effects:[#{id:"person",set:#{friend:#{fromField:"person"}}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:()}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:5}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina"},clear:["friend"]}]}"#,
        r#"#{effects:[#{id:"existing",clear:["name"]}]}"#,
        r#"#{effects:[#{id:"existing",clear:["friend","friend"]}]}"#,
        r#"#{effects:[#{id:"existing"}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:"550e8400-e29b-41d4-a716-446655440000"}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromField:"given-name"}}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"friend"}}}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"existing"}}},#{id:"existing",clear:["friend"]}]}"#,
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"friend"}}},#{id:"friend",set:#{name:"Sam",friend:#{fromEffect:"person"}}}]}"#,
    ] {
        assert!(evaluate(&result(expression)).is_err(), "{expression}");
    }
}

#[test]
fn handler_orders_symbolic_creates_and_permits_optional_patch_clears() {
    let ActionHandlerOutcome::Effects(effects) = evaluate(&result(r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"friend"}}},#{id:"friend",set:#{name:"Sam"}},#{id:"existing",clear:["friend"]}]}"#)).unwrap() else { panic!("effects expected") };
    let position = |id| effects.iter().position(|effect| effect.id == id).unwrap();
    assert!(position("friend") < position("person"));
    assert_eq!(
        effects[position("existing")].mutations,
        vec![CompiledActionMutation::Clear {
            field: "friend".into()
        }]
    );
}

#[test]
fn local_handler_diagnostics_name_compiled_fields_and_preserve_runtime_errors() {
    for (expression, kind, slot, field, message) in [
        (
            r#"#{effects:[#{id:"person",set:#{friend:#{fromField:"person"}}}]}"#,
            ActionHandlerError::Ceiling,
            "person",
            "name",
            "Set this required field when creating a record.",
        ),
        (
            r#"#{effects:[#{id:"person",set:#{name:#{private_value_canary:ctx.inputs["given-name"]}}}]}"#,
            ActionHandlerError::Result,
            "person",
            "name",
            "Use a value matching the declared field type and bounds.",
        ),
        (
            r#"#{effects:[#{id:"person",set:#{name:()}}]}"#,
            ActionHandlerError::Result,
            "person",
            "name",
            "Set a non-null value; use clear only for optional patch fields.",
        ),
        (
            r#"#{effects:[#{id:"existing",clear:["name"]}]}"#,
            ActionHandlerError::Ceiling,
            "existing",
            "name",
            "Set a value for this required field; it cannot be cleared.",
        ),
        (
            r#"#{effects:[#{id:"person",set:#{name:"Mina"},clear:["friend"]}]}"#,
            ActionHandlerError::Ceiling,
            "person",
            "friend",
            "Create effects cannot clear fields; omit optional fields or set a value.",
        ),
        (
            r#"#{effects:[#{id:"existing",set:#{friend:#{fromField:"person"}},clear:["friend"]}]}"#,
            ActionHandlerError::Ceiling,
            "existing",
            "friend",
            "Write each field once, using either set or clear.",
        ),
    ] {
        let script = result(expression);
        let action = compile(project(), &script).unwrap();
        let mut input = inputs();
        input["given-name"] = json!("private-input-canary");
        let diagnostic = evaluate_action_detailed(
            &action,
            input.as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, kind);
        assert_eq!(diagnostic.slot.as_deref(), Some(slot));
        assert_eq!(diagnostic.field.as_deref(), Some(field));
        assert_eq!(diagnostic.message, message);
        assert_eq!(
            evaluate_action(
                &action,
                input.as_object().unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err(),
            kind
        );
        let rendered = format!("{diagnostic:?}");
        for canary in [
            "private-input-canary",
            "private_value_canary",
            "550e8400-e29b-41d4-a716-446655440000",
            "fn handle",
        ] {
            assert!(
                !rendered.contains(canary),
                "local diagnostic disclosed a value or source"
            );
        }
    }
}

#[test]
fn local_handler_diagnostics_hide_unknown_output_names_and_preserve_success() {
    for (expression, slot) in [
        (
            r#"#{effects:[#{id:"private-slot-canary",set:#{name:"private-value-canary"}}]}"#,
            None,
        ),
        (
            r#"#{effects:[#{id:"person",set:#{private_field_canary:"private-value-canary"}}]}"#,
            Some("person"),
        ),
        (
            r#"#{effects:[#{id:"existing",clear:["private-field-canary"]}]}"#,
            Some("existing"),
        ),
        (
            r#"#{effects:[#{id:"person",private_key_canary:ctx.inputs}]}"#,
            Some("person"),
        ),
    ] {
        let action = compile(project(), &result(expression)).unwrap();
        let diagnostic = evaluate_action_detailed(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.slot.as_deref(), slot);
        assert_eq!(diagnostic.field, None);
        let rendered = format!("{diagnostic:?}");
        for canary in [
            "private-slot-canary",
            "private_field_canary",
            "private-field-canary",
            "private_key_canary",
            "private-value-canary",
            "Mina",
        ] {
            assert!(
                !rendered.contains(canary),
                "local diagnostic disclosed unknown output"
            );
        }
    }
    for expression in [
        r#"let name = ctx.inputs["given-name"]; name.trim(); #{effects:[#{id:"person",set:#{name:name}}]}"#,
        r#"#{refusal:#{code:"blank-name",field:"given-name"}}"#,
    ] {
        let action = compile(project(), &result(expression)).unwrap();
        let detailed = evaluate_action_detailed(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            detailed,
            evaluate_action(
                &action,
                inputs().as_object().unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
        );
    }
}

#[test]
fn handler_input_diagnostics_distinguish_admission_from_execution() {
    let action = compile(project(), "fn handle(ctx) { throw ctx.inputs; }").unwrap();
    for (input, field, message) in [
        (
            json!({"inputs": inputs()}),
            None,
            "Use only declared input IDs in the input object; do not wrap it in an HTTP request body.",
        ),
        (
            json!({"private_key_canary": "private-value-canary"}),
            None,
            "Use only declared input IDs in the input object; do not wrap it in an HTTP request body.",
        ),
        (
            json!({"given-name": null}),
            Some("given-name"),
            "Supply a non-null value for this required input.",
        ),
        (
            json!({}),
            Some("given-name"),
            "Supply a non-null value for this required input.",
        ),
        (
            json!({"given-name": {"private_value_canary": true}}),
            Some("given-name"),
            "Use an input value matching the declared type and bounds.",
        ),
    ] {
        let diagnostic = evaluate_action_detailed(
            &action,
            input.as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, ActionHandlerError::Input);
        assert_eq!(diagnostic.kind.code(), "action.input.invalid");
        assert_eq!(diagnostic.slot, None);
        assert_eq!(diagnostic.field.as_deref(), field);
        assert_eq!(diagnostic.message, message);
        assert!(!format!("{diagnostic:?}").contains("canary"));
    }
    assert_eq!(
        evaluate_action(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err(),
        ActionHandlerError::Execution
    );
}

#[test]
fn handler_decoder_diagnostics_identify_repairable_causes_without_values() {
    for (expression, kind, slot, message) in [
        (
            r#"#{effects:[],refusal:#{code:"blank-name"}}"#,
            ActionHandlerError::Result,
            None,
            "Return either effects or refusal, never both.",
        ),
        (
            r#"#{refusal:#{code:"private-code-canary"}}"#,
            ActionHandlerError::Result,
            None,
            "Use a code from the handler's declared refusal catalogue.",
        ),
        (
            r#"#{effects:[#{id:"person",private_key_canary:ctx.inputs}]}"#,
            ActionHandlerError::Result,
            Some("person"),
            "An effect may contain only id, set and clear; the declared slot fixes its target and operation.",
        ),
        (
            r#"#{effects:[#{id:"person",set:#{name:"Mina"}},#{id:"person",set:#{name:"Sam"}}]}"#,
            ActionHandlerError::Result,
            Some("person"),
            "Emit each declared write slot at most once.",
        ),
        (
            r#"#{effects:[]}"#,
            ActionHandlerError::Ceiling,
            None,
            "Emit at least one declared write slot, or return a declared refusal.",
        ),
        (
            r#"#{effects:[#{id:"person",set:#{private_field_canary:"private-value-canary"}}]}"#,
            ActionHandlerError::Ceiling,
            Some("person"),
            "Set only fields declared by this slot.",
        ),
    ] {
        let action = compile(project(), &result(expression)).unwrap();
        let diagnostic = evaluate_action_detailed(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, kind);
        assert_eq!(diagnostic.slot.as_deref(), slot);
        assert_eq!(diagnostic.field, None);
        assert_eq!(diagnostic.message, message);
        let rendered = format!("{diagnostic:?}");
        for canary in ["canary", "Mina", "Sam"] {
            assert!(!rendered.contains(canary));
        }
    }
}

#[test]
fn handler_optional_inputs_preserve_absence_and_explicit_null() {
    let action = compile(
        project(),
        r#"fn handle(ctx) {
            let name = "absent";
            if "family-name" in ctx.inputs {
                if ctx.inputs["family-name"] == () {
                    name = "null";
                } else {
                    name = ctx.inputs["family-name"];
                    name.trim();
                }
            }
            #{effects:[#{id:"person",set:#{name:name}}]}
        }"#,
    )
    .unwrap();
    for (optional, expected) in [
        (None, "absent"),
        (Some(Value::Null), "null"),
        (Some(json!(" Rahman ")), "Rahman"),
    ] {
        let mut input = inputs();
        if let Some(value) = optional {
            input["family-name"] = value;
        }
        let ActionHandlerOutcome::Effects(effects) = evaluate_action(
            &action,
            input.as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap() else {
            panic!("effects expected")
        };
        assert_eq!(
            effects[0].mutations,
            vec![CompiledActionMutation::Set {
                field: "name".into(),
                value: CompiledActionValue::Literal {
                    value: json!(expected)
                },
            }]
        );
    }
    assert_eq!(
        evaluate(r#"fn handle(ctx) { let name = ctx.inputs["family-name"]; name.trim(); #{effects:[#{id:"person",set:#{name:name}}]} }"#)
            .unwrap_err(),
        ActionHandlerError::Execution
    );
}

#[test]
fn handler_compiler_rejects_inputs_outside_the_scalar_abi() {
    let script = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    for (field_type, code, member, repair) in [
        (
            json!({"type":"string","maxLength":17_000}),
            "action.handler.input.string_bound",
            "maxLength",
            "4096",
        ),
        (
            json!({"type":"text","maxLength":20_000}),
            "action.handler.input.string_bound",
            "maxLength",
            "4096",
        ),
        (
            json!({"type":"crs84-point","precision":6}),
            "action.handler.input.type_unsupported",
            "type",
            "scalar",
        ),
        (
            json!({"type":"structured","maxBytes":1024,"schema":{
                "type":"object","properties":{"value":{"type":"number"}},
                "additionalProperties":false
            }}),
            "action.handler.input.type_unsupported",
            "type",
            "scalar",
        ),
    ] {
        let mut input = field_type;
        input["id"] = json!("extra");
        input["classification"] = json!("restricted");
        let mut source = project();
        source["actions"][0]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(input.clone());
        let failure = compile(source, &script).unwrap_err();
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("expected {code}: {:?}", failure.diagnostics()));
        assert_eq!(
            diagnostic.path,
            format!("actions[register-person].inputs[extra].{member}")
        );
        assert!(diagnostic.message.contains(repair));
        assert!(diagnostic.message.contains("registry.action-handler/v1"));

        // The same declared input is valid for an action with fixed effects.
        let mut fixed = project();
        fixed["actions"][0]
            .as_object_mut()
            .unwrap()
            .remove("handler");
        fixed["actions"][0]["inputs"] = json!([
            input,
            {"id":"name","type":"string","maxLength":160,"required":true,"classification":"restricted"}
        ]);
        fixed["actions"][0]["effects"] = json!([{
            "id":"person","target":{"entity":"person"},"operation":"create",
            "set":{"name":{"fromField":"name"}}
        }]);
        fixed["accessProfiles"][0]["permissions"][0]["results"] = json!(["person"]);
        let fixed = parse_project_json(&serde_json::to_vec(&fixed).unwrap()).unwrap();
        compile_project_with_assets(&fixed, &[], &[], CompileProfile::Authoring).unwrap();
    }
}

#[test]
fn handler_string_declarations_cover_the_full_unicode_boundary() {
    let script = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    for kind in ["string", "text"] {
        let mut source = project();
        source["actions"][0]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":"extra","type":kind,"maxLength":4096,"classification":"restricted"
            }));
        let action = compile(source.clone(), &script).unwrap();
        let mut input = inputs();
        input["extra"] = json!("\u{1f642}".repeat(4096));
        assert_eq!(
            input["extra"].as_str().unwrap().len(),
            registry_breg::rhai_planner::MAXIMUM_STRING_BYTES
        );
        assert!(matches!(
            evaluate_action(
                &action,
                input.as_object().unwrap(),
                Instant::now() + Duration::from_secs(5)
            ),
            Ok(ActionHandlerOutcome::Effects(_))
        ));
        input["extra"] = json!("\u{1f642}".repeat(4097));
        let diagnostic = evaluate_action_detailed(
            &action,
            input.as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, ActionHandlerError::Input);
        assert_eq!(diagnostic.field.as_deref(), Some("extra"));

        source["actions"][0]["inputs"][3]["maxLength"] = json!(4097);
        assert!(compile(source, &script)
            .unwrap_err()
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "action.handler.input.string_bound"));
    }
}

#[test]
fn handler_accepts_supported_scalars_and_rejects_oversized_timestamp_input() {
    let script = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    for (field_type, value) in [
        (json!({"type":"boolean"}), json!(true)),
        (json!({"type":"int64"}), json!(i64::MIN)),
        (
            json!({"type":"decimal","precision":38,"scale":2}),
            json!("-123456789012345678901234567890123456.78"),
        ),
        (json!({"type":"date"}), json!("2026-09-08")),
        (
            json!({"type":"uuid"}),
            json!("550e8400-e29b-41d4-a716-446655440000"),
        ),
        (
            json!({"type":"vocabulary-code","vocabulary":"codes","values":["a".repeat(64)]}),
            json!("a".repeat(64)),
        ),
        (
            json!({"type":"timestamp"}),
            json!("2026-09-08T12:00:00.123456789+07:00"),
        ),
    ] {
        let mut extra = field_type;
        extra["id"] = json!("extra");
        extra["classification"] = json!("restricted");
        let mut source = project();
        source["actions"][0]["inputs"]
            .as_array_mut()
            .unwrap()
            .push(extra);
        let action = compile(source, &script).unwrap();
        let mut input = inputs();
        input["extra"] = value;
        assert!(matches!(
            evaluate_action(
                &action,
                input.as_object().unwrap(),
                Instant::now() + Duration::from_secs(5)
            ),
            Ok(ActionHandlerOutcome::Effects(_))
        ));
        if input["extra"].as_str() == Some("2026-09-08T12:00:00.123456789+07:00") {
            let oversized = format!("2026-09-08T12:00:00.{}Z", "1".repeat(17_000));
            assert!(time::OffsetDateTime::parse(
                &oversized,
                &time::format_description::well_known::Rfc3339
            )
            .is_ok());
            input["extra"] = json!(oversized);
            let diagnostic = evaluate_action_detailed(
                &action,
                input.as_object().unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
            assert_eq!(diagnostic.kind, ActionHandlerError::Input);
            assert_eq!(diagnostic.field.as_deref(), Some("extra"));
            assert_eq!(
                diagnostic.message,
                "Use a handler input string of at most 16,384 UTF-8 bytes."
            );
            assert!(!format!("{diagnostic:?}").contains("2026-09-08"));
        }
    }
}

#[test]
fn handler_cannot_write_an_existing_field_outside_its_narrower_slot() {
    let mut source = project();
    source["actions"][0]["handler"]["writes"][2]["fields"] = json!(["name"]);
    let action = compile(
        source,
        &result(r#"#{effects:[#{id:"existing",set:#{friend:#{fromField:"person"}}}]}"#),
    )
    .unwrap();
    assert!(action
        .handler
        .as_ref()
        .unwrap()
        .writes
        .iter()
        .any(|slot| { slot.id == "person" && slot.ceiling.fields.contains("friend") }));
    let diagnostic = evaluate_action_detailed(
        &action,
        inputs().as_object().unwrap(),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(diagnostic.kind, ActionHandlerError::Ceiling);
    assert_eq!(diagnostic.slot.as_deref(), Some("existing"));
    assert_eq!(diagnostic.field, None);
    assert_eq!(diagnostic.message, "Set only fields declared by this slot.");
}

#[test]
fn handler_evaluation_requires_a_handler_and_obeys_compiled_result_bounds() {
    let script = result(
        r#"#{effects:[#{id:"person",set:#{name:"Mina"}},#{id:"friend",set:#{name:"Sam"}}]}"#,
    );
    let mut action = compile(project(), &script).unwrap();
    for field_bound in [false, true] {
        action.maximum_targets = if field_bound { 16 } else { 1 };
        action.maximum_field_mutations = if field_bound { 1 } else { 128 };
        let diagnostic = evaluate_action_detailed(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(diagnostic.kind, ActionHandlerError::Ceiling);
        assert_eq!(
            diagnostic.message,
            if field_bound {
                "Emit no more field mutations than the action's field-mutation bound."
            } else {
                "Emit no more effects than the action's target bound."
            }
        );
    }
    action.handler = None;
    assert_eq!(
        evaluate_action(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err(),
        ActionHandlerError::Source
    );
}

#[test]
fn handler_rejects_ambiguous_sources_and_binds_governed_semantics() {
    let valid = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    let action = compile(project(), &valid).unwrap();
    for (pointer, value) in [
        ("/actions/0/handler/abi", json!("registry.action-plan/v1")),
        ("/actions/0/handler/script", json!("../outside.rhai")),
        ("/actions/0/handler/writes/0/id", json!("friend")),
        ("/actions/0/handler/writes/0/fields", json!(["friend"])),
        (
            "/actions/0/handler/writes/0/fields",
            json!(["name", "name"]),
        ),
        (
            "/actions/0/handler/writes/0/fields",
            json!(["name", "unknown"]),
        ),
        (
            "/actions/0/handler/refusals",
            json!([{"code":"blank-name","label":""}]),
        ),
        ("/actions/0/inputs/2/required", json!(false)),
    ] {
        let mut source = project();
        *source.pointer_mut(pointer).unwrap() = value;
        assert!(compile(source, &valid).is_err(), "{pointer}");
    }
    let mut mixed = project();
    mixed["actions"][0]["effects"] = json!([{"id":"fixed","target":{"entity":"person"},"operation":"create","set":{"name":{"fromField":"given-name"}}}]);
    assert!(compile(mixed, &valid).is_err());
    for script in [
        "fn plan(ctx) { #{} }",
        "fn handle() { #{} }",
        "private fn handle(ctx) { #{} }",
        "fn handle(ctx) { #{} } fn handle(ctx, other) { #{} }",
    ] {
        assert!(compile(project(), script).is_err());
    }
    assert_ne!(
        action.contract_fingerprint,
        compile(project(), &(valid.clone() + "\n// governed change"))
            .unwrap()
            .contract_fingerprint
    );
    let mut changed = project();
    changed["actions"][0]["handler"]["refusals"][0]["label"] =
        json!("A supplied name is required.");
    assert_ne!(
        action.contract_fingerprint,
        compile(changed, &valid).unwrap().contract_fingerprint
    );
    let mut changed = project();
    changed["actions"][0]["handler"]["writes"][0]["fields"] = json!(["name"]);
    assert_ne!(
        action.contract_fingerprint,
        compile(changed, &valid).unwrap().contract_fingerprint
    );
    let mut changed = project();
    changed["entities"][0]["fields"][0]["pattern"] = json!("^.+$");
    assert_ne!(
        action.contract_fingerprint,
        compile(changed, &valid).unwrap().contract_fingerprint
    );
}

#[test]
fn handler_compiler_diagnostics_name_the_authored_handler_boundary() {
    let script = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    let assert_diagnostic = |source, code, path| {
        let failure = compile(source, &script).unwrap_err();
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| { diagnostic.code == code && diagnostic.path == path }),
            "expected {code} at {path}: {:?}",
            failure.diagnostics()
        );
    };

    let mut source = project();
    source["entities"][0]["fields"][0]["classification"] = json!("public");
    assert_diagnostic(
        source,
        "action.handler.classification_ceiling",
        "actions[register-person].handler.writes[slot=person].fields[field=name]",
    );

    let mut source = project();
    source["actions"][0]["handler"]["refusals"] = json!([
        {"code":"blank-name","label":"A name is required."},
        {"code":"blank-name","label":"A second label cannot redefine the same code."},
    ]);
    assert_diagnostic(
        source,
        "action.handler.refusal_invalid",
        "actions[register-person].handler.refusals",
    );

    let mut source = project();
    source["actions"][0]["effects"] = json!([{"id":"fixed","target":{"entity":"person"},"operation":"create","set":{"name":{"fromField":"given-name"}}}]);
    assert_diagnostic(
        source,
        "action.implementation.exclusive",
        "actions[register-person]",
    );

    let mut source = project();
    source["actions"][0]["handler"]["writes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"overlap","target":{"fromField":"person"},"operation":"patch","fields":["name"],
        }));
    assert_diagnostic(
        source,
        "action.effect.overlapping_write",
        "actions[register-person].handler.writes[slot=overlap].fields[field=name]",
    );

    let mut source = project();
    source["actions"][0]["inputs"][2]["required"] = json!(false);
    assert_diagnostic(
        source,
        "action.handler.reference_required",
        "actions[register-person].inputs[person]",
    );

    let mut source = project();
    source["actions"][0]["handler"]["writes"] = Value::Array((0..17).map(|index| json!({
        "id":format!("slot-{index}"),"target":{"entity":"person"},"operation":"create","fields":["name"],
    })).collect());
    assert_diagnostic(
        source,
        "action.bounds.targets",
        "actions[register-person].handler.writes",
    );

    let mut source = project();
    for index in 0..128 {
        let field = format!("flag-{index}");
        source["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id":field,"type":"boolean","classification":"restricted",
            }));
        source["actions"][0]["handler"]["writes"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!(field));
    }
    assert_diagnostic(
        source,
        "action.bounds.field_mutations",
        "actions[register-person].handler.writes",
    );

    let mut source = project();
    source["entities"][0]["fields"][0]["maxLength"] = json!(1_000_000);
    assert_diagnostic(
        source,
        "action.bounds.snapshot_bytes",
        "actions[register-person].handler.writes",
    );
}

#[test]
fn handler_source_diagnostics_distinguish_assets_parse_positions_and_entrypoints() {
    let source = parse_project_json(&serde_json::to_vec(&project()).unwrap()).unwrap();
    for (script, code) in [
        (None, "action.handler.source_missing"),
        (
            Some(&[b' '; registry_breg::rhai_planner::MAXIMUM_SOURCE_BYTES + 1][..]),
            "action.handler.source_bound",
        ),
        (Some(&b"\xff"[..]), "action.handler.source_encoding"),
        (
            Some(&b"fn handle(ctx) {\n let private_source_canary = ;\n}"[..]),
            "action.handler.parse",
        ),
        (
            Some(&b"fn private_source_canary(ctx) { #{} }"[..]),
            "action.handler.entrypoint",
        ),
    ] {
        let assets = script
            .map(|bytes| ModuleAssetSource {
                module: None,
                path: "handlers/register.rhai".into(),
                bytes: bytes.to_vec(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        let failure = compile_project_with_assets(&source, &[], &assets, CompileProfile::Authoring)
            .unwrap_err();
        let diagnostics = failure
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == code)
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1, "{code}: {:?}", failure.diagnostics());
        assert_eq!(
            diagnostics[0].path,
            "actions[register-person].handler.script"
        );
        assert!(!diagnostics[0].message.contains("private_source_canary"));
        if code == "action.handler.parse" {
            assert!(diagnostics[0].message.contains("line 2, column "));
        }
        if code == "action.handler.source_missing" {
            assert!(diagnostics[0].message.contains("handlers/register.rhai"));
        }
    }
}

#[test]
fn handler_bounds_execution_inputs_and_decoded_results() {
    assert_eq!(
        evaluate("fn handle(ctx) { loop {} }").unwrap_err(),
        ActionHandlerError::Resource
    );
    assert!(compile_source("import \"private\"; fn handle(ctx) { #{} }").is_err());
    assert!(compile_source("fn handle(ctx) { eval(\"1\"); }").is_err());
    let valid = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    let action = compile(project(), &valid).unwrap();
    assert_eq!(
        evaluate_action(&action, inputs().as_object().unwrap(), Instant::now()).unwrap_err(),
        ActionHandlerError::Deadline
    );
    for input in [
        json!({}),
        json!({"givenName":"Mina"}),
        json!({"given-name":12}),
        json!({"given-name":null}),
        json!({"given-name":"Mina","extra":true}),
    ] {
        assert!(evaluate_action(
            &action,
            input.as_object().unwrap(),
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());
    }
    let mut action = action;
    action.maximum_snapshot_bytes = 100;
    assert_eq!(
        evaluate_action(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5)
        )
        .unwrap_err(),
        ActionHandlerError::Resource
    );
    assert!(evaluate("fn handle(ctx) { let a = []; for n in 0..65 { a = [a]; } a }").is_err());
}

#[cfg(all(feature = "tooling", feature = "runtime"))]
#[test]
fn handler_package_captures_exact_project_and_module_script_origins() {
    use registry_breg::package::{
        inspect_package_integrity, prepare_package_with_project_assets, PackageBuildRequest,
        PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    };
    let script = result(r#"#{effects:[#{id:"person",set:#{name:"Mina"}}]}"#);
    let asset = PackageSourceFile {
        path: "handlers/register.rhai".into(),
        bytes: script.as_bytes().to_vec(),
    };
    let mut source = project();
    source["package"] = json!({"environment":"local","instanceId":"instance-under-test","sequence":1,"sourceRevision":"compiler-source-revision"});
    let request = PackageBuildRequest {
        environment: "local".into(),
        instance_id: "instance-under-test".into(),
        database_id: "database-under-test".into(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: "compiler-source-revision".into(),
        schema_fingerprint: format!("sha256:{}", "2".repeat(64)),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: vec![],
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".into(),
            bytes: serde_json::to_vec(&source).unwrap(),
        },
        modules: vec![],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".into(),
            bytes: b"apiVersion: registry.registrystack.org/breg-journeys/v1\njourneys: []\n"
                .to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    };
    let package =
        prepare_package_with_project_assets(request.clone(), vec![asset.clone()]).unwrap();
    assert_eq!(
        package.package_revision(),
        prepare_package_with_project_assets(request.clone(), vec![asset.clone()])
            .unwrap()
            .package_revision()
    );
    assert!(prepare_package_with_project_assets(request.clone(), vec![]).is_err());
    let mut revised_asset = asset.clone();
    revised_asset
        .bytes
        .extend_from_slice(b"\n// revised governed source");
    assert_ne!(
        package.package_revision(),
        prepare_package_with_project_assets(request.clone(), vec![revised_asset])
            .unwrap()
            .package_revision()
    );
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let published = directory.path().join("project");
    package.publish_to_directory(&published, vec![]).unwrap();
    inspect_package_integrity(&published).unwrap();
    std::fs::write(
        published.join("source/project/handlers/register.rhai"),
        b"fn handle(ctx) { throw 1; }",
    )
    .unwrap();
    assert!(inspect_package_integrity(&published).is_err());

    let action = source["actions"].take();
    source.as_object_mut().unwrap().remove("actions");
    let module_value = json!({"id":"actions","version":"1","actions":action});
    let module =
        registry_breg::contract::parse_module_json(&serde_json::to_vec(&module_value).unwrap())
            .unwrap();
    let compiler_asset = ModuleAssetSource {
        module: Some("actions".into()),
        path: asset.path.clone(),
        bytes: asset.bytes.clone(),
    };
    source["modules"] = json!([{"id":"actions","version":"1","digest":registry_breg::compiler::module_digest_with_assets(&module, &[compiler_asset])}]);
    let mut module_request = request;
    module_request.project.bytes = serde_json::to_vec(&source).unwrap();
    module_request.modules = vec![PackageModuleSource {
        id: "actions".into(),
        path: "source/modules/actions/module.yaml".into(),
        bytes: serde_json::to_vec(&module_value).unwrap(),
        assets: vec![asset.clone()],
    }];
    let package = prepare_package_with_project_assets(module_request.clone(), vec![]).unwrap();
    let published = directory.path().join("module");
    package.publish_to_directory(&published, vec![]).unwrap();
    inspect_package_integrity(&published).unwrap();
    module_request.modules[0].assets.clear();
    assert!(prepare_package_with_project_assets(module_request, vec![asset]).is_err());
}

#[test]
fn fixed_action_fingerprints_omit_handler_and_bind_native_patterns() {
    let mut source = project();
    source["actions"][0]
        .as_object_mut()
        .unwrap()
        .remove("handler");
    source["actions"][0]["inputs"][0]["maxLength"] = json!(160);
    source["actions"][0]["effects"] = json!([{"id":"person","target":{"entity":"person"},"operation":"create","set":{"name":{"fromField":"given-name"}}}]);
    source["accessProfiles"][0]["permissions"][0]["results"] = json!(["person"]);
    let compile = |source: &Value| {
        let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
        registry_breg::compiler::compile_project(&project, &[], CompileProfile::Authoring)
            .unwrap()
            .actions()
            .actions[0]
            .clone()
    };
    let before = compile(&source);
    assert!(serde_json::to_value(&before)
        .unwrap()
        .get("handler")
        .is_none());
    assert_eq!(
        before.contract_fingerprint,
        compile(&source).contract_fingerprint
    );
    source["entities"][0]["fields"][0]["pattern"] = json!("^.+$");
    assert_ne!(
        before.contract_fingerprint,
        compile(&source).contract_fingerprint
    );
}

#[test]
fn handler_rejects_reference_to_a_create_of_an_incompatible_entity() {
    let mut source = project();
    let mut second = source["entities"][0].clone();
    second["id"] = json!("organization");
    second["route"] = json!("organizations");
    source["entities"].as_array_mut().unwrap().push(second);
    source["actions"][0]["handler"]["writes"][1]["target"]["entity"] = json!("organization");
    source["accessProfiles"][0]["permissions"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"entity":"organization","rowBoundaries":[]}));
    let script = result(
        r#"#{effects:[#{id:"person",set:#{name:"Mina",friend:#{fromEffect:"friend"}}},#{id:"friend",set:#{name:"Company"}}]}"#,
    );
    let action = compile(source, &script).unwrap();
    assert_eq!(
        evaluate_action(
            &action,
            inputs().as_object().unwrap(),
            Instant::now() + Duration::from_secs(5)
        )
        .unwrap_err(),
        ActionHandlerError::Ceiling
    );
}
