// SPDX-License-Identifier: Apache-2.0
//! Canonical Workflow authoring, typed Functions and revision dependency closure.
use registry_coordinator::{authoring, definition::Definition, CoordinatorError};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};

fn project() -> Value {
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id":"typed-workflow","version":"1"},
        "types": {"request": {"type":"object","additionalProperties":false,"required":["text"],
            "properties":{"text":{"type":"string"}}}},
        "functions": {"render": {"runtime":"rhai","source":"functions.rhai","entrypoint":"render",
            "inputs":{"request":{"typeRef":"request"}},"output":{"type":"string"}}},
        "workflow": {"input":{"typeRef":"request"},"deadlineSeconds":3600,"start":"done",
            "steps":{"done":{"type":"finish","outcome":"rendered","output":{"type":"function","function":"render","inputs":{"request":{"type":"input"}}}}},
            "outcomes":{"rendered":{"type":"string"}}}
    })
}

fn load(project: &Value, source: &str) -> registry_coordinator::Result<Definition> {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string_pretty(project).unwrap(),
    )
    .unwrap();
    fs::write(root.path().join("functions.rhai"), source).unwrap();
    Definition::load(root.path())
}

fn refused(project: &Value, source: &str) -> CoordinatorError {
    load(project, source)
        .err()
        .expect("the project must be refused")
}

const SOURCE: &str = "fn render(inputs) { inputs.request.text }";

#[test]
fn named_function_inputs_are_typed_and_the_snapshot_restores_without_sources() {
    let definition = load(&project(), SOURCE).unwrap();
    assert_eq!(
        definition
            .evaluate("done", &json!({"text":"hello"}), &BTreeMap::new())
            .unwrap(),
        json!("hello")
    );
    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
    assert_eq!(
        restored
            .evaluate("done", &json!({"text":"restored"}), &BTreeMap::new())
            .unwrap(),
        json!("restored")
    );
    let error = definition
        .evaluate("done", &json!({"text":42}), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code, "function.input");
    assert!(!error.message.contains("42"));
}

#[test]
fn presentation_version_and_unreferenced_definitions_do_not_change_workflow_revision() {
    let initial = load(&project(), SOURCE).unwrap();
    let mut edited = project();
    edited["title"] = json!("Readable workflow");
    edited["project"]["version"] = json!("next");
    edited["workflow"]["steps"]["done"]["title"] = json!("Show the text");
    edited["functions"]["render"]["title"] = json!("Render a notice");
    edited["types"]["request"]["properties"]["text"]["description"] = json!("Public text");
    edited["types"]["unrelated"] = json!({"type":"integer"});
    edited["functions"]["unrelated"] = json!({"runtime":"rhai","source":"functions.rhai","entrypoint":"render",
        "inputs":{"ignored":{"type":"integer"}},"output":{"type":"string"}});
    let edited = load(&edited, SOURCE).unwrap();
    assert_eq!(initial.digest, edited.digest);
    assert_ne!(initial.snapshot().unwrap(), edited.snapshot().unwrap());
    assert_eq!(
        edited.explain().unwrap()["steps"][0]["presentation"]["title"],
        json!("Show the text")
    );
}

#[test]
fn changed_function_code_or_limits_changes_workflow_revision() {
    let initial = load(&project(), SOURCE).unwrap();
    assert_ne!(
        initial.digest,
        load(
            &project(),
            "fn render(inputs) { inputs.request.text + \"!\" }"
        )
        .unwrap()
        .digest
    );
    let mut edited = project();
    edited["functions"]["render"]["limits"] = json!({"operations":500});
    let edited = load(&edited, SOURCE).unwrap();
    assert_ne!(initial.digest, edited.digest);
    assert_eq!(
        edited.explain().unwrap()["functions"]["render"]["limits"]["operations"],
        500
    );
}

#[test]
fn signature_names_and_closed_output_are_enforced_without_rendering_values() {
    let mut edited = project();
    edited["workflow"]["steps"]["done"]["output"]["inputs"] = json!({"wrong":{"type":"input"}});
    let error = refused(&edited, SOURCE);
    assert!(error
        .diagnostics
        .iter()
        .any(|finding| finding.path == "/workflow/steps/done/output/inputs"));
    let definition = load(&project(), "fn render(inputs) { 42 }").unwrap();
    let error = definition
        .evaluate("done", &json!({"text":"private-canary"}), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code, "function.output");
    assert!(!error.message.contains("private-canary"));
}

#[test]
fn schema_references_resolve_nested_properties_and_preserve_reference_sites() {
    let definition = load(&project(), SOURCE).unwrap();
    assert_eq!(
        definition.workflow.input["properties"]["text"]["type"],
        "string"
    );
    let references = definition.explain().unwrap()["references"].clone();
    assert_eq!(
        references["/workflow/input/typeRef"]["target"],
        "/types/request"
    );
    assert!(references["/workflow/input/typeRef"]["source"]["line"].is_number());
    assert_eq!(
        references["/workflow/steps/done/output/function"]["target"],
        "/functions/render"
    );
}

#[test]
fn schema_cycles_mixtures_and_undeclared_references_point_to_authored_fields() {
    for (schema, expected) in [
        (json!({"typeRef":"missing"}), "/workflow/input"),
        (
            json!({"typeRef":"request","type":"object"}),
            "/workflow/input",
        ),
    ] {
        let mut edited = project();
        edited["workflow"]["input"] = schema;
        let error = refused(&edited, SOURCE);
        assert_eq!(error.diagnostics[0].path, expected);
        assert!(error.diagnostics[0].source.as_ref().unwrap().line.is_some());
    }
    let mut edited = project();
    edited["types"]["request"]["properties"]["text"] = json!({"typeRef":"request"});
    assert!(refused(&edited, SOURCE).diagnostics[0]
        .message
        .contains("cycle"));
}

#[test]
fn the_default_profile_has_no_clock_and_narrowing_cannot_widen_it() {
    let error = refused(&project(), "fn render(inputs) { timestamp().to_string() }");
    assert_eq!(error.code, "coordinator.function.unknown-call");
    let mut edited = project();
    edited["functions"]["render"]["limits"] = json!({"operations":100001});
    let error = refused(&edited, SOURCE);
    assert_eq!(
        error.diagnostics[0].path,
        "/functions/render/limits/operations"
    );
    assert_eq!(error.diagnostics[0].code, "config.out-of-range");
}

#[test]
fn removed_top_level_shape_and_positional_arguments_are_refused() {
    let mut edited = project();
    edited["functionsFile"] = json!("functions.rhai");
    assert!(refused(&edited, SOURCE)
        .diagnostics
        .iter()
        .any(|finding| finding.path == "/functionsFile"));
    let mut edited = project();
    edited["workflow"]["steps"]["done"]["output"]["arguments"] = json!([{ "type":"input" }]);
    assert!(refused(&edited, SOURCE)
        .diagnostics
        .iter()
        .any(|finding| finding.path == "/workflow/steps/done/output/arguments"));
}

#[test]
fn poll_completion_uses_base_schemas_then_resolves_typed_terminal_output() {
    let mut edited = project();
    edited["operations"] = json!({"read-job":{"uses":"external.get/v1","connection":"jobs","responseSchema":{"type":"object","required":["status","body"],"additionalProperties":false,"properties":{"status":{"type":"integer"},"body":{"type":"object"}}},
        "completions":{"terminal":{"type":"bounded-poll","interpret":"observe","intervalSeconds":30}}}});
    edited["functions"] = json!({"observe":{"runtime":"rhai","source":"functions.rhai","entrypoint":"observe",
    "inputs":{"command":{"operationInput":"read-job"},"response":{"operationOutput":"read-job"}},"output":{"oneOf":[
        {"type":"object","additionalProperties":false,"required":["state"],"properties":{"state":{"type":"string","const":"pending"}}},
        {"type":"object","additionalProperties":false,"required":["state","result"],"properties":{"state":{"type":"string","const":"complete"},"result":{"type":"string"}}},
        {"type":"object","additionalProperties":false,"required":["state","code"],"properties":{"state":{"type":"string","const":"refused"},"code":{"type":"string","enum":["job-failed"]}}}
    ]}}});
    edited["workflow"] = json!({"input":{"type":"null"},"deadlineSeconds":900,"start":"read","steps":{
        "read":{"type":"call","operation":"read-job","input":{"type":"fields","fields":{"path":{"type":"literal","value":"/status"}}},"next":"wait"},
        "wait":{"type":"wait-for","completion":{"step":"read","name":"terminal"},"timeoutSeconds":600,"next":"done"},
        "done":{"type":"finish","outcome":"terminal","output":{"type":"step","step":"wait"}}},
        "outcomes":{"terminal":{"completionOutput":{"operation":"read-job","name":"terminal"}}}});
    let definition = load(&edited, "fn observe(inputs) { #{state: \"pending\"} }").unwrap();
    let reference = registry_coordinator::definition::CompletionReference {
        step: "read".into(),
        name: "terminal".into(),
    };
    let contract = definition.completion_contract(&reference).unwrap();
    assert!(std::ptr::eq(
        contract,
        definition.completion_contract(&reference).unwrap()
    ));
    contract
        .check(&json!({"state":"complete","result":"ready"}))
        .unwrap();
    contract
        .check(&json!({"state":"refused","code":"job-failed"}))
        .unwrap();
    assert!(contract.check(&json!({"state":"pending"})).is_err());
    let violation = contract
        .check(&json!({"state":"complete","result":"x".repeat(16_385)}))
        .unwrap_err();
    assert!(violation.path.is_empty());
    assert_eq!(
        violation.expected,
        "a value within the host's bounded JSON contract"
    );
    assert_eq!(
        definition.workflow.references["/workflow/steps/wait/completion/name"].target,
        "/operations/read-job/completions/terminal"
    );
    let observation = definition.explain().unwrap()["operationContracts"]["external.get/v1"]
        ["completionObservation"]
        .clone();
    assert_eq!(observation["profile"], "bounded-poll");
    assert_eq!(observation["minimumIntervalSeconds"], 30);
    assert_eq!(observation["maximumRetryAfterSeconds"], 86400);
    let output = &definition.workflow.outcomes["terminal"];
    assert_eq!(output["oneOf"].as_array().unwrap().len(), 2);
    definition
        .validate_outcome("terminal", &json!({"state":"refused","code":"job-failed"}))
        .unwrap();
    assert!(definition
        .validate_outcome("terminal", &json!({"state":"pending"}))
        .is_err());
    edited["functions"]["observe"]["output"]["oneOf"][1]["title"] =
        json!("A successful job observation");
    let retitled = load(&edited, "fn observe(inputs) { #{state: \"pending\"} }").unwrap();
    assert_eq!(definition.digest, retitled.digest);
    edited["types"]["job-result"] = json!({
        "$defs":{"identifier":{"type":"string","minLength":1}},
        "type":"object","required":["id"],"additionalProperties":false,
        "properties":{"id":{"$ref":"#/$defs/identifier"}}
    });
    edited["functions"]["observe"]["output"]["oneOf"][1]["properties"]["result"] =
        json!({"typeRef":"job-result"});
    let referenced = load(&edited, "fn observe(inputs) { #{state: \"pending\"} }").unwrap();
    referenced
        .validate_outcome(
            "terminal",
            &json!({"state":"complete","result":{"id":"job-1"}}),
        )
        .unwrap();
    assert!(referenced
        .validate_outcome("terminal", &json!({"state":"complete","result":{"id":42}}))
        .is_err());
    let restored = Definition::from_snapshot(&referenced.snapshot().unwrap()).unwrap();
    restored
        .completion_contract(&reference)
        .unwrap()
        .check(&json!({"state":"complete","result":{"id":"job-1"}}))
        .unwrap();
    restored
        .validate_outcome("terminal", &json!({"state":"refused","code":"job-failed"}))
        .unwrap();
    edited["functions"]["observe"]["output"] =
        json!({"completionOutput":{"operation":"read-job","name":"terminal"}});
    let error = refused(&edited, "fn observe(inputs) { #{state: \"pending\"} }");
    assert_eq!(error.diagnostics[0].path, "/functions/observe/output");
}

#[cfg(feature = "schema")]
#[test]
fn generated_schema_describes_the_same_canonical_model() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    assert!(validator.is_valid(&project()));
    assert!(schema["properties"].get("workflow").is_some());
    assert!(schema["properties"].get("functionsFile").is_none());
}

#[test]
fn whole_schema_references_rebase_local_definitions_when_embedded() {
    let mut edited = project();
    edited["types"]["message"] = json!({"type":"object","additionalProperties":false,"required":["value"],
        "$defs":{"text":{"type":"string","minLength":2}},
        "properties":{"value":{"$ref":"#/$defs/text"}}});
    edited["types"]["request"]["properties"]["text"] = json!({"typeRef":"message"});
    edited["functions"]["render"]["output"] = json!({"typeRef":"message"});
    edited["workflow"]["outcomes"]["rendered"] = json!({"typeRef":"message"});
    let definition = load(&edited, SOURCE).unwrap();
    assert!(definition
        .validate_input(&json!({"text":{"value":"x"}}))
        .is_err());
    let input = json!({"text":{"value":"valid"}});
    definition.validate_input(&input).unwrap();
    assert_eq!(
        definition
            .evaluate("done", &input, &BTreeMap::new())
            .unwrap(),
        json!({"value":"valid"})
    );
}

#[test]
fn function_source_assets_cannot_escape_the_project() {
    let mut edited = project();
    edited["functions"]["render"]["source"] = json!("../outside.rhai");
    let error = refused(&edited, SOURCE);
    assert!(error.message.contains("relative path"));
}

#[test]
fn generated_owner_action_schemas_specialize_inputs_outputs_and_revision_closure() {
    let root = tempfile::tempdir().unwrap();
    let artifact: Value = serde_json::from_str(include_str!(
        "fixtures/breg-contracts/facilities.contract.json"
    ))
    .unwrap();
    let project = json!({"apiVersion":authoring::API_VERSION,"kind":authoring::KIND,"project":{"id":"owner-contract","version":"1"},
        "contracts":{"facilities":{"type":"breg","source":"facilities.json"}},
        "operations":{"correction":{"uses":"breg.invoke-action/v1","connection":"facilities","action":{"contract":"facilities","id":"register-facility"}}},
        "workflow":{"input":{"operationInput":"correction"},"deadlineSeconds":60,"start":"correct","steps":{
            "correct":{"type":"call","operation":"correction","input":{"type":"input"},"next":"done"},
            "done":{"type":"finish","outcome":"accepted","output":{"type":"step","step":"correct"}}},
            "outcomes":{"accepted":{"operationOutput":"correction"}}}});
    fs::write(root.path().join("workflow.yaml"), project.to_string()).unwrap();
    fs::write(root.path().join("facilities.json"), artifact.to_string()).unwrap();
    let initial = Definition::load(root.path()).unwrap();
    assert_eq!(
        initial.workflow.input["properties"]["input"]["properties"]["operatorId"]["format"],
        "uuid"
    );
    assert_eq!(
        initial.workflow.outcomes["accepted"]["properties"]["results"]["properties"]["facility"]
            ["properties"]["revision"]["type"],
        "integer"
    );
    let action = initial.workflow.operations["correction"]
        .action
        .as_ref()
        .unwrap();
    assert_eq!(action.action_id, "register-facility");
    assert!(action.action_revision.starts_with("sha256:"));
    let mut unrelated = artifact;
    unrelated["actions"][0]["display"]["label"] = json!("A renamed unrelated Action");
    fs::write(root.path().join("facilities.json"), unrelated.to_string()).unwrap();
    let edited = Definition::load(root.path()).unwrap();
    assert_eq!(initial.digest, edited.digest);
    assert_ne!(initial.snapshot().unwrap(), edited.snapshot().unwrap());
}

#[test]
fn imported_action_reference_errors_point_to_the_authored_selection() {
    let root = tempfile::tempdir().unwrap();
    let artifact = include_str!("fixtures/breg-contracts/facilities.contract.json");
    fs::write(root.path().join("facilities.json"), artifact).unwrap();
    let original = json!({"apiVersion":authoring::API_VERSION,"kind":authoring::KIND,"project":{"id":"owner-reference","version":"1"},
        "contracts":{"facilities":{"type":"breg","source":"facilities.json"}},
        "operations":{"correction":{"uses":"breg.invoke-action/v1","connection":"facilities","action":{"contract":"facilities","id":"register-facility"}}},
        "workflow":{"input":{"operationInput":"correction"},"deadlineSeconds":60,"start":"correct","steps":{
            "correct":{"type":"call","operation":"correction","input":{"type":"input"},"next":"done"},
            "done":{"type":"finish","outcome":"accepted","output":{"type":"step","step":"correct"}}},
            "outcomes":{"accepted":{"operationOutput":"correction"}}}});
    for member in ["contract", "id"] {
        let mut changed = original.clone();
        changed["operations"]["correction"]["action"][member] = json!("undeclared");
        fs::write(
            root.path().join("workflow.yaml"),
            serde_json::to_string_pretty(&changed).unwrap(),
        )
        .unwrap();
        let error = Definition::load(root.path())
            .err()
            .expect("bad selection refuses");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(
            diagnostic.path,
            format!("/operations/correction/action/{member}")
        );
        assert!(diagnostic.source.as_ref().unwrap().line.unwrap() > 1);
        assert!(!diagnostic.code.starts_with("coordinator.coordinator."));
    }
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string_pretty(&original).unwrap(),
    )
    .unwrap();
    fs::write(root.path().join("facilities.json"), "{}").unwrap();
    let error = Definition::load(root.path())
        .err()
        .expect("invalid export refuses");
    assert_eq!(error.diagnostics[0].path, "/contracts/facilities/source");
    assert_eq!(
        error.diagnostics[0].code,
        "coordinator.operation.contract-invalid"
    );
}

#[test]
fn unavailable_and_nonregular_contract_imports_keep_the_authored_source_position() {
    let root = tempfile::tempdir().unwrap();
    let mut authored = project();
    authored["contracts"] = json!({"registry":{"type":"breg","source":"contract.json"}});
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string_pretty(&authored).unwrap(),
    )
    .unwrap();
    for (directory, exit) in [(false, 3), (true, 1)] {
        if directory {
            fs::create_dir(root.path().join("contract.json")).unwrap();
        }
        let error = Definition::load(root.path()).err().unwrap();
        assert_eq!(error.exit_code, exit);
        assert_eq!(error.diagnostics[0].path, "/contracts/registry/source");
        let source = error.diagnostics[0].source.as_ref().unwrap();
        assert!(source.file.ends_with("workflow.yaml"));
        assert!(source.line.is_some_and(|line| line > 1));
    }
}

#[cfg(unix)]
#[test]
fn unreadable_contract_import_keeps_the_authored_source_position() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let asset = root.path().join("contract.json");
    let mut authored = project();
    authored["contracts"] = json!({"registry":{"type":"breg","source":"contract.json"}});
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string_pretty(&authored).unwrap(),
    )
    .unwrap();
    fs::write(&asset, "{}").unwrap();
    let permissions = fs::metadata(&asset).unwrap().permissions();
    fs::set_permissions(&asset, fs::Permissions::from_mode(0o0)).unwrap();
    if fs::read(&asset).is_ok() {
        fs::set_permissions(&asset, permissions).unwrap();
        eprintln!(
            "skipping unreadable import assertion: this process can read a file with mode 000"
        );
        return;
    }
    let error = Definition::load(root.path()).err();
    fs::set_permissions(&asset, permissions).unwrap();
    let error = error.expect("an unreadable import must refuse authoring");
    assert_eq!(error.exit_code, 3);
    assert_eq!(error.code, "coordinator.definition.read");
    assert_eq!(error.diagnostics[0].path, "/contracts/registry/source");
    let source = error.diagnostics[0].source.as_ref().unwrap();
    assert!(source.file.ends_with("workflow.yaml"));
    assert!(source.line.is_some_and(|line| line > 1));
}

#[test]
fn literal_schema_data_cannot_declare_resources_or_change_revision_rules() {
    let mut edited = project();
    edited["workflow"]["input"] = json!({"const":{"$id":"literal-value","$ref":"https://example.invalid/data","typeRef":"literal-data"}});
    edited["workflow"]["steps"]["done"]["output"] = json!({"type":"literal","value":"done"});
    let definition = load(&edited, SOURCE).unwrap();
    definition
        .validate_input(&json!({"$id":"literal-value","$ref":"https://example.invalid/data","typeRef":"literal-data"}))
        .unwrap();
    assert!(!definition
        .workflow
        .references
        .contains_key("/workflow/input/const/typeRef"));
    edited["workflow"]["input"] = json!({"$ref":"https://example.invalid/schema"});
    assert!(load(&edited, SOURCE).is_err());
    edited["workflow"]["input"] = json!({"$id":"https://example.invalid/schema","type":"object"});
    assert!(load(&edited, SOURCE).is_err());
}

#[test]
fn explain_exposes_the_registered_host_contract_pinned_by_the_operation_revision() {
    let project = json!({"apiVersion":authoring::API_VERSION,"kind":authoring::KIND,
        "project":{"id":"host-contract","version":"1"},
        "operations":{"send":{"uses":"messaging.submit-message/v1","connection":"messages"}},
        "workflow":{"input":{"operationInput":"send"},"deadlineSeconds":60,"start":"send",
            "steps":{"send":{"type":"call","operation":"send","input":{"type":"input"},"next":"done"},
                "done":{"type":"finish","outcome":"sent","output":{"type":"step","step":"send"}}},
            "outcomes":{"sent":{"operationOutput":"send"}}}});
    let initial = load(&project, "").unwrap();
    let expected = registry_coordinator::protocol::Operation::SubmitMessage
        .descriptor()
        .host_contract();
    assert_eq!(
        initial.explain().unwrap()["operationContracts"]["messaging.submit-message/v1"],
        expected
    );
    assert_eq!(
        expected["limits"]["value"],
        json!({
            "maximumBytes":131072,"maximumDepth":32,"maximumNodes":4096,
            "maximumArrayItems":256,"maximumObjectMembers":256,"maximumStringBytes":16384
        })
    );
    assert_eq!(expected["limits"]["attemptTimeoutSeconds"], 10);
    assert_eq!(expected["limits"]["maximumPreparationBytes"], 65536);
    assert_eq!(expected["limits"]["maximumCallAttempts"], 10);
    assert_eq!(expected["limits"]["maximumCallRetryDelaySeconds"], 300);
    assert_eq!(
        expected["limits"]["http"],
        json!({
            "maximumResponseBytes":65536,"attemptTimeoutMilliseconds":2000,
            "connectTimeoutMilliseconds":1000,"maximumMutationRetries":0
        })
    );
    let external = registry_coordinator::protocol::Operation::ExternalGet
        .descriptor()
        .host_contract();
    assert_eq!(
        external["limits"]["http"]["attemptTimeoutMilliseconds"],
        2000
    );
    assert_eq!(external["limits"]["http"]["connectionMayLowerLimits"], true);
    let evaluation = registry_coordinator::protocol::Operation::EvaluateDecision
        .descriptor()
        .host_contract();
    assert_eq!(
        evaluation["limits"]["http"]["attemptTimeoutMilliseconds"],
        8000
    );
    assert_eq!(evaluation["limits"]["http"]["maximumRequestBytes"], 65536);
    for contract in [&expected, &external, &evaluation] {
        assert!(contract["limits"]["http"]
            .get("requestTimeoutMilliseconds")
            .is_none());
        assert!(contract["limits"]["http"].get("mutationRetries").is_none());
    }
    assert_eq!(
        initial.explain().unwrap()["valueLimits"],
        expected["limits"]["value"]
    );
    assert_eq!(expected["completionObservation"], Value::Null);
    let restored = Definition::from_snapshot(&initial.snapshot().unwrap()).unwrap();
    assert_eq!(initial.digest, restored.digest);
    assert_eq!(
        initial.workflow.operations["send"].revision,
        restored.workflow.operations["send"].revision
    );
    assert_eq!(
        restored.explain().unwrap()["operationContracts"]["messaging.submit-message/v1"],
        expected
    );
}

#[test]
fn neutral_review_context_modes_use_the_exact_owning_operation_schema() {
    let project = json!({"apiVersion":authoring::API_VERSION,"kind":authoring::KIND,
        "project":{"id":"review-context","version":"1"},
        "operations":{"review":{"uses":"casework.submit-review-request/v1","connection":"review"}},
        "workflow":{"input":{"operationInput":"review"},"deadlineSeconds":60,"start":"submit",
            "steps":{"submit":{"type":"call","operation":"review","input":{"type":"input"},"next":"done"},
                "done":{"type":"finish","outcome":"accepted","output":{"type":"step","step":"submit"}}},
            "outcomes":{"accepted":{"operationOutput":"review"}}}});
    let definition = load(&project, "").unwrap();
    let mut input = json!({
        "policy":{"id":"notice-review","version":"1","digest":format!("sha256:{}","b".repeat(64))},
        "subject":{"source":"notices","type":"notice","id":"notice-7","version":"3","digest":format!("sha256:{}","a".repeat(64))},
        "requesterReference":"notice-request-7",
        "context":{"mode":"submitted","snapshot":{"summary":"Synthetic notice"}}
    });
    definition.validate_input(&input).unwrap();
    input["context"] = json!({"mode":"current-source","binding":{"reference":"notice-7"}});
    definition.validate_input(&input).unwrap();
    for context in [
        json!({"strategy":"submitted","snapshot":{"summary":"Synthetic notice"}}),
        json!({"strategy":"current-source","binding":{"reference":"notice-7"}}),
        json!({"mode":"current-source","reference":"notice-7"}),
    ] {
        input["context"] = context;
        assert!(definition.validate_input(&input).is_err());
    }
}
