// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use registry_coordinator::{definition::Definition, CoordinatorError};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};
use tempfile::TempDir;

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const SOURCE: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const CANARY: &str = "secret-value-never-render-this";

fn project(workflow: &str, source: &str) -> TempDir {
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join("workflow.yaml"), workflow).unwrap();
    fs::write(project.path().join("functions.rhai"), source).unwrap();
    project
}
fn load(workflow: &str, source: &str) -> registry_coordinator::Result<Definition> {
    Definition::load(project(workflow, source).path())
}
fn fixture() -> Definition {
    load(WORKFLOW, SOURCE).unwrap()
}
/// The example's wait and read computed by functions rather than references,
/// so a test can replace a function body with the expression it exercises.
fn authored_value(source: &str) -> Value {
    registry_platform_yaml::Reader::new("workflow.yaml")
        .scan(source.as_bytes())
        .unwrap()
        .unwrap()
        .to_json_value()
}
fn computed_workflow() -> String {
    let mut workflow = authored_value(WORKFLOW);
    workflow["functions"]["send-after"] = json!({"runtime":"rhai","source":"functions.rhai","entrypoint":"send_after",
        "inputs":{"input":{"typeRef":"workflow-input"}},"output":{"type":"string","format":"date-time"}});
    workflow["functions"]["read-request"] = json!({"runtime":"rhai","source":"functions.rhai","entrypoint":"read_request",
        "inputs":{"input":{"typeRef":"workflow-input"}},"output":{"operationInput":"applications-read-record"}});
    workflow["workflow"]["steps"]["due"]["waitUntil"] =
        json!({"type":"function","function":"send-after","inputs":{"input":{"type":"input"}}});
    workflow["workflow"]["steps"]["read-application"]["input"] =
        json!({"type":"function","function":"read-request","inputs":{"input":{"type":"input"}}});
    workflow.to_string()
}
fn computed_source() -> String {
    format!("{SOURCE}\nfn send_after(input) {{ let input = input.input; input.sendAfter }}\nfn read_request(input) {{ let input = input.input; #{{ collection: \"applications\", recordId: input.applicationId }} }}")
}
fn input() -> Value {
    json!({"applicationId": "00000000-0000-4000-8000-000000000001", "sendAfter": "2026-10-10T09:00:00Z"})
}
/// A read-record success that satisfies the operation output contract.
fn record(domain_data: Value) -> Value {
    json!({
        "meta": {"registryIdentifier": "applications-registry", "datasetIdentifier": "applications",
            "entityTypeIdentifier": "application"},
        "data": {"recordIdentifier": "00000000-0000-4000-8000-000000000001",
            "revisionIdentifier": "revision-1", "domainData": domain_data}
    })
}
fn instant(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}
fn refused(result: registry_coordinator::Result<Definition>) -> CoordinatorError {
    match result {
        Ok(_) => panic!("definition must refuse"),
        Err(error) => error,
    }
}

#[test]
fn synthetic_fixture_maps_current_permission_and_receipt() {
    let definition = fixture();
    let input = input();
    let now = instant("2026-10-09T09:00:00Z");
    assert_eq!(
        definition.initial_due(&input, now).unwrap(),
        Some(instant("2026-10-10T09:00:00Z"))
    );
    assert_eq!(
        definition.deadline_at(now).unwrap(),
        instant("2026-11-08T09:00:00Z")
    );
    assert_eq!(
        definition
            .evaluate("read-application", &input, &BTreeMap::new())
            .unwrap(),
        json!({"collection": "applications", "recordId": input["applicationId"]})
    );
    let current_record = record(json!({"noticeAllowed": true, "email": "person@example.invalid"}));
    let mut outputs = BTreeMap::from([("read-application".into(), current_record)]);
    assert_eq!(
        definition.evaluate("permission", &input, &outputs).unwrap(),
        "send"
    );
    let command = definition.evaluate("notify", &input, &outputs).unwrap();
    assert_eq!(command["to"]["email"], "person@example.invalid");
    outputs.insert(
        "notify".into(),
        json!({"id": "00000000-0000-4000-8000-000000000002"}),
    );
    let outcome = definition.evaluate("accepted", &input, &outputs).unwrap();
    definition
        .validate_outcome("message-accepted", &outcome)
        .unwrap();
    outputs.insert(
        "read-application".into(),
        record(json!({"noticeAllowed": false})),
    );
    assert_eq!(
        definition.evaluate("permission", &input, &outputs).unwrap(),
        "skip"
    );
    definition
        .validate_outcome("no-current-permission", &Value::Null)
        .unwrap();
}

#[test]
fn shared_mapping_is_validated_only_for_the_executing_branch() {
    let workflow = json!({
        "apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"shared-mapping","version":"1"},
        "functions":{
            "branch":{"runtime":"rhai","source":"functions.rhai","entrypoint":"branch","inputs":{"input":{"type":"object"}},"output":{"type":"string","enum":["number","text"]}},
            "value":{"runtime":"rhai","source":"functions.rhai","entrypoint":"value","inputs":{"input":{"type":"object"}},"output":{}}
        },"workflow":{"input":{"type":"object","required":["choice","value"],"properties":{"choice":{"enum":["number","text"]},"value":{}},"additionalProperties":false},"deadlineSeconds":3600,"start":"select",
            "steps":{
                "select":{"type":"choose","choose":{"type":"function","function":"branch","inputs":{"input":{"type":"input"}}},"cases":{"number":"finish-number","text":"finish-text"}},
                "finish-number":{"type":"finish","outcome":"number","output":{"type":"function","function":"value","inputs":{"input":{"type":"input"}}}},
                "finish-text":{"type":"finish","outcome":"text","output":{"type":"function","function":"value","inputs":{"input":{"type":"input"}}}}
            },"outcomes":{"number":{"type":"integer"},"text":{"type":"string"}}}
    });
    let definition = load(
        &serde_norway::to_string(&workflow).unwrap(),
        "fn branch(args) { args.input.choice } fn value(args) { args.input.value }",
    )
    .unwrap();
    for (choice, value, other) in [
        ("number", json!(42), "text"),
        ("text", json!("accepted"), "number"),
    ] {
        let scenario = serde_json::from_value(json!({
            "name": choice, "admittedAt": "2026-10-09T09:00:00Z",
            "input": {"choice": choice, "value": value}, "replies": {},
            "expect": {"path": ["select", format!("finish-{choice}")],
                "state": "completed", "outcome": choice, "output": value}
        }))
        .unwrap();
        let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
        assert_eq!(report.outcome.as_deref(), Some(choice));
        assert_eq!(report.output, Some(value));

        let wrong_step = format!("finish-{other}");
        let error = definition
            .evaluate(&wrong_step, &scenario.input, &BTreeMap::new())
            .unwrap_err();
        assert_eq!(error.code, "definition.outcome");
        assert_eq!(
            error.field.as_deref(),
            Some(format!("steps.{wrong_step}.output").as_str())
        );
    }
}

#[test]
fn snapshot_restores_exact_functions_after_project_changes_or_removal() {
    let project = project(&computed_workflow(), &computed_source());
    let original = Definition::load(project.path()).unwrap();
    let snapshot = original.snapshot().unwrap();
    fs::write(
        project.path().join("functions.rhai"),
        computed_source().replace("input.sendAfter", "42"),
    )
    .unwrap();
    drop(project);
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.digest, original.digest);
    assert_eq!(restored.snapshot().unwrap(), snapshot);
    assert_eq!(
        restored
            .initial_due(&input(), instant("2026-10-09T09:00:00Z"))
            .unwrap(),
        Some(instant("2026-10-10T09:00:00Z"))
    );
}

#[test]
fn definition_cache_compiles_each_snapshot_once_within_its_bound() {
    use registry_coordinator::definition::DefinitionCache;
    use std::sync::Arc;

    let original = Arc::new(fixture());
    let snapshot = original.snapshot().unwrap();
    let cache = DefinitionCache::new(2);
    cache.seed(original.clone()).unwrap();
    assert!(Arc::ptr_eq(&cache.get(&snapshot).unwrap(), &original));
    assert_eq!(cache.len(), 1);

    let other = load(WORKFLOW, &format!("{SOURCE}\n// second flow\n"))
        .unwrap()
        .snapshot()
        .unwrap();
    let first = cache.get(&other).unwrap();
    assert!(Arc::ptr_eq(&first, &cache.get(&other).unwrap()));
    assert_ne!(first.digest, original.digest);
    assert_eq!(cache.len(), 2);

    let refused = cache.get("{}").err().unwrap();
    assert_eq!(
        refused.code,
        Definition::from_snapshot("{}").err().unwrap().code
    );
    assert_eq!(cache.len(), 2, "a refused snapshot is never cached");

    let third = load(WORKFLOW, &format!("{SOURCE}\n// third flow\n"))
        .unwrap()
        .snapshot()
        .unwrap();
    cache.get(&third).unwrap();
    assert_eq!(cache.len(), 1, "a full cache starts again from empty");
    assert!(!Arc::ptr_eq(&cache.get(&snapshot).unwrap(), &original));
}

#[test]
fn digest_pins_plan_schema_and_exact_function_bytes() {
    let baseline = fixture().digest;
    assert_ne!(
        baseline,
        load(WORKFLOW, &format!("{SOURCE}\n// extra source bytes\n"))
            .unwrap()
            .digest
    );
    assert_ne!(
        baseline,
        load(
            &WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: 2505600"),
            SOURCE
        )
        .unwrap()
        .digest
    );
    let mut changed_schema = authored_value(WORKFLOW);
    changed_schema["workflow"]["outcomes"]["message-accepted"]["properties"]["messageId"]
        .as_object_mut()
        .unwrap()
        .remove("format");
    assert_ne!(
        baseline,
        load(&changed_schema.to_string(), SOURCE).unwrap().digest
    );
    assert_eq!(
        baseline,
        load(&format!("# cosmetic workflow comment\n{WORKFLOW}"), SOURCE)
            .unwrap()
            .digest
    );
}

#[test]
fn bad_graphs_and_whole_value_references_refuse() {
    let base = authored_value(WORKFLOW);
    for (pointer, value) in [
        ("/workflow/steps/due/next", json!("due")),
        ("/workflow/steps/due/next", json!("missing")),
        ("/workflow/start", json!("missing")),
        ("/workflow/steps/permission/cases", json!({})),
        (
            "/workflow/steps/permission/choose/inputs/record/step",
            json!("read-application.output.data"),
        ),
        (
            "/workflow/steps/permission/choose/inputs/record/step",
            json!("notify"),
        ),
        ("/workflow/steps/due/next", json!("permission")),
        (
            "/workflow/steps/read-application/operation",
            json!("notices-submit-message"),
        ),
        (
            "/workflow/steps/read-application/operation",
            json!("arbitrary-http"),
        ),
        ("/workflow/deadlineSeconds", json!("é")),
        ("/functions/notice-route/source", json!("../functions.rhai")),
        ("/workflow/deadlineSeconds", json!("${DEADLINE}")),
    ] {
        let mut workflow = base.clone();
        *workflow.pointer_mut(pointer).unwrap() = value;
        refused(load(&workflow.to_string(), SOURCE));
    }
    let mut unknown = base.clone();
    unknown["unknown"] = json!(true);
    refused(load(&unknown.to_string(), SOURCE));
    refused(load(
        &base.to_string().replacen("{", "{\"project\":{},", 1),
        SOURCE,
    ));
    let mut joined = base;
    joined["workflow"]["steps"]["permission"]["cases"]["skip"] = json!("accepted");
    joined["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .remove("skipped");
    joined["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("no-current-permission");
    assert_eq!(
        refused(load(&joined.to_string(), SOURCE)).code,
        "coordinator.mapping.dominance"
    );
}

#[test]
fn function_name_arity_and_disabled_language_refuse() {
    let (workflow, source) = (computed_workflow(), computed_source());
    for source in [
        source.replace("fn send_after(input)", "fn other(input)"),
        source.replace("fn send_after(input)", "fn send_after(input, extra)"),
        format!("{source}\nfn send_after(x, y) {{ x }}"),
        source.replace("input.sendAfter", "eval(\"42\")"),
        source.replace("input.sendAfter", "import \"external\"; input.sendAfter"),
    ] {
        refused(load(&workflow, &source));
    }
    refused(load(WORKFLOW, &" ".repeat(65_537)));
}

#[test]
fn branch_timestamp_schema_and_missing_values_refuse_without_values() {
    let definition = load(
        WORKFLOW,
        &SOURCE.replace(
            "if record.data.domainData.noticeAllowed { \"send\" } else { \"skip\" }",
            &format!("\"{CANARY}\""),
        ),
    )
    .unwrap();
    let outputs = BTreeMap::from([(
        "read-application".into(),
        record(json!({"noticeAllowed":true})),
    )]);
    let error = definition
        .evaluate("permission", &input(), &outputs)
        .unwrap_err();
    assert_eq!(error.code, "function.output");
    assert!(!error.to_string().contains(CANARY));
    let definition = fixture();
    assert_eq!(
        definition
            .evaluate("notify", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "mapping.missing_output"
    );
    let outputs = BTreeMap::from([("notify".into(), json!({"id": CANARY}))]);
    let error = definition
        .evaluate("accepted", &input(), &outputs)
        .unwrap_err();
    assert_eq!(error.code, "definition.outcome");
    assert!(!error.to_string().contains(CANARY));
    assert!(definition
        .validate_input(&json!({"applicationId": CANARY, "sendAfter": CANARY}))
        .is_err());
    assert!(definition.validate_input(&json!({"applicationId": input()["applicationId"], "sendAfter": "2026-10-10T09:00:00Z", "extra": CANARY})).is_err());
    let bad_due = load(
        &computed_workflow(),
        &computed_source().replace("input.sendAfter", "42"),
    )
    .unwrap();
    assert_eq!(
        bad_due
            .initial_due(&input(), instant("2026-10-09T09:00:00Z"))
            .unwrap_err()
            .code,
        "function.output"
    );
}

#[test]
fn pure_profile_has_no_clock_sleep_or_io_and_limits_computation() {
    let (workflow, source) = (computed_workflow(), computed_source());
    for expression in ["sleep(0)", "timestamp()", "read_file(\"anything\")"] {
        let definition = load(&workflow, &source.replace("input.sendAfter", expression)).unwrap();
        assert_eq!(
            definition
                .evaluate("due", &input(), &BTreeMap::new())
                .unwrap_err()
                .code,
            "function.execution"
        );
    }
    for expression in [
        "let n = 0; loop { n += 1; }",
        "let items = []; for n in 0..300 { items.push(n); } items",
        "let s = \"abcdefghijklmnop\"; for n in 0..2000 { s += \"abcdefghijklmnop\"; } s",
    ] {
        let definition = load(&workflow, &source.replace("input.sendAfter", expression)).unwrap();
        assert_eq!(
            definition
                .evaluate("due", &input(), &BTreeMap::new())
                .unwrap_err()
                .code,
            "function.resource_limit"
        );
    }
    let definition = load(
        &workflow,
        &source.replace("input.sendAfter", &format!("throw \"{CANARY}\"")),
    )
    .unwrap();
    let error = definition
        .evaluate("due", &input(), &BTreeMap::new())
        .unwrap_err();
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn snapshots_refuse_unsupported_abi_duplicate_fields_and_mutation() {
    let mut definition = fixture();
    let snapshot = definition.snapshot().unwrap();
    let mut value: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(
        value["schemaAbi"],
        "coordinator/jsonschema-0.18/draft202012/formats-asserted+uuid+numeric-widths/v2"
    );
    value["schemaAbi"] = json!("coordinator/jsonschema-0.18/draft202012/formats-asserted+uuid/v1");
    assert_eq!(
        refused(Definition::from_snapshot(&value.to_string())).code,
        "definition.abi"
    );
    value = serde_json::from_str(&snapshot).unwrap();
    value["interpreterAbi"] = json!("unknown");
    assert_eq!(
        refused(Definition::from_snapshot(&value.to_string())).code,
        "definition.abi"
    );
    value = serde_json::from_str(&snapshot).unwrap();
    value["workflow"]["steps"]["due"]["next"] = json!("due");
    refused(Definition::from_snapshot(&value.to_string()));
    refused(Definition::from_snapshot(&snapshot.replacen(
        "{",
        "{\"source\":\"\",",
        1,
    )));
    definition.workflow.deadline = "1d".into();
    assert_eq!(
        definition.snapshot().unwrap_err().code,
        "definition.changed"
    );
    assert_eq!(
        definition.validate_input(&input()).unwrap_err().code,
        "definition.changed"
    );
}

fn canonical(value: &Value) -> String {
    String::from_utf8(registry_platform_canonical_json::canonicalize_json(value).unwrap()).unwrap()
}

#[test]
fn snapshots_refuse_missing_changed_extra_or_reordered_operation_contracts() {
    let original: Value = serde_json::from_str(&fixture().snapshot().unwrap()).unwrap();
    assert_eq!(original["operationIdentities"].as_array().unwrap().len(), 2);
    assert_eq!(
        Definition::from_snapshot(&canonical(&original))
            .unwrap()
            .snapshot()
            .unwrap(),
        canonical(&original)
    );
    for field in [
        "version",
        "product",
        "effect",
        "keyRequirement",
        "recovery",
        "readReceipt",
        "requiresPreparation",
    ] {
        let mut changed = original.clone();
        changed["operationIdentities"][0][field] = match field {
            "version" => json!(2),
            "product" => json!("messaging"),
            "effect" => json!("mutation"),
            "keyRequirement" => json!("required"),
            "recovery" => json!("same-command"),
            _ => json!(true),
        };
        assert!(
            Definition::from_snapshot(&canonical(&changed)).is_err(),
            "{field}"
        );
    }
    let mut changed = original.clone();
    changed
        .as_object_mut()
        .unwrap()
        .remove("operationIdentities");
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    let mut changed = original.clone();
    let extra = changed["operationIdentities"][0].clone();
    changed["operationIdentities"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    let mut changed = original.clone();
    changed["operationIdentities"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    for pinned in [true, false] {
        let mut changed = original.clone();
        changed["adapterAbi"] = json!("coordinator/product-operations/v2");
        if !pinned {
            changed
                .as_object_mut()
                .unwrap()
                .remove("operationIdentities");
        }
        assert!(Definition::from_snapshot(&canonical(&changed)).is_err());
    }
}

#[test]
fn remote_schemas_and_non_null_finish_without_mapping_refuse() {
    let mut workflow = authored_value(WORKFLOW);
    workflow["workflow"]["outcomes"]["message-accepted"]["properties"]["messageId"] =
        json!({"$ref":"https://example.invalid/schema"});
    assert_eq!(
        refused(load(&workflow.to_string(), SOURCE)).code,
        "coordinator.definition.schema"
    );
    let mut workflow = authored_value(WORKFLOW);
    workflow["types"]["workflow-input"]["properties"]["applicationId"]["format"] =
        json!("unsupported-format");
    assert_eq!(
        refused(load(&workflow.to_string(), SOURCE)).code,
        "coordinator.definition.schema"
    );
    let mut workflow = authored_value(WORKFLOW);
    workflow["workflow"]["outcomes"]["no-current-permission"] = json!({"type":"string"});
    assert_eq!(
        refused(load(&workflow.to_string(), SOURCE)).code,
        "coordinator.definition.outcome"
    );
}

#[test]
fn resource_limits_include_recursion_input_values_and_non_object_commands() {
    let (workflow, source) = (computed_workflow(), computed_source());
    let recursive =
        format!("{source}\nfn descend(n) {{ if n <= 0 {{ 0 }} else {{ descend(n - 1) }} }}")
            .replace("input.sendAfter", "descend(1000)");
    let definition = load(&workflow, &recursive).unwrap();
    assert_eq!(
        definition
            .evaluate("due", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "function.resource_limit"
    );
    let definition = fixture();
    let mut excessive = input();
    excessive["sendAfter"] = json!("x".repeat(16385));
    assert_eq!(
        definition.validate_input(&excessive).unwrap_err().code,
        "function.value_limit"
    );
    let definition = load(
        &workflow,
        &source.replace(
            "#{ collection: \"applications\", recordId: input.applicationId }",
            "42",
        ),
    )
    .unwrap();
    assert_eq!(
        definition
            .evaluate("read-application", &input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "function.output"
    );
}

#[test]
fn minimal_finished_workflow_needs_no_mapping_or_timer() {
    let workflow = json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"minimal","version":"1"},
        "workflow":{"input":true,"deadlineSeconds":3600,"start":"done","steps":{"done":{"type":"finish","outcome":"done"}},"outcomes":{"done":{"type":"null"}}}}).to_string();
    let definition = load(&workflow, "").unwrap();
    assert_eq!(
        definition
            .initial_due(&Value::Null, instant("2026-10-09T09:00:00Z"))
            .unwrap(),
        None
    );
    assert!(definition.validate_outcome("done", &Value::Null).is_ok());
    assert!(definition
        .evaluate("arbitrary", &Value::Null, &BTreeMap::new())
        .is_err());
    // Unreferenced files are outside this project's named Function asset closure.
    assert_eq!(
        definition.digest,
        load(&workflow, "fn unused(x) { x } fn unused(x,y) { y }")
            .unwrap()
            .digest
    );
}

#[test]
fn authored_workflow_refuses_environment_substitution() {
    let error = refused(load(
        &WORKFLOW.replace(
            "deadlineSeconds: 2592000",
            "deadlineSeconds: ${PRIVATE_DEADLINE}",
        ),
        SOURCE,
    ));
    assert_eq!(error.code, "config.substitution-not-allowed");
    assert_eq!(error.field.as_deref(), Some("/workflow/deadlineSeconds"));
    assert!(error.suggested_action.is_some());
}

#[test]
fn authoring_diagnostics_locate_graph_reference_and_functions_without_runtime_values() {
    let mut unavailable = authored_value(WORKFLOW);
    unavailable["workflow"]["steps"]["permission"]["choose"]["inputs"]["record"]["step"] =
        json!("notify");
    let error = refused(load(&unavailable.to_string(), SOURCE));
    assert_eq!(
        error.field.as_deref(),
        Some("/workflow/steps/permission/choose/inputs/record")
    );
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("before the branch"));
    let (workflow, source) = (computed_workflow(), computed_source());
    let error = refused(load(
        &workflow,
        &source.replace("fn send_after(input)", "fn send_after(input, extra)"),
    ));
    // The step that calls the function is where the mismatch is placed.
    assert_eq!(error.code, "coordinator.function.definition");
    assert_eq!(
        error.field.as_deref(),
        Some("/functions/send-after/entrypoint")
    );
    assert!(error.diagnostics[0]
        .source
        .as_ref()
        .unwrap()
        .file
        .ends_with("workflow.yaml"));
    assert!(
        error.message.contains("exactly one parameter")
            || error.message.contains("one named-input object")
    );
    let definition = load(
        &workflow,
        &source.replace("input.sendAfter", &format!("throw \"{CANARY}\"")),
    )
    .unwrap();
    let error = definition
        .evaluate("due", &input(), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("steps.due.waitUntil"));
    assert!(!error.to_string().contains(CANARY));
}

#[test]
fn deferred_appointment_graph_preserves_grant_and_maps_product_contracts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let input = json!({"applicationId":"00000000-0000-4000-8000-000000000001",
        "bookAfter":"2026-10-09T09:16:00Z","searchStart":"2026-10-10T10:00:00Z",
        "searchEnd":"2026-10-10T11:00:00Z","grant":{"id":"00000000-0000-4000-8000-000000000003","expiresAt":1791620000}});
    definition.validate_input(&input).unwrap();
    let mut outputs = BTreeMap::from([
        (
            "read-application".into(),
            record(json!({"appointmentAllowed":true,"email":"person@example.invalid"})),
        ),
        (
            "metadata".into(),
            json!({"schedulingId":"appointments","policyRevision":7,"policyDigest":"sha256:policy"}),
        ),
        (
            "availability".into(),
            json!({"items":[{"kind":"slot","start":"2026-10-10T10:00:00Z","end":"2026-10-10T10:30:00Z","free":1}],"nextCursor":null}),
        ),
    ]);
    assert_eq!(
        definition
            .evaluate("eligibility", &input, &outputs)
            .unwrap(),
        json!("book")
    );
    assert_eq!(
        definition.evaluate("capacity", &input, &outputs).unwrap(),
        json!("available")
    );
    let booking = definition.evaluate("book", &input, &outputs).unwrap();
    assert_eq!(booking["grant"], input["grant"]);
    assert_eq!(booking["appointment"]["admission"]["policyRevision"], 7);
    assert_eq!(
        booking["appointment"]["admission"]["start"],
        "2026-10-10T10:00:00Z"
    );
    let _: registry_scheduling_client::CreateAppointmentRequest =
        serde_json::from_value(booking["appointment"].clone()).unwrap();
    let scenarios = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let registry_coordinator::scenarios::Reply::Success { success: booked } =
        &scenarios.cases[0].replies["book"][0]
    else {
        panic!("the fixture books an appointment");
    };
    outputs.insert("book".into(), booked.clone());
    let notice = definition.evaluate("notify", &input, &outputs).unwrap();
    let _: registry_messaging_client::SubmitMessageRequest =
        serde_json::from_value(notice).unwrap();
    outputs.insert(
        "notify".into(),
        json!({"id":"00000000-0000-4000-8000-000000000002"}),
    );
    assert_eq!(
        definition.evaluate("accepted", &input, &outputs).unwrap(),
        json!({"appointmentId":"appointment-one","messageId":"00000000-0000-4000-8000-000000000002"})
    );
    outputs.insert("availability".into(), json!({"items":[],"nextCursor":null}));
    assert_eq!(
        definition.evaluate("capacity", &input, &outputs).unwrap(),
        json!("unavailable")
    );
}

#[test]
fn executable_scenarios_follow_real_graph_functions_and_frozen_commands() {
    for name in ["delayed-follow-up", "deferred-appointment"] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../products/coordinator/examples/{name}"));
        let definition = Definition::load(&root).unwrap();
        let scenarios =
            registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
        let reports = registry_coordinator::scenarios::check(&definition, &scenarios).unwrap();
        assert!(reports.iter().any(|report| report.elapsed_seconds == 960));
        assert!(reports.iter().any(|report| report.state == "uncertain"));
        assert!(reports
            .iter()
            .any(|report| report.call_attempts.values().any(|count| *count == 2)));
        let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
        let repeat = registry_coordinator::scenarios::check(&restored, &scenarios).unwrap();
        assert_eq!(
            serde_json::to_value(reports).unwrap(),
            serde_json::to_value(repeat).unwrap()
        );
    }
}

#[test]
fn scenario_waits_expire_at_the_workflow_deadline_without_executing_next_steps() {
    let definition = load(
        &WORKFLOW.replace("deadlineSeconds: 2592000", "deadlineSeconds: 3600"),
        SOURCE,
    )
    .unwrap();
    for (name, due, elapsed, expired) in [
        ("past-due", "2026-10-09T08:00:00Z", 0, false),
        ("before-deadline", "2026-10-09T09:30:00Z", 1800, false),
        ("at-deadline", "2026-10-09T10:00:00Z", 3600, true),
        ("after-deadline", "2026-10-09T12:00:00Z", 3600, true),
    ] {
        let mut value = input();
        value["sendAfter"] = json!(due);
        let mut scenario: registry_coordinator::scenarios::Scenario =
            serde_json::from_value(json!({
                "name": name, "admittedAt": "2026-10-09T09:00:00Z",
                "input": value,
                "replies": if expired { json!({}) } else { json!({
                    "read-application": [{"success": record(json!({"noticeAllowed": false}))}]
                }) },
                "expect": if expired { json!({
                    "path": ["due"], "state": "deadline-exceeded", "elapsedSeconds": elapsed
                }) } else { json!({
                    "path": ["due", "read-application", "permission", "skipped"],
                    "state": "completed", "outcome": "no-current-permission", "elapsedSeconds": elapsed
                }) }
            }))
            .unwrap();
        let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
        assert_eq!(report.elapsed_seconds, elapsed, "{name}");
        assert_eq!(report.frozen_commands, 0, "{name}");
        if expired {
            assert!(report.call_attempts.is_empty(), "{name}");
            assert!(report.outcome.is_none(), "{name}");
            assert!(report.output.is_none(), "{name}");
        } else {
            assert_eq!(report.call_attempts["read-application"], 1, "{name}");
        }
        if name == "after-deadline" {
            scenario.expect.elapsed_seconds = Some(10_800);
            assert_eq!(
                registry_coordinator::scenarios::run(&definition, &scenario)
                    .err()
                    .unwrap()
                    .code,
                "scenario.expectation"
            );
        }
    }
}

#[test]
fn scenario_past_due_wait_does_not_rewind_an_advanced_clock() {
    let mut workflow: Value = registry_coordinator::authoring::parse_project(
        std::path::Path::new("workflow.yaml"),
        WORKFLOW,
    )
    .unwrap()
    .1
    .to_json_value();
    workflow["workflow"]["deadlineSeconds"] = json!(3600);
    workflow["workflow"]["steps"]["due"]["next"] = json!("earlier");
    workflow["workflow"]["steps"]["earlier"] = json!({
        "type": "wait-until", "waitUntil": {"type": "literal", "value":"2026-10-09T09:10:00Z"},
        "next": "read-application"
    });
    let definition = load(
        &serde_norway::to_string(&workflow).unwrap(),
        &format!("{SOURCE}\nfn earlier_due(input) {{ \"2026-10-09T09:10:00Z\" }}"),
    )
    .unwrap();
    let mut value = input();
    value["sendAfter"] = json!("2026-10-09T09:30:00Z");
    let scenario = serde_json::from_value(json!({
        "name": "earlier-wait", "admittedAt": "2026-10-09T09:00:00Z", "input": value,
        "replies": {"read-application": [{"success": record(json!({"noticeAllowed": false}))}]},
        "expect": {
            "path": ["due", "earlier", "read-application", "permission", "skipped"],
            "state": "completed", "outcome": "no-current-permission", "elapsedSeconds": 1800
        }
    }))
    .unwrap();
    let report = registry_coordinator::scenarios::run(&definition, &scenario).unwrap();
    assert_eq!(report.elapsed_seconds, 1800);
    assert_eq!(report.call_attempts["read-application"], 1);
}

#[test]
fn scenario_recovery_is_explicit_and_freezes_each_mutation_once() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let recovered = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    let report = registry_coordinator::scenarios::run(&definition, recovered).unwrap();
    assert_eq!(report.call_attempts["book"], 2);
    assert_eq!(
        report.frozen_commands, 2,
        "booking and notice each freeze once, recovery reuses booking"
    );
    recovered.recovery.clear();
    assert_eq!(
        registry_coordinator::scenarios::run(&definition, recovered)
            .err()
            .unwrap()
            .code,
        "scenario.recovery"
    );
}

#[test]
fn receipt_expiry_forbids_later_scenario_replies_for_retry_and_reconciliation() {
    use registry_coordinator::scenarios::{Recovery, Reply};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let case = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let recovered = registry_coordinator::scenarios::run(&definition, case).unwrap();
        assert_eq!(recovered.state, "completed");
        assert_eq!(recovered.call_attempts["book"], 2);
        assert_eq!(recovered.frozen_commands, 2);
    }
    case.replies.get_mut("book").unwrap()[0] = Reply::ReceiptExpired {
        receipt_expired: true,
    };
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let refused = registry_coordinator::scenarios::run(&definition, case)
            .err()
            .expect("an expired receipt cannot be followed by synthetic success");
        assert_eq!(refused.code, "scenario.receipt-expired");
        assert_eq!(refused.field.as_deref(), Some("/replies/book/1"));
        assert!(refused.message.contains("step book"), "{}", refused.message);
        assert!(refused
            .suggested_action
            .as_deref()
            .unwrap()
            .contains("Remove the replies after receipt-expired"));
    }
    case.replies.get_mut("book").unwrap().pop();
    case.expect.path.truncate(
        case.expect
            .path
            .iter()
            .position(|step| step == "book")
            .unwrap()
            + 1,
    );
    case.expect.state = "uncertain".into();
    case.expect.outcome = None;
    case.expect.output = None;
    for recovery in [Recovery::RetrySame, Recovery::Reconcile] {
        case.recovery.insert("book".into(), recovery);
        let report = registry_coordinator::scenarios::run(&definition, case).unwrap();
        assert_eq!(report.call_attempts["book"], 1);
        assert_eq!(report.frozen_commands, 1);
        assert_eq!(report.state, "uncertain");
        assert!(report.outcome.is_none());
        assert!(report.output.is_none());
    }
    case.recovery.clear();
    let report = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(report.state, "uncertain");
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

#[test]
fn authored_snapshot_must_fit_the_existing_restore_boundary() {
    let root = tempfile::tempdir().unwrap();
    snapshot_boundary::project_at_snapshot_size(root.path(), snapshot_boundary::SNAPSHOT_BOUND + 1);
    let error = refused(Definition::load(root.path()));
    assert_eq!(error.code, "coordinator.definition.snapshot-limit");
    assert!(!error.to_string().contains(&"x".repeat(100)));
}

#[test]
fn canonical_snapshot_boundary_and_fitting_noncanonical_inputs_restore_unchanged() {
    let root = tempfile::tempdir().unwrap();
    for size in [
        snapshot_boundary::SNAPSHOT_BOUND,
        snapshot_boundary::SNAPSHOT_BOUND - 64,
    ] {
        snapshot_boundary::project_at_snapshot_size(root.path(), size);
        let definition = Definition::load(root.path()).unwrap();
        let snapshot = definition.snapshot().unwrap();
        assert_eq!(snapshot.len(), size);
        let restored = Definition::from_snapshot(&snapshot).unwrap();
        assert_eq!(restored.digest, definition.digest);
        assert_eq!(restored.snapshot().unwrap(), snapshot);
        if size < snapshot_boundary::SNAPSHOT_BOUND {
            let object: Value = serde_json::from_str(&snapshot).unwrap();
            let fields = object
                .as_object()
                .unwrap()
                .iter()
                .rev()
                .map(|(key, value)| format!("{}:{}", serde_json::to_string(key).unwrap(), value))
                .collect::<Vec<_>>()
                .join(",");
            let reordered = format!(" {{ {fields} }} ");
            assert!(reordered.len() <= snapshot_boundary::SNAPSHOT_BOUND);
            let restored = Definition::from_snapshot(&reordered).unwrap();
            assert_eq!(restored.digest, definition.digest);
            assert_eq!(restored.snapshot().unwrap(), snapshot);
        } else {
            assert_eq!(
                refused(Definition::from_snapshot(&format!("{snapshot} "))).code,
                "definition.snapshot_limit"
            );
        }
    }
}

#[test]
fn bounded_noncanonical_input_cannot_expand_into_an_unrestorable_snapshot() {
    let root = tempfile::tempdir().unwrap();
    snapshot_boundary::project_at_snapshot_size(root.path(), snapshot_boundary::SNAPSHOT_BOUND);
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    let mut value: Value = serde_json::from_str(&snapshot).unwrap();
    value["workflow"]["input"]["description"] = json!(format!(
        "{}x",
        value["workflow"]["input"]["description"].as_str().unwrap()
    ));
    let canonical = registry_platform_canonical_json::canonicalize_json(&value).unwrap();
    assert_eq!(canonical.len(), snapshot_boundary::SNAPSHOT_BOUND + 1);
    let compact = String::from_utf8(canonical)
        .unwrap()
        .replacen("0.000001", "1e-6", 1);
    assert!(compact.len() <= snapshot_boundary::SNAPSHOT_BOUND);
    assert_eq!(
        refused(Definition::from_snapshot(&compact)).code,
        "definition.snapshot_limit"
    );
}

#[test]
fn scenario_reconciliation_requires_an_uncertain_mutation() {
    use registry_coordinator::scenarios::{Recovery, Reply};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/deferred-appointment");
    let definition = Definition::load(&root).unwrap();
    let mut document = registry_coordinator::scenarios::load(&root.join("scenarios.yaml")).unwrap();
    let case = document
        .cases
        .iter_mut()
        .find(|case| case.name == "booking-response-loss-same-command")
        .unwrap();
    case.replies.get_mut("book").unwrap()[0] = Reply::Retryable {
        retryable: "rate-limited".into(),
    };
    case.recovery.insert("book".into(), Recovery::RetrySame);
    let retried = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(retried.state, "completed");
    assert_eq!(retried.call_attempts["book"], 2);
    assert_eq!(retried.frozen_commands, 2);

    case.recovery.insert("book".into(), Recovery::Reconcile);
    let refused = registry_coordinator::scenarios::run(&definition, case)
        .err()
        .expect("a definite retryable rejection has no success receipt to observe");
    assert_eq!(refused.code, "scenario.recovery");

    case.replies.get_mut("book").unwrap()[0] = Reply::Uncertain {
        uncertain: "transport-uncertain".into(),
    };
    case.replies.get_mut("book").unwrap().insert(
        1,
        Reply::Retryable {
            retryable: "observation-unavailable".into(),
        },
    );
    let reconciled = registry_coordinator::scenarios::run(&definition, case).unwrap();
    assert_eq!(reconciled.state, "completed");
    assert_eq!(reconciled.call_attempts["book"], 3);
    assert_eq!(reconciled.frozen_commands, 2);
}
