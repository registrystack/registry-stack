// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    parse_module_json, parse_project_json, parse_project_yaml, ModuleAssetSource, Operation,
    RegistryProject,
};
use registry_breg::model::{CompiledTimerInput, CompiledTimerValue};
use serde_json::{json, Value};

fn timer_project_value() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/minimal/registry.yaml");
    let bytes = fs::read(path).expect("the maintained minimal project is readable");
    let project = parse_project_yaml(&bytes).expect("the maintained minimal project parses");
    let mut source = serde_json::to_value(project).expect("the project serializes");
    remove_nulls(&mut source);

    let record = &mut source["recordTypes"][0];
    record["fields"]
        .as_array_mut()
        .expect("fields are a list")
        .extend([
            json!({"id":"active","type":"boolean","classification":"internal"}),
            json!({"id":"activates-at","type":"timestamp","classification":"internal"}),
            json!({"id":"activation-window-end","type":"timestamp","classification":"internal"}),
            json!({"id":"activation-revision","type":"uuid","classification":"internal"}),
        ]);
    record["timers"] = json!([{
        "id":"activate",
        "at":"activates-at",
        "notAfter":"activation-window-end",
        "rearmOn":"activation-revision",
        "when":{"type":"fields","equals":{"active":false}},
        "invoke":"activate-contact",
        "input":{
            "contact":{"fromRecordId":true},
            "planned-at":{"fromField":"activates-at"},
            "operation-id":{"fromTimer":"occurrence-id"}
        }
    }]);

    source["timerGrants"] = json!([{"recordType":"contact","timer":"activate"}]);
    source["actions"]
        .as_array_mut()
        .expect("actions are a list")
        .push(json!({
            "id":"activate-contact",
            "execution":{"mode":"immediate"},
            "inputs":[
                {"id":"contact","type":"reference","target":"contact","required":true,"classification":"internal"},
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ],
            "plan":{"type":"fixed","effects":[{
                "id":"activated",
                "target":{"fromInput":"contact"},
                "operation":"patch",
                "set":{"active":{"value":true}}
            }]}
        }));

    let record_permission = &mut source["accessProfiles"][0]["permissions"]["records"][0];
    record_permission["writableFields"] = json!([
        "name",
        "email",
        "jurisdiction",
        "active",
        "activates-at",
        "activation-window-end",
        "activation-revision"
    ]);
    source
}

fn remove_nulls(value: &mut Value) {
    match value {
        Value::Object(members) => {
            members.retain(|_, value| !value.is_null());
            members.values_mut().for_each(remove_nulls);
        }
        Value::Array(items) => items.iter_mut().for_each(remove_nulls),
        _ => {}
    }
}

fn compile_value(source: Value) -> Result<registry_breg::CompiledRegistry, Vec<String>> {
    compile_value_with_assets(source, &[])
}

fn compile_value_with_assets(
    source: Value,
    assets: &[ModuleAssetSource],
) -> Result<registry_breg::CompiledRegistry, Vec<String>> {
    let bytes = serde_json::to_vec(&source).expect("source serializes");
    let project = parse_project_json(&bytes).expect("source shape parses");
    compile_project_with_assets(&project, &[], assets, CompileProfile::Authoring).map_err(
        |failure| {
            failure
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect()
        },
    )
}

fn assert_refused(source: Value, code: &str) {
    let diagnostics = compile_value(source).expect_err("timer project must be refused");
    assert!(
        diagnostics.iter().any(|candidate| candidate == code),
        "expected {code}, got {diagnostics:?}"
    );
}

fn assert_compiler_refused(source: Value, code: &str) {
    let project: RegistryProject =
        serde_json::from_value(source).expect("the typed compiler input deserializes");
    let diagnostics = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("timer project must be refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect::<Vec<_>>();
    assert!(
        diagnostics.iter().any(|candidate| candidate == code),
        "expected {code}, got {diagnostics:?}"
    );
}

fn assert_refused_with_assets(source: Value, assets: &[ModuleAssetSource], code: &str) {
    let diagnostics =
        compile_value_with_assets(source, assets).expect_err("timer project must be refused");
    assert!(
        diagnostics.iter().any(|candidate| candidate == code),
        "expected {code}, got {diagnostics:?}"
    );
}

fn replace_once(source: &str, needle: &str, replacement: &str) -> String {
    assert_eq!(
        source.matches(needle).count(),
        1,
        "the fixture must contain exactly one {needle}"
    );
    source.replacen(needle, replacement, 1)
}

fn timer_revision(registry: &registry_breg::CompiledRegistry) -> &str {
    &registry.entities()["contact"].timers["activate"].definition_revision
}

fn evidence_contract() -> Value {
    serde_json::from_str(
        r#"{"apiVersion":"id.registrystack.org/formats/evidence/client-contracts/v1","kind":"EvidenceClientContracts","assuranceProfile":"local","audience":"urn:example:client:audience:relying-party","issuedBy":"urn:example:client:issuer","providedBy":"urn:example:client:provider","definitions":[{"handle":"status-holds","requirement":"urn:example:client:requirement:status:v1","configurationRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000","kind":"criterion","evidenceType":"urn:example:client:evidence-type:status:v1","purpose":"example-decision","responseFormats":["signed-jws","sd-jwt-vc"],"referenceFrameworks":["urn:example:client:framework:status:v1"],"subjects":[{"role":"subject","cardinality":"one","selector":{"profile":"record-lookup-v1","valueOrigin":"request","fields":[{"type":"string","name":"record_reference","minimumBytes":1,"maximumBytes":200}]}}],"concepts":[{"handle":"status-holds","concept":"urn:example:client:concept:status-holds","required":true,"form":{"type":"boolean"}}]}]}"#,
    )
    .expect("Evidence contract fixture is JSON")
}

fn evidence_assets() -> Vec<ModuleAssetSource> {
    vec![ModuleAssetSource {
        module: None,
        path: "evidence/contracts.json".into(),
        bytes: serde_json::to_vec(&evidence_contract()).unwrap(),
    }]
}

#[test]
fn timer_compiles_complete_typed_mapping_and_exact_system_grant() {
    let registry = compile_value(timer_project_value()).expect("timer project compiles");
    let entity = registry
        .entities()
        .get("contact")
        .expect("contact compiles");
    let timer = entity.timers.get("activate").expect("timer compiles");

    assert_eq!(timer.at, "activates-at");
    assert_eq!(timer.not_after.as_deref(), Some("activation-window-end"));
    assert_eq!(timer.rearm_on.as_deref(), Some("activation-revision"));
    assert_eq!(timer.invoke, "activate-contact");
    assert_eq!(timer.action_revision, timer.system_grant.action_revision);
    assert!(timer.definition_revision.starts_with("sha256:"));
    assert_eq!(
        timer.control_fields,
        [
            "activates-at".to_owned(),
            "activation-window-end".to_owned(),
            "activation-revision".to_owned(),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        timer.predicate_fields,
        ["active".to_owned()].into_iter().collect()
    );
    assert_eq!(
        timer.effect_input_fields,
        ["activates-at".to_owned()].into_iter().collect()
    );
    let predicate = timer.when.as_ref().expect("timer predicate compiles");
    assert!(predicate.matches(
        &serde_json::from_value(json!({"active":false})).expect("record shape is an object")
    ));
    assert!(!predicate.matches(
        &serde_json::from_value(json!({"active":true})).expect("record shape is an object")
    ));
    assert!(
        !predicate.matches(&serde_json::from_value(json!({})).expect("record shape is an object"))
    );
    assert!(matches!(
        timer.input.get("contact"),
        Some(CompiledTimerInput::RecordId)
    ));
    assert!(matches!(
        timer.input.get("planned-at"),
        Some(CompiledTimerInput::Field { field }) if field == "activates-at"
    ));
    assert!(matches!(
        timer.input.get("operation-id"),
        Some(CompiledTimerInput::Timer {
            value: CompiledTimerValue::OccurrenceId
        })
    ));
    assert!(timer
        .system_grant
        .targets
        .iter()
        .any(|target| target.entity_id == "contact"
            && target.operation == registry_breg::contract::Operation::Patch
            && target.fields.contains("active")));
    assert_eq!(
        timer
            .system_grant
            .targets
            .iter()
            .find(|target| {
                target.entity_id == "contact"
                    && target.operation == registry_breg::contract::Operation::Get
            })
            .expect("timer authority includes exact locked anchor reads")
            .read_fields,
        timer
            .control_fields
            .iter()
            .chain(&timer.predicate_fields)
            .chain(&timer.effect_input_fields)
            .cloned()
            .collect()
    );
    assert_eq!(registry.timers().count(), 1);

    let timer_action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "activate-contact")
        .expect("timer Action remains governed and inspectable");
    assert!(timer_action.permissions.is_empty());
    assert!(!registry
        .actions()
        .routes
        .iter()
        .any(|route| route.action_id == "activate-contact"));
    assert!(!registry
        .actions()
        .access
        .iter()
        .any(|access| access.action_id == "activate-contact"));
    let contracts: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/action-contracts.json")
            .expect("portable Action contracts are generated")
            .bytes,
    )
    .expect("portable Action contracts parse");
    assert!(!contracts["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "activate-contact"));
    assert!(contracts["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "update-contact-email"));
    assert!(contracts["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "register-contact"));
    let metadata: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/metadata/registry.json")
            .expect("public Registry metadata is generated")
            .bytes,
    )
    .expect("public Registry metadata parses");
    assert!(!metadata["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "activate-contact"));
    assert!(metadata["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "update-contact-email"));
    assert!(metadata["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "register-contact"));
    for path in ["generated/sdk/project.ts", "generated/sdk/project.py"] {
        let sdk = std::str::from_utf8(
            &registry
                .artifacts()
                .get(path)
                .expect("project SDK is generated")
                .bytes,
        )
        .expect("project SDK is UTF-8");
        assert!(!sdk.contains("activate-contact"));
        assert!(sdk.contains("update-contact-email"));
        assert!(sdk.contains("register-contact"));
    }
    for suffix in ["input", "response"] {
        assert!(registry
            .artifacts()
            .get(&format!(
                "generated/action-schemas/activate-contact.invoke.{suffix}.schema.json"
            ))
            .is_none());
        assert!(registry
            .artifacts()
            .get(&format!(
                "generated/action-schemas/update-contact-email.invoke.{suffix}.schema.json"
            ))
            .is_some());
    }
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .expect("OpenAPI parses");
    let component_schemas = openapi["components"]["schemas"]
        .as_object()
        .expect("OpenAPI component schemas are an object");
    for suffix in ["invoke-input", "invoke-response"] {
        assert!(!component_schemas.contains_key(&format!("action-activate-contact-{suffix}")));
        assert!(component_schemas.contains_key(&format!("action-update-contact-email-{suffix}")));
    }
    let governed_actions: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("compiled/actions.json")
            .expect("governed Actions are compiled")
            .bytes,
    )
    .expect("governed Action inventory parses");
    assert!(governed_actions["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "activate-contact"));
}

#[test]
fn encrypted_predicate_and_mapped_fields_are_in_the_exact_anchor_read_ceiling() {
    let mut source = timer_project_value();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"secret", "type":"string", "maximumLength":160,
            "classification":"restricted", "encrypted":true
        }));
    source["recordTypes"][0]["timers"][0]["when"]["equals"]["secret"] = json!("ready");
    source["recordTypes"][0]["timers"][0]["input"]["secret"] = json!({"fromField":"secret"});
    let action = source["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "activate-contact")
        .unwrap();
    action["inputs"].as_array_mut().unwrap().push(json!({
        "id":"secret", "type":"string", "maximumLength":160,
        "required":true, "classification":"restricted"
    }));

    let registry = compile_value(source).expect("encrypted timer facts compile");
    let timer = &registry.entities()["contact"].timers["activate"];
    assert!(timer.predicate_fields.contains("secret"));
    assert!(timer.effect_input_fields.contains("secret"));
    let anchor_read = timer
        .system_grant
        .targets
        .iter()
        .find(|target| target.entity_id == "contact" && target.operation == Operation::Get)
        .expect("the timer grant includes the exact locked anchor read");
    assert!(anchor_read.read_fields.contains("secret"));
}

#[test]
fn timestamp_predicate_matches_the_stored_instant_across_offsets() {
    let mut source = timer_project_value();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("fields are a list")
        .push(json!({
            "id":"gate-at", "type":"timestamp", "classification":"internal"
        }));
    source["recordTypes"][0]["timers"][0]["when"]["equals"] =
        json!({"gate-at":"2026-10-28T08:15:30+07:00"});

    let registry = compile_value(source.clone()).expect("a timestamp predicate compiles");
    let timer = &registry.entities()["contact"].timers["activate"];
    let predicate = timer
        .when
        .as_ref()
        .expect("the timestamp predicate compiles");
    assert_eq!(
        predicate.timestamp_fields,
        ["gate-at".to_owned()].into_iter().collect()
    );
    assert_eq!(
        serde_json::to_value(predicate).expect("compiled predicate serializes")["timestampFields"],
        json!(["gate-at"])
    );
    assert!(predicate.matches(
        &serde_json::from_value(json!({"gate-at":"2026-10-28T01:15:30+00:00"}))
            .expect("the stored record is an object")
    ));
    assert!(!predicate.matches(
        &serde_json::from_value(json!({"gate-at":"2026-10-28T01:15:31+00:00"}))
            .expect("the stored record is an object")
    ));

    let stable = compile_value(source.clone()).expect("stable source recompiles");
    assert_eq!(
        timer.definition_revision,
        stable.entities()["contact"].timers["activate"].definition_revision
    );
    source["recordTypes"][0]["timers"][0]["when"]["equals"]["gate-at"] =
        json!("2026-10-28T08:15:31+07:00");
    let changed = compile_value(source).expect("a changed timestamp predicate compiles");
    assert_ne!(
        timer.definition_revision,
        changed.entities()["contact"].timers["activate"].definition_revision
    );
}

#[test]
fn timer_authoring_is_closed_and_root_grants_are_root_only() {
    let mut unknown = timer_project_value();
    unknown["recordTypes"][0]["timers"][0]["cron"] = json!("daily");
    let bytes = serde_json::to_vec(&unknown).unwrap();
    assert!(parse_project_json(&bytes).is_err());

    let module = json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"timer-module",
        "version":"1",
        "timerGrants":[{"recordType":"contact","timer":"activate"}]
    });
    assert!(parse_module_json(&serde_json::to_vec(&module).unwrap()).is_err());
}

#[test]
fn timer_reader_refuses_duplicate_members_keys_and_ids() {
    let serialized =
        serde_json::to_string(&timer_project_value()).expect("timer project serializes");
    let mut duplicate_timer_id = timer_project_value();
    let timer = duplicate_timer_id["recordTypes"][0]["timers"][0].clone();
    duplicate_timer_id["recordTypes"][0]["timers"]
        .as_array_mut()
        .expect("timers are a list")
        .push(timer);

    for (name, source, yaml_code) in [
        (
            "timer member",
            replace_once(
                &serialized,
                r#""at":"activates-at""#,
                r#""at":"activates-at","at":"activation-window-end""#,
            ),
            "yaml.duplicate-key",
        ),
        (
            "input key",
            replace_once(
                &serialized,
                r#""contact":{"fromRecordId":true}"#,
                r#""contact":{"fromRecordId":true},"contact":{"fromRecordId":true}"#,
            ),
            "yaml.duplicate-key",
        ),
        (
            "predicate key",
            replace_once(
                &serialized,
                r#""active":false"#,
                r#""active":false,"active":true"#,
            ),
            "yaml.duplicate-key",
        ),
        (
            "timer id",
            serde_json::to_string(&duplicate_timer_id).expect("duplicate timer source serializes"),
            "config.duplicate-id",
        ),
    ] {
        let json_failure = match parse_project_json(source.as_bytes()) {
            Ok(_) => panic!("{name} must be refused by the JSON project parser"),
            Err(failure) => failure,
        };
        let expected_json_code = if name == "timer id" {
            yaml_code
        } else {
            "breg.source.json-invalid"
        };
        assert!(
            json_failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == expected_json_code),
            "expected {expected_json_code} for {name}, got {json_failure:?}"
        );

        let yaml_failure = match parse_project_yaml(source.as_bytes()) {
            Ok(_) => panic!("{name} must be refused by the YAML project parser"),
            Err(failure) => failure,
        };
        assert!(
            yaml_failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == yaml_code),
            "expected {yaml_code} for {name}, got {yaml_failure:?}"
        );
    }
}

#[test]
fn module_timer_definition_requires_and_uses_root_enablement() {
    let mut source = timer_project_value();
    let timer = source["recordTypes"][0]
        .as_object_mut()
        .expect("Record type is an object")
        .remove("timers")
        .expect("root timer exists");
    source["modules"] = json!([{"id":"timer-module","version":"1"}]);
    let module = parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
            "kind":"BRegModule",
            "id":"timer-module",
            "version":"1",
            "extendRecordTypes":[{"recordType":"contact","timers":timer}]
        }))
        .expect("module source serializes"),
    )
    .expect("module timer parses");
    let expected_digest = registry_breg::compiler::module_digest(&module);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = compile_project(
        &project,
        std::slice::from_ref(&module),
        CompileProfile::Authoring,
    )
    .expect("root enables the contributed timer");
    assert_eq!(
        registry
            .entities()
            .get("contact")
            .unwrap()
            .timers
            .get("activate")
            .unwrap()
            .source_module
            .as_deref(),
        Some("timer-module")
    );
    assert_eq!(
        registry
            .module_closure()
            .iter()
            .find(|entry| entry.id == "timer-module")
            .and_then(|entry| entry.digest.as_deref()),
        Some(expected_digest.as_str())
    );
    assert_ne!(
        registry.revision(),
        compile_value(timer_project_value())
            .expect("equivalent root timer compiles")
            .revision(),
        "module identity and origin remain covered by the package revision"
    );

    let mut missing_grant_source = source.clone();
    missing_grant_source["timerGrants"] = json!([]);
    let missing_grant_project =
        parse_project_json(&serde_json::to_vec(&missing_grant_source).unwrap()).unwrap();
    let failure = compile_project(
        &missing_grant_project,
        std::slice::from_ref(&module),
        CompileProfile::Authoring,
    )
    .expect_err("a contributed definition is inert without root enablement");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.timer.grant-missing"));

    let mut duplicate_source = timer_project_value();
    duplicate_source["modules"] = json!([{"id":"timer-module","version":"1"}]);
    let duplicate_project =
        parse_project_json(&serde_json::to_vec(&duplicate_source).unwrap()).unwrap();
    let failure = compile_project(
        &duplicate_project,
        &[parse_module_json(
            &serde_json::to_vec(&json!({
                "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
                "kind":"BRegModule",
                "id":"timer-module",
                "version":"1",
                "extendRecordTypes":[{"recordType":"contact","timers":timer_project_value()["recordTypes"][0]["timers"].clone()}]
            }))
            .unwrap(),
        )
        .unwrap()],
        CompileProfile::Authoring,
    )
    .expect_err("duplicate contributed timer is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.extension.timer-duplicate"));

    let mut duplicate_grant = timer_project_value();
    duplicate_grant["timerGrants"]
        .as_array_mut()
        .unwrap()
        .push(json!({"recordType":"contact","timer":"activate"}));
    assert_refused(duplicate_grant, "breg.timer.grant-duplicate");

    let second_module = parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
            "kind":"BRegModule","id":"timer-module-2","version":"1",
            "extendRecordTypes":[{"recordType":"contact","timers":timer_project_value()["recordTypes"][0]["timers"].clone()}]
        }))
        .unwrap(),
    )
    .unwrap();
    let mut two_module_source = source;
    two_module_source["modules"] = json!([
        {"id":"timer-module","version":"1"},
        {"id":"timer-module-2","version":"1"}
    ]);
    let two_module_project =
        parse_project_json(&serde_json::to_vec(&two_module_source).unwrap()).unwrap();
    let failure = compile_project(
        &two_module_project,
        &[module, second_module],
        CompileProfile::Authoring,
    )
    .expect_err("two modules cannot contribute the same local timer id");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.extension.timer-duplicate"));
}

#[test]
fn timer_requires_exact_root_grant_and_complete_mapping() {
    let mut missing_grant = timer_project_value();
    missing_grant["timerGrants"] = json!([]);
    assert_refused(missing_grant, "breg.timer.grant-missing");

    let mut dangling_grant = timer_project_value();
    dangling_grant["timerGrants"][0]["timer"] = json!("missing");
    assert_refused(dangling_grant, "breg.timer.grant-unknown");

    let mut unknown_action = timer_project_value();
    unknown_action["recordTypes"][0]["timers"][0]["invoke"] = json!("missing");
    unknown_action["actions"].as_array_mut().unwrap().pop();
    assert_refused(unknown_action, "breg.timer.action-unknown");

    let mut incomplete = timer_project_value();
    incomplete["recordTypes"][0]["timers"][0]["input"]
        .as_object_mut()
        .unwrap()
        .remove("planned-at");
    assert_refused(incomplete, "breg.timer.input-incomplete");

    let mut wrong_type = timer_project_value();
    wrong_type["recordTypes"][0]["timers"][0]["input"]["operation-id"] =
        json!({"fromField":"activates-at"});
    assert_refused(wrong_type, "breg.timer.input-type-mismatch");

    let mut multiple_sources = timer_project_value();
    multiple_sources["recordTypes"][0]["timers"][0]["input"]["planned-at"]["value"] =
        json!("2026-10-28T00:00:00Z");
    assert_refused(multiple_sources, "breg.timer.input-source-invalid");

    let mut wrong_predicate_type = timer_project_value();
    wrong_predicate_type["recordTypes"][0]["timers"][0]["when"]["equals"]["active"] =
        json!("false");
    assert_refused(wrong_predicate_type, "breg.timer.predicate-invalid");
}

#[test]
fn timer_action_refuses_revision_unchanged_guard_without_a_caller_condition() {
    let mut source = timer_project_value();
    source["actions"][2]["commitGuards"] = json!({"targets":[{
        "input":"contact","revision":"unchanged"
    }]});

    assert_refused(source, "breg.timer.action-revision-guard-forbidden");
}

#[test]
fn timer_control_predicate_and_mapping_types_are_closed() {
    let mut unknown_at = timer_project_value();
    unknown_at["recordTypes"][0]["timers"][0]["at"] = json!("missing");
    assert_refused(unknown_at, "breg.timer.control-field-unknown");

    let mut wrong_at = timer_project_value();
    wrong_at["recordTypes"][0]["timers"][0]["at"] = json!("active");
    assert_refused(wrong_at, "breg.timer.control-field-type");

    let mut same_window = timer_project_value();
    same_window["recordTypes"][0]["timers"][0]["notAfter"] = json!("activates-at");
    assert_refused(same_window, "breg.timer.control-field-type");

    let mut wrong_rearm = timer_project_value();
    wrong_rearm["recordTypes"][0]["timers"][0]["rearmOn"] = json!("activates-at");
    assert_refused(wrong_rearm, "breg.timer.control-field-type");

    let mut integer_rearm = timer_project_value();
    integer_rearm["recordTypes"][0]["fields"][6]["type"] = json!("int64");
    compile_value(integer_rearm).expect("an integer revision may rearm the same date");

    let mut wrong_anchor = timer_project_value();
    wrong_anchor["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other","route":"others","primaryDataset":"directory",
            "mutationMode":"mutable","fields":[{"id":"name","type":"string","maximumLength":32,"classification":"internal"}]
        }));
    wrong_anchor["actions"][2]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other","type":"reference","target":"other","required":true,"classification":"internal"
        }));
    wrong_anchor["recordTypes"][0]["timers"][0]["input"]["other"] = json!({"fromRecordId":true});
    assert_refused(wrong_anchor, "breg.timer.input-type-mismatch");

    let mut unknown_field = timer_project_value();
    unknown_field["recordTypes"][0]["timers"][0]["input"]["planned-at"] =
        json!({"fromField":"missing"});
    assert_refused(unknown_field, "breg.timer.input-field-unknown");

    let mut due_at = timer_project_value();
    due_at["actions"][2]["inputs"][2]["type"] = json!("timestamp");
    due_at["recordTypes"][0]["timers"][0]["input"]["operation-id"] = json!({"fromTimer":"due-at"});
    compile_value(due_at).expect("the stored due instant maps to a timestamp input");

    let mut wrong_due_at = timer_project_value();
    wrong_due_at["recordTypes"][0]["timers"][0]["input"]["operation-id"] =
        json!({"fromTimer":"due-at"});
    assert_refused(wrong_due_at, "breg.timer.input-type-mismatch");

    let mut literal = timer_project_value();
    literal["recordTypes"][0]["timers"][0]["input"]["operation-id"] =
        json!({"value":"00000000-0000-4000-8000-000000000001"});
    compile_value(literal).expect("a typed literal maps to an Action input");

    let mut wrong_literal = timer_project_value();
    wrong_literal["recordTypes"][0]["timers"][0]["input"]["operation-id"] =
        json!({"value":"not-a-uuid"});
    assert_refused(wrong_literal, "breg.timer.input-type-mismatch");

    let mut non_canonical_integer_literal = timer_project_value();
    non_canonical_integer_literal["actions"][2]["inputs"][2]["type"] = json!("int64");
    non_canonical_integer_literal["recordTypes"][0]["timers"][0]["input"]["operation-id"] =
        json!({"value":i64::MAX});
    assert_compiler_refused(
        non_canonical_integer_literal,
        "breg.timer.input-type-mismatch",
    );

    let mut non_canonical_integer_predicate = timer_project_value();
    non_canonical_integer_predicate["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"unsafe-count","type":"int64","classification":"internal"
        }));
    non_canonical_integer_predicate["recordTypes"][0]["timers"][0]["when"]["equals"] =
        json!({"unsafe-count":i64::MAX});
    assert_compiler_refused(
        non_canonical_integer_predicate,
        "breg.timer.predicate-invalid",
    );

    let mut null_literal = timer_project_value();
    null_literal["recordTypes"][0]["timers"][0]["input"]["operation-id"] = json!({"value":null});
    let null_failure = parse_project_json(&serde_json::to_vec(&null_literal).unwrap())
        .expect_err("null is not an authored timer literal");
    assert!(null_failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.null-value"));

    let mut empty_predicate = timer_project_value();
    empty_predicate["recordTypes"][0]["timers"][0]["when"]["equals"] = json!({});
    assert_refused(empty_predicate, "breg.timer.predicate-bounds");

    let mut wide_predicate = timer_project_value();
    wide_predicate["recordTypes"][0]["timers"][0]["when"]["equals"] = json!({});
    for index in 0..17 {
        let field = format!("predicate-{index}");
        wide_predicate["recordTypes"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":field,"type":"boolean","classification":"internal"}));
        wide_predicate["recordTypes"][0]["timers"][0]["when"]["equals"]
            .as_object_mut()
            .unwrap()
            .insert(field, json!(true));
    }
    assert_refused(wide_predicate, "breg.timer.predicate-bounds");
}

#[test]
fn timer_refuses_public_invoke_and_non_immediate_actions() {
    let mut public_invoke = timer_project_value();
    public_invoke["accessProfiles"][0]["permissions"]["actions"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "action":"activate-contact",
            "operations":["invoke"],
            "targets":[{"recordType":"contact","rowBoundaries":"unrestricted"}],
            "results":["activated"]
        }));
    assert_refused(public_invoke, "breg.timer.action-public-invoke");

    let mut proposal = timer_project_value();
    proposal["actions"][2]["execution"] = json!({
        "mode":"proposal",
        "proposal":{"review":{"type":"none"},"retention":{"mode":"retain"}}
    });
    assert_refused(proposal, "breg.timer.action-not-immediate");
}

#[test]
fn timer_refuses_remote_function_and_evidence_capabilities() {
    let mut remote = timer_project_value();
    remote["functions"].as_array_mut().unwrap().push(json!({
        "id":"timer-plan","runtime":"rhai","source":"plans/timer.rhai",
        "entrypoint":"plan","abi":"registry.action-plan/v1","capabilities":["evidence"]
    }));
    remote["actions"][2]["plan"] = json!({
        "type":"function","function":"timer-plan",
        "inputs":["contact","planned-at","operation-id"],
        "capabilities":["evidence"],"refusals":[],
        "writes":[{"id":"activated","target":{"fromInput":"contact"},"operation":"patch","fields":["active"]}]
    });
    let remote_assets = [ModuleAssetSource {
        module: None,
        path: "plans/timer.rhai".into(),
        bytes: br#"fn plan(ctx) { #{effects: [#{id: "activated", set: #{active: true}}]} }"#
            .to_vec(),
    }];
    assert_refused_with_assets(
        remote,
        &remote_assets,
        "breg.timer.action-capability-forbidden",
    );

    let mut evidence = timer_project_value();
    evidence["functions"] = json!([{
        "id":"timer-plan","runtime":"rhai","source":"plans/timer.rhai",
        "entrypoint":"plan","abi":"registry.action-plan/v1","capabilities":["evidence"]
    }]);
    evidence["actions"][2]["plan"] = json!({
        "type":"function","function":"timer-plan",
        "inputs":["contact","planned-at","operation-id"],
        "capabilities":["evidence"],"refusals":[],
        "writes":[{"id":"activated","target":{"fromInput":"contact"},"operation":"patch","fields":["active"]}]
    });
    evidence["evidenceProviders"] = json!([{
        "id":"provider","contracts":"evidence/contracts.json",
        "subjectResolution":"trusted-provider-exact-selector"
    }]);
    evidence["actions"][2]["evidence"] = json!([{
        "id":"status","provider":"provider",
        "requirement":"urn:example:client:requirement:status:v1",
        "subjects":{"subject":{"profile":"record-lookup-v1"}},
        "outputs":["status-holds"],"maximumObservationAgeSeconds":60
    }]);
    let mut evidence_handler_assets = evidence_assets();
    evidence_handler_assets.push(ModuleAssetSource {
        module: None,
        path: "plans/timer.rhai".into(),
        bytes: br#"fn plan(ctx) { #{effects: [#{id: "activated", set: #{active: true}}]} }"#
            .to_vec(),
    });
    assert_refused_with_assets(
        evidence,
        &evidence_handler_assets,
        "breg.timer.action-capability-forbidden",
    );

    let mut commit_evidence = timer_project_value();
    commit_evidence["evidenceProviders"] = json!([{
        "id":"provider","contracts":"evidence/contracts.json",
        "subjectResolution":"trusted-provider-exact-selector"
    }]);
    commit_evidence["actions"][2]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"evidence-key","type":"string","minimumLength":1,"maximumLength":200,
            "required":true,"classification":"internal"
        }));
    commit_evidence["recordTypes"][0]["timers"][0]["input"]["evidence-key"] =
        json!({"value":"contact"});
    commit_evidence["actions"][2]["commitGuards"] = json!({"evidence":[{
        "id":"commit-status","provider":"provider",
        "requirement":"urn:example:client:requirement:status:v1",
        "subjects":{"subject":{"profile":"record-lookup-v1","selectors":{
            "record_reference":{"type":"input","input":"evidence-key"}
        }}},
        "requires":[{"output":"status-holds","equals":true}],
        "maximumObservationAgeSeconds":60
    }]});
    assert_refused_with_assets(
        commit_evidence,
        &evidence_assets(),
        "breg.timer.action-capability-forbidden",
    );
}

#[test]
fn timer_refuses_consent_issuance_capability() {
    let authored = parse_project_yaml(include_bytes!("fixtures/consent-access.yaml"))
        .expect("maintained consent fixture parses");
    let mut consent = serde_json::to_value(authored).unwrap();
    remove_nulls(&mut consent);
    consent["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"activates-at","type":"timestamp","classification":"internal"
        }));
    consent["recordTypes"][0]["timers"] = json!([{
        "id":"record-consent","at":"activates-at","invoke":"timer-record-consent",
        "input":{
            "subject":{"fromRecordId":true},"recipient":{"value":"wfp"},
            "purpose":{"value":"food-assistance"},"scope":{"value":"food-targeting"},
            "decision":{"value":"given"},"effective-at":{"fromField":"activates-at"},
            "expires-at":{"value":"2027-10-28T00:00:00Z"}
        }
    }]);
    consent["accessProfiles"][2]["permissions"]["records"][0]["writableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("activates-at"));
    let mut consent_action = consent["actions"][0].clone();
    consent_action["id"] = json!("timer-record-consent");
    consent["actions"]
        .as_array_mut()
        .unwrap()
        .push(consent_action);
    consent["timerGrants"] = json!([{"recordType":"person","timer":"record-consent"}]);
    assert_refused(consent, "breg.timer.action-capability-forbidden");
}

#[test]
fn timer_revision_covers_controls_gate_mapping_action_and_system_grant() {
    let source = timer_project_value();
    let baseline = compile_value(source.clone()).expect("baseline compiles");
    let repeated = compile_value(source.clone()).expect("stable recompile succeeds");
    assert_eq!(timer_revision(&baseline), timer_revision(&repeated));
    assert_eq!(baseline.revision(), repeated.revision());

    let mut variants = Vec::new();

    let mut at = source.clone();
    at["recordTypes"][0]["timers"][0]["at"] = json!("activation-window-end");
    at["recordTypes"][0]["timers"][0]["notAfter"] = json!("activates-at");
    variants.push(at);

    let mut not_after = source.clone();
    not_after["recordTypes"][0]["timers"][0]
        .as_object_mut()
        .unwrap()
        .remove("notAfter");
    variants.push(not_after);

    let mut rearm = source.clone();
    rearm["recordTypes"][0]["timers"][0]
        .as_object_mut()
        .unwrap()
        .remove("rearmOn");
    variants.push(rearm);

    let mut predicate = source.clone();
    predicate["recordTypes"][0]["timers"][0]["when"]["equals"]["active"] = json!(true);
    variants.push(predicate);

    let mut mapping = source.clone();
    mapping["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"alternate-planned-at","type":"timestamp","classification":"internal"
        }));
    mapping["recordTypes"][0]["timers"][0]["input"]["planned-at"] =
        json!({"fromField":"alternate-planned-at"});
    let mapping_changed =
        compile_value(mapping).expect("mapped anchor read ceiling change compiles");
    assert_ne!(
        baseline.entities()["contact"].timers["activate"]
            .system_grant
            .revision,
        mapping_changed.entities()["contact"].timers["activate"]
            .system_grant
            .revision
    );
    assert_ne!(timer_revision(&baseline), timer_revision(&mapping_changed));
    assert_ne!(baseline.revision(), mapping_changed.revision());

    for variant in variants {
        let changed = compile_value(variant).expect("one timer contract member changes validly");
        assert_ne!(timer_revision(&baseline), timer_revision(&changed));
        assert_ne!(baseline.revision(), changed.revision());
    }

    let baseline_timer = &baseline.entities()["contact"].timers["activate"];
    let mut action_semantics = source.clone();
    action_semantics["actions"][2]["plan"]["effects"][0]["set"]["active"]["value"] = json!(false);
    let action_changed = compile_value(action_semantics).expect("Action semantic change compiles");
    let action_timer = &action_changed.entities()["contact"].timers["activate"];
    assert_ne!(baseline_timer.action_revision, action_timer.action_revision);
    assert_ne!(timer_revision(&baseline), timer_revision(&action_changed));

    let mut authority = source;
    authority["actions"][2]["plan"]["effects"][0]["set"]["jurisdiction"] = json!({"value":"timer"});
    let authority_changed = compile_value(authority).expect("authority expansion compiles");
    let authority_timer = &authority_changed.entities()["contact"].timers["activate"];
    assert_ne!(
        baseline_timer.system_grant.revision,
        authority_timer.system_grant.revision
    );
    assert_ne!(
        timer_revision(&baseline),
        timer_revision(&authority_changed)
    );
}

#[test]
fn timer_revision_covers_affected_event_delivery_definition() {
    let mut source = timer_project_value();
    source["recordTypes"][0]["hooks"] = json!([{
        "id":"contact-patched","phase":"after","trigger":"patched","projection":["active"],
        "handler":{"type":"url","destinationId":"timer-events"}
    }]);
    let baseline = compile_value(source.clone()).expect("timer event closure compiles");
    let baseline_timer = &baseline.entities()["contact"].timers["activate"];
    assert_eq!(baseline_timer.event_deliveries.len(), 1);

    source["recordTypes"][0]["hooks"][0]["projection"] = json!(["active", "name"]);
    let changed = compile_value(source).expect("changed event projection compiles");
    let changed_timer = &changed.entities()["contact"].timers["activate"];
    assert_eq!(
        baseline_timer.event_deliveries,
        changed_timer.event_deliveries
    );
    assert_ne!(
        baseline_timer.definition_revision,
        changed_timer.definition_revision
    );
    assert_ne!(baseline.revision(), changed.revision());
}

#[test]
fn timer_system_authority_is_anchor_and_create_bounded() {
    let mut create_only = timer_project_value();
    create_only["recordTypes"][0]["mutationMode"] = json!("create-only");
    create_only["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"activation-log","route":"activation-logs","primaryDataset":"directory",
            "mutationMode":"create-only","fields":[
                {"id":"contact","type":"reference","target":"contact","required":true,"classification":"internal"},
                {"id":"planned-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"operation-id","type":"uuid","required":true,"classification":"internal"}
            ]
        }));
    create_only["actions"][2]["plan"]["effects"] = json!([{
        "id":"activation-log","target":{"recordType":"activation-log"},"operation":"create",
        "set":{
            "contact":{"fromInput":"contact"},"planned-at":{"fromInput":"planned-at"},
            "operation-id":{"fromInput":"operation-id"}
        }
    }]);
    create_only["actions"]
        .as_array_mut()
        .unwrap()
        .retain(|action| action["id"] != "update-contact-email");
    create_only["accessProfiles"][0]["permissions"]["actions"]
        .as_array_mut()
        .unwrap()
        .retain(|permission| permission["action"] != "update-contact-email");
    create_only["accessProfiles"][0]["permissions"]["records"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .retain(|operation| operation != "patch");
    let registry = compile_value(create_only.clone())
        .expect("a new create-only anchor may arm one bounded create Action");
    let timer = &registry.entities()["contact"].timers["activate"];
    assert!(timer.system_grant.targets.iter().any(|target| {
        target.entity_id == "activation-log"
            && target.operation == registry_breg::contract::Operation::Create
            && target.fields
                == ["contact", "operation-id", "planned-at"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
    }));
    let anchor_read = timer
        .system_grant
        .targets
        .iter()
        .find(|target| {
            target.entity_id == "contact"
                && target.operation == registry_breg::contract::Operation::Get
        })
        .expect("create-only timer authority still reads its locked anchor");
    assert_eq!(
        anchor_read.read_fields,
        timer
            .control_fields
            .iter()
            .chain(&timer.predicate_fields)
            .chain(&timer.effect_input_fields)
            .cloned()
            .collect()
    );
    assert!(!timer.system_grant.targets.iter().any(|target| {
        target.entity_id == "contact"
            && target.operation == registry_breg::contract::Operation::Patch
    }));

    let create_effects = (0..15)
        .map(|index| {
            json!({
                "id":format!("activation-log-{index}"),
                "target":{"recordType":"activation-log"},
                "operation":"create",
                "set":{
                    "contact":{"fromInput":"contact"},
                    "planned-at":{"fromInput":"planned-at"},
                    "operation-id":{"fromInput":"operation-id"}
                }
            })
        })
        .collect::<Vec<_>>();
    let mut exact_anchor_at_ceiling = create_only;
    exact_anchor_at_ceiling["actions"][1]["plan"]["effects"] = json!(create_effects);
    compile_value(exact_anchor_at_ceiling.clone())
        .expect("an existing exact anchor target counts once at the target ceiling");

    exact_anchor_at_ceiling["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"related-contact","type":"reference","target":"contact",
            "classification":"internal"
        }));
    exact_anchor_at_ceiling["recordTypes"][0]["timers"][0]["input"]["contact"] =
        json!({"fromField":"related-contact"});
    assert_refused(exact_anchor_at_ceiling, "breg.timer.bounds-targets");

    let mut oversized_anchor_read = timer_project_value();
    oversized_anchor_read["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"large-policy-fact","type":"string","maximumLength":1_000_000,
            "classification":"internal"
        }));
    oversized_anchor_read["recordTypes"][0]["timers"][0]["when"]["equals"]["large-policy-fact"] =
        json!("ready");
    assert_refused(oversized_anchor_read, "breg.timer.bounds-snapshot-bytes");

    let mut proposal_required = timer_project_value();
    proposal_required["recordTypes"][0]["mutationPolicy"] = json!({"patch":"proposal-required"});
    assert_refused(proposal_required, "breg.action.effect-controlled-target");

    let mut other_existing = timer_project_value();
    other_existing["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other",
            "route":"others",
            "primaryDataset":"directory",
            "mutationMode":"mutable",
            "fields":[{"id":"active","type":"boolean","classification":"internal"}]
        }));
    other_existing["actions"][2]["inputs"].as_array_mut().unwrap().push(json!({
        "id":"other","type":"reference","target":"other","required":true,"classification":"internal"
    }));
    other_existing["actions"][2]["plan"]["effects"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other-activated",
            "target":{"fromInput":"other"},
            "operation":"patch",
            "set":{"active":{"value":true}}
        }));
    other_existing["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"other","type":"reference","target":"other","classification":"internal"
        }));
    other_existing["recordTypes"][0]["timers"][0]["input"]["other"] = json!({"fromField":"other"});
    assert_refused(
        other_existing,
        "breg.timer.action-existing-target-forbidden",
    );

    let mut tombstone_anchor = timer_project_value();
    tombstone_anchor["actions"][2]["plan"]["effects"] = json!([{
        "id":"remove-contact","target":{"fromInput":"contact"},"operation":"tombstone"
    }]);
    assert_refused(tombstone_anchor, "breg.action.effect-operation-unsupported");
}

#[test]
fn timer_control_fields_cannot_be_encrypted() {
    let mut source = timer_project_value();
    let at = source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|field| field["id"] == "activates-at")
        .expect("the fixture declares the at field");
    at["encrypted"] = json!(true);
    at["classification"] = json!("restricted");

    let failure = parse_project_json(&serde_json::to_vec(&source).unwrap())
        .expect_err("an encrypted timestamp control field is outside the field contract");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "config.invalid-value"));
}
