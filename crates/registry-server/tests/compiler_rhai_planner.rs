// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use registry_server::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{
        parse_project_yaml, FieldTypeSource, ModuleAssetSource, Operation,
        CHANGE_REQUEST_PLAN_ABI_V1,
    },
    model::{
        CompiledChangeRequest, CompiledChangeRequestApplication,
        CompiledChangeRequestApplicationMode, CompiledChangeRequestDisposition,
        CompiledChangeRequestPlanner, CompiledChangeRequestPlannerKind,
        CompiledChangeRequestPlannerLimits, CompiledChangeRequestPlannerWrite,
        CompiledChangeRequestRetentionMode, CompiledChangeRequestReviewMode,
    },
    rhai_planner::{
        plan_change_request_effects, CandidateChangeRequestMutation, CandidateChangeRequestValue,
        ChangeRequestPlannerError, ChangeRequestPlannerRuntime, MAXIMUM_ARRAY_ITEMS,
        MAXIMUM_CALL_DEPTH, MAXIMUM_EXPRESSION_DEPTH, MAXIMUM_MAP_ENTRIES, MAXIMUM_OPERATIONS,
        MAXIMUM_SOURCE_BYTES, MAXIMUM_STRING_BYTES, MAXIMUM_VALUE_DEPTH,
    },
};
use serde_json::{json, Map, Value};

fn plan(script: &str, mode: CompiledChangeRequestApplicationMode) -> CompiledChangeRequest {
    let allowed_dispositions = if mode == CompiledChangeRequestApplicationMode::Planner {
        [
            CompiledChangeRequestDisposition::Apply,
            CompiledChangeRequestDisposition::Queue,
        ]
        .into_iter()
        .collect()
    } else {
        BTreeSet::new()
    };
    let queue_reasons = if mode == CompiledChangeRequestApplicationMode::Planner {
        BTreeMap::from([("needs_review".to_owned(), "Needs review".to_owned())])
    } else {
        BTreeMap::new()
    };
    CompiledChangeRequest {
        request_entity_id: "request".to_owned(),
        contract_fingerprint: "sha256:test".to_owned(),
        retention_mode: CompiledChangeRequestRetentionMode::Retain,
        review_mode: CompiledChangeRequestReviewMode::None,
        application: CompiledChangeRequestApplication {
            mode,
            allowed_dispositions,
            queue_reasons,
        },
        planner: Some(CompiledChangeRequestPlanner {
            kind: CompiledChangeRequestPlannerKind::Rhai,
            source_module: None,
            script_path: "planners/change.rhai".to_owned(),
            abi: CHANGE_REQUEST_PLAN_ABI_V1.to_owned(),
            rhai_version: "1.25.1".to_owned(),
            script_sha256: "sha256:test".to_owned(),
            script_bytes: script.as_bytes().to_vec(),
            limits: CompiledChangeRequestPlannerLimits {
                maximum_source_bytes: 65_536,
                maximum_operations: MAXIMUM_OPERATIONS,
                maximum_call_depth: MAXIMUM_CALL_DEPTH as u16,
                maximum_expression_depth: MAXIMUM_EXPRESSION_DEPTH as u16,
                maximum_string_bytes: MAXIMUM_STRING_BYTES as u32,
                maximum_array_items: MAXIMUM_ARRAY_ITEMS as u16,
                maximum_map_entries: MAXIMUM_MAP_ENTRIES as u16,
                maximum_modules: 0,
            },
            request_fields: vec![
                "subject".to_owned(),
                "label".to_owned(),
                "optional".to_owned(),
            ],
            writes: vec![CompiledChangeRequestPlannerWrite {
                target_entity_id: "record".to_owned(),
                target_from_field: Some("subject".to_owned()),
                operation: Operation::Patch,
                fields: BTreeSet::from(["label".to_owned()]),
                field_types: BTreeMap::from([(
                    "label".to_owned(),
                    FieldTypeSource::String {
                        min_length: 1,
                        max_length: 80,
                    },
                )]),
                required_fields: BTreeSet::new(),
                reference_sources: BTreeMap::new(),
            }],
        }),
        effects: Vec::new(),
        stages: Vec::new(),
        actions: Vec::new(),
        review_grants: Vec::new(),
        apply_grants: Vec::new(),
        presence_grants: Vec::new(),
        target_entities: BTreeSet::from(["record".to_owned()]),
        maximum_targets: 16,
        maximum_field_mutations: 128,
        maximum_snapshot_bytes: 2_097_152,
    }
}

fn request() -> Map<String, Value> {
    Map::from_iter([
        (
            "subject".to_owned(),
            json!("550e8400-e29b-41d4-a716-446655440000"),
        ),
        ("label".to_owned(), json!("bounded")),
        ("optional".to_owned(), Value::Null),
        (
            "undeclared_canary".to_owned(),
            json!("must-not-reach-script"),
        ),
    ])
}

fn plan_with_field_type(script: &str, field_type: FieldTypeSource) -> CompiledChangeRequest {
    let mut plan = plan(script, CompiledChangeRequestApplicationMode::Automatic);
    plan.planner.as_mut().expect("test planner exists").writes[0]
        .field_types
        .insert("label".to_owned(), field_type);
    plan
}

fn structured_plan(script: &str) -> CompiledChangeRequest {
    plan_with_field_type(
        script,
        FieldTypeSource::Structured {
            max_bytes: 1_048_576,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"value": {}},
                "required": ["value"]
            }),
        },
    )
}

fn healthy_script(value: &str) -> String {
    format!(
        "fn plan(ctx) {{ #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `{value}`}}}}]}} }}"
    )
}

fn nested_array(depth: usize) -> Value {
    (0..depth).fold(Value::Null, |value, _| Value::Array(vec![value]))
}

fn literal(candidate: &registry_server::rhai_planner::CompiledEffectPlanCandidate) -> &Value {
    match &candidate.effects[0].mutations[0] {
        CandidateChangeRequestMutation::Set {
            value: CandidateChangeRequestValue::Literal(value),
            ..
        } => value,
        other => panic!("expected a literal mutation, got {other:?}"),
    }
}

#[test]
fn rhai_planner_authoring_is_strict_and_compiles_declared_policy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let project = parse_project_yaml(&project_bytes).expect("strict fixture parses");
    let script =
        std::fs::read(root.join("scripts/person-name-change.rhai")).expect("planner reads");
    let compiled = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: script.clone(),
        }],
        CompileProfile::Authoring,
    )
    .expect("declared planner compiles");
    let request = compiled
        .entities()
        .get("person-name-change-request")
        .and_then(|entity| entity.change_request.as_ref())
        .expect("request plan compiles");
    let planner = request
        .planner
        .as_ref()
        .expect("Rhai planner remains explicit");
    assert_eq!(planner.abi, CHANGE_REQUEST_PLAN_ABI_V1);
    assert_eq!(
        planner.rhai_version,
        registry_server::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
    );
    assert_eq!(
        planner.limits,
        CompiledChangeRequestPlannerLimits {
            maximum_source_bytes: MAXIMUM_SOURCE_BYTES as u32,
            maximum_operations: MAXIMUM_OPERATIONS,
            maximum_call_depth: MAXIMUM_CALL_DEPTH as u16,
            maximum_expression_depth: MAXIMUM_EXPRESSION_DEPTH as u16,
            maximum_string_bytes: MAXIMUM_STRING_BYTES as u32,
            maximum_array_items: MAXIMUM_ARRAY_ITEMS as u16,
            maximum_map_entries: MAXIMUM_MAP_ENTRIES as u16,
            maximum_modules: 0,
        }
    );
    assert_eq!(
        planner.request_fields,
        ["person", "given-name", "family-name", "handling"]
    );
    assert!(!planner.script_sha256.contains("display-name"));
    let original_fingerprint = request.contract_fingerprint.clone();

    let mut changed_script = script;
    changed_script.extend_from_slice(b"\n// governed script revision\n");
    let changed = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: changed_script,
        }],
        CompileProfile::Authoring,
    )
    .expect("revised planner compiles");
    let changed_fingerprint = &changed.entities()["person-name-change-request"]
        .change_request
        .as_ref()
        .expect("revised plan compiles")
        .contract_fingerprint;
    assert_ne!(&original_fingerprint, changed_fingerprint);

    let mut downgraded = project.clone();
    downgraded.entities[0]
        .fields
        .iter_mut()
        .find(|field| field.id == "display-name")
        .expect("target field exists")
        .classification = registry_server::contract::Classification::Public;
    let failure = compile_project_with_assets(
        &downgraded,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                .expect("planner rereads"),
        }],
        CompileProfile::Authoring,
    )
    .expect_err("classification downgrade is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.planner.classification_ceiling"));

    let undeclared_asset = compile_project_with_assets(
        &project,
        &[],
        &[
            ModuleAssetSource {
                module: None,
                path: "scripts/person-name-change.rhai".to_owned(),
                bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                    .expect("planner rereads"),
            },
            ModuleAssetSource {
                module: None,
                path: "scripts/ambient.rhai".to_owned(),
                bytes: b"fn plan(ctx) { #{} }".to_vec(),
            },
        ],
        CompileProfile::Authoring,
    )
    .expect_err("undeclared Rhai asset is refused");
    assert!(undeclared_asset
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "change_request.planner.asset_undeclared"));

    let mut value: serde_json::Value =
        serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    value["entities"][1]["changeRequest"]["planner"]["ambient"] = json!(true);
    let unknown = serde_json::to_vec(&value).expect("test project serializes");
    assert!(registry_server::contract::parse_project_json(&unknown).is_err());
}

#[test]
fn rhai_planner_authoring_refuses_closed_contract_violations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let base: Value = serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    let script =
        std::fs::read(root.join("scripts/person-name-change.rhai")).expect("planner reads");

    let compile_diagnostics = |value: &Value, assets: Vec<ModuleAssetSource>| {
        let project = registry_server::contract::parse_project_json(
            &serde_json::to_vec(value).expect("test project serializes"),
        )
        .expect("strict test project parses");
        compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
            .expect_err("invalid planner contract is refused")
            .diagnostics()
            .to_vec()
    };
    let compile_codes = |value: &Value, assets: Vec<ModuleAssetSource>| {
        compile_diagnostics(value, assets)
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect::<BTreeSet<_>>()
    };
    let owned_asset = || ModuleAssetSource {
        module: None,
        path: "scripts/person-name-change.rhai".to_owned(),
        bytes: script.clone(),
    };

    let mut both = base.clone();
    both["entities"][1]["changeRequest"]["effects"] = json!([{
        "target": {"fromField": "person"},
        "operation": "patch",
        "set": {"display-name": {"fromField": "given-name"}}
    }]);
    let both_diagnostics = compile_diagnostics(&both, vec![owned_asset()]);
    let exclusive = both_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "change_request.plan.exclusive")
        .expect("effects and planner are mutually exclusive");
    assert_eq!(
        exclusive.path,
        "entities[id=person-name-change-request].changeRequest"
    );

    let mut neither = base.clone();
    neither["entities"][1]["changeRequest"]
        .as_object_mut()
        .expect("change request is an object")
        .remove("planner");
    assert!(compile_codes(&neither, Vec::new()).contains("change_request.plan.exclusive"));

    let mut wrong_abi = base.clone();
    wrong_abi["entities"][1]["changeRequest"]["planner"]["abi"] = json!("unsupported/v9");
    let abi_diagnostics = compile_diagnostics(&wrong_abi, vec![owned_asset()]);
    let invalid_abi = abi_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "change_request.planner.abi_invalid")
        .expect("unsupported planner ABI is refused");
    assert_eq!(
        invalid_abi.path,
        "entities[id=person-name-change-request].changeRequest.planner.abi"
    );

    let mut unknown_request_field = base.clone();
    unknown_request_field["entities"][1]["changeRequest"]["planner"]["requestFields"]
        .as_array_mut()
        .expect("request fields are an array")
        .push(json!("ambient-field"));
    let request_field_diagnostics =
        compile_diagnostics(&unknown_request_field, vec![owned_asset()]);
    let unknown_request_field = request_field_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "change_request.planner.request_field_unknown")
        .expect("unknown planner input is refused");
    assert_eq!(
        unknown_request_field.path,
        "entities[id=person-name-change-request].changeRequest.planner.requestFields[field=ambient-field]"
    );

    let mut unknown_write_field = base.clone();
    unknown_write_field["entities"][1]["changeRequest"]["planner"]["writes"][0]["fields"]
        .as_array_mut()
        .expect("write fields are an array")
        .push(json!("ambient-field"));
    let write_diagnostics = compile_diagnostics(&unknown_write_field, vec![owned_asset()]);
    let unknown_field = write_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "change_request.planner.write_field_unknown")
        .expect("unknown planner write field is refused");
    assert_eq!(
        unknown_field.path,
        "entities[id=person-name-change-request].changeRequest.planner.writes[0].fields[field=ambient-field]"
    );

    let mut forbidden_application_policy = base.clone();
    forbidden_application_policy["entities"][1]["changeRequest"]["application"]["mode"] =
        json!("manual");
    let application_diagnostics =
        compile_diagnostics(&forbidden_application_policy, vec![owned_asset()]);
    let forbidden_policy = application_diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "change_request.application.policy_forbidden")
        .expect("manual application policy cannot declare planner dispositions");
    assert_eq!(
        forbidden_policy.path,
        "entities[id=person-name-change-request].changeRequest.application"
    );

    let mut escaping_path = base.clone();
    escaping_path["entities"][1]["changeRequest"]["planner"]["script"] = json!("../outside.rhai");
    let escaping_codes = compile_codes(
        &escaping_path,
        vec![ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: script.clone(),
        }],
    );
    assert!(
        escaping_codes.contains("change_request.planner.source_invalid"),
        "unexpected diagnostics: {escaping_codes:?}"
    );

    assert!(compile_codes(&base, Vec::new()).contains("change_request.planner.source_missing"));

    let invalid_entrypoint = compile_codes(
        &base,
        vec![ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: b"fn not_plan(ctx) { #{} }".to_vec(),
        }],
    );
    assert!(invalid_entrypoint.contains("change_request.planner.entrypoint"));

    let wrong_origin = compile_codes(
        &base,
        vec![ModuleAssetSource {
            module: Some("unrelated-module".to_owned()),
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: script,
        }],
    );
    assert!(wrong_origin.contains("change_request.planner.source_missing"));
    assert!(wrong_origin.contains("change_request.planner.asset_undeclared"));

    for (path, value) in [
        ("planner kind", json!("javascript")),
        ("application mode", json!("background")),
        ("disposition", json!("defer")),
        ("write operation", json!("delete")),
    ] {
        let mut unknown = base.clone();
        match path {
            "planner kind" => unknown["entities"][1]["changeRequest"]["planner"]["kind"] = value,
            "application mode" => {
                unknown["entities"][1]["changeRequest"]["application"]["mode"] = value
            }
            "disposition" => {
                unknown["entities"][1]["changeRequest"]["application"]["allowedDispositions"] =
                    json!([value])
            }
            "write operation" => {
                unknown["entities"][1]["changeRequest"]["planner"]["writes"][0]["operation"] = value
            }
            _ => unreachable!(),
        }
        let encoded = serde_json::to_vec(&unknown).expect("unknown contract serializes");
        assert!(
            registry_server::contract::parse_project_json(&encoded).is_err(),
            "unknown {path} must fail closed"
        );
    }
}

#[test]
fn rhai_planner_contract_fingerprint_binds_governed_meaning_only() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let base: Value = serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    let script =
        std::fs::read(root.join("scripts/person-name-change.rhai")).expect("planner reads");
    let fingerprint = |value: &Value, asset_path: &str, asset_bytes: Vec<u8>| {
        let project = registry_server::contract::parse_project_json(
            &serde_json::to_vec(value).expect("test project serializes"),
        )
        .expect("strict test project parses");
        let compiled = compile_project_with_assets(
            &project,
            &[],
            &[ModuleAssetSource {
                module: None,
                path: asset_path.to_owned(),
                bytes: asset_bytes,
            }],
            CompileProfile::Authoring,
        )
        .expect("valid planner variant compiles");
        compiled.entities()["person-name-change-request"]
            .change_request
            .as_ref()
            .expect("request contract compiles")
            .contract_fingerprint
            .clone()
    };
    let original = fingerprint(&base, "scripts/person-name-change.rhai", script.clone());

    let mut changed_script = script.clone();
    changed_script.push(b' ');
    assert_ne!(
        original,
        fingerprint(&base, "scripts/person-name-change.rhai", changed_script)
    );

    let mut request_fields = base.clone();
    request_fields["entities"][1]["changeRequest"]["planner"]["requestFields"] =
        json!(["person", "given-name", "family-name"]);
    assert_ne!(
        original,
        fingerprint(
            &request_fields,
            "scripts/person-name-change.rhai",
            script.clone()
        )
    );

    let mut write_ceiling = base.clone();
    write_ceiling["entities"][1]["changeRequest"]["planner"]["writes"][0]["fields"] =
        json!(["display-name", "person-code"]);
    assert_ne!(
        original,
        fingerprint(
            &write_ceiling,
            "scripts/person-name-change.rhai",
            script.clone()
        )
    );

    let mut application_policy = base.clone();
    application_policy["entities"][1]["changeRequest"]["application"]["allowedDispositions"] =
        json!(["apply"]);
    application_policy["entities"][1]["changeRequest"]["application"]
        .as_object_mut()
        .expect("application is an object")
        .remove("queueReasons");
    assert_ne!(
        original,
        fingerprint(
            &application_policy,
            "scripts/person-name-change.rhai",
            script.clone()
        )
    );

    let mut queue_reason = base.clone();
    queue_reason["entities"][1]["changeRequest"]["application"]["queueReasons"]
        ["assisted-review"] = json!("A revised reviewed label");
    assert_ne!(
        original,
        fingerprint(
            &queue_reason,
            "scripts/person-name-change.rhai",
            script.clone()
        )
    );

    let mut review_policy = base.clone();
    review_policy["entities"][1]["changeRequest"]["review"] =
        json!({"stages": [{"id": "review", "approvals": 1}]});
    let submitter_grant = &mut review_policy["accessProfiles"][1]["grants"][0];
    submitter_grant["operations"] = json!([
        "create",
        "get",
        "submit_request",
        "approve_request",
        "apply_request"
    ]);
    submitter_grant["reviewStages"] = json!([{
        "stage": "review",
        "targets": [{"entity": "person", "readableFields": ["display-name"]}]
    }]);
    assert_ne!(
        original,
        fingerprint(
            &review_policy,
            "scripts/person-name-change.rhai",
            script.clone()
        )
    );

    let mut renamed_path = base.clone();
    renamed_path["entities"][1]["changeRequest"]["planner"]["script"] =
        json!("scripts/renamed-person-name-change.rhai");
    // A path-only rename within the same declaring origin is package closure,
    // not planner meaning. Exact bytes and origin stay bound separately.
    assert_eq!(
        original,
        fingerprint(
            &renamed_path,
            "scripts/renamed-person-name-change.rhai",
            script.clone()
        )
    );

    let mut unrelated = base;
    unrelated["manifestProjection"]["catalog"]["description"] =
        json!("Unrelated public catalogue wording");
    assert_eq!(
        original,
        fingerprint(&unrelated, "scripts/person-name-change.rhai", script)
    );
}

#[test]
fn rhai_planner_output_abi_is_closed_and_symbolic() {
    let valid_effect =
        "#{target: #{fromField: `subject`}, operation: `patch`, set: #{label: `safe`}}";
    let invalid_scripts = [
        "fn plan(ctx) { 42 }".to_owned(),
        format!("fn plan(ctx) {{ #{{effects: [{valid_effect}], actor: `forged`}} }}"),
        "fn plan(ctx) { #{effects: #{}} }".to_owned(),
        "fn plan(ctx) { #{effects: []} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{id: `550e8400-e29b-41d4-a716-446655440000`}, operation: `patch`, set: #{label: `unsafe`}}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{entity: `record`}, operation: `patch`, set: #{label: `unsafe`}}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `delete`, set: #{label: `unsafe`}}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, set: #{label: `safe`}, unexpected: true}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, dependsOn: [`other`], set: #{label: `safe`}}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, clear: `label`}]} }".to_owned(),
        "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, set: #{label: ()}}]} }".to_owned(),
    ];
    for script in invalid_scripts {
        assert!(
            plan_change_request_effects(
                &plan(&script, CompiledChangeRequestApplicationMode::Automatic),
                &request(),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err(),
            "invalid output ABI was accepted: {script}"
        );
    }

    let reference_script = |value: &str| {
        format!(
            "fn plan(ctx) {{ #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: {value}}}}}]}} }}"
        )
    };
    let reference_plan = |script: &str| {
        let mut candidate = plan(script, CompiledChangeRequestApplicationMode::Automatic);
        let write = &mut candidate
            .planner
            .as_mut()
            .expect("test planner exists")
            .writes[0];
        write.field_types.insert(
            "label".to_owned(),
            FieldTypeSource::Reference {
                target: "record".to_owned(),
                on_delete: registry_server::contract::ReferenceDelete::Restrict,
            },
        );
        write.reference_sources.insert(
            "label".to_owned(),
            registry_server::model::CompiledChangeRequestReferenceSources {
                request_fields: BTreeSet::from(["subject".to_owned()]),
                create_entities: BTreeSet::new(),
            },
        );
        candidate
    };
    for value in [
        "`550e8400-e29b-41d4-a716-446655440000`",
        "#{fromField: `optional`}",
        "#{fromEffect: `unreserved`}",
        "#{fromField: `subject`, fromEffect: `other`}",
    ] {
        let script = reference_script(value);
        assert!(
            plan_change_request_effects(
                &reference_plan(&script),
                &request(),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err(),
            "unsafe reference output was accepted: {value}"
        );
    }

    let required_clear = "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, clear: [`label`]}]} }";
    let mut required_plan = plan(
        required_clear,
        CompiledChangeRequestApplicationMode::Automatic,
    );
    required_plan
        .planner
        .as_mut()
        .expect("test planner exists")
        .writes[0]
        .required_fields
        .insert("label".to_owned());
    assert_eq!(
        plan_change_request_effects(
            &required_plan,
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Ceiling)
    );
}

#[test]
fn rhai_planner_application_disposition_truth_table_is_exact() {
    let effect = "#{target: #{fromField: `subject`}, operation: `patch`, set: #{label: `safe`}}";
    let script = |members: &str| format!("fn plan(ctx) {{ #{{{members}effects: [{effect}]}} }}");
    let run = |mode, members: &str| {
        plan_change_request_effects(
            &plan(&script(members), mode),
            &request(),
            Instant::now() + Duration::from_secs(1),
        )
    };

    let manual = run(CompiledChangeRequestApplicationMode::Manual, "")
        .expect("manual policy queues a complete plan");
    assert_eq!(manual.disposition, CompiledChangeRequestDisposition::Queue);
    assert!(manual.queue_reason.is_none());
    assert_eq!(
        run(
            CompiledChangeRequestApplicationMode::Manual,
            "disposition: `apply`, "
        ),
        Err(ChangeRequestPlannerError::Disposition)
    );

    let automatic = run(CompiledChangeRequestApplicationMode::Automatic, "")
        .expect("automatic policy applies a complete plan");
    assert_eq!(
        automatic.disposition,
        CompiledChangeRequestDisposition::Apply
    );
    assert_eq!(
        run(
            CompiledChangeRequestApplicationMode::Automatic,
            "disposition: `queue`, reasonCode: `needs_review`, "
        ),
        Err(ChangeRequestPlannerError::Disposition)
    );

    let apply = run(
        CompiledChangeRequestApplicationMode::Planner,
        "disposition: `apply`, ",
    )
    .expect("allowed apply disposition is accepted");
    assert_eq!(apply.disposition, CompiledChangeRequestDisposition::Apply);
    assert!(apply.queue_reason.is_none());

    let queue = run(
        CompiledChangeRequestApplicationMode::Planner,
        "disposition: `queue`, reasonCode: `needs_review`, ",
    )
    .expect("allowed queue disposition and declared reason are accepted");
    assert_eq!(queue.disposition, CompiledChangeRequestDisposition::Queue);
    assert_eq!(
        queue
            .queue_reason
            .as_ref()
            .map(|reason| reason.code.as_str()),
        Some("needs_review")
    );

    for members in [
        "",
        "disposition: `queue`, ",
        "disposition: `apply`, reasonCode: `needs_review`, ",
        "disposition: `queue`, reasonCode: `dynamic-secret`, ",
        "reasonCode: `needs_review`, ",
    ] {
        assert_eq!(
            run(CompiledChangeRequestApplicationMode::Planner, members),
            Err(ChangeRequestPlannerError::Disposition),
            "invalid planner application result was accepted: {members}"
        );
    }

    let mut apply_only = plan(
        &script("disposition: `queue`, reasonCode: `needs_review`, "),
        CompiledChangeRequestApplicationMode::Planner,
    );
    apply_only.application.allowed_dispositions =
        BTreeSet::from([CompiledChangeRequestDisposition::Apply]);
    assert_eq!(
        plan_change_request_effects(
            &apply_only,
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Disposition)
    );
}

#[test]
fn anonymous_presence_rejects_a_non_public_rhai_target_link() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let mut project: serde_json::Value =
        serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    project["entities"][0]["classification"] = json!("public");
    project["entities"][0]["fields"][0]["classification"] = json!("public");
    project["entities"][1]["classification"] = json!("public");
    for field in project["entities"][1]["fields"]
        .as_array_mut()
        .expect("request fields are an array")
    {
        field["classification"] = json!("public");
    }
    project["entities"][1]["fields"][0]["classification"] = json!("internal");
    project["accessProfiles"]
        .as_array_mut()
        .expect("profiles are an array")
        .push(json!({
            "id": "public-person-reader",
            "anonymous": true,
            "grants": [{
                "entity": "person",
                "operations": ["get", "list"],
                "readableFields": ["person-code"],
                "requestPresence": [{"requestType": "person-name-change-request"}]
            }]
        }));
    let project = registry_server::contract::parse_project_json(
        &serde_json::to_vec(&project).expect("test project serializes"),
    )
    .expect("strict project parses");
    let failure = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                .expect("planner reads"),
        }],
        CompileProfile::Authoring,
    )
    .expect_err("anonymous presence cannot process a classified Rhai target link");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "change_request.presence.anonymous_non_public" }));
}

#[test]
fn automatic_apply_requires_same_profile_trigger_and_target_authority() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let mut project: serde_json::Value =
        serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    let submitter = project["accessProfiles"]
        .as_array_mut()
        .expect("profiles are an array")
        .iter_mut()
        .find(|profile| profile["id"] == "name-change-submitter")
        .expect("submitter profile exists");
    submitter["grants"][0]["operations"] = json!(["create", "get", "submit_request"]);
    submitter["grants"][0]
        .as_object_mut()
        .expect("grant is an object")
        .remove("applyTargets");
    let project = registry_server::contract::parse_project_json(
        &serde_json::to_vec(&project).expect("test project serializes"),
    )
    .expect("strict project parses");
    let failure = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                .expect("planner reads"),
        }],
        CompileProfile::Authoring,
    )
    .expect_err("split submit and apply profiles cannot satisfy apply-on-ready");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.code == "change_request.application.automatic_apply_profile_missing"
        })
        .expect("automatic application requires one complete triggering profile");
    assert_eq!(
        diagnostic.path,
        "entities[id=person-name-change-request].accessProfiles"
    );
}

#[test]
fn staged_planner_final_review_cannot_borrow_a_separate_apply_profile() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance/person-name-change-rhai");
    let project_bytes = std::fs::read(root.join("registry.yaml")).expect("fixture project reads");
    let mut project: serde_json::Value =
        serde_norway::from_slice(&project_bytes).expect("fixture YAML converts");
    let request = project["entities"]
        .as_array_mut()
        .expect("entities are an array")
        .iter_mut()
        .find(|entity| entity["id"] == "person-name-change-request")
        .expect("request entity exists");
    request["changeRequest"]["review"] = json!({
        "stages": [{"id": "final", "approvals": 1}]
    });
    let profiles = project["accessProfiles"]
        .as_array_mut()
        .expect("profiles are an array");
    profiles.push(json!({
        "id": "final-reviewer-without-apply",
        "principalClaim": "registry_principal",
        "grants": [{
            "entity": "person-name-change-request",
            "operations": ["get", "approve_request"],
            "readableFields": ["person", "given-name", "family-name", "handling"],
            "reviewStages": [{
                "stage": "final",
                "targets": [{"entity": "person", "readableFields": ["display-name"]}]
            }]
        }]
    }));
    profiles.push(json!({
        "id": "separate-staged-applier",
        "principalClaim": "registry_principal",
        "grants": [{
            "entity": "person-name-change-request",
            "operations": ["get", "apply_request"],
            "readableFields": ["person", "given-name", "family-name", "handling"],
            "applyTargets": [{"entity": "person", "rowBoundaries": []}]
        }]
    }));
    let project = registry_server::contract::parse_project_json(
        &serde_json::to_vec(&project).expect("test project serializes"),
    )
    .expect("strict project parses");
    let failure = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/person-name-change.rhai".to_owned(),
            bytes: std::fs::read(root.join("scripts/person-name-change.rhai"))
                .expect("planner reads"),
        }],
        CompileProfile::Authoring,
    )
    .expect_err("final review cannot borrow a separate profile's apply authority");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "change_request.application.automatic_apply_profile_missing"
    }));
}

#[test]
fn rhai_planner_source_byte_limit_is_exact_and_defensive() {
    let base = healthy_script("source-bound");
    let exact = format!("{base}{}", " ".repeat(MAXIMUM_SOURCE_BYTES - base.len()));
    assert_eq!(exact.len(), MAXIMUM_SOURCE_BYTES);
    ChangeRequestPlannerRuntime::compile_source(&exact).expect("exact source bound compiles");

    let oversized = format!("{exact} ");
    assert!(matches!(
        ChangeRequestPlannerRuntime::compile_source(&oversized),
        Err(ChangeRequestPlannerError::Source)
    ));
    let error = plan_change_request_effects(
        &plan(&oversized, CompiledChangeRequestApplicationMode::Automatic),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect_err("runtime rechecks source bytes independently of compilation");
    assert_eq!(error, ChangeRequestPlannerError::Source);
}

#[test]
fn rhai_planner_call_depth_limit_is_enforced() {
    let script = format!(
        r#"
        fn descend(remaining) {{
            if remaining == 0 {{ return 0; }}
            1 + descend(remaining - 1)
        }}
        fn plan(ctx) {{
            let depth = descend({});
            #{{effects: [#{{target: #{{fromField: "subject"}}, operation: "patch", set: #{{label: "depth"}}}}]}}
        }}
        "#,
        MAXIMUM_CALL_DEPTH * 2
    );
    let error = plan_change_request_effects(
        &plan(&script, CompiledChangeRequestApplicationMode::Automatic),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect_err("recursive calls stop at the fixed call-depth limit");
    assert_eq!(error, ChangeRequestPlannerError::Resource);
}

#[test]
fn rhai_planner_expression_depth_limit_is_enforced() {
    let expression = (0..MAXIMUM_EXPRESSION_DEPTH + 8)
        .fold("1".to_owned(), |nested, _| format!("1 + ({nested})"));
    let script = format!(
        "fn plan(ctx) {{ let deep = {expression}; #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `expression`}}}}]}} }}"
    );
    assert!(matches!(
        ChangeRequestPlannerRuntime::compile_source(&script),
        Err(ChangeRequestPlannerError::Source)
    ));
    ChangeRequestPlannerRuntime::compile_source(&healthy_script("shallow"))
        .expect("ordinary expressions remain available");
}

#[test]
fn rhai_planner_string_limit_is_enforced_for_input_and_output() {
    let script = healthy_script("string-bound");
    let input_plan = plan(&script, CompiledChangeRequestApplicationMode::Automatic);
    let mut exact_input = request();
    exact_input.insert(
        "optional".to_owned(),
        Value::String("x".repeat(MAXIMUM_STRING_BYTES)),
    );
    plan_change_request_effects(
        &input_plan,
        &exact_input,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact input string bound is accepted");
    exact_input.insert(
        "optional".to_owned(),
        Value::String("x".repeat(MAXIMUM_STRING_BYTES + 1)),
    );
    assert_eq!(
        plan_change_request_effects(
            &input_plan,
            &exact_input,
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );

    let output = r#"
        fn plan(ctx) {
            let text = "x";
            for n in 0..14 { text += text; }
            #{effects: [#{target: #{fromField: "subject"}, operation: "patch", set: #{label: "string-output"}}]}
        }
    "#;
    plan_change_request_effects(
        &plan(output, CompiledChangeRequestApplicationMode::Automatic),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("a script can build and consume the exact string bound");

    let oversized = output.replace("#{effects:", "text += `x`; #{effects:");
    assert_eq!(
        plan_change_request_effects(
            &plan(&oversized, CompiledChangeRequestApplicationMode::Automatic),
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );
}

#[test]
fn rhai_planner_array_limit_is_enforced_for_input_and_output() {
    let mut input = request();
    input.insert(
        "optional".to_owned(),
        Value::Array(vec![Value::Null; MAXIMUM_ARRAY_ITEMS]),
    );
    plan_change_request_effects(
        &plan(
            &healthy_script("array-input"),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &input,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact input array bound is accepted");
    input.insert(
        "optional".to_owned(),
        Value::Array(vec![Value::Null; MAXIMUM_ARRAY_ITEMS + 1]),
    );
    assert_eq!(
        plan_change_request_effects(
            &plan(
                &healthy_script("array-input"),
                CompiledChangeRequestApplicationMode::Automatic,
            ),
            &input,
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );

    let array_script = |items| {
        format!(
            "fn plan(ctx) {{ let values = []; for n in 0..{items} {{ values.push(n); }} #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `array-output`}}}}]}} }}"
        )
    };
    plan_change_request_effects(
        &plan(
            &array_script(MAXIMUM_ARRAY_ITEMS),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("a script can build and consume the exact array bound");
    let array_output_script = |items| {
        format!(
            "fn plan(ctx) {{ let values = []; for n in 0..{items} {{ values.push(n); }} #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: #{{value: values}}}}}}]}} }}"
        )
    };
    let candidate = plan_change_request_effects(
        &structured_plan(&array_output_script(8)),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("ordinary array output is accepted");
    assert_eq!(
        literal(&candidate)
            .get("value")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(8)
    );
    assert_eq!(
        plan_change_request_effects(
            &structured_plan(&array_output_script(MAXIMUM_ARRAY_ITEMS + 1)),
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );
}

#[test]
fn rhai_planner_map_limit_is_enforced_for_input_and_output() {
    let exact_map = (0..MAXIMUM_MAP_ENTRIES)
        .map(|index| (format!("key-{index}"), Value::Null))
        .collect();
    let mut input = request();
    input.insert("optional".to_owned(), Value::Object(exact_map));
    plan_change_request_effects(
        &plan(
            &healthy_script("map-input"),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &input,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact input map bound is accepted");
    let oversized_map = (0..=MAXIMUM_MAP_ENTRIES)
        .map(|index| (format!("key-{index}"), Value::Null))
        .collect();
    input.insert("optional".to_owned(), Value::Object(oversized_map));
    assert_eq!(
        plan_change_request_effects(
            &plan(
                &healthy_script("map-input"),
                CompiledChangeRequestApplicationMode::Automatic,
            ),
            &input,
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );

    let map_script = |entries| {
        format!(
            "fn plan(ctx) {{ let values = #{{}}; for n in 0..{entries} {{ values[n.to_string()] = n; }} #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `map-output`}}}}]}} }}"
        )
    };
    plan_change_request_effects(
        &plan(
            &map_script(MAXIMUM_MAP_ENTRIES),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("a script can build and consume the exact map bound");
    let map_output_script = |entries| {
        format!(
            "fn plan(ctx) {{ let values = #{{}}; for n in 0..{entries} {{ values[n.to_string()] = n; }} #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: #{{value: values}}}}}}]}} }}"
        )
    };
    let candidate = plan_change_request_effects(
        &structured_plan(&map_output_script(8)),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("ordinary map output is accepted");
    assert_eq!(
        literal(&candidate)
            .get("value")
            .and_then(Value::as_object)
            .map(Map::len),
        Some(8)
    );
    assert_eq!(
        plan_change_request_effects(
            &structured_plan(&map_output_script(MAXIMUM_MAP_ENTRIES + 1)),
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );
}

#[test]
fn rhai_planner_module_limit_is_zero_and_imports_never_resolve() {
    let plan = plan(
        &healthy_script("no-modules"),
        CompiledChangeRequestApplicationMode::Automatic,
    );
    assert_eq!(
        plan.planner
            .as_ref()
            .expect("test planner exists")
            .limits
            .maximum_modules,
        0
    );
    assert!(matches!(
        ChangeRequestPlannerRuntime::compile_source(
            "import `ambient` as ambient; fn plan(ctx) { #{} }"
        ),
        Err(ChangeRequestPlannerError::Source)
    ));
}

#[test]
fn rhai_planner_recursive_input_and_output_conversion_is_bounded() {
    let mut input = request();
    input.insert("optional".to_owned(), nested_array(MAXIMUM_VALUE_DEPTH));
    plan_change_request_effects(
        &plan(
            &healthy_script("nested-input"),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &input,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact recursive input bound is accepted");
    input.insert("optional".to_owned(), nested_array(MAXIMUM_VALUE_DEPTH + 1));
    assert_eq!(
        plan_change_request_effects(
            &plan(
                &healthy_script("nested-input"),
                CompiledChangeRequestApplicationMode::Automatic,
            ),
            &input,
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );

    let output_script = |depth| {
        format!(
            "fn plan(ctx) {{ let value = (); for n in 0..{depth} {{ value = #{{child: value}}; }} #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: #{{value: value}}}}}}]}} }}"
        )
    };
    plan_change_request_effects(
        &structured_plan(&output_script(MAXIMUM_VALUE_DEPTH - 1)),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact recursive output bound is accepted");
    assert_eq!(
        plan_change_request_effects(
            &structured_plan(&output_script(MAXIMUM_VALUE_DEPTH)),
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Resource)
    );
}

#[test]
fn rhai_planner_deterministic_language_surface_is_usable() {
    let script = r#"
        fn normalize(parts) {
            let normalized = [];
            for part in parts {
                let clean = part;
                clean.trim();
                clean.make_lower();
                if !clean.is_empty() { normalized.push(clean); }
            }
            normalized.join("-")
        }
        fn plan(ctx) {
            let selected = if ctx.request.optional == () { ctx.request.label } else { "wrong" };
            let label = normalize(selected.split("|"));
            #{effects: [#{target: #{fromField: "subject"}, operation: "patch", set: #{label: label}}]}
        }
    "#;
    let mut input = request();
    input.insert("label".to_owned(), json!(" Alpha | BETA "));
    let candidate = plan_change_request_effects(
        &plan(script, CompiledChangeRequestApplicationMode::Automatic),
        &input,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("deterministic authoring surface runs");
    assert_eq!(literal(&candidate), "alpha-beta");
}

#[test]
fn rhai_planner_runs_have_fresh_state_and_failures_leave_runtime_healthy() {
    let script = r#"
        fn plan(ctx) {
            ctx.request.label += "-once";
            #{effects: [#{target: #{fromField: "subject"}, operation: "patch", set: #{label: ctx.request.label}}]}
        }
    "#;
    let fresh_plan = plan(script, CompiledChangeRequestApplicationMode::Automatic);
    for _ in 0..2 {
        let candidate = plan_change_request_effects(
            &fresh_plan,
            &request(),
            Instant::now() + Duration::from_secs(1),
        )
        .expect("each run receives a fresh context and engine");
        assert_eq!(literal(&candidate), "bounded-once");
    }
    let failure = plan_change_request_effects(
        &plan(
            "fn plan(ctx) { while true {} }",
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect_err("resource exhaustion is isolated");
    assert_eq!(failure, ChangeRequestPlannerError::Resource);
    plan_change_request_effects(
        &fresh_plan,
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("a fresh run remains healthy after exhaustion");
}

#[test]
fn rhai_planner_input_and_engine_capabilities_are_closed() {
    for source in [
        "fn plan(ctx) { print(ctx); }",
        "fn plan(ctx) { debug(ctx); }",
        "fn plan(ctx) { eval(`40 + 2`); }",
        "import \"ambient\" as ambient; fn plan(ctx) { #{} }",
    ] {
        assert!(
            ChangeRequestPlannerRuntime::compile_source(source).is_err(),
            "{source}"
        );
    }
    for expression in [
        "get_env(`RHAI_PLANNER_CANARY`)",
        "read_file(`/tmp/rhai-planner-canary`)",
        "http_get(`https://example.invalid`)",
        "run_process(`rhai-planner-canary`)",
        "now()",
        "random()",
    ] {
        let source = format!(
            "fn plan(ctx) {{ let ambient = {expression}; #{{effects: [#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `ambient`}}}}]}} }}"
        );
        assert_eq!(
            plan_change_request_effects(
                &plan(&source, CompiledChangeRequestApplicationMode::Automatic),
                &request(),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ChangeRequestPlannerError::Execution),
            "ambient capability was unexpectedly available: {expression}"
        );
    }
    let script = r#"
        fn plan(ctx) {
            for key in [
                "claims", "principal", "scopes", "purpose", "headers", "trace",
                "time", "random", "environment", "filesystem", "network", "process",
                "credentials", "target", "targets", "before", "after", "lifecycle"
            ] {
                if ctx.contains(key) { throw "ambient context"; }
            }
            let chosen = if ctx.request.contains("undeclared_canary") { "leaked" } else { ctx.request.label };
            if !ctx.request.contains("optional") || ctx.request.optional != () { throw "bad presence"; }
            #{effects: [#{target: #{fromField: "subject"}, operation: "patch", set: #{label: chosen}}]}
        }
    "#;
    let candidate = plan_change_request_effects(
        &plan(script, CompiledChangeRequestApplicationMode::Automatic),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("closed planner runs");
    assert!(matches!(
        &candidate.effects[0].mutations[0],
        CandidateChangeRequestMutation::Set {
            value: CandidateChangeRequestValue::Literal(value), ..
        } if value == "bounded"
    ));
}

#[test]
fn rhai_planner_resource_limits_and_deadline_leave_runtime_healthy() {
    let effects_script = |count| {
        format!(
            "fn plan(ctx) {{ let effects = []; for n in 0..{count} {{ effects.push(#{{target: #{{fromField: `subject`}}, operation: `patch`, set: #{{label: `bounded`}}}}); }} #{{effects: effects}} }}"
        )
    };
    let exact_effects = plan_change_request_effects(
        &plan(
            &effects_script(16),
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect("exact canonical target ceiling is accepted by the planner ABI");
    assert_eq!(exact_effects.effects.len(), 16);
    assert_eq!(
        plan_change_request_effects(
            &plan(
                &effects_script(17),
                CompiledChangeRequestApplicationMode::Automatic,
            ),
            &request(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ChangeRequestPlannerError::Ceiling)
    );

    let exhausted = plan_change_request_effects(
        &plan(
            "fn plan(ctx) { while true {} }",
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(5),
    )
    .expect_err("operation exhaustion is closed");
    assert_eq!(exhausted, ChangeRequestPlannerError::Resource);

    let deadline = plan_change_request_effects(
        &plan(
            "fn plan(ctx) { #{} }",
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now(),
    )
    .expect_err("expired action deadline is honored");
    assert_eq!(deadline, ChangeRequestPlannerError::Deadline);

    let healthy = plan_change_request_effects(
        &plan(
            "fn plan(ctx) { #{effects: [#{target: #{fromField: `subject`}, operation: `patch`, set: #{label: `healthy`}}]} }",
            CompiledChangeRequestApplicationMode::Automatic,
        ),
        &request(),
        Instant::now() + Duration::from_secs(1),
    );
    assert!(healthy.is_ok());
}

#[test]
fn rhai_planner_errors_and_queue_reasons_are_value_free() {
    let script = r#"
        fn plan(ctx) {
            #{disposition: "queue", reasonCode: "secret-canary", effects: [#{target: #{fromField: "subject"}, operation: "patch", set: #{label: ctx.request.label}}]}
        }
    "#;
    let error = plan_change_request_effects(
        &plan(script, CompiledChangeRequestApplicationMode::Planner),
        &request(),
        Instant::now() + Duration::from_secs(1),
    )
    .expect_err("undeclared reason is refused");
    assert_eq!(error.code(), "change_request.planner.disposition");
    assert!(!error.to_string().contains("secret-canary"));
    assert!(!format!("{error:?}").contains("secret-canary"));
}
