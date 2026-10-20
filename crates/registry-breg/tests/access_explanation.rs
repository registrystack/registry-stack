// SPDX-License-Identifier: Apache-2.0

use registry_breg::{
    compile_project, compile_project_with_assets,
    contract::{ModuleAssetSource, Operation},
    parse_project_json, CompileProfile,
};
use serde_json::{json, Value};

fn source() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"access-explanation","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access.example.test"},
        "recordTypes":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"district","type":"string","maximumLength":32,"classification":"internal"}]}],
        "accessProfiles":[{"id":"clerk","principalClaim":"registry_principal","requiredScopes":["entry:edit"],
          "permissions":{"records":[{"recordType":"entry","operations":["get","patch"],"readableFields":["district"],"writableFields":["district"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]}}]
    })
}

fn compile(source: &Value) -> registry_breg::CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn repeated_action_target_source() -> Value {
    let mut candidate = source();
    candidate["actions"] = json!([{"execution":{"mode":"immediate"},
        "id":"create-paired-entries",
        "inputs":[
            {"id":"first-district", "type":"string", "maximumLength":32, "required":true, "classification":"internal"},
            {"id":"second-district", "type":"string", "maximumLength":32, "required":true, "classification":"internal"}
        ],
        "plan":{"type":"fixed","effects":[
            {"id":"first", "target":{"recordType":"entry"}, "operation":"create", "set":{"district":{"fromInput":"first-district"}}},
            {"id":"second", "target":{"recordType":"entry"}, "operation":"create", "set":{"district":{"fromInput":"second-district"}}}
        ]}
    }]);
    candidate["accessProfiles"] = json!([{
        "id":"clerk", "default":true, "principalClaim":"registry_principal",
        "requiredScopes":["entry:edit"],
        "permissions":{"actions":[{
            "action":"create-paired-entries", "operations":["invoke"],
            "targets":[{"recordType":"entry", "rowBoundaries":[{"field":"district", "claim":"districts", "operator":"in"}]}],
            "results":["first", "second"]
        }]}
    }]);
    candidate
}

fn mixed_action_target_source() -> Value {
    let mut candidate = source();
    candidate["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"related", "type":"reference", "target":"entry",
            "classification":"internal"
        }));
    candidate["actions"] = json!([{"execution":{"mode":"immediate"},
        "id":"create-and-patch-entry",
        "inputs":[
            {"id":"existing", "type":"reference", "target":"entry", "required":true, "classification":"internal"},
            {"id":"linked", "type":"reference", "target":"entry", "required":true, "classification":"internal"},
            {"id":"create-district", "type":"string", "maximumLength":32, "required":true, "classification":"internal"},
            {"id":"patch-district", "type":"string", "maximumLength":32, "required":true, "classification":"internal"}
        ],
        "plan":{"type":"fixed","effects":[
            {"id":"created", "target":{"recordType":"entry"}, "operation":"create", "set":{
                "district":{"fromInput":"create-district"}, "related":{"fromInput":"linked"}
            }},
            {"id":"updated", "target":{"fromInput":"existing"}, "operation":"patch", "set":{
                "district":{"fromInput":"patch-district"}
            }}
        ]}
    }]);
    candidate["accessProfiles"] = json!([{
        "id":"clerk", "default":true, "principalClaim":"registry_principal",
        "requiredScopes":["entry:edit"],
        "permissions":{"actions":[{
            "action":"create-and-patch-entry", "operations":["invoke"],
            "targets":[{"recordType":"entry", "rowBoundaries":[{"field":"district", "claim":"districts", "operator":"in"}]}],
            "results":["created", "updated"]
        }]}
    }]);
    candidate
}

fn function_action_target_source() -> Value {
    let mut candidate = source();
    candidate["functions"] = json!([{
        "id":"create-entry-plan", "runtime":"rhai", "source":"plans/create-entry.rhai",
        "entrypoint":"plan", "abi":"registry.action-plan/v1"
    }]);
    candidate["actions"] = json!([{"execution":{"mode":"immediate"},
        "id":"create-entry",
        "inputs":[{"id":"district", "type":"string", "maximumLength":32, "required":true, "classification":"internal"}],
        "plan":{"type":"function", "function":"create-entry-plan", "inputs":["district"], "writes":[{
            "id":"entry", "target":{"recordType":"entry"}, "operation":"create", "fields":["district"]
        }]}
    }]);
    candidate["accessProfiles"] = json!([{
        "id":"clerk", "default":true, "principalClaim":"registry_principal",
        "requiredScopes":["entry:edit"],
        "permissions":{"actions":[{
            "action":"create-entry", "operations":["invoke"],
            "targets":[{"recordType":"entry", "rowBoundaries":[{"field":"district", "claim":"districts", "operator":"in"}]}],
            "results":["entry"]
        }]}
    }]);
    candidate
}

fn compile_function_action(source: &Value) -> registry_breg::CompiledRegistry {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/create-entry.rhai".to_owned(),
            bytes: br#"fn plan(ctx) { #{effects:[#{id:"entry",set:#{district:ctx.inputs.district}}]} }"#
                .to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn membership_source() -> Value {
    let mut source = source();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"organization", "type":"reference", "target":"organization",
            "classification":"internal"
        }));
    source["recordTypes"].as_array_mut().unwrap().extend([
        json!({"id":"organization", "primaryDataset":"test-dataset", "route":"organizations", "mutationMode":"mutable",
            "fields":[{"id":"label", "type":"string", "maximumLength":32, "classification":"internal"}]}),
        json!({"id":"membership", "primaryDataset":"test-dataset", "route":"memberships", "mutationMode":"mutable",
            "fields":[
                {"id":"organization", "type":"reference", "target":"organization", "classification":"internal"},
                {"id":"principal", "type":"string", "maximumLength":64, "classification":"internal"},
                {"id":"active", "type":"boolean", "classification":"internal"}
            ]}),
    ]);
    source["accessProfiles"][0]["principalClaim"] = json!("sub");
    let grant = &mut source["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["get", "list"]);
    grant["writableFields"] = json!([]);
    grant["rowBoundaries"] = json!("unrestricted");
    grant["membershipBoundaries"] = json!([{
        "field":"organization", "membershipRecordType":"membership",
        "membershipKeyField":"organization", "principalField":"principal", "activeField":"active"
    }]);
    source
}

#[test]
fn access_explanation_connects_row_reach_to_typed_claim_requirements() {
    let registry = compile(&source());
    let explanation =
        serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    assert_eq!(explanation["rowReach"][0]["rows"], "claim_bound");
    assert_eq!(
        explanation["recordTypes"][0]["profiles"][0]["allowCount"],
        false
    );
    assert_eq!(
        explanation["recordTypes"][0]["profiles"][0]["rowBoundaries"],
        source()["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"]
    );
    // A project without consent configuration states no consent block.
    assert_eq!(explanation["consent"], serde_json::Value::Null);
    assert!(explanation.as_object().unwrap().contains_key("consent"));
    // A project without statistical datasets states an empty audience list.
    assert_eq!(explanation["statisticalDatasets"], json!([]));
    assert_eq!(explanation["rowReach"][0]["profile"], "clerk");
    assert_eq!(explanation["rowReach"][0]["ownerOnly"], false);
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["multiValue"],
        true
    );
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["fieldType"]["type"],
        "string"
    );
    assert_eq!(
        explanation["claimContract"]["directClaims"]["districts"]["uses"][0]["recordType"],
        "entry"
    );
    assert!(explanation["claimContractError"].is_null());
    assert!(explanation["evaluation"]
        .as_str()
        .unwrap()
        .contains("not evaluated"));

    let mut broad = source();
    broad["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!("unrestricted");
    let registry = compile(&broad);
    assert!(registry
        .findings()
        .iter()
        .any(|finding| finding.code == "breg.access.profile-unrestricted-rows"));
    let explanation =
        serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    assert_eq!(explanation["rowReach"][0]["rows"], "all");
    assert_eq!(
        explanation["recordTypes"][0]["profiles"][0]["rowBoundaries"],
        "unrestricted"
    );
    assert_eq!(
        explanation["recordTypes"][0]["profiles"][0]["operations"],
        json!(["get", "patch"])
    );
}

#[test]
fn inspection_reports_count_defaults_without_changing_compiled_profile_serialization() {
    for allow_count in [false, true] {
        let mut source = source();
        let grant = &mut source["accessProfiles"][0]["permissions"]["records"][0];
        grant["operations"] = json!(["get", "list"]);
        grant["writableFields"] = json!([]);
        grant["rowBoundaries"] = json!("unrestricted");
        grant["allowCount"] = json!(allow_count);
        let registry = compile(&source);
        let compiled = &registry.entities()["entry"].access_profiles["clerk"];
        let before = serde_json::to_value(compiled).unwrap();
        let inspection =
            serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
        let profile = &inspection["recordTypes"][0]["profiles"][0];
        assert_eq!(profile["allowCount"], allow_count);
        assert_eq!(profile["rowBoundaries"], "unrestricted");
        assert_eq!(before["rowBoundaries"], json!([]));
        assert_eq!(
            before.get("allowCount").cloned(),
            allow_count.then_some(json!(true))
        );
        assert_eq!(serde_json::to_value(compiled).unwrap(), before);
        let warning = registry
            .findings()
            .iter()
            .find(|finding| finding.code == "breg.access.profile-unrestricted-collection")
            .unwrap();
        assert!(warning
            .message
            .contains("restrict the profile to intended callers"));
        assert!(warning
            .message
            .contains("publishers require unrestricted reads"));
        assert!(!warning
            .message
            .contains("Add a claim-bound row restriction"));
    }
}

#[test]
fn discriminated_action_targets_keep_one_entity_authority_lock() {
    let registry = compile(&repeated_action_target_source());
    let grant = &registry.actions().actions[0].permissions[0];
    assert_eq!(
        grant.targets.len(),
        2,
        "both effect sources stay discriminated"
    );

    let explanation = registry_breg::access::explain_access(&registry);
    let action_reach = explanation
        .row_reach
        .iter()
        .filter(|reach| reach.surface == "action_target")
        .collect::<Vec<_>>();
    assert_eq!(
        action_reach.len(),
        1,
        "row reach describes the entity lock once"
    );
    assert_eq!(action_reach[0].entity, "entry");
    let authority = action_reach[0]
        .action_target_authority
        .as_ref()
        .expect("Action row reach identifies its authority");
    assert_eq!(authority.enforcement, "runtime_enforced");
    assert_eq!(authority.record_grant_relationship, "additional");
    assert!(!authority.has_direct_record_grant);
    assert_eq!(authority.uses.len(), 2);
    assert!(authority
        .uses
        .iter()
        .all(|use_| use_.role == "write" && use_.operation == Operation::Create));

    let claim_uses = &explanation
        .claim_contract
        .expect("the authority inventory compiles")
        .direct_claims["districts"]
        .uses;
    let action_uses = claim_uses
        .iter()
        .filter(|use_| use_.surface.starts_with("actions/"))
        .collect::<Vec<_>>();
    assert_eq!(
        action_uses.len(),
        1,
        "authority inventory describes the entity lock once"
    );
}

#[test]
fn action_target_authority_distinguishes_writes_from_existing_targets() {
    let candidate = mixed_action_target_source();
    let explanation = registry_breg::access::explain_access(&compile(&candidate));
    let action_reach = explanation
        .row_reach
        .iter()
        .filter(|reach| reach.surface == "action_target")
        .collect::<Vec<_>>();
    assert_eq!(action_reach.len(), 1, "one entity has one authority lock");
    let authority = action_reach[0]
        .action_target_authority
        .as_ref()
        .expect("Action row reach identifies its authority");
    assert_eq!(authority.enforcement, "runtime_enforced");
    assert_eq!(authority.record_grant_relationship, "additional");
    assert!(!authority.has_direct_record_grant);
    assert!(authority
        .uses
        .iter()
        .any(|use_| use_.role == "write" && use_.operation == Operation::Create));
    assert!(authority
        .uses
        .iter()
        .any(|use_| use_.role == "write" && use_.operation == Operation::Patch));
    assert!(authority
        .uses
        .iter()
        .any(|use_| use_.role == "existing_target" && use_.operation == Operation::Get));

    let mut with_direct_grant = candidate;
    with_direct_grant["accessProfiles"][0]["permissions"]["records"] =
        source()["accessProfiles"][0]["permissions"]["records"].clone();
    let explanation = registry_breg::access::explain_access(&compile(&with_direct_grant));
    let authority = explanation
        .row_reach
        .iter()
        .find(|reach| reach.surface == "action_target")
        .and_then(|reach| reach.action_target_authority.as_ref())
        .expect("Action row reach identifies its authority");
    assert!(authority.has_direct_record_grant);
}

#[test]
fn function_action_target_authority_uses_the_compiled_write_ceiling() {
    let registry = compile_function_action(&function_action_target_source());
    let explanation = registry_breg::access::explain_access(&registry);
    let authority = explanation
        .row_reach
        .iter()
        .find(|reach| reach.surface == "action_target")
        .and_then(|reach| reach.action_target_authority.as_ref())
        .expect("Function Action row reach identifies its authority");
    assert_eq!(authority.uses.len(), 1);
    assert_eq!(authority.uses[0].role, "write");
    assert_eq!(authority.uses[0].operation, Operation::Create);
    assert!(matches!(
        authority.uses[0].source,
        registry_breg::model::CompiledActionTargetUseSource::Effect { ref effect }
            if effect == "entry"
    ));
}

#[test]
fn membership_row_reach_is_explicit_and_uses_the_selected_principal() {
    for (boundaries, rows, direct_claims) in [
        (json!("unrestricted"), "membership_bound", 0),
        (
            json!([{"field":"district", "claim":"districts", "operator":"in"}]),
            "claim_and_membership_bound",
            1,
        ),
    ] {
        let mut source = membership_source();
        source["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
            boundaries.clone();
        let registry = compile(&source);
        let explanation = registry_breg::access::explain_access(&registry);
        let inspected = serde_json::to_value(&explanation).unwrap();
        let grant = &inspected["recordTypes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["recordType"] == "entry")
            .unwrap()["profiles"][0];
        assert_eq!(grant["rowBoundaries"], boundaries);
        assert_eq!(grant["membershipBoundaries"].as_array().unwrap().len(), 1);
        let reach = explanation
            .row_reach
            .iter()
            .find(|reach| reach.entity == "entry" && reach.profile == "clerk")
            .unwrap();
        assert_eq!(reach.rows, rows);
        assert_eq!(reach.membership_boundaries.len(), 1);
        assert_eq!(reach.membership_boundaries[0].principal_field, "principal");
        assert!(!registry.findings().iter().any(|finding| matches!(
            finding.code.as_str(),
            "breg.access.profile-unrestricted-rows" | "breg.access.profile-unrestricted-collection"
        )));
        let claims = explanation.claim_contract.unwrap();
        assert_eq!(claims.principal_claims, ["sub".to_owned()].into());
        assert_eq!(claims.direct_claims.len(), direct_claims);
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn membership_changes_report_authority_narrowing_and_widening() {
    use registry_breg::tooling::{classify_registry_diff, AccessChangeDirection};

    let mut source = membership_source();
    source["recordTypes"][2]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"approved", "type":"boolean", "classification":"internal"}));
    let mut additional =
        source["accessProfiles"][0]["permissions"]["records"][0]["membershipBoundaries"][0].clone();
    additional["activeField"] = json!("approved");
    let mut boundaries = source["accessProfiles"][0]["permissions"]["records"][0]
        ["membershipBoundaries"]
        .as_array()
        .unwrap()
        .clone();
    boundaries.push(additional);
    let registries = (0..=2)
        .map(|count| {
            source["accessProfiles"][0]["permissions"]["records"][0]["membershipBoundaries"] =
                json!(&boundaries[..count]);
            compile(&source)
        })
        .collect::<Vec<_>>();
    for (before, after, expected) in [
        (0, 1, AccessChangeDirection::Narrowing),
        (1, 2, AccessChangeDirection::Narrowing),
        (2, 1, AccessChangeDirection::Widening),
        (1, 0, AccessChangeDirection::Widening),
    ] {
        let diff = classify_registry_diff(&registries[before], &registries[after], "baseline");
        let detail = diff
            .changes
            .iter()
            .flat_map(|change| &change.access_details)
            .find(|detail| detail.field == "membershipBoundaries")
            .expect("changed membership authority is reported");
        assert_eq!(detail.direction, expected, "{before} -> {after}");
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn synthetic_own_record_preview_reuses_principal_and_refuses_identity_override() {
    let mut source = source();
    source["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!([{"field":"district","claim":"registry_principal","operator":"equals"}]);
    let registry = compile(&source);
    let mut scenario = json!({
        "recordType":"entry", "accessProfile":"clerk", "operation":"get",
        "claims":{"principalClaim":"registry_principal", "principal":"synthetic-clerk", "scopes":["entry:edit"]}
    });
    let mut removed = scenario.clone();
    removed.as_object_mut().unwrap().remove("recordType");
    removed["entity"] = json!("entry");
    assert!(
        serde_json::from_value::<registry_breg::access_preview::AccessScenario>(removed).is_err()
    );
    let preview = registry_breg::access_preview::preview_access(
        &registry,
        serde_json::from_value(scenario.clone()).unwrap(),
    )
    .unwrap();
    assert!(preview.admitted);
    assert_eq!(preview.record_access, "not-evaluated");
    scenario["claims"]["directClaims"] = json!({"registry_principal":"different-clerk"});
    assert!(registry_breg::access_preview::preview_access(
        &registry,
        serde_json::from_value(scenario).unwrap()
    )
    .is_err());
}
