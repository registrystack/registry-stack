// SPDX-License-Identifier: Apache-2.0

use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

fn source() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"access-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access-example.example.test"},
        "recordTypes":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"district","type":"string","maximumLength":32,"classification":"internal"}],
          "accessRequirements":{"requiredScopes":["entry:read"],"allowedPurposes":["administration"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}}],
        "accessProfiles":[{"id":"reader","principalClaim":"registry_principal","requiredScopes":["entry:read"],
          "requiredPurposes":["administration"],"permissions":{"records":[{"recordType":"entry","operations":["get","list"],
            "readableFields":["code","district"],"filterableFields":["district"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]}}]
    })
}

fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_with_profile(value, CompileProfile::Authoring)
}

fn compile_with_profile(
    value: &Value,
    profile: CompileProfile,
) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        profile,
    )
}

#[test]
fn a_grants_key_on_an_access_profile_is_refused_as_an_unknown_field() {
    let mut value = source();
    let permissions = value["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("permissions")
        .unwrap();
    value["accessProfiles"][0]["grants"] = permissions;

    let failure = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    let [diagnostic] = failure.diagnostics() else {
        panic!("the key is refused by one diagnostic: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.unknown-key");
    assert!(
        diagnostic.message.contains("`grants` is not a member"),
        "{}",
        diagnostic.message
    );
}

fn assert_refused(value: &Value, code: &str) {
    let failure = compile(value).unwrap_err();
    assert!(
        failure.diagnostics().iter().any(|d| d.code == code),
        "{failure:?}"
    );
}

#[test]
fn requirements_are_mandatory_not_grants_and_cannot_be_weakened_by_profiles() {
    let compiled = compile(&source()).unwrap();
    assert!(compiled
        .findings()
        .iter()
        .all(|d| !d.code.starts_with("access.")));
    let mutations = [
        (
            "/accessProfiles/0/requiredScopes",
            json!("unrestricted"),
            "breg.access.requirements-scope-missing",
        ),
        (
            "/accessProfiles/0/requiredPurposes",
            json!(["other"]),
            "breg.access.requirements-purpose-widened",
        ),
        (
            "/accessProfiles/0/permissions/records/0/rowBoundaries",
            json!("unrestricted"),
            "breg.access.requirements-row-boundary-missing",
        ),
        (
            "/accessProfiles/0/permissions/records/0/rowBoundaries/0/claim",
            json!("caller_district"),
            "breg.access.requirements-row-boundary-missing",
        ),
        (
            "/accessProfiles/0/permissions/records/0/rowBoundaries/0/operator",
            json!("equals"),
            "breg.access.requirements-row-boundary-missing",
        ),
    ];
    for (path, replacement, code) in mutations {
        let mut value = source();
        *value.pointer_mut(path).unwrap() = replacement;
        assert_refused(&value, code);
    }
    let mut unnarrowed = source();
    unnarrowed["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredPurposes");
    assert_refused(&unnarrowed, "breg.access.requirements-purpose-widened");
    let mut stricter = source();
    stricter["recordTypes"][0]["accessRequirements"]["allowedPurposes"] =
        json!(["administration", "review"]);
    stricter["accessProfiles"][0]["requiredScopes"] = json!(["entry:read", "entry:review"]);
    stricter["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .push(json!({"field":"code","claim":"assigned_code","operator":"equals"}));
    compile(&stricter).expect("profiles may add restrictions and narrow allowed purposes");
    let mut value = source();
    value["accessProfiles"] = json!([]);
    let compiled = compile(&value).unwrap();
    assert!(
        compiled.entities()["entry"].access_profiles.is_empty(),
        "requirements must not manufacture a grant"
    );
}

#[test]
fn requirements_validate_even_without_profiles() {
    for (requirements, code) in [
        (json!({}), "breg.access.requirements-empty"),
        (
            json!({"requiredScopes":[""]}),
            "breg.access.requirements-empty-value",
        ),
        (
            json!({"rowBoundaries":[{"field":"unknown","claim":"district","operator":"equals"}]}),
            "breg.access.requirements-row-boundary-invalid",
        ),
    ] {
        let mut value = source();
        value["recordTypes"][0]["accessRequirements"] = requirements;
        value["accessProfiles"] = json!([]);
        assert_refused(&value, code);
    }
}

fn read_refusals(failure: &registry_breg::CompileFailure) -> Vec<(&str, &str)> {
    failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

#[test]
fn an_anonymous_member_is_refused_when_the_project_is_read_with_its_fix_named() {
    use registry_breg::contract::parse_project_yaml;
    for written in [json!(true), json!(false)] {
        let mut value = source();
        value["accessProfiles"][0]["anonymous"] = written;
        let failure = parse_project_yaml(&serde_json::to_vec(&value).unwrap())
            .expect_err("an anonymous member is refused when the project is read");
        assert_eq!(
            read_refusals(&failure),
            vec![("config.removed-key", "project.accessProfiles[0].anonymous")],
            "{failure:?}"
        );
        let message = &failure.diagnostics()[0].message;
        assert!(
            message.contains("authenticated") && message.contains("requiredScopes"),
            "the refusal names the fix: {message}"
        );
    }
}

#[test]
fn an_anonymous_member_on_a_module_profile_is_refused_when_the_module_is_read() {
    use registry_breg::contract::parse_module_yaml;
    let profile = json!({"id":"public","anonymous":true,"operations":["get"],"rowBoundaries":[]});
    for (module, path) in [
        (
            json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule", "id":"extra","version":"1","recordTypes":[{"id":"place","primaryDataset":"test-dataset",
              "route":"places","mutationMode":"mutable","accessProfiles":[profile.clone()]}]}),
            "module.recordTypes[0].accessProfiles[0].anonymous",
        ),
        (
            json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule", "id":"extra","version":"1","extendRecordTypes":[{"recordType":"entry",
              "accessProfiles":[profile.clone()]}]}),
            "module.extendRecordTypes[0].accessProfiles[0].anonymous",
        ),
    ] {
        let failure = parse_module_yaml(&serde_json::to_vec(&module).unwrap())
            .expect_err("an anonymous member is refused when the module is read");
        assert!(
            read_refusals(&failure).contains(&("config.removed-key", path)),
            "{failure:?}"
        );
    }
}

#[test]
fn a_profile_that_names_no_principal_claim_is_refused_when_the_project_is_read() {
    use registry_breg::contract::parse_project_yaml;
    let mut value = source();
    value["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("principalClaim")
        .unwrap();
    let failure = parse_project_yaml(&serde_json::to_vec(&value).unwrap())
        .expect_err("a profile that names no principal claim is refused when the project is read");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the project: {failure:?}");
    };
    assert_eq!(diagnostic.code, "config.missing-key", "{failure:?}");
    assert_eq!(diagnostic.path, "project.accessProfiles[0]");
    assert!(
        diagnostic.message.contains("principalClaim"),
        "the refusal names the member: {}",
        diagnostic.message
    );
}

#[test]
fn a_module_profile_that_names_no_principal_claim_is_refused_when_the_module_is_read() {
    use registry_breg::contract::parse_module_yaml;
    let module = |profile: &Value| {
        [
            (
                json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule", "id":"extra","version":"1","recordTypes":[{"id":"place","primaryDataset":"test-dataset",
                  "route":"places","mutationMode":"mutable","accessProfiles":[profile.clone()]}]}),
                "module.recordTypes[0].accessProfiles[0]",
            ),
            (
                json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule", "id":"extra","version":"1","extendRecordTypes":[{"recordType":"entry",
                  "accessProfiles":[profile.clone()]}]}),
                "module.extendRecordTypes[0].accessProfiles[0]",
            ),
        ]
    };
    let unnamed = json!({"id":"clerk","requiredScopes":"unrestricted","operations":["get"],
        "rowBoundaries":"unrestricted"});
    for (module, path) in module(&unnamed) {
        let failure = parse_module_yaml(&serde_json::to_vec(&module).unwrap()).expect_err(
            "a profile that names no principal claim is refused when the module is read",
        );
        assert_eq!(
            read_refusals(&failure),
            vec![("config.missing-key", path)],
            "{failure:?}"
        );
    }
    let mut named = unnamed;
    named["principalClaim"] = json!("registry_principal");
    for (module, _) in module(&named) {
        parse_module_yaml(&serde_json::to_vec(&module).unwrap())
            .expect("a profile that names its principal claim is read");
    }
}

#[test]
fn a_principal_claim_written_empty_is_refused_when_the_project_is_compiled() {
    let mut value = source();
    value["accessProfiles"][0]["principalClaim"] = json!("");
    assert_refused(&value, "breg.access-profile.principal-claim-required");
}

#[test]
fn additional_profile_cannot_omit_entity_requirements() {
    let mut value = source();
    let mut additional = value["accessProfiles"][0].clone();
    additional["id"] = json!("another-reader");
    additional["requiredScopes"] = json!("unrestricted");
    value["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(additional);
    let failure = compile(&value).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|d| d.code == "breg.access.requirements-scope-missing"
            && d.path.contains("another-reader")));
}

#[test]
fn module_extensions_may_add_but_never_replace_requirements() {
    use registry_breg::contract::parse_module_json;
    let mut value = source();
    value["modules"] = json!([{"id":"extra","version":"1"}]);
    let module = parse_module_json(
        &serde_json::to_vec(&json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule", "id":"extra","version":"1","extendRecordTypes":[{
            "recordType":"entry","accessRequirements":{"requiredScopes":["entry:read"]}
        }]}))
        .unwrap(),
    )
    .unwrap();
    let project = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let failure = compile_project(
        &project,
        std::slice::from_ref(&module),
        CompileProfile::Authoring,
    )
    .unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|d| d.code == "breg.extension.access-requirements-replace-forbidden"));
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    let project = parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        compile_project(&project, &[module], CompileProfile::Authoring)
            .unwrap()
            .entities()["entry"]
            .access_requirements
            .is_some()
    );
}

#[test]
fn relationship_grants_cannot_bypass_target_or_join_requirements() {
    let mut value = source();
    value["recordTypes"][0]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    value["accessProfiles"][0]["permissions"]["records"][0]["readPaths"] =
        json!([{"path":"children","readableFields":["code"]}]);
    value["recordTypes"].as_array_mut().unwrap().extend([
        json!({"id":"child","primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]}),
        json!({"id":"link","primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","fields":[{"id":"entry","type":"reference","target":"entry","classification":"internal"},{"id":"child","type":"reference","target":"child","classification":"internal"}]})
    ]);
    let baseline = compile(&value).unwrap();
    let warning = baseline
        .findings()
        .iter()
        .find(|d| {
            d.code == "breg.access.profile-related-disclosure"
                && d.path.contains("readPaths[path=children]")
        })
        .expect("the uncovered related disclosure warns");
    for identifier in ["reader", "child", "entry", "link", "children", "code"] {
        assert!(warning.message.contains(identifier), "{}", warning.message);
    }
    value["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "recordType":"child",
            "operations":["create","patch"],
            "readableFields":["code"],
            "writableFields":["code"],
            "rowBoundaries":"unrestricted"
        }));
    assert!(compile(&value).unwrap().findings().iter().any(|d| {
        d.code == "breg.access.profile-related-disclosure"
            && d.path.contains("readPaths[path=children]")
    }));
    value["accessProfiles"][0]["permissions"]["records"][1]["operations"] = json!(["get"]);
    value["accessProfiles"][0]["permissions"]["records"][1]
        .as_object_mut()
        .unwrap()
        .remove("writableFields");
    assert!(!compile(&value).unwrap().findings().iter().any(|d| {
        d.code == "breg.access.profile-related-disclosure"
            && d.path.contains("readPaths[path=children]")
    }));
    value["accessProfiles"][0]["permissions"]["records"][1]["rowBoundaries"] =
        json!([{"field":"code","claim":"child_code","operator":"equals"}]);
    assert!(compile(&value).unwrap().findings().iter().any(|d| {
        d.code == "breg.access.profile-related-disclosure"
            && d.path.contains("readPaths[path=children]")
    }));
    let explanation = serde_json::to_value(registry_breg::access::explain_access(&baseline))
        .expect("access explanation serializes");
    let entry = explanation["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["recordType"] == "entry")
        .expect("entry access explanation exists");
    let grant = &entry["profiles"][0]["readPaths"][0];
    assert_eq!(grant["targetRecordType"], "child");
    assert_eq!(grant["throughRecordType"], "link");
    assert_eq!(grant["route"], "children");
    assert!(explanation["rowReach"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reach| reach["surface"] == "read_path"
            && reach["recordType"] == "child"
            && reach["profile"] == "reader"
            && reach["sourcePath"]
                == "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children]"));
    for index in [1, 2] {
        value["recordTypes"][index]["accessRequirements"] =
            json!({"requiredScopes":["entry:read"]});
        compile(&value).unwrap();
        value["recordTypes"][index]["accessRequirements"] =
            json!({"requiredScopes":["separate:read"]});
        let failure = compile(&value).unwrap_err();
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|d| d.code == "breg.access.requirements-scope-missing"
                    && d.path.contains("readPaths[path=children]")),
            "{failure:?}"
        );
        value["recordTypes"][index]["accessRequirements"] =
            json!({"rowBoundaries":[{"field":"id","claim":"record_id","operator":"equals"}]});
        assert_refused(
            &value,
            "breg.access.requirements-read-path-row-boundary-unsupported",
        );
        value["recordTypes"][index]
            .as_object_mut()
            .unwrap()
            .remove("accessRequirements");
    }
}

#[test]
fn spatial_query_grants_do_not_satisfy_or_weaken_access_requirements() {
    let mut value = source();
    value["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("fields are an array")
        .push(json!({
            "id":"location",
            "type":"crs84-point",
            "precision":6,
            "classification":"internal"
        }));
    value["recordTypes"][0]["geojson"] = json!({"geometryField":"location"});
    value["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .expect("readable fields are an array")
        .push(json!("location"));
    value["accessProfiles"][0]["permissions"]["records"][0]["spatialQueries"] = json!({
        "bbox": {
            "maximumLongitudeSpanDegrees": 0.25,
            "maximumLatitudeSpanDegrees": 1.5
        }
    });

    compile(&value).unwrap();
    value["accessProfiles"][0]["requiredScopes"] = json!("unrestricted");
    assert_refused(&value, "breg.access.requirements-scope-missing");
}

#[test]
fn footgun_findings_are_actionable_deterministic_and_do_not_change_authority() {
    let mut value = source();
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]["requiredScopes"] = json!("unrestricted");
    value["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!("unrestricted");
    value["accessProfiles"][0]["permissions"]["records"][0]["allowDataExport"] = json!(true);
    let compiled = compile(&value).unwrap();
    for code in [
        "breg.access.profile-unrestricted-collection",
        "breg.access.profile-data-export",
    ] {
        let finding = compiled.findings().iter().find(|d| d.code == code).unwrap();
        assert!(finding.path.contains("entry") && finding.path.contains("reader"));
        assert!(finding.message.len() > 60);
    }
    assert_eq!(compiled.findings(), compile(&value).unwrap().findings());
    assert!(compiled.entities()["entry"].access_profiles["reader"]
        .row_boundaries
        .is_empty());
    let explanation =
        serde_json::to_value(registry_breg::access::explain_access(&compiled)).unwrap();
    assert_eq!(
        explanation["recordTypes"][0]["profiles"][0]["allowDataExport"],
        true
    );
    assert!(explanation["scopeMatching"]
        .as_str()
        .unwrap()
        .contains("all"));
}

#[test]
fn history_sensitive_fields_and_writable_boundaries_are_visible_for_review() {
    let mut value = source();
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredPurposes");
    value["recordTypes"][0]["fields"][0]["classification"] = json!("restricted");
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["get", "list", "patch", "revisions"]);
    grant["revisionAccess"] = json!(true);
    grant["writableFields"] = json!(["district"]);
    let compiled = compile(&value).unwrap();
    for code in [
        "breg.access.profile-higher-classification",
        "breg.access.profile-writable-row-boundary",
        "breg.access.profile-revision-history",
    ] {
        assert!(compiled.findings().iter().any(|d| d.code == code), "{code}");
    }
    let patch_only = compiled
        .findings()
        .iter()
        .find(|d| d.code == "breg.access.profile-writable-row-boundary")
        .unwrap();
    assert!(
        patch_only.message.contains("remove it from writableFields"),
        "{}",
        patch_only.message
    );
    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!([]);
    assert!(!compile(&value)
        .unwrap()
        .findings()
        .iter()
        .any(|d| d.code == "breg.access.profile-writable-row-boundary"));
}

#[test]
fn token_requirements_do_not_clear_a_higher_classification() {
    let mut value = source();
    value["recordTypes"][0]["fields"][0]["classification"] = json!("restricted");

    let compiled = compile(&value).expect("the project compiles with advisory findings");
    let findings = compiled
        .findings()
        .iter()
        .filter(|finding| finding.code == "breg.access.profile-higher-classification")
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1, "{:#?}", compiled.findings());
    assert_eq!(
        findings[0].path,
        "recordTypes[id=entry].accessProfiles[id=reader].readableFields[field=code]"
    );
}

/// A row boundary compiles to an INSERT `WITH CHECK` pinning its field to the
/// caller's claim, so a grant that also creates must keep that field writable.
#[test]
fn create_grants_keep_the_row_boundary_field_writable() {
    let mut value = source();
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["create", "get", "list", "patch"]);
    grant["writableFields"] = json!(["code", "district"]);
    let compiled = compile(&value).unwrap();
    let finding = compiled
        .findings()
        .iter()
        .find(|d| d.code == "breg.access.profile-writable-row-boundary")
        .expect("a patch with a multi-value boundary reports possible moves for review");
    assert!(
        finding.path.contains("entry")
            && finding.path.contains("reader")
            && finding.path.ends_with("writableFields")
    );
    assert!(
        !finding.message.contains("remove it from writableFields"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains("create")
            && finding.message.contains("keep")
            && finding.message.contains("patch"),
        "{}",
        finding.message
    );
    assert!(compiled
        .findings()
        .iter()
        .all(|d| d.code != "breg.access.profile-row-boundary-not-writable"));

    let mut create_only = value.clone();
    create_only["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["create", "get", "list"]);
    let create_only = compile(&create_only).unwrap();
    assert!(create_only
        .findings()
        .iter()
        .all(|d| d.code != "breg.access.profile-writable-row-boundary"));

    let mut equality = value.clone();
    equality["recordTypes"][0]["accessRequirements"]["rowBoundaries"][0]["operator"] =
        json!("equals");
    equality["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"][0]["operator"] =
        json!("equals");
    let equality = compile(&equality).unwrap();
    assert!(equality
        .findings()
        .iter()
        .all(|d| d.code != "breg.access.profile-writable-row-boundary"));
    let profile = &equality.entities()["entry"].access_profiles["reader"];
    assert_eq!(profile.row_boundaries.len(), 1);
    assert_eq!(
        profile.row_boundaries[0].operator,
        registry_breg::contract::BoundaryOperator::Equals
    );
    assert_eq!(profile.row_boundaries[0].field, "district");
    assert_eq!(profile.row_boundaries[0].claim, "districts");

    // Taking the patch-only advice on a create-bearing grant refuses every create.
    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!(["code"]);
    let compiled = compile(&value).unwrap();
    let finding = compiled
        .findings()
        .iter()
        .find(|d| d.code == "breg.access.profile-row-boundary-not-writable")
        .expect("a create that cannot name its boundary field is reported");
    assert!(
        finding.path.contains("entry")
            && finding.path.contains("reader")
            && finding.path.ends_with("writableFields")
    );
    assert!(
        finding.message.contains("district") && finding.message.contains("writableFields"),
        "{}",
        finding.message
    );
    assert!(compiled
        .findings()
        .iter()
        .all(|d| d.code != "breg.access.profile-writable-row-boundary"));
    assert_eq!(compiled.findings(), compile(&value).unwrap().findings());

    // Without `create` the boundary field may stay unwritable.
    value["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["get", "list", "patch"]);
    assert!(compile(&value)
        .unwrap()
        .findings()
        .iter()
        .all(|d| d.code != "breg.access.profile-row-boundary-not-writable"));
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn synthetic_preview_uses_http_admission_and_never_renders_claim_values() {
    let compiled = compile(&source()).unwrap();
    let scenario = json!({"recordType":"entry","accessProfile":"reader","operation":"list","claims":{
        "principalClaim":"registry_principal","principal":"private-principal-canary","scopes":["entry:read"],"purpose":"administration",
        "directClaims":{"districts":["private-district-canary"]}
    }});
    let preview = |value: Value| {
        registry_breg::access_preview::preview_access(
            &compiled,
            serde_json::from_value(value).unwrap(),
        )
        .unwrap()
    };
    let allowed = serde_json::to_value(preview(scenario.clone())).unwrap();
    assert_eq!(allowed["admitted"], true);
    assert_eq!(allowed["recordAccess"], "not-evaluated");
    assert_eq!(allowed["credentialsVerified"], false);
    assert!(!allowed.to_string().contains("canary"));
    for (path, replacement, reason) in [
        ("/claims/scopes", json!([]), "required-scope-missing"),
        (
            "/claims/purpose",
            json!("another-purpose"),
            "purpose-missing-or-not-allowed",
        ),
        (
            "/claims/directClaims",
            json!({}),
            "row-claim-missing-or-wrong-cardinality",
        ),
        ("/operation", json!("patch"), "operation-not-granted"),
        (
            "/claims/principalClaim",
            json!("sub"),
            "principal-missing-or-mismatched",
        ),
    ] {
        let mut value = scenario.clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let refused = preview(value);
        assert!(!refused.admitted);
        assert_eq!(refused.reason, reason);
    }
    let mut wrong_shape = scenario.clone();
    wrong_shape["claims"]["directClaims"]["districts"] = json!("scalar-instead-of-array");
    assert!(registry_breg::access_preview::preview_access(
        &compiled,
        serde_json::from_value(wrong_shape).unwrap()
    )
    .is_err());
    // A value repeated in a multi-valued claim asserts the same authority once,
    // so HTTP admission collapses it and the preview reports the same answer.
    let mut repeated = scenario;
    repeated["claims"]["directClaims"]["districts"] =
        json!(["private-district-canary", "private-district-canary"]);
    let collapsed = serde_json::to_value(preview(repeated)).unwrap();
    assert_eq!(collapsed["admitted"], true);
    assert_eq!(collapsed, allowed);
    assert!(!collapsed.to_string().contains("canary"));
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn access_diffs_show_each_changed_dimension_without_guessing_mixed_authority() {
    let baseline = compile(&source()).unwrap();
    let mut value = source();
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]["requiredScopes"] = json!("unrestricted");
    value["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredPurposes");
    value["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!("unrestricted");
    value["accessProfiles"][0]["permissions"]["records"][0]["allowDataExport"] = json!(true);
    let candidate = compile(&value).unwrap();
    let diff =
        registry_breg::tooling::classify_registry_diff(&baseline, &candidate, "package-under-test");
    let details = diff
        .changes
        .iter()
        .flat_map(|c| &c.access_details)
        .collect::<Vec<_>>();
    for field in [
        "requiredScopes",
        "requiredPurposes",
        "rowBoundaries",
        "allowDataExport",
    ] {
        assert!(
            details.iter().any(|d| d.field == field
                && d.direction == registry_breg::tooling::AccessChangeDirection::Widening),
            "{details:?}"
        );
    }
    assert!(diff.changes.iter().any(|c| c.change.code
        == registry_breg::package::CompiledRegistryChangeCode::EntityAccessRequirementsChanged));

    let narrowing =
        registry_breg::tooling::classify_registry_diff(&candidate, &baseline, "package-under-test");
    for field in [
        "requiredScopes",
        "requiredPurposes",
        "rowBoundaries",
        "allowDataExport",
    ] {
        assert!(narrowing
            .changes
            .iter()
            .flat_map(|c| &c.access_details)
            .any(|d| d.field == field
                && d.direction == registry_breg::tooling::AccessChangeDirection::Narrowing));
    }

    let mut only_requirements = source();
    only_requirements["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    let diff = registry_breg::tooling::classify_registry_diff(
        &baseline,
        &compile(&only_requirements).unwrap(),
        "package-under-test",
    );
    assert_eq!(
        diff.changes.len(),
        1,
        "requirements-only changes must not be lost even when grants are unchanged"
    );
    assert_eq!(
        diff.changes[0].classification,
        registry_breg::tooling::DiffClassification::AccessChange
    );

    let mut reordered = source();
    let binding = json!({"field":"code","claim":"assigned_code","operator":"equals"});
    reordered["recordTypes"][0]["accessRequirements"]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .push(binding.clone());
    reordered["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .push(binding);
    let before = compile(&reordered).unwrap();
    reordered["recordTypes"][0]["accessRequirements"]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let diff = registry_breg::tooling::classify_registry_diff(
        &before,
        &compile(&reordered).unwrap(),
        "package-under-test",
    );
    assert!(
        diff.changes
            .iter()
            .flat_map(|c| &c.access_details)
            .all(|d| d.direction == registry_breg::tooling::AccessChangeDirection::ReviewRequired),
        "reordering predicates is not evidence of widening or narrowing"
    );
}

fn second_reader() -> Value {
    json!({"id":"auditor","principalClaim":"registry_principal","requiredScopes":["entry:read"],
      "requiredPurposes":["administration"],"permissions":{"records":[{"recordType":"entry","operations":["get","list"],
        "readableFields":["code","district"],"filterableFields":["district"],
        "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]}})
}

fn diagnostic_for<'a>(
    failure: &'a registry_breg::CompileFailure,
    code: &str,
    fragment: &str,
) -> &'a registry_breg::Diagnostic {
    failure
        .diagnostics()
        .iter()
        .find(|item| item.code == code && item.message.contains(fragment))
        .unwrap_or_else(|| panic!("{code} naming {fragment} is reported: {failure:?}"))
}

#[test]
fn default_profile_refusals_name_the_entity_the_operation_and_the_profiles() {
    let mut without_default = source();
    without_default["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(second_reader());
    let registry = compile(&without_default).expect("explicit selection needs no default");
    assert!(registry
        .access()
        .entries
        .iter()
        .all(|entry| entry.default_profile_id.is_none()));
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    for route in &registry.routes().routes {
        let parameters = openapi["paths"][&route.path]["get"]["parameters"]
            .as_array()
            .unwrap();
        let selector = parameters
            .iter()
            .find(|parameter| parameter["name"] == "accessProfile")
            .unwrap();
        assert_eq!(selector["required"], true);
    }

    let mut two_defaults = without_default.clone();
    two_defaults["accessProfiles"][0]["default"] = json!(true);
    two_defaults["accessProfiles"][1]["default"] = json!(true);
    let failure = compile(&two_defaults).unwrap_err();
    let diagnostic = diagnostic_for(
        &failure,
        "breg.access-profile.default-invalid",
        "operation `get`",
    );
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=entry].accessProfiles[id=auditor].default"
    );
    assert!(
        diagnostic.message.contains("`reader` already"),
        "{diagnostic:?}"
    );

    let mut one_default = without_default;
    one_default["accessProfiles"][0]["default"] = json!(true);
    compile(&one_default).expect("exactly one default profile per operation compiles");
}

#[test]
fn write_grants_without_writable_fields_are_reported() {
    let mut value = source();
    value["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["get", "list", "create", "patch"]);
    let compiled = compile(&value).unwrap();
    let finding = compiled
        .findings()
        .iter()
        .find(|d| d.code == "breg.access.profile-no-writable-fields")
        .expect("a create or patch grant naming no writable field is reported");
    assert_eq!(
        finding.path,
        "recordTypes[id=entry].accessProfiles[id=reader].writableFields"
    );
    assert!(
        finding.message.contains("`create`") && finding.message.contains("`patch`"),
        "{finding:?}"
    );
    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!(["code"]);
    assert!(!compile(&value)
        .unwrap()
        .findings()
        .iter()
        .any(|d| d.code == "breg.access.profile-no-writable-fields"));
}

#[test]
fn create_grants_report_each_required_field_the_profile_cannot_write() {
    let mut value = source();
    value["recordTypes"][0]["fields"][0]["required"] = json!(true);
    value["recordTypes"][0]["fields"][1]["required"] = json!(true);
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["create", "get", "list", "patch"]);
    grant["writableFields"] = json!([]);

    let compiled = compile(&value).expect("the authoring-compatible mistake remains a finding");
    let findings = compiled
        .findings()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "breg.access.profile-create-required-field-not-writable"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        findings.len(),
        2,
        "one finding is reported per missing field"
    );
    assert_eq!(
        findings
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>(),
        [
            "recordTypes[id=entry].accessProfiles[id=reader].writableFields[field=code]",
            "recordTypes[id=entry].accessProfiles[id=reader].writableFields[field=district]",
        ]
    );
    assert!(findings
        .iter()
        .all(|diagnostic| diagnostic.message.contains("required")));

    let mut production = value.clone();
    production["package"] = json!({"sourceRevision":"test-revision"});
    let production = compile_with_profile(&production, CompileProfile::Production)
        .expect("production compilation reports the same review finding");
    assert_eq!(
        production
            .findings()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "breg.access.profile-create-required-field-not-writable"
            })
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>(),
        findings
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>()
    );

    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] =
        json!(["code", "district"]);
    assert!(compile(&value)
        .unwrap()
        .findings()
        .iter()
        .all(|diagnostic| {
            diagnostic.code != "breg.access.profile-create-required-field-not-writable"
        }));

    value["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["get", "list", "patch"]);
    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!([]);
    assert!(compile(&value)
        .unwrap()
        .findings()
        .iter()
        .all(|diagnostic| {
            diagnostic.code != "breg.access.profile-create-required-field-not-writable"
        }));
}

#[test]
fn import_grants_report_each_required_field_the_profile_cannot_write() {
    let mut value = source();
    value["recordTypes"][0]["fields"][0]["required"] = json!(true);
    value["recordTypes"][0]["fields"][1]["required"] = json!(true);
    value["recordTypes"][0]["batch"] = json!({
        "maximumItems": 100,
        "maximumBytes": 1_048_576
    });
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["import"]);
    grant["writableFields"] = json!([]);

    let compiled = compile(&value).expect("an import-only grant remains authoring-compatible");
    let findings = compiled
        .findings()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "breg.access.profile-create-required-field-not-writable"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        findings
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>(),
        [
            "recordTypes[id=entry].accessProfiles[id=reader].writableFields[field=code]",
            "recordTypes[id=entry].accessProfiles[id=reader].writableFields[field=district]",
        ]
    );
    assert!(findings
        .iter()
        .all(|diagnostic| diagnostic.message.contains("`import`")));

    let mut production = value.clone();
    production["package"] = json!({"sourceRevision":"test-revision"});
    let production = compile_with_profile(&production, CompileProfile::Production)
        .expect("production compilation reports import-only findings");
    assert_eq!(
        production
            .findings()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "breg.access.profile-create-required-field-not-writable"
            })
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>(),
        findings
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>()
    );

    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] =
        json!(["code", "district"]);
    assert!(compile(&value)
        .unwrap()
        .findings()
        .iter()
        .all(|diagnostic| {
            diagnostic.code != "breg.access.profile-create-required-field-not-writable"
        }));

    value["accessProfiles"][0]["permissions"]["records"][0]["operations"] = json!(["get", "list"]);
    value["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!([]);
    assert!(compile(&value)
        .unwrap()
        .findings()
        .iter()
        .all(|diagnostic| {
            diagnostic.code != "breg.access.profile-create-required-field-not-writable"
        }));
}

#[test]
fn unresolved_access_profile_fields_have_one_concrete_path_per_reference() {
    let mut value = source();
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["operations"] = json!(["get", "list", "patch"]);
    grant["readableFields"] = json!(["missing-readable"]);
    grant["filterableFields"] = json!(["missing-filterable"]);
    grant["sortableFields"] = json!(["missing-sortable"]);
    grant["writableFields"] = json!(["missing-writable"]);
    grant["rowBoundaries"] =
        json!([{"field":"missing-boundary","claim":"districts","operator":"in"}]);

    let failure = compile(&value).expect_err("unresolved field references fail compilation");
    let paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.access-profile.field-unknown")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "recordTypes[id=entry].accessProfiles[id=reader].filterableFields[field=missing-filterable]",
            "recordTypes[id=entry].accessProfiles[id=reader].readableFields[field=missing-readable]",
            "recordTypes[id=entry].accessProfiles[id=reader].rowBoundaries[field=missing-boundary]",
            "recordTypes[id=entry].accessProfiles[id=reader].sortableFields[field=missing-sortable]",
            "recordTypes[id=entry].accessProfiles[id=reader].writableFields[field=missing-writable]",
        ]
    );
}

#[test]
fn processing_wider_than_read_names_each_access_profile_field() {
    let mut value = source();
    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0];
    grant["readableFields"] = json!(["code"]);
    grant["filterableFields"] = json!(["district"]);
    grant["sortableFields"] = json!(["district"]);

    let failure = compile(&value).expect_err("processing an unreadable field is refused");
    let paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.access-profile.processing-wider-than-read")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "recordTypes[id=entry].accessProfiles[id=reader].filterableFields[field=district]",
            "recordTypes[id=entry].accessProfiles[id=reader].sortableFields[field=district]",
        ]
    );
}

#[test]
fn unresolved_read_path_fields_have_one_concrete_path_per_reference() {
    let mut value = source();
    value["recordTypes"][0]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    value["accessProfiles"][0]["permissions"]["records"][0]["readPaths"] = json!([{
        "path":"children",
        "readableFields":["missing-readable"],
        "filterableFields":["missing-filterable"],
        "sortableFields":["missing-sortable"]
    }]);
    value["recordTypes"].as_array_mut().unwrap().extend([
        json!({"id":"child","primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]}),
        json!({"id":"link","primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","fields":[{"id":"entry","type":"reference","target":"entry","classification":"internal"},{"id":"child","type":"reference","target":"child","classification":"internal"}]})
    ]);

    let failure = compile(&value).expect_err("unresolved read-path fields fail compilation");
    let paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.access-profile.read-path-field-unknown")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children].filterableFields[field=missing-filterable]",
            "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children].readableFields[field=missing-readable]",
            "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children].sortableFields[field=missing-sortable]",
        ]
    );

    let grant = &mut value["accessProfiles"][0]["permissions"]["records"][0]["readPaths"][0];
    grant["readableFields"] = json!(["id", "code"]);
    grant["filterableFields"] = json!(["code"]);
    grant["sortableFields"] = json!(["code"]);
    compile(&value).expect("known stored and engine-managed read-path fields compile");
}

#[test]
fn read_path_processing_wider_than_read_names_each_target_field() {
    let mut value = source();
    value["recordTypes"][0]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    value["accessProfiles"][0]["permissions"]["records"][0]["readPaths"] = json!([{
        "path":"children",
        "readableFields":["id"],
        "filterableFields":["code"],
        "sortableFields":["code"]
    }]);
    value["recordTypes"].as_array_mut().unwrap().extend([
        json!({"id":"child","primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]}),
        json!({"id":"link","primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","fields":[{"id":"entry","type":"reference","target":"entry","classification":"internal"},{"id":"child","type":"reference","target":"child","classification":"internal"}]})
    ]);

    let failure = compile(&value).expect_err("read-path processing of an unreadable field fails");
    let paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "breg.access-profile.read-path-processing-wider-than-read"
        })
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children].filterableFields[field=code]",
            "recordTypes[id=entry].accessProfiles[id=reader].readPaths[path=children].sortableFields[field=code]",
        ]
    );
}

#[test]
fn unresolved_constraint_fields_name_the_entity_constraint_and_field() {
    let mut value = source();
    value["recordTypes"][0]["constraints"] = json!([
        {"type":"unique","id":"unknowns","fields":["missing-first","missing-second"]},
        {"type":"int-range","id":"range","field":"missing-range","minimum":0},
        {"type":"unique","id":"empty","fields":[]},
        {"type":"temporal-non-overlap","id":"empty-temporal","scopeFields":[]}
    ]);

    let failure = compile(&value).expect_err("unresolved constraint fields fail compilation");
    let diagnostics = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.constraint.field-unknown")
        .collect::<Vec<_>>();
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>(),
        [
            "recordTypes[id=entry].constraints[id=empty-temporal].scopeFields",
            "recordTypes[id=entry].constraints[id=empty].fields",
            "recordTypes[id=entry].constraints[id=range].field[field=missing-range]",
            "recordTypes[id=entry].constraints[id=unknowns].fields[field=missing-first]",
            "recordTypes[id=entry].constraints[id=unknowns].fields[field=missing-second]",
        ]
    );
    assert!(diagnostics[..2]
        .iter()
        .all(|diagnostic| diagnostic.message == "a constraint must name at least one field"));
    assert!(diagnostics[2..]
        .iter()
        .all(|diagnostic| diagnostic.message == "a constraint refers to an unknown field"));
}

#[test]
fn sole_profile_is_implicit_default_and_action_routes_may_require_explicit_selection() {
    let registry = compile(&source()).unwrap();
    assert!(registry
        .access()
        .entries
        .iter()
        .all(|entry| entry.default_profile_id.as_deref() == Some("reader")));
    let mut project =
        registry_breg::parse_project_yaml(include_bytes!("fixtures/action-authority-mapping.yaml"))
            .unwrap();
    for profile in &mut project.access_profiles {
        profile.default = false;
    }
    let registry = compile_project(&project, &[], CompileProfile::Authoring).unwrap();
    assert!(!registry.actions().routes.is_empty());
    assert!(registry
        .actions()
        .routes
        .iter()
        .all(|route| route.default_access_profile.is_none()));
    for profile in &mut project.access_profiles {
        profile.default = true;
    }
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.route-access-default-multiple"));
}

/// A profile with no row or membership boundary, listing a non-public record type.
fn unbounded_listing_source() -> Value {
    let mut value = source();
    value["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!("unrestricted");
    value
}

fn finding_codes(value: &Value) -> Vec<String> {
    compile(value)
        .unwrap()
        .findings()
        .iter()
        .map(|d| d.code.to_string())
        .collect()
}

#[test]
fn a_profile_requiring_scopes_and_purposes_may_read_whole_collections_without_a_warning() {
    let mut value = unbounded_listing_source();
    assert_eq!(
        value["accessProfiles"][0]["permissions"]["records"][0]["operations"],
        json!(["get", "list"])
    );
    let codes = finding_codes(&value);
    for code in [
        "breg.access.profile-unrestricted-collection",
        "breg.access.profile-unrestricted-rows",
    ] {
        assert!(!codes.iter().any(|c| c == code), "{code}: {codes:?}");
    }

    value["accessProfiles"][0]["permissions"]["records"][0]["operations"] = json!(["get"]);
    let codes = finding_codes(&value);
    assert!(
        !codes
            .iter()
            .any(|c| c == "breg.access.profile-unrestricted-rows"),
        "{codes:?}"
    );
}

#[test]
fn a_profile_missing_scopes_or_purposes_is_reported_as_unrestricted() {
    let mut without_purposes = unbounded_listing_source();
    without_purposes["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredPurposes");
    let codes = finding_codes(&without_purposes);
    assert!(
        codes
            .iter()
            .any(|c| c == "breg.access.profile-unrestricted-collection"),
        "{codes:?}"
    );

    let mut without_scopes = unbounded_listing_source();
    without_scopes["accessProfiles"][0]["requiredScopes"] = json!("unrestricted");
    let codes = finding_codes(&without_scopes);
    assert!(
        codes
            .iter()
            .any(|c| c == "breg.access.profile-unrestricted-collection"),
        "{codes:?}"
    );

    let mut rows_without_purposes = unbounded_listing_source();
    rows_without_purposes["accessProfiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredPurposes");
    rows_without_purposes["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["get"]);
    let codes = finding_codes(&rows_without_purposes);
    assert!(
        codes
            .iter()
            .any(|c| c == "breg.access.profile-unrestricted-rows"),
        "{codes:?}"
    );
}
