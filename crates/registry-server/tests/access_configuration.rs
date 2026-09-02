// SPDX-License-Identifier: Apache-2.0

use registry_server::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

fn source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"access-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access-example.example.test"},
        "entities":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"},
                    {"id":"district","type":"string","maxLength":32,"classification":"internal"}],
          "accessRequirements":{"requiredScopes":["entry:read"],"allowedPurposes":["administration"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}}],
        "accessProfiles":[{"id":"reader","principalClaim":"registry_principal","requiredScopes":["entry:read"],
          "requiredPurposes":["administration"],"grants":[{"entity":"entry","operations":["get","list"],
            "readableFields":["code","district"],"filterableFields":["district"],
            "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]}]
    })
}

fn compile(value: &Value) -> Result<CompiledRegistry, registry_server::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
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
            json!([]),
            "access.requirements.scope_missing",
        ),
        (
            "/accessProfiles/0/requiredPurposes",
            json!([]),
            "access.requirements.purpose_widened",
        ),
        (
            "/accessProfiles/0/requiredPurposes",
            json!(["other"]),
            "access.requirements.purpose_widened",
        ),
        (
            "/accessProfiles/0/grants/0/rowBoundaries",
            json!([]),
            "access.requirements.row_boundary_missing",
        ),
        (
            "/accessProfiles/0/grants/0/rowBoundaries/0/claim",
            json!("caller_district"),
            "access.requirements.row_boundary_missing",
        ),
        (
            "/accessProfiles/0/grants/0/rowBoundaries/0/operator",
            json!("equals"),
            "access.requirements.row_boundary_missing",
        ),
    ];
    for (path, replacement, code) in mutations {
        let mut value = source();
        *value.pointer_mut(path).unwrap() = replacement;
        assert_refused(&value, code);
    }
    let mut stricter = source();
    stricter["entities"][0]["accessRequirements"]["allowedPurposes"] =
        json!(["administration", "review"]);
    stricter["accessProfiles"][0]["requiredScopes"] = json!(["entry:read", "entry:review"]);
    stricter["accessProfiles"][0]["grants"][0]["rowBoundaries"]
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
fn requirements_validate_even_without_profiles_and_reject_anonymous_access() {
    for (requirements, code) in [
        (json!({}), "access.requirements.empty"),
        (
            json!({"requiredScopes":[""]}),
            "access.requirements.empty_value",
        ),
        (
            json!({"rowBoundaries":[{"field":"unknown","claim":"district","operator":"equals"}]}),
            "access.requirements.row_boundary.invalid",
        ),
    ] {
        let mut value = source();
        value["entities"][0]["accessRequirements"] = requirements;
        value["accessProfiles"] = json!([]);
        assert_refused(&value, code);
    }
    let mut value = source();
    value["accessProfiles"][0]["anonymous"] = json!(true);
    assert_refused(&value, "access.requirements.authentication");
}

#[test]
fn additional_profile_cannot_omit_entity_requirements() {
    let mut value = source();
    let mut additional = value["accessProfiles"][0].clone();
    additional["id"] = json!("another-reader");
    additional["requiredScopes"] = json!([]);
    value["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(additional);
    let failure = compile(&value).unwrap_err();
    assert!(failure.diagnostics().iter().any(
        |d| d.code == "access.requirements.scope_missing" && d.path.contains("another-reader")
    ));
}

#[test]
fn module_extensions_may_add_but_never_replace_requirements() {
    use registry_server::contract::parse_module_json;
    let mut value = source();
    value["modules"] = json!([{"id":"extra","version":"1"}]);
    let module = parse_module_json(
        &serde_json::to_vec(&json!({"id":"extra","version":"1","extendEntities":[{
            "entity":"entry","accessRequirements":{"requiredScopes":["entry:read"]}
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
        .any(|d| d.code == "extension.access_requirements.replace_forbidden"));
    value["entities"][0]
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
    value["entities"][0]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    value["accessProfiles"][0]["grants"][0]["readPaths"] =
        json!([{"path":"children","readableFields":["code"]}]);
    value["entities"].as_array_mut().unwrap().extend([
        json!({"id":"child","primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}]}),
        json!({"id":"link","primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","fields":[{"id":"entry","type":"reference","target":"entry","classification":"internal"},{"id":"child","type":"reference","target":"child","classification":"internal"}]})
    ]);
    let baseline = compile(&value).unwrap();
    assert!(baseline
        .findings()
        .iter()
        .any(|d| d.code == "access.profile.related_disclosure"
            && d.path.contains("readPaths[path=children]")));
    for index in [1, 2] {
        value["entities"][index]["accessRequirements"] = json!({"requiredScopes":["entry:read"]});
        compile(&value).unwrap();
        value["entities"][index]["accessRequirements"] =
            json!({"requiredScopes":["separate:read"]});
        let failure = compile(&value).unwrap_err();
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|d| d.code == "access.requirements.scope_missing"
                    && d.path.contains("readPaths[path=children]")),
            "{failure:?}"
        );
        value["entities"][index]["accessRequirements"] =
            json!({"rowBoundaries":[{"field":"id","claim":"record_id","operator":"equals"}]});
        assert_refused(
            &value,
            "access.requirements.read_path.row_boundary_unsupported",
        );
        value["entities"][index]
            .as_object_mut()
            .unwrap()
            .remove("accessRequirements");
    }
}

#[test]
fn spatial_query_grants_do_not_satisfy_or_weaken_access_requirements() {
    let mut value = source();
    value["entities"][0]["fields"]
        .as_array_mut()
        .expect("fields are an array")
        .push(json!({
            "id":"location",
            "type":"crs84-point",
            "precision":6,
            "classification":"internal"
        }));
    value["entities"][0]["geojson"] = json!({"geometryField":"location"});
    value["accessProfiles"][0]["grants"][0]["readableFields"]
        .as_array_mut()
        .expect("readable fields are an array")
        .push(json!("location"));
    value["accessProfiles"][0]["grants"][0]["spatialQueries"] = json!({
        "bbox": {
            "maximumLongitudeSpanDegrees": 0.25,
            "maximumLatitudeSpanDegrees": 1.5
        }
    });

    compile(&value).unwrap();
    value["accessProfiles"][0]["requiredScopes"] = json!([]);
    assert_refused(&value, "access.requirements.scope_missing");
}

#[test]
fn footgun_findings_are_actionable_deterministic_and_do_not_change_authority() {
    let mut value = source();
    value["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]["requiredScopes"] = json!([]);
    value["accessProfiles"][0]["grants"][0]["rowBoundaries"] = json!([]);
    value["accessProfiles"][0]["grants"][0]["allowDataExport"] = json!(true);
    let compiled = compile(&value).unwrap();
    for code in [
        "access.profile.no_required_scope",
        "access.profile.unrestricted_collection",
        "access.profile.data_export",
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
        serde_json::to_value(registry_server::access::explain_access(&compiled)).unwrap();
    assert_eq!(
        explanation["entities"][0]["profiles"][0]["allowDataExport"],
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
    value["entities"][0]["fields"][0]["classification"] = json!("restricted");
    let grant = &mut value["accessProfiles"][0]["grants"][0];
    grant["operations"] = json!(["get", "list", "patch", "revisions"]);
    grant["revisionAccess"] = json!(true);
    grant["writableFields"] = json!(["district"]);
    let compiled = compile(&value).unwrap();
    for code in [
        "access.profile.higher_classification",
        "access.profile.writable_row_boundary",
        "access.profile.revision_history",
    ] {
        assert!(compiled.findings().iter().any(|d| d.code == code), "{code}");
    }
    value["accessProfiles"][0]["grants"][0]["writableFields"] = json!([]);
    assert!(!compile(&value)
        .unwrap()
        .findings()
        .iter()
        .any(|d| d.code == "access.profile.writable_row_boundary"));
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[test]
fn synthetic_preview_uses_http_admission_and_never_renders_claim_values() {
    let compiled = compile(&source()).unwrap();
    let scenario = json!({"entity":"entry","accessProfile":"reader","operation":"list","claims":{
        "principalClaim":"registry_principal","principal":"private-principal-canary","scopes":["entry:read"],"purpose":"administration",
        "directClaims":{"districts":["private-district-canary"]}
    }});
    let preview = |value: Value| {
        registry_server::access_preview::preview_access(
            &compiled,
            serde_json::from_value(value).unwrap(),
        )
        .unwrap()
    };
    let allowed = serde_json::to_value(preview(scenario.clone())).unwrap();
    assert_eq!(allowed["admitted"], true);
    assert_eq!(allowed["recordAccess"], "not_evaluated");
    assert_eq!(allowed["credentialsVerified"], false);
    assert!(!allowed.to_string().contains("canary"));
    for (path, replacement, reason) in [
        ("/claims/scopes", json!([]), "required_scope_missing"),
        (
            "/claims/purpose",
            json!("another-purpose"),
            "purpose_missing_or_not_allowed",
        ),
        (
            "/claims/directClaims",
            json!({}),
            "row_claim_missing_or_wrong_cardinality",
        ),
        ("/operation", json!("patch"), "operation_not_granted"),
        (
            "/claims/principalClaim",
            json!("sub"),
            "principal_missing_or_mismatched",
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
    assert!(registry_server::access_preview::preview_access(
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
    value["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    value["accessProfiles"][0]["requiredScopes"] = json!([]);
    value["accessProfiles"][0]["requiredPurposes"] = json!([]);
    value["accessProfiles"][0]["grants"][0]["rowBoundaries"] = json!([]);
    value["accessProfiles"][0]["grants"][0]["allowDataExport"] = json!(true);
    let candidate = compile(&value).unwrap();
    let diff = registry_server::tooling::classify_registry_diff(
        &baseline,
        &candidate,
        "package-under-test",
    );
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
                && d.direction == registry_server::tooling::AccessChangeDirection::Widening),
            "{details:?}"
        );
    }
    assert!(diff.changes.iter().any(|c| c.change.code
        == registry_server::package::CompiledRegistryChangeCode::EntityAccessRequirementsChanged));

    let narrowing = registry_server::tooling::classify_registry_diff(
        &candidate,
        &baseline,
        "package-under-test",
    );
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
                && d.direction == registry_server::tooling::AccessChangeDirection::Narrowing));
    }

    let mut only_requirements = source();
    only_requirements["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    let diff = registry_server::tooling::classify_registry_diff(
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
        registry_server::tooling::DiffClassification::AccessChange
    );

    let mut reordered = source();
    let binding = json!({"field":"code","claim":"assigned_code","operator":"equals"});
    reordered["entities"][0]["accessRequirements"]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .push(binding.clone());
    reordered["accessProfiles"][0]["grants"][0]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .push(binding);
    let before = compile(&reordered).unwrap();
    reordered["entities"][0]["accessRequirements"]["rowBoundaries"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let diff = registry_server::tooling::classify_registry_diff(
        &before,
        &compile(&reordered).unwrap(),
        "package-under-test",
    );
    assert!(diff.changes.iter().flat_map(|c| &c.access_details).all(|d|
        d.direction == registry_server::tooling::AccessChangeDirection::ReviewRequired),
        "reordering predicates is not evidence of widening or narrowing");
}

fn second_reader() -> Value {
    json!({"id":"auditor","principalClaim":"registry_principal","requiredScopes":["entry:read"],
      "requiredPurposes":["administration"],"grants":[{"entity":"entry","operations":["get","list"],
        "readableFields":["code","district"],"filterableFields":["district"],
        "rowBoundaries":[{"field":"district","claim":"districts","operator":"in"}]}]})
}

fn diagnostic_for<'a>(
    failure: &'a registry_server::CompileFailure,
    code: &str,
    fragment: &str,
) -> &'a registry_server::Diagnostic {
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
    let failure = compile(&without_default).unwrap_err();
    let diagnostic = diagnostic_for(
        &failure,
        "access_profile.default.invalid",
        "operation `get`",
    );
    assert_eq!(
        diagnostic.path,
        "entities[id=entry].accessProfiles[].default"
    );
    assert!(
        diagnostic.message.contains("entity `entry`"),
        "{diagnostic:?}"
    );
    assert!(diagnostic.message.contains("`reader`"), "{diagnostic:?}");
    assert!(diagnostic.message.contains("`auditor`"), "{diagnostic:?}");

    let mut two_defaults = without_default.clone();
    two_defaults["accessProfiles"][0]["default"] = json!(true);
    two_defaults["accessProfiles"][1]["default"] = json!(true);
    let failure = compile(&two_defaults).unwrap_err();
    let diagnostic = diagnostic_for(
        &failure,
        "access_profile.default.invalid",
        "operation `get`",
    );
    assert_eq!(
        diagnostic.path,
        "entities[id=entry].accessProfiles[id=auditor].default"
    );
    assert!(
        diagnostic.message.contains("`reader` already"),
        "{diagnostic:?}"
    );

    let mut one_default = without_default;
    one_default["accessProfiles"][0]["default"] = json!(true);
    compile(&one_default).expect("exactly one default profile per operation compiles");
}

fn anonymous_source() -> Value {
    json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"public-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://public-example.example.test"},
        "entities":[{"id":"place","primaryDataset":"test-dataset","route":"places","mutationMode":"mutable",
          "fields":[{"id":"code","type":"string","maxLength":32,"classification":"public"},
                    {"id":"note","type":"string","maxLength":32,"classification":"internal"}]}],
        "accessProfiles":[{"id":"public-map","default":true,"anonymous":true,
          "grants":[{"entity":"place","operations":["list"],"readableFields":["code"]}]}]
    })
}

#[test]
fn anonymous_processing_refusals_name_the_entity_or_field_that_is_not_public() {
    let failure = compile(&anonymous_source()).unwrap_err();
    let diagnostic = diagnostic_for(
        &failure,
        "access_profile.public.processing_non_public",
        "entity `place`",
    );
    assert!(
        diagnostic.message.contains("classified `internal`"),
        "{diagnostic:?}"
    );
    assert!(
        diagnostic.message.contains("`public-map`"),
        "{diagnostic:?}"
    );

    let mut public_entity = anonymous_source();
    public_entity["entities"][0]["classification"] = json!("public");
    compile(&public_entity).expect("a public entity with public readable fields compiles");

    let mut hidden_field = public_entity;
    hidden_field["accessProfiles"][0]["grants"][0]["readableFields"] = json!(["code", "note"]);
    let failure = compile(&hidden_field).unwrap_err();
    let diagnostic = diagnostic_for(
        &failure,
        "access_profile.public.processing_non_public",
        "field `note`",
    );
    assert!(
        diagnostic.message.contains("classified `internal`"),
        "{diagnostic:?}"
    );
    assert!(!diagnostic.message.contains("`code`"), "{diagnostic:?}");
}

#[test]
fn write_grants_without_writable_fields_and_anonymous_collections_are_reported() {
    let mut value = source();
    value["accessProfiles"][0]["grants"][0]["operations"] =
        json!(["get", "list", "create", "patch"]);
    let compiled = compile(&value).unwrap();
    let finding = compiled
        .findings()
        .iter()
        .find(|d| d.code == "access.profile.no_writable_fields")
        .expect("a create or patch grant naming no writable field is reported");
    assert_eq!(
        finding.path,
        "entities[id=entry].accessProfiles[id=reader].writableFields"
    );
    assert!(
        finding.message.contains("`create`") && finding.message.contains("`patch`"),
        "{finding:?}"
    );
    value["accessProfiles"][0]["grants"][0]["writableFields"] = json!(["code"]);
    assert!(!compile(&value)
        .unwrap()
        .findings()
        .iter()
        .any(|d| d.code == "access.profile.no_writable_fields"));

    let mut public = anonymous_source();
    public["entities"][0]["classification"] = json!("public");
    let compiled = compile(&public).unwrap();
    let finding = compiled
        .findings()
        .iter()
        .find(|d| d.code == "access.profile.anonymous_collection")
        .expect("an anonymous list grant is reported");
    assert_eq!(
        finding.path,
        "entities[id=place].accessProfiles[id=public-map].operations"
    );
    assert!(finding.message.contains("`list`"), "{finding:?}");
    assert!(
        !compiled
            .findings()
            .iter()
            .any(|d| d.code == "access.profile.unrestricted_collection"),
        "a public entity keeps the authenticated-only collection finding out of the report"
    );
    public["accessProfiles"][0]["grants"][0]["operations"] = json!(["get"]);
    assert!(!compile(&public)
        .unwrap()
        .findings()
        .iter()
        .any(|d| d.code == "access.profile.anonymous_collection"));
}
