// SPDX-License-Identifier: Apache-2.0

//! How disclosure conditions show in author inspection, the offline access
//! preview and the ODRL export. None of them carries a `when` literal to a
//! caller, but the author surfaces list the conditions in full.

use registry_breg::access::explain_access;
use registry_breg::access_preview::{preview_access, AccessScenario};
use registry_breg::artifacts::inspect_registry;
use registry_breg::odrl_export::export_odrl;
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

fn source() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"exposure","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://exposure.example.test"},
        "recordTypes":[{"id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"family-name","type":"string","maximumLength":64,"classification":"internal"},
                    {"id":"protected","type":"boolean","classification":"internal"},
                    {"id":"phone","type":"string","maximumLength":32,"classification":"internal"}],
          "disclosureConditions":[
            {"id":"hide-protected","when":[{"type":"field-equals","field":"protected","value":true}],
             "withhold":"record","exemptProfiles":["officer"]},
            {"id":"hide-phone","when":[{"type":"field-equals","field":"protected","value":true}],
             "withhold":"fields","fields":["phone"],"exemptProfiles":["officer"]}]}],
        "accessProfiles":[
          {"id":"reader","default":true,"principalClaim":"registry_principal","requiredScopes":["registry.read"],
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected"]}]}},
          {"id":"officer","principalClaim":"registry_principal","requiredScopes":["registry.officer"],
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected","phone"]}]}}]
    })
}

fn compile(source: &Value) -> CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .expect("the project compiles")
}

fn compiled() -> CompiledRegistry {
    compile(&source())
}

fn person(explanation: &Value) -> &Value {
    &explanation["recordTypes"][0]
}

#[test]
fn author_inspection_lists_the_conditions_in_full() {
    let registry = compiled();
    let expected = json!([
        {"id":"hide-protected","when":[{"type":"field-equals","field":"protected","value":true}],
         "withhold":"record","exemptProfiles":["officer"]},
        {"id":"hide-phone","when":[{"type":"field-equals","field":"protected","value":true}],
         "withhold":{"fields":["phone"]},"exemptProfiles":["officer"]}]);
    let access = serde_json::to_value(explain_access(&registry)).unwrap();
    assert_eq!(person(&access)["disclosureConditions"], expected);
    assert_eq!(
        person(&inspect_registry(&registry))["disclosureConditions"],
        expected
    );
}

fn scenario(profile: &str) -> AccessScenario {
    serde_json::from_value(
        json!({"recordType":"person","accessProfile":profile,"operation":"get",
        "claims":{"principalClaim":"registry_principal","principal":"someone",
                  "scopes":["registry.read","registry.officer"]}}),
    )
    .unwrap()
}

#[test]
fn the_access_preview_names_the_conditions_that_bind_the_profile() {
    let registry = compiled();
    let bound =
        serde_json::to_value(preview_access(&registry, scenario("reader")).unwrap()).unwrap();
    assert_eq!(
        bound["disclosureConditions"],
        json!(["hide-protected", "hide-phone"])
    );
    let exempt =
        serde_json::to_value(preview_access(&registry, scenario("officer")).unwrap()).unwrap();
    assert!(
        exempt.get("disclosureConditions").is_none(),
        "an exempt profile has no conditions to name: {exempt}"
    );
    assert!(
        !bound.to_string().contains("\"value\":true"),
        "the preview carries no `when` literal: {bound}"
    );
}

#[test]
fn the_odrl_export_omits_a_grant_a_condition_binds() {
    let export = export_odrl(&compiled(), None).unwrap();
    let reasons = |profile: &str| {
        let grant = export.coverage["grants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|grant| grant["accessProfile"] == profile && grant["operation"] == "get")
            .unwrap();
        (grant["status"].clone(), grant["reasons"].clone())
    };
    assert_eq!(
        reasons("reader"),
        (json!("omitted"), json!(["disclosure-condition"]))
    );
    assert_eq!(reasons("officer"), (json!("exported"), json!([])));
}

/// The fixture with a `registrar` that may create, patch and batch `person`
/// under no row boundary. `bound_by` names the one condition that binds it.
fn writable(bound_by: Option<&str>) -> Value {
    let mut value = source();
    value["recordTypes"][0]["batch"] = json!({"maximumItems": 4, "maximumBytes": 8192});
    for condition in value["recordTypes"][0]["disclosureConditions"]
        .as_array_mut()
        .unwrap()
    {
        if Some(condition["id"].as_str().unwrap()) != bound_by {
            condition["exemptProfiles"] = json!(["officer", "registrar"]);
        }
    }
    value["accessProfiles"].as_array_mut().unwrap().push(json!(
        {"id":"registrar","principalClaim":"registry_principal","requiredScopes":["registry.registrar"],
         "permissions":{"records":[{"recordType":"person","operations":["create","get","list","patch","batch"],
           "rowBoundaries":"unrestricted","readableFields":["family-name","protected","phone"],
           "writableFields":["family-name","protected","phone"],"sortableFields":["family-name"]}]}}
    ));
    value
}

/// Whether the generated OpenAPI declares the `write.outside-boundary` 403 on
/// the person create, patch and batch operations, in that order.
fn declared_write_refusals(registry: &CompiledRegistry) -> [bool; 3] {
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .unwrap();
    let declares = |path: &str, method: &str| {
        let refusal = &openapi["paths"][path][method]["responses"]["403"];
        assert!(
            !openapi["paths"][path][method].is_null(),
            "the fixture has no {method} {path}"
        );
        !refusal.is_null()
            && refusal["content"]["application/problem+json"]["examples"]
                .get("write.outside-boundary")
                .is_some()
    };
    [
        declares("/v1/records/people", "post"),
        declares("/v1/records/people/{record_id}", "patch"),
        declares("/v1/records/people:batch", "post"),
    ]
}

/// A bound writer's Patch or Batch item is refused when it would lift a mark
/// or overwrite a withheld field, and its Create is refused when the result is
/// a record a `record` condition withholds from it. An exempt writer meets
/// neither refusal, even when a read-only profile is bound.
#[test]
fn the_openapi_declares_the_write_refusal_a_binding_condition_can_give() {
    assert_eq!(
        declared_write_refusals(&compile(&writable(Some("hide-phone")))),
        [false, true, true]
    );
    assert_eq!(
        declared_write_refusals(&compile(&writable(Some("hide-protected")))),
        [true, true, true]
    );
    assert_eq!(
        declared_write_refusals(&compile(&writable(None))),
        [false, false, false]
    );
}

/// The writable fixture, where the `registrar` also sets the phone number
/// through the immediate Action `set-person-phone` and applies the manual
/// Proposal `propose-person-phone`. Both plans patch `person`.
fn acting(bound_by: Option<&str>) -> Value {
    let mut value = writable(bound_by);
    let inputs = json!([
        {"id": "person", "apiName": "personId", "type": "reference", "target": "person",
         "required": true, "classification": "internal"},
        {"id": "phone", "apiName": "phone", "type": "string", "maximumLength": 32,
         "required": true, "classification": "internal"}]);
    let plan = json!({"type": "fixed", "effects": [
        {"id": "contact", "target": {"fromInput": "person"}, "operation": "patch",
         "set": {"phone": {"fromInput": "phone"}}}]});
    value["actions"] = json!([
        {"id": "set-person-phone", "inputs": inputs, "plan": plan,
         "execution": {"mode": "immediate"}},
        {"id": "propose-person-phone", "inputs": inputs, "plan": plan,
         "commitGuards": {"targets": [{"input": "person", "revision": "unchanged"}]},
         "execution": {"mode": "proposal", "proposal": {"review": {"type": "none"},
           "application": {"mode": "manual"}, "retention": {"mode": "operator-erase"}}}}]);
    let targets = json!([{"recordType": "person", "rowBoundaries": "unrestricted"}]);
    let registrar = value["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "registrar")
        .unwrap();
    registrar["permissions"]["actions"] = json!([
        {"action": "set-person-phone", "operations": ["invoke"], "targets": targets},
        {"action": "propose-person-phone", "operations": ["start"], "targets": targets}]);
    registrar["permissions"]["proposals"] = json!([
        {"action": "propose-person-phone", "ownership": "caller",
         "operations": ["get", "list", "edit", "submit", "cancel", "apply"], "targets": targets}]);
    value
}

/// Whether the generated OpenAPI declares the `write.outside-boundary` 403 on
/// the Action invoke and on the Proposal apply, in that order.
fn declared_workflow_write_refusals(registry: &CompiledRegistry) -> [bool; 2] {
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .unwrap();
    let invoke = &openapi["paths"]["/v1/actions/set-person-phone"]["post"];
    let apply = &openapi["paths"]["/v1/proposals/{proposal_id}/apply"]["post"];
    assert!(!invoke.is_null(), "the fixture has no Action invoke");
    assert!(!apply.is_null(), "the fixture has no Proposal apply");
    [
        invoke["responses"]["403"]["content"]["application/problem+json"]["examples"]
            .get("write.outside-boundary")
            .is_some(),
        apply["responses"]["403"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("`write.outside-boundary`")),
    ]
}

/// A plan Patch by a profile a `fields` or `history` condition binds is
/// refused when it would lift a mark or overwrite a withheld field. A
/// `record` condition hides the row instead, and an exempt writer meets no
/// refusal.
#[test]
fn the_openapi_declares_the_write_refusal_on_an_action_invoke_and_a_proposal_apply() {
    assert_eq!(
        declared_workflow_write_refusals(&compile(&acting(Some("hide-phone")))),
        [true, true]
    );
    assert_eq!(
        declared_workflow_write_refusals(&compile(&acting(Some("hide-protected")))),
        [false, false]
    );
    assert_eq!(
        declared_workflow_write_refusals(&compile(&acting(None))),
        [false, false]
    );
}
