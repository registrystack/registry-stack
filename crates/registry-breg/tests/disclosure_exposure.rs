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

fn compiled() -> CompiledRegistry {
    let source = json!({"datasets":[{"id": "test-dataset"}],
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
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .expect("the project compiles")
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
