// SPDX-License-Identifier: Apache-2.0

//! Compile-time rules for `disclosureConditions`, `requireAccessReason` and
//! the read-trigger hook.

use registry_breg::model::DisclosureWithhold;
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

fn source() -> Value {
    json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"disclosure","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://disclosure.example.test"},
        "recordTypes":[{"id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"family-name","type":"string","maximumLength":64,"classification":"internal"},
                    {"id":"protected","type":"boolean","classification":"internal"},
                    {"id":"district","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"age","type":"int64","classification":"internal"},
                    {"id":"phone","type":"string","maximumLength":32,"classification":"internal"}],
          "disclosureConditions":[
            {"id":"hide-protected","when":[{"type":"field-equals","field":"protected","value":true}],
             "withhold":"record","exemptProfiles":["protection-officer"]},
            {"id":"hide-phone","when":[{"type":"field-is-not-null","field":"protected"},
                                      {"type":"field-in","field":"district","values":["north","south"]}],
             "withhold":"fields","fields":["phone"],"exemptProfiles":["protection-officer"]}],
          "hooks":[{"id":"person-read","phase":"after","trigger":"read","profiles":["registrar"],"projection":[]}]}],
        "accessProfiles":[
          {"id":"registrar","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","requireAccessReason":true,
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected","district","age","phone"],
             "filterableFields":["family-name","district"]}]}},
          {"id":"protection-officer","principalClaim":"registry_principal","requiredScopes":"unrestricted",
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected","district","age","phone"],
             "filterableFields":["family-name","phone"]}]}}]
    })
}

fn compile(value: &Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
}

fn refusal(value: &Value) -> Vec<(String, String)> {
    compile(value)
        .expect_err("the project is refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

fn conditions(value: &mut Value) -> &mut Vec<Value> {
    value["recordTypes"][0]["disclosureConditions"]
        .as_array_mut()
        .unwrap()
}

fn assert_refused(value: &Value, code: &str, path: &str) {
    let found = refusal(value);
    assert!(
        found.contains(&(code.to_owned(), path.to_owned())),
        "expected {code} at {path}, got {found:?}"
    );
}

const COND: &str = "recordTypes[id=person].disclosureConditions[id=hide-protected]";
const FIELDS_COND: &str = "recordTypes[id=person].disclosureConditions[id=hide-phone]";

#[test]
fn a_starter_shaped_configuration_compiles() {
    let registry = compile(&source()).expect("valid conditions compile");
    let person = &registry.entities()["person"];
    assert_eq!(person.disclosure_conditions.len(), 2);
    assert_eq!(person.disclosure_conditions[0].id, "hide-protected");
    assert_eq!(
        person.disclosure_conditions[0].withhold,
        DisclosureWithhold::Record
    );
    assert_eq!(
        person.disclosure_conditions[1].withhold,
        DisclosureWithhold::Fields(["phone".to_owned()].into())
    );
    assert!(person.access_profiles["registrar"].require_access_reason);
    assert!(!person.access_profiles["protection-officer"].require_access_reason);
    assert_eq!(person.hooks["person-read"].profiles.len(), 1);
}

#[test]
fn a_project_without_conditions_compiles_to_none() {
    let mut value = source();
    let person = value["recordTypes"][0].as_object_mut().unwrap();
    person.remove("disclosureConditions");
    person.remove("hooks");
    let registry = compile(&value).expect("compiles");
    assert!(registry.entities()["person"]
        .disclosure_conditions
        .is_empty());
}

#[test]
fn a_duplicate_id_is_refused() {
    let mut value = source();
    let copy = conditions(&mut value)[0].clone();
    conditions(&mut value).push(copy);
    assert_refused(
        &value,
        "breg.disclosure.id-duplicate",
        &format!("{COND}.id"),
    );
}

#[test]
fn more_than_eight_conditions_are_refused() {
    let mut value = source();
    let template = conditions(&mut value)[0].clone();
    for index in 0..8 {
        let mut copy = template.clone();
        copy["id"] = json!(format!("extra-{index}"));
        conditions(&mut value).push(copy);
    }
    assert_refused(
        &value,
        "breg.disclosure.too-many",
        "recordTypes[id=person].disclosureConditions",
    );
}

#[test]
fn an_unusable_when_field_is_refused() {
    for field in ["no-such-field", "family-name-derived"] {
        let mut value = source();
        conditions(&mut value)[0]["when"][0]["field"] = json!(field);
        assert_refused(
            &value,
            "breg.disclosure.when-field-invalid",
            &format!("{COND}.when[0].field"),
        );
    }
    let mut encrypted = source();
    encrypted["recordTypes"][0]["fields"][4]["encrypted"] = json!(true);
    encrypted["recordTypes"][0]["fields"][4]["classification"] = json!("restricted");
    conditions(&mut encrypted)[0]["when"][0] = json!({"type":"field-is-null","field":"phone"});
    assert_refused(
        &encrypted,
        "breg.disclosure.when-field-invalid",
        &format!("{COND}.when[0].field"),
    );
}

#[test]
fn an_unusable_when_value_is_refused() {
    let path = format!("{COND}.when[0]");
    let mut wrong_type = source();
    conditions(&mut wrong_type)[0]["when"][0]["value"] = json!("yes");
    assert_refused(&wrong_type, "breg.disclosure.when-value-invalid", &path);
    let mut empty_in = source();
    conditions(&mut empty_in)[0]["when"][0] =
        json!({"type":"field-in","field":"district","values":[]});
    assert_refused(
        &empty_in,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when[0].values"),
    );
    let mut wide_in = source();
    let values: Vec<String> = (0..33).map(|n| format!("d{n}")).collect();
    conditions(&mut wide_in)[0]["when"][0] =
        json!({"type":"field-in","field":"district","values":values});
    assert_refused(
        &wide_in,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when[0].values"),
    );
    let mut empty_when = source();
    conditions(&mut empty_when)[0]["when"] = json!([]);
    assert_refused(
        &empty_when,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when"),
    );
    let mut five = source();
    conditions(&mut five)[0]["when"] = json!((0..5)
        .map(|_| json!({"type":"field-is-not-null","field":"age"}))
        .collect::<Vec<_>>());
    assert_refused(
        &five,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when"),
    );
}

#[test]
fn invalid_fields_are_refused() {
    let mut missing = source();
    conditions(&mut missing)[1]["fields"] = json!([]);
    assert_refused(
        &missing,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields"),
    );
    let mut unknown = source();
    conditions(&mut unknown)[1]["fields"] = json!(["no-such-field"]);
    assert_refused(
        &unknown,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields[field=no-such-field]"),
    );
    let mut stray = source();
    conditions(&mut stray)[0]["fields"] = json!(["phone"]);
    assert_refused(
        &stray,
        "breg.disclosure.fields-invalid",
        &format!("{COND}.fields"),
    );
}

#[test]
fn invalid_exempt_profiles_are_refused() {
    let mut empty = source();
    conditions(&mut empty)[0]["exemptProfiles"] = json!([]);
    assert_refused(
        &empty,
        "breg.disclosure.exempt-profiles-invalid",
        &format!("{COND}.exemptProfiles"),
    );
    let mut unknown = source();
    conditions(&mut unknown)[0]["exemptProfiles"] = json!(["ghost"]);
    assert_refused(
        &unknown,
        "breg.disclosure.exempt-profiles-invalid",
        &format!("{COND}.exemptProfiles[profile=ghost]"),
    );
}

#[test]
fn a_withheld_field_a_bound_profile_can_reach_is_refused() {
    let path = format!("{FIELDS_COND}.fields[field=phone]");
    for (member, value) in [
        ("filterableFields", json!(["family-name", "phone"])),
        ("sortableFields", json!(["phone"])),
    ] {
        let mut value_source = source();
        value_source["accessProfiles"][0]["permissions"]["records"][0][member] = value;
        assert_refused(
            &value_source,
            "breg.disclosure.withheld-field-exposed",
            &path,
        );
    }
    let mut export = source();
    export["accessProfiles"][0]["permissions"]["records"][0]["allowDataExport"] = json!(true);
    assert_refused(&export, "breg.disclosure.withheld-field-exposed", &path);
    let mut lookup = source();
    lookup["recordTypes"][0]["selectorProfiles"] = json!([{"id":"by-phone","fields":["phone"]}]);
    lookup["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
        json!(["get", "list", "lookup"]);
    lookup["accessProfiles"][0]["permissions"]["records"][0]["lookups"] =
        json!([{"selector":"by-phone","valueOrigin":"request"}]);
    assert_refused(&lookup, "breg.disclosure.withheld-field-exposed", &path);
    let mut hook = source();
    hook["recordTypes"][0]["hooks"].as_array_mut().unwrap().push(
        json!({"id":"person-patched","phase":"after","trigger":"patched","projection":["phone"]}),
    );
    assert_refused(&hook, "breg.disclosure.withheld-field-exposed", &path);
    let mut record_hook = source();
    record_hook["recordTypes"][0]["hooks"].as_array_mut().unwrap().push(
        json!({"id":"person-patched","phase":"after","trigger":"patched","projection":["district"]}),
    );
    assert_refused(&record_hook, "breg.disclosure.withheld-field-exposed", COND);
}

#[test]
fn an_exempt_profile_may_reach_a_withheld_field() {
    // `protection-officer` filters on `phone` in the base source, and compiles.
    assert!(compile(&source()).is_ok());
}

#[test]
fn an_invalid_read_hook_is_refused() {
    let hook = "recordTypes[id=person].hooks[id=person-read]";
    let mut no_profiles = source();
    no_profiles["recordTypes"][0]["hooks"][0]["profiles"] = json!([]);
    assert_refused(
        &no_profiles,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.profiles"),
    );
    let mut unknown = source();
    unknown["recordTypes"][0]["hooks"][0]["profiles"] = json!(["ghost"]);
    assert_refused(
        &unknown,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.profiles[profile=ghost]"),
    );
    let mut projecting = source();
    projecting["recordTypes"][0]["hooks"][0]["projection"] = json!(["district"]);
    assert_refused(
        &projecting,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.projection"),
    );
    let mut stray = source();
    stray["recordTypes"][0]["hooks"] = json!([{"id":"person-created","phase":"after","trigger":"created","projection":["district"],"profiles":["registrar"]}]);
    assert_refused(
        &stray,
        "breg.hook.read-trigger-invalid",
        "recordTypes[id=person].hooks[id=person-created].profiles",
    );
}

fn statistics_source() -> Value {
    json!({"datasets":[{"id": "statistics-test"}],
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id":"statistics-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test","timezone":"UTC"},
        "recordTypes": [{
            "id": "record", "primaryDataset": "statistics-test", "route": "records", "mutationMode": "mutable",
            "fields": [
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"valid-from","type":"date","required":true,"classification":"internal"},
                {"id":"valid-to","type":"date","classification":"internal"}
            ],
            "temporal": {"startField":"valid-from","endField":"valid-to"},
            "disclosureConditions":[{"id":"hide-inactive","when":[{"type":"field-equals","field":"active","value":false}],
                "withhold":"record","exemptProfiles":["analyst"]}]
        }],
        "accessProfiles": [
            {"id":"analyst","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["active","category","event-date","valid-from","valid-to"],
                "filterableFields":["active","category","event-date","valid-from","valid-to"],
                "allowCount":true,"rowBoundaries":"unrestricted"}],
              "datasets":[{"dataset":"records-by-category","operations":["read-live","read-releases"]}]}},
            {"id":"publisher","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["active","category","event-date","valid-from","valid-to"],
                "filterableFields":["active","category","event-date","valid-from","valid-to"],
                "allowCount":true,"rowBoundaries":"unrestricted"}],
              "datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}}
        ],
        "vocabularies": [{"id":"category","values":["a","b"]}],
        "statisticalDatasets": [{
            "id":"records-by-category","unit":"record","population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],
            "disclosure":{"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}}]
    })
}

#[test]
fn a_publisher_bound_by_a_record_condition_is_refused() {
    let found = refusal(&statistics_source());
    assert!(
        found
            .iter()
            .any(|(code, _)| code == "breg.disclosure.statistics-publisher-bound"),
        "{found:?}"
    );
    let mut exempt = statistics_source();
    exempt["recordTypes"][0]["disclosureConditions"][0]["exemptProfiles"] =
        json!(["analyst", "publisher"]);
    assert!(compile(&exempt).is_ok(), "{:?}", refusal(&exempt));
}

#[test]
fn a_dataset_cannot_release_a_field_withheld_from_a_reader() {
    let mut value = statistics_source();
    value["recordTypes"][0]["disclosureConditions"] = json!([{"id":"hide-category",
        "when":[{"type":"field-equals","field":"active","value":false}],
        "withhold":"fields","fields":["category"],"exemptProfiles":["analyst"]}]);
    let found = refusal(&value);
    assert!(
        found
            .iter()
            .any(|(code, _)| code == "breg.disclosure.withheld-field-exposed"),
        "{found:?}"
    );
}

#[test]
fn a_reason_profile_may_hold_enforced_read_operations() {
    let mut project = source();
    project["accessProfiles"][0]["permissions"]["records"][0]["allowCount"] = json!(true);
    assert!(compile(&project).is_ok());
}

#[test]
fn a_reason_profile_cannot_hold_an_operation_that_does_not_check_the_reason() {
    const PROFILE: &str = "project.accessProfiles[id=registrar].permissions";
    let code = "breg.access-profile.access-reason-operation-unsupported";
    for operation in ["import", "invoke", "start"] {
        let mut project = source();
        project["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
            json!(["get", operation]);
        assert_refused(
            &project,
            code,
            &format!("{PROFILE}.records[recordType=person].operations"),
        );
    }
    let mut actions = source();
    actions["accessProfiles"][0]["permissions"]["actions"] =
        json!([{"action":"close","operations":["invoke"]}]);
    assert_refused(&actions, code, &format!("{PROFILE}.actions"));
    let mut proposals = source();
    proposals["accessProfiles"][0]["permissions"]["proposals"] =
        json!([{"action":"close","operations":["get"]}]);
    assert_refused(&proposals, code, &format!("{PROFILE}.proposals"));
    let mut datasets = source();
    datasets["accessProfiles"][0]["permissions"]["datasets"] =
        json!([{"dataset":"counts","operations":["read-live"]}]);
    assert_refused(&datasets, code, &format!("{PROFILE}.datasets"));
    let mut views = source();
    views["accessProfiles"][0]["permissions"]["externalViews"] =
        json!([{"view":"directory","links":[]}]);
    assert_refused(&views, code, &format!("{PROFILE}.externalViews"));
    let mut refresh = source();
    refresh["accessProfiles"][0]["permissions"]["refreshExternalProjections"] =
        json!(["directory"]);
    assert_refused(
        &refresh,
        code,
        &format!("{PROFILE}.refreshExternalProjections"),
    );
}

#[test]
fn a_profile_without_a_reason_requirement_may_import() {
    let mut project = source();
    project["accessProfiles"][1]["permissions"]["records"][0]["operations"] =
        json!(["get", "import"]);
    let found = refusal_or_empty(&project);
    assert!(
        !found
            .iter()
            .any(|(code, _)| code == "breg.access-profile.access-reason-operation-unsupported"),
        "{found:?}"
    );
}

fn refusal_or_empty(value: &Value) -> Vec<(String, String)> {
    match compile(value) {
        Ok(_) => Vec::new(),
        Err(failure) => failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect(),
    }
}
