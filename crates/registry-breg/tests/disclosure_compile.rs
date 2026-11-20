// SPDX-License-Identifier: Apache-2.0

//! Compile-time rules for `disclosureConditions`, `requireAccessReason` and
//! the read-trigger hook.

use registry_breg::contract::ModuleAssetSource;
use registry_breg::model::DisclosureWithhold;
use registry_breg::{
    compile_project, compile_project_with_assets, parse_project_json, CompileProfile,
    CompiledRegistry,
};
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

// Surfaces a `fields` condition must not leave open to a profile it binds.

const REGISTRAR: usize = 0;
const OFFICER: usize = 1;

fn has_code(value: &Value, code: &str) -> bool {
    refusal_or_empty(value)
        .iter()
        .any(|(found, _)| found == code)
}

fn assert_refused_code(value: &Value, code: &str) {
    let found = refusal(value);
    assert!(
        found.iter().any(|(found, _)| found == code),
        "expected {code}, got {found:?}"
    );
}

fn person_permission(value: &mut Value, profile: usize) -> &mut Value {
    &mut value["accessProfiles"][profile]["permissions"]["records"][0]
}

#[test]
fn a_required_field_or_the_canonical_id_cannot_be_withheld() {
    let mut required = source();
    required["recordTypes"][0]["fields"][4]["required"] = json!(true);
    assert_refused(
        &required,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields[field=phone]"),
    );
    let mut canonical = source();
    conditions(&mut canonical)[1]["fields"] = json!(["id"]);
    assert_refused(
        &canonical,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields[field=id]"),
    );
}

fn when_probe(field_type: Value) -> Value {
    let mut value = source();
    let mut probe = json!({"id":"probe","classification":"internal"});
    probe
        .as_object_mut()
        .unwrap()
        .extend(field_type.as_object().unwrap().clone());
    value["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(probe);
    value["vocabularies"] = json!([{"id":"probe-codes","values":["a","b"]}]);
    conditions(&mut value).push(json!({"id":"probe-condition",
        "when":[{"type":"field-is-not-null","field":"probe"}],
        "withhold":"record","exemptProfiles":["protection-officer"]}));
    value
}

#[test]
fn a_when_field_is_one_of_the_admitted_types() {
    for field_type in [
        json!({"type":"boolean"}),
        json!({"type":"string","maximumLength":16}),
        json!({"type":"text","maximumLength":64}),
        json!({"type":"vocabulary-code","vocabulary":"probe-codes"}),
        json!({"type":"int64"}),
        json!({"type":"date"}),
        json!({"type":"uuid"}),
    ] {
        let value = when_probe(field_type.clone());
        assert!(
            compile(&value).is_ok(),
            "{field_type} is admitted: {:?}",
            compile(&value).err().map(|failure| failure
                .diagnostics()
                .iter()
                .map(|d| (d.code.clone(), d.path.clone()))
                .collect::<Vec<_>>())
        );
    }
    for field_type in [
        json!({"type":"decimal","precision":10,"scale":2}),
        json!({"type":"timestamp"}),
        json!({"type":"reference","target":"person"}),
    ] {
        assert_refused(
            &when_probe(field_type),
            "breg.disclosure.when-field-invalid",
            &format!(
                "{}.when[0].field",
                "recordTypes[id=person].disclosureConditions[id=probe-condition]"
            ),
        );
    }
}

fn geometry_source() -> Value {
    let mut value = source();
    value["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"location","type":"crs84-point","precision":6,"classification":"internal"}),
        );
    value["recordTypes"][0]["geojson"] = json!({"geometryField":"location"});
    conditions(&mut value)[1]["fields"] = json!(["location"]);
    for profile in [REGISTRAR, OFFICER] {
        let permission = person_permission(&mut value, profile);
        permission["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(json!("location"));
        permission["spatialQueries"] = json!({"bbox":{
            "maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}});
    }
    value
}

#[test]
fn a_bound_profile_cannot_run_spatial_queries_over_a_withheld_geometry() {
    let mut value = geometry_source();
    person_permission(&mut value, OFFICER)
        .as_object_mut()
        .unwrap()
        .insert(
            "spatialQueries".to_owned(),
            json!({"bbox":{
            "maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}}),
        );
    assert_refused(
        &value,
        "breg.disclosure.spatial-query-withheld-geometry",
        &format!("{FIELDS_COND}.fields[field=location]"),
    );
    person_permission(&mut value, REGISTRAR)
        .as_object_mut()
        .unwrap()
        .remove("spatialQueries");
    let found = refusal_or_empty(&value);
    assert!(
        !found
            .iter()
            .any(|(code, _)| code == "breg.disclosure.spatial-query-withheld-geometry"),
        "an exempt profile and a profile without the grant stay accepted: {found:?}"
    );
}

#[test]
fn a_row_boundary_cannot_read_a_withheld_field() {
    let mut value = source();
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"age","claim":"age","operator":"equals"}]);
    conditions(&mut value)[1]["fields"] = json!(["age"]);
    assert_refused(
        &value,
        "breg.disclosure.row-boundary-withheld-field",
        &format!("{FIELDS_COND}.fields[field=age]"),
    );
    conditions(&mut value)[1]["exemptProfiles"] = json!(["protection-officer", "registrar"]);
    assert!(!has_code(
        &value,
        "breg.disclosure.row-boundary-withheld-field"
    ));
}

#[test]
fn a_membership_boundary_cannot_read_a_withheld_field() {
    #[path = "support/membership_fixture.rs"]
    mod membership_fixture;
    let mut value = membership_fixture::source("facility");
    let facility = value["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "facility")
        .unwrap();
    facility["fields"][0]["required"] = json!(false);
    facility["disclosureConditions"] = json!([{"id":"hide-organization",
        "when":[{"type":"field-is-not-null","field":"label"}],
        "withhold":"fields","fields":["organization"],"exemptProfiles":["steward"]}]);
    let found: Vec<String> = membership_fixture::compile(&value)
        .expect_err("the boundary reads a withheld field")
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect();
    assert!(
        found.contains(&"breg.disclosure.membership-boundary-withheld-field".to_owned()),
        "{found:?}"
    );
}

#[test]
fn a_consent_boundary_cannot_read_a_withheld_field() {
    #[path = "support/consent_fixture.rs"]
    mod consent_fixture;
    let mut value = consent_fixture::source();
    let consenting: Vec<String> = value["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|profile| {
            profile["permissions"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| {
                    record["recordType"] == "enrolment" && record.get("requireConsent").is_some()
                })
        })
        .map(|profile| profile["id"].as_str().unwrap().to_owned())
        .collect();
    let exempt = value["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|profile| profile["id"].as_str().unwrap().to_owned())
        .find(|id| !consenting.contains(id))
        .expect("a profile that does not require consent on enrolment");
    let enrolment = value["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entity| entity["id"] == "enrolment")
        .unwrap();
    for field in enrolment["fields"].as_array_mut().unwrap() {
        if field["id"] == "person" {
            field["required"] = json!(false);
        }
    }
    enrolment["disclosureConditions"] = json!([{"id":"hide-person",
        "when":[{"type":"field-is-not-null","field":"programme"}],
        "withhold":"fields","fields":["person"],"exemptProfiles":[exempt]}]);
    let found = consent_fixture::refusal_codes(&value);
    assert!(
        found.contains(&"breg.disclosure.consent-boundary-withheld-field".to_owned()),
        "{found:?}"
    );
}

#[test]
fn a_read_path_cannot_run_through_a_withheld_reference() {
    let mut value = source();
    value["recordTypes"].as_array_mut().unwrap().extend([
        json!({"id":"child","primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]}),
        json!({"id":"link","primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                      {"id":"child","type":"reference","target":"child","classification":"internal"},
                      {"id":"sealed","type":"boolean","classification":"internal"}],
            "disclosureConditions":[{"id":"hide-child",
              "when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["child"],"exemptProfiles":["protection-officer"]}]}),
    ]);
    value["recordTypes"][0]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    person_permission(&mut value, REGISTRAR)["readPaths"] =
        json!([{"path":"children","readableFields":["code"]}]);
    let found = refusal_or_empty(&value);
    assert!(
        found.contains(&(
            "breg.disclosure.read-path-withheld-field".to_owned(),
            "recordTypes[id=link].disclosureConditions[id=hide-child].fields[field=child]"
                .to_owned()
        )),
        "{found:?}"
    );
    value["recordTypes"][2]["disclosureConditions"][0]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!has_code(
        &value,
        "breg.disclosure.read-path-withheld-field"
    ));
}

fn compile_with_sql(
    value: &Value,
    sql: &str,
) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/derived.sql".to_owned(),
            bytes: sql.as_bytes().to_vec(),
        }],
        CompileProfile::Authoring,
    )
}

fn codes(result: Result<CompiledRegistry, registry_breg::CompileFailure>) -> Vec<String> {
    result
        .err()
        .map(|failure| {
            failure
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_derived_field_cannot_read_a_withheld_field_for_a_bound_profile() {
    let mut value = source();
    value["recordTypes"][0]["derived"] = json!([{"id":"phone-state","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"has-phone","type":"boolean","classification":"internal"}]}]);
    person_permission(&mut value, REGISTRAR)["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("has-phone"));
    let sql = "SELECT p.id AS id, p.phone IS NOT NULL AS has_phone FROM registry_source.person p";
    assert!(codes(compile_with_sql(&value, sql))
        .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()));
    let unrelated = "SELECT p.id AS id, p.age > 17 AS has_phone FROM registry_source.person p";
    assert!(!codes(compile_with_sql(&value, unrelated))
        .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()));
    conditions(&mut value)[1]["exemptProfiles"] = json!(["protection-officer", "registrar"]);
    assert!(!codes(compile_with_sql(&value, sql))
        .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()));
}

const LINKED: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: linked-example, version: "1", defaultLanguage: en, canonicalBaseIri: "https://registry.example.test"}
datasets: [{id: local-records}]
recordTypes:
  - id: local-record
    primaryDataset: local-records
    route: local-records
    mutationMode: mutable
    classification: internal
    fields:
      - {id: subject-key, type: string, maximumLength: 32, classification: internal}
      - {id: local-title, type: string, maximumLength: 120, classification: internal}
      - {id: sealed, type: boolean, classification: internal}
    disclosureConditions:
      - id: hide-key
        when: [{type: field-equals, field: sealed, value: true}]
        withhold: fields
        fields: [subject-key]
        exemptProfiles: [officer]
externalRecordTypes:
  - id: external-subject
    authority: urn:example:source
    identifierScheme: urn:example:subject-key
    fields:
      - {id: label, type: string, classification: internal}
externalProjections:
  - id: approved-subjects
    recordType: external-subject
    sourceRoute: subjects-by-key
    sourceRouteVersion: "1"
    purpose: local-consultation
    scope: approved-subjects
    mode: indexed
    cardinality: one
    cacheTtlSeconds: 600
    fields: [label]
externalViews:
  - id: local-with-subject
    recordType: local-record
    links:
      - id: subject
        projection: approved-subjects
        fromField: subject-key
accessProfiles:
  - id: reader
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [local-consultation]
    permissions:
      records:
        - recordType: local-record
          operations: [get, list]
          readableFields: [local-title]
          rowBoundaries: unrestricted
      externalViews:
        - view: local-with-subject
          links:
            - link: subject
              readableFields: [label]
  - id: officer
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [local-consultation]
    permissions:
      records:
        - recordType: local-record
          operations: [get, list]
          readableFields: [local-title]
          rowBoundaries: unrestricted
      externalViews:
        - view: local-with-subject
          links:
            - link: subject
              readableFields: [label]
"#;

#[test]
fn an_external_view_cannot_link_from_a_withheld_field_for_a_bound_profile() {
    let project = registry_breg::contract::parse_project_yaml(LINKED.as_bytes()).unwrap();
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("the reader is bound and links from the withheld field");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|d| d.code == "breg.disclosure.external-view-withheld-field"),
        "{:?}",
        failure.diagnostics()
    );
    let exempt = LINKED.replace(
        "exemptProfiles: [officer]",
        "exemptProfiles: [officer, reader]",
    );
    let project = registry_breg::contract::parse_project_yaml(exempt.as_bytes()).unwrap();
    let outcome = compile_project(&project, &[], CompileProfile::Authoring);
    assert!(
        outcome.is_ok(),
        "{:?}",
        outcome.err().map(|f| f.diagnostics().to_vec())
    );
}

fn live_statistics_source() -> Value {
    let mut value = statistics_source();
    value["recordTypes"][0]["disclosureConditions"][0]["exemptProfiles"] = json!(["publisher"]);
    value
}

#[test]
fn a_live_statistics_read_is_refused_where_a_record_condition_binds_the_reader() {
    let mut value = live_statistics_source();
    assert_refused_code(&value, "breg.disclosure.statistics-live-bound");
    value["accessProfiles"][0]["permissions"]["datasets"] =
        json!([{"dataset":"records-by-category","operations":["read-releases"]}]);
    assert!(
        !has_code(&value, "breg.disclosure.statistics-live-bound"),
        "release reads stay allowed: {:?}",
        refusal_or_empty(&value)
    );
}

#[test]
fn a_dataset_cannot_read_a_withheld_field_of_a_dependency_entity() {
    let mut value = statistics_source();
    value["recordTypes"][0]["disclosureConditions"][0]["exemptProfiles"] =
        json!(["analyst", "publisher"]);
    value["recordTypes"][0]["derived"] = json!([{
        "id":"statistics","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"internal"}]
    }]);
    value["recordTypes"].as_array_mut().unwrap().push(json!({
        "id":"lookup","primaryDataset":"statistics-test","route":"lookups","mutationMode":"mutable",
        "fields":[{"id":"flag","type":"boolean","classification":"internal"}],
        "disclosureConditions":[{"id":"hide-flag",
          "when":[{"type":"field-is-not-null","field":"flag"}],
          "withhold":"fields","fields":["flag"],"exemptProfiles":["publisher"]}]
    }));
    value["accessProfiles"][1]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"lookup","operations":["list"],"readableFields":["flag"],
            "allowCount":true,"rowBoundaries":"unrestricted"}),
        );
    value["statisticalDatasets"][0]["dimensions"] = json!(["evaluated-category"]);
    let sql = "SELECT r.id AS id, CASE WHEN l.flag THEN 'a' ELSE 'b' END AS evaluated_category FROM registry_source.record r JOIN registry_source.lookup l ON l.id = r.id";
    let found = codes(compile_with_sql(&value, sql));
    assert!(
        found.contains(&"breg.disclosure.statistics-withheld-field".to_owned()),
        "{found:?}"
    );
    value["recordTypes"][1]["disclosureConditions"][0]["exemptProfiles"] =
        json!(["analyst", "publisher"]);
    let found = codes(compile_with_sql(&value, sql));
    assert!(
        !found.contains(&"breg.disclosure.statistics-withheld-field".to_owned()),
        "an exempt reader is accepted: {found:?}"
    );
}

fn evidence_options() -> registry_breg::evidence_source::EvidenceSourceOptions {
    registry_breg::evidence_source::EvidenceSourceOptions {
        access_profile: "evidence-source".into(),
        entity: "record".into(),
        selectors: vec!["by-code".into()],
        fields: vec!["status".into()],
        source_id: "registry-status".into(),
        connection: "registry".into(),
        authentication:
            registry_breg::evidence_source::EvidenceSourceAuthentication::StaticAuthorization,
    }
}

fn evidence_project(exempt: &str) -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "datasets":[{"id":"test-dataset"}],
        "recordTypes":[{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal"},
            {"id":"status","type":"string","maximumLength":16,"classification":"internal"},
            {"id":"sealed","type":"boolean","classification":"internal"}],
            "selectorProfiles":[{"id":"by-code","fields":["code"]}],
            "disclosureConditions":[{"id":"hide-status",
              "when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["status"],"exemptProfiles":[exempt]}]}],
        "accessProfiles":[
          {"id":"evidence-source","principalClaim":"principal","requiredScopes":["registry.read"],"permissions":{"records":[{
            "recordType":"record","operations":["lookup"],"readableFields":["code","status"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"}],"rowBoundaries":"unrestricted"}]}},
          {"id":"officer","principalClaim":"principal","requiredScopes":["registry.read"],"permissions":{"records":[{
            "recordType":"record","operations":["get"],"readableFields":["code","status"],
            "rowBoundaries":"unrestricted"}]}}]})
}

#[test]
fn an_evidence_source_cannot_export_a_withheld_fact() {
    let refused = compile(&evidence_project("officer")).expect("the project compiles");
    let Err(diagnostic) =
        registry_breg::evidence_source::export_evidence_source(&refused, &evidence_options())
    else {
        panic!("the profile is bound by a condition that withholds `status`");
    };
    assert_eq!(
        diagnostic.code,
        "breg.disclosure.evidence-fact-withheld-field"
    );
    let exempt = compile(&evidence_project("evidence-source")).expect("the project compiles");
    registry_breg::evidence_source::export_evidence_source(&exempt, &evidence_options())
        .expect("an exempt profile exports the fact");
}

#[test]
fn the_record_timer_profile_id_is_reserved() {
    let mut value = source();
    value["accessProfiles"][1]["id"] = json!("system-record-timer");
    conditions(&mut value)[0]["exemptProfiles"] = json!(["registrar"]);
    conditions(&mut value)[1]["exemptProfiles"] = json!(["registrar"]);
    assert_refused_code(&value, "breg.access-profile.system-id-reserved");
}
