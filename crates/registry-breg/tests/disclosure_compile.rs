// SPDX-License-Identifier: Apache-2.0

//! Compile-time rules for `disclosureConditions`, `requireAccessReason` and
//! the read-trigger hook.

use registry_breg::contract::{ModuleAssetSource, RegistryModule};
use registry_breg::model::DisclosureWithhold;
use registry_breg::{
    compile_project, compile_project_with_assets, parse_project_json, CompileProfile,
    CompiledRegistry,
};
use serde_json::{json, Value};

#[path = "support/consent_fixture.rs"]
mod consent_fixture;
#[path = "support/membership_fixture.rs"]
mod membership_fixture;

fn source() -> Value {
    json!({"datasets":{"test-dataset": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"disclosure","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://disclosure.example.test"},
        "recordTypes":{"person": {"primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"family-name","type":"string","maximumLength":64,"classification":"internal"},
                    {"id":"protected","type":"boolean","classification":"internal"},
                    {"id":"district","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"age","type":"int64","classification":"internal"},
                    {"id":"phone","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"subject-id","type":"string","maximumLength":64,"required":true,"classification":"internal"}],
          "disclosureConditions":{
            "hide-protected": {"when":[{"type":"field-equals","field":"protected","value":true}],
             "withhold":"record","exemptProfiles":["protection-officer"]},
            "hide-phone": {"when":[{"type":"field-is-not-null","field":"protected"},
                                      {"type":"field-in","field":"district","values":["north","south"]}],
             "withhold":"fields","fields":["phone"],"exemptProfiles":["protection-officer"]}},
          "accessLog":{"subjectField":"subject-id"},
          "hooks":[{"id":"person-read","phase":"after","trigger":"read","profiles":["registrar"],"projection":[]}]}},
        "accessProfiles":{
          "registrar": {"default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","requireAccessReason":true,
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected","district","age","phone"],
             "filterableFields":["family-name","district"]}]}},
          "protection-officer": {"principalClaim":"registry_principal","requiredScopes":"unrestricted",
           "permissions":{"records":[{"recordType":"person","operations":["get","list"],"rowBoundaries":"unrestricted",
             "readableFields":["family-name","protected","district","age","phone"],
             "filterableFields":["family-name","phone"]}]}}}
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

fn conditions(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value["recordTypes"]["person"]["disclosureConditions"]
        .as_object_mut()
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
    assert_eq!(person.disclosure_conditions[0].id, "hide-phone");
    assert_eq!(
        person.disclosure_conditions[0].withhold,
        DisclosureWithhold::Fields(["phone".to_owned()].into())
    );
    assert_eq!(person.disclosure_conditions[1].id, "hide-protected");
    assert_eq!(
        person.disclosure_conditions[1].withhold,
        DisclosureWithhold::Record
    );
    assert!(person.access_profiles["registrar"].require_access_reason);
    assert!(!person.access_profiles["protection-officer"].require_access_reason);
    assert_eq!(person.hooks["person-read"].profiles.len(), 1);
}

#[test]
fn a_project_without_conditions_compiles_to_none() {
    let mut value = source();
    let person = value["recordTypes"]["person"].as_object_mut().unwrap();
    person.remove("disclosureConditions");
    person.remove("hooks");
    let registry = compile(&value).expect("compiles");
    assert!(registry.entities()["person"]
        .disclosure_conditions
        .is_empty());
}

#[test]
fn a_list_of_conditions_is_refused_with_the_mapping_named() {
    let mut listed = source();
    listed["recordTypes"]["person"]["disclosureConditions"] = json!([
        {"id":"hide-protected","when":[{"type":"field-equals","field":"protected","value":true}],
         "withhold":"record","exemptProfiles":["protection-officer"]}]);
    let failure = parse_project_json(&serde_json::to_vec(&listed).unwrap())
        .expect_err("the list form is refused");
    let found = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        vec![(
            "config.removed-key",
            "project.recordTypes.person.disclosureConditions[0].id"
        )],
        "{failure:?}"
    );
    assert!(
        failure.diagnostics()[0]
            .message
            .contains("disclosureConditions: {CONDITION_ID: {"),
        "the refusal names the mapping shape: {failure:?}"
    );
}

#[test]
fn more_than_eight_conditions_are_refused() {
    let mut value = source();
    let template = conditions(&mut value)["hide-protected"].clone();
    for index in 0..8 {
        conditions(&mut value).insert(format!("extra-{index}"), template.clone());
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
        conditions(&mut value)["hide-protected"]["when"][0]["field"] = json!(field);
        assert_refused(
            &value,
            "breg.disclosure.when-field-invalid",
            &format!("{COND}.when[0].field"),
        );
    }
    let mut encrypted = source();
    encrypted["recordTypes"]["person"]["fields"][4]["encrypted"] = json!(true);
    encrypted["recordTypes"]["person"]["fields"][4]["classification"] = json!("restricted");
    conditions(&mut encrypted)["hide-protected"]["when"][0] =
        json!({"type":"field-is-null","field":"phone"});
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
    conditions(&mut wrong_type)["hide-protected"]["when"][0]["value"] = json!("yes");
    assert_refused(&wrong_type, "breg.disclosure.when-value-invalid", &path);
    let mut empty_in = source();
    conditions(&mut empty_in)["hide-protected"]["when"][0] =
        json!({"type":"field-in","field":"district","values":[]});
    assert_refused(
        &empty_in,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when[0].values"),
    );
    let mut wide_in = source();
    let values: Vec<String> = (0..33).map(|n| format!("d{n}")).collect();
    conditions(&mut wide_in)["hide-protected"]["when"][0] =
        json!({"type":"field-in","field":"district","values":values});
    assert_refused(
        &wide_in,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when[0].values"),
    );
    let mut empty_when = source();
    conditions(&mut empty_when)["hide-protected"]["when"] = json!([]);
    assert_refused(
        &empty_when,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when"),
    );
    let mut five = source();
    conditions(&mut five)["hide-protected"]["when"] = json!((0..5)
        .map(|_| json!({"type":"field-is-not-null","field":"age"}))
        .collect::<Vec<_>>());
    assert_refused(
        &five,
        "breg.disclosure.when-value-invalid",
        &format!("{COND}.when"),
    );
}

#[test]
fn a_repeated_withheld_field_is_refused_by_the_reader() {
    let mut repeated = source();
    conditions(&mut repeated)["hide-phone"]["fields"] = json!(["phone", "phone"]);
    let failure = parse_project_json(&serde_json::to_vec(&repeated).unwrap())
        .expect_err("a repeated withheld field is refused rather than collapsed");
    let found = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        vec![(
            "config.duplicate-item",
            "project.recordTypes.person.disclosureConditions.hide-phone.fields[1]"
        )],
        "{failure:?}"
    );
}

#[test]
fn invalid_fields_are_refused() {
    let mut missing = source();
    conditions(&mut missing)["hide-phone"]["fields"] = json!([]);
    assert_refused(
        &missing,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields"),
    );
    let mut unknown = source();
    conditions(&mut unknown)["hide-phone"]["fields"] = json!(["no-such-field"]);
    assert_refused(
        &unknown,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields[field=no-such-field]"),
    );
    let mut stray = source();
    conditions(&mut stray)["hide-protected"]["fields"] = json!(["phone"]);
    assert_refused(
        &stray,
        "breg.disclosure.fields-invalid",
        &format!("{COND}.fields"),
    );
}

#[test]
fn invalid_exempt_profiles_are_refused() {
    let mut empty = source();
    conditions(&mut empty)["hide-protected"]["exemptProfiles"] = json!([]);
    assert_refused(
        &empty,
        "breg.disclosure.exempt-profiles-invalid",
        &format!("{COND}.exemptProfiles"),
    );
    let mut unknown = source();
    conditions(&mut unknown)["hide-protected"]["exemptProfiles"] = json!(["ghost"]);
    assert_refused(
        &unknown,
        "breg.disclosure.exempt-profiles-invalid",
        &format!("{COND}.exemptProfiles[profile=ghost]"),
    );
}

/// The source with a `household` record type and three profiles that hold no
/// record grant: `action-clerk` invokes an immediate Action on `person`,
/// `proposal-clerk` applies a Proposal on `person` that the protection officer
/// starts, and `household-clerk` invokes an immediate Action on `household`
/// only.
fn workflow_source() -> Value {
    let mut value = source();
    value["recordTypes"]["household"] = json!(
        {"primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
         "classification":"internal",
         "fields":[{"id":"label","type":"string","maximumLength":64,"classification":"internal"}]});
    let action = |record_type: &str, field: &str, execution: Value| {
        json!({"execution": execution,
            "inputs":[{"id":"target","type":"reference","target":record_type,"required":true,"classification":"internal"},
                      {"id":"name","type":"string","maximumLength":64,"required":true,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"rename","target":{"fromInput":"target"},"operation":"patch",
                "set":{field:{"fromInput":"name"}}}]}})
    };
    let proposal = json!({"mode":"proposal","proposal":{"review":{"type":"none"},
        "application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}});
    value["actions"] = json!({
        "rename-person": action("person", "family-name", json!({"mode":"immediate"})),
        "propose-person-name": action("person", "family-name", proposal),
        "rename-household": action("household", "label", json!({"mode":"immediate"}))
    });
    let targets =
        |record_type: &str| json!([{"recordType":record_type,"rowBoundaries":"unrestricted"}]);
    let clerk = |permissions: Value| {
        json!({"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "permissions":permissions})
    };
    value["accessProfiles"]["protection-officer"]["permissions"]["actions"] = json!([
        {"action":"propose-person-name","operations":["start"],"targets":targets("person")}]);
    let profiles = value["accessProfiles"].as_object_mut().unwrap();
    profiles.insert(
        "action-clerk".to_owned(),
        clerk(json!({"actions":[
            {"action":"rename-person","operations":["invoke"],"targets":targets("person")}]})),
    );
    profiles.insert(
        "proposal-clerk".to_owned(),
        clerk(json!({"proposals":[
            {"action":"propose-person-name","ownership":"caller","operations":["get","list","apply"],
             "targets":targets("person")}]})),
    );
    profiles.insert(
        "household-clerk".to_owned(),
        clerk(json!({"actions":[
            {"action":"rename-household","operations":["invoke"],"targets":targets("household")}]})),
    );
    value
}

#[test]
fn a_condition_exempts_a_profile_that_writes_the_record_type_through_an_action_or_proposal() {
    let base = workflow_source();
    compile(&base).unwrap_or_else(|failure| panic!("{:#?}", failure.diagnostics()));
    let mut exempt = base.clone();
    for condition in conditions(&mut exempt).values_mut() {
        condition["exemptProfiles"] =
            json!(["protection-officer", "action-clerk", "proposal-clerk"]);
    }
    let registry =
        compile(&exempt).unwrap_or_else(|failure| panic!("{:#?}", failure.diagnostics()));
    for condition in &registry.entities()["person"].disclosure_conditions {
        for profile in ["action-clerk", "proposal-clerk"] {
            assert!(
                condition.exempt_profiles.contains(profile),
                "{} exempts {profile}",
                condition.id
            );
        }
    }
    // A profile whose Action writes another record type only is not one this
    // record type's condition can exempt.
    let mut elsewhere = base;
    conditions(&mut elsewhere)["hide-protected"]["exemptProfiles"] =
        json!(["protection-officer", "household-clerk"]);
    assert_refused(
        &elsewhere,
        "breg.disclosure.exempt-profiles-invalid",
        &format!("{COND}.exemptProfiles[profile=household-clerk]"),
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
        value_source["accessProfiles"]["registrar"]["permissions"]["records"][0][member] = value;
        assert_refused(
            &value_source,
            "breg.disclosure.withheld-field-exposed",
            &path,
        );
    }
    let mut export = source();
    export["accessProfiles"]["registrar"]["permissions"]["records"][0]["allowDataExport"] =
        json!(true);
    assert_refused(&export, "breg.disclosure.withheld-field-exposed", &path);
    let mut lookup = source();
    lookup["recordTypes"]["person"]["selectorProfiles"] =
        json!([{"id":"by-phone","fields":["phone"]}]);
    lookup["accessProfiles"]["registrar"]["permissions"]["records"][0]["operations"] =
        json!(["get", "list", "lookup"]);
    lookup["accessProfiles"]["registrar"]["permissions"]["records"][0]["lookups"] =
        json!([{"selector":"by-phone","valueOrigin":"request"}]);
    assert_refused(&lookup, "breg.disclosure.withheld-field-exposed", &path);
    let mut hook = source();
    hook["recordTypes"]["person"]["hooks"].as_array_mut().unwrap().push(
        json!({"id":"person-patched","phase":"after","trigger":"patched","projection":["phone"]}),
    );
    assert_refused(&hook, "breg.disclosure.withheld-field-exposed", &path);
    let mut record_hook = source();
    record_hook["recordTypes"]["person"]["hooks"].as_array_mut().unwrap().push(
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
    no_profiles["recordTypes"]["person"]["hooks"][0]["profiles"] = json!([]);
    assert_refused(
        &no_profiles,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.profiles"),
    );
    let mut unknown = source();
    unknown["recordTypes"]["person"]["hooks"][0]["profiles"] = json!(["ghost"]);
    assert_refused(
        &unknown,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.profiles[profile=ghost]"),
    );
    let mut projecting = source();
    projecting["recordTypes"]["person"]["hooks"][0]["projection"] = json!(["district"]);
    assert_refused(
        &projecting,
        "breg.hook.read-trigger-invalid",
        &format!("{hook}.projection"),
    );
    let mut stray = source();
    stray["recordTypes"]["person"]["hooks"] = json!([{"id":"person-created","phase":"after","trigger":"created","projection":["district"],"profiles":["registrar"]}]);
    assert_refused(
        &stray,
        "breg.hook.read-trigger-invalid",
        "recordTypes[id=person].hooks[id=person-created].profiles",
    );
}

#[test]
fn a_read_hook_on_a_record_type_without_an_access_log_is_refused() {
    let mut value = source();
    value["recordTypes"]["person"]
        .as_object_mut()
        .unwrap()
        .remove("accessLog");
    assert_refused(
        &value,
        "breg.disclosure.read-hook-access-log-required",
        "recordTypes[id=person].hooks[id=person-read].trigger",
    );
}

const PROBE: &str = "breg.disclosure.withheld-field-probe";

/// The paths at which `value` compiles with the withheld-field probe finding.
fn probe_findings(value: &Value) -> Vec<String> {
    compile(value)
        .expect("a constraint on a withheld field is a finding, not a refusal")
        .findings()
        .iter()
        .filter(|finding| finding.code == PROBE)
        .map(|finding| {
            assert_eq!(
                finding.severity,
                registry_breg::DiagnosticSeverity::Finding,
                "{finding:?}"
            );
            finding.path.clone()
        })
        .collect()
}

/// A Create that repeats a withheld value answers a conflict and any other
/// value succeeds, so a constraint over a withheld field confirms a guess.
/// The project still compiles, with a finding to accept or act on.
#[test]
fn a_uniqueness_constraint_on_a_withheld_field_is_a_finding() {
    let path = format!("{FIELDS_COND}.fields[field=phone]");
    for fields in [json!(["phone"]), json!(["district", "phone"])] {
        let mut value = source();
        value["recordTypes"]["person"]["constraints"] =
            json!([{"type": "unique", "fields": fields}]);
        assert_eq!(probe_findings(&value), [path.as_str()]);
    }
    let mut unrelated = source();
    unrelated["recordTypes"]["person"]["constraints"] =
        json!([{"type": "unique", "fields": ["subject-id"]}]);
    assert!(probe_findings(&unrelated).is_empty());
}

/// A partial uniqueness constraint holds only for records its `when` matches,
/// so a Create that repeats the unique value answers a conflict exactly when a
/// hidden record's withheld field meets the predicate.
#[test]
fn a_withheld_field_in_a_partial_uniqueness_when_is_a_finding() {
    let path = format!("{FIELDS_COND}.fields[field=phone]");
    for predicate in [
        json!({"type":"field-is-not-null","field":"phone"}),
        json!({"type":"field-is-null","field":"phone"}),
        json!({"type":"field-equals","field":"phone","value":"0000"}),
    ] {
        let mut value = source();
        value["recordTypes"]["person"]["constraints"] =
            json!([{"type": "unique", "fields": ["subject-id"], "when": [predicate]}]);
        assert_eq!(probe_findings(&value), [path.as_str()]);
    }
    let mut unrelated = source();
    unrelated["recordTypes"]["person"]["constraints"] = json!([{"type": "unique", "fields": ["subject-id"],
        "when": [{"type":"field-is-not-null","field":"district"}]}]);
    assert!(probe_findings(&unrelated).is_empty());
}

/// An encrypted field's unique blind index answers a repeated value with a
/// conflict in the same way as a uniqueness constraint.
#[test]
fn a_unique_blind_index_on_a_withheld_field_is_a_finding() {
    let encrypted_phone = |unique: bool| {
        let mut value = source();
        value["recordTypes"]["person"]["fields"][4] = json!({"id":"phone","type":"string","maximumLength":32,
            "classification":"restricted","encrypted":true,"lookup":{"unique":unique}});
        person_permission(&mut value, OFFICER)["filterableFields"] = json!(["family-name"]);
        value
    };
    assert!(probe_findings(&encrypted_phone(false)).is_empty());
    assert_eq!(
        probe_findings(&encrypted_phone(true)),
        [format!("{FIELDS_COND}.fields[field=phone]")]
    );
}

/// A Create whose period overlaps a hidden record's within the same scope
/// answers a conflict, so a withheld period field in a temporal non-overlap
/// key confirms a guess as a unique member does.
#[test]
fn a_withheld_field_in_a_temporal_non_overlap_key_is_a_finding() {
    let temporal = |constraint: Option<Value>| {
        let mut value = source();
        let person = &mut value["recordTypes"]["person"];
        let fields = person["fields"].as_array_mut().unwrap();
        fields.push(
            json!({"id":"valid-from","type":"timestamp","validTimeRole":"valid-from",
            "required":true,"classification":"internal"}),
        );
        fields.push(
            json!({"id":"valid-to","type":"timestamp","validTimeRole":"valid-to",
            "classification":"internal"}),
        );
        person["temporal"] = json!({"startField":"valid-from","endField":"valid-to"});
        person["disclosureConditions"]["hide-phone"]["fields"] = json!(["valid-to"]);
        if let Some(constraint) = constraint {
            person["constraints"] = json!([constraint]);
        }
        for profile in [REGISTRAR, OFFICER] {
            person_permission(&mut value, profile)["readableFields"]
                .as_array_mut()
                .unwrap()
                .extend([json!("valid-from"), json!("valid-to")]);
        }
        value
    };
    assert!(probe_findings(&temporal(None)).is_empty());
    // The key compares the valid-time fields whether or not it names them.
    for constraint in [
        json!({"type":"temporal-non-overlap","scopeFields":["subject-id"],
            "startField":"valid-from","endField":"valid-to"}),
        json!({"type":"temporal-non-overlap","scopeFields":["subject-id"]}),
    ] {
        assert_eq!(
            probe_findings(&temporal(Some(constraint))),
            [format!("{FIELDS_COND}.fields[field=valid-to]")]
        );
    }
}

fn statistics_source() -> Value {
    json!({"datasets":{"statistics-test": {}},
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id":"statistics-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test","timezone":"UTC"},
        "recordTypes": {"record": {
            "primaryDataset": "statistics-test", "route": "records", "mutationMode": "mutable",
            "fields": [
                {"id":"active","type":"boolean","required":true,"classification":"internal"},
                {"id":"category","type":"vocabulary-code","vocabulary":"category","required":true,"classification":"internal"},
                {"id":"event-date","type":"date","required":true,"classification":"internal"},
                {"id":"valid-from","type":"date","required":true,"classification":"internal"},
                {"id":"valid-to","type":"date","classification":"internal"}
            ],
            "temporal": {"startField":"valid-from","endField":"valid-to"},
            "disclosureConditions":{"hide-inactive": {"when":[{"type":"field-equals","field":"active","value":false}],
                "withhold":"record","exemptProfiles":["analyst"]}}
        }},
        "accessProfiles": {
            "analyst": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["active","category","event-date","valid-from","valid-to"],
                "filterableFields":["active","category","event-date","valid-from","valid-to"],
                "allowCount":true,"rowBoundaries":"unrestricted"}],
              "datasets":[{"dataset":"records-by-category","operations":["read-live","read-releases"]}]}},
            "publisher": {"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
                "recordType":"record","operations":["list"],
                "readableFields":["active","category","event-date","valid-from","valid-to"],
                "filterableFields":["active","category","event-date","valid-from","valid-to"],
                "allowCount":true,"rowBoundaries":"unrestricted"}],
              "datasets":[{"dataset":"records-by-category","operations":["publish","read-releases"]}]}}
        },
        "vocabularies": {"category": {"values":["a","b"]}},
        "statisticalDatasets": {"records-by-category": {
            "unit":"record","population":"active eq true",
            "period":{"type":"flow","field":"event-date","granularity":"month","firstPeriod":"2025-01"},
            "dimensions":["category"],
            "disclosure":{"type":"minimum-count-and-rounding","minimumCount":5,"roundingBase":5}}}
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
    exempt["recordTypes"]["record"]["disclosureConditions"]["hide-inactive"]["exemptProfiles"] =
        json!(["analyst", "publisher"]);
    assert!(compile(&exempt).is_ok(), "{:?}", refusal(&exempt));
}

#[test]
fn a_dataset_cannot_release_a_field_withheld_from_a_reader() {
    let mut value = statistics_source();
    value["recordTypes"]["record"]["disclosureConditions"] = json!({"hide-category": {"when":[{"type":"field-equals","field":"active","value":false}],
        "withhold":"fields","fields":["category"],"exemptProfiles":["analyst"]}});
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
    project["accessProfiles"]["registrar"]["permissions"]["records"][0]["allowCount"] = json!(true);
    assert!(compile(&project).is_ok());
}

#[test]
fn a_reason_profile_cannot_hold_an_operation_that_does_not_check_the_reason() {
    const PROFILE: &str = "project.accessProfiles[id=registrar].permissions";
    let code = "breg.access-profile.access-reason-operation-unsupported";
    for operation in ["import", "invoke", "start"] {
        let mut project = source();
        project["accessProfiles"]["registrar"]["permissions"]["records"][0]["operations"] =
            json!(["get", operation]);
        assert_refused(
            &project,
            code,
            &format!("{PROFILE}.records[recordType=person].operations"),
        );
    }
    let mut actions = source();
    actions["accessProfiles"]["registrar"]["permissions"]["actions"] =
        json!([{"action":"close","operations":["invoke"]}]);
    assert_refused(&actions, code, &format!("{PROFILE}.actions"));
    let mut proposals = source();
    proposals["accessProfiles"]["registrar"]["permissions"]["proposals"] =
        json!([{"action":"close","operations":["get"]}]);
    assert_refused(&proposals, code, &format!("{PROFILE}.proposals"));
    let mut datasets = source();
    datasets["accessProfiles"]["registrar"]["permissions"]["datasets"] =
        json!([{"dataset":"counts","operations":["read-live"]}]);
    assert_refused(&datasets, code, &format!("{PROFILE}.datasets"));
    let mut views = source();
    views["accessProfiles"]["registrar"]["permissions"]["externalViews"] =
        json!([{"view":"directory","links":[]}]);
    assert_refused(&views, code, &format!("{PROFILE}.externalViews"));
    let mut refresh = source();
    refresh["accessProfiles"]["registrar"]["permissions"]["refreshExternalProjections"] =
        json!(["directory"]);
    assert_refused(
        &refresh,
        code,
        &format!("{PROFILE}.refreshExternalProjections"),
    );
}

#[test]
fn a_reason_profile_cannot_export_data() {
    let code = "breg.access-profile.access-reason-operation-unsupported";
    let mut project = source();
    // The export client sends no Registry-Access-Reason header, so the list
    // route would refuse every page.
    person_permission(&mut project, REGISTRAR)["allowDataExport"] = json!(true);
    assert_refused(
        &project,
        code,
        "project.accessProfiles[id=registrar].permissions.records[recordType=person].allowDataExport",
    );
    let mut without_reason = source();
    person_permission(&mut without_reason, OFFICER)["allowDataExport"] = json!(true);
    assert!(
        !has_code(&without_reason, code),
        "a profile without a reason requirement may export"
    );
}

/// A module contributes `profile` to `person` by extension.
fn with_module_profile(profile: Value) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    let module = registry_breg::contract::parse_module_yaml(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id":"extra","version":"1",
            "extendRecordTypes":{"person": {"accessProfiles":{"module-reader": profile}}}}))
        .unwrap(),
    )
    .unwrap();
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source()).unwrap()).unwrap(),
        &[module],
        CompileProfile::Authoring,
    )
}

fn module_profile(operations: Value, export: bool, reason: bool) -> Value {
    json!({"principalClaim":"registry_principal","requiredScopes":"unrestricted",
        "requireAccessReason":reason,"operations":operations,"readableFields":["family-name"],
        "rowBoundaries":"unrestricted","allowDataExport":export})
}

#[test]
fn a_module_reason_profile_cannot_hold_an_operation_that_does_not_check_the_reason() {
    let code = "breg.access-profile.access-reason-operation-unsupported";
    for operation in ["import", "invoke", "start"] {
        let found = codes(with_module_profile(module_profile(
            json!(["get", operation]),
            false,
            true,
        )));
        assert!(found.contains(&code.to_owned()), "{operation}: {found:?}");
    }
    let found = codes(with_module_profile(module_profile(
        json!(["get", "list"]),
        true,
        true,
    )));
    assert!(found.contains(&code.to_owned()), "export: {found:?}");
    let found = codes(with_module_profile(module_profile(
        json!(["get", "import"]),
        false,
        false,
    )));
    assert!(
        !found.contains(&code.to_owned()),
        "a profile without a reason requirement is unaffected: {found:?}"
    );
}

#[test]
fn a_profile_without_a_reason_requirement_may_import() {
    let mut project = source();
    project["accessProfiles"]["protection-officer"]["permissions"]["records"][0]["operations"] =
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

const REGISTRAR: &str = "registrar";
const OFFICER: &str = "protection-officer";

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

fn person_permission<'a>(value: &'a mut Value, profile: &str) -> &'a mut Value {
    &mut value["accessProfiles"][profile]["permissions"]["records"][0]
}

#[test]
fn a_required_field_or_the_canonical_id_cannot_be_withheld() {
    let mut required = source();
    required["recordTypes"]["person"]["fields"][4]["required"] = json!(true);
    assert_refused(
        &required,
        "breg.disclosure.fields-invalid",
        &format!("{FIELDS_COND}.fields[field=phone]"),
    );
    let mut canonical = source();
    conditions(&mut canonical)["hide-phone"]["fields"] = json!(["id"]);
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
    value["recordTypes"]["person"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(probe);
    value["vocabularies"] = json!({"probe-codes": {"values":["a","b"]}});
    conditions(&mut value).insert(
        "probe-condition".to_owned(),
        json!({"when":[{"type":"field-is-not-null","field":"probe"}],
            "withhold":"record","exemptProfiles":["protection-officer"]}),
    );
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
    value["recordTypes"]["person"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"location","type":"crs84-point","precision":6,"classification":"internal"}),
        );
    value["recordTypes"]["person"]["geojson"] = json!({"geometryField":"location"});
    conditions(&mut value)["hide-phone"]["fields"] = json!(["location"]);
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
    conditions(&mut value)["hide-phone"]["fields"] = json!(["age"]);
    assert_refused(
        &value,
        "breg.disclosure.row-boundary-withheld-field",
        &format!("{FIELDS_COND}.fields[field=age]"),
    );
    conditions(&mut value)["hide-phone"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!has_code(
        &value,
        "breg.disclosure.row-boundary-withheld-field"
    ));
}

#[test]
fn a_membership_boundary_cannot_read_a_withheld_field() {
    let mut value = membership_fixture::source("facility");
    let facility = &mut value["recordTypes"]["facility"];
    facility["fields"][0]["required"] = json!(false);
    facility["disclosureConditions"] = json!({"hide-organization": {"when":[{"type":"field-is-not-null","field":"label"}],
        "withhold":"fields","fields":["organization"],"exemptProfiles":["steward"]}});
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
    let mut value = consent_fixture::source();
    let consenting: Vec<String> = value["accessProfiles"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, profile)| {
            profile["permissions"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| {
                    record["recordType"] == "enrolment" && record.get("requireConsent").is_some()
                })
        })
        .map(|(id, _)| id.clone())
        .collect();
    let exempt = value["accessProfiles"]
        .as_object()
        .unwrap()
        .keys()
        .find(|id| !consenting.contains(*id))
        .cloned()
        .expect("a profile that does not require consent on enrolment");
    let enrolment = &mut value["recordTypes"]["enrolment"];
    for field in enrolment["fields"].as_array_mut().unwrap() {
        if field["id"] == "person" {
            field["required"] = json!(false);
        }
    }
    enrolment["disclosureConditions"] = json!({"hide-person": {"when":[{"type":"field-is-not-null","field":"programme"}],
        "withhold":"fields","fields":["person"],"exemptProfiles":[exempt]}});
    let found = consent_fixture::refusal_codes(&value);
    assert!(
        found.contains(&"breg.disclosure.consent-boundary-withheld-field".to_owned()),
        "{found:?}"
    );
}

/// The consent check of `requireConsent` reads the consent record type under
/// the gated profile, so a `record` condition there could hide a revocation
/// and let an earlier consent stand. Field and history conditions leave that
/// read whole.
#[test]
fn a_consent_record_cannot_carry_a_record_condition() {
    let with_condition = |withhold: Value| {
        let mut value = consent_fixture::source();
        let mut condition = json!({"when":[{"type":"field-equals","field":"decision","value":"withdrawn"}],
            "withhold": withhold, "exemptProfiles":["steward"]});
        if withhold == "fields" {
            condition["fields"] = json!(["expires-at"]);
        }
        value["recordTypes"][consent_fixture::CONSENT_RECORD]["disclosureConditions"] =
            json!({"hide-withdrawn": condition});
        value
    };
    let found = refusal(&with_condition(json!("record")));
    assert!(
        found.contains(&(
            "breg.disclosure.consent-record-condition".to_owned(),
            "recordTypes[id=consent-decision].disclosureConditions[id=hide-withdrawn]".to_owned()
        )),
        "{found:?}"
    );
    for withhold in ["fields", "history"] {
        let value = with_condition(json!(withhold));
        assert!(
            consent_fixture::compile(&value).is_ok(),
            "{withhold}: {:?}",
            refusal_or_empty(&value)
        );
    }
}

#[test]
fn a_read_path_cannot_run_through_a_withheld_reference() {
    let mut value = source();
    value["recordTypes"]["child"] = json!({"primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]});
    value["recordTypes"]["link"] = json!({"primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                      {"id":"child","type":"reference","target":"child","classification":"internal"},
                      {"id":"sealed","type":"boolean","classification":"internal"}],
            "disclosureConditions":{"hide-child": {"when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["child"],"exemptProfiles":["protection-officer"]}}});
    value["recordTypes"]["person"]["readPaths"] =
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
    value["recordTypes"]["link"]["disclosureConditions"]["hide-child"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!has_code(
        &value,
        "breg.disclosure.read-path-withheld-field"
    ));
}

/// A read path compiles the grant's filter and sort over the `to` record
/// type, and the filter runs before the reader withholds the field, so
/// `$filter=code eq 'guess'` would say whether a withheld value matches.
#[test]
fn a_read_path_cannot_filter_or_sort_a_withheld_target_field() {
    let mut value = source();
    value["recordTypes"]["child"] = json!({"primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                      {"id":"sealed","type":"boolean","classification":"internal"}],
            "disclosureConditions":{"hide-code": {"when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["code"],"exemptProfiles":["protection-officer"]}}});
    value["recordTypes"]["link"] = json!({"primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                      {"id":"child","type":"reference","target":"child","classification":"internal"}]});
    value["recordTypes"]["person"]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    let path = "recordTypes[id=child].disclosureConditions[id=hide-code].fields[field=code]";
    for surface in ["filterableFields", "sortableFields"] {
        let mut granted = value.clone();
        person_permission(&mut granted, REGISTRAR)["readPaths"] =
            json!([{"path":"children","readableFields":["code"], surface: ["code"]}]);
        let found = refusal_or_empty(&granted);
        assert!(
            found.contains(&(
                "breg.disclosure.read-path-withheld-field".to_owned(),
                path.to_owned()
            )),
            "{surface}: {found:?}"
        );
        granted["recordTypes"]["child"]["disclosureConditions"]["hide-code"]["exemptProfiles"] =
            json!(["protection-officer", "registrar"]);
        assert!(
            compile(&granted).is_ok(),
            "{surface}: {:?}",
            refusal_or_empty(&granted)
        );
    }
    // Reading the field through the path stays allowed: the reader withholds
    // it from the response.
    person_permission(&mut value, REGISTRAR)["readPaths"] = json!([{"path":"children","readableFields":["code","sealed"],"filterableFields":["sealed"]}]);
    assert!(compile(&value).is_ok(), "{:?}", refusal_or_empty(&value));
}

fn compile_with_sql(
    value: &Value,
    sql: &str,
) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_with_modules_and_sql(value, &[], sql)
}

fn compile_with_modules_and_sql(
    value: &Value,
    modules: &[RegistryModule],
    sql: &str,
) -> Result<CompiledRegistry, registry_breg::CompileFailure> {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(value).unwrap()).unwrap(),
        modules,
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
    value["recordTypes"]["person"]["derived"] = json!([{"id":"phone-state","sql":"sql/derived.sql","key":"id",
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
    conditions(&mut value)["hide-phone"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!codes(compile_with_sql(&value, sql))
        .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()));
}

#[test]
fn a_read_path_cannot_read_a_derived_field_that_reads_a_withheld_field() {
    let mut value = source();
    value["recordTypes"]["child"] = json!({"primaryDataset":"test-dataset","route":"children","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                      {"id":"sealed","type":"boolean","classification":"internal"}],
            "derived":[{"id":"code-state","sql":"sql/derived.sql","key":"id",
              "fields":[{"id":"has-code","type":"boolean","classification":"internal"}]}],
            "disclosureConditions":{"hide-code": {"when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["code"],"exemptProfiles":["protection-officer"]}}});
    value["recordTypes"]["link"] = json!({"primaryDataset":"test-dataset","route":"links","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                      {"id":"child","type":"reference","target":"child","classification":"internal"}]});
    value["recordTypes"]["person"]["readPaths"] =
        json!([{"id":"children","through":"link","to":"child","route":"children"}]);
    let sql = "SELECT c.id AS id, c.code IS NOT NULL AS has_code FROM registry_source.child c";
    for surface in ["filterableFields", "sortableFields"] {
        let mut granted = value.clone();
        person_permission(&mut granted, REGISTRAR)["readPaths"] = json!([{"path":"children","readableFields":["sealed","has-code"], surface: ["has-code"]}]);
        assert!(
            codes(compile_with_sql(&granted, sql))
                .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()),
            "{surface}"
        );
    }
    person_permission(&mut value, REGISTRAR)["readPaths"] =
        json!([{"path":"children","readableFields":["sealed","has-code"]}]);
    assert!(codes(compile_with_sql(&value, sql))
        .contains(&"breg.disclosure.derived-reads-withheld-field".to_owned()));
    let unrelated =
        "SELECT c.id AS id, c.sealed IS NOT NULL AS has_code FROM registry_source.child c";
    assert!(
        compile_with_sql(&value, unrelated).is_ok(),
        "{:?}",
        codes(compile_with_sql(&value, unrelated))
    );
    value["recordTypes"]["child"]["disclosureConditions"]["hide-code"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(
        compile_with_sql(&value, sql).is_ok(),
        "{:?}",
        codes(compile_with_sql(&value, sql))
    );
}

// A derived field is computed in the reader's request, under the reader's
// row security, so a record type its SQL reads besides the owner contributes
// only the rows the reader's own grant on it sees.

const UNREADABLE_SOURCE: &str = "breg.disclosure.derived-reads-unreadable-source";
const SOURCE_BOUNDARY: &str = "breg.disclosure.derived-reads-source-boundary";
const OTHER_OWNER_ROWS: &str = "breg.disclosure.derived-reads-other-owner-rows";
const VISIT_SQL: &str = "SELECT p.id AS id, (count(v.id) FILTER (WHERE v.outcome = 'closed') > 0) AS has_closed_visit FROM registry_source.person p LEFT JOIN registry_source.visit v ON v.person = p.id GROUP BY p.id";

/// A person-level derived field computed over `visit`, a record type that
/// links to the person. The registrar reads the derived field and holds no
/// grant on `visit`.
fn visit_source() -> Value {
    let mut value = source();
    value["recordTypes"]["visit"] = json!({"primaryDataset":"test-dataset","route":"visits","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                  {"id":"district","type":"string","maximumLength":32,"classification":"internal"},
                  {"id":"outcome","type":"string","maximumLength":32,"classification":"internal"}]});
    value["recordTypes"]["person"]["derived"] = json!([{"id":"visit-state","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"has-closed-visit","type":"boolean","classification":"internal"}]}]);
    person_permission(&mut value, REGISTRAR)["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("has-closed-visit"));
    value
}

/// The least grant that lets the registrar's requests read visits: `get`,
/// with only the link field readable.
fn grant_visits(value: &mut Value, row_boundaries: Value) {
    value["accessProfiles"][REGISTRAR]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"visit","operations":["get"],"rowBoundaries":row_boundaries,
            "readableFields":["person"]}),
        );
}

fn by_district() -> Value {
    json!([{"field":"district","claim":"district","operator":"equals"}])
}

fn derived_diagnostics(value: &Value, sql: &str) -> Vec<(String, String, String)> {
    diagnostics_of(compile_with_sql(value, sql))
}

fn diagnostics_of(
    result: Result<CompiledRegistry, registry_breg::CompileFailure>,
) -> Vec<(String, String, String)> {
    match result {
        Ok(_) => Vec::new(),
        Err(failure) => failure
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.clone(),
                    diagnostic.path.clone(),
                    diagnostic.message.clone(),
                )
            })
            .collect(),
    }
}

fn assert_compiles_with_sql(value: &Value, sql: &str) {
    let found = derived_diagnostics(value, sql);
    assert!(found.is_empty(), "{found:?}");
}

const WITHHELD_SOURCE_ROWS: &str = "breg.disclosure.derived-reads-withheld-source-rows";

/// The paths and messages of the withheld-source-rows findings a project that
/// must compile carries.
fn withheld_source_rows(
    result: Result<CompiledRegistry, registry_breg::CompileFailure>,
) -> Vec<(String, String)> {
    result
        .unwrap_or_else(|failure| panic!("{:?}", failure.diagnostics()))
        .findings()
        .iter()
        .filter(|finding| finding.code == WITHHELD_SOURCE_ROWS)
        .map(|finding| {
            assert_eq!(
                finding.severity,
                registry_breg::DiagnosticSeverity::Finding,
                "{finding:?}"
            );
            (finding.path.clone(), finding.message.clone())
        })
        .collect()
}

fn finding_paths(findings: &[(String, String)]) -> Vec<&str> {
    findings.iter().map(|(path, _)| path.as_str()).collect()
}

#[test]
fn a_derived_field_cannot_read_a_record_type_its_reader_cannot_read() {
    let mut value = visit_source();
    let found = derived_diagnostics(&value, VISIT_SQL);
    let (_, _, message) = found
        .iter()
        .find(|(code, path, _)| {
            code == UNREADABLE_SOURCE
                && path == "recordTypes[id=visit].accessProfiles[id=registrar].operations"
        })
        .unwrap_or_else(|| panic!("expected {UNREADABLE_SOURCE}, got {found:?}"));
    for named in ["`registrar`", "`has-closed-visit`", "`visit`", "`get`"] {
        assert!(message.contains(named), "{named} in {message}");
    }
    // A grant that cannot read rows holds no read policy either.
    value["accessProfiles"][REGISTRAR]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"visit","operations":["create"],"rowBoundaries":"unrestricted",
            "readableFields":["person"],"writableFields":["person","district","outcome"]}),
        );
    assert!(codes(compile_with_sql(&value, VISIT_SQL)).contains(&UNREADABLE_SOURCE.to_owned()));
}

#[test]
fn a_derived_field_may_read_a_record_type_under_the_same_row_boundaries() {
    let mut unrestricted = visit_source();
    grant_visits(&mut unrestricted, json!("unrestricted"));
    assert_compiles_with_sql(&unrestricted, VISIT_SQL);

    let mut bounded = visit_source();
    person_permission(&mut bounded, REGISTRAR)["rowBoundaries"] = by_district();
    grant_visits(&mut bounded, by_district());
    assert_compiles_with_sql(&bounded, VISIT_SQL);
}

/// The request installs the reader's boundary values for its grant on the
/// owner, and a grant on the source sees rows only when its own boundaries
/// name the same fields and operators in the same order. An unrestricted
/// source grant then sees no row at all.
#[test]
fn a_derived_field_cannot_read_a_record_type_under_other_row_boundaries() {
    let path = "recordTypes[id=visit].accessProfiles[id=registrar].rowBoundaries";
    for (reader, visits) in [
        (by_district(), json!("unrestricted")),
        (
            by_district(),
            json!([{"field":"district","claim":"region","operator":"equals"}]),
        ),
        (
            by_district(),
            json!([{"field":"district","claim":"district","operator":"in"}]),
        ),
        (
            by_district(),
            json!([{"field":"district","claim":"district","operator":"equals"},
                   {"field":"outcome","claim":"outcome","operator":"equals"}]),
        ),
        (json!("unrestricted"), by_district()),
    ] {
        let mut value = visit_source();
        person_permission(&mut value, REGISTRAR)["rowBoundaries"] = reader.clone();
        grant_visits(&mut value, visits.clone());
        let found = derived_diagnostics(&value, VISIT_SQL);
        let (_, _, message) = found
            .iter()
            .find(|(code, found, _)| code == SOURCE_BOUNDARY && found == path)
            .unwrap_or_else(|| panic!("{reader} over {visits}: got {found:?}"));
        for named in ["`registrar`", "`has-closed-visit`", "`visit`", "`person`"] {
            assert!(message.contains(named), "{named} in {message}");
        }
    }
}

/// A boundary on `id` names each record's own identity, which no linked row
/// of another record type shares.
#[test]
fn a_derived_field_cannot_read_another_record_type_for_a_reader_bounded_by_id() {
    let mut value = visit_source();
    let by_id = json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_id.clone();
    grant_visits(&mut value, by_id);
    assert!(derived_diagnostics(&value, VISIT_SQL)
        .iter()
        .any(|(code, path, _)| {
            code == SOURCE_BOUNDARY
                && path == "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries"
        }));
}

#[test]
fn a_derived_field_over_its_own_record_type_needs_no_other_grant() {
    let mut value = visit_source();
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    let own = "SELECT p.id AS id, p.age > 17 AS has_closed_visit FROM registry_source.person p";
    assert_compiles_with_sql(&value, own);
}

/// Readable fields limit the answer, not the computation: the grant on
/// `visit` need not make `outcome` readable for the derived field to read it.
#[test]
fn a_derived_field_may_read_source_fields_its_reader_cannot_read() {
    let mut value = visit_source();
    grant_visits(&mut value, json!("unrestricted"));
    let visits = &value["accessProfiles"][REGISTRAR]["permissions"]["records"][1];
    assert_eq!(visits["readableFields"], json!(["person"]));
    assert_compiles_with_sql(&value, VISIT_SQL);
}

/// A read path request installs the reader's boundary values for its grant on
/// the path's root, so the grant on the derived field's source must match
/// that grant.
#[test]
fn a_read_path_reader_must_read_the_derived_source_under_its_root_boundaries() {
    let mut value = visit_source();
    value["recordTypes"]["person"]
        .as_object_mut()
        .unwrap()
        .remove("derived");
    person_permission(&mut value, REGISTRAR)["readableFields"]
        .as_array_mut()
        .unwrap()
        .retain(|field| field != "has-closed-visit");
    value["recordTypes"]["dossier"] = json!({"primaryDataset":"test-dataset","route":"dossiers","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                  {"id":"code","type":"string","maximumLength":32,"classification":"internal"}],
        "derived":[{"id":"visit-state","sql":"sql/derived.sql","key":"id",
          "fields":[{"id":"has-closed-visit","type":"boolean","classification":"internal"}]}]});
    value["recordTypes"]["dossier-link"] = json!({"primaryDataset":"test-dataset","route":"dossier-links","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                  {"id":"dossier","type":"reference","target":"dossier","classification":"internal"}]});
    value["recordTypes"]["person"]["readPaths"] =
        json!([{"id":"dossiers","through":"dossier-link","to":"dossier","route":"dossiers"}]);
    person_permission(&mut value, REGISTRAR)["readPaths"] =
        json!([{"path":"dossiers","readableFields":["code","has-closed-visit"]}]);
    let sql = "SELECT c.id AS id, (count(v.id) FILTER (WHERE v.outcome = 'closed') > 0) AS has_closed_visit FROM registry_source.dossier c LEFT JOIN registry_source.visit v ON v.person = c.person GROUP BY c.id";
    assert!(codes(compile_with_sql(&value, sql)).contains(&UNREADABLE_SOURCE.to_owned()));

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    let mut unrestricted = value.clone();
    grant_visits(&mut unrestricted, json!("unrestricted"));
    assert!(codes(compile_with_sql(&unrestricted, sql)).contains(&SOURCE_BOUNDARY.to_owned()));
    grant_visits(&mut value, by_district());
    assert_compiles_with_sql(&value, sql);
}

/// The grant follows the derived relation, not the column: one SQL statement
/// computes every column of the relation, so reading one column needs the
/// rows of every record type the statement reads.
#[test]
fn reading_one_column_of_a_derived_relation_needs_every_source_it_reads() {
    let mut value = visit_source();
    value["recordTypes"]["referral"] = json!({"primaryDataset":"test-dataset","route":"referrals","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"}]});
    value["recordTypes"]["person"]["derived"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"has-referral","type":"boolean","classification":"internal"}));
    let sql = "SELECT p.id AS id, (count(v.id) FILTER (WHERE v.outcome = 'closed') > 0) AS has_closed_visit, (count(r.id) > 0) AS has_referral FROM registry_source.person p LEFT JOIN registry_source.visit v ON v.person = p.id LEFT JOIN registry_source.referral r ON r.person = p.id GROUP BY p.id";
    grant_visits(&mut value, json!("unrestricted"));
    let readable = &person_permission(&mut value, REGISTRAR)["readableFields"];
    assert!(readable
        .as_array()
        .unwrap()
        .contains(&json!("has-closed-visit")));
    assert!(!readable
        .as_array()
        .unwrap()
        .contains(&json!("has-referral")));

    let found = derived_diagnostics(&value, sql);
    let (_, _, message) = found
        .iter()
        .find(|(code, path, _)| {
            code == UNREADABLE_SOURCE
                && path == "recordTypes[id=referral].accessProfiles[id=registrar].operations"
        })
        .unwrap_or_else(|| panic!("expected {UNREADABLE_SOURCE} on referral, got {found:?}"));
    assert!(message.contains("`has-closed-visit`"), "{message}");
    assert!(
        !found.iter().any(|(code, path, _)| {
            [UNREADABLE_SOURCE, SOURCE_BOUNDARY].contains(&code.as_str())
                && path.contains("[id=visit]")
        }),
        "{found:?}"
    );

    value["accessProfiles"][REGISTRAR]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"referral","operations":["get"],"rowBoundaries":"unrestricted",
            "readableFields":["person"]}),
        );
    assert_compiles_with_sql(&value, sql);
}

/// Row boundaries are not judged one by one. The request installs the
/// reader's boundaries for its grant on the owner as one ordered list, and a
/// grant on the source sees a row only when its own list has the same length
/// and the same field and operator at each position. A source grant with
/// fewer boundaries than the reader's, or the same ones in another order,
/// therefore sees no row at all, not more rows.
#[test]
fn a_derived_field_cannot_read_a_record_type_under_a_subset_or_reordering_of_its_readers_boundaries(
) {
    let region = || json!({"field":"region","claim":"region","operator":"equals"});
    let district = || by_district()[0].clone();
    let reader = json!([district(), region()]);
    let path = "recordTypes[id=visit].accessProfiles[id=registrar].rowBoundaries";
    let with_region = || {
        let mut value = visit_source();
        for record_type in ["person", "visit"] {
            value["recordTypes"][record_type]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"region","type":"string","maximumLength":32,"classification":"internal"}));
        }
        person_permission(&mut value, REGISTRAR)["rowBoundaries"] = reader.clone();
        value
    };

    let mut same = with_region();
    grant_visits(&mut same, reader.clone());
    assert_compiles_with_sql(&same, VISIT_SQL);

    for visits in [
        json!([district()]),
        json!([region()]),
        json!("unrestricted"),
        json!([region(), district()]),
    ] {
        let mut value = with_region();
        grant_visits(&mut value, visits.clone());
        let found = derived_diagnostics(&value, VISIT_SQL);
        assert!(
            found
                .iter()
                .any(|(code, found, _)| code == SOURCE_BOUNDARY && found == path),
            "{visits}: got {found:?}"
        );
    }
}

/// A membership boundary is checked per row against the caller's own
/// memberships, so on a source grant it leaves out the source rows the
/// caller holds no membership for. That same grant governs the profile's
/// direct reads, where the boundary may be the point, so the project compiles
/// with a finding whether the reader's own grant carries the boundary or not,
/// on whatever field. A source grant that omits it raises none.
#[test]
fn a_membership_boundary_on_a_derived_source_grant_is_a_finding() {
    let mut value = membership_fixture::source("facility");
    value["recordTypes"]["inspection"] = json!({"primaryDataset":"test-dataset","route":"inspections","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"facility","type":"reference","target":"facility","classification":"internal"},
                  {"id":"organization","type":"reference","target":"organization","classification":"internal"},
                  {"id":"inspecting-organization","type":"reference","target":"organization","classification":"internal"},
                  {"id":"passed","type":"boolean","classification":"internal"}]});
    value["recordTypes"]["facility"]["derived"] = json!([{"id":"inspection-state","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"has-passed-inspection","type":"boolean","classification":"internal"}]}]);
    let sql = "SELECT f.id AS id, (count(i.id) FILTER (WHERE i.passed IS TRUE) > 0) AS has_passed_inspection FROM registry_source.facility f LEFT JOIN registry_source.inspection i ON i.facility = f.id GROUP BY f.id";
    let membership = json!([{"field":"organization","membershipRecordType":"membership",
        "membershipKeyField":"organization","principalField":"principal","activeField":"active"}]);
    let grant = |profile: &str, value: &mut Value, membership: Option<&Value>| {
        let records = value["accessProfiles"][profile]["permissions"]["records"]
            .as_array_mut()
            .unwrap();
        for record in records.iter_mut() {
            if record["recordType"] == "facility" {
                record["readableFields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("has-passed-inspection"));
            }
        }
        let mut inspection = json!({"recordType":"inspection","operations":["get"],
            "rowBoundaries":"unrestricted","readableFields":["facility"]});
        if let Some(membership) = membership {
            inspection["membershipBoundaries"] = membership.clone();
        }
        records.push(inspection);
    };

    let mut member = value.clone();
    grant("member", &mut member, None);
    assert!(withheld_source_rows(compile_with_sql(&member, sql)).is_empty());

    // The reader's grant on the facility carries the same membership.
    let mut member = value.clone();
    grant("member", &mut member, Some(&membership));
    let found = withheld_source_rows(compile_with_sql(&member, sql));
    assert_eq!(
        finding_paths(&found),
        ["recordTypes[id=inspection].accessProfiles[id=member].membershipBoundaries"]
    );
    for named in [
        "`member`",
        "`has-passed-inspection`",
        "`inspection`",
        "`membership`",
    ] {
        assert!(found[0].1.contains(named), "{named} in {found:?}");
    }

    // A membership on another field than the reader's own is a finding too.
    let mut member = value.clone();
    let mut other_field = membership.clone();
    other_field[0]["field"] = json!("inspecting-organization");
    grant("member", &mut member, Some(&other_field));
    assert_eq!(
        finding_paths(&withheld_source_rows(compile_with_sql(&member, sql))),
        ["recordTypes[id=inspection].accessProfiles[id=member].membershipBoundaries"]
    );

    // The steward's grant on the facility carries none.
    grant("steward", &mut value, Some(&membership));
    assert_eq!(
        finding_paths(&withheld_source_rows(compile_with_sql(&value, sql))),
        ["recordTypes[id=inspection].accessProfiles[id=steward].membershipBoundaries"]
    );
}

/// A consent requirement is checked per row against recorded consent, so on
/// a source grant it leaves out the source rows without it. As with a
/// membership boundary, the project compiles with a finding whether the
/// reader's own grant requires the same consent or not.
#[test]
fn a_consent_requirement_on_a_derived_source_grant_is_a_finding() {
    let path = "recordTypes[id=enrolment].accessProfiles[id=food-targeting].requireConsent";
    let value = consent_fixture::source();
    let derive = |value: &mut Value, owner: &str| {
        value["recordTypes"][owner]["derived"] = json!([{"id":"enrolment-state","sql":"sql/derived.sql","key":"id",
            "fields":[{"id":"has-enrolment","type":"boolean","classification":"internal"}]}]);
        let records = value["accessProfiles"]["food-targeting"]["permissions"]["records"]
            .as_array_mut()
            .unwrap();
        for record in records.iter_mut() {
            if record["recordType"] == owner {
                record["readableFields"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("has-enrolment"));
            }
        }
    };

    // The grants on person and on enrolment require the same consent record.
    let mut person = value.clone();
    derive(&mut person, "person");
    let found = withheld_source_rows(compile_with_sql(
        &person,
        "SELECT p.id AS id, (count(e.id) > 0) AS has_enrolment FROM registry_source.person p LEFT JOIN registry_source.enrolment e ON e.person = p.id GROUP BY p.id",
    ));
    assert_eq!(finding_paths(&found), [path]);
    for named in [
        "`food-targeting`",
        "`has-enrolment`",
        "`enrolment`",
        &format!("`{}`", consent_fixture::CONSENT_RECORD),
    ] {
        assert!(found[0].1.contains(named), "{named} in {found:?}");
    }

    // The grant on household requires none.
    let mut household = value;
    derive(&mut household, "household");
    household["accessProfiles"]["food-targeting"]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"enrolment-household","operations":["get"],
            "rowBoundaries":"unrestricted","readableFields":["household"]}),
        );
    let sql = "SELECT h.id AS id, (count(e.id) > 0) AS has_enrolment FROM registry_source.household h LEFT JOIN registry_source.enrolment_household l ON l.household = h.id LEFT JOIN registry_source.enrolment e ON e.id = l.enrolment GROUP BY h.id";
    assert_eq!(
        finding_paths(&withheld_source_rows(compile_with_sql(&household, sql))),
        [path]
    );
}

/// A module grant of `get` on visits to the registrar, unrestricted, under
/// `purposes` when any are given.
fn visit_module_grant(purposes: &[&str]) -> RegistryModule {
    let mut grant = json!({"principalClaim":"registry_principal","requiredScopes":"unrestricted",
        "operations":["get"],"readableFields":["person"],"rowBoundaries":"unrestricted"});
    if !purposes.is_empty() {
        grant["requiredPurposes"] = json!(purposes);
    }
    registry_breg::contract::parse_module_yaml(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id":"extra","version":"1",
            "extendRecordTypes":{"visit": {"accessProfiles":{REGISTRAR: grant}}}}))
        .unwrap(),
    )
    .unwrap()
}

/// A request runs under one purpose, and a grant that requires purposes sees
/// rows only under one of them. So a grant on the source must require no
/// purpose, or every purpose the reader's grant admits. A reader's grant that
/// requires none admits a request under any purpose, so then the source grant
/// must require none either.
#[test]
fn a_derived_field_cannot_read_a_record_type_under_purposes_its_reader_lacks() {
    let path = "recordTypes[id=visit].accessProfiles[id=registrar].requiredPurposes";
    for (reader, visits, refused) in [
        (&["service-delivery"][..], &["audit"][..], true),
        (&[][..], &["audit"][..], true),
        (&["service-delivery", "audit"][..], &["audit"][..], true),
        (&["service-delivery"][..], &[][..], false),
        (
            &["service-delivery"][..],
            &["service-delivery", "audit"][..],
            false,
        ),
        (&[][..], &[][..], false),
    ] {
        let mut value = visit_source();
        value["modules"] = json!({"extra":{"version":"1"}});
        if !reader.is_empty() {
            value["accessProfiles"][REGISTRAR]["requiredPurposes"] = json!(reader);
        }
        let found = diagnostics_of(compile_with_modules_and_sql(
            &value,
            &[visit_module_grant(visits)],
            VISIT_SQL,
        ));
        if refused {
            let (_, _, message) = found
                .iter()
                .find(|(code, found, _)| code == SOURCE_BOUNDARY && found == path)
                .unwrap_or_else(|| panic!("{reader:?} over {visits:?}: got {found:?}"));
            for named in ["`registrar`", "`has-closed-visit`", "`visit`", "`audit`"] {
                assert!(message.contains(named), "{named} in {message}");
            }
        } else {
            assert!(
                found.is_empty(),
                "{reader:?} over {visits:?}: got {found:?}"
            );
        }
    }
}

const SELF_JOIN_SQL: &str = "SELECT p.id AS id, count(q.id) AS household_size FROM registry_source.person p LEFT JOIN registry_source.person q ON q.district = p.district GROUP BY p.id";

/// A person-level derived field the registrar reads, computed by `sql`.
fn self_join_source() -> Value {
    let mut value = source();
    value["recordTypes"]["person"]["derived"] = json!([{"id":"household","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"household-size","type":"int64","classification":"internal"}]}]);
    person_permission(&mut value, REGISTRAR)["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("household-size"));
    value
}

/// A refusal of the owner as a source names the rewrite that keeps each owner
/// row apart. Its grant on the owner is the one the reader reads under, so
/// aligning a grant with it is no fix.
fn assert_names_the_owner_rewrite(message: &str, owner: &str) {
    for named in [
        format!("read `{owner}` once, in the top-level `FROM`, key on its own `id`"),
        "group or pick `DISTINCT ON` by nothing or by that `id`".to_owned(),
    ] {
        assert!(message.contains(&named), "{named} in {message}");
    }
    assert!(!message.contains("linked"), "{message}");
}

/// SQL that reads its owner's record type more than once reads rows besides
/// the one it computes for, and a reader bounded by `id` sees only that one.
/// A second read through a common table expression or a subquery counts.
#[test]
fn a_derived_field_that_reads_its_own_record_type_twice_cannot_serve_a_reader_bounded_by_id() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let mut value = self_join_source();
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    for sql in [
        SELF_JOIN_SQL,
        "WITH people AS (SELECT p.id AS id, p.district AS district FROM registry_source.person p) SELECT a.id AS id, count(b.id) AS household_size FROM people a LEFT JOIN people b ON b.district = a.district GROUP BY a.id",
        "SELECT p.id AS id, (SELECT count(q.id) FROM registry_source.person q WHERE q.district = p.district) AS household_size FROM registry_source.person p",
    ] {
        let found = derived_diagnostics(&value, sql);
        let (_, _, message) = found
            .iter()
            .find(|(code, found, _)| code == OTHER_OWNER_ROWS && found == path)
            .unwrap_or_else(|| panic!("{sql}: got {found:?}"));
        for named in ["`registrar`", "`household-size`", "`person`", "`id`"] {
            assert!(message.contains(named), "{named} in {message}");
        }
        assert_names_the_owner_rewrite(message, "person");
    }
    let once = "SELECT p.id AS id, p.age AS household_size FROM registry_source.person p";
    assert_compiles_with_sql(&value, once);

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    assert!(compile_with_sql(&value, SELF_JOIN_SQL).is_ok());
}

/// Thirty table expressions, each joining the one before it to itself, read
/// `person` 2^29 times. Counting those reads must not take that long: the
/// project still compiles promptly, with the same verdict as one self-join.
#[test]
fn a_long_chain_of_self_joined_table_expressions_compiles_promptly() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let mut ctes = vec!["c0 AS (SELECT p.id AS id FROM registry_source.person p)".to_owned()];
    for index in 1..30 {
        let previous = index - 1;
        ctes.push(format!(
            "c{index} AS (SELECT a.id AS id FROM c{previous} a JOIN c{previous} b ON b.id = a.id)"
        ));
    }
    let sql = format!(
        "WITH {} SELECT p.id AS id, count(x.id) AS household_size FROM registry_source.person p LEFT JOIN c29 x ON x.id = p.id GROUP BY p.id",
        ctes.join(", ")
    );
    let mut value = self_join_source();
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    let mut by_district_value = value.clone();
    person_permission(&mut by_district_value, REGISTRAR)["rowBoundaries"] = by_district();
    let (bounded_by_id, bounded_by_district) = finishes_within(30, move || {
        (
            derived_diagnostics(&value, &sql),
            derived_diagnostics(&by_district_value, &sql),
        )
    });
    let (_, _, message) = bounded_by_id
        .iter()
        .find(|(code, found, _)| code == OTHER_OWNER_ROWS && found == path)
        .unwrap_or_else(|| panic!("got {bounded_by_id:?}"));
    assert_names_the_owner_rewrite(message, "person");
    assert!(bounded_by_district.is_empty(), "{bounded_by_district:?}");
}

/// Run `work` on its own thread and fail the test if it has not finished
/// within `seconds`.
fn finishes_within<T: Send + 'static>(
    seconds: u64,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || sender.send(work()));
    receiver
        .recv_timeout(std::time::Duration::from_secs(seconds))
        .unwrap_or_else(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => {
                panic!("did not finish within {seconds} seconds")
            }
            std::sync::mpsc::RecvTimeoutError::Disconnected => panic!("panicked before finishing"),
        })
}

/// SQL that combines rows of its owner's record type in one read computes a
/// row's value from other rows too: here a head of household's count comes
/// from the people who name them. A reader bounded by `id` would see only its
/// own row, so the count would be silently wrong. Window functions are refused
/// for every reader, and a value computed from the row alone stays readable.
#[test]
fn a_derived_field_that_combines_its_own_rows_in_one_read_cannot_serve_a_reader_bounded_by_id() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let mut value = self_join_source();
    let fields = value["recordTypes"]["person"]["fields"]
        .as_array_mut()
        .unwrap();
    fields.push(
        json!({"id":"head","type":"reference","target":"person","classification":"internal"}),
    );
    fields.push(json!({"id":"birth-date","type":"date","classification":"internal"}));
    value["project"]["timezone"] = json!("UTC");
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    for sql in [
        "SELECT p.head AS id, count(p.id) AS household_size FROM registry_source.person p GROUP BY p.head",
        "SELECT DISTINCT p.head AS id, 1::int8 AS household_size FROM registry_source.person p",
    ] {
        let found = derived_diagnostics(&value, sql);
        let (_, _, message) = found
            .iter()
            .find(|(code, found, _)| code == OTHER_OWNER_ROWS && found == path)
            .unwrap_or_else(|| panic!("{sql}: got {found:?}"));
        for named in ["`registrar`", "`household-size`", "`person`", "`id`"] {
            assert!(message.contains(named), "{named} in {message}");
        }
        assert_names_the_owner_rewrite(message, "person");
    }
    let window = "SELECT p.id AS id, count(p.id) OVER (PARTITION BY p.district) AS household_size FROM registry_source.person p";
    assert!(
        codes(compile_with_sql(&value, window)).contains(&"breg.derived.sql-invalid".to_owned())
    );
    let age = "SELECT p.id AS id, (registry_context.evaluation_date() - p.birth_date) / 365 AS household_size FROM registry_source.person p";
    assert_compiles_with_sql(&value, age);

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    assert_compiles_with_sql(
        &value,
        "SELECT p.head AS id, count(p.id) AS household_size FROM registry_source.person p GROUP BY p.head",
    );
}

/// `DISTINCT ON` keeps one row among the owner rows that share a value, so the
/// row it keeps depends on the rows the reader sees. A reader bounded by `id`
/// sees only its own row and would find it kept every time. A reader under a
/// boundary the rows share sees them all.
#[test]
fn a_derived_field_that_picks_among_its_own_rows_cannot_serve_a_reader_bounded_by_id() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let mut value = self_join_source();
    value["recordTypes"]["person"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"head","type":"reference","target":"person","classification":"internal"}),
        );
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    let pick = "SELECT DISTINCT ON (p.head) p.id AS id, 1::int8 AS household_size FROM registry_source.person p ORDER BY p.head, p.id";
    let found = derived_diagnostics(&value, pick);
    let (_, _, message) = found
        .iter()
        .find(|(code, found, _)| code == OTHER_OWNER_ROWS && found == path)
        .unwrap_or_else(|| panic!("got {found:?}"));
    for named in ["`registrar`", "`household-size`", "`person`", "`id`"] {
        assert!(message.contains(named), "{named} in {message}");
    }
    assert_names_the_owner_rewrite(message, "person");
    // Naming the row's own `id` keeps every row.
    assert_compiles_with_sql(
        &value,
        "SELECT DISTINCT ON (p.id) p.id AS id, p.age AS household_size FROM registry_source.person p ORDER BY p.id, p.age",
    );

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    assert_compiles_with_sql(&value, pick);
}

/// A key other than the owner's own `id`, read directly, gives a row the value
/// computed from other owner rows, combined or not: here a person is a head
/// when someone names them. A reader bounded by `id` sees only its own row, so
/// the value would be silently wrong. A key read through a table expression or
/// a `FROM` subquery counts as another key too.
#[test]
fn a_derived_field_keyed_by_another_column_cannot_serve_a_reader_bounded_by_id() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let mut value = source();
    value["recordTypes"]["person"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"head","type":"reference","target":"person","classification":"internal"}),
        );
    value["recordTypes"]["person"]["derived"] = json!([{"id":"household","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"is-head","type":"boolean","classification":"internal"}]}]);
    person_permission(&mut value, REGISTRAR)["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("is-head"));
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] =
        json!([{"field":"id","claim":"person_id","operator":"equals"}]);
    let head = "SELECT p.head AS id, true AS is_head FROM registry_source.person p";
    for sql in [
        head,
        "WITH people AS (SELECT p.id AS id, p.age AS age FROM registry_source.person p) SELECT a.id AS id, a.age > 17 AS is_head FROM people a",
        "SELECT s.id AS id, true AS is_head FROM (SELECT p.id AS id FROM registry_source.person p) s",
    ] {
        let found = derived_diagnostics(&value, sql);
        let (_, _, message) = found
            .iter()
            .find(|(code, found, _)| code == OTHER_OWNER_ROWS && found == path)
            .unwrap_or_else(|| panic!("{sql}: got {found:?}"));
        for named in ["`registrar`", "`is-head`", "`person`", "`id`"] {
            assert!(message.contains(named), "{named} in {message}");
        }
        assert_names_the_owner_rewrite(message, "person");
    }
    for sql in [
        "SELECT p.id AS id, p.head IS NULL AS is_head FROM registry_source.person p",
        "SELECT id AS id, head IS NULL AS is_head FROM registry_source.person",
    ] {
        assert_compiles_with_sql(&value, sql);
    }

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    assert_compiles_with_sql(&value, head);
}

/// `LIMIT` or `OFFSET` on the rows a derived relation returns ranks them across
/// the whole Record type, so which rows get a value depends on the rows the
/// reader can see, under any boundary or none. That is refused for every
/// reader, also through a table expression or a `FROM` subquery. A correlated
/// subquery may still pick among one row's linked rows.
#[test]
fn a_derived_relation_cannot_limit_the_rows_it_returns() {
    let sql_path = "recordTypes[person].derived[household].sql";
    let mut value = self_join_source();
    for boundaries in [
        json!([{"field":"id","claim":"person_id","operator":"equals"}]),
        by_district(),
        json!("unrestricted"),
    ] {
        person_permission(&mut value, REGISTRAR)["rowBoundaries"] = boundaries;
        for sql in [
            "SELECT p.id AS id, 1::int8 AS household_size FROM registry_source.person p ORDER BY p.id LIMIT 10",
            "SELECT p.id AS id, 1::int8 AS household_size FROM registry_source.person p ORDER BY p.id OFFSET 10",
            "WITH early AS (SELECT p.id AS id FROM registry_source.person p ORDER BY p.id LIMIT 10) SELECT e.id AS id, 1::int8 AS household_size FROM early e",
            "SELECT e.id AS id, 1::int8 AS household_size FROM (SELECT p.id AS id FROM registry_source.person p ORDER BY p.id FETCH FIRST 10 ROWS ONLY) e",
        ] {
            let found = derived_diagnostics(&value, sql);
            assert!(
                found.iter().any(|(code, path, message)| code == "breg.derived.sql-invalid"
                    && path == sql_path
                    && message.contains("which rows the reader can see")),
                "{sql}: got {found:?}"
            );
        }
    }

    let mut visits = visit_source();
    person_permission(&mut visits, REGISTRAR)["rowBoundaries"] = by_district();
    grant_visits(&mut visits, by_district());
    assert_compiles_with_sql(
        &visits,
        "SELECT p.id AS id, (SELECT v.outcome = 'closed' FROM registry_source.visit v WHERE v.person = p.id ORDER BY v.id DESC LIMIT 1) AS has_closed_visit FROM registry_source.person p",
    );
}

/// A `record` condition on the owner hides rows from a second read of the
/// owner's record type as it does from a source's.
#[test]
fn a_record_condition_on_a_self_joined_owner_that_binds_the_reader_is_a_finding() {
    let value = self_join_source();
    let found = withheld_source_rows(compile_with_sql(&value, SELF_JOIN_SQL));
    assert_eq!(finding_paths(&found), [COND]);
    for named in ["`registrar`", "`household-size`", "`person`"] {
        assert!(found[0].1.contains(named), "{named} in {found:?}");
    }
    let once = "SELECT p.id AS id, p.age AS household_size FROM registry_source.person p";
    assert!(withheld_source_rows(compile_with_sql(&value, once)).is_empty());
}

/// A read path request installs the reader's boundary values for its grant on
/// the path's root, so SQL that reads the owner's record type more than once,
/// or combines its rows, needs the reader's own grant on the owner, under the
/// root's boundaries, as it would for any other source.
#[test]
fn a_read_path_reader_of_a_self_joined_derived_field_must_read_the_owner_under_its_root_boundaries()
{
    let mut value = source();
    value["recordTypes"]["dossier"] = json!({"primaryDataset":"test-dataset","route":"dossiers","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                  {"id":"district","type":"string","maximumLength":32,"classification":"internal"}],
        "derived":[{"id":"related","sql":"sql/derived.sql","key":"id",
          "fields":[{"id":"related-count","type":"int64","classification":"internal"}]}]});
    value["recordTypes"]["dossier-link"] = json!({"primaryDataset":"test-dataset","route":"dossier-links","mutationMode":"mutable","classification":"internal",
        "fields":[{"id":"person","type":"reference","target":"person","classification":"internal"},
                  {"id":"dossier","type":"reference","target":"dossier","classification":"internal"}]});
    value["recordTypes"]["person"]["readPaths"] =
        json!([{"id":"dossiers","through":"dossier-link","to":"dossier","route":"dossiers"}]);
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    person_permission(&mut value, REGISTRAR)["readPaths"] =
        json!([{"path":"dossiers","readableFields":["code","related-count"]}]);
    let twice = "SELECT c.id AS id, count(d.id) AS related_count FROM registry_source.dossier c LEFT JOIN registry_source.dossier d ON d.code = c.code GROUP BY c.id";
    // Grouping by the owner's `id` keeps each owner row apart.
    let once = "SELECT c.id AS id, count(c.id) AS related_count FROM registry_source.dossier c GROUP BY c.id";
    assert_compiles_with_sql(&value, once);
    let found = derived_diagnostics(&value, twice);
    let (_, _, message) = found
        .iter()
        .find(|(code, path, _)| {
            code == OTHER_OWNER_ROWS
                && path == "recordTypes[id=dossier].accessProfiles[id=registrar].operations"
        })
        .unwrap_or_else(|| panic!("{found:?}"));
    assert_names_the_owner_rewrite(message, "dossier");
    // A read path reader may instead read the owner under the root's boundaries.
    for named in [
        "grant it `get` on `dossier`",
        "`district` equals claim `district`",
    ] {
        assert!(message.contains(named), "{named} in {message}");
    }

    let grant_dossiers = |value: &mut Value, row_boundaries: Value| {
        value["accessProfiles"][REGISTRAR]["permissions"]["records"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"recordType":"dossier","operations":["get"],"rowBoundaries":row_boundaries,
                "readableFields":["code"]}),
            );
    };
    let mut unrestricted = value.clone();
    grant_dossiers(&mut unrestricted, json!("unrestricted"));
    let found = derived_diagnostics(&unrestricted, twice);
    let (_, _, message) = found
        .iter()
        .find(|(code, path, _)| {
            code == OTHER_OWNER_ROWS
                && path == "recordTypes[id=dossier].accessProfiles[id=registrar].rowBoundaries"
        })
        .unwrap_or_else(|| panic!("{found:?}"));
    assert_names_the_owner_rewrite(message, "dossier");
    grant_dossiers(&mut value, by_district());
    assert_compiles_with_sql(&value, twice);
}

/// A subquery that refers to no column of the row computes one value over
/// every row of the record type it reads that the reader sees, not over the
/// rows linked to the row. Under a grant on that type with row boundaries that
/// is part of the rows, so it is a finding. Under an unbounded grant the value
/// is exact, and it raises none.
#[test]
fn a_subquery_unlinked_to_the_row_is_a_finding_under_a_bounded_source_grant() {
    let unlinked = "SELECT p.id AS id, (SELECT count(v.id) > 0 FROM registry_source.visit v) AS has_closed_visit FROM registry_source.person p";
    let linked = "SELECT p.id AS id, (SELECT count(v.id) > 0 FROM registry_source.visit v WHERE v.person = p.id) AS has_closed_visit FROM registry_source.person p";
    let mut bounded = visit_source();
    person_permission(&mut bounded, REGISTRAR)["rowBoundaries"] = by_district();
    grant_visits(&mut bounded, by_district());
    let found = withheld_source_rows(compile_with_sql(&bounded, unlinked));
    assert_eq!(
        finding_paths(&found),
        ["recordTypes[id=visit].accessProfiles[id=registrar].rowBoundaries"]
    );
    for named in [
        "`registrar`",
        "`has-closed-visit`",
        "`visit`",
        "`district` equals claim `district`",
        "refers to no column of the row",
    ] {
        assert!(found[0].1.contains(named), "{named} in {found:?}");
    }
    for sql in [linked, VISIT_SQL] {
        assert!(
            withheld_source_rows(compile_with_sql(&bounded, sql)).is_empty(),
            "{sql}"
        );
    }

    let mut unrestricted = visit_source();
    grant_visits(&mut unrestricted, json!("unrestricted"));
    assert!(withheld_source_rows(compile_with_sql(&unrestricted, unlinked)).is_empty());
}

/// The owner's own record type, read in a subquery that refers to no column of
/// the row, gives the same finding under a bounded grant on the owner.
#[test]
fn a_subquery_unlinked_to_the_row_over_the_owner_is_a_finding_under_a_bounded_grant() {
    let path = "recordTypes[id=person].accessProfiles[id=registrar].rowBoundaries";
    let unlinked = "SELECT p.id AS id, (SELECT count(q.id) FROM registry_source.person q) AS household_size FROM registry_source.person p";
    let mut value = self_join_source();
    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = by_district();
    let found = withheld_source_rows(compile_with_sql(&value, unlinked));
    assert!(finding_paths(&found).contains(&path), "{found:?}");
    assert!(!finding_paths(&withheld_source_rows(compile_with_sql(
        &value,
        SELF_JOIN_SQL
    )))
    .contains(&path));

    person_permission(&mut value, REGISTRAR)["rowBoundaries"] = json!("unrestricted");
    assert!(
        !finding_paths(&withheld_source_rows(compile_with_sql(&value, unlinked))).contains(&path)
    );
}

/// A `record` condition on a source hides the rows it matches from every
/// profile it binds, the derived computation included. Hiding them may be the
/// point, so the project compiles with a finding. An exempt profile, and a
/// `fields` or `history` condition, which hide no current row, raise none.
#[test]
fn a_record_condition_on_a_derived_source_that_binds_the_reader_is_a_finding() {
    let path = "recordTypes[id=visit].disclosureConditions[id=hide-sealed]";
    let with_condition = |withhold: Value, exempt: Value| {
        let mut value = visit_source();
        grant_visits(&mut value, json!("unrestricted"));
        value["recordTypes"]["visit"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"sealed","type":"boolean","classification":"internal"}));
        let mut condition = json!({"when":[{"type":"field-equals","field":"sealed","value":true}],
            "exemptProfiles":exempt});
        for (member, value) in withhold.as_object().unwrap() {
            condition[member] = value.clone();
        }
        value["recordTypes"]["visit"]["disclosureConditions"] = json!({"hide-sealed": condition});
        value
    };

    let bound = with_condition(json!({"withhold":"record"}), json!([OFFICER]));
    let found = withheld_source_rows(compile_with_sql(&bound, VISIT_SQL));
    assert_eq!(finding_paths(&found), [path]);
    for named in ["`registrar`", "`has-closed-visit`", "`visit`"] {
        assert!(found[0].1.contains(named), "{named} in {found:?}");
    }

    for (withhold, exempt) in [
        (json!({"withhold":"record"}), json!([OFFICER, REGISTRAR])),
        (json!({"withhold":"history"}), json!([OFFICER])),
        (
            json!({"withhold":"fields","fields":["district"]}),
            json!([OFFICER]),
        ),
    ] {
        let value = with_condition(withhold.clone(), exempt);
        assert!(
            withheld_source_rows(compile_with_sql(&value, VISIT_SQL)).is_empty(),
            "{withhold}"
        );
    }
}

const LINKED: &str = r#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project: {id: linked-example, version: "1", defaultLanguage: en, canonicalBaseIri: "https://registry.example.test"}
datasets: {local-records: {}}
recordTypes:
  local-record:
    primaryDataset: local-records
    route: local-records
    mutationMode: mutable
    classification: internal
    fields:
      - {id: subject-key, type: string, maximumLength: 32, classification: internal}
      - {id: local-title, type: string, maximumLength: 120, classification: internal}
      - {id: sealed, type: boolean, classification: internal}
    disclosureConditions:
      hide-key:
        when: [{type: field-equals, field: sealed, value: true}]
        withhold: fields
        fields: [subject-key]
        exemptProfiles: [officer]
externalRecordTypes:
  external-subject:
    authority: urn:example:source
    identifierScheme: urn:example:subject-key
    fields:
      - {id: label, type: string, classification: internal}
externalProjections:
  approved-subjects:
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
  local-with-subject:
    recordType: local-record
    links:
      - id: subject
        projection: approved-subjects
        fromField: subject-key
accessProfiles:
  reader:
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
  officer:
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

const REFRESH_SKIPS: &str = "breg.disclosure.external-refresh-withheld-root";

/// The linked example with `withhold` and `exemptProfiles` of its root
/// condition replaced by `condition`, and a refresh service profile.
fn refreshed(condition: &str) -> String {
    LINKED
        .replace(
            "        withhold: fields\n        fields: [subject-key]\n        exemptProfiles: [officer]",
            condition,
        )
        .replace(
            "accessProfiles:\n",
            "accessProfiles:
  refresher:
    actorKind: service
    requesterClients: [refresh-worker]
    principalClaim: registry_principal
    requiredScopes: [registry.refresh]
    requiredPurposes: [local-consultation]
    permissions:
      records:
        - {recordType: local-record, operations: [get, list], readableFields: [local-title], rowBoundaries: unrestricted}
      refreshExternalProjections: [approved-subjects]
",
        )
}

/// The paths and messages of the refresh finding `source` compiles with.
fn refresh_findings(source: &str) -> Vec<(String, String)> {
    let project = registry_breg::contract::parse_project_yaml(source.as_bytes()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring)
        .unwrap_or_else(|failure| panic!("{:?}", failure.diagnostics()))
        .findings()
        .iter()
        .filter(|finding| finding.code == REFRESH_SKIPS)
        .map(|finding| {
            assert_eq!(
                finding.severity,
                registry_breg::DiagnosticSeverity::Finding,
                "{finding:?}"
            );
            (finding.path.clone(), finding.message.clone())
        })
        .collect()
}

/// A refresh lists the view's roots under the refreshing profile, so a
/// `record` condition that binds it leaves the records it matches out of the
/// refresh. Leaving protected subjects out may be intended, so the project
/// compiles with a finding. An exempt profile, and a `fields` or `history`
/// condition, which hide no row, raise none.
#[test]
fn a_record_condition_that_binds_a_refresh_profile_is_a_finding() {
    let bound = refreshed("        withhold: record\n        exemptProfiles: [officer]");
    let findings = refresh_findings(&bound);
    assert_eq!(findings.len(), 1, "{findings:?}");
    let (path, message) = &findings[0];
    assert_eq!(
        path,
        "recordTypes[id=local-record].disclosureConditions[id=hide-key]"
    );
    for named in ["`refresher`", "`local-with-subject`"] {
        assert!(message.contains(named), "{named}: {message}");
    }

    for condition in [
        "        withhold: record\n        exemptProfiles: [officer, refresher]",
        "        withhold: fields\n        fields: [local-title]\n        exemptProfiles: [officer]",
        "        withhold: history\n        exemptProfiles: [officer]",
    ] {
        assert_eq!(
            refresh_findings(&refreshed(condition)),
            Vec::<(String, String)>::new(),
            "{condition}"
        );
    }
}

fn live_statistics_source() -> Value {
    let mut value = statistics_source();
    value["recordTypes"]["record"]["disclosureConditions"]["hide-inactive"]["exemptProfiles"] =
        json!(["publisher"]);
    value
}

#[test]
fn a_live_statistics_read_is_refused_where_a_record_condition_binds_the_reader() {
    let mut value = live_statistics_source();
    assert_refused_code(&value, "breg.disclosure.statistics-live-bound");
    value["accessProfiles"]["analyst"]["permissions"]["datasets"] =
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
    value["recordTypes"]["record"]["disclosureConditions"]["hide-inactive"]["exemptProfiles"] =
        json!(["analyst", "publisher"]);
    value["recordTypes"]["record"]["derived"] = json!([{
        "id":"statistics","sql":"sql/derived.sql","key":"id",
        "fields":[{"id":"evaluated-category","type":"vocabulary-code","vocabulary":"category","values":["a","b"],"classification":"internal"}]
    }]);
    value["recordTypes"]["lookup"] = json!({
        "primaryDataset":"statistics-test","route":"lookups","mutationMode":"mutable",
        "fields":[{"id":"flag","type":"boolean","classification":"internal"}],
        "disclosureConditions":{"hide-flag": {"when":[{"type":"field-is-not-null","field":"flag"}],
          "withhold":"fields","fields":["flag"],"exemptProfiles":["publisher"]}}
    });
    value["accessProfiles"]["publisher"]["permissions"]["records"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"recordType":"lookup","operations":["list"],"readableFields":["flag"],
            "allowCount":true,"rowBoundaries":"unrestricted"}),
        );
    value["statisticalDatasets"]["records-by-category"]["dimensions"] =
        json!(["evaluated-category"]);
    let sql = "SELECT r.id AS id, CASE WHEN l.flag THEN 'a' ELSE 'b' END AS evaluated_category FROM registry_source.record r JOIN registry_source.lookup l ON l.id = r.id";
    let found = codes(compile_with_sql(&value, sql));
    assert!(
        found.contains(&"breg.disclosure.statistics-withheld-field".to_owned()),
        "{found:?}"
    );
    value["recordTypes"]["lookup"]["disclosureConditions"]["hide-flag"]["exemptProfiles"] =
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
        required_values: std::collections::BTreeMap::new(),
        optional_fields: Vec::new(),
    }
}

fn evidence_project(exempt: &str) -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "datasets":{"test-dataset": {}},
        "recordTypes":{"record": {"primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal"},
            {"id":"status","type":"string","maximumLength":16,"classification":"internal"},
            {"id":"sealed","type":"boolean","classification":"internal"}],
            "selectorProfiles":[{"id":"by-code","fields":["code"]}],
            "disclosureConditions":{"hide-status": {"when":[{"type":"field-equals","field":"sealed","value":true}],
              "withhold":"fields","fields":["status"],"exemptProfiles":[exempt]}}}},
        "accessProfiles":{
          "evidence-source": {"principalClaim":"principal","requiredScopes":["registry.read"],"permissions":{"records":[{
            "recordType":"record","operations":["lookup"],"readableFields":["code","status"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"}],"rowBoundaries":"unrestricted"}]}},
          "officer": {"principalClaim":"principal","requiredScopes":["registry.read"],"permissions":{"records":[{
            "recordType":"record","operations":["get"],"readableFields":["code","status"],
            "rowBoundaries":"unrestricted"}]}}}})
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
    let profiles = value["accessProfiles"].as_object_mut().unwrap();
    let officer = profiles.remove("protection-officer").unwrap();
    profiles.insert("system-record-timer".to_owned(), officer);
    conditions(&mut value)["hide-protected"]["exemptProfiles"] = json!(["registrar"]);
    conditions(&mut value)["hide-phone"]["exemptProfiles"] = json!(["registrar"]);
    assert_refused_code(&value, "breg.access-profile.system-id-reserved");
}

/// A person with a callback Record timer and a condition that withholds the
/// callback time and phone number from the registrar.
fn timer_source() -> Value {
    let mut value = source();
    let person = &mut value["recordTypes"]["person"];
    person["fields"].as_array_mut().unwrap().extend([
        json!({"id":"call-at","type":"timestamp","classification":"internal"}),
        json!({"id":"called","type":"boolean","classification":"internal"}),
        json!({"id":"call-note","type":"string","maximumLength":64,"classification":"internal"}),
        json!({"id":"call-revision","type":"int64","classification":"internal"}),
    ]);
    person["disclosureConditions"]["hide-callback"] = json!({"when":[{"type":"field-equals","field":"protected","value":true}],
            "withhold":"fields","fields":["call-at","called","call-revision"],"exemptProfiles":["protection-officer"]});
    person["timers"] = json!([{
        "id":"call-back","at":"district-call-at","invoke":"note-call",
        "input":{"person":{"fromRecordId":true},"note":{"fromField":"family-name"}}}]);
    person["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"district-call-at","type":"timestamp","classification":"internal"}));
    value["timerGrants"] = json!([{"recordType":"person","timer":"call-back"}]);
    value["actions"] = json!({"note-call": {
        "execution":{"mode":"immediate"},
        "inputs":[
            {"id":"person","type":"reference","target":"person","required":true,"classification":"internal"},
            {"id":"note","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
        "plan":{"type":"fixed","effects":[{"id":"noted","target":{"fromInput":"person"},
            "operation":"patch","set":{"call-note":{"fromInput":"note"}}}]}}});
    value
}

const CALLBACK_COND: &str = "recordTypes[id=person].disclosureConditions[id=hide-callback]";

fn timer(value: &mut Value) -> &mut Value {
    &mut value["recordTypes"]["person"]["timers"][0]
}

#[test]
fn a_record_timer_over_fields_no_condition_withholds_compiles() {
    compile(&timer_source()).expect("the timer reads no withheld field");
}

#[test]
fn a_record_timer_cannot_read_a_withheld_field_for_a_bound_profile() {
    let code = "breg.disclosure.timer-reads-withheld-field";

    let mut copied = timer_source();
    copied["recordTypes"]["person"]["fields"][4]["maximumLength"] = json!(64);
    timer(&mut copied)["input"]["note"] = json!({"fromField":"phone"});
    assert_refused(&copied, code, &format!("{FIELDS_COND}.fields[field=phone]"));

    let mut timed = timer_source();
    timer(&mut timed)["at"] = json!("call-at");
    assert_refused(
        &timed,
        code,
        &format!("{CALLBACK_COND}.fields[field=call-at]"),
    );

    let mut closed = timer_source();
    timer(&mut closed)["notAfter"] = json!("call-at");
    assert_refused(
        &closed,
        code,
        &format!("{CALLBACK_COND}.fields[field=call-at]"),
    );

    let mut rearmed = timer_source();
    timer(&mut rearmed)["rearmOn"] = json!("call-revision");
    assert_refused(
        &rearmed,
        code,
        &format!("{CALLBACK_COND}.fields[field=call-revision]"),
    );

    let mut predicated = timer_source();
    timer(&mut predicated)["when"] = json!({"type":"fields","equals":{"called":false}});
    assert_refused(
        &predicated,
        code,
        &format!("{CALLBACK_COND}.fields[field=called]"),
    );

    // A timer runs without any condition, so only exempting every profile the
    // condition would bind leaves the withheld value unreachable.
    let mut exempt = timed.clone();
    conditions(&mut exempt)["hide-callback"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!has_code(&exempt, code), "{:?}", refusal_or_empty(&exempt));
}

/// The timer fixture with a `call-log` Record type that the timer's Action
/// also creates, carrying the anchor's id and a value read from it.
fn logging_timer_source(log_readers: &[&str]) -> Value {
    let mut value = timer_source();
    value["recordTypes"]["call-log"] = json!({
        "primaryDataset":"test-dataset","route":"call-logs","mutationMode":"create-only",
        "classification":"internal",
        "fields":[
            {"id":"person","type":"reference","target":"person","required":true,"classification":"internal"},
            {"id":"noted","type":"string","maximumLength":64,"required":true,"classification":"internal"}]});
    value["actions"]["note-call"]["plan"]["effects"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"id":"logged","target":{"recordType":"call-log"},"operation":"create",
            "set":{"person":{"fromInput":"person"},"noted":{"fromInput":"note"}}}),
        );
    for (id, profile) in value["accessProfiles"].as_object_mut().unwrap() {
        if log_readers.contains(&id.as_str()) {
            profile["permissions"]["records"]
                .as_array_mut()
                .unwrap()
                .push(json!({"recordType":"call-log","operations":["get","list"],
                    "rowBoundaries":"unrestricted","readableFields":["person","noted"]}));
        }
    }
    value
}

#[test]
fn a_record_timer_cannot_create_a_record_a_profile_the_record_condition_binds_reads() {
    let code = "breg.disclosure.timer-creates-readable-record";

    // `hide-protected` withholds the whole person from the registrar, so a
    // call log the registrar reads would name a person it must not see.
    let read_by_bound = logging_timer_source(&["registrar"]);
    assert_refused(&read_by_bound, code, COND);

    // A log only an exempt profile reads reveals nothing past the condition.
    let read_by_exempt = logging_timer_source(&["protection-officer"]);
    compile(&read_by_exempt).expect("only an exempt profile reads the created record");

    // Exempting the reader from the record condition lifts the refusal.
    let mut exempt = read_by_bound.clone();
    conditions(&mut exempt)["hide-protected"]["exemptProfiles"] =
        json!(["protection-officer", "registrar"]);
    assert!(!has_code(&exempt, code), "{:?}", refusal_or_empty(&exempt));
}
