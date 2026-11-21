// SPDX-License-Identifier: Apache-2.0

//! Compile-time rules for `requiredFilters` on a record permission grant.

use registry_breg::model::CompiledQueryKind;
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

fn source(required_filters: Value, operations: Value) -> Value {
    json!({"datasets":{"test-dataset": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"required-filters","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://required-filters.example.test"},
        "recordTypes":{"person": {"primaryDataset":"test-dataset","route":"people","mutationMode":"mutable","classification":"internal",
          "fields":[{"id":"national-id","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"family-name","type":"string","maximumLength":64,"classification":"internal"},
                    {"id":"birth-date","type":"date","classification":"internal"},
                    {"id":"district","type":"string","maximumLength":32,"classification":"internal"}]}},
        "accessProfiles":{"registrar": {"default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
          "permissions":{"records":[{"recordType":"person","operations":operations,
            "rowBoundaries":"unrestricted",
            "readableFields":["national-id","family-name","birth-date","district"],
            "filterableFields":["national-id","family-name","birth-date"],
            "requiredFilters":required_filters}]}}}
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
        .expect_err("the grant is refused")
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

#[test]
fn alternatives_compile_onto_the_list_family_only() {
    let mut value = source(
        json!([{"fields":["national-id"]},{"fields":["family-name","birth-date"]}]),
        json!(["get", "list"]),
    );
    value["recordTypes"]["person"]["temporal"] = Value::Null;
    value["recordTypes"]["person"]
        .as_object_mut()
        .unwrap()
        .remove("temporal");
    let registry = compile(&value).expect("valid alternatives compile");
    // An alternative is a set, so it compiles in field order.
    let expected = vec![
        vec!["national-id".to_owned()],
        vec!["birth-date".to_owned(), "family-name".to_owned()],
    ];
    let lists = registry
        .queries()
        .operations
        .iter()
        .filter(|operation| operation.kind == CompiledQueryKind::List)
        .collect::<Vec<_>>();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].required_filters, expected);
}

#[test]
fn a_grant_without_required_filters_compiles_to_none() {
    let mut value = source(json!([]), json!(["get", "list"]));
    value["accessProfiles"]["registrar"]["permissions"]["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("requiredFilters");
    let registry = compile(&value).expect("grant compiles");
    assert!(registry
        .queries()
        .operations
        .iter()
        .all(|operation| operation.required_filters.is_empty()));
}

#[test]
fn lookups_and_gets_are_not_governed() {
    let mut value = source(
        json!([{"fields":["national-id"]}]),
        json!(["get", "list", "lookup"]),
    );
    value["recordTypes"]["person"]["selectorProfiles"] =
        json!([{"id":"by-national-id","fields":["national-id"]}]);
    value["accessProfiles"]["registrar"]["permissions"]["records"][0]["lookups"] =
        json!([{"selector":"by-national-id","valueOrigin":"request"}]);
    let registry = compile(&value).expect("lookup grant compiles");
    for operation in &registry.queries().operations {
        if operation.selector_fields.is_empty() {
            assert_eq!(operation.required_filters.len(), 1, "{}", operation.id);
        } else {
            assert!(operation.required_filters.is_empty(), "{}", operation.id);
        }
    }
}

#[test]
fn invalid_required_filters_are_refused_with_a_code_and_path() {
    let base = "recordTypes[id=person].accessProfiles[id=registrar].requiredFilters";
    let cases = [
        (
            json!([{"fields":["national-id"]}]),
            json!(["get"]),
            "breg.access-profile.required-filters-list-required",
            base.to_owned(),
        ),
        (
            json!([{"fields":["district"]}]),
            json!(["list"]),
            "breg.access-profile.required-filters-field-not-filterable",
            format!("{base}[0].fields[field=district]"),
        ),
        (
            json!([{"fields":[]}]),
            json!(["list"]),
            "breg.access-profile.required-filters-empty",
            format!("{base}[0].fields"),
        ),
        (
            json!([{"fields":["national-id","family-name"]},{"fields":["family-name","national-id"]}]),
            json!(["list"]),
            "breg.access-profile.required-filters-duplicate",
            format!("{base}[1]"),
        ),
        (
            json!((0..9)
                .map(|_| json!({"fields":["national-id"]}))
                .collect::<Vec<_>>()),
            json!(["list"]),
            "breg.access-profile.required-filters-too-many",
            base.to_owned(),
        ),
    ];
    for (required, operations, code, path) in cases {
        let found = refusal(&source(required, operations));
        assert!(
            found.contains(&(code.to_owned(), path.clone())),
            "expected {code} at {path}, got {found:?}"
        );
    }
}

#[test]
fn an_alternative_no_filter_can_carry_is_refused() {
    // A `$filter` holds at most 32 predicates, so an alternative of 33 fields
    // could never be met.
    let fields = (0..33)
        .map(|index| format!("code-{index}"))
        .collect::<Vec<_>>();
    let mut value = source(json!([{"fields": fields}]), json!(["list"]));
    let person = &mut value["recordTypes"]["person"];
    for field in &fields {
        person["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": field,
            "type": "string", "maximumLength": 32, "classification": "internal"}));
    }
    let grant = &mut value["accessProfiles"]["registrar"]["permissions"]["records"][0];
    grant["readableFields"] = json!(fields);
    grant["filterableFields"] = json!(fields);
    let found = refusal(&value);
    let expected = (
        "breg.access-profile.required-filters-too-many".to_owned(),
        "recordTypes[id=person].accessProfiles[id=registrar].requiredFilters[0].fields".to_owned(),
    );
    assert!(
        found.contains(&expected),
        "expected {expected:?}, got {found:?}"
    );
}

#[test]
fn an_empty_list_of_alternatives_is_refused_by_the_reader() {
    // An empty list reads as both "no criteria" and "no list passes", so an
    // author omits the member to put no criteria on lists.
    let value = source(json!([]), json!(["list"]));
    let failure = parse_project_json(&serde_json::to_vec(&value).unwrap())
        .expect_err("an empty requiredFilters is refused rather than read as absent");
    let found = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        vec![(
            "config.invalid-value",
            "project.accessProfiles.registrar.permissions.records[0].requiredFilters"
        )],
        "{failure:?}"
    );
    assert!(
        failure.diagnostics()[0]
            .message
            .contains("Omit requiredFilters"),
        "{failure:?}"
    );
}

#[test]
fn a_repeated_field_inside_an_alternative_is_refused_by_the_reader() {
    let value = source(
        json!([{"fields":["national-id","national-id"]}]),
        json!(["list"]),
    );
    let failure = parse_project_json(&serde_json::to_vec(&value).unwrap())
        .expect_err("a repeated field is refused rather than collapsed");
    let found = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        vec![(
            "config.duplicate-item",
            "project.accessProfiles.registrar.permissions.records[0].requiredFilters[0].fields[1]"
        )],
        "{failure:?}"
    );
}

#[test]
fn an_unknown_member_inside_an_alternative_is_refused() {
    let value = source(
        json!([{"fields":["national-id"],"operator":"eq"}]),
        json!(["list"]),
    );
    let failure = parse_project_json(&serde_json::to_vec(&value).unwrap())
        .expect_err("unknown members are refused");
    assert_eq!(failure.diagnostics()[0].code, "config.unknown-key");
}
