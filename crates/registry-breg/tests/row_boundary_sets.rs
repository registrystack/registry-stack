// SPDX-License-Identifier: Apache-2.0

//! Named row-boundary sets: `rowBoundarySets` declares a reusable list of
//! boundaries once, and `rowBoundaries: {rowBoundarySet: <id>}` reaches it
//! wherever a row reach is written. A grant still writes its own
//! `rowBoundaries`, so reach stays visible at every grant. A reference is
//! expanded when the file is read, and an empty list means every row, so a
//! reference never resolves to an empty list.

use registry_breg::contract::{parse_module_yaml, parse_project_yaml, RegistryProject};
use registry_breg::{compile_project, CompileFailure, CompileProfile, CompiledRegistry};
use serde_json::{json, Value};

const SET: &str = "same-district";
const REFERENCE_CODE: &str = "breg.row-boundary-set.reference-invalid";

fn boundary() -> Value {
    json!({"field":"district","claim":"districts","operator":"in"})
}

fn reference() -> Value {
    json!({"rowBoundarySet": SET})
}

/// A project that writes its row reach inline at every site: a record
/// permission, an Action target, a Proposal target and a record type's
/// access requirement.
fn inline() -> Value {
    json!({
        "datasets":{"test-dataset": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":"access-example","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://access-example.example.test"},
        "recordTypes":{"entry": {"primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
          "accessRequirements":{"rowBoundaries":[boundary()]},
          "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                    {"id":"district","type":"string","maximumLength":32,"classification":"internal"}]}},
        "accessProfiles":{"reader": {"principalClaim":"registry_principal","requiredScopes":["entry:read"],
          "permissions":{
            "records":[{"recordType":"entry","operations":["get","list"],
              "readableFields":["code","district"],"filterableFields":["district"],
              "rowBoundaries":[boundary()]}],
            "actions":[{"action":"register","operations":["invoke"],
              "targets":[{"recordType":"entry","rowBoundaries":[boundary()]}]}],
            "proposals":[{"action":"register","operations":["get"],"ownership":"caller",
              "targets":[{"recordType":"entry","rowBoundaries":[boundary()]}]}]
          }}}
    })
}

const SITES: [&str; 4] = [
    "/accessProfiles/reader/permissions/records/0/rowBoundaries",
    "/accessProfiles/reader/permissions/actions/0/targets/0/rowBoundaries",
    "/accessProfiles/reader/permissions/proposals/0/targets/0/rowBoundaries",
    "/recordTypes/entry/accessRequirements/rowBoundaries",
];

/// `inline()` with the set declared once and every site referencing it.
fn by_reference() -> Value {
    let mut value = inline();
    value["rowBoundarySets"] = json!({ SET: [boundary()] });
    for site in SITES {
        set(&mut value, site, reference());
    }
    value
}

fn set(value: &mut Value, pointer: &str, written: Value) {
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("{pointer} exists")) = written;
}

fn read(value: &Value) -> Result<RegistryProject, CompileFailure> {
    parse_project_yaml(&serde_json::to_vec(value).unwrap())
}

fn compile(value: &Value) -> Result<CompiledRegistry, CompileFailure> {
    compile_project(&read(value)?, &[], CompileProfile::Authoring)
}

/// The one refusal a read answers with, as its code, path, and message.
fn refusal(value: &Value) -> (String, String, String) {
    let failure = read(value).expect_err("the project is refused when it is read");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the project: {failure:?}");
    };
    (
        diagnostic.code.clone(),
        diagnostic.path.clone(),
        diagnostic.message.clone(),
    )
}

/// Compiling needs the Actions the grants name, so a compiled comparison keeps
/// the record permission and the record type's requirement.
fn compilable(mut value: Value) -> Value {
    let permissions = value["accessProfiles"]["reader"]["permissions"]
        .as_object_mut()
        .unwrap();
    permissions.remove("actions");
    permissions.remove("proposals");
    value
}

#[test]
fn a_reference_reads_as_the_inline_list_at_every_site() {
    let referenced = read(&by_reference()).expect("a reference is accepted at every site");
    let written = read(&inline()).expect("the inline form is accepted");
    assert_eq!(
        serde_json::to_value(&referenced).unwrap(),
        serde_json::to_value(&written).unwrap(),
        "a reference expands to the boundaries the set lists, and the set is not part of the read project"
    );
    let compiled = compile(&compilable(by_reference())).expect("the referenced project compiles");
    let inline_compiled = compile(&compilable(inline())).expect("the inline project compiles");
    assert_eq!(
        serde_json::to_value(&compiled).unwrap(),
        serde_json::to_value(&inline_compiled).unwrap(),
        "the compiled model does not record where a boundary was written"
    );
    let permission = &referenced.access_profiles[0].permissions;
    assert_eq!(permission.entities[0].row_boundaries.len(), 1);
    assert_eq!(permission.actions[0].targets[0].row_boundaries.len(), 1);
    assert_eq!(permission.proposals[0].targets[0].row_boundaries.len(), 1);
    assert_eq!(
        referenced.entities[0]
            .access_requirements
            .as_ref()
            .expect("the record type carries its requirement")
            .row_boundaries
            .len(),
        1
    );
}

#[test]
fn each_site_takes_the_reference_on_its_own() {
    for site in SITES {
        let mut value = inline();
        value["rowBoundarySets"] = json!({ SET: [boundary()] });
        set(&mut value, site, reference());
        let project = read(&value).unwrap_or_else(|failure| panic!("{site}: {failure:?}"));
        assert_eq!(
            serde_json::to_value(&project).unwrap(),
            serde_json::to_value(read(&inline()).unwrap()).unwrap(),
            "{site}"
        );
    }
}

#[test]
fn an_unknown_set_is_refused_at_the_reference() {
    let mut value = by_reference();
    set(
        &mut value,
        SITES[0],
        json!({"rowBoundarySet": "no-such-set"}),
    );
    let (code, path, message) = refusal(&value);
    assert_eq!(code, REFERENCE_CODE, "{message}");
    assert!(
        path.ends_with("permissions.records[0].rowBoundaries.rowBoundarySet"),
        "{path}"
    );

    // No declaration at all is the same refusal, never an unrestricted read.
    let mut undeclared = inline();
    set(&mut undeclared, SITES[0], reference());
    let (code, _, message) = refusal(&undeclared);
    assert_eq!(code, REFERENCE_CODE, "{message}");
}

#[test]
fn a_reference_is_a_mapping_with_one_string_member() {
    for written in [
        json!({"rowBoundarySet": SET, "field": "district"}),
        json!({"rowBoundarySet": ["a"]}),
        json!({"rowBoundarySet": 3}),
    ] {
        let mut value = by_reference();
        set(&mut value, SITES[0], written);
        let (code, _, message) = refusal(&value);
        assert_eq!(code, REFERENCE_CODE, "{message}");
    }
}

#[test]
fn a_set_lists_at_least_one_boundary_and_is_never_unrestricted() {
    for written in [json!([]), json!("unrestricted")] {
        let mut value = by_reference();
        value["rowBoundarySets"][SET] = written;
        let (code, path, message) = refusal(&value);
        assert_eq!(code, "config.invalid-value", "{message}");
        assert_eq!(path, format!("project.rowBoundarySets.{SET}"));
        assert!(
            message.contains("at least one row boundary"),
            "the refusal says what a set holds: {message}"
        );
    }
}

#[test]
fn an_unresolved_reference_never_decodes_to_an_empty_list() {
    // The reader expands references before typed decoding. A path that
    // reaches the typed model without it must be refused, because an empty
    // list means every row.
    serde_json::from_value::<RegistryProject>(inline())
        .expect("the same project written inline decodes, so only the reference is refused");
    let value = by_reference();
    let decoded = serde_json::from_value::<RegistryProject>(value);
    let error = decoded.expect_err("a reference that reaches the typed model is refused");
    assert!(
        error.to_string().contains("a row boundary set reference"),
        "the typed model names the unexpanded reference: {error}"
    );
}

/// A structured field whose schema literal holds a mapping shaped like a
/// reference. The shape is schema data here, not a row reach.
fn with_reference_shaped_literal(mut value: Value, name: &str) -> Value {
    value["recordTypes"]["entry"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"payload","type":"structured","maximumBytes":256,"classification":"internal",
          "schema":{"type":"object","additionalProperties":false,
                    "const":{"rowBoundaries":{"rowBoundarySet": name}}}}));
    value
}

#[test]
fn a_reference_shaped_schema_literal_is_data_and_never_a_reference() {
    const LITERAL: &str = "/recordTypes/entry/fields/2/schema/const";
    for (declared, name) in [(false, "no-such-set"), (true, SET)] {
        let mut value = with_reference_shaped_literal(inline(), name);
        if declared {
            value["rowBoundarySets"] = json!({ SET: [boundary()] });
        }
        let parsed = read(&value).expect("a schema literal is not a row boundary reference");
        let written = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            written.pointer(LITERAL),
            Some(&json!({"rowBoundaries":{"rowBoundarySet": name}})),
            "the literal is kept as written (set declared: {declared})"
        );
    }
}

#[test]
fn a_reference_shaped_schema_literal_beside_a_real_reference_stays_unchanged() {
    let value = with_reference_shaped_literal(by_reference(), SET);
    let parsed = read(&value).expect("references and literals read together");
    let written = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        written.pointer("/recordTypes/entry/fields/2/schema/const"),
        Some(&json!({"rowBoundaries":{"rowBoundarySet": SET}}))
    );
    assert_eq!(
        written.pointer("/accessProfiles/reader/permissions/records/0/rowBoundaries"),
        Some(&json!([boundary()]))
    );
}

#[test]
fn a_module_profile_takes_the_reference_where_it_writes_its_reach() {
    let module = serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
        "id":"extra","version":"1",
        "rowBoundarySets":{ SET: [boundary()] },
        "extendRecordTypes":{"entry": {"accessProfiles":{"auditor":{
            "principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "operations":["get"],"readableFields":["code"],
            "rowBoundaries": reference()}}}}
    }))
    .unwrap();
    let parsed = parse_module_yaml(&module).expect("a module profile reaches its own set");
    let written = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        written.pointer("/extendRecordTypes/entry/accessProfiles/auditor/rowBoundaries"),
        Some(&json!([boundary()]))
    );
}

#[test]
fn a_set_field_missing_on_the_record_type_is_refused_as_an_inline_boundary_is() {
    let mut referenced = compilable(by_reference());
    referenced["rowBoundarySets"][SET][0]["field"] = json!("missing");
    let mut written = compilable(inline());
    for site in [SITES[0], SITES[3]] {
        written.pointer_mut(site).unwrap()[0]["field"] = json!("missing");
    }
    let by_set = compile(&referenced).expect_err("a boundary on a missing field is refused");
    let by_hand = compile(&written).expect_err("a boundary on a missing field is refused");
    let summarize = |failure: &CompileFailure| {
        failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.message.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(summarize(&by_set), summarize(&by_hand));
    let codes: Vec<_> = summarize(&by_set)
        .into_iter()
        .map(|(code, _)| code)
        .collect();
    for expected in [
        "breg.access-profile.field-unknown",
        "breg.access.requirements-row-boundary-invalid",
    ] {
        assert!(
            codes.iter().any(|code| code == expected),
            "the refusal carries {expected}: {codes:?}"
        );
    }
}

#[test]
fn unrestricted_inline_lists_and_omission_keep_their_meaning() {
    let mut value = by_reference();
    set(&mut value, SITES[0], json!("unrestricted"));
    set(&mut value, SITES[1], json!([boundary()]));
    let project = read(&value).expect("the three forms sit beside each other");
    let permissions = &project.access_profiles[0].permissions;
    assert!(permissions.entities[0].row_boundaries.is_empty());
    assert_eq!(permissions.actions[0].targets[0].row_boundaries.len(), 1);
    assert_eq!(permissions.proposals[0].targets[0].row_boundaries.len(), 1);

    let mut omitted = by_reference();
    omitted
        .pointer_mut("/accessProfiles/reader/permissions/records/0")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove("rowBoundaries");
    let (code, _, message) = refusal(&omitted);
    assert_eq!(code, "config.invalid-value", "{message}");
    assert!(
        message.contains("write unrestricted to reach every row"),
        "{message}"
    );
}

#[test]
fn a_module_resolves_its_own_sets_and_never_the_projects() {
    let module = |set_declared: bool| {
        let mut module = json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
            "id":"extra","version":"1",
            "extendRecordTypes":{"entry": {"accessRequirements":{"rowBoundaries": reference()}}}
        });
        if set_declared {
            module["rowBoundarySets"] = json!({ SET: [boundary()] });
        }
        serde_json::to_vec(&module).unwrap()
    };
    let parsed = parse_module_yaml(&module(true)).expect("a module reaches its own set");
    let written = serde_json::to_value(&parsed).unwrap();
    assert_eq!(
        written.pointer("/extendRecordTypes/entry/accessRequirements/rowBoundaries"),
        Some(&json!([boundary()]))
    );
    assert!(written.get("rowBoundarySets").is_none());

    let failure = parse_module_yaml(&module(false))
        .expect_err("a module does not see a set its project declares");
    let [diagnostic] = failure.diagnostics() else {
        panic!("one diagnostic refuses the module: {failure:?}");
    };
    assert_eq!(diagnostic.code, REFERENCE_CODE);
}

#[test]
fn the_authoring_schema_accepts_the_reference_and_the_set_declaration() {
    let schema = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/generated/authoring/registry-project.schema.json"),
    )
    .expect("the generated authoring schema is committed");
    let schema: Value = serde_json::from_str(&schema).unwrap();
    assert!(
        schema.pointer("/properties/rowBoundarySets").is_some(),
        "the project schema declares rowBoundarySets"
    );
    let text = schema.to_string();
    assert!(
        text.contains("\"rowBoundarySet\""),
        "the schema describes the reference mapping"
    );
}
