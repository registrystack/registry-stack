// SPDX-License-Identifier: Apache-2.0
//! `choose: {type: compare}`: a decision on typed values without a Function.
//! The definition refuses malformed compares at check, the host evaluates the
//! tests in order, and a value that is missing or of the wrong type fails the
//! run instead of routing to `unmatched`.
use registry_coordinator::{authoring, definition::Definition, scenarios, CoordinatorError};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

const CANARY: &str = "private-canary-value";

fn project(compare: Value) -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {"id": "compared", "version": "1"},
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": ["hectares", "tier", "visitDate"],
                "properties": {
                    "hectares": {"type": "number"},
                    "parcels": {"type": "integer"},
                    "tier": {"type": "string"},
                    "visitDate": {"type": "string", "format": "date"},
                    "note": {"type": "string"},
                    "extent": {"type": "number"},
                    "followUp": {"type": "string", "format": "date"},
                    "active": {"type": "boolean"}
                }
            },
            "deadlineSeconds": 86400,
            "start": "size",
            "steps": {
                "size": {
                    "type": "choose",
                    "choose": compare,
                    "cases": {"matched": "large", "unmatched": "small"}
                },
                "large": {"type": "finish", "outcome": "large"},
                "small": {"type": "finish", "outcome": "small"}
            },
            "outcomes": {"large": {"type": "null"}, "small": {"type": "null"}}
        }
    })
}

fn input(path: &str) -> Value {
    json!({"type": "input", "path": path})
}

fn all(conditions: Value) -> Value {
    json!({"type": "compare", "all": conditions})
}

fn any(conditions: Value) -> Value {
    json!({"type": "compare", "any": conditions})
}

fn base_input() -> Value {
    json!({"hectares": 3.5, "parcels": 4, "tier": "gold", "visitDate": "2026-02-01", "active": true})
}

fn load(project: &Value) -> registry_coordinator::Result<Definition> {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string(project).unwrap(),
    )
    .unwrap();
    Definition::load(root.path())
}

fn refused(project: &Value) -> CoordinatorError {
    match load(project) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn parse_refused(project: &Value) -> CoordinatorError {
    match authoring::parse_project(Path::new("workflow.yaml"), project.to_string()) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn assert_finding(error: &CoordinatorError, code: &str, path: &str, message: &str) {
    assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
    let finding: &Diagnostic = &error.diagnostics[0];
    assert_eq!(finding.code, code, "{finding:#?}");
    assert_eq!(finding.path, path, "{finding:#?}");
    assert_eq!(finding.message, message);
    assert!(!finding.suggested_action.is_empty(), "{finding:#?}");
    assert!(finding.source.as_ref().unwrap().line.is_some());
}

/// The label a compare step chooses over this input.
fn choose(compare: Value, input: &Value) -> registry_coordinator::Result<Value> {
    load(&project(compare))
        .unwrap()
        .evaluate("size", input, &BTreeMap::new())
}

fn matches(compare: Value, input: &Value) -> bool {
    match choose(compare, input).unwrap().as_str().unwrap() {
        "matched" => true,
        "unmatched" => false,
        other => panic!("unexpected label {other}"),
    }
}

#[test]
fn a_compare_loads_and_survives_the_snapshot() {
    let compare = all(json!([
        {"value": input("/hectares"), "greater": 2},
        {"value": input("/tier"), "oneOf": ["gold", "silver"]}
    ]));
    let definition = load(&project(compare)).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(
        restored
            .evaluate("size", &base_input(), &BTreeMap::new())
            .unwrap(),
        json!("matched")
    );
    let value: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(
        value["workflow"]["steps"]["size"]["choose"]["compare"]["all"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_compare_has_exactly_one_of_all_or_any() {
    let condition = json!({"value": input("/tier"), "equals": "gold"});
    for compare in [
        json!({"type": "compare", "all": [condition], "any": [condition]}),
        json!({"type": "compare"}),
    ] {
        assert_finding(
            &refused(&project(compare)),
            "coordinator.definition.compare-conditions",
            "/workflow/steps/size/choose",
            "a compare has exactly one of all or any",
        );
    }
}

#[test]
fn a_compare_holds_one_to_sixteen_conditions() {
    let condition = json!({"value": input("/tier"), "equals": "gold"});
    for count in [0, 17] {
        let conditions = vec![condition.clone(); count];
        assert_finding(
            &refused(&project(all(json!(conditions)))),
            "coordinator.definition.compare-conditions",
            "/workflow/steps/size/choose/all",
            "a compare holds 1 to 16 conditions",
        );
    }
    let conditions = vec![condition.clone(); 16];
    load(&project(any(json!(conditions)))).unwrap();
    let conditions = vec![condition; 17];
    assert_finding(
        &refused(&project(any(json!(conditions)))),
        "coordinator.definition.compare-conditions",
        "/workflow/steps/size/choose/any",
        "a compare holds 1 to 16 conditions",
    );
}

#[test]
fn a_condition_names_exactly_one_test() {
    for condition in [
        json!({"value": input("/tier")}),
        json!({"value": input("/hectares"), "greater": 1, "less": 9}),
        json!({"value": input("/tier"), "equals": "gold", "present": true}),
    ] {
        assert_finding(
            &refused(&project(all(json!([condition])))),
            "coordinator.definition.compare-test",
            "/workflow/steps/size/choose/all/0",
            "a condition has exactly one test: equals, oneOf, less, greater or present",
        );
    }
}

#[test]
fn test_operands_are_literals_of_the_kind_the_test_takes() {
    for (condition, message) in [
        (
            json!({"value": input("/tier"), "equals": {"a": 1}}),
            "equals takes a string, a number or a boolean",
        ),
        (
            json!({"value": input("/tier"), "oneOf": []}),
            "oneOf takes a list of strings, numbers or booleans of one kind",
        ),
        (
            json!({"value": input("/tier"), "oneOf": ["gold", 3]}),
            "oneOf takes a list of strings, numbers or booleans of one kind",
        ),
        (
            json!({"value": input("/hectares"), "greater": "big"}),
            "less and greater take a number or a calendar date such as 2026-01-31",
        ),
        (
            json!({"value": input("/visitDate"), "less": "2026-02-30"}),
            "less and greater take a number or a calendar date such as 2026-01-31",
        ),
        (
            json!({"value": input("/hectares"), "less": true}),
            "less and greater take a number or a calendar date such as 2026-01-31",
        ),
    ] {
        assert_finding(
            &refused(&project(all(json!([condition])))),
            "coordinator.definition.compare-test",
            "/workflow/steps/size/choose/all/0",
            message,
        );
    }
}

#[test]
fn a_compare_has_exactly_the_cases_matched_and_unmatched() {
    let compare = all(json!([{"value": input("/tier"), "equals": "gold"}]));
    for cases in [
        json!({"matched": "large"}),
        json!({"matched": "large", "unmatched": "small", "other": "small"}),
        json!({"yes": "large", "no": "small"}),
    ] {
        let mut project = project(compare.clone());
        project["workflow"]["steps"]["size"]["cases"] = cases;
        // A route left without a case also leaves its step unreachable, so
        // the refusal is one finding among others.
        let error = refused(&project);
        let findings: Vec<_> = error
            .diagnostics
            .iter()
            .filter(|finding| finding.code == "coordinator.definition.compare-cases")
            .collect();
        assert_eq!(findings.len(), 1, "{:#?}", error.diagnostics);
        assert_eq!(findings[0].path, "/workflow/steps/size/cases");
        assert_eq!(
            findings[0].message,
            "a compare routes to exactly the cases matched and unmatched"
        );
    }
}

#[test]
fn a_compare_belongs_to_a_choose_step() {
    let mut project = project(all(json!([{"value": input("/tier"), "equals": "gold"}])));
    project["workflow"]["steps"]["size"]["choose"] = input("/tier");
    project["workflow"]["steps"]["size"]["cases"] = json!({"gold": "large", "other": "small"});
    project["workflow"]["steps"]["large"]["output"] =
        all(json!([{"value": input("/tier"), "equals": "gold"}]));
    assert_finding(
        &refused(&project),
        "coordinator.definition.compare-placement",
        "/workflow/steps/large/output",
        "a compare decides a choose step; it cannot build a value",
    );
}

#[test]
fn a_condition_refuses_unknown_members_and_a_non_boolean_present() {
    // The same shape without the fault parses, so each refusal below is the
    // fault and not the shape.
    let control = project(all(json!([{"value": input("/tier"), "equals": "gold"}])));
    authoring::parse_project(Path::new("workflow.yaml"), control.to_string()).unwrap();
    for (condition, code, path) in [
        (
            json!({"value": input("/tier"), "equals": "gold", "contains": "g"}),
            "config.unknown-key",
            "/workflow/steps/size/choose/all/0/contains",
        ),
        (
            json!({"value": input("/tier"), "present": "yes"}),
            "config.expected-boolean",
            "/workflow/steps/size/choose/all/0/present",
        ),
        (
            json!({"equals": "gold"}),
            "config.missing-key",
            "/workflow/steps/size/choose/all/0",
        ),
    ] {
        let error = parse_refused(&project(all(json!([condition]))));
        assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
        assert_eq!(error.diagnostics[0].code, code);
        assert_eq!(error.diagnostics[0].path, path);
    }
    // A compare does not nest: a condition takes no all or any of its own.
    let nested = json!({"type": "compare", "all": [{"value": input("/tier"), "all": []}]});
    let error = parse_refused(&project(nested));
    assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
    assert_eq!(error.diagnostics[0].code, "config.unknown-key");
    assert_eq!(
        error.diagnostics[0].path,
        "/workflow/steps/size/choose/all/0/all"
    );
}

#[test]
fn a_test_must_fit_the_type_the_reference_declares() {
    // A number test on a string.
    assert_finding(
        &refused(&project(all(
            json!([{"value": input("/tier"), "greater": 2}]),
        ))),
        "coordinator.mapping.type",
        "/workflow/steps/size/choose/all/0/value",
        "expected a number for greater; the reference reads a string",
    );
    // A date test needs a declared date format.
    assert_finding(
        &refused(&project(all(
            json!([{"value": input("/tier"), "less": "2026-02-01"}]),
        ))),
        "coordinator.mapping.type",
        "/workflow/steps/size/choose/all/0/value",
        "expected a date string for less; the reference reads a string",
    );
    assert_finding(
        &refused(&project(all(
            json!([{"value": input("/hectares"), "less": "2026-02-01"}]),
        ))),
        "coordinator.mapping.type",
        "/workflow/steps/size/choose/all/0/value",
        "expected a date string for less; the reference reads a number",
    );
    // A number test on a date.
    assert_finding(
        &refused(&project(all(
            json!([{"value": input("/visitDate"), "greater": 2}]),
        ))),
        "coordinator.mapping.type",
        "/workflow/steps/size/choose/all/0/value",
        "expected a number for greater; the reference reads a date string",
    );
    // equals and oneOf compare the kind the reference reads.
    assert_finding(
        &refused(&project(all(
            json!([{"value": input("/parcels"), "equals": "four"}]),
        ))),
        "coordinator.mapping.type",
        "/workflow/steps/size/choose/all/0/value",
        "expected a string for equals; the reference reads an integer",
    );
    // A path the input schema does not declare is refused as everywhere else.
    assert_eq!(
        refused(&project(all(
            json!([{"value": input("/missing"), "present": true}])
        )))
        .diagnostics[0]
            .code,
        "coordinator.mapping.path"
    );
    // The matching types load.
    load(&project(all(json!([
        {"value": input("/hectares"), "less": 10},
        {"value": input("/parcels"), "greater": 1},
        {"value": input("/visitDate"), "less": "2026-03-01"},
        {"value": input("/tier"), "equals": "gold"},
        {"value": input("/active"), "equals": true},
        {"value": input("/note"), "present": true}
    ]))))
    .unwrap();
}

#[cfg(feature = "schema")]
#[test]
fn the_authored_schema_carries_the_condition_count() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
    let condition = json!({"value": input("/tier"), "equals": "gold"});
    for (count, accepted) in [(0, false), (1, true), (16, true), (17, false)] {
        let conditions = vec![condition.clone(); count];
        for compare in [all(json!(conditions)), any(json!(conditions))] {
            assert_eq!(
                validator.is_valid(&project(compare)),
                accepted,
                "{count} conditions"
            );
        }
    }
}

/// The project with these properties added to the workflow input.
fn project_declaring(compare: Value, properties: Value) -> Value {
    let mut project = project(compare);
    let declared = project["workflow"]["input"]["properties"]
        .as_object_mut()
        .unwrap();
    for (name, schema) in properties.as_object().unwrap() {
        declared.insert(name.clone(), schema.clone());
    }
    project
}

#[test]
fn a_nullable_date_can_be_compared_with_or_without_a_present_guard() {
    let properties = json!({
        "endDate": {"type": ["string", "null"], "format": "date"},
        "lastDay": {"anyOf": [{"type": "string", "format": "date"}, {"type": "null"}]}
    });
    for name in ["endDate", "lastDay"] {
        let path = format!("/{name}");
        let guarded = all(json!([
            {"value": input(&path), "present": true},
            {"value": input(&path), "less": "2026-06-01"}
        ]));
        let unguarded = all(json!([{"value": input(&path), "less": "2026-06-01"}]));
        for compare in [guarded.clone(), unguarded.clone()] {
            let definition = load(&project_declaring(compare, properties.clone())).unwrap();
            let none = BTreeMap::new();
            let mut values = base_input();
            values[name] = json!("2026-02-01");
            assert_eq!(
                definition.evaluate("size", &values, &none).unwrap(),
                json!("matched"),
                "{name}"
            );
        }
        // A null date still cannot be ordered: the guard routes it to
        // unmatched and its absence fails the run.
        let mut values = base_input();
        values[name] = Value::Null;
        let definition = load(&project_declaring(guarded, properties.clone())).unwrap();
        assert_eq!(
            definition
                .evaluate("size", &values, &BTreeMap::new())
                .unwrap(),
            json!("unmatched")
        );
        let definition = load(&project_declaring(unguarded, properties.clone())).unwrap();
        let error = definition
            .evaluate("size", &values, &BTreeMap::new())
            .unwrap_err();
        assert_eq!(error.code, "mapping.choice");
    }
    // A schema that can read something other than a date or null is still
    // refused, and a schema that reads only null has no date to order.
    for schema in [
        json!({"type": ["string", "null"]}),
        json!({"type": ["string", "number"], "format": "date"}),
        json!({"type": "null"}),
    ] {
        let error = refused(&project_declaring(
            all(json!([{"value": input("/endDate"), "less": "2026-06-01"}])),
            json!({"endDate": schema}),
        ));
        assert_eq!(error.diagnostics[0].code, "coordinator.mapping.type");
    }
}

#[test]
fn every_operand_is_held_to_the_literal_bounds() {
    let long = "x".repeat(100_000);
    let many: Vec<i64> = (0..20_000).collect();
    for (condition, member) in [
        (
            json!({"value": input("/parcels"), "equals": 9_007_199_254_740_993_i64}),
            "equals",
        ),
        (
            json!({"value": input("/parcels"), "greater": 9_007_199_254_740_993_i64}),
            "greater",
        ),
        (
            json!({"value": input("/hectares"), "less": 9_007_199_254_740_993_i64}),
            "less",
        ),
        (
            json!({"value": input("/tier"), "equals": long.clone()}),
            "equals",
        ),
        (
            json!({"value": input("/tier"), "oneOf": [long.clone()]}),
            "oneOf",
        ),
        (
            json!({"value": input("/parcels"), "oneOf": many.clone()}),
            "oneOf",
        ),
    ] {
        // The oversized operand is the second condition, so the finding must
        // name that position and not the first.
        let compare = any(json!([
            {"value": input("/tier"), "equals": "gold"},
            condition
        ]));
        let error = refused(&project(compare));
        assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
        let finding = &error.diagnostics[0];
        assert_eq!(finding.code, "coordinator.mapping.literal", "{member}");
        assert_eq!(
            finding.path,
            format!("/workflow/steps/size/choose/any/1/{member}")
        );
        assert_eq!(
            finding.message,
            format!("the {member} operand exceeds the structured value bounds")
        );
        assert!(!finding.suggested_action.is_empty());
    }
    // The largest safe integer and a long string within the bound load.
    load(&project(all(json!([
        {"value": input("/parcels"), "less": 9_007_199_254_740_991_i64},
        {"value": input("/tier"), "equals": "x".repeat(16_384)}
    ]))))
    .unwrap();
}

#[test]
fn each_test_decides_matched_or_unmatched() {
    let input = base_input();
    let one = |condition: Value| all(json!([condition]));
    for (condition, expected) in [
        (
            json!({"value": self::input("/tier"), "equals": "gold"}),
            true,
        ),
        (
            json!({"value": self::input("/tier"), "equals": "silver"}),
            false,
        ),
        (json!({"value": self::input("/parcels"), "equals": 4}), true),
        (
            json!({"value": self::input("/parcels"), "equals": 4.0}),
            true,
        ),
        (
            json!({"value": self::input("/active"), "equals": true}),
            true,
        ),
        (
            json!({"value": self::input("/active"), "equals": false}),
            false,
        ),
        (
            json!({"value": self::input("/tier"), "oneOf": ["silver", "gold"]}),
            true,
        ),
        (
            json!({"value": self::input("/tier"), "oneOf": ["silver", "bronze"]}),
            false,
        ),
        (
            json!({"value": self::input("/parcels"), "oneOf": [1, 4]}),
            true,
        ),
        (json!({"value": self::input("/hectares"), "less": 4}), true),
        (
            json!({"value": self::input("/hectares"), "less": 3.5}),
            false,
        ),
        (
            json!({"value": self::input("/hectares"), "greater": 3}),
            true,
        ),
        (
            json!({"value": self::input("/hectares"), "greater": 3.5}),
            false,
        ),
        (
            json!({"value": self::input("/parcels"), "greater": 3}),
            true,
        ),
        (
            json!({"value": self::input("/tier"), "present": true}),
            true,
        ),
        (
            json!({"value": self::input("/tier"), "present": false}),
            false,
        ),
        (
            json!({"value": self::input("/note"), "present": true}),
            false,
        ),
        (
            json!({"value": self::input("/note"), "present": false}),
            true,
        ),
    ] {
        assert_eq!(
            matches(one(condition.clone()), &input),
            expected,
            "{condition}"
        );
    }
}

#[test]
fn a_null_value_is_not_present() {
    let mut input = base_input();
    input["note"] = Value::Null;
    assert!(!matches(
        all(json!([{"value": self::input("/note"), "present": true}])),
        &input
    ));
    assert!(matches(
        all(json!([{"value": self::input("/note"), "present": false}])),
        &input
    ));
}

#[test]
fn dates_compare_as_calendar_dates_across_month_and_year_boundaries() {
    for (visit, test, bound, expected) in [
        ("2026-02-01", "greater", "2026-01-31", true),
        ("2026-01-31", "less", "2026-02-01", true),
        ("2026-01-31", "greater", "2026-02-01", false),
        ("2026-03-01", "greater", "2026-02-28", true),
        ("2028-03-01", "greater", "2028-02-29", true),
        ("2028-02-29", "less", "2028-03-01", true),
        ("2027-01-01", "greater", "2026-12-31", true),
        ("2026-12-31", "less", "2027-01-01", true),
        ("2026-02-01", "less", "2026-02-01", false),
        ("2026-02-01", "greater", "2026-02-01", false),
    ] {
        let mut input = base_input();
        input["visitDate"] = json!(visit);
        let compare = all(json!([{"value": self::input("/visitDate"), test: bound}]));
        assert_eq!(matches(compare, &input), expected, "{visit} {test} {bound}");
    }
}

#[test]
fn all_stops_at_the_first_false_condition_and_any_at_the_first_true() {
    // The visit date is not a date, so evaluating its condition fails the run.
    let mut input = base_input();
    input["visitDate"] = json!(CANARY);
    let broken = json!({"value": self::input("/visitDate"), "less": "2026-03-01"});
    let false_first = json!({"value": self::input("/tier"), "equals": "silver"});
    let true_first = json!({"value": self::input("/tier"), "equals": "gold"});

    // all: a false condition decides before the broken one is read.
    assert!(!matches(
        all(json!([false_first.clone(), broken.clone()])),
        &input
    ));
    // all: the broken condition comes first, so the run fails.
    assert_eq!(
        choose(all(json!([broken.clone(), false_first])), &input)
            .unwrap_err()
            .code,
        "mapping.choice"
    );
    // any: a true condition decides before the broken one is read.
    assert!(matches(
        any(json!([true_first.clone(), broken.clone()])),
        &input
    ));
    // any: the broken condition comes first, so the run fails.
    assert_eq!(
        choose(any(json!([broken, true_first])), &input)
            .unwrap_err()
            .code,
        "mapping.choice"
    );
}

#[test]
fn present_guards_a_test_on_an_optional_value() {
    let mut project = project(all(json!([
        {"value": input("/note"), "present": true},
        {"value": input("/note"), "equals": "urgent"}
    ])));
    project["workflow"]["input"]["properties"]["note"] = json!({"type": "string"});
    let definition = load(&project).unwrap();
    let none = BTreeMap::new();
    assert_eq!(
        definition.evaluate("size", &base_input(), &none).unwrap(),
        json!("unmatched")
    );
    let mut input = base_input();
    input["note"] = json!("urgent");
    assert_eq!(
        definition.evaluate("size", &input, &none).unwrap(),
        json!("matched")
    );
}

#[test]
fn a_missing_or_wrongly_typed_value_fails_the_choice() {
    let cases = [
        // Missing value in each test but present.
        (json!({"value": input("/note"), "equals": "x"}), json!({})),
        (json!({"value": input("/note"), "oneOf": ["x"]}), json!({})),
        (json!({"value": input("/extent"), "less": 3}), json!({})),
        (json!({"value": input("/extent"), "greater": 3}), json!({})),
        (
            json!({"value": input("/followUp"), "greater": "2026-01-01"}),
            json!({}),
        ),
        // A null value is missing.
        (
            json!({"value": input("/note"), "equals": "x"}),
            json!({"note": null}),
        ),
        // Wrong types.
        (
            json!({"value": input("/hectares"), "greater": 3}),
            json!({"hectares": CANARY}),
        ),
        (
            json!({"value": input("/hectares"), "less": 3}),
            json!({"hectares": true}),
        ),
        (
            json!({"value": input("/tier"), "equals": "gold"}),
            json!({"tier": 3}),
        ),
        (
            json!({"value": input("/parcels"), "equals": 4}),
            json!({"parcels": "4"}),
        ),
        (
            json!({"value": input("/tier"), "oneOf": ["gold"]}),
            json!({"tier": CANARY.len()}),
        ),
        (
            json!({"value": input("/active"), "equals": true}),
            json!({"active": "true"}),
        ),
        (
            json!({"value": input("/visitDate"), "less": "2026-03-01"}),
            json!({"visitDate": 20260201}),
        ),
        (
            json!({"value": input("/visitDate"), "less": "2026-03-01"}),
            json!({"visitDate": "2026-02-30"}),
        ),
        (
            json!({"value": input("/visitDate"), "less": "2026-03-01"}),
            json!({"visitDate": "2026-2-1"}),
        ),
        (
            json!({"value": input("/visitDate"), "less": "2026-03-01"}),
            json!({"visitDate": "2026-02-01T00:00:00Z"}),
        ),
    ];
    for (condition, values) in cases {
        for compare in [
            all(json!([condition.clone()])),
            any(json!([condition.clone()])),
        ] {
            let error = choose(compare, &values).unwrap_err();
            assert_eq!(error.code, "mapping.choice", "{condition} {values}");
            // The refusal names the condition and never the value.
            assert!(
                error
                    .field
                    .as_deref()
                    .unwrap()
                    .starts_with("steps.size.choose."),
                "{:?}",
                error.field
            );
            assert!(!error.to_string().contains(CANARY));
            assert!(!format!("{error:?}").contains(CANARY));
        }
    }
}

#[test]
fn the_failing_condition_is_named_by_position() {
    let compare = all(json!([
        {"value": input("/tier"), "equals": "gold"},
        {"value": input("/hectares"), "greater": 3}
    ]));
    let mut values = base_input();
    values["hectares"] = json!("wide");
    let error = choose(compare, &values).unwrap_err();
    assert_eq!(error.code, "mapping.choice");
    assert_eq!(error.field.as_deref(), Some("steps.size.choose.all.1"));
}

#[test]
fn a_step_output_is_read_through_the_same_reference() {
    let mut project = project(all(json!([
        {"value": {"type": "step", "step": "read", "path": "/data/domainData/areaHectares"}, "greater": 2}
    ])));
    project["operations"] = json!({
        "read-record": {"uses": "breg.read-record/v1", "connection": "applications"}
    });
    project["workflow"]["start"] = json!("read");
    project["workflow"]["steps"]["read"] = json!({
        "type": "call",
        "operation": "read-record",
        "input": {"type": "fields", "fields": {
            "collection": {"type": "literal", "value": "farms"},
            "recordId": {"type": "literal", "value": "farm-1"}
        }},
        "next": "size"
    });
    let definition = load(&project).unwrap();
    let record = |area: Value| {
        json!({
            "data": {"recordIdentifier": "farm-1", "revisionIdentifier": "1", "domainData": {"areaHectares": area}},
            "meta": {"registryIdentifier": "r", "datasetIdentifier": "d", "recordTypeIdentifier": "e"}
        })
    };
    let outputs = |area: Value| BTreeMap::from([("read".to_owned(), record(area))]);
    assert_eq!(
        definition
            .evaluate("size", &base_input(), &outputs(json!(5)))
            .unwrap(),
        json!("matched")
    );
    assert_eq!(
        definition
            .evaluate("size", &base_input(), &outputs(json!(1.5)))
            .unwrap(),
        json!("unmatched")
    );
    assert_eq!(
        definition
            .evaluate("size", &base_input(), &outputs(json!("big")))
            .unwrap_err()
            .code,
        "mapping.choice"
    );
}

const WORKFLOW: &str = r#"apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project: {id: farm-size, version: '1'}
operations:
  read-record: {uses: breg.read-record/v1, connection: farms}
workflow:
  input:
    type: object
    additionalProperties: false
    required: [farmId, season]
    properties:
      farmId: {type: string}
      season: {type: string, format: date}
  deadlineSeconds: 86400
  start: read
  steps:
    read:
      type: call
      operation: read-record
      input:
        type: fields
        fields:
          collection: {type: literal, value: farms}
          recordId: {type: input, path: /farmId}
      next: size
    size:
      type: choose
      choose:
        type: compare
        all:
          - {value: {type: step, step: read, path: /data/domainData/areaHectares}, present: true}
          - {value: {type: step, step: read, path: /data/domainData/areaHectares}, greater: 2}
          - {value: {type: input, path: /season}, less: '2027-01-01'}
      cases: {matched: large-farm, unmatched: smallholding}
    large-farm: {type: finish, outcome: large}
    smallholding: {type: finish, outcome: small}
  outcomes:
    large: {type: 'null'}
    small: {type: 'null'}
"#;

fn scenario(id: &str, season: &str, domain_data: &str, path: &str, outcome: &str) -> String {
    format!(
        "- id: {id}
  admittedAt: '2026-10-09T09:00:00Z'
  input: {{farmId: farm-1, season: '{season}'}}
  replies:
    read:
    - type: success
      value:
        meta: {{registryIdentifier: r, datasetIdentifier: d, recordTypeIdentifier: e}}
        data: {{recordIdentifier: farm-1, revisionIdentifier: '1', domainData: {domain_data}}}
  expect:
    path: [{path}]
    state: completed
    outcome: {{type: named, value: {outcome}}}
    output: null
"
    )
}

#[test]
fn a_compare_routes_a_workflow_scenario_end_to_end() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("workflow.yaml"), WORKFLOW).unwrap();
    let scenarios_file = format!(
        "apiVersion: {}\nkind: {}\ncases:\n{}{}{}{}",
        scenarios::API_VERSION,
        scenarios::KIND,
        scenario(
            "large-farm",
            "2026-10-01",
            "{areaHectares: 5}",
            "read, size, large-farm",
            "large"
        ),
        scenario(
            "small-farm",
            "2026-10-01",
            "{areaHectares: 1.5}",
            "read, size, smallholding",
            "small"
        ),
        scenario(
            "area-not-recorded",
            "2026-10-01",
            "{}",
            "read, size, smallholding",
            "small"
        ),
        scenario(
            "season-after-the-cutoff",
            "2027-01-01",
            "{areaHectares: 5}",
            "read, size, smallholding",
            "small"
        ),
    );
    fs::write(root.path().join("scenarios.yaml"), &scenarios_file).unwrap();
    let definition = Definition::load(root.path()).unwrap();
    let document = scenarios::load(&root.path().join("scenarios.yaml")).unwrap();
    let reports = scenarios::check(&definition, &document).unwrap();
    assert_eq!(reports.len(), 4);
    assert_eq!(
        reports
            .iter()
            .map(|report| report.outcome.as_deref().unwrap())
            .collect::<Vec<_>>(),
        ["large", "small", "small", "small"]
    );

    // A recorded area of the wrong type is a refusal, never a silent
    // unmatched route.
    let wrong = scenario(
        "area-is-text",
        "2026-10-01",
        "{areaHectares: wide}",
        "read, size, smallholding",
        "small",
    );
    let wrong = format!(
        "apiVersion: {}\nkind: {}\ncases:\n{wrong}",
        scenarios::API_VERSION,
        scenarios::KIND
    );
    fs::write(root.path().join("wrong.yaml"), wrong).unwrap();
    let document = scenarios::load(&root.path().join("wrong.yaml")).unwrap();
    let Err(error) = scenarios::check(&definition, &document) else {
        panic!("a wrongly typed area must be refused");
    };
    assert_eq!(error.code, "mapping.choice");
}
