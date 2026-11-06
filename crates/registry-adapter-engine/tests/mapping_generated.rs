// SPDX-License-Identifier: Apache-2.0

//! Generated `AdapterMapping` scripts run under the real Rhai sandbox, so the
//! semantics the generator relies on (a missing map key reads as `()`, string
//! and character operations, nested index assignment) are proven by running
//! them, not assumed.

use std::time::{Duration, Instant};

use registry_adapter_core::{
    check_mapping, generate, AdapterMapping, BindingTransform, ProjectSchema, ProjectScript,
};
use registry_adapter_engine::artifacts::ProjectArtifactBytes;
use registry_adapter_engine::project_transform::{CompiledProjectTransform, ProjectTransformError};
use registry_adapter_engine::public_schema::check_public_schema;
use registry_adapter_engine::scripts::{CodeMaps, SCRIPT_PROFILE};
use registry_platform_config::sha256_uri;
use registry_platform_script::rhai::{
    build_engine, call_with_fresh_scope, compile_entrypoint, entrypoint_parameters,
};
use serde_json::{json, Value};

const MODEL_DIGEST: &str =
    "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9";
const REFERENCE: &str = "../person.mapping.yaml";

fn schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://registry.example/schemas/person/1/schema.json",
        "type": "object",
        "properties": {
            "source": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string"}
                },
                "required": ["id", "kind"],
                "additionalProperties": false
            },
            "household": {
                "type": "object",
                "properties": {
                    "size": {"type": "integer"},
                    "head": {"type": "string"}
                },
                "required": ["size"],
                "additionalProperties": false
            },
            "dateOfBirth": {"type": "string"},
            "active": {"type": "boolean"},
            "level": {"type": "integer"},
            "nickname": {"type": "string"},
            "code": {"type": "string"}
        },
        "required": ["source"],
        "additionalProperties": false
    })
}

fn mapping(target: &str, mode: Option<&str>, assignments: Value) -> AdapterMapping {
    let mut header = json!({
        "id": "person-registration",
        "target": target,
        "targetSchema": "schemas/person.schema.json",
        "script": "scripts/person.rhai",
        "entrypoint": "project_person"
    });
    if let Some(mode) = mode {
        header["ingestionMode"] = json!(mode);
    }
    serde_json::from_value(json!({
        "apiVersion": "id.registrystack.org/formats/adapter/mapping/v1alpha1",
        "kind": "AdapterMapping",
        "mapping": header,
        "assignments": assignments
    }))
    .expect("model")
}

fn script_for(model: &AdapterMapping, schema: &Value) -> String {
    match generate(model, schema, REFERENCE, MODEL_DIGEST) {
        Ok(script) => script,
        Err(findings) => panic!("generation refused: {findings:#?}"),
    }
}

/// Run `entrypoint` over `argument` under the maintained sandbox profile.
/// The error is the engine's text, which must stay value-free.
fn call(
    script: &str,
    entrypoint: &str,
    parameter: &str,
    argument: &Value,
) -> Result<Value, String> {
    let ast = compile_entrypoint(&SCRIPT_PROFILE, script, entrypoint, &[1])
        .expect("the generated script compiles under the sandbox profile");
    assert_eq!(entrypoint_parameters(&ast, entrypoint), vec![parameter]);
    let engine = build_engine(
        &SCRIPT_PROFILE,
        Some(Instant::now() + Duration::from_secs(5)),
        |_| {},
    );
    let argument = rhai::serde::to_dynamic(argument).expect("argument");
    match call_with_fresh_scope(&engine, &ast, entrypoint, (argument,)) {
        Ok(result) => Ok(rhai::serde::from_dynamic::<Value>(&result).expect("json result")),
        Err(error) => Err(error.to_string()),
    }
}

/// Consultation and Evidence: run through the project transformation seam,
/// which also validates the output against the target schema.
fn apply(script: &str, schema: &Value, source: &Value) -> Result<Value, String> {
    apply_entrypoint(script, schema, "project_person", source)
}

fn apply_entrypoint(
    script: &str,
    schema: &Value,
    entrypoint: &str,
    source: &Value,
) -> Result<Value, String> {
    compile_transform(script, schema, entrypoint)?
        .apply(
            &CodeMaps::default(),
            source,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(|error| error.to_string())
}

fn compile_transform(
    script: &str,
    schema: &Value,
    entrypoint: &str,
) -> Result<CompiledProjectTransform, String> {
    let schema_bytes = serde_json::to_vec(schema).expect("schema bytes");
    let script_ref: ProjectScript = serde_json::from_value(json!({
        "id": "person-script",
        "file": "scripts/person.rhai",
        "digest": sha256_uri(script.as_bytes())
    }))
    .expect("script ref");
    let schema_ref: ProjectSchema = serde_json::from_value(json!({
        "id": "person-schema",
        "file": "schemas/person.schema.json",
        "digest": sha256_uri(&schema_bytes)
    }))
    .expect("schema ref");
    let transform: BindingTransform = serde_json::from_value(json!({
        "script": "person-script",
        "entrypoint": entrypoint
    }))
    .expect("transform");
    let artifacts = ProjectArtifactBytes::new([
        ("scripts/person.rhai".to_owned(), script.as_bytes().to_vec()),
        ("schemas/person.schema.json".to_owned(), schema_bytes),
    ]);
    CompiledProjectTransform::compile_parts(&script_ref, &transform, &schema_ref, &artifacts)
        .map_err(|error| format!("compile: {error}"))
}

fn base_assignments() -> Vec<Value> {
    vec![
        json!({"target": "source.id", "from": "id"}),
        json!({"target": "source.kind", "constant": "person"}),
    ]
}

fn with(extra: Value) -> Value {
    let mut all = base_assignments();
    all.extend(extra.as_array().expect("array").iter().cloned());
    Value::Array(all)
}

fn run(assignments: Value, source: &Value) -> Result<Value, String> {
    let schema = schema();
    let model = mapping("consultation", None, assignments);
    let script = script_for(&model, &schema);
    call(&script, "project_person", "source", source)
}

// --- copy, constant, nested ---------------------------------------------

#[test]
fn copy_constant_and_nested_objects_validate_against_the_target_schema() {
    let schema = schema();
    let model = mapping(
        "consultation",
        None,
        with(json!([
            {"target": "household.size", "from": "household.size_text", "convert": "integer"},
            {"target": "household.head", "from": "head"},
            {"target": "active", "constant": true},
            {"target": "level", "constant": 7}
        ])),
    );
    let script = script_for(&model, &schema);
    let source =
        json!({"id": "abc", "household": {"size_text": "4"}, "head": "Asha", "extra": "ignored"});
    let output = apply(&script, &schema, &source).expect("valid output");
    assert_eq!(
        output,
        json!({
            "source": {"id": "abc", "kind": "person"},
            "household": {"size": 4, "head": "Asha"},
            "active": true,
            "level": 7
        })
    );
    // The same script serves the Evidence target's `source` root.
    let evidence = mapping("evidence", None, model_assignments(&model));
    assert_eq!(
        call(
            &script_for(&evidence, &schema),
            "project_person",
            "source",
            &source
        )
        .unwrap(),
        output
    );
}

fn model_assignments(model: &AdapterMapping) -> Value {
    serde_json::to_value(&model.assignments).expect("assignments")
}

#[test]
fn quoted_keys_with_dots_and_string_constants_with_quotes_and_unicode() {
    let output = run(
        with(json!([
            {"target": "nickname", "from": "\"household.nick\""},
            {"target": "code", "constant": "say \"hi\" \\ \u{e9}"}
        ])),
        &json!({"id": "1", "household.nick": "Nia", "household": {"nick": "wrong"}}),
    )
    .unwrap();
    assert_eq!(output["nickname"], "Nia");
    assert_eq!(output["code"], "say \"hi\" \\ \u{e9}");
}

#[test]
fn integer_constants_include_the_extremes() {
    for value in [0_i64, -1, i64::MAX, i64::MIN] {
        let output = run(
            with(json!([{"target": "level", "constant": value}])),
            &json!({"id": "1"}),
        )
        .unwrap();
        assert_eq!(output["level"], json!(value));
    }
}

#[test]
fn deepest_allowed_paths_run_inside_the_sandbox_limits() {
    // Sixteen segments in the target and in the selector.
    let names: Vec<String> = (0..16).map(|i| format!("n{i}")).collect();
    let mut leaf = json!({"type": "string"});
    for name in names.iter().rev() {
        leaf = json!({"type": "object", "properties": {name: leaf}, "required": [name],
                      "additionalProperties": false});
    }
    let schema = leaf;
    let target = names.join(".");
    let model = mapping(
        "consultation",
        None,
        json!([{"target": target, "from": names.join(".")}]),
    );
    assert_eq!(check_mapping(&model, &schema), vec![]);
    let script = script_for(&model, &schema);
    let mut source = json!("deep");
    for name in names.iter().rev() {
        source = json!({ name: source });
    }
    let output = call(&script, "project_person", "source", &source).unwrap();
    assert_eq!(output, source);
}

#[test]
fn a_hundred_assignments_stay_inside_the_script_bound() {
    let mut properties = serde_json::Map::new();
    let mut assignments = Vec::new();
    let mut source = serde_json::Map::new();
    for index in 0..100 {
        properties.insert(format!("p{index}"), json!({"type": "string"}));
        assignments.push(
            json!({"target": format!("p{index}"), "from": format!("s{index}"),
                                "convert": "text"}),
        );
        source.insert(format!("s{index}"), json!(index));
    }
    let schema = json!({"type": "object", "properties": properties,
                        "additionalProperties": false});
    let model = mapping("consultation", None, Value::Array(assignments));
    let script = script_for(&model, &schema);
    assert!(script.len() <= SCRIPT_PROFILE.maximum_source_bytes);
    let output = call(&script, "project_person", "source", &Value::Object(source)).unwrap();
    assert_eq!(output["p99"], "99");
}

// --- keyed selection ----------------------------------------------------

fn dob_assignments() -> Value {
    with(json!([{"target": "dateOfBirth",
        "from": "attributes[attribute = \"Dob\"].value"}]))
}

#[test]
fn keyed_selection_one_match_passes() {
    let output = run(
        dob_assignments(),
        &json!({"id": "1", "attributes": [
            {"attribute": "Other", "value": "x"},
            {"attribute": "Dob", "value": "2001-05-06"}
        ]}),
    )
    .unwrap();
    assert_eq!(output["dateOfBirth"], "2001-05-06");
}

#[test]
fn keyed_selection_zero_matches_is_a_missing_refusal() {
    for attributes in [
        json!([{"attribute": "Other", "value": "x"}]),
        json!([]),
        json!("not an array"),
        json!(null),
    ] {
        let error = run(
            dob_assignments(),
            &json!({"id": "1", "attributes": attributes}),
        )
        .unwrap_err();
        assert!(error.contains("mapping.missing: dateOfBirth"), "{error}");
    }
    let error = run(dob_assignments(), &json!({"id": "1"})).unwrap_err();
    assert!(error.contains("mapping.missing: dateOfBirth"), "{error}");
}

#[test]
fn keyed_selection_two_matches_is_a_duplicate_refusal() {
    let error = run(
        dob_assignments(),
        &json!({"id": "1", "attributes": [
            {"attribute": "Dob", "value": "SECRET-ONE"},
            {"attribute": "Dob", "value": "SECRET-TWO"}
        ]}),
    )
    .unwrap_err();
    assert!(error.contains("mapping.duplicate: dateOfBirth"), "{error}");
    assert!(!error.contains("SECRET"), "{error}");
}

#[test]
fn keyed_selection_ignores_non_map_elements_and_type_mismatched_keys() {
    let output = run(
        dob_assignments(),
        &json!({"id": "1", "attributes": [
            7, null, "text", {"attribute": 5, "value": "no"}, {"value": "no"},
            {"attribute": "Dob", "value": "1999-12-31"}
        ]}),
    )
    .unwrap();
    assert_eq!(output["dateOfBirth"], "1999-12-31");
}

// --- conversions ----------------------------------------------------------

fn level_from(convert: &str) -> Value {
    with(json!([{"target": "level", "from": "v", "convert": convert}]))
}

#[test]
fn integer_conversion_accepts_i64_and_digit_strings() {
    for (input, expected) in [
        (json!(42), 42_i64),
        (json!(-3), -3),
        (json!("42"), 42),
        (json!("-7"), -7),
        (json!("007"), 7),
        (json!("999999999999999999"), 999_999_999_999_999_999),
        (json!("-999999999999999999"), -999_999_999_999_999_999),
    ] {
        let output = run(level_from("integer"), &json!({"id": "1", "v": input})).unwrap();
        assert_eq!(output["level"], json!(expected), "{input}");
    }
}

#[test]
fn integer_conversion_refuses_everything_else_without_the_value() {
    for input in [
        json!("12x"),
        json!(""),
        json!("-"),
        json!("+5"),
        json!(" 5"),
        json!("1.5"),
        json!("1000000000000000000"),
        json!(1.5),
        json!(true),
        json!([1]),
        json!({"a": 1}),
    ] {
        let error = run(level_from("integer"), &json!({"id": "1", "v": input})).unwrap_err();
        assert!(
            error.contains("mapping.conversion: level"),
            "{input}: {error}"
        );
        assert!(!error.contains("12x"), "{error}");
    }
}

#[test]
fn text_conversion_accepts_strings_and_integers_only() {
    let assignments = with(json!([{"target": "nickname", "from": "v", "convert": "text"}]));
    for (input, expected) in [(json!("abc"), "abc"), (json!(12), "12"), (json!(-4), "-4")] {
        let output = run(assignments.clone(), &json!({"id": "1", "v": input})).unwrap();
        assert_eq!(output["nickname"], expected);
    }
    for input in [json!(true), json!(1.5), json!([]), json!({})] {
        let error = run(assignments.clone(), &json!({"id": "1", "v": input})).unwrap_err();
        assert!(error.contains("mapping.conversion: nickname"), "{error}");
    }
}

#[test]
fn date_conversion_checks_the_real_calendar() {
    let assignments = with(json!([{"target": "dateOfBirth", "from": "v", "convert": "date"}]));
    for valid in [
        "2000-02-29",
        "2024-02-29",
        "2001-12-31",
        "1999-01-01",
        "2023-04-30",
        "0001-01-01",
        "9999-12-31",
        // RFC 3339 full-date, which JSON Schema `format: date` follows,
        // allows year 0000, a leap year.
        "0000-01-01",
        "0000-02-29",
    ] {
        let output = run(assignments.clone(), &json!({"id": "1", "v": valid})).unwrap();
        assert_eq!(output["dateOfBirth"], valid);
    }
    for invalid in [
        "2024-13-01",
        "2024-00-10",
        "2024-04-31",
        "2023-02-29",
        "1900-02-29",
        "2024-01-00",
        "2024-01-32",
        "0001-02-29",
        "0000-02-30",
        "24-01-01",
        "2024/01/01",
        "2024-1-01",
        "2024-01-011",
        "20240101",
        "2024-01-0a",
        " 2024-01-0",
        "",
        "\u{e9}024-01-01",
    ] {
        let error = run(assignments.clone(), &json!({"id": "1", "v": invalid})).unwrap_err();
        assert!(
            error.contains("mapping.conversion: dateOfBirth"),
            "{invalid}: {error}"
        );
    }
    for invalid in [
        json!(20240101),
        json!(null),
        json!(true),
        json!(["2024-01-01"]),
    ] {
        assert!(run(assignments.clone(), &json!({"id": "1", "v": invalid})).is_err());
    }
}

#[test]
fn converted_output_is_valid_against_the_schema_through_the_transform_seam() {
    let schema = schema();
    let model = mapping(
        "consultation",
        None,
        with(json!([{"target": "dateOfBirth", "from": "v", "convert": "date"}])),
    );
    let script = script_for(&model, &schema);
    let output = apply(&script, &schema, &json!({"id": "1", "v": "2020-02-29"})).unwrap();
    assert_eq!(output["dateOfBirth"], "2020-02-29");
    assert!(apply(&script, &schema, &json!({"id": "1", "v": "2021-02-29"})).is_err());
}

// --- omit and missing -----------------------------------------------------

#[test]
fn omit_leaves_an_optional_target_out_when_the_value_is_absent_or_null() {
    let assignments = with(json!([
        {"target": "nickname", "from": "nick", "whenMissing": "omit"},
        {"target": "household.head", "from": "head", "whenMissing": "omit", "convert": "text"},
        {"target": "household.size", "from": "size"}
    ]));
    let absent = run(assignments.clone(), &json!({"id": "1", "size": 2})).unwrap();
    assert_eq!(
        absent,
        json!({
            "source": {"id": "1", "kind": "person"},
            "household": {"size": 2}
        })
    );
    let null = run(
        assignments.clone(),
        &json!({"id": "1", "size": 2, "nick": null, "head": null}),
    )
    .unwrap();
    assert_eq!(null, absent);
    let present = run(
        assignments.clone(),
        &json!({"id": "1", "size": 2, "nick": "Nia", "head": 9}),
    )
    .unwrap();
    assert_eq!(present["nickname"], "Nia");
    assert_eq!(present["household"], json!({"size": 2, "head": "9"}));
    // A present but unconvertible value is still refused, never dropped.
    let error = run(assignments, &json!({"id": "1", "size": 2, "head": true})).unwrap_err();
    assert!(
        error.contains("mapping.conversion: household.head"),
        "{error}"
    );
}

#[test]
fn omit_inside_an_object_with_nothing_else_still_yields_a_valid_object() {
    let schema = json!({
        "$id": "https://registry.example/schemas/opt/1/schema.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"extra": {"type": "object",
            "properties": {"note": {"type": "string"}}, "additionalProperties": false}},
        "additionalProperties": false
    });
    let model = mapping(
        "consultation",
        None,
        json!([{"target": "extra.note", "from": "note", "whenMissing": "omit"}]),
    );
    let script = script_for(&model, &schema);
    let output = apply(&script, &schema, &json!({})).unwrap();
    assert_eq!(output, json!({"extra": {}}));
    let output = apply(&script, &schema, &json!({"note": "n"})).unwrap();
    assert_eq!(output, json!({"extra": {"note": "n"}}));
}

#[test]
fn a_missing_required_value_is_refused_naming_only_the_target() {
    for source in [
        json!({}),
        json!({"id": null}),
        json!("not a map"),
        json!(null),
    ] {
        let error = run(base_assignments().into(), &source).unwrap_err();
        assert!(error.contains("mapping.missing: source.id"), "{error}");
    }
    // The refusal is never the reserved unmapped marker.
    let error = run(base_assignments().into(), &json!({})).unwrap_err();
    assert!(!error.contains("conversion.unmapped:"));
}

#[test]
fn falsy_values_are_present_not_missing() {
    let output = run(
        with(json!([
            {"target": "level", "from": "zero"},
            {"target": "active", "from": "no"},
            {"target": "nickname", "from": "empty"}
        ])),
        &json!({"id": "", "zero": 0, "no": false, "empty": ""}),
    )
    .unwrap();
    assert_eq!(output["level"], 0);
    assert_eq!(output["active"], false);
    assert_eq!(output["nickname"], "");
}

// --- other targets --------------------------------------------------------

fn exchange(body: Value) -> Value {
    json!({"body": body, "headers": {"recordid": "rec-9"}, "properties": {}})
}

#[test]
fn source_request_reads_the_exchange() {
    let schema = schema();
    let model = mapping(
        "source-request",
        None,
        json!([
            {"target": "source.id", "from": "headers.recordid"},
            {"target": "source.kind", "constant": "request"},
            {"target": "nickname", "from": "body.nick", "whenMissing": "omit"}
        ]),
    );
    let script = script_for(&model, &schema);
    let output = call(
        &script,
        "project_person",
        "exchange",
        &exchange(json!({"nick": "N"})),
    )
    .unwrap();
    assert_eq!(
        output,
        json!({"source": {"id": "rec-9", "kind": "request"}, "nickname": "N"})
    );
    let checked = check_public_schema(schema).expect("schema");
    assert!(checked.validates(&output));
    let bare = call(&script, "project_person", "exchange", &exchange(json!({}))).unwrap();
    assert!(bare.get("nickname").is_none());
}

fn ingestion_model(mode: &str) -> AdapterMapping {
    mapping(
        "ingestion",
        Some(mode),
        json!([
            {"target": "source.id", "from": "_id", "convert": "text"},
            {"target": "source.kind", "constant": "submission"},
            {"target": "household.size", "from": "\"household.household_size\"", "convert": "integer"}
        ]),
    )
}

#[test]
fn ingestion_proposal_wraps_a_schema_valid_input() {
    let schema = schema();
    let script = script_for(&ingestion_model("proposal"), &schema);
    let item = json!({"_id": 501, "household.household_size": "5"});

    let input = call(&script, "project_person_input", "source", &item).unwrap();
    assert_eq!(
        input,
        json!({"source": {"id": "501", "kind": "submission"}, "household": {"size": 5}})
    );
    let checked = check_public_schema(schema).expect("schema");
    assert!(checked.validates(&input));

    let wrapped = call(&script, "project_person", "exchange", &exchange(item)).unwrap();
    assert_eq!(
        wrapped,
        json!({"startInput": {"input": input}, "submitBody": {}})
    );
}

/// The inner ingestion function is a project transformation: it compiles
/// through `compile_parts` (one parameter named `source`) and its output is
/// validated against the target schema.
#[test]
fn ingestion_inner_function_goes_through_compile_parts() {
    let schema = schema();
    let script = script_for(&ingestion_model("proposal"), &schema);
    let item = json!({"_id": 501, "household.household_size": "5"});
    let output = apply_entrypoint(&script, &schema, "project_person_input", &item).unwrap();
    assert_eq!(
        output,
        json!({"source": {"id": "501", "kind": "submission"}, "household": {"size": 5}})
    );
    let error = apply_entrypoint(
        &script,
        &schema,
        "project_person_input",
        &json!({"_id": 501, "household.household_size": "five"}),
    )
    .unwrap_err();
    assert!(error.contains("failed"), "{error}");
}

/// Authoring preview sees the innermost string the generated script threw;
/// the runtime `apply` keeps its categorical, value-free refusal.
#[test]
fn preview_apply_returns_the_thrown_mapping_failure() {
    let schema = schema();
    let model = mapping(
        "consultation",
        None,
        with(json!([
            {"target": "household.size", "from": "size", "convert": "integer"},
            {"target": "dateOfBirth", "from": "attributes[attribute = \"Dob\"].value"}
        ])),
    );
    let script = script_for(&model, &schema);
    let compiled = compile_transform(&script, &schema, "project_person").unwrap();
    let deadline = || Instant::now() + Duration::from_secs(5);
    for (source, thrown) in [
        (json!({"size": 2}), "mapping.missing: source.id"),
        (
            json!({"id": "1", "size": "SECRET"}),
            "mapping.conversion: household.size",
        ),
        (
            json!({"id": "1", "size": 2, "attributes": [
                {"attribute": "Dob", "value": "a"}, {"attribute": "Dob", "value": "b"}
            ]}),
            "mapping.duplicate: dateOfBirth",
        ),
    ] {
        let refusal = compiled
            .apply_for_preview(&CodeMaps::default(), &source, deadline())
            .unwrap_err();
        assert_eq!(refusal.error, ProjectTransformError::Failed);
        assert_eq!(refusal.thrown.as_deref(), Some(thrown));
        assert_eq!(
            compiled
                .apply(&CodeMaps::default(), &source, deadline())
                .unwrap_err(),
            ProjectTransformError::Failed
        );
    }
    let output = compiled
        .apply_for_preview(
            &CodeMaps::default(),
            &json!({"id": "1", "size": 2, "attributes": [{"attribute": "Dob", "value": "a"}]}),
            deadline(),
        )
        .unwrap();
    assert_eq!(output["household"]["size"], 2);
}

/// A refusal that is not a script throw carries no thrown text.
#[test]
fn preview_apply_carries_no_thrown_text_for_an_output_refusal() {
    let schema = schema();
    let script = "fn project_person(source) { #{ unknown: 1 } }";
    let compiled = compile_transform(script, &schema, "project_person").unwrap();
    let refusal = compiled
        .apply_for_preview(
            &CodeMaps::default(),
            &json!({}),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
    assert_eq!(refusal.error, ProjectTransformError::OutputInvalid);
    assert!(refusal.thrown.is_none());
}

#[test]
fn ingestion_immediate_returns_the_bare_input() {
    let schema = schema();
    let script = script_for(&ingestion_model("immediate"), &schema);
    let item = json!({"_id": "x1", "household.household_size": 2});
    let bare = call(
        &script,
        "project_person",
        "exchange",
        &exchange(item.clone()),
    )
    .unwrap();
    assert_eq!(
        bare,
        call(&script, "project_person_input", "source", &item).unwrap()
    );
    assert!(bare.get("startInput").is_none());
    // A bad item is refused through the wrapper too.
    let error = call(
        &script,
        "project_person",
        "exchange",
        &exchange(json!({"_id": "x1", "household.household_size": "two"})),
    )
    .unwrap_err();
    assert!(
        error.contains("mapping.conversion: household.size"),
        "{error}"
    );
}

// --- the hand-written example ---------------------------------------------

#[test]
fn reproduces_the_hand_written_dhis2_person_view() {
    let handwritten = include_str!(
        "../../../products/adapter/examples/dhis2-consultation/scripts/person-public.rhai"
    );
    let schema: Value = serde_json::from_str(include_str!(
        "../../../products/adapter/examples/dhis2-consultation/schemas/person-public.schema.json"
    ))
    .unwrap();
    let model: AdapterMapping = serde_json::from_value(json!({
        "apiVersion": "id.registrystack.org/formats/adapter/mapping/v1alpha1",
        "kind": "AdapterMapping",
        "mapping": {
            "id": "person-public",
            "target": "consultation",
            "targetSchema": "schemas/person-public.schema.json",
            "script": "scripts/person-public.rhai",
            "entrypoint": "project_person_public"
        },
        "assignments": [
            {"target": "source.id", "from": "trackedEntity"},
            {"target": "source.type", "from": "trackedEntityType"},
            {"target": "registration.organisationUnit", "from": "orgUnit"},
            {"target": "registration.createdAt", "from": "createdAt"},
            {"target": "registration.updatedAt", "from": "updatedAt"}
        ]
    }))
    .unwrap();
    let generated = generate(
        &model,
        &schema,
        "../person-public.mapping.yaml",
        MODEL_DIGEST,
    )
    .expect("generated");
    let source = json!({
        "trackedEntity": "te1", "trackedEntityType": "person", "orgUnit": "ou1",
        "createdAt": "2026-01-01", "updatedAt": "2026-01-02",
        "attributes": [{"attribute": "private", "value": "canary"}]
    });
    let expected = call(handwritten, "project_person_public", "source", &source).unwrap();
    assert_eq!(
        call(&generated, "project_person_public", "source", &source).unwrap(),
        expected
    );
}

#[test]
fn the_source_request_example_runs_in_the_pack_script_sandbox() {
    let script = include_str!(
        "../../../products/adapter/examples/formats/mapping/scripts/tracked-entity-request.rhai"
    );
    // `call` compiles under the pack script profile and requires the
    // entrypoint's one parameter to be named `exchange`.
    let body = call(
        script,
        "build_tracked_entity_request",
        "exchange",
        &json!({
            "body": {"org_unit": "ou-1", "tracked_entity_type": "person", "ignored": "x"},
            "headers": {"recordid": "te-1"},
            "properties": {}
        }),
    )
    .expect("the request body maps");
    assert_eq!(
        body,
        json!({"trackedEntity": "te-1", "orgUnit": "ou-1", "trackedEntityType": "person"})
    );
    let error = call(
        script,
        "build_tracked_entity_request",
        "exchange",
        &json!({"body": {"org_unit": "ou-1"}, "headers": {"recordid": "te-1"}}),
    )
    .unwrap_err();
    assert!(
        error.contains("mapping.missing: trackedEntityType"),
        "{error}"
    );
}

// --- hostile text -----------------------------------------------------------

const HOSTILE_CONSTANTS: &[&str] = &[
    "${x}",
    "`",
    "`${x}`",
    "//",
    "/*",
    "*/",
    "/* unterminated",
    "\u{2028}",
    "\u{2029}",
    "\u{202e}",
    "\u{feff}",
    "trailing\\",
    "\\",
    "\\\\",
    "\"",
    "a\"; throw \"boom",
    "\\\"",
    "#{}",
    "{",
];

#[test]
fn hostile_constants_compile_and_come_back_verbatim() {
    for constant in HOSTILE_CONSTANTS {
        let output = run(
            with(json!([{"target": "code", "constant": constant}])),
            &json!({"id": "1"}),
        )
        .unwrap_or_else(|error| panic!("{constant:?}: {error}"));
        assert_eq!(output["code"], *constant, "{constant:?}");
    }
}

/// Names from the edges of the grammar: plain, keyword-like, and quoted text
/// full of script punctuation.
fn edge_names() -> Vec<String> {
    let mut names: Vec<String> = [
        "a",
        "_a",
        "A_1",
        "if",
        "fn",
        "let",
        "true",
        "()",
        "a.b",
        "a b",
        "${x}",
        "`",
        "//",
        "/*",
        "*/",
        "~!@#$%^&*()-_=+[]{};:',<>?|",
        "caf\u{e9}",
        "cafe\u{301}",
        "Saint-\u{c9}tienne \u{1F600}",
        "say \"hi\"",
        "back\\slash",
        "\\\"",
        "ends\\",
        "zero\u{200b}width",
        "\u{feff}bom",
        "join\u{200c}er",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    names.push("x".repeat(128));
    names
}

fn rendered(name: &str) -> String {
    let mut characters = name.chars();
    let plain = characters
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if plain {
        name.to_owned()
    } else {
        format!("\"{}\"", escaped(name))
    }
}

/// The text of a quoted key or filter literal: only a quote and a backslash
/// are escaped.
fn escaped(name: &str) -> String {
    name.replace('\\', "\\\\").replace('"', "\\\"")
}

#[test]
fn quoted_segments_and_filter_literals_with_script_punctuation_run_verbatim() {
    for name in edge_names() {
        let schema = json!({"type": "object",
            "properties": {name.clone(): {"type": "string"}},
            "additionalProperties": false});
        let direct = json!([{"target": rendered(&name), "from": rendered(&name)}]);
        let keyed = json!([{"target": rendered(&name),
            "from": format!("rows[k = \"{}\"].v", escaped(&name))}]);
        let omitted = json!([{"target": rendered(&name), "from": rendered(&name),
            "whenMissing": "omit"}]);
        let cases = [
            (direct, json!({name.clone(): "ok"})),
            (
                keyed,
                json!({"rows": [{"k": "other", "v": "no"}, {"k": name, "v": "ok"}]}),
            ),
            (omitted, json!({name.clone(): "ok"})),
        ];
        for (assignments, source) in cases {
            let model = mapping("consultation", None, assignments);
            assert_eq!(check_mapping(&model, &schema), vec![], "{name:?}");
            let script = script_for(&model, &schema);
            let output = call(&script, "project_person", "source", &source)
                .unwrap_or_else(|error| panic!("{name:?}: {error}"));
            assert_eq!(output, json!({name.clone(): "ok"}), "{name:?}");
        }
    }
}

// --- integer and filter edges ------------------------------------------------

#[test]
fn integer_conversion_signs_and_leading_zeros() {
    let negative_zero = run(level_from("integer"), &json!({"id": "1", "v": "-0"})).unwrap();
    assert_eq!(negative_zero["level"], json!(0));
    let padded = run(level_from("integer"), &json!({"id": "1", "v": "-007"})).unwrap();
    assert_eq!(padded["level"], json!(-7));
    let error = run(level_from("integer"), &json!({"id": "1", "v": "+5"})).unwrap_err();
    assert!(error.contains("mapping.conversion: level"), "{error}");
}

#[test]
fn filters_compare_strings_exactly_so_a_numeric_key_does_not_match() {
    let assignments = with(json!([{"target": "dateOfBirth",
        "from": "attributes[attribute = \"5\"].value"}]));
    // A string key "5" matches.
    let output = run(
        assignments.clone(),
        &json!({"id": "1", "attributes": [{"attribute": "5", "value": "2001-05-06"}]}),
    )
    .unwrap();
    assert_eq!(output["dateOfBirth"], "2001-05-06");
    // A numeric key 5 is a different value: no match, so the value is missing.
    let error = run(
        assignments,
        &json!({"id": "1", "attributes": [{"attribute": 5, "value": "2001-05-06"}]}),
    )
    .unwrap_err();
    assert!(error.contains("mapping.missing: dateOfBirth"), "{error}");
}

#[test]
fn omit_does_not_hide_a_duplicate_keyed_match() {
    let assignments = with(json!([{"target": "nickname",
        "from": "attributes[attribute = \"Nick\"].value", "whenMissing": "omit"}]));
    let absent = run(
        assignments.clone(),
        &json!({"id": "1", "attributes": [{"attribute": "Other", "value": "x"}]}),
    )
    .unwrap();
    assert!(absent.get("nickname").is_none());
    let error = run(
        assignments,
        &json!({"id": "1", "attributes": [
            {"attribute": "Nick", "value": "SECRET-ONE"},
            {"attribute": "Nick", "value": "SECRET-TWO"}
        ]}),
    )
    .unwrap_err();
    assert!(error.contains("mapping.duplicate: nickname"), "{error}");
    assert!(!error.contains("SECRET"), "{error}");
}

// --- every accepted model compiles --------------------------------------------

const ENTRYPOINT_CANDIDATES: &[&str] = &[
    "project_person",
    "_a",
    "a_",
    "a",
    "A1",
    "x_input",
    "source",
    "exchange",
    "out",
    "value_0",
    "item",
    // Rhai keywords, reserved words, and built-ins the helpers call.
    "contains",
    "len",
    "parse_int",
    "starts_with",
    "sub_string",
    "to_chars",
    "to_string",
    "type_of",
    "default",
    "is",
    "is_shared",
    "nil",
    "null",
    "void",
    "Fn",
    "fn",
    "_",
    "__",
    "_1",
    "mapping_walk",
    "print",
    "debug",
];

#[test]
fn every_entrypoint_the_check_accepts_compiles_and_runs_in_the_sandbox() {
    let schema = schema();
    let assignments = with(json!([
        {"target": "household.size", "from": "s", "convert": "integer"},
        {"target": "household.head", "from": "h", "convert": "text"},
        {"target": "dateOfBirth", "from": "d", "convert": "date"},
        {"target": "nickname", "from": "n", "whenMissing": "omit"}
    ]));
    let body = json!({"id": "1", "s": "4", "h": 7, "d": "2001-05-06", "n": "Nia"});
    let expected = json!({
        "source": {"id": "1", "kind": "person"},
        "household": {"size": 4, "head": "7"},
        "dateOfBirth": "2001-05-06",
        "nickname": "Nia"
    });
    let mut accepted = 0;
    let mut refused = Vec::new();
    for entrypoint in ENTRYPOINT_CANDIDATES {
        for (target, mode) in [
            ("consultation", None),
            ("evidence", None),
            ("source-request", None),
            ("ingestion", Some("immediate")),
            ("ingestion", Some("proposal")),
        ] {
            let mut model = mapping(target, mode, assignments.clone());
            model.mapping.entrypoint = (*entrypoint).to_owned();
            if !check_mapping(&model, &schema).is_empty() {
                refused.push(format!("{entrypoint}/{target}"));
                continue;
            }
            accepted += 1;
            let script = script_for(&model, &schema);
            let ok = |result: Result<Value, String>| {
                result.unwrap_or_else(|error| panic!("{entrypoint}/{target}: {error}"))
            };
            match target {
                "consultation" | "evidence" => {
                    assert_eq!(ok(call(&script, entrypoint, "source", &body)), expected)
                }
                "source-request" => {
                    assert_eq!(ok(call(&script, entrypoint, "exchange", &body)), expected)
                }
                _ => {
                    let inner = format!("{entrypoint}_input");
                    assert_eq!(ok(call(&script, &inner, "source", &body)), expected);
                    let wrapped = ok(call(
                        &script,
                        entrypoint,
                        "exchange",
                        &exchange(body.clone()),
                    ));
                    if mode == Some("immediate") {
                        assert_eq!(wrapped, expected);
                    } else {
                        assert_eq!(wrapped["startInput"]["input"], expected);
                    }
                }
            }
        }
    }
    assert!(accepted > 50, "the sweep must not be vacuous: {accepted}");
    for name in [
        "contains",
        "len",
        "parse_int",
        "starts_with",
        "sub_string",
        "to_chars",
        "to_string",
        "type_of",
        "default",
        "is",
        "is_shared",
        "nil",
        "null",
        "void",
        "_",
        "__",
        "_1",
    ] {
        assert!(
            refused
                .iter()
                .any(|entry| entry.starts_with(&format!("{name}/consultation"))),
            "{name} must be refused"
        );
    }
}
