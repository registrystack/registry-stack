// SPDX-License-Identifier: Apache-2.0

//! A date interval can name an inclusive last day in place of an exclusive end.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::diagnostics::{CompileFailure, DiagnosticSeverity};
use registry_breg::CompiledRegistry;
use serde_json::{json, Value};

/// A licence whose validity runs from `valid-from` through `valid-through`.
fn project(start_type: &str, last_day_type: &str) -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "licences", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://licences.example.test", "timezone": "UTC"},
        "datasets": [{"id": "licences"}],
        "recordTypes": [{
            "id": "licence", "primaryDataset": "licences", "route": "licences", "mutationMode": "mutable",
            "fields": [
                {"id": "holder", "type": "string", "maximumLength": 32, "required": true, "classification": "internal"},
                {"id": "valid-from", "type": start_type, "required": true, "classification": "internal"},
                {"id": "valid-to", "type": start_type, "classification": "internal"},
                {"id": "valid-through", "type": last_day_type, "classification": "internal"}
            ],
            "temporal": {"startField": "valid-from", "lastDayField": "valid-through"},
            "constraints": [{
                "type": "temporal-non-overlap", "scopeFields": ["holder"],
                "startField": "valid-from", "lastDayField": "valid-through"
            }]
        }],
        "accessProfiles": [{
            "id": "reader", "default": true, "principalClaim": "principal", "requiredScopes": "unrestricted",
            "permissions": {"records": [{
                "recordType": "licence", "operations": ["list"],
                "readableFields": ["holder", "valid-from", "valid-through"],
                "rowBoundaries": "unrestricted"
            }]}
        }]
    })
}

fn compile(source: &Value) -> Result<CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).expect("source parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn temporal_errors(failure: &CompileFailure) -> Vec<(String, String)> {
    failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.code.starts_with("breg.temporal.")
        })
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

fn ddl(registry: &CompiledRegistry, id_prefix: &str) -> String {
    registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id.starts_with(id_prefix))
        .unwrap_or_else(|| panic!("a DDL statement starts with {id_prefix}"))
        .sql
        .clone()
}

fn physical(registry: &CompiledRegistry, field: &str) -> String {
    registry.entities()["licence"].fields[field]
        .physical_name
        .clone()
}

#[test]
fn an_interval_declares_exactly_one_of_an_end_and_a_last_day() {
    let mut both = project("date", "date");
    both["recordTypes"][0]["temporal"]["endField"] = json!("valid-to");
    let mut neither = project("date", "date");
    neither["recordTypes"][0]["temporal"]
        .as_object_mut()
        .unwrap()
        .remove("lastDayField");
    for (label, source) in [("both", both), ("neither", neither)] {
        let failure = compile(&source).expect_err(label);
        assert!(
            temporal_errors(&failure).contains(&(
                "breg.temporal.end-conflict".to_owned(),
                "recordTypes[id=licence].temporal".to_owned()
            )),
            "{label}: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn a_last_day_is_a_date_on_a_date_interval() {
    for (label, start_type, last_day_type) in [
        ("timestamp interval", "timestamp", "timestamp"),
        ("non-date last day", "date", "string"),
    ] {
        let mut source = project(start_type, last_day_type);
        if last_day_type == "string" {
            source["recordTypes"][0]["fields"][3]["maximumLength"] = json!(10);
        }
        let failure = compile(&source).expect_err(label);
        assert!(
            temporal_errors(&failure).contains(&(
                "breg.temporal.last-day-type".to_owned(),
                "recordTypes[id=licence].temporal.lastDayField".to_owned()
            )),
            "{label}: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn a_last_day_interval_is_in_force_through_its_last_day() {
    let registry = compile(&project("date", "date")).expect("a last-day interval compiles");
    let order = ddl(&registry, "entity.licence.constraint.temporal-order");
    let from = physical(&registry, "valid-from");
    let through = physical(&registry, "valid-through");
    assert!(
        order.contains(&format!(r#""{from}" <= "{through}""#)),
        "a last day may equal the start but not precede it: {order}"
    );
    let overlap = ddl(&registry, "entity.licence.constraint.temporal-non-overlap-");
    assert!(
        overlap.contains(&format!(
            r#"daterange("{from}", "{through}", '[]') WITH &&"#
        )),
        "two intervals sharing a last day overlap: {overlap}"
    );
}

#[test]
fn a_non_overlap_constraint_names_the_last_day_in_place_of_the_end() {
    let mut source = project("date", "date");
    source["recordTypes"][0]["constraints"][0]
        .as_object_mut()
        .unwrap()
        .remove("lastDayField");
    source["recordTypes"][0]["constraints"][0]["endField"] = json!("valid-through");
    let failure = compile(&source).expect_err("an endField on a last-day interval is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.constraint.temporal-roles-invalid"),
        "{:?}",
        failure.diagnostics()
    );
}

#[test]
fn query_metadata_states_the_inclusive_last_day() {
    let registry = compile(&project("date", "date")).expect("compiles");
    let openapi: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI")
            .bytes,
    )
    .unwrap();
    let rendered = openapi.to_string();
    assert!(
        !rendered.contains("start-inclusive-end-exclusive"),
        "a last-day interval never claims an exclusive end"
    );
    let effective: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("compiled/effective-model.json")
            .expect("effective model")
            .bytes,
    )
    .unwrap();
    assert!(
        effective
            .to_string()
            .contains("start-inclusive-last-day-inclusive"),
        "the compiled query binding states its semantics"
    );
}

#[test]
fn the_record_schema_marker_names_the_last_day_and_its_semantics() {
    let registry = compile(&project("date", "date")).expect("compiles");
    let schema: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("generated/schemas/licence.schema.json")
            .expect("record schema")
            .bytes,
    )
    .unwrap();
    assert_eq!(
        schema["x-registry-temporal"],
        json!({
            "startProperty": "validFrom",
            "endProperty": "validThrough",
            "valueKind": "date",
            "semantics": "start-inclusive-last-day-inclusive",
            "route": "licences",
            "nonOverlapScopeProperties": [["holder"]]
        })
    );
}
