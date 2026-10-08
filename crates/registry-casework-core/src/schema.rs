// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework project, `casework.yaml`, and for
//! the offline test files beside it: fixtures, simulations, and holiday sets.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{
    CaseworkFixture, CaseworkHolidaySet, CaseworkProject, CaseworkSimulation, CASEWORK_API_VERSION,
    CASEWORK_FIXTURE_API_VERSION, CASEWORK_FIXTURE_KIND, CASEWORK_HOLIDAY_SET_API_VERSION,
    CASEWORK_HOLIDAY_SET_KIND, CASEWORK_KIND, CASEWORK_SIMULATION_API_VERSION,
    CASEWORK_SIMULATION_KIND,
};

pub const PROJECT_SCHEMA_FILE: &str = "project.schema.json";
pub const PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json";
pub const FIXTURE_SCHEMA_FILE: &str = "fixture/fixture.schema.json";
pub const FIXTURE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/fixture/fixture.v1alpha1.schema.json";
pub const SIMULATION_SCHEMA_FILE: &str = "simulation/simulation.schema.json";
pub const SIMULATION_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/simulation/simulation.v1alpha1.schema.json";
pub const HOLIDAY_SET_SCHEMA_FILE: &str = "holiday-set/holiday-set.schema.json";
pub const HOLIDAY_SET_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/holiday-set/holiday-set.v1alpha1.schema.json";

/// The committed schema documents, by file name.
pub fn project_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let rendered = render(
        schemars::schema_for!(CaseworkProject),
        CASEWORK_API_VERSION,
        CASEWORK_KIND,
        PROJECT_SCHEMA_ID,
        "Registry Casework project",
    )?;
    Ok([(PROJECT_SCHEMA_FILE, rendered)].into())
}

/// The committed schema documents of the offline test files, by path below
/// `products/casework/generated`.
pub fn offline_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok([
        (
            FIXTURE_SCHEMA_FILE,
            render(
                schemars::schema_for!(CaseworkFixture),
                CASEWORK_FIXTURE_API_VERSION,
                CASEWORK_FIXTURE_KIND,
                FIXTURE_SCHEMA_ID,
                "Registry Casework fixture",
            )?,
        ),
        (
            SIMULATION_SCHEMA_FILE,
            render(
                schemars::schema_for!(CaseworkSimulation),
                CASEWORK_SIMULATION_API_VERSION,
                CASEWORK_SIMULATION_KIND,
                SIMULATION_SCHEMA_ID,
                "Registry Casework simulation",
            )?,
        ),
        (
            HOLIDAY_SET_SCHEMA_FILE,
            render(
                schemars::schema_for!(CaseworkHolidaySet),
                CASEWORK_HOLIDAY_SET_API_VERSION,
                CASEWORK_HOLIDAY_SET_KIND,
                HOLIDAY_SET_SCHEMA_ID,
                "Registry Casework holiday set",
            )?,
        ),
    ]
    .into())
}

/// One committed schema document: the derived schema with `null` refused,
/// each stated zero minimum kept, identifier-keyed maps typed, the envelope
/// pinned to `api_version` and `kind`, and the `$id` and title set.
pub fn render(
    schema: schemars::Schema,
    api_version: &str,
    kind: &str,
    id: &str,
    title: &str,
) -> Result<String, serde_json::Error> {
    let mut derived = serde_json::to_value(schema)?;
    // A record value is the one position where `null` is a value
    // (CFG-EMPTY-1), so its definition keeps the `null` type.
    let literal = derived.pointer("/$defs/DataLiteral").cloned();
    refuse_null(&mut derived);
    if let (Some(literal), Some(slot)) = (literal, derived.pointer_mut("/$defs/DataLiteral")) {
        *slot = literal;
    }
    state_zero_minimum(&mut derived);
    // A type used only as a map key is inlined as a pattern, so the
    // definitions come from the types rather than from `$defs`.
    let definitions = [
        ("LocalId", definition::<registry_platform_yaml::LocalId>()?),
        (
            "ExternalId",
            definition::<registry_platform_yaml::ExternalId>()?,
        ),
    ];
    let identifiers = definitions
        .iter()
        .filter_map(|(name, definition)| {
            let pattern = definition.get("pattern")?.as_str()?.to_owned();
            Some((pattern, *name))
        })
        .collect::<BTreeMap<_, _>>();
    type_map_keys(&mut derived, &identifiers);
    for (name, definition) in definitions {
        let pointer = format!("#/$defs/{name}");
        if references(&derived, &pointer) {
            if let Some(Value::Object(defs)) = derived.get_mut("$defs") {
                defs.entry(name).or_insert(definition);
            }
        }
    }
    set_const(&mut derived, "apiVersion", api_version);
    set_const(&mut derived, "kind", kind);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(id.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok(rendered)
}

/// The reader refuses `null` in every member (CFG-EMPTY-1), so an optional
/// member is written by leaving it out: drop the `null` schemars adds to an
/// `Option` and the `default: null` it declares for one.
pub fn refuse_null(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if object.get("default") == Some(&Value::Null) {
                object.remove("default");
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [only] = types.as_slice() {
                    let only = only.clone();
                    object.insert("type".to_owned(), only);
                }
            }
            if let Some(Value::Array(branches)) = object.get_mut("anyOf") {
                branches.retain(|branch| branch.get("type") != Some(&Value::from("null")));
                if let [only] = branches.as_slice() {
                    let only = only.clone();
                    object.remove("anyOf");
                    if let Value::Object(only) = only {
                        object.extend(only);
                    }
                }
            }
            for member in object.values_mut() {
                refuse_null(member);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(refuse_null),
        _ => {}
    }
}

/// A bounded whole number whose least value is zero states `minimum: 0`
/// beside the unsigned `format` schemars adds, which reads as the format's
/// implicit bound rather than a stated one (CFG-QTY-4). Both bounds are
/// stated, so the format says nothing more and is dropped.
fn state_zero_minimum(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            let unsigned = object
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|format| format.starts_with("uint"));
            if unsigned
                && object.get("minimum") == Some(&Value::from(0))
                && object.contains_key("maximum")
            {
                object.remove("format");
            }
            object.values_mut().for_each(state_zero_minimum);
        }
        Value::Array(items) => items.iter_mut().for_each(state_zero_minimum),
        _ => {}
    }
}

/// Schemars writes a map keyed by an identifier type as `patternProperties`
/// under the identifier's pattern, which drops its other bounds. State the
/// key as the identifier itself (CFG-SCHEMA-4, CFG-ID-1):
/// `propertyNames: {$ref: #/$defs/<identifier>}` and
/// `additionalProperties: <value schema>`.
fn type_map_keys(schema: &mut Value, identifiers: &BTreeMap<String, &str>) {
    match schema {
        Value::Object(object) => {
            let keyed = match object.get("patternProperties") {
                Some(Value::Object(patterns)) if patterns.len() == 1 => {
                    patterns.iter().next().and_then(|(pattern, value)| {
                        identifiers.get(pattern).map(|name| (*name, value.clone()))
                    })
                }
                _ => None,
            };
            if let Some((name, value)) = keyed {
                object.remove("patternProperties");
                object.insert(
                    "propertyNames".to_owned(),
                    serde_json::json!({"$ref": format!("#/$defs/{name}")}),
                );
                object.insert("additionalProperties".to_owned(), value);
            }
            for member in object.values_mut() {
                type_map_keys(member, identifiers);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| type_map_keys(item, identifiers)),
        _ => {}
    }
}

/// The definition of a shared type, as `$defs` holds it.
fn definition<T: schemars::JsonSchema>() -> Result<Value, serde_json::Error> {
    serde_json::to_value(T::json_schema(&mut schemars::SchemaGenerator::default()))
}

/// Whether any `$ref` in `schema` is `pointer`.
fn references(schema: &Value, pointer: &str) -> bool {
    match schema {
        Value::Object(object) => {
            object.get("$ref").and_then(Value::as_str) == Some(pointer)
                || object.values().any(|member| references(member, pointer))
        }
        Value::Array(items) => items.iter().any(|item| references(item, pointer)),
        _ => false,
    }
}

fn set_const(schema: &mut Value, property: &str, expected: &str) {
    if let Some(member) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut(property))
        .and_then(Value::as_object_mut)
    {
        member.insert("const".to_owned(), Value::String(expected.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::{Draft, JSONSchema};

    fn project_schema() -> JSONSchema {
        let documents = project_documents().expect("the project schema generates");
        let document: Value = serde_json::from_str(&documents[PROJECT_SCHEMA_FILE])
            .expect("the project schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the project schema compiles as Draft 2020-12")
    }

    fn example(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples")
            .join(name)
            .join("casework.yaml");
        let text = std::fs::read_to_string(path).expect("read the example");
        serde_norway::from_str(&text).expect("the example is YAML")
    }

    #[test]
    fn every_maintained_example_validates_against_the_project_schema() {
        let schema = project_schema();
        for name in [
            "multi-stage-routing-clocks",
            "payment-review",
            "professional-review",
            "standalone-decision",
        ] {
            let document = example(name);
            let errors = schema
                .validate(&document)
                .err()
                .map(|errors| {
                    errors
                        .map(|error| format!("{} {error}", error.instance_path))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            assert!(errors.is_empty(), "{name}: {errors:#?}");
        }
    }

    #[test]
    fn the_project_schema_refuses_what_the_reader_refuses() {
        let schema = project_schema();
        let valid = example("standalone-decision");
        assert!(schema.is_valid(&valid));
        let mut unknown = valid.clone();
        unknown["queuez"] = Value::Array(Vec::new());
        assert!(!schema.is_valid(&unknown));
        let mut null = valid.clone();
        null["queues"][0]["label"] = Value::Null;
        assert!(!schema.is_valid(&null));
        let mut version = valid;
        version["apiVersion"] = Value::from("registry.registrystack.org/casework/v1alpha0");
        assert!(!schema.is_valid(&version));
    }

    #[test]
    fn project_schema_is_deterministic_and_versioned() {
        let first = project_documents().unwrap();
        let second = project_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[PROJECT_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], PROJECT_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            CASEWORK_API_VERSION
        );
        assert_eq!(document["properties"]["kind"]["const"], CASEWORK_KIND);
    }

    fn offline_schema(file: &str) -> JSONSchema {
        let documents = offline_documents().expect("the offline schemas generate");
        let document: Value =
            serde_json::from_str(&documents[file]).expect("the offline schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the offline schema compiles as Draft 2020-12")
    }

    fn example_file(path: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples")
            .join(path);
        let text = std::fs::read_to_string(path).expect("read the example");
        serde_norway::from_str(&text).expect("the example is YAML")
    }

    fn assert_valid(schema: &JSONSchema, name: &str, document: &Value) {
        let errors = schema
            .validate(document)
            .err()
            .map(|errors| {
                errors
                    .map(|error| format!("{} {error}", error.instance_path))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(errors.is_empty(), "{name}: {errors:#?}");
    }

    #[test]
    fn every_maintained_offline_example_validates_against_its_schema() {
        let fixture = offline_schema(FIXTURE_SCHEMA_FILE);
        for name in [
            "multi-stage-routing-clocks/fixtures/multi-stage-policy.yaml",
            "payment-review/fixtures/payment-review.yaml",
            "professional-review/fixtures/professional-review.yaml",
            "standalone-decision/fixtures/standalone-decision.yaml",
        ] {
            assert_valid(&fixture, name, &example_file(name));
        }
        let simulation = offline_schema(SIMULATION_SCHEMA_FILE);
        for name in [
            "multi-stage-routing-clocks/simulations/friday-review.yaml",
            "multi-stage-routing-clocks/simulations/resubmitted-response.yaml",
        ] {
            assert_valid(&simulation, name, &example_file(name));
        }
        let name = "multi-stage-routing-clocks/simulations/holiday-sets/office-holidays-7.yaml";
        assert_valid(
            &offline_schema(HOLIDAY_SET_SCHEMA_FILE),
            name,
            &example_file(name),
        );
    }

    #[test]
    fn the_offline_schemas_refuse_what_the_reader_refuses() {
        let fixture = offline_schema(FIXTURE_SCHEMA_FILE);
        let valid = example_file("professional-review/fixtures/professional-review.yaml");
        assert!(fixture.is_valid(&valid));
        let mut none = valid.clone();
        none["expect"]["target"] = Value::from("none");
        assert!(fixture.is_valid(&none));
        let mut null = valid.clone();
        null["expect"]["target"] = Value::Null;
        assert!(!fixture.is_valid(&null));
        let mut zero = valid.clone();
        zero["expect"]["target"]["elapsedMinutes"] = Value::from(0);
        assert!(!fixture.is_valid(&zero));
        let mut retired = valid;
        retired["name"] = Value::from("professional-review-offline");
        assert!(!fixture.is_valid(&retired));
        let review = example_file("payment-review/fixtures/payment-review.yaml");
        assert!(fixture.is_valid(&review));
        let mut empty_display = review.clone();
        empty_display["review"]["display"]["currency"] = Value::Null;
        assert!(!fixture.is_valid(&empty_display));
        let mut control_key = review;
        control_key["review"]["display"]["line\nbreak"] = Value::from("x");
        assert!(!fixture.is_valid(&control_key));

        let simulation = offline_schema(SIMULATION_SCHEMA_FILE);
        let valid = example_file("multi-stage-routing-clocks/simulations/friday-review.yaml");
        let mut literal = valid.clone();
        literal["subject"]["fields"]["region"] = Value::Null;
        assert!(simulation.is_valid(&literal), "a field value may be null");
        let mut nested = valid.clone();
        nested["subject"]["fields"]["region"] = serde_json::json!(["north"]);
        assert!(!simulation.is_valid(&nested));
        let mut long_field = valid.clone();
        long_field["subject"]["fields"]["f".repeat(513)] = Value::from("north");
        assert!(!simulation.is_valid(&long_field));
        let mut holiday_set = valid.clone();
        holiday_set["holidayRevisions"]["Office"] = Value::from(7);
        assert!(!simulation.is_valid(&holiday_set));
        let mut state = valid;
        state["expect"]["dueState"] = Value::from("atRisk");
        assert!(!simulation.is_valid(&state));

        let holidays = offline_schema(HOLIDAY_SET_SCHEMA_FILE);
        let valid = example_file(
            "multi-stage-routing-clocks/simulations/holiday-sets/office-holidays-7.yaml",
        );
        let mut repeated = valid.clone();
        repeated["dates"] = serde_json::json!(["2026-09-07", "2026-09-07"]);
        assert!(!holidays.is_valid(&repeated));
        let mut zero = valid;
        zero["revision"] = Value::from(0);
        assert!(!holidays.is_valid(&zero));
    }

    #[test]
    fn a_whole_number_that_may_be_zero_states_both_bounds() {
        let simulation: Value =
            serde_json::from_str(&offline_documents().unwrap()[SIMULATION_SCHEMA_FILE]).unwrap();
        for pointer in [
            "/$defs/SimulationExpectation/properties/remainingMilliseconds",
            "/$defs/SimulationReviewTiming/properties/pausedMilliseconds",
        ] {
            let member = simulation.pointer(pointer).unwrap();
            assert_eq!(member["minimum"], 0, "{pointer}");
            assert!(member["maximum"].is_u64(), "{pointer}");
            assert!(member.get("format").is_none(), "{pointer}");
        }
    }

    #[test]
    fn offline_schemas_are_deterministic_and_versioned() {
        let first = offline_documents().unwrap();
        assert_eq!(first, offline_documents().unwrap());
        for (file, id, api_version, kind) in [
            (
                FIXTURE_SCHEMA_FILE,
                FIXTURE_SCHEMA_ID,
                CASEWORK_FIXTURE_API_VERSION,
                CASEWORK_FIXTURE_KIND,
            ),
            (
                SIMULATION_SCHEMA_FILE,
                SIMULATION_SCHEMA_ID,
                CASEWORK_SIMULATION_API_VERSION,
                CASEWORK_SIMULATION_KIND,
            ),
            (
                HOLIDAY_SET_SCHEMA_FILE,
                HOLIDAY_SET_SCHEMA_ID,
                CASEWORK_HOLIDAY_SET_API_VERSION,
                CASEWORK_HOLIDAY_SET_KIND,
            ),
        ] {
            let document: Value = serde_json::from_str(&first[file]).unwrap();
            assert_eq!(document["$id"], id);
            assert_eq!(document["properties"]["apiVersion"]["const"], api_version);
            assert_eq!(document["properties"]["kind"]["const"], kind);
        }
    }

    #[test]
    fn committed_offline_schemas_match_generated_bytes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated");
        for (file, generated) in offline_documents().unwrap() {
            assert_eq!(
                std::fs::read_to_string(root.join(file)).unwrap_or_default(),
                generated,
                "products/casework/generated/{file} differs from its generator; run cargo run -p registry-casework-core --features schema --example offline-schemas -- --output products/casework/generated"
            );
        }
    }

    #[test]
    fn committed_project_schema_matches_generated_bytes() {
        let generated = project_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated/project")
            .join(PROJECT_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[PROJECT_SCHEMA_FILE],
            "products/casework/generated/project/{PROJECT_SCHEMA_FILE} differs from its generator; run cargo run -p registry-casework-core --features schema --example project-schema -- --output products/casework/generated/project"
        );
    }
}
