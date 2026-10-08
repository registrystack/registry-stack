// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework project, `casework.yaml`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{CaseworkProject, CASEWORK_API_VERSION, CASEWORK_KIND};

pub const PROJECT_SCHEMA_FILE: &str = "project.schema.json";
pub const PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json";

/// The committed schema documents, by file name.
pub fn project_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(CaseworkProject))?;
    refuse_null(&mut derived);
    set_const(&mut derived, "apiVersion", CASEWORK_API_VERSION);
    set_const(&mut derived, "kind", CASEWORK_KIND);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(PROJECT_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Casework project".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(PROJECT_SCHEMA_FILE, rendered)].into())
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
