// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schemas for the Scheduling authoring formats, and the
//! shared steps every generated Scheduling schema takes.
//!
//! The schemas are derived from the strict reader types, never written by
//! hand. Regenerate the committed documents with:
//!
//! ```bash
//! cargo run -p registry-scheduling-core --features schema --example authoring-schemas -- \
//!   --output products/scheduling/generated
//! ```

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde_json::Value;

use crate::{
    SchedulingFixture, SchedulingPolicy, SchedulingRecords, SCHEDULING_FIXTURE_API_VERSION,
    SCHEDULING_FIXTURE_KIND, SCHEDULING_FIXTURE_SCHEMA_ID, SCHEDULING_POLICY_API_VERSION,
    SCHEDULING_POLICY_KIND, SCHEDULING_PROJECT_SCHEMA_ID, SCHEDULING_RECORDS_API_VERSION,
    SCHEDULING_RECORDS_KIND, SCHEDULING_RECORDS_SCHEMA_ID,
};

/// The project file's schema, relative to `products/scheduling/generated`.
pub const PROJECT_SCHEMA_PATH: &str = "project/project.schema.json";

/// The records document's schema, relative to `products/scheduling/generated`.
pub const RECORDS_SCHEMA_PATH: &str = "records/records.schema.json";

/// The fixture's schema, relative to `products/scheduling/generated`.
pub const FIXTURE_SCHEMA_PATH: &str = "fixture/fixture.schema.json";

/// Every authoring format's schema, keyed by its path relative to
/// `products/scheduling/generated`.
pub fn authoring_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok([
        (
            PROJECT_SCHEMA_PATH,
            document::<SchedulingPolicy>(&Format {
                id: SCHEDULING_PROJECT_SCHEMA_ID,
                title: "Registry Scheduling project",
                api_version: SCHEDULING_POLICY_API_VERSION,
                kind: SCHEDULING_POLICY_KIND,
            })?,
        ),
        (
            RECORDS_SCHEMA_PATH,
            document::<SchedulingRecords>(&Format {
                id: SCHEDULING_RECORDS_SCHEMA_ID,
                title: "Registry Scheduling records",
                api_version: SCHEDULING_RECORDS_API_VERSION,
                kind: SCHEDULING_RECORDS_KIND,
            })?,
        ),
        (
            FIXTURE_SCHEMA_PATH,
            document::<SchedulingFixture>(&Format {
                id: SCHEDULING_FIXTURE_SCHEMA_ID,
                title: "Registry Scheduling fixture",
                api_version: SCHEDULING_FIXTURE_API_VERSION,
                kind: SCHEDULING_FIXTURE_KIND,
            })?,
        ),
    ]
    .into())
}

struct Format {
    id: &'static str,
    title: &'static str,
    api_version: &'static str,
    kind: &'static str,
}

fn document<T: JsonSchema>(format: &Format) -> Result<String, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(T))?;
    refuse_null(&mut derived);
    set_const(&mut derived, "apiVersion", format.api_version);
    set_const(&mut derived, "kind", format.kind);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for a reader type"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(format.id.to_owned()));
    object.insert("title".to_owned(), Value::String(format.title.to_owned()));
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

/// Pin the root `property` of `schema` to the one value it may hold.
pub fn set_const(schema: &mut Value, property: &str, expected: &str) {
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
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use std::path::{Path, PathBuf};

    use super::*;

    fn generated() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/scheduling/generated")
    }

    fn examples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/scheduling/examples")
    }

    fn schema(path: &str) -> Value {
        serde_json::from_str(&authoring_documents().unwrap()[path]).unwrap()
    }

    fn yaml(path: &Path) -> Value {
        serde_norway::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn assert_valid(schema: &Value, document: &Value, file: &Path) {
        let validator = jsonschema::JSONSchema::compile(schema).unwrap();
        let errors: Vec<String> = match validator.validate(document) {
            Ok(()) => Vec::new(),
            Err(errors) => errors
                .map(|error| error.instance_path.to_string())
                .collect(),
        };
        assert!(
            errors.is_empty(),
            "{} fails its schema at {errors:?}",
            file.display()
        );
    }

    #[test]
    fn authoring_schemas_are_deterministic_and_versioned() {
        let first = authoring_documents().unwrap();
        assert_eq!(first, authoring_documents().unwrap());
        for (path, id, api_version, kind) in [
            (
                PROJECT_SCHEMA_PATH,
                SCHEDULING_PROJECT_SCHEMA_ID,
                SCHEDULING_POLICY_API_VERSION,
                SCHEDULING_POLICY_KIND,
            ),
            (
                RECORDS_SCHEMA_PATH,
                SCHEDULING_RECORDS_SCHEMA_ID,
                SCHEDULING_RECORDS_API_VERSION,
                SCHEDULING_RECORDS_KIND,
            ),
            (
                FIXTURE_SCHEMA_PATH,
                SCHEDULING_FIXTURE_SCHEMA_ID,
                SCHEDULING_FIXTURE_API_VERSION,
                SCHEDULING_FIXTURE_KIND,
            ),
        ] {
            let document = schema(path);
            assert_eq!(document["$id"], id, "{path}");
            assert_eq!(
                document["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(document["properties"]["apiVersion"]["const"], api_version);
            assert_eq!(document["properties"]["kind"]["const"], kind);
            assert_eq!(document["additionalProperties"], false, "{path}");
            assert!(
                !first[path].contains("\"null\""),
                "{path} admits null, which the reader refuses"
            );
        }
    }

    #[test]
    fn committed_authoring_schemas_match_generated_bytes() {
        for (path, generated_bytes) in authoring_documents().unwrap() {
            assert_eq!(
                std::fs::read_to_string(generated().join(path)).unwrap(),
                generated_bytes,
                "{path} drifted from its generator; rerun the authoring-schemas example"
            );
        }
    }

    #[test]
    fn every_example_document_passes_its_schema() {
        let project = schema(PROJECT_SCHEMA_PATH);
        let records = schema(RECORDS_SCHEMA_PATH);
        let fixture = schema(FIXTURE_SCHEMA_PATH);
        let mut fixtures = 0;
        for example in std::fs::read_dir(examples()).unwrap() {
            let example = example.unwrap().path();
            // `formats` holds committed command output, not a project.
            if example.ends_with("formats") {
                continue;
            }
            let policy = example.join("scheduling.yaml");
            assert_valid(&project, &yaml(&policy), &policy);
            let records_file = example.join("records.yaml");
            assert_valid(&records, &yaml(&records_file), &records_file);
            for file in std::fs::read_dir(example.join("fixtures")).unwrap() {
                let file = file.unwrap().path();
                assert_valid(&fixture, &yaml(&file), &file);
                fixtures += 1;
            }
        }
        assert!(fixtures > 0, "the examples carry fixtures");
    }

    #[test]
    fn the_schemas_refuse_what_the_readers_refuse() {
        let example = examples().join("standalone-exact-time");
        let project = jsonschema::JSONSchema::compile(&schema(PROJECT_SCHEMA_PATH)).unwrap();
        let policy = yaml(&example.join("scheduling.yaml"));
        assert!(project.is_valid(&policy));
        for (pointer, value) in [
            (
                "/apiVersion",
                Value::from(crate::RETIRED_SCHEDULING_POLICY_API_VERSION),
            ),
            ("/kind", Value::from("SchedulingPolicyPackage")),
            ("/channels", serde_json::json!([])),
            ("/holdPolicy/ttlMinutes", Value::from(0)),
            ("/holdPolicy/stray", Value::from(1)),
        ] {
            let mut refused = policy.clone();
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            refused
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert(member.to_owned(), value);
            assert!(!project.is_valid(&refused), "{pointer}");
        }
        let records = jsonschema::JSONSchema::compile(&schema(RECORDS_SCHEMA_PATH)).unwrap();
        let mut unenveloped = yaml(&example.join("records.yaml"));
        assert!(records.is_valid(&unenveloped));
        unenveloped.as_object_mut().unwrap().remove("apiVersion");
        assert!(!records.is_valid(&unenveloped));
    }

    #[test]
    fn an_optional_member_loses_its_null_branch_and_null_default() {
        let mut schema = serde_json::json!({
            "properties": {
                "label": {"type": ["string", "null"], "default": null},
                "window": {"anyOf": [{"$ref": "#/$defs/Window"}, {"type": "null"}]}
            }
        });
        refuse_null(&mut schema);
        assert_eq!(
            schema,
            serde_json::json!({
                "properties": {
                    "label": {"type": "string"},
                    "window": {"$ref": "#/$defs/Window"}
                }
            })
        );
    }
}
