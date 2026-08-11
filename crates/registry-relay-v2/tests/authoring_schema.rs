// SPDX-License-Identifier: Apache-2.0
//! Agreement between generated editor schemas and the acceptance documents.

#![cfg(feature = "schema")]

use std::{fs, path::Path};

use registry_relay_v2::schema::{documents, REGISTRY_SCHEMA_FILE, RUNTIME_SCHEMA_FILE};
use serde_json::Value;

fn validator(document: &str) -> jsonschema::JSONSchema {
    let schema: Value = serde_json::from_str(document).unwrap();
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap()
}

#[test]
fn schemas_accept_every_coequal_acceptance_project() {
    let documents = documents().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/relay-v2/acceptance");
    for project in [
        "social-assistance",
        "business-registry",
        "civil-event",
        "labour-statistics",
    ] {
        for (file, schema_file) in [
            ("registry.yaml", REGISTRY_SCHEMA_FILE),
            ("runtime.yaml", RUNTIME_SCHEMA_FILE),
        ] {
            let validator = validator(documents.get(schema_file).unwrap());
            let instance: Value =
                serde_norway::from_str(&fs::read_to_string(root.join(project).join(file)).unwrap())
                    .unwrap();
            assert!(validator.is_valid(&instance), "{project}/{file}");
        }
    }
}

#[test]
fn registry_schema_rejects_a_key_the_strict_type_rejects() {
    let documents = documents().unwrap();
    let validator = validator(documents.get(REGISTRY_SCHEMA_FILE).unwrap());
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/relay-v2/acceptance/social-assistance/registry.yaml");
    let mut instance: Value = serde_norway::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    instance["unexpected"] = Value::Bool(true);

    assert!(!validator.is_valid(&instance));
}
