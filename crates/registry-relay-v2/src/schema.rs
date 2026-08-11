// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schemas for Relay V2 authoring documents.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::contract::{RegistryContract, RelayRuntime};

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

pub const REGISTRY_SCHEMA_FILE: &str = "registry.schema.json";
pub const RUNTIME_SCHEMA_FILE: &str = "runtime.schema.json";
pub const REGISTRY_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registry-relay/authoring/registry.v2alpha1.schema.json";
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/registry-relay/authoring/runtime.v2alpha1.schema.json";

/// Every authoring schema under its committed artifact filename.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [
        (
            REGISTRY_SCHEMA_FILE,
            "Relay V2 governed Registry contract",
            REGISTRY_SCHEMA_ID,
            serde_json::to_value(schemars::schema_for!(RegistryContract))?,
        ),
        (
            RUNTIME_SCHEMA_FILE,
            "Relay V2 deployment binding",
            RUNTIME_SCHEMA_ID,
            serde_json::to_value(schemars::schema_for!(RelayRuntime))?,
        ),
    ];
    entries
        .into_iter()
        .map(|(file, title, identifier, derived)| {
            Ok((file, render(published(derived, title, identifier))?))
        })
        .collect()
}

fn published(derived: Value, title: &str, identifier: &str) -> Value {
    let mut object = match derived {
        Value::Object(object) => object,
        other => {
            let mut object = Map::new();
            object.insert("$comment".to_owned(), other);
            object
        }
    };
    object.insert(
        "$schema".to_owned(),
        Value::String(SCHEMA_DIALECT.to_owned()),
    );
    object.insert("$id".to_owned(), Value::String(identifier.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    Value::Object(object)
}

fn render(value: Value) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(&value)?;
    rendered.push('\n');
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_strict_authoring_documents_have_generated_schemas() {
        let documents = documents().unwrap();
        assert_eq!(documents.len(), 2);
        assert!(documents.contains_key(REGISTRY_SCHEMA_FILE));
        assert!(documents.contains_key(RUNTIME_SCHEMA_FILE));
        for (file, expected_id) in [
            (REGISTRY_SCHEMA_FILE, REGISTRY_SCHEMA_ID),
            (RUNTIME_SCHEMA_FILE, RUNTIME_SCHEMA_ID),
        ] {
            let document = &documents[file];
            let value: Value = serde_json::from_str(document).unwrap();
            assert_eq!(value["$schema"], SCHEMA_DIALECT);
            assert_eq!(value["$id"], expected_id);
            assert_eq!(value["additionalProperties"], false);
        }
    }
}
