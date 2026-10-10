// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the local development clients file a Casework
//! project holds, `dev-clients.yaml`.

use std::collections::BTreeMap;

use crate::dev::config::{Clients, DEV_CLIENTS_API_VERSION, DEV_CLIENTS_KIND};

pub const DEV_CLIENTS_SCHEMA_FILE: &str = "dev-clients/dev-clients.schema.json";
pub const DEV_CLIENTS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/dev-clients/dev-clients.v1alpha1.schema.json";

/// The committed schema documents, by path below
/// `products/casework/generated`.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    Ok([(
        DEV_CLIENTS_SCHEMA_FILE,
        registry_casework_core::schema::render(
            schemars::schema_for!(Clients),
            DEV_CLIENTS_API_VERSION,
            DEV_CLIENTS_KIND,
            DEV_CLIENTS_SCHEMA_ID,
            "Registry Casework development clients",
        )?,
    )]
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::{Draft, JSONSchema};
    use serde_json::Value;

    fn schema() -> JSONSchema {
        let document: Value = serde_json::from_str(&documents().unwrap()[DEV_CLIENTS_SCHEMA_FILE])
            .expect("the dev-clients schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the dev-clients schema compiles as Draft 2020-12")
    }

    fn example() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/examples/standalone-decision/dev-clients.yaml");
        let bytes = std::fs::read(path).expect("read the example");
        crate::dev::config::read("dev-clients.yaml", &bytes)
            .expect("the example is accepted")
            .document
            .to_json_value()
    }

    #[test]
    fn the_maintained_example_and_templates_validate_against_the_schema() {
        let schema = schema();
        assert!(schema.is_valid(&example()));
        for template in [
            crate::project::STANDALONE_DEV_CLIENTS,
            crate::project::PROFESSIONAL_REVIEW_DEV_CLIENTS,
        ] {
            let document = crate::dev::config::read("dev-clients.yaml", template.as_bytes())
                .unwrap()
                .document
                .to_json_value();
            assert!(schema.is_valid(&document));
        }
    }

    #[test]
    fn the_schema_refuses_what_the_reader_refuses() {
        let schema = schema();
        let valid = example();
        let mut unknown = valid.clone();
        unknown["client"] = Value::Array(Vec::new());
        assert!(!schema.is_valid(&unknown));
        let mut retired = valid.clone();
        retired["version"] = Value::from(1);
        assert!(!schema.is_valid(&retired));
        let mut null = valid.clone();
        null["directory"] = Value::Null;
        assert!(!schema.is_valid(&null));
        let mut port = valid.clone();
        port["integrations"] = serde_json::json!({
            "resource": "https://casework.example.test",
            "taskAuthority": {"issuer": "https://issuer.example.test", "jwksPort": 0, "statusClients": {}}
        });
        assert!(!schema.is_valid(&port));
        let mut kind = valid;
        kind["kind"] = Value::from("BregDevClients");
        assert!(!schema.is_valid(&kind));
    }

    #[test]
    fn the_schema_is_deterministic_and_versioned() {
        let first = documents().unwrap();
        assert_eq!(first, documents().unwrap());
        let document: Value = serde_json::from_str(&first[DEV_CLIENTS_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], DEV_CLIENTS_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            DEV_CLIENTS_API_VERSION
        );
        assert_eq!(document["properties"]["kind"]["const"], DEV_CLIENTS_KIND);
    }

    #[test]
    fn committed_schema_matches_generated_bytes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated");
        for (file, generated) in documents().unwrap() {
            assert_eq!(
                std::fs::read_to_string(root.join(file)).unwrap_or_default(),
                generated,
                "products/casework/generated/{file} differs from its generator; run cargo run -p registry-caseworkctl --features schema --example dev-clients-schema -- --output products/casework/generated"
            );
        }
    }
}
