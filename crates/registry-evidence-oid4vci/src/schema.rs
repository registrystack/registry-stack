//! Generated JSON Schema for the wallet-delivery runtime configuration.
//!
//! The schema is derived from the strict `DeliveryDocument` reader types,
//! never written by hand. Regenerate the committed document with:
//!
//! ```bash
//! cargo run -p registry-evidence-oid4vci --features schema --example runtime-schema -- \
//!   --output products/evidence/generated/oid4vci-runtime
//! ```
//!
//! The schema states the shape and the per-member bounds the reader enforces.
//! The rules that relate members to one another, such as https outside
//! supervised local development or a nonce lifetime within the access token
//! lifetime, are the reader's and `evidence-oid4vci check` reports them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::config::{
    DeliveryDocument, OID4VCI_RUNTIME_API_VERSION, OID4VCI_RUNTIME_KIND, OID4VCI_RUNTIME_SCHEMA_ID,
    RUNTIME_SCHEMA_FILE,
};

/// The runtime schema document, keyed by its file name.
pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(DeliveryDocument))?;
    refuse_null_outside_shared_blocks(&mut derived)?;
    set_const(&mut derived, "apiVersion", OID4VCI_RUNTIME_API_VERSION);
    set_const(&mut derived, "kind", OID4VCI_RUNTIME_KIND);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for DeliveryDocument"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(OID4VCI_RUNTIME_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Evidence OID4VCI delivery runtime configuration".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(RUNTIME_SCHEMA_FILE, rendered)].into())
}

/// The reader refuses `null` in every member (CFG-EMPTY-1), so drop the
/// `null` schemars adds to each optional delivery member. The shared blocks
/// are embedded exactly as the platform publishes them.
fn refuse_null_outside_shared_blocks(schema: &mut Value) -> Result<(), serde_json::Error> {
    let shared: Value =
        serde_json::from_str(&registry_platform_config::schema::shared_blocks_document()?)?;
    let shared: BTreeSet<String> = shared
        .get("$defs")
        .and_then(Value::as_object)
        .map(|definitions| definitions.keys().cloned().collect())
        .unwrap_or_default();
    let Some(object) = schema.as_object_mut() else {
        return Ok(());
    };
    for (key, member) in object.iter_mut() {
        if key != "$defs" {
            refuse_null(member);
            continue;
        }
        if let Some(definitions) = member.as_object_mut() {
            for (name, definition) in definitions.iter_mut() {
                if !shared.contains(name) {
                    refuse_null(definition);
                }
            }
        }
    }
    Ok(())
}

/// Remove `null` from every type list, `anyOf`, and `default` below `schema`.
fn refuse_null(schema: &mut Value) {
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

    fn runtime_schema() -> jsonschema::JSONSchema {
        let document: Value =
            serde_json::from_str(&runtime_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&document)
            .expect("the generated schema compiles")
    }

    /// The reference deployment the reader tests load, as JSON.
    fn reference_instance() -> Value {
        serde_json::json!({
            "apiVersion": OID4VCI_RUNTIME_API_VERSION,
            "kind": OID4VCI_RUNTIME_KIND,
            "credentialIssuer": "https://wallet.example.org",
            "listener": {"bind": "127.0.0.1:8090"},
            "secretProviders": {"file": {"root": "/run/secrets/evidence-oid4vci"}},
            "evidence": {"baseUrl": "https://evidence.example.org"},
            "tokenClient": {
                "tokenEndpoint": "https://mint.example.org/token",
                "clientId": "evidence-oid4vci",
                "privateKeyRef": "secret:file/delivery-client.jwk.json"
            },
            "offers": {
                "issuer": "https://mint.example.org",
                "jwksUri": "https://mint.example.org/.well-known/jwks.json",
                "audiences": ["https://wallet.example.org"],
                "algorithms": ["EdDSA"],
                "authorizedClients": ["adopter-front-end"],
                "requiredScopes": ["oid4vci:offer"],
                "maximumTokenLifetimeSeconds": 900
            },
            "store": {
                "maximumOffers": 4096,
                "offerLifetimeSeconds": 300,
                "accessTokenLifetimeSeconds": 300,
                "nonceLifetimeSeconds": 120,
                "maximumTransactionCodeAttempts": 3
            }
        })
    }

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        let second = runtime_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[RUNTIME_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], OID4VCI_RUNTIME_SCHEMA_ID);
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            OID4VCI_RUNTIME_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            OID4VCI_RUNTIME_KIND
        );
    }

    #[test]
    fn the_schema_accepts_the_reference_deployment_and_refuses_what_the_reader_refuses() {
        let schema = runtime_schema();
        let instance = reference_instance();
        assert!(schema.is_valid(&instance));

        let refused = |change: &dyn Fn(&mut Value)| {
            let mut document = instance.clone();
            change(&mut document);
            !schema.is_valid(&document)
        };
        assert!(refused(&|document| document["version"] = Value::from(1)));
        assert!(refused(&|document| {
            document["tokenClient"]["privateKeyFile"] = Value::from("client.jwk")
        }));
        assert!(refused(
            &|document| document["listener"]["port"] = Value::from(8090)
        ));
        assert!(refused(&|document| document["store"] = Value::Null));
        assert!(refused(&|document| {
            document["tokenClient"]["privateKeyRef"] = Value::from("/run/secrets/client.jwk")
        }));
        assert!(refused(&|document| {
            document["offers"]["authorizedClients"] = serde_json::json!([])
        }));
        assert!(refused(&|document| {
            document["offers"]["requiredScopes"] = Value::from("anything")
        }));
        assert!(refused(&|document| {
            document["offers"]
                .as_object_mut()
                .unwrap()
                .remove("requiredScopes");
        }));
        assert!(refused(&|document| {
            document["offers"]["audiences"] = serde_json::json!(["a", "a"])
        }));
        assert!(refused(&|document| {
            document["store"]["maximumOffers"] = Value::from(255)
        }));
        assert!(!refused(&|document| {
            document["offers"]["authorizedClients"] = Value::from("unrestricted")
        }));
    }

    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let generated = runtime_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/generated/oid4vci-runtime")
            .join(RUNTIME_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(&committed).unwrap_or_default(),
            generated[RUNTIME_SCHEMA_FILE],
            "{} is stale; regenerate it with `cargo run -p registry-evidence-oid4vci \
             --features schema --example runtime-schema -- --output \
             products/evidence/generated/oid4vci-runtime`",
            committed.display()
        );
    }
}
