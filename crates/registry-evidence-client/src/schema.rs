//! Generated JSON Schemas for the client profile and the reviewed contracts
//! file.
//!
//! Both are derived from the reader types, never written by hand. A
//! contracts file holds the definitions as the service published them, so
//! its schema refers each definition to the published Evidence definitions
//! contract (`evidence-definitions-v1.schema.json`, beside these documents),
//! which owns that shape. Regenerate the committed documents with:
//!
//! ```bash
//! cargo run -p registry-evidence-client --features schema --example client-schema -- \
//!   --output products/evidence/generated
//! ```
//!
//! The schemas state the shape and the per-member bounds the readers
//! enforce. The rules that relate members to one another, such as an https
//! base URL outside local loopback trust, or a definition that meets the
//! request contract, are the readers'.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::profile_file::{
    ContractsDocument, ProfileDocument, EVIDENCE_CLIENT_CONTRACTS_SCHEMA_ID,
    EVIDENCE_CLIENT_PROFILE_SCHEMA_ID,
};

/// Where the client profile schema is written, below the output directory.
pub const CLIENT_PROFILE_SCHEMA_FILE: &str = "client-profile/client-profile.schema.json";
/// Where the reviewed contracts schema is written, below the output
/// directory.
pub const CLIENT_CONTRACTS_SCHEMA_FILE: &str = "client-contracts/client-contracts.schema.json";

/// The client schema documents, keyed by their path below the output
/// directory.
pub fn client_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let profile = document(
        serde_json::to_value(schemars::schema_for!(ProfileDocument))?,
        EVIDENCE_CLIENT_PROFILE_SCHEMA_ID,
        "Evidence client profile",
    )?;
    let contracts = document(
        serde_json::to_value(schemars::schema_for!(ContractsDocument))?,
        EVIDENCE_CLIENT_CONTRACTS_SCHEMA_ID,
        "Evidence client reviewed contracts",
    )?;
    Ok([
        (CLIENT_PROFILE_SCHEMA_FILE, profile),
        (CLIENT_CONTRACTS_SCHEMA_FILE, contracts),
    ]
    .into())
}

fn document(mut derived: Value, id: &str, title: &str) -> Result<String, serde_json::Error> {
    refuse_null(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for a reader document"),
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

/// The readers refuse `null` in every member (CFG-EMPTY-1), so drop the
/// `null` schemars adds to each optional member.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated schema, with the published definitions contract its
    /// contracts schema refers to.
    fn compiled(file: &str) -> jsonschema::JSONSchema {
        let document: Value = serde_json::from_str(&client_documents().unwrap()[file]).unwrap();
        let published: Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../products/evidence/generated/evidence-definitions-v1.schema.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let published_id = published["$id"].as_str().unwrap().to_owned();
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .with_document(published_id, published)
            .compile(&document)
            .expect("the generated schema compiles")
    }

    fn profile_instance() -> Value {
        serde_json::json!({
            "schema": "registry.evidence-client-profile/v1",
            "baseUrl": "https://evidence.example.org",
            "clientId": "relying-party",
            "privateKey": {"source": "file", "path": "relying-party.private.jwk.json"},
            "trust": {"type": "pinned-jwks", "file": "evidence.jwks.json"},
            "contracts": {"type": "reviewed", "file": "evidence.contracts.json"},
            "verification": {"maximumAssertionLifetimeSeconds": 300, "clockSkewSeconds": 30},
            "expected": {
                "audience": "https://relying-party.example.org",
                "issuer": "https://evidence.example.org",
                "provider": "https://registry.example.org",
                "definitions": {
                    "adult-status": {
                        "configurationRevision": format!("sha256:{}", "a".repeat(64)),
                        "evidenceType": "https://example.org/evidence/adult-status",
                        "purpose": "benefit.eligibility",
                        "assuranceProfile": "production",
                        "responseFormat": "signed-jws"
                    }
                }
            },
            "oauth": {
                "clientAssertionAudience": "https://issuer.example.org",
                "resource": "https://evidence.example.org",
                "scopes": ["evidence:request"]
            },
            "maximumMetadataCacheSeconds": 600
        })
    }

    fn contracts_instance() -> Value {
        serde_json::json!({
            "schema": "registry.evidence-client-contracts/v1",
            "assuranceProfile": "production",
            "audience": "https://relying-party.example.org",
            "issuedBy": "https://evidence.example.org",
            "providedBy": "https://registry.example.org",
            "definitions": [{
                "handle": "adult-status",
                "requirement": "https://example.org/requirements/adult-status",
                "configurationRevision": format!("sha256:{}", "a".repeat(64)),
                "kind": "criterion",
                "evidenceType": "https://example.org/evidence/adult-status",
                "purpose": "benefit.eligibility",
                "responseFormats": ["signed-jws"],
                "referenceFrameworks": ["https://example.org/frameworks/benefits"],
                "subjects": [{
                    "role": "applicant",
                    "cardinality": "one",
                    "selector": {
                        "profile": "national-id",
                        "valueOrigin": "request",
                        "fields": [{"type": "string", "name": "id", "minimumBytes": 1, "maximumBytes": 32}]
                    }
                }],
                "concepts": [{
                    "handle": "adult",
                    "concept": "https://example.org/concepts/adult",
                    "required": true,
                    "form": "boolean"
                }]
            }]
        })
    }

    fn refused(
        schema: &jsonschema::JSONSchema,
        instance: &Value,
        change: &dyn Fn(&mut Value),
    ) -> bool {
        let mut document = instance.clone();
        change(&mut document);
        !schema.is_valid(&document)
    }

    #[test]
    fn client_schemas_are_deterministic_and_identified() {
        let first = client_documents().unwrap();
        assert_eq!(first, client_documents().unwrap());
        for (file, id) in [
            (
                CLIENT_PROFILE_SCHEMA_FILE,
                EVIDENCE_CLIENT_PROFILE_SCHEMA_ID,
            ),
            (
                CLIENT_CONTRACTS_SCHEMA_FILE,
                EVIDENCE_CLIENT_CONTRACTS_SCHEMA_ID,
            ),
        ] {
            let document: Value = serde_json::from_str(&first[file]).unwrap();
            assert_eq!(document["$id"], id);
            assert_eq!(
                document["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert!(!first[file].contains("null"), "{file} admits null");
        }
    }

    #[test]
    fn the_profile_schema_accepts_what_the_reader_accepts_and_refuses_its_shapes() {
        let schema = compiled(CLIENT_PROFILE_SCHEMA_FILE);
        let instance = profile_instance();
        assert!(schema.is_valid(&instance));
        crate::read_client_profile(
            "profile.json",
            serde_json::to_string(&instance).unwrap().as_bytes(),
        )
        .expect("the reader accepts the schema's sample");

        assert!(refused(&schema, &instance, &|document| document
            ["version"] =
            Value::from(1)));
        assert!(refused(&schema, &instance, &|document| document["trust"] =
            Value::Null));
        assert!(refused(&schema, &instance, &|document| {
            document["privateKey"] = serde_json::json!({"source": "file"})
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["privateKey"] =
                serde_json::json!({"source": "environment", "variable": "1KEY"})
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["trust"] = serde_json::json!({"type": "https-discovery", "file": "x"})
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["oauth"]["scopes"] = serde_json::json!(["a", "a"])
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["oauth"]["scopes"] = serde_json::json!([])
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["maximumMetadataCacheSeconds"] = Value::from(601)
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["expected"]["definitions"]["Adult"] =
                document["expected"]["definitions"]["adult-status"].clone()
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["expected"]["definitions"]["adult-status"]["responseFormat"] =
                Value::from("sd-jwt-vc-batch")
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["clientId"] = Value::from("a".repeat(257))
        }));
        assert!(!refused(&schema, &instance, &|document| {
            let object = document.as_object_mut().unwrap();
            for optional in [
                "trust",
                "contracts",
                "verification",
                "expected",
                "oauth",
                "maximumMetadataCacheSeconds",
            ] {
                object.remove(optional);
            }
        }));
    }

    #[test]
    fn the_contracts_schema_holds_the_published_definition_shape() {
        let published: Value = serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../products/evidence/generated/evidence-definitions-v1.schema.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let generated: Value =
            serde_json::from_str(&client_documents().unwrap()[CLIENT_CONTRACTS_SCHEMA_FILE])
                .unwrap();
        assert_eq!(
            generated["properties"]["definitions"]["items"]["$ref"],
            format!("{}#/$defs/definition", published["$id"].as_str().unwrap()),
            "each definition refers to the published definitions contract"
        );
        let schema = compiled(CLIENT_CONTRACTS_SCHEMA_FILE);
        let instance = contracts_instance();
        assert!(schema.is_valid(&instance));
        crate::read_reviewed_contracts(
            "evidence.contracts.json",
            serde_json::to_string(&instance).unwrap().as_bytes(),
        )
        .expect("the reader accepts the schema's sample");

        assert!(refused(&schema, &instance, &|document| {
            document["schema"] = Value::from("registry.evidence-definitions/v1")
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["holderBoundBatchMaxSize"] = Value::from(1)
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["definitions"][0]["handle"] = Value::from("Adult")
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["definitions"][0]["subjects"][0]["selector"]["fields"][0]["maximumBytes"] =
                Value::from(8193)
        }));
        assert!(refused(&schema, &instance, &|document| {
            document["definitions"][0]["concepts"][0]["form"] = Value::from("date")
        }));
        assert!(refused(&schema, &instance, &|document| {
            let definition = document["definitions"][0].clone();
            document["definitions"]
                .as_array_mut()
                .unwrap()
                .push(definition);
        }));
    }

    #[test]
    fn the_committed_examples_hold_to_their_schemas_and_readers() {
        let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples");
        let profile = std::fs::read(examples.join("client-profile/client-profile.json")).unwrap();
        assert!(compiled(CLIENT_PROFILE_SCHEMA_FILE)
            .is_valid(&serde_json::from_slice::<Value>(&profile).unwrap()));
        crate::read_client_profile("client-profile.json", &profile)
            .expect("the reader accepts the committed profile example");

        let contracts =
            std::fs::read(examples.join("client-contracts/evidence.contracts.json")).unwrap();
        assert!(compiled(CLIENT_CONTRACTS_SCHEMA_FILE)
            .is_valid(&serde_json::from_slice::<Value>(&contracts).unwrap()));
        crate::read_reviewed_contracts("evidence.contracts.json", &contracts)
            .expect("the reader accepts the committed contracts example");
    }

    #[test]
    fn committed_client_schemas_match_generated_bytes() {
        let generated = client_documents().unwrap();
        for (file, contents) in generated {
            let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/generated")
                .join(file);
            assert_eq!(
                std::fs::read_to_string(&committed).unwrap_or_default(),
                contents,
                "{} is stale; regenerate it with `cargo run -p registry-evidence-client \
                 --features schema --example client-schema -- --output \
                 products/evidence/generated`",
                committed.display()
            );
        }
    }
}
