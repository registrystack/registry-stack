// SPDX-License-Identifier: Apache-2.0

//! Generated JSON Schema for the Scheduling runtime configuration.
//!
//! The schema is derived from the strict `RuntimeConfig` types, never written
//! by hand. Regenerate the committed document with:
//!
//! ```bash
//! cargo run -p registry-scheduling --features schema --example runtime-schema -- \
//!   --output products/scheduling/generated/runtime
//! ```
//!
//! The derived schema states the bounds `RuntimeConfig::check` enforces, so
//! a document an operator's editor accepts is one the runtime starts on
//! rather than one it refuses after the operator has already written it.

use std::collections::BTreeMap;

use serde_json::Value;

use registry_scheduling_core::{
    RUNTIME_SCHEMA_FILE, SCHEDULING_RUNTIME_API_VERSION, SCHEDULING_RUNTIME_KIND,
    SCHEDULING_RUNTIME_SCHEMA_ID,
};

use crate::config::RuntimeConfig;

const SECRET_REFERENCE_SCHEMA_PATTERN: &str =
    "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut derived, "apiVersion", SCHEDULING_RUNTIME_API_VERSION);
    set_const(&mut derived, "kind", SCHEDULING_RUNTIME_KIND);
    install_runtime_constraints(&mut derived);
    let mut object = match derived {
        Value::Object(object) => object,
        _ => unreachable!("schemars derives a schema object for RuntimeConfig"),
    };
    object.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        Value::String(SCHEDULING_RUNTIME_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Scheduling runtime configuration".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(RUNTIME_SCHEMA_FILE, rendered)].into())
}

/// State in the schema the bounds `RuntimeConfig::check` and
/// `validate_secret_references` enforce at load: operated paths are absolute,
/// every secret field is a secret reference, a static JWKS document names its
/// provider, and at least one secret provider is configured.
fn install_runtime_constraints(schema: &mut Value) {
    for (definition, property) in [
        ("RuntimePackageConfig", "root"),
        ("FileSecretProviderConfig", "root"),
        ("AuditConfig", "path"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            Value::String("^/".to_owned()),
        );
    }
    for (definition, property) in [
        ("DatabaseConfig", "runtimeUrlRef"),
        ("DatabaseConfig", "migrationUrlRef"),
        ("DatabaseConfig", "trustedRootCertificateRef"),
        ("AuditConfig", "hashKeyRef"),
        ("ReminderDestinationConfig", "bearerTokenRef"),
    ] {
        set_definition_property(
            schema,
            definition,
            property,
            "pattern",
            Value::String("^secret:(?:env|file)/".to_owned()),
        );
    }
    set_jwks_document_reference_constraints(schema);
    if let Some(providers) = schema
        .get_mut("$defs")
        .and_then(|definitions| definitions.get_mut("SecretProvidersConfig"))
        .and_then(Value::as_object_mut)
    {
        providers.insert(
            "anyOf".to_owned(),
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ]),
        );
    }
    if let Some(root) = schema.as_object_mut() {
        root.insert(
            "allOf".to_owned(),
            serde_json::json!([
                secret_provider_requirement("^secret:env/", "environment"),
                secret_provider_requirement("^secret:file/", "file")
            ]),
        );
    }
}

/// A static JWKS document reference is the one secret field whose full
/// reference grammar the schema states: the other fields need only name a
/// provider, while this one an operator authors directly.
fn set_jwks_document_reference_constraints(schema: &mut Value) {
    if let Some(variants) = schema
        .pointer_mut("/$defs/OidcJwksSource/oneOf")
        .and_then(Value::as_array_mut)
    {
        for variant in variants {
            if let Some(document_reference) = variant
                .pointer_mut("/properties/documentRef")
                .and_then(Value::as_object_mut)
            {
                document_reference.insert(
                    "pattern".to_owned(),
                    Value::String(SECRET_REFERENCE_SCHEMA_PATTERN.to_owned()),
                );
            }
        }
    }
}

/// A static JWKS document reference names its provider by its prefix, so a
/// configuration carrying one must enable that provider.
fn secret_provider_requirement(reference_pattern: &str, provider: &str) -> Value {
    serde_json::json!({
        "if": {
            "properties": {
                "authentication": {
                    "properties": {
                        "oidc": {
                            "properties": {
                                "jwksSource": {
                                    "properties": {
                                        "documentRef": {"pattern": reference_pattern}
                                    },
                                    "required": ["documentRef"]
                                }
                            },
                            "required": ["jwksSource"]
                        }
                    },
                    "required": ["oidc"]
                }
            },
            "required": ["authentication"]
        },
        "then": {
            "properties": {
                "secretProviders": {
                    "properties": {
                        provider: {
                            "$ref": format!("#/$defs/{}SecretProviderConfig", match provider {
                                "environment" => "Environment",
                                "file" => "File",
                                _ => unreachable!("closed secret provider schema"),
                            })
                        }
                    },
                    "required": [provider]
                }
            }
        }
    })
}

fn set_definition_property(
    schema: &mut Value,
    definition: &str,
    property: &str,
    keyword: &str,
    value: Value,
) {
    if let Some(member) = schema
        .get_mut("$defs")
        .and_then(|definitions| definitions.get_mut(definition))
        .and_then(|definition| definition.get_mut("properties"))
        .and_then(|properties| properties.get_mut(property))
        .and_then(Value::as_object_mut)
    {
        member.insert(keyword.to_owned(), value);
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

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        let second = runtime_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[RUNTIME_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], SCHEDULING_RUNTIME_SCHEMA_ID);
        assert_eq!(
            document["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            document["title"],
            "Registry Scheduling runtime configuration"
        );
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            SCHEDULING_RUNTIME_API_VERSION
        );
        assert_eq!(
            document["properties"]["kind"]["const"],
            SCHEDULING_RUNTIME_KIND
        );
    }

    #[test]
    fn the_schema_states_the_bounds_the_runtime_enforces() {
        let documents = runtime_documents().unwrap();
        let document: Value = serde_json::from_str(&documents[RUNTIME_SCHEMA_FILE]).unwrap();
        for (definition, property) in [
            ("RuntimePackageConfig", "root"),
            ("FileSecretProviderConfig", "root"),
            ("AuditConfig", "path"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"], "^/",
                "{definition}.{property} must be absolute"
            );
        }
        for (definition, property) in [
            ("DatabaseConfig", "runtimeUrlRef"),
            ("DatabaseConfig", "migrationUrlRef"),
            ("DatabaseConfig", "trustedRootCertificateRef"),
            ("AuditConfig", "hashKeyRef"),
            ("ReminderDestinationConfig", "bearerTokenRef"),
        ] {
            assert_eq!(
                document["$defs"][definition]["properties"][property]["pattern"],
                "^secret:(?:env|file)/",
                "{definition}.{property} must be a secret reference"
            );
        }
        assert_eq!(
            document["$defs"]["SecretProvidersConfig"]["anyOf"],
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ]),
            "at least one secret provider must be configured"
        );
        assert_eq!(
            document["$defs"]["OidcJwksSource"]["oneOf"][1]["properties"]["documentRef"]["pattern"],
            SECRET_REFERENCE_SCHEMA_PATTERN
        );
    }

    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let generated = runtime_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/scheduling/generated/runtime")
            .join(RUNTIME_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[RUNTIME_SCHEMA_FILE]
        );
    }
}
