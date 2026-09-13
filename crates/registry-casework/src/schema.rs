// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework runtime configuration.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::{RuntimeConfig, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND};

pub const RUNTIME_CONFIG_SCHEMA_FILE: &str = "runtime.schema.json";
pub const RUNTIME_CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/runtime/runtime.v1alpha1.schema.json";
const SECRET_REFERENCE_SCHEMA_PATTERN: &str =
    "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    set_const(&mut derived, "apiVersion", RUNTIME_CONFIG_API_VERSION);
    set_const(&mut derived, "kind", RUNTIME_CONFIG_KIND);
    install_runtime_constraints(&mut derived);
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
        Value::String(RUNTIME_CONFIG_SCHEMA_ID.to_owned()),
    );
    object.insert(
        "title".to_owned(),
        Value::String("Registry Casework runtime configuration".to_owned()),
    );
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok([(RUNTIME_CONFIG_SCHEMA_FILE, rendered)].into())
}

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
        ("TaskAuthorityConfig", "signingKeyRef"),
        ("BregBinding", "clientIdRef"),
        ("BregBinding", "clientAssertionKeyRef"),
        ("BregBinding", "webhookSecretRef"),
        ("BregBinding", "trustedRootCertificatesRef"),
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
    if let Some(sources) = schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut("sources"))
        .and_then(Value::as_object_mut)
    {
        sources.insert(
            "propertyNames".to_owned(),
            serde_json::json!({"minLength": 1}),
        );
    }
}

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
    use crate::RuntimeConfigError;
    use jsonschema::{Draft, JSONSchema};

    fn runtime_schema() -> JSONSchema {
        let documents = runtime_documents().expect("the runtime schema generates");
        let document: Value = serde_json::from_str(&documents[RUNTIME_CONFIG_SCHEMA_FILE])
            .expect("the runtime schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the runtime schema compiles as Draft 2020-12")
    }

    fn runtime_instance(document_ref: &str, provider: &str) -> Value {
        let secret_providers = match provider {
            "environment" => serde_json::json!({"environment": {}}),
            "file" => serde_json::json!({"file": {"root": "/run/casework/secrets"}}),
            "both" => serde_json::json!({
                "environment": {},
                "file": {"root": "/run/casework/secrets"}
            }),
            _ => panic!("unsupported test provider"),
        };
        let supporting_reference = if provider == "file" {
            "secret:file/runtime"
        } else {
            "secret:env/RUNTIME"
        };
        serde_json::json!({
            "apiVersion": RUNTIME_CONFIG_API_VERSION,
            "kind": RUNTIME_CONFIG_KIND,
            "package": {"root": "/var/lib/casework/package"},
            "listener": {"tlsTermination": "development-loopback"},
            "secretProviders": secret_providers,
            "database": {
                "runtimeUrlRef": supporting_reference,
                "migrationUrlRef": supporting_reference
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:casework",
                "jwksSource": {"kind": "static", "documentRef": document_ref}
            }},
            "audit": {"path": "/var/log/casework/audit.jsonl", "hashKeyRef": supporting_reference}
        })
    }

    #[test]
    fn runtime_schema_is_deterministic_and_versioned() {
        let first = runtime_documents().unwrap();
        let second = runtime_documents().unwrap();
        assert_eq!(first, second);
        let document: Value = serde_json::from_str(&first[RUNTIME_CONFIG_SCHEMA_FILE]).unwrap();
        assert_eq!(document["$id"], RUNTIME_CONFIG_SCHEMA_ID);
        assert_eq!(
            document["properties"]["apiVersion"]["const"],
            RUNTIME_CONFIG_API_VERSION
        );
        assert_eq!(document["properties"]["kind"]["const"], RUNTIME_CONFIG_KIND);
        assert_eq!(
            document["$defs"]["RuntimePackageConfig"]["properties"]["root"]["pattern"],
            "^/"
        );
        assert_eq!(
            document["$defs"]["SecretProvidersConfig"]["anyOf"],
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ])
        );
        assert_eq!(
            document["$defs"]["OidcJwksSource"]["oneOf"][1]["properties"]["documentRef"]["pattern"],
            SECRET_REFERENCE_SCHEMA_PATTERN
        );
    }

    #[test]
    fn static_jwks_secret_reference_schema_matches_runtime_validation() {
        let schema = runtime_schema();
        for reference in [
            "plain-value",
            "secret:env/lowercase",
            "secret:file/../jwks.json",
        ] {
            let instance = runtime_instance(reference, "both");
            let config: RuntimeConfig =
                serde_json::from_value(instance.clone()).expect("the runtime shape parses");
            assert!(matches!(
                config.check(),
                Err(RuntimeConfigError::InvalidSecretReference { path })
                    if path == "authentication.oidc.jwksSource.documentRef"
            ));
            assert!(
                !schema.is_valid(&instance),
                "schema accepted runtime-refused static JWKS reference"
            );
        }

        for (reference, enabled_provider, disabled_provider) in [
            ("secret:env/CASEWORK_JWKS", "file", "environment"),
            ("secret:file/jwks.json", "environment", "file"),
        ] {
            for explicit_null in [false, true] {
                let mut instance = runtime_instance(reference, enabled_provider);
                if explicit_null {
                    instance["secretProviders"][disabled_provider] = Value::Null;
                }
                let config: RuntimeConfig =
                    serde_json::from_value(instance.clone()).expect("the runtime shape parses");
                assert!(matches!(
                    config.check(),
                    Err(RuntimeConfigError::SecretProviderRequired { path })
                        if path == "authentication.oidc.jwksSource.documentRef"
                ));
                assert!(
                    !schema.is_valid(&instance),
                    "schema accepted a static JWKS reference with its provider disabled"
                );
            }
        }

        assert!(schema.is_valid(&runtime_instance("secret:env/CASEWORK_JWKS", "environment")));
        assert!(schema.is_valid(&runtime_instance("secret:file/jwks.json", "file")));
    }

    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let generated = runtime_documents().unwrap();
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/casework/generated/runtime")
            .join(RUNTIME_CONFIG_SCHEMA_FILE);
        assert_eq!(
            std::fs::read_to_string(committed).unwrap(),
            generated[RUNTIME_CONFIG_SCHEMA_FILE]
        );
    }
}
