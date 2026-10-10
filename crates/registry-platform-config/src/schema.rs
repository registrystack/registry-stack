//! The canonical JSON Schema of the shared runtime configuration blocks.

use serde_json::{Map, Value};

use crate::blocks::{
    AuditKeyConfig, DatabaseConfig, JwksSource, ListenerConfig, OidcClientsConfig,
    OidcIssuerConfig, PackageConfig, PrivateListenerConfig, SecretProvidersConfig,
};

/// File name the shared-blocks generator writes.
pub const SHARED_BLOCKS_SCHEMA_FILE: &str = "runtime-config-blocks.schema.json";

/// Every shared block as a definition, keyed by the name a runtime schema
/// derived with schemars gives it.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)]
struct SharedBlocks {
    secret_providers: SecretProvidersConfig,
    database: DatabaseConfig,
    jwks_source: JwksSource,
    package: PackageConfig,
    listener: ListenerConfig,
    private_listener: PrivateListenerConfig,
    audit_key: AuditKeyConfig,
    oidc_issuer: OidcIssuerConfig,
    oidc_clients: OidcClientsConfig,
}

/// The pretty-printed shared-blocks document, newline terminated.
pub fn shared_blocks_document() -> Result<String, serde_json::Error> {
    let derived = serde_json::to_value(schemars::schema_for!(SharedBlocks))?;
    let definitions = derived.get("$defs").cloned().unwrap_or_default();
    let mut document = Map::new();
    document.insert(
        "$schema".to_owned(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    document.insert(
        "title".to_owned(),
        Value::String("Registry Stack shared runtime configuration blocks".to_owned()),
    );
    document.insert("$defs".to_owned(), definitions);
    let mut rendered = serde_json::to_string_pretty(&Value::Object(document))?;
    rendered.push('\n');
    Ok(rendered)
}

/// Root `allOf` members stating that a static JWKS document at
/// `authentication.oidc.jwksSource.documentRef` names a secret provider by
/// its prefix, so a configuration carrying one must enable that provider.
pub fn jwks_document_provider_requirements() -> Value {
    serde_json::json!([
        secret_provider_requirement(
            "^secret:env/",
            "environment",
            "EnvironmentSecretProviderConfig"
        ),
        secret_provider_requirement("^secret:file/", "file", "FileSecretProviderConfig"),
    ])
}

fn secret_provider_requirement(reference_pattern: &str, provider: &str, definition: &str) -> Value {
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
                        provider: {"$ref": format!("#/$defs/{definition}")}
                    },
                    "required": [provider]
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn null_admissions(node: &Value, pointer: &str, found: &mut Vec<String>) {
        match node {
            Value::Object(members) => {
                let kind = members.get("type");
                if kind == Some(&Value::from("null"))
                    || kind
                        .and_then(Value::as_array)
                        .is_some_and(|kinds| kinds.contains(&Value::from("null")))
                {
                    found.push(pointer.to_owned());
                }
                for (key, member) in members {
                    null_admissions(member, &format!("{pointer}/{key}"), found);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    null_admissions(item, &format!("{pointer}/{index}"), found);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn cfg_empty_1_the_shared_blocks_admit_null_where_the_reader_does_nowhere() {
        use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader};

        const PROVIDERS: FormatSpec<'static> = FormatSpec {
            kind: "SecretProviders",
            envelope: EnvelopeRule::Exempt {
                reason: "one shared block read alone",
            },
            removed_keys: &[],
        };
        for (member, yaml) in [("file", "file: null\n"), ("environment", "environment:\n")] {
            let refused = Reader::new("providers.yaml")
                .decode::<SecretProvidersConfig>(yaml.as_bytes(), &Expect::one(&PROVIDERS))
                .unwrap_err();
            let found: Vec<_> = refused
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
                .collect();
            assert_eq!(
                found,
                [("config.null-value", format!("/{member}").as_str())]
            );
        }

        let document: Value = serde_json::from_str(&shared_blocks_document().unwrap()).unwrap();
        let mut found = Vec::new();
        null_admissions(&document, "", &mut found);
        assert!(
            found.is_empty(),
            "the shared blocks admit null at {found:#?}"
        );
    }

    #[test]
    fn a_static_jwks_document_requires_the_provider_its_reference_names() {
        let requirement = |pattern: &str, provider: &str, definition: &str| {
            serde_json::json!({
                "if": {
                    "properties": {
                        "authentication": {
                            "properties": {
                                "oidc": {
                                    "properties": {
                                        "jwksSource": {
                                            "properties": {"documentRef": {"pattern": pattern}},
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
                            "properties": {provider: {"$ref": format!("#/$defs/{definition}")}},
                            "required": [provider]
                        }
                    }
                }
            })
        };
        assert_eq!(
            jwks_document_provider_requirements(),
            serde_json::json!([
                requirement(
                    "^secret:env/",
                    "environment",
                    "EnvironmentSecretProviderConfig"
                ),
                requirement("^secret:file/", "file", "FileSecretProviderConfig"),
            ])
        );
    }
}
