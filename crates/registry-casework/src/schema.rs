// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for the Casework runtime configuration.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use registry_casework_core::schema::{refuse_null, type_identifier_keyed_maps};

use crate::{RuntimeConfig, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND};

pub const RUNTIME_CONFIG_SCHEMA_FILE: &str = "runtime.schema.json";
pub const RUNTIME_CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/casework/runtime/runtime.v1alpha1.schema.json";

pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut derived = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    refuse_null_outside_shared_blocks(&mut derived)?;
    type_identifier_keyed_maps(&mut derived)?;
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

/// The reader refuses `null` in every member (CFG-EMPTY-1), so drop the
/// `null` schemars adds to each optional Casework member. The shared blocks
/// are embedded exactly as the platform publishes them.
fn refuse_null_outside_shared_blocks(schema: &mut Value) -> Result<(), serde_json::Error> {
    let shared: Value =
        serde_json::from_str(&registry_platform_config::schema::shared_blocks_document()?)?;
    let shared = shared
        .get("$defs")
        .and_then(Value::as_object)
        .map(|definitions| definitions.keys().cloned().collect::<BTreeSet<_>>())
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

/// State in the schema the bounds `RuntimeConfig::check` and
/// `validate_secret_references` enforce at load beyond the reader types and
/// the shared blocks, which carry their own: operated paths are absolute, and
/// a static JWKS document names an enabled provider.
fn install_runtime_constraints(schema: &mut Value) {
    // `identity` is optional in the Rust type only so that a missing block
    // gets a diagnostic naming the key to add; the document requires it.
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.insert(2, Value::String("identity".to_owned()));
    }
    if let Some(identity) = schema.pointer_mut("/properties/identity") {
        *identity = serde_json::json!({"$ref": "#/$defs/IdentityConfig"});
    }
    set_definition_property(
        schema,
        "RuntimePackageConfig",
        "root",
        "pattern",
        Value::String("^/".to_owned()),
    );
    // The audit file is also refused with a `..` segment.
    set_definition_property(
        schema,
        "AuditConfig",
        "path",
        "pattern",
        Value::String(registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN.to_owned()),
    );
    set_secret_provider_requirements(schema);
    set_review_completion_auth_constraints(schema);
    set_audit_destination_constraints(schema);
}

/// State the shape `AuditConfig::destination` requires: a `file`
/// destination, the default, names an absolute `path`, and `stdout` takes
/// none of the file-only settings.
fn set_audit_destination_constraints(schema: &mut Value) {
    if let Some(audit) = schema
        .pointer_mut("/$defs/AuditConfig")
        .and_then(Value::as_object_mut)
    {
        audit.insert(
            "if".to_owned(),
            serde_json::json!({
                "required": ["destination"],
                "properties": {"destination": {"const": "stdout"}}
            }),
        );
        audit.insert(
            "then".to_owned(),
            serde_json::json!({
                "not": {"anyOf": [
                    {"required": ["path"]},
                    {"required": ["rotateBytes"]},
                    {"required": ["retentionDays"]}
                ]}
            }),
        );
        audit.insert("else".to_owned(), serde_json::json!({"required": ["path"]}));
    }
}

/// State the shape `RuntimeConfig::validate_secret_references` requires of a
/// completion destination: exactly one of `bearerTokenRef` and `auth`, and a
/// header name made of HTTP token characters. The reserved header set is
/// enforced at load, where names compare case-insensitively.
fn set_review_completion_auth_constraints(schema: &mut Value) {
    if let Some(destination) = schema
        .pointer_mut("/$defs/ReviewCompletionRuntimeConfig")
        .and_then(Value::as_object_mut)
    {
        destination.insert(
            "oneOf".to_owned(),
            serde_json::json!([{"required": ["bearerTokenRef"]}, {"required": ["auth"]}]),
        );
    }
    set_definition_property(
        schema,
        "ReviewCompletionAuthConfig",
        "header",
        "pattern",
        Value::String("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$".to_owned()),
    );
}

/// Every secret reference names its provider by its prefix. When a provider
/// is absent, prohibit that prefix at every fixed and keyed binding location.
/// Expressing the rule from the absent-provider side makes
/// `additionalProperties` cover every entry in the two keyed maps.
fn set_secret_provider_requirements(schema: &mut Value) {
    if let Some(root) = schema.as_object_mut() {
        root.insert(
            "allOf".to_owned(),
            serde_json::json!([
                absent_secret_provider_requirement("environment", "^secret:env/"),
                absent_secret_provider_requirement("file", "^secret:file/")
            ]),
        );
    }
}

fn absent_secret_provider_requirement(provider: &str, reference_pattern: &str) -> Value {
    let forbidden = serde_json::json!({"not": {"pattern": reference_pattern}});
    serde_json::json!({
        "if": {
            "properties": {
                "secretProviders": {
                    "not": {"required": [provider]}
                }
            },
            "required": ["secretProviders"]
        },
        "then": {
            "properties": {
                "database": {
                    "properties": {
                        "runtimeUrlRef": forbidden,
                        "migrationUrlRef": forbidden,
                        "trustedRootCertificateRef": forbidden
                    }
                },
                "authentication": {
                    "properties": {
                        "oidc": {
                            "properties": {
                                "jwksSource": {
                                    "properties": {"documentRef": forbidden}
                                }
                            }
                        }
                    }
                },
                "audit": {
                    "properties": {"hashKeyRef": forbidden}
                },
                "taskAuthority": {
                    "properties": {"signingKeyRef": forbidden}
                },
                "contextProviders": {
                    "additionalProperties": {
                        "properties": {
                            "clientIdRef": forbidden,
                            "clientAssertionKeyRef": forbidden
                        }
                    }
                },
                "reviewCompletionDestinations": {
                    "additionalProperties": {
                        "properties": {
                            "bearerTokenRef": forbidden,
                            "auth": {
                                "properties": {"secretRef": forbidden}
                            }
                        }
                    }
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
    use registry_platform_config::{
        ConfigBlockErrorKind, MAX_ASSERTION_ISSUERS_PER_CLIENT, MAX_ASSERTION_ISSUER_BYTES,
        MAX_ASSERTION_ISSUER_CLIENTS, MAX_ASSERTION_ISSUER_CLIENT_BYTES,
    };

    fn runtime_schema() -> JSONSchema {
        let documents = runtime_documents().expect("the runtime schema generates");
        let document: Value = serde_json::from_str(&documents[RUNTIME_CONFIG_SCHEMA_FILE])
            .expect("the runtime schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&document)
            .expect("the runtime schema compiles as Draft 2020-12")
    }

    /// Decode an instance through the shared reader, as the runtime does
    /// before its own checks.
    fn read(instance: &Value) -> Result<RuntimeConfig, RuntimeConfigError> {
        let text = serde_norway::to_string(instance).expect("the instance serializes");
        RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(&text, |_| None)
            .map(|loaded| loaded.config)
            .map_err(RuntimeConfigError::Load)
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
            "identity": {"databaseId": "casework-schema-test"},
            "package": {"root": "/var/lib/casework/package"},
            "listener": {"bind": "127.0.0.1:8100", "tlsTermination": "development-loopback"},
            "secretProviders": secret_providers,
            "database": {
                "runtimeUrlRef": supporting_reference,
                "migrationUrlRef": supporting_reference
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:casework",
                "allowedClients": "unrestricted",
                "jwksSource": {"type": "static", "documentRef": document_ref}
            }},
            "audit": {"path": "/var/log/casework/audit.jsonl", "hashKeyRef": supporting_reference}
        })
    }

    #[test]
    fn the_schema_requires_the_database_identity_the_runtime_requires() {
        let schema = runtime_schema();
        let instance = runtime_instance("secret:env/CASEWORK_JWKS", "both");
        assert!(schema.is_valid(&instance));
        let mut missing = instance.clone();
        missing.as_object_mut().unwrap().remove("identity");
        assert!(!schema.is_valid(&missing));
        let mut null = instance.clone();
        null["identity"] = Value::Null;
        assert!(!schema.is_valid(&null));
        let mut empty = instance;
        empty["identity"]["databaseId"] = Value::from("");
        assert!(!schema.is_valid(&empty));
    }

    #[test]
    fn the_schema_states_the_database_identity_grammar_the_runtime_enforces() {
        let schema = runtime_schema();
        let instance = runtime_instance("secret:env/CASEWORK_JWKS", "both");
        let with_id = |database_id: &str| {
            let mut document = instance.clone();
            document["identity"]["databaseId"] = Value::from(database_id);
            schema.is_valid(&document)
        };
        for accepted in ["casework-production", "a", "two words", "caf\u{e9}"] {
            assert!(with_id(accepted), "{accepted:?} must be accepted");
        }
        for refused in [
            "",
            " ",
            " leading",
            "trailing ",
            "\u{a0}no-break",
            "ideographic\u{3000}",
            "line\u{2028}",
            "bell\u{7}inside",
            "next-line\u{85}inside",
            "tab\tinside",
        ] {
            assert!(!with_id(refused), "{refused:?} must be refused");
        }
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
            document["$defs"]["AuditConfig"]["properties"]["path"]["pattern"],
            registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN
        );
        assert_eq!(
            document["$defs"]["SecretProvidersConfig"]["anyOf"],
            serde_json::json!([
                {"required": ["file"], "properties": {"file": {"$ref": "#/$defs/FileSecretProviderConfig"}}},
                {"required": ["environment"], "properties": {"environment": {"$ref": "#/$defs/EnvironmentSecretProviderConfig"}}}
            ])
        );
        assert_eq!(
            document["$defs"]["JwksSource"]["oneOf"][2]["properties"]["documentRef"]["$ref"],
            "#/$defs/SecretReference"
        );
        // The shared blocks carry their own bounds into this schema.
        assert_eq!(
            document["$defs"]["AuditConfig"]["properties"]["hashKeyRef"]["$ref"],
            "#/$defs/SecretReference"
        );
        assert_eq!(
            document["$defs"]["OidcConfig"]["properties"]["issuer"]["$ref"],
            "#/$defs/Url"
        );
    }

    #[test]
    fn assertion_issuer_schema_states_the_bounds_the_runtime_enforces() {
        // The published schema is what an operator's editor reads before the
        // runtime ever sees the document, so it refuses the same maps
        // the shared `OidcClientsConfig::check` refuses at load, whose own
        // coverage lives beside it in `registry-platform-config`.
        let schema = runtime_schema();
        let with = |issuers: Value| {
            let mut instance = runtime_instance("secret:file/jwks.json", "file");
            instance["authentication"]["oidc"]["assertionIssuers"] = issuers;
            instance
        };
        let many_clients = (0..=MAX_ASSERTION_ISSUER_CLIENTS)
            .map(|index| {
                (
                    format!("task-agent-{index}"),
                    serde_json::json!(["https://exchange.example.test"]),
                )
            })
            .collect::<Map<_, _>>();
        let many_issuers = (0..=MAX_ASSERTION_ISSUERS_PER_CLIENT)
            .map(|index| Value::String(format!("https://exchange-{index}.example.test")))
            .collect::<Vec<_>>();
        let mut long_client = Map::new();
        long_client.insert(
            "a".repeat(MAX_ASSERTION_ISSUER_CLIENT_BYTES + 1),
            serde_json::json!(["https://exchange.example.test"]),
        );
        for (label, issuers) in [
            (
                "empty client key",
                serde_json::json!({"": ["https://exchange.example.test"]}),
            ),
            ("over-long client key", Value::Object(long_client)),
            ("too many clients", Value::Object(many_clients)),
            (
                "too many issuers for one client",
                serde_json::json!({"task-agent": many_issuers}),
            ),
            ("empty issuer", serde_json::json!({"task-agent": [""]})),
            (
                "over-long issuer",
                serde_json::json!({"task-agent": [format!(
                    "https://{}.example.test",
                    "a".repeat(MAX_ASSERTION_ISSUER_BYTES)
                )]}),
            ),
            (
                "repeated issuer in one client's list",
                serde_json::json!({"task-agent": [
                    "https://exchange.example.test",
                    "https://exchange.example.test"
                ]}),
            ),
        ] {
            assert!(
                !schema.is_valid(&with(issuers)),
                "{label}: the schema accepted a map the runtime refuses"
            );
        }

        assert!(schema.is_valid(&with(serde_json::json!({
            "task-agent": ["https://exchange-a.example.test", "https://exchange-b.example.test"]
        }))));
    }

    #[test]
    fn revoked_key_ids_have_one_typed_contract_in_the_schema_and_reader() {
        let schema = runtime_schema();
        let with = |kids: Option<Value>| {
            let mut instance = runtime_instance("secret:file/jwks.json", "file");
            if let Some(kids) = kids {
                instance["authentication"]["oidc"]["revokedKeyIds"] = kids;
            }
            instance
        };

        let omitted = with(None);
        assert!(schema.is_valid(&omitted));
        assert!(read(&omitted).is_ok());
        let listed = with(Some(serde_json::json!(["retired-key", "emergency-key"])));
        assert!(schema.is_valid(&listed));
        assert!(read(&listed).is_ok());

        for (label, kids) in [
            ("empty", serde_json::json!([])),
            (
                "duplicate",
                serde_json::json!(["retired-key", "retired-key"]),
            ),
            (
                "invalid external id",
                serde_json::json!(["retired\u{7}key"]),
            ),
        ] {
            let instance = with(Some(kids));
            assert!(read(&instance).is_err(), "{label}: the runtime accepted it");
            assert!(
                !schema.is_valid(&instance),
                "{label}: the schema accepted a value the runtime refuses"
            );
        }

        let document: Value =
            serde_json::from_str(&runtime_documents().unwrap()[RUNTIME_CONFIG_SCHEMA_FILE])
                .unwrap();
        let revoked = &document["$defs"]["OidcConfig"]["properties"]["revokedKeyIds"];
        assert!(revoked.get("default").is_none());
        assert_eq!(revoked["uniqueItems"], true);
        assert_eq!(revoked["minItems"], 1);
        assert_eq!(revoked["maxItems"], 128);
        assert_eq!(revoked["items"]["$ref"], "#/$defs/ExternalId");
    }

    #[test]
    fn completion_destination_schema_names_exactly_one_secret_and_a_token_header() {
        let schema = runtime_schema();
        let with = |destination: Value| {
            let mut instance = runtime_instance("secret:file/jwks.json", "file");
            instance["reviewCompletionDestinations"] =
                serde_json::json!({ "review-requester": destination });
            instance
        };
        let url = "https://requester.example.test/completions";
        for accepted in [
            serde_json::json!({"url": url, "bearerTokenRef": "secret:file/completion-token"}),
            serde_json::json!({"url": url, "auth": {"secretRef": "secret:file/completion-key"}}),
            serde_json::json!({
                "url": url,
                "auth": {"header": "x-api-key", "secretRef": "secret:file/completion-key"}
            }),
        ] {
            assert!(schema.is_valid(&with(accepted.clone())), "{accepted}");
        }
        // An explicit null is refused, by the schema and by the reader alike.
        for nulled in [
            serde_json::json!({
                "url": url,
                "bearerTokenRef": null,
                "auth": {"secretRef": "secret:file/completion-key"}
            }),
            serde_json::json!({
                "url": url,
                "bearerTokenRef": "secret:file/completion-token",
                "auth": null
            }),
        ] {
            assert!(!schema.is_valid(&with(nulled.clone())), "{nulled}");
            assert!(read(&with(nulled.clone())).is_err(), "{nulled}");
        }
        for refused in [
            serde_json::json!({"url": url}),
            serde_json::json!({"url": url, "bearerTokenRef": null}),
            serde_json::json!({"url": url, "auth": null}),
            serde_json::json!({"url": url, "bearerTokenRef": null, "auth": null}),
            serde_json::json!({
                "url": url,
                "bearerTokenRef": "secret:file/completion-token",
                "auth": {"secretRef": "secret:file/completion-key"}
            }),
            serde_json::json!({
                "url": url,
                "auth": {"header": "x api key", "secretRef": "secret:file/completion-key"}
            }),
            serde_json::json!({
                "url": url,
                "auth": {"header": "x-api-key", "secretRef": "completion-key"}
            }),
            serde_json::json!({"url": url, "auth": {"header": "x-api-key"}}),
        ] {
            assert!(!schema.is_valid(&with(refused.clone())), "{refused}");
        }
    }

    #[test]
    fn completion_destination_schema_states_the_bounds_the_runtime_enforces() {
        let schema = runtime_schema();
        let with = |timeout_milliseconds, maximum_attempts, retry_seconds| {
            let mut instance = runtime_instance("secret:file/jwks.json", "file");
            instance["reviewCompletionDestinations"] = serde_json::json!({
                "review-requester": {
                    "url": "https://requester.example.test/completions",
                    "bearerTokenRef": "secret:file/completion-token",
                    "attemptTimeoutMilliseconds": timeout_milliseconds,
                    "maximumAttempts": maximum_attempts,
                    "retryDelaySeconds": retry_seconds
                }
            });
            instance
        };

        for (label, instance) in [
            (
                "timeout below minimum",
                with(
                    crate::config::MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS - 1,
                    1,
                    1,
                ),
            ),
            (
                "timeout above maximum",
                with(
                    crate::config::MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS + 1,
                    1,
                    1,
                ),
            ),
            (
                "attempts below minimum",
                with(
                    100,
                    crate::config::MINIMUM_REVIEW_COMPLETION_ATTEMPTS - 1,
                    1,
                ),
            ),
            (
                "attempts above maximum",
                with(
                    100,
                    crate::config::MAXIMUM_REVIEW_COMPLETION_ATTEMPTS + 1,
                    1,
                ),
            ),
            (
                "retry below minimum",
                with(
                    100,
                    1,
                    crate::config::MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS - 1,
                ),
            ),
            (
                "retry above maximum",
                with(
                    100,
                    1,
                    crate::config::MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS + 1,
                ),
            ),
        ] {
            assert!(
                !schema.is_valid(&instance),
                "{label}: the schema accepted a destination the runtime refuses"
            );
        }

        assert!(schema.is_valid(&with(
            crate::config::MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS,
            crate::config::MINIMUM_REVIEW_COMPLETION_ATTEMPTS,
            crate::config::MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS,
        )));
        assert!(schema.is_valid(&with(
            crate::config::MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS,
            crate::config::MAXIMUM_REVIEW_COMPLETION_ATTEMPTS,
            crate::config::MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS,
        )));
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
            let config = read(&instance).expect("the runtime shape parses");
            assert!(matches!(
                config.check(),
                Err(RuntimeConfigError::Block(error))
                    if error.kind() == ConfigBlockErrorKind::InvalidSecretReference
                        && error.field() == "authentication.oidc.jwksSource.documentRef"
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
            let instance = runtime_instance(reference, enabled_provider);
            let config = read(&instance).expect("the runtime shape parses");
            assert!(matches!(
                config.check(),
                Err(RuntimeConfigError::Block(error))
                    if error.kind() == ConfigBlockErrorKind::SecretProviderDisabled
                        && error.field() == "authentication.oidc.jwksSource.documentRef"
            ));
            assert!(
                !schema.is_valid(&instance),
                "schema accepted a static JWKS reference with its provider disabled"
            );

            // A provider written as null is refused by the reader, not read
            // as disabled.
            let mut nulled = instance.clone();
            nulled["secretProviders"][disabled_provider] = Value::Null;
            assert!(read(&nulled).is_err(), "the reader read a null provider");
        }

        assert!(schema.is_valid(&runtime_instance("secret:env/CASEWORK_JWKS", "environment")));
        assert!(schema.is_valid(&runtime_instance("secret:file/jwks.json", "file")));
    }

    fn runtime_instance_with_every_secret_reference() -> Value {
        let mut instance = runtime_instance("secret:env/CASEWORK_JWKS", "both");
        instance["database"]["trustedRootCertificateRef"] =
            Value::String("secret:file/database-ca.pem".to_owned());
        instance["audit"]["hashKeyRef"] = Value::String("secret:env/CASEWORK_AUDIT_KEY".to_owned());
        instance["contextProviders"] = serde_json::json!({
            "facility-registry": {
                "baseUrl": "https://registry.example.test",
                "statusProfile": "casework-review-status",
                "tokenEndpoint": "https://identity.example.test/oauth2/token",
                "clientIdRef": "secret:file/breg-client-id",
                "clientAssertionKeyRef": "secret:env/BREG_CLIENT_ASSERTION_KEY"
            }
        });
        instance["reviewCompletionDestinations"] = serde_json::json!({
            "bearer": {
                "url": "https://producer.example.test/completions",
                "bearerTokenRef": "secret:file/completion-token"
            },
            "header": {
                "url": "https://another-producer.example.test/completions",
                "auth": {
                    "header": "x-api-key",
                    "secretRef": "secret:env/COMPLETION_API_KEY"
                }
            }
        });
        instance["taskAuthority"] = serde_json::json!({
            "issuer": "https://casework.example.test",
            "exchangeAudience": "urn:example:casework:task-grants",
            "signingKeyRef": "secret:file/task-authority-key",
            "statusClients": {"scheduling": "urn:example:scheduling"}
        });
        instance
    }

    #[test]
    fn every_secret_reference_has_schema_and_runtime_provider_parity() {
        let schema = runtime_schema();
        let mixed = runtime_instance_with_every_secret_reference();
        assert!(
            schema.is_valid(&mixed),
            "valid mixed providers were refused"
        );
        let mixed_config = read(&mixed).expect("the mixed-provider runtime shape parses");
        let findings = mixed_config.findings(None);
        assert!(findings.is_empty(), "{findings:#?}");

        let mut optional_references_absent = mixed.clone();
        optional_references_absent["database"]
            .as_object_mut()
            .unwrap()
            .remove("trustedRootCertificateRef");
        optional_references_absent
            .as_object_mut()
            .unwrap()
            .remove("taskAuthority");
        optional_references_absent
            .as_object_mut()
            .unwrap()
            .remove("contextProviders");
        optional_references_absent
            .as_object_mut()
            .unwrap()
            .remove("reviewCompletionDestinations");
        assert!(schema.is_valid(&optional_references_absent));
        assert!(read(&optional_references_absent).is_ok());

        let pointers = [
            "/database/runtimeUrlRef",
            "/database/migrationUrlRef",
            "/database/trustedRootCertificateRef",
            "/authentication/oidc/jwksSource/documentRef",
            "/audit/hashKeyRef",
            "/contextProviders/facility-registry/clientIdRef",
            "/contextProviders/facility-registry/clientAssertionKeyRef",
            "/reviewCompletionDestinations/bearer/bearerTokenRef",
            "/reviewCompletionDestinations/header/auth/secretRef",
            "/taskAuthority/signingKeyRef",
        ];
        for &pointer in &pointers {
            let mut invalid = mixed.clone();
            *invalid.pointer_mut(pointer).expect("test pointer exists") =
                Value::String("plain-secret-value".to_owned());
            let runtime_refused = match read(&invalid) {
                Err(_) => true,
                Ok(config) => config.findings(None).iter().any(|finding| {
                    finding.pointer() == pointer
                        && matches!(
                            finding,
                            RuntimeConfigError::Block(error)
                                | RuntimeConfigError::BindingSecret { error, .. }
                                if error.kind() == ConfigBlockErrorKind::InvalidSecretReference
                        )
                }),
            };
            assert!(runtime_refused, "runtime accepted {pointer}");
            assert!(
                !schema.is_valid(&invalid),
                "schema accepted invalid grammar at {pointer}"
            );

            let mut nulled = mixed.clone();
            *nulled.pointer_mut(pointer).expect("test pointer exists") = Value::Null;
            assert!(read(&nulled).is_err(), "runtime read null at {pointer}");
            assert!(
                !schema.is_valid(&nulled),
                "schema accepted null at {pointer}"
            );
        }

        for (disabled_provider, disabled_reference, enabled_provider, enabled_reference) in [
            (
                "environment",
                "secret:env/DISABLED_REFERENCE",
                "file",
                "secret:file/enabled-reference",
            ),
            (
                "file",
                "secret:file/disabled-reference",
                "environment",
                "secret:env/ENABLED_REFERENCE",
            ),
        ] {
            for &pointer in &pointers {
                let mut disabled = mixed.clone();
                for &reference_pointer in &pointers {
                    *disabled
                        .pointer_mut(reference_pointer)
                        .expect("test pointer exists") =
                        Value::String(enabled_reference.to_owned());
                }
                *disabled.pointer_mut(pointer).expect("test pointer exists") =
                    Value::String(disabled_reference.to_owned());
                disabled["secretProviders"] = if enabled_provider == "file" {
                    serde_json::json!({"file": {"root": "/run/casework/secrets"}})
                } else {
                    serde_json::json!({"environment": {}})
                };
                let config = read(&disabled).expect("disabled providers remain a readable shape");
                let findings = config.findings(None);
                assert!(
                    findings.iter().any(|finding| {
                        finding.pointer() == pointer
                            && matches!(
                                finding,
                                RuntimeConfigError::Block(error)
                                    | RuntimeConfigError::BindingSecret { error, .. }
                                    if error.kind() == ConfigBlockErrorKind::SecretProviderDisabled
                            )
                    }),
                    "runtime did not refuse {disabled_reference} at {pointer} with {disabled_provider} disabled"
                );
                assert!(
                    !schema.is_valid(&disabled),
                    "schema accepted {disabled_reference} at {pointer} with {disabled_provider} disabled"
                );
            }
        }

        for provider in ["environment", "file"] {
            let mut nulled = mixed.clone();
            nulled["secretProviders"][provider] = Value::Null;
            assert!(
                read(&nulled).is_err(),
                "runtime read a null {provider} provider"
            );
            assert!(
                !schema.is_valid(&nulled),
                "schema accepted a null {provider} provider"
            );
        }
    }

    #[test]
    fn expected_digest_schema_matches_runtime_validation() {
        let schema = runtime_schema();
        let with = |digest: &str| {
            let mut instance = runtime_instance("secret:env/CASEWORK_JWKS", "environment");
            instance["package"]["expectedDigest"] = Value::String(digest.to_owned());
            instance
        };
        assert!(schema.is_valid(&with(&format!("sha256:{}", "0a".repeat(32)))));
        for digest in [
            String::new(),
            format!("sha256:{}", "0A".repeat(32)),
            "0a".repeat(32),
            format!("sha256:{}0", "0a".repeat(32)),
            format!("sha512:{}", "0a".repeat(32)),
        ] {
            assert!(
                !schema.is_valid(&with(&digest)),
                "{digest}: the schema accepted a digest the runtime refuses"
            );
        }
    }

    #[test]
    fn audit_destination_schema_matches_runtime_validation() {
        let schema = runtime_schema();
        let with = |audit: Value| {
            let mut instance = runtime_instance("secret:env/CASEWORK_JWKS", "environment");
            instance["audit"] = audit;
            instance
        };
        let key = "secret:env/CASEWORK_AUDIT_KEY";
        for accepted in [
            serde_json::json!({"hashKeyRef": key, "path": "/var/log/casework/audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "file",
                "path": "/audit.jsonl", "rotateBytes": 1_048_576, "retentionDays": 1}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout"}),
        ] {
            assert!(schema.is_valid(&with(accepted.clone())), "{accepted}");
        }
        // An explicit null is refused, by the schema and by the reader alike.
        for nulled in [
            serde_json::json!({"hashKeyRef": key, "path": null}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "path": null}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout",
                "path": null, "rotateBytes": null, "retentionDays": null}),
        ] {
            assert!(!schema.is_valid(&with(nulled.clone())), "{nulled}");
            assert!(read(&with(nulled.clone())).is_err(), "{nulled}");
        }
        for refused in [
            serde_json::json!({"hashKeyRef": key}),
            serde_json::json!({"hashKeyRef": key, "path": "audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "path": "/audit.jsonl"}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "rotateBytes": 1_048_576}),
            serde_json::json!({"hashKeyRef": key, "destination": "stdout", "retentionDays": 1}),
        ] {
            assert!(!schema.is_valid(&with(refused.clone())), "{refused}");
        }
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
