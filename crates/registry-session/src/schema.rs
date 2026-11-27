// SPDX-License-Identifier: Apache-2.0

//! JSON Schema derived from the session service's runtime configuration types.
//!
//! Regenerate with `cargo run -p registry-session --features schema --example
//! session-runtime-schema -- --output products/platform/generated/session-runtime`.

use std::{borrow::Cow, collections::BTreeMap};

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde_json::{json, Value};

use crate::config::{
    Authority, ClaimName, ClusterName, FilterName, HostName, ModuleAudience, ResourceUri,
    RewritePrefix, RuntimeConfig, ScopeToken, RUNTIME_API_VERSION, RUNTIME_KIND,
};

/// The `$id` of the runtime schema.
pub const RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/session-runtime/session-runtime.v1alpha1.schema.json";
/// The file name of the committed runtime schema.
pub const RUNTIME_SCHEMA_FILE: &str = "session-runtime.schema.json";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut runtime = serde_json::to_value(schemars::schema_for!(RuntimeConfig))?;
    runtime["$schema"] = json!("https://json-schema.org/draft/2020-12/schema");
    runtime["$id"] = json!(RUNTIME_SCHEMA_ID);
    runtime["title"] = json!("Registry Stack session service runtime configuration");
    runtime["properties"]["apiVersion"]["const"] = json!(RUNTIME_API_VERSION);
    runtime["properties"]["kind"]["const"] = json!(RUNTIME_KIND);
    set_audit_destination_constraints(&mut runtime);
    let mut rendered = serde_json::to_string_pretty(&runtime)?;
    rendered.push('\n');
    Ok([(RUNTIME_SCHEMA_FILE, rendered)].into())
}

/// File audit requires an absolute path. Stdout accepts no file-only setting.
fn set_audit_destination_constraints(schema: &mut Value) {
    schema["$defs"]["AuditConfig"]["properties"]["path"]["pattern"] =
        json!(registry_platform_audit::ABSOLUTE_AUDIT_PATH_PATTERN);
    let audit = &mut schema["$defs"]["AuditConfig"];
    audit["if"] = json!({
        "required": ["destination"],
        "properties": {"destination": {"const": "stdout"}}
    });
    audit["then"] = json!({"not": {"anyOf": [
        {"required": ["path"]},
        {"required": ["rotateBytes"]},
        {"required": ["retentionDays"]}
    ]}});
    audit["else"] = json!({"required": ["path"]});
}

pub(crate) fn route_prefix_schema(_generator: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "string",
        "minLength": 2,
        "maxLength": 256,
        "pattern": "^/(?!session(?:/|$))(?!.*[%\\\\?#])(?:(?!\\.\\.?(?:/|$))[!-\\.0-~]+(?:/|$))+$",
    })
}

pub(crate) fn scopes_schema(generator: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "array",
        "items": generator.subschema_for::<ScopeToken>(),
        "maxItems": 16,
        "uniqueItems": true,
        "not": {"contains": {"const": "openid"}},
    })
}

/// String wrappers have custom readers, so their schemas state the same
/// lexical rules instead of describing the Rust newtype's storage.
macro_rules! text_schema {
    ($name:ident, $maximum:expr, $pattern:expr) => {
        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": $maximum,
                    "pattern": $pattern,
                })
            }
        }
    };
}

text_schema!(ScopeToken, 512, "^[!#-\\[\\]-~]+$");
text_schema!(
    ResourceUri,
    512,
    "^[A-Za-z][A-Za-z0-9+.-]*:(?!//[^/?#]*@)(?:[A-Za-z0-9._~:/?\\[\\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$"
);
text_schema!(
    ClaimName,
    64,
    "^(?!(?:iss|aud|exp|nbf|iat|jti|nonce|at_hash|c_hash|s_hash|azp|cnf|sid)$)[A-Za-z0-9_.:-]+$"
);
text_schema!(HostName, 253, "^[A-Za-z0-9._-]+$");
text_schema!(Authority, 260, "^[a-z0-9._:\\[\\]-]+$");
text_schema!(ClusterName, 128, "^[A-Za-z0-9._:-]+$");
text_schema!(FilterName, 128, "^[A-Za-z0-9._:-]+$");
text_schema!(RewritePrefix, 256, "^/(?!.*[%\\\\?#])[!-~]*$");

impl JsonSchema for ModuleAudience {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ModuleAudience")
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({"anyOf": [
            {"type": "string", "const": "person"},
            generator.subschema_for::<ResourceUri>()
        ]})
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;
    use serde_json::{json, Value};

    use super::*;
    use crate::config::{check_runtime, tests::document};

    const PRODUCT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/platform");

    fn validator() -> JSONSchema {
        let schema: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("the schema compiles as Draft 2020-12: {error}"))
    }

    fn as_json(text: &str) -> Value {
        Reader::new("runtime.yaml")
            .scan(text.as_bytes())
            .expect("the file is YAML")
            .expect("the file is not empty")
            .to_json_value()
    }

    fn reader_accepts(text: &str) -> bool {
        let (_directory, path) = crate::config::tests::written(text);
        check_runtime(&path, true).diagnostics.is_empty()
    }

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(
                Path::new(PRODUCT)
                    .join("generated/session-runtime")
                    .join(name),
            )
            .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted; regenerate with `cargo run -p registry-session --features schema \
                 --example session-runtime-schema -- --output products/platform/generated/session-runtime`"
            );
        }
    }

    #[test]
    fn shared_blocks_are_embedded_unchanged() {
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        let document: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        let definitions = document["$defs"].as_object().unwrap();
        let mut shared = 0;
        for (definition, schema) in definitions {
            if let Some(platform) = canonical["$defs"].get(definition) {
                assert_eq!(schema, platform, "changed shared block {definition}");
                shared += 1;
            }
        }
        assert!(shared > 0);
    }

    #[test]
    fn no_service_member_accepts_or_defaults_to_null() {
        fn visit(node: &Value, at: &str) {
            match node {
                Value::Object(object) => {
                    assert_ne!(
                        object.get("default"),
                        Some(&Value::Null),
                        "default null at {at}"
                    );
                    assert_ne!(
                        object.get("type"),
                        Some(&json!("null")),
                        "null type at {at}"
                    );
                    if let Some(Value::Array(types)) = object.get("type") {
                        assert!(!types.contains(&json!("null")), "nullable type at {at}");
                    }
                    for (key, value) in object {
                        visit(value, &format!("{at}/{key}"));
                    }
                }
                Value::Array(items) => {
                    for (index, value) in items.iter().enumerate() {
                        visit(value, &format!("{at}/{index}"));
                    }
                }
                _ => {}
            }
        }
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        let mut document: Value =
            serde_json::from_str(&schema_documents().unwrap()[RUNTIME_SCHEMA_FILE]).unwrap();
        document["$defs"]
            .as_object_mut()
            .unwrap()
            .retain(|name, _| canonical["$defs"].get(name).is_none());
        visit(&document, "");
    }

    #[test]
    fn the_committed_example_is_accepted_by_schema_and_reader() {
        let example = Path::new(PRODUCT).join("examples/session/runtime.yaml");
        let text = std::fs::read_to_string(example).unwrap();
        assert!(reader_accepts(&text));
        assert!(validator().is_valid(&as_json(&text)));
        assert!(validator().is_valid(&as_json(&document())));
    }

    #[test]
    fn runtime_members_are_judged_alike_by_schema_and_reader() {
        let validator = validator();
        for (from, to, accepted) in [
            ("scopes: [registry:read]", "scopes: []", true),
            (
                "scopes: [registry:read]",
                "scopes: [registry:read, registry:read]",
                false,
            ),
            (
                "scopes: [registry:read]",
                "scopes: ['registry read']",
                false,
            ),
            ("scopes: [registry:read]", "scopes: [openid]", false),
            (
                "jwks: https://id.example/oauth2/jwks",
                "jwks: https://id.example/oauth2/jwks\n  attemptTimeoutMilliseconds: 100",
                true,
            ),
            (
                "jwks: https://id.example/oauth2/jwks",
                "jwks: https://id.example/oauth2/jwks\n  attemptTimeoutMilliseconds: 99",
                false,
            ),
            (
                "jwks: https://id.example/oauth2/jwks",
                "jwks: https://id.example/oauth2/jwks\n  timeoutMilliseconds: 100",
                false,
            ),
            ("clientId: citizen-app", "clientId: ''", false),
            (
                "clientSecretRef: secret:file/citizen-secret",
                "clientSecretRef: inline",
                false,
            ),
            ("audience: person", "audience: 'urn:a b'", false),
            (
                "publicOrigin: https://app.example",
                "publicOrigin: app.example",
                false,
            ),
            ("prefix: /api/registry/", "prefix: api/registry", false),
            ("prefix: /api/registry/", "prefix: /api/registry", true),
            ("prefix: /api/registry/", "prefix: /api/registry/..", false),
            ("prefix: /api/registry/", "prefix: /api//registry", false),
            ("prefix: /apply/", "prefix: /session", false),
            ("prefix: /apply/", "prefix: /sess", true),
            ("prefix: /apply/", "prefix: /a", true),
            ("  citizen:\n", "  Citizen:\n", false),
            ("  citizen:\n", "  citizen:\n    id: redundant\n", false),
            (
                "path: /var/lib/session/audit.jsonl",
                "path: audit.jsonl",
                false,
            ),
            (
                "hashKeyRef: secret:env/SESSION_AUDIT_KEY",
                "hashKeyRef: inline",
                false,
            ),
            (
                "path: /var/lib/session/audit.jsonl",
                "destination: stdout",
                true,
            ),
            (
                "path: /var/lib/session/audit.jsonl",
                "destination: stdout\n  path: /var/lib/session/audit.jsonl",
                false,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nsession:\n  absoluteLifetimeSeconds: 299",
                false,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nsession:\n  absoluteLifetimeSeconds: 86400",
                true,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nsession:\n  idleLifetimeSeconds: null",
                false,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nme:\n  claims: [sub, nonce]",
                false,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nme:\n  claims: []",
                true,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nwhoAmI:\n  claims: []",
                false,
            ),
            (
                "kind: PlatformSessionRuntimeConfig",
                "kind: PlatformSessionRuntimeConfig\nunrecognized: true",
                false,
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            assert_eq!(reader_accepts(&text), accepted, "reader: {to}");
            assert_eq!(
                validator.is_valid(&as_json(&text)),
                accepted,
                "schema: {to}"
            );
        }
    }
}
