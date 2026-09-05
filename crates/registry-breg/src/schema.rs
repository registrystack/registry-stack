// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schema for Base Registry Engine authoring documents.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::contract::{RegistryModule, RegistryProject};
#[cfg(feature = "runtime")]
use crate::runtime_config::runtime_config_schema;

const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

pub const REGISTRY_PROJECT_SCHEMA_FILE: &str = "registry-project.schema.json";
pub const REGISTRY_PROJECT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/breg/authoring/registry-project.v1alpha1.schema.json";
pub const REGISTRY_MODULE_SCHEMA_FILE: &str = "registry-module.schema.json";
pub const REGISTRY_MODULE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/breg/authoring/registry-module.v1alpha1.schema.json";
#[cfg(feature = "runtime")]
pub const RUNTIME_CONFIG_SCHEMA_FILE: &str = "runtime.schema.json";
#[cfg(feature = "runtime")]
pub const RUNTIME_CONFIG_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/breg/runtime/runtime.v1alpha1.schema.json";

/// Every authoring schema under its committed artifact filename.
pub fn documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [
        (
            REGISTRY_PROJECT_SCHEMA_FILE,
            "Base Registry Engine authored project",
            REGISTRY_PROJECT_SCHEMA_ID,
            serde_json::to_value(schemars::schema_for!(RegistryProject))?,
        ),
        (
            REGISTRY_MODULE_SCHEMA_FILE,
            "Base Registry Engine authored module",
            REGISTRY_MODULE_SCHEMA_ID,
            serde_json::to_value(schemars::schema_for!(RegistryModule))?,
        ),
    ];
    entries
        .into_iter()
        .map(|(file, title, identifier, derived)| {
            Ok((file, render(published(derived, title, identifier))?))
        })
        .collect()
}

/// Every runtime schema under its committed artifact filename.
#[cfg(feature = "runtime")]
pub fn runtime_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let entries = [(
        RUNTIME_CONFIG_SCHEMA_FILE,
        "Base Registry Engine runtime configuration",
        RUNTIME_CONFIG_SCHEMA_ID,
        runtime_config_schema()?,
    )];
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
    use std::{fs, path::Path};

    use jsonschema::{Draft, JSONSchema};
    use serde_json::Value;

    use super::{
        documents, REGISTRY_MODULE_SCHEMA_FILE, REGISTRY_MODULE_SCHEMA_ID,
        REGISTRY_PROJECT_SCHEMA_FILE, REGISTRY_PROJECT_SCHEMA_ID,
    };
    #[cfg(feature = "runtime")]
    use super::{runtime_documents, RUNTIME_CONFIG_SCHEMA_FILE, RUNTIME_CONFIG_SCHEMA_ID};
    #[cfg(feature = "runtime")]
    use crate::runtime_config::{
        parse_runtime_config, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND,
    };

    const ACCEPTANCE_PROJECTS: &[&str] = &[
        "asset-site-placement",
        "business",
        "inspection",
        "facility",
        "business-establishments",
    ];

    fn schema_document() -> String {
        documents()
            .expect("the Base Registry Engine authoring schema generates")
            .remove(REGISTRY_PROJECT_SCHEMA_FILE)
            .expect("the RegistryProject schema is generated")
    }

    fn compile(document: &str) -> JSONSchema {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&value)
            .expect("a generated schema compiles as 2020-12")
    }

    #[cfg(feature = "runtime")]
    fn runtime_schema_document() -> String {
        runtime_documents()
            .expect("the Base Registry Engine runtime schema generates")
            .remove(RUNTIME_CONFIG_SCHEMA_FILE)
            .expect("the RuntimeConfig schema is generated")
    }

    #[cfg(feature = "runtime")]
    fn runtime_instance() -> Value {
        serde_json::json!({
            "apiVersion": RUNTIME_CONFIG_API_VERSION,
            "kind": RUNTIME_CONFIG_KIND,
            "listener": {
                "bind": "127.0.0.1:8080"
            },
            "identity": {
                "environment": "production",
                "instanceId": "registry-primary",
                "databaseId": "registry-db",
                "databaseInitializationEnvironment": "production"
            },
            "secretProviders": {
                "environment": {},
                "file": {
                    "root": "/var/lib/breg/secrets"
                }
            },
            "database": {
                "runtimeUrlRef": "secret:env/BREG_DATABASE_URL",
                "migrationUrlRef": "secret:env/BREG_MIGRATION_DATABASE_URL",
                "pool": {
                    "maxSize": 4
                },
                "roles": {
                    "migration": "registry_migration",
                    "runtime": "registry_runtime"
                }
            },
            "package": {
                "root": "/var/lib/breg/package",
                "trustAnchorPath": "/etc/breg/package-trust-anchor.json",
                "compilerSourceRevision": "source-revision",
                "activeRevision": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "activeSequence": 1
            },
            "authentication": {
                "oidc": {
                    "issuer": "https://issuer.example",
                    "audience": "urn:breg:test",
                    "allowedAlgorithm": "EdDSA",
                    "accessTokenType": "JWT",
                    "scopeClaim": "scope",
                    "scopeSeparator": " ",
                    "maxTokenLifetimeSeconds": 300,
                    "leewayMilliseconds": 60000
                },
                "authorityClaims": {
                    "principal": "registry_principal"
                }
            },
            "audit": {
                "hashKeyRef": "secret:file/audit-key"
            },
            "cursor": {
                "secretRef": "secret:file/cursor-key"
            }
        })
    }

    #[cfg(feature = "runtime")]
    fn valid_event_destination() -> Value {
        serde_json::json!({
            "origin": "https://webhook.example",
            "path": "/events",
            "networkProfile": "productionHttps",
            "dnsFamily": "dualStackStrict",
            "allowedPrivateCidrs": [],
            "hmacSha256KeyRef": "secret:file/webhook-hmac",
            "classificationCeiling": "public",
            "deliveryCeilings": {
                "attemptTimeoutMilliseconds": 1000,
                "maximumAttempts": 1
            }
        })
    }

    #[cfg(feature = "runtime")]
    fn assert_schema_rejects_parser_refused_runtime(
        schema: &JSONSchema,
        label: &str,
        mutate: impl FnOnce(&mut Value),
    ) {
        let mut instance = runtime_instance();
        mutate(&mut instance);
        let raw = serde_json::to_string(&instance).expect("the mutated runtime is JSON");
        assert!(
            parse_runtime_config(&raw).is_err(),
            "{label}: parser accepted the representative invalid runtime"
        );
        assert!(
            !schema.is_valid(&instance),
            "{label}: schema accepted a runtime the parser rejects"
        );
    }

    fn acceptance_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/acceptance")
    }

    fn fixture(project: &str) -> Value {
        let path = acceptance_root().join(project).join("registry.yaml");
        serde_norway::from_str(&fs::read_to_string(path).expect("the fixture exists"))
            .expect("the fixture is well-formed YAML")
    }

    #[test]
    fn authoring_documents_cover_projects_and_modules() {
        let documents = documents().expect("the Base Registry Engine authoring schema generates");
        assert_eq!(
            documents.keys().copied().collect::<Vec<_>>(),
            vec![REGISTRY_MODULE_SCHEMA_FILE, REGISTRY_PROJECT_SCHEMA_FILE],
        );
    }

    #[test]
    fn module_schema_accepts_shipped_modules_and_rejects_unknown_fields() {
        let document = documents()
            .expect("authoring schemas generate")
            .remove(REGISTRY_MODULE_SCHEMA_FILE)
            .expect("the module schema is generated");
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        assert_eq!(value["$id"], REGISTRY_MODULE_SCHEMA_ID);
        let schema = compile(&document);
        for project in ACCEPTANCE_PROJECTS {
            for entry in fs::read_dir(acceptance_root().join(project).join("modules"))
                .expect("the acceptance project has modules")
            {
                let entry = entry.expect("the module entry exists");
                if !entry.file_type().expect("the entry has a type").is_dir() {
                    continue;
                }
                let path = entry.path().join("module.yaml");
                let raw = fs::read(&path).expect("the module can be read");
                crate::contract::parse_module_yaml(&raw).expect("the parser accepts the module");
                let mut instance: Value =
                    serde_norway::from_slice(&raw).expect("the module is YAML");
                assert!(schema.is_valid(&instance), "module {}", path.display());
                instance["unexpected"] = Value::Bool(true);
                assert!(!schema.is_valid(&instance));
            }
        }
        let mut extension = serde_json::json!({
            "id": "notifications", "version": "1.0.0",
            "extendEntities": [{"entity": "record", "events": [{
                "id": "record-labelled-v1", "trigger": "patched", "projection": ["label"],
                "when": {"kind": "fields", "changed": ["label"]},
                "webhook": {"destinationId": "receiver"}
            }]}]
        });
        assert!(schema.is_valid(&extension));
        extension["extendEntities"][0]["events"][0]["webhook"]["url"] =
            Value::String("https://example.com/events".into());
        assert!(!schema.is_valid(&extension));

        let mut module_with_entity = serde_json::json!({
            "id": "records", "version": "1",
            "entities": [{
                "id": "record", "primaryDataset": "records",
                "route": "records", "mutationMode": "create_only"
            }]
        });
        assert!(schema.is_valid(&module_with_entity));
        module_with_entity["entities"][0]
            .as_object_mut()
            .expect("entity is an object")
            .remove("primaryDataset");
        assert!(
            !schema.is_valid(&module_with_entity),
            "module entities structurally require primaryDataset"
        );
    }

    #[test]
    fn registry_project_schema_declares_the_published_dialect_identifier_and_title() {
        let document = schema_document();
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
        );
        assert_eq!(
            value.get("$id").and_then(Value::as_str),
            Some(REGISTRY_PROJECT_SCHEMA_ID),
        );
        assert_eq!(
            value.get("title").and_then(Value::as_str),
            Some("Base Registry Engine authored project"),
        );
        assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
    }

    #[test]
    fn registry_project_schema_reproduces_byte_for_byte() {
        assert_eq!(
            documents().expect("the Base Registry Engine authoring schema generates"),
            documents().expect("the Base Registry Engine authoring schema generates again"),
        );
    }

    #[test]
    fn registry_project_schema_is_pretty_json_with_one_trailing_newline() {
        let document = schema_document();
        assert!(document.ends_with('\n') && !document.ends_with("\n\n"));
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        let mut rendered =
            serde_json::to_string_pretty(&value).expect("a parsed schema renders again");
        rendered.push('\n');
        assert_eq!(document, rendered);
    }

    #[test]
    fn schema_accepts_the_current_registry_yaml_fixtures() {
        let document = schema_document();
        let schema = compile(&document);
        for project in ACCEPTANCE_PROJECTS {
            assert!(
                schema.is_valid(&fixture(project)),
                "{project}/registry.yaml"
            );
        }
    }

    #[test]
    fn schema_rejects_unknown_top_level_keys() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["unexpected"] = Value::Bool(true);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn project_schema_structurally_requires_canonical_iri_and_entity_dataset() {
        let document = schema_document();
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        for (definition, field) in [
            ("RegistryIdentitySource", "canonicalBaseIri"),
            ("EntitySource", "primaryDataset"),
        ] {
            let required = value["$defs"][definition]["required"]
                .as_array()
                .expect("definition has required members");
            assert!(required.iter().any(|member| member == field));
            assert_eq!(
                value["$defs"][definition]["properties"][field]["type"],
                "string"
            );
        }

        let schema = compile(&document);
        let mut missing_iri = fixture("asset-site-placement");
        missing_iri["registry"]
            .as_object_mut()
            .expect("registry is an object")
            .remove("canonicalBaseIri");
        assert!(!schema.is_valid(&missing_iri));

        let mut missing_dataset = fixture("asset-site-placement");
        missing_dataset["entities"][0]
            .as_object_mut()
            .expect("entity is an object")
            .remove("primaryDataset");
        assert!(!schema.is_valid(&missing_dataset));
    }

    #[test]
    fn schema_rejects_the_legacy_top_level_access_profile_vocabulary() {
        let document = schema_document();
        let schema = compile(&document);
        let mut old_purposes = fixture("asset-site-placement");
        let required_purposes = old_purposes["accessProfiles"][0]
            .as_object_mut()
            .expect("access profile is an object")
            .remove("requiredPurposes")
            .expect("fixture uses canonical requiredPurposes");
        old_purposes["accessProfiles"][0]["purposes"] = required_purposes;
        assert!(!schema.is_valid(&old_purposes));

        let mut old_actions = fixture("asset-site-placement");
        let operations = old_actions["accessProfiles"][0]["grants"][0]
            .as_object_mut()
            .expect("access grant is an object")
            .remove("operations")
            .expect("fixture uses canonical operations");
        old_actions["accessProfiles"][0]["grants"][0]["actions"] = operations;
        assert!(!schema.is_valid(&old_actions));
    }

    #[test]
    fn schema_rejects_entity_local_project_access_profiles() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("business");
        instance["entities"][0]["accessProfiles"] = serde_json::json!([{
            "id": "entity-local-reader",
            "anonymous": true,
            "operations": ["get"],
            "readableFields": ["legal-name"]
        }]);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_accepts_geojson_and_bbox_authoring_and_rejects_duplicate_bbox_geometry() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id":"location",
                "type":"crs84-point",
                "precision":6,
                "classification":"internal"
            }));
        instance["entities"][0]["geojson"] = serde_json::json!({"geometryField":"location"});
        instance["accessProfiles"][0]["grants"][0]["readableFields"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("location".to_owned()));
        instance["accessProfiles"][0]["grants"][0]["spatialQueries"] = serde_json::json!({
            "bbox":{
                "maximumLongitudeSpanDegrees":0.25,
                "maximumLatitudeSpanDegrees":1.5
            }
        });
        assert!(schema.is_valid(&instance));

        instance["accessProfiles"][0]["grants"][0]["spatialQueries"]["bbox"]["geometryField"] =
            Value::String("location".to_owned());
        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_field_options_that_do_not_belong_to_the_field_type() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]["precision"] = Value::from(2_u64);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_missing_type_options_required_by_the_field_type() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]
            .as_object_mut()
            .expect("the field is an object")
            .remove("maxLength");

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_unknown_field_kinds() {
        let document = schema_document();
        let schema = compile(&document);
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["fields"][0]["type"] = Value::String("bytes".to_owned());

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn schema_accepts_the_minimal_tagged_event_and_webhook_shape() {
        let schema = compile(&schema_document());
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["events"] = serde_json::json!([{
            "id": "asset-created-v1",
            "trigger": "created",
            "projection": ["asset-code", "label"],
            "when": {
                "kind": "fields",
                "afterEquals": {"asset-class": "equipment"}
            },
            "webhook": {"destinationId": "asset-operations"}
        }]);

        assert!(schema.is_valid(&instance));
    }

    #[test]
    fn schema_rejects_per_event_delivery_policy() {
        let schema = compile(&schema_document());
        let mut instance = fixture("asset-site-placement");
        instance["entities"][0]["events"] = serde_json::json!([{
            "id": "asset-created-v1",
            "trigger": "created",
            "projection": ["asset-code"],
            "webhook": {
                "destinationId": "asset-operations",
                "authenticationProfile": "hmac_sha256_v1"
            }
        }]);

        assert!(!schema.is_valid(&instance));
    }

    #[test]
    fn committed_authoring_schema_matches_generated_bytes() {
        let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/generated/authoring")
            .join(REGISTRY_PROJECT_SCHEMA_FILE);
        assert_eq!(
            fs::read_to_string(committed).expect("the committed schema exists"),
            schema_document(),
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_declares_the_published_dialect_identifier_and_title() {
        let document = runtime_schema_document();
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
        );
        assert_eq!(
            value.get("$id").and_then(Value::as_str),
            Some(RUNTIME_CONFIG_SCHEMA_ID),
        );
        assert_eq!(
            value.get("title").and_then(Value::as_str),
            Some("Base Registry Engine runtime configuration"),
        );
        assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
        assert_eq!(
            value
                .pointer("/properties/apiVersion/const")
                .and_then(Value::as_str),
            Some(RUNTIME_CONFIG_API_VERSION),
        );
        assert_eq!(
            value
                .pointer("/properties/kind/const")
                .and_then(Value::as_str),
            Some(RUNTIME_CONFIG_KIND),
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_publishes_only_safe_operational_defaults() {
        let document = runtime_schema_document();
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        for (pointer, expected) in [
            (
                "/$defs/RawPoolBounds/properties/waitTimeoutMilliseconds/default",
                Value::from(30_000_u64),
            ),
            (
                "/$defs/RawPoolBounds/properties/createTimeoutMilliseconds/default",
                Value::from(30_000_u64),
            ),
            (
                "/$defs/RawPoolBounds/properties/recycleTimeoutMilliseconds/default",
                Value::from(30_000_u64),
            ),
            (
                "/$defs/RawOidcVerifierConfig/properties/jwksCache/default/requestTimeoutMilliseconds",
                Value::from(5_000_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/cacheTtlSeconds/default",
                Value::from(600_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/negativeCacheTtlSeconds/default",
                Value::from(60_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/refreshCooldownSeconds/default",
                Value::from(30_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/maxDocumentBytes/default",
                Value::from(65_536_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/requestTimeoutMilliseconds/default",
                Value::from(5_000_u64),
            ),
            (
                "/$defs/RawJwksCacheConfig/properties/outageToleranceSeconds/default",
                Value::from(900_u64),
            ),
            (
                "/$defs/RawCursorConfig/properties/maxAgeSeconds/default",
                Value::from(300_u64),
            ),
            (
                "/properties/eventDelivery/default/payloadRetentionDays",
                Value::from(7_u64),
            ),
            (
                "/properties/operationalTimeouts/default/httpRequestMilliseconds",
                Value::from(10_000_u64),
            ),
            (
                "/$defs/RawOperationalTimeouts/properties/httpRequestMilliseconds/default",
                Value::from(10_000_u64),
            ),
            (
                "/$defs/RawOperationalTimeouts/properties/shutdownGraceMilliseconds/default",
                Value::from(30_000_u64),
            ),
            (
                "/$defs/RawOperationalTimeouts/properties/recordLockMilliseconds/default",
                Value::from(5_000_u64),
            ),
            (
                "/$defs/RawOperationalTimeouts/properties/migrationLockMilliseconds/default",
                Value::from(30_000_u64),
            ),
            (
                "/$defs/RawOperationalTimeouts/properties/migrationStatementMilliseconds/default",
                Value::from(60_000_u64),
            ),
        ] {
            assert_eq!(value.pointer(pointer), Some(&expected), "{pointer}");
        }
        for pointer in [
            "/properties/eventDestinations/default",
            "/$defs/RawAuthorityClaimsConfig/properties/purpose/default",
            "/$defs/RawDatabaseConfig/properties/password/default",
            "/$defs/RawDatabaseConfig/properties/plaintext/default",
            "/$defs/RawDatabaseConfig/properties/url/default",
            "/$defs/RawEventDestinationConfig/properties/tls/default",
            "/$defs/RawEventDestinationTlsConfig/properties/caBundleRef/default",
            "/$defs/RawEventDestinationTlsConfig/properties/clientIdentityRef/default",
            "/$defs/RawOidcVerifierConfig/properties/allowedClients/default",
            "/$defs/RawOidcVerifierConfig/properties/deniedKids/default",
            "/$defs/RawOidcVerifierConfig/properties/jwksSource/default",
        ] {
            assert_eq!(value.pointer(pointer), None, "{pointer}");
        }
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_accepts_defaulted_runtime_and_rejects_inline_database_material() {
        let schema = compile(&runtime_schema_document());
        assert!(
            schema.is_valid(&runtime_instance()),
            "minimal runtime with safe defaults validates"
        );

        for (field, value) in [
            (
                "url",
                Value::String("postgres://inline.example/db".to_owned()),
            ),
            ("password", Value::String("inline-password".to_owned())),
            ("plaintext", Value::Bool(true)),
        ] {
            let mut instance = runtime_instance();
            instance["database"][field] = value;
            assert!(!schema.is_valid(&instance), "{field}");
        }

        let mut wrong_kind = runtime_instance();
        wrong_kind["kind"] = Value::String("RegistryProject".to_owned());
        assert!(!schema.is_valid(&wrong_kind));

        let value: Value =
            serde_json::from_str(&runtime_schema_document()).expect("the schema is JSON");
        assert!(value.pointer("/$defs/RawEventDestinationConfig").is_some());
        assert!(value
            .pointer("/$defs/RawEventDestinationConfigSchema")
            .is_none());
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_rejects_representative_parser_refused_values() {
        let schema = compile(&runtime_schema_document());
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "payload retention above runtime maximum",
            |instance| {
                instance["eventDelivery"] = serde_json::json!({"payloadRetentionDays": 31});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "package active sequence must be positive",
            |instance| {
                instance["package"]["activeSequence"] = Value::from(0_u64);
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "pool size above runtime maximum",
            |instance| {
                instance["database"]["pool"]["maxSize"] = Value::from(129_u64);
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "pool wait timeout above runtime maximum",
            |instance| {
                instance["database"]["pool"]["waitTimeoutMilliseconds"] = Value::from(60_001_u64);
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "SQL role identifier grammar",
            |instance| {
                instance["database"]["roles"]["runtime"] = Value::String("RegistryRuntime".into());
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "database secret reference grammar",
            |instance| {
                instance["database"]["runtimeUrlRef"] =
                    Value::String("secret:env/not_uppercase".into());
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "OIDC maximum token lifetime",
            |instance| {
                instance["authentication"]["oidc"]["maxTokenLifetimeSeconds"] =
                    Value::from(7_201_u64);
            },
        );
        assert_schema_rejects_parser_refused_runtime(&schema, "OIDC leeway", |instance| {
            instance["authentication"]["oidc"]["leewayMilliseconds"] = Value::from(300_001_u64);
        });
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "OIDC scope claim grammar",
            |instance| {
                instance["authentication"]["oidc"]["scopeClaim"] =
                    Value::String("bad claim".into());
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "OIDC scope separator grammar",
            |instance| {
                instance["authentication"]["oidc"]["scopeSeparator"] = Value::String("a".into());
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "OIDC client list uniqueness",
            |instance| {
                instance["authentication"]["oidc"]["allowedClients"] =
                    serde_json::json!(["client-a", "client-a"]);
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "authority claim excludes registered JWT claims",
            |instance| {
                instance["authentication"]["authorityClaims"]["principal"] =
                    Value::String("iss".into());
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "JWKS cache document size",
            |instance| {
                instance["authentication"]["oidc"]["jwksCache"] =
                    serde_json::json!({"maxDocumentBytes": 1_048_577});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "JWKS negative cache lower bound",
            |instance| {
                instance["authentication"]["oidc"]["jwksCache"] =
                    serde_json::json!({"negativeCacheTtlSeconds": 0});
            },
        );
        assert_schema_rejects_parser_refused_runtime(&schema, "cursor maximum age", |instance| {
            instance["cursor"]["maxAgeSeconds"] = Value::from(86_401_u64);
        });
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "operational timeout upper bound",
            |instance| {
                instance["operationalTimeouts"] =
                    serde_json::json!({"migrationStatementMilliseconds": 3_600_001});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "event destination identifier grammar",
            |instance| {
                instance["eventDestinations"] =
                    serde_json::json!({"AssetOps": valid_event_destination()});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "event destination signing secret reference grammar",
            |instance| {
                let mut destination = valid_event_destination();
                destination["hmacSha256KeyRef"] = Value::String("secret:file/".into());
                instance["eventDestinations"] = serde_json::json!({"asset_ops": destination});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "event destination attempt timeout lower bound",
            |instance| {
                let mut destination = valid_event_destination();
                destination["deliveryCeilings"]["attemptTimeoutMilliseconds"] = Value::from(99_u64);
                instance["eventDestinations"] = serde_json::json!({"asset_ops": destination});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "event destination maximum attempts upper bound",
            |instance| {
                let mut destination = valid_event_destination();
                destination["deliveryCeilings"]["maximumAttempts"] = Value::from(6_u64);
                instance["eventDestinations"] = serde_json::json!({"asset_ops": destination});
            },
        );
        assert_schema_rejects_parser_refused_runtime(
            &schema,
            "event destination TLS requires at least one string ref",
            |instance| {
                let mut destination = valid_event_destination();
                destination["tls"] = serde_json::json!({});
                instance["eventDestinations"] = serde_json::json!({"asset_ops": destination});
            },
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_reproduces_byte_for_byte() {
        assert_eq!(
            runtime_documents().expect("the Base Registry Engine runtime schema generates"),
            runtime_documents().expect("the Base Registry Engine runtime schema generates again"),
        );
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn runtime_schema_is_pretty_json_with_one_trailing_newline() {
        let document = runtime_schema_document();
        assert!(document.ends_with('\n') && !document.ends_with("\n\n"));
        let value: Value = serde_json::from_str(&document).expect("the schema is JSON");
        let mut rendered =
            serde_json::to_string_pretty(&value).expect("a parsed schema renders again");
        rendered.push('\n');
        assert_eq!(document, rendered);
    }

    #[cfg(feature = "runtime")]
    #[test]
    fn committed_runtime_schema_matches_generated_bytes() {
        let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/generated/runtime")
            .join(RUNTIME_CONFIG_SCHEMA_FILE);
        assert_eq!(
            fs::read_to_string(committed).expect("the committed runtime schema exists"),
            runtime_schema_document(),
        );
    }
}
