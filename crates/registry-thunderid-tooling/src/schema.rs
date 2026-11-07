//! The generated JSON Schemas for the task connection file and the two
//! identity generator inputs (identity facts and the identity deployment).
//!
//! Each schema is derived from the type its reader parses, never written by
//! hand. Regenerate the committed document in
//! `products/platform/schemas` with:
//!
//! ```bash
//! cargo run -p registry-thunderid-tooling --features schema \
//!   --example tooling-schemas -- --output products/platform/schemas
//! ```

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::identity_deployment::IdentityDeployment;
use crate::identity_facts::IdentityFacts;
use crate::task_connection::{TaskConnection, API_VERSION, KIND};

/// The `$id` of the task connection schema.
pub const TASK_CONNECTION_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/task-connection/task-connection.v1alpha1.schema.json";

pub const TASK_CONNECTION_SCHEMA_FILE: &str = "task-connection.schema.json";

/// The `$id` of the identity facts schema.
pub const IDENTITY_FACTS_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/identity-facts/identity-facts.v1.schema.json";

pub const IDENTITY_FACTS_SCHEMA_FILE: &str = "identity-facts.schema.json";

/// The `$id` of the identity deployment schema.
pub const IDENTITY_DEPLOYMENT_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/identity-deployment/identity-deployment.v1.schema.json";

pub const IDENTITY_DEPLOYMENT_SCHEMA_FILE: &str = "identity-deployment.schema.json";

/// A claim name: letters, digits and underscores.
const CLAIM_NAME_PATTERN: &str = "^[A-Za-z0-9_]{1,128}$";

/// An environment secret reference: the only kind a deployment file states.
const ENVIRONMENT_SECRET_PATTERN: &str = "^secret:env/[A-Z][A-Z0-9_]{0,127}$";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// `https`, or `http` to 127.0.0.1, localhost, or [::1]; no query or
/// fragment.
const ENDPOINT_PATTERN: &str = "^(?:[Hh][Tt][Tt][Pp][Ss]://[^/?#@]+|[Hh][Tt][Tt][Pp]://(?:127\\.0\\.0\\.1|localhost|\\[::1\\])(?::[0-9]+)?)(?:/[^?#]*)?$";

/// An absolute URI written in URI characters, without a fragment.
const RESOURCE_PATTERN: &str =
    "^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~:/?\\[\\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$";

/// An OAuth scope token without `*`.
const SCOPE_PATTERN: &str = "^[!#-)+-\\[\\]-~]+$";

const CLIENT_ID_PATTERN: &str = "^[a-z0-9-]{1,64}$";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut connection = serde_json::to_value(schemars::schema_for!(TaskConnection))?;
    install_constraints(&mut connection);
    let mut facts = serde_json::to_value(schemars::schema_for!(IdentityFacts))?;
    install_facts_constraints(&mut facts);
    let mut deployment = serde_json::to_value(schemars::schema_for!(IdentityDeployment))?;
    install_deployment_constraints(&mut deployment);
    Ok([
        (
            TASK_CONNECTION_SCHEMA_FILE,
            render(
                connection,
                TASK_CONNECTION_SCHEMA_ID,
                "Registry Stack task connection",
            )?,
        ),
        (
            IDENTITY_FACTS_SCHEMA_FILE,
            render(
                facts,
                IDENTITY_FACTS_SCHEMA_ID,
                "Registry Stack identity facts",
            )?,
        ),
        (
            IDENTITY_DEPLOYMENT_SCHEMA_FILE,
            render(
                deployment,
                IDENTITY_DEPLOYMENT_SCHEMA_ID,
                "Registry Stack identity deployment",
            )?,
        ),
    ]
    .into())
}

/// The derived schema with its `$schema`, `$id`, and `title`, pretty printed
/// with a final newline.
fn render(derived: Value, id: &str, title: &str) -> Result<String, serde_json::Error> {
    let Value::Object(mut object) = derived else {
        unreachable!("schemars derives a schema object for a struct")
    };
    object.insert("$schema".to_owned(), Value::String(DRAFT.to_owned()));
    object.insert("$id".to_owned(), Value::String(id.to_owned()));
    object.insert("title".to_owned(), Value::String(title.to_owned()));
    let mut rendered = serde_json::to_string_pretty(&Value::Object(object))?;
    rendered.push('\n');
    Ok(rendered)
}

/// State in the schema what `task_connection::check` enforces beyond the
/// types: the envelope values, the endpoint and resource rules, client ids
/// that are file names, and the client and scope bounds. Each rule narrows
/// a member with `allOf` beside its shared type, which stays unchanged.
fn install_constraints(schema: &mut Value) {
    for (property, value) in [("apiVersion", API_VERSION), ("kind", KIND)] {
        if let Some(member) = schema
            .pointer_mut(&format!("/properties/{property}"))
            .and_then(Value::as_object_mut)
        {
            member.insert("const".to_owned(), Value::String(value.to_owned()));
        }
    }
    let narrowings = [
        (
            "/properties/caseworkUrl",
            json!([{"pattern": ENDPOINT_PATTERN}]),
        ),
        (
            "/properties/tokenEndpoint",
            json!([{"pattern": ENDPOINT_PATTERN}]),
        ),
        (
            "/properties/clientAssertionAudience",
            json!([{"pattern": RESOURCE_PATTERN}]),
        ),
        (
            "/properties/bootstrapResource",
            json!([{"pattern": RESOURCE_PATTERN}]),
        ),
        (
            "/$defs/TaskClient/properties/resource",
            json!([{"pattern": RESOURCE_PATTERN}]),
        ),
        (
            "/$defs/TaskClient/properties/scopes",
            json!([{
                "minItems": 1,
                "maxItems": crate::task_connection::MAXIMUM_SCOPES,
                "items": {
                    "maxLength": crate::task_connection::MAXIMUM_SCOPE_BYTES,
                    "pattern": SCOPE_PATTERN
                }
            }]),
        ),
    ];
    for (pointer, all_of) in narrowings {
        if let Some(member) = schema.pointer_mut(pointer).and_then(Value::as_object_mut) {
            member.insert("allOf".to_owned(), all_of);
        }
    }
    if let Some(clients) = schema
        .pointer_mut("/properties/clients")
        .and_then(Value::as_object_mut)
    {
        clients.insert(
            "propertyNames".to_owned(),
            json!({
                "$ref": "#/$defs/ExternalId",
                "allOf": [{"pattern": CLIENT_ID_PATTERN}]
            }),
        );
        clients.insert("minProperties".to_owned(), json!(1));
        clients.insert(
            "maxProperties".to_owned(),
            json!(crate::task_connection::MAXIMUM_CLIENTS),
        );
    }
}

/// Pin `apiVersion` and `kind` to the values the reader accepts.
fn install_envelope(schema: &mut Value, api_version: &str, kind: &str) {
    for (property, value) in [("apiVersion", api_version), ("kind", kind)] {
        if let Some(member) = schema
            .pointer_mut(&format!("/properties/{property}"))
            .and_then(Value::as_object_mut)
        {
            member.insert("const".to_owned(), Value::String(value.to_owned()));
        }
    }
}

/// Name the keys of the claim mapping at `pointer`: external ids that are
/// also claim names. Defines `ExternalId` when no member of the schema
/// already uses it.
fn install_claim_names(schema: &mut Value, pointer: &str) {
    if schema.pointer("/$defs/ExternalId").is_none() {
        let mut definition =
            serde_json::to_value(schemars::schema_for!(registry_platform_yaml::ExternalId))
                .expect("the ExternalId schema is JSON");
        if let Some(object) = definition.as_object_mut() {
            object.remove("$schema");
            object.remove("title");
        }
        if let Some(definitions) = schema.pointer_mut("/$defs").and_then(Value::as_object_mut) {
            definitions.insert("ExternalId".to_owned(), definition);
        }
    }
    install_bounds(
        schema,
        pointer,
        json!({"propertyNames": {
            "$ref": "#/$defs/ExternalId",
            "allOf": [{"pattern": CLAIM_NAME_PATTERN}]
        }}),
    );
}

/// Bound a list or mapping member the way the reader's limits do.
fn install_bounds(schema: &mut Value, pointer: &str, bounds: Value) {
    if let (Some(member), Some(bounds)) = (
        schema.pointer_mut(pointer).and_then(Value::as_object_mut),
        bounds.as_object(),
    ) {
        member.extend(bounds.clone());
    }
}

/// State in the schema what `identity_facts::read` enforces beyond the types:
/// the envelope, claim names and counts, and the list limits.
fn install_facts_constraints(schema: &mut Value) {
    use crate::identity_facts as facts;
    install_envelope(schema, facts::API_VERSION, facts::KIND);
    install_claim_names(schema, "/properties/claims");
    install_claim_names(schema, "/$defs/AssertionIssuer/properties/projectedClaims");
    install_bounds(
        schema,
        "/properties/claims",
        json!({"maxProperties": facts::MAXIMUM_CLAIMS}),
    );
    install_bounds(
        schema,
        "/properties/accessProfiles",
        json!({"maxItems": facts::MAXIMUM_PROFILES}),
    );
    install_bounds(
        schema,
        "/properties/assertionIssuers",
        json!({"maxItems": facts::MAXIMUM_ASSERTION_ISSUERS}),
    );
    install_bounds(
        schema,
        "/$defs/Admission/anyOf/1",
        json!({"minItems": 1, "maxItems": facts::MAXIMUM_CLIENTS}),
    );
    install_bounds(
        schema,
        "/$defs/AccessProfile/properties/scopes",
        json!({"minItems": 1, "maxItems": facts::MAXIMUM_SCOPES}),
    );
    install_claim_names(schema, "/$defs/AccessProfile/properties/selectedBy");
    install_bounds(
        schema,
        "/$defs/AccessProfile/properties/selectedBy",
        json!({"maxProperties": facts::MAXIMUM_CLAIMS}),
    );
    install_bounds(
        schema,
        "/$defs/AccessProfile/properties/selectedBy/additionalProperties",
        json!({"maxItems": facts::MAXIMUM_SELECTOR_VALUES}),
    );
    install_bounds(
        schema,
        "/$defs/AccessProfile/properties/purposes",
        json!({"maxItems": facts::MAXIMUM_PURPOSES}),
    );
    install_bounds(
        schema,
        "/$defs/AccessProfile/properties/requiredClaims",
        json!({"maxItems": facts::MAXIMUM_CLAIMS, "uniqueItems": true}),
    );
    for pointer in [
        "/$defs/AccessProfile/properties/requiredClaims/items",
        "/$defs/AccessProfile/properties/refusedClaims/items",
    ] {
        install_bounds(schema, pointer, json!({"pattern": CLAIM_NAME_PATTERN}));
    }
    for pointer in [
        "/$defs/AccessProfile/properties/scopes",
        "/$defs/AccessProfile/properties/purposes",
        "/$defs/AccessProfile/properties/requesterClients",
        "/$defs/AccessProfile/properties/selectedBy/additionalProperties",
        "/$defs/AccessProfile/properties/admittedActorKinds",
        "/$defs/AccessProfile/properties/refusedClaims",
    ] {
        install_bounds(schema, pointer, json!({"uniqueItems": true}));
    }
}

/// State in the schema what `identity_deployment::read` enforces beyond the
/// types: the envelope, environment-only secret references, and the principal
/// and grant limits.
fn install_deployment_constraints(schema: &mut Value) {
    use crate::identity_deployment as deployment;
    install_envelope(schema, deployment::API_VERSION, deployment::KIND);
    for pointer in [
        "/properties/clients",
        "/properties/browserApps",
        "/properties/users",
    ] {
        install_bounds(
            schema,
            pointer,
            json!({"maxItems": deployment::MAXIMUM_PRINCIPALS}),
        );
    }
    install_claim_names(schema, "/$defs/Client/properties/claims");
    install_claim_names(schema, "/$defs/User/properties/claims");
    for definition in ["Client", "BrowserApp", "User"] {
        install_bounds(
            schema,
            &format!("/$defs/{definition}/properties/grants"),
            json!({"minItems": 1, "maxItems": deployment::MAXIMUM_GRANTS}),
        );
    }
    for pointer in [
        "/$defs/BrowserApp/properties/clientSecretRef",
        "/$defs/User/properties/passwordRef",
    ] {
        install_bounds(
            schema,
            pointer,
            json!({"allOf": [{"pattern": ENVIRONMENT_SECRET_PATTERN}]}),
        );
    }
    for pointer in [
        "/$defs/Grant/properties/accessProfiles",
        "/$defs/BrowserApp/properties/redirectUris",
        "/$defs/BrowserApp/properties/tokenAttributes",
        "/$defs/BrowserApp/properties/userTypes",
        "/$defs/UserType/properties/attributes",
    ] {
        install_bounds(schema, pointer, json!({"uniqueItems": true}));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;

    use super::*;
    use crate::task_connection::read;

    const PLATFORM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/platform");

    fn validator() -> JSONSchema {
        let schema: Value =
            serde_json::from_str(&schema_documents().unwrap()[TASK_CONNECTION_SCHEMA_FILE])
                .unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("the schema compiles as Draft 2020-12: {error}"))
    }

    fn example() -> Value {
        let bytes =
            std::fs::read(Path::new(PLATFORM).join("examples/task-connection.yaml")).unwrap();
        Reader::new("task-connection.yaml")
            .scan(&bytes)
            .expect("the example is YAML")
            .expect("the example is not empty")
            .to_json_value()
    }

    /// The example with the member at `pointer` replaced.
    fn with(pointer: &str, value: Value) -> Value {
        let mut document = example();
        *document.pointer_mut(pointer).unwrap() = value;
        document
    }

    fn judged_alike(document: &Value, accepted: bool, case: &str) {
        let text = serde_json::to_string(document).unwrap();
        assert_eq!(
            read("task-connection.yaml", text.as_bytes()).is_ok(),
            accepted,
            "reader: {case}"
        );
        assert_eq!(validator().is_valid(document), accepted, "schema: {case}");
    }

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(Path::new(PLATFORM).join("schemas").join(name))
                .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-thunderid-tooling --features schema --example \
                 tooling-schemas -- --output products/platform/schemas`"
            );
        }
    }

    #[test]
    fn shared_blocks_are_embedded_unchanged() {
        let canonical: Value = serde_json::from_str(include_str!(
            "../../../products/platform/generated/runtime-config-blocks.schema.json"
        ))
        .unwrap();
        for (name, document) in schema_documents().unwrap() {
            let document: Value = serde_json::from_str(&document).unwrap();
            for (definition, schema) in document["$defs"].as_object().unwrap() {
                if let Some(shared) = canonical["$defs"].get(definition) {
                    assert_eq!(schema, shared, "{name} changed shared block {definition}");
                }
            }
        }
    }

    #[test]
    fn the_committed_example_is_accepted_by_schema_and_reader() {
        judged_alike(&example(), true, "the example");
    }

    #[test]
    fn endpoints_are_judged_alike_by_schema_and_reader() {
        for (url, accepted) in [
            ("https://casework.example", true),
            ("https://casework.example:8443/api", true),
            ("http://127.0.0.1:8090", true),
            ("http://localhost/api", true),
            ("http://[::1]:8090", true),
            ("http://casework.example", false),
            ("https://casework.example/api?tenant=a", false),
            ("https://casework.example/api#part", false),
            ("ftp://casework.example", false),
        ] {
            for member in ["/caseworkUrl", "/tokenEndpoint"] {
                judged_alike(
                    &with(member, json!(url)),
                    accepted,
                    &format!("{member} {url}"),
                );
            }
        }
    }

    #[test]
    fn resources_are_judged_alike_by_schema_and_reader() {
        for (resource, accepted) in [
            ("urn:registry:breg", true),
            ("https://breg.example/api", true),
            ("https://breg.example/api#part", false),
            ("registry", false),
            ("urn:registry breg", false),
            ("1urn:registry", false),
        ] {
            for member in [
                "/clientAssertionAudience",
                "/bootstrapResource",
                "/clients/task-agent/resource",
            ] {
                judged_alike(
                    &with(member, json!(resource)),
                    accepted,
                    &format!("{member} {resource}"),
                );
            }
        }
    }

    #[test]
    fn scopes_are_judged_alike_by_schema_and_reader() {
        let long = "s".repeat(crate::task_connection::MAXIMUM_SCOPE_BYTES + 1);
        let many: Vec<String> = (0..=crate::task_connection::MAXIMUM_SCOPES)
            .map(|index| format!("scope-{index}"))
            .collect();
        for (scopes, accepted) in [
            (json!(["records:get", "records:list"]), true),
            (json!([]), false),
            (json!(["records:*"]), false),
            (json!(["records get"]), false),
            (json!(["records\"get"]), false),
            (json!([long]), false),
            (json!(many), false),
            (json!(["records:get", "records:get"]), false),
        ] {
            judged_alike(
                &with("/clients/task-agent/scopes", scopes.clone()),
                accepted,
                &scopes.to_string(),
            );
        }
    }

    #[test]
    fn clients_are_judged_alike_by_schema_and_reader() {
        let client = example()["clients"]["task-agent"].clone();
        let clients = |ids: &[String]| {
            Value::Object(ids.iter().map(|id| (id.clone(), client.clone())).collect())
        };
        let bound = crate::task_connection::MAXIMUM_CLIENTS;
        for (ids, accepted) in [
            (vec!["task-agent".to_owned()], true),
            (
                (0..bound).map(|index| format!("agent-{index}")).collect(),
                true,
            ),
            (vec![], false),
            (
                (0..=bound).map(|index| format!("agent-{index}")).collect(),
                false,
            ),
            (vec!["Task-Agent".to_owned()], false),
            (vec!["task_agent".to_owned()], false),
            (vec!["task/agent".to_owned()], false),
            (vec!["a".repeat(65)], false),
        ] {
            judged_alike(
                &with("/clients", clients(&ids)),
                accepted,
                &format!("{ids:?}"),
            );
        }
    }

    fn identity_validator(file: &str) -> JSONSchema {
        let schema: Value = serde_json::from_str(&schema_documents().unwrap()[file]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("the schema compiles as Draft 2020-12: {error}"))
    }

    fn identity_example(name: &str) -> Value {
        let bytes =
            std::fs::read(Path::new(PLATFORM).join("examples/identity").join(name)).unwrap();
        Reader::new(name)
            .scan(&bytes)
            .expect("the example is YAML")
            .expect("the example is not empty")
            .to_json_value()
    }

    /// The schema and the reader must agree on `document`.
    fn identity_judged_alike(
        file: &str,
        read: fn(&str, &[u8]) -> bool,
        document: &Value,
        accepted: bool,
        case: &str,
    ) {
        let text = serde_json::to_string(document).unwrap();
        assert_eq!(
            read("example.yaml", text.as_bytes()),
            accepted,
            "reader: {case}"
        );
        assert_eq!(
            identity_validator(file).is_valid(document),
            accepted,
            "schema: {case}"
        );
    }

    fn reads_facts(file: &str, bytes: &[u8]) -> bool {
        crate::identity_facts::read(file, bytes).is_ok()
    }

    fn reads_deployment(file: &str, bytes: &[u8]) -> bool {
        crate::identity_deployment::read(file, bytes).is_ok()
    }

    fn facts_judged(pointer: &str, value: Value, accepted: bool) {
        let mut document = identity_example("identity-facts.yaml");
        *document.pointer_mut(pointer).unwrap() = value.clone();
        identity_judged_alike(
            IDENTITY_FACTS_SCHEMA_FILE,
            reads_facts,
            &document,
            accepted,
            &format!("{pointer} {value}"),
        );
    }

    fn deployment_judged(pointer: &str, value: Value, accepted: bool) {
        let mut document = identity_example("identity-deployment.yaml");
        *document.pointer_mut(pointer).unwrap() = value.clone();
        identity_judged_alike(
            IDENTITY_DEPLOYMENT_SCHEMA_FILE,
            reads_deployment,
            &document,
            accepted,
            &format!("{pointer} {value}"),
        );
    }

    #[test]
    fn the_identity_examples_are_accepted_by_schema_and_reader() {
        identity_judged_alike(
            IDENTITY_FACTS_SCHEMA_FILE,
            reads_facts,
            &identity_example("identity-facts.yaml"),
            true,
            "the facts example",
        );
        let deployment = identity_example("identity-deployment.yaml");
        let text = serde_json::to_string(&deployment).unwrap();
        assert!(identity_validator(IDENTITY_DEPLOYMENT_SCHEMA_FILE).is_valid(&deployment));
        // The reader needs the key file beside the example only at generation
        // time; reading the document alone does not open it.
        assert!(reads_deployment("example.yaml", text.as_bytes()));
    }

    #[test]
    fn identity_envelopes_are_judged_alike_by_schema_and_reader() {
        for (pointer, value, accepted) in [
            ("/kind", json!("PlatformIdentityFacts"), true),
            ("/kind", json!("PlatformIdentityDeployment"), false),
            (
                "/apiVersion",
                json!("id.registrystack.org/formats/platform/identity-facts/v2"),
                false,
            ),
        ] {
            facts_judged(pointer, value, accepted);
        }
        deployment_judged("/kind", json!("PlatformIdentityFacts"), false);
    }

    #[test]
    fn admission_is_judged_alike_by_schema_and_reader() {
        for (value, accepted) in [
            (json!("unrestricted"), true),
            (json!(["case-portal"]), true),
            (json!([]), false),
            (json!(["case-portal", "case-portal"]), false),
            (json!("everyone"), false),
            (json!([1]), false),
        ] {
            facts_judged("/allowedClients", value, accepted);
        }
    }

    #[test]
    fn claims_are_judged_alike_by_schema_and_reader() {
        // The example's profiles require registry_principal, so every case
        // keeps it declared.
        for (claims, accepted) in [
            (json!({"registry_principal": "string"}), true),
            (
                json!({"registry_principal": "string", "evidence_tags": "string-array"}),
                true,
            ),
            (json!({"registry_principal": "number"}), false),
            (
                json!({"registry_principal": "string", "bad name": "string"}),
                false,
            ),
            (json!({"registry_principal": "string", "": "string"}), false),
        ] {
            facts_judged("/claims", claims, accepted);
        }
    }

    #[test]
    fn required_claims_are_judged_alike_by_schema_and_reader() {
        let many: Vec<String> = (0..=crate::identity_facts::MAXIMUM_CLAIMS)
            .map(|index| format!("claim_{index}"))
            .collect();
        for (required, accepted) in [
            (json!(["registry_role"]), true),
            (json!([]), true),
            (json!(["registry_role", "registry_role"]), false),
            (json!(["bad name"]), false),
            (json!(many), false),
        ] {
            facts_judged(
                "/accessProfiles/0/requiredClaims",
                required.clone(),
                accepted,
            );
        }
    }

    #[test]
    fn secret_references_are_judged_alike_by_schema_and_reader() {
        for (member, valid) in [
            (
                "/browserApps/0/clientSecretRef",
                "secret:env/PORTAL_APP_SECRET",
            ),
            ("/users/0/passwordRef", "secret:env/OFFICER_PASSWORD"),
        ] {
            for (reference, accepted) in [
                (valid, true),
                ("secret:file/staff-portal.secret", false),
                ("secret:env/lowercase", false),
                ("plain-text", false),
            ] {
                deployment_judged(member, json!(reference), accepted);
            }
        }
    }

    #[test]
    fn principal_ids_are_judged_alike_by_schema_and_reader() {
        for (member, valid) in [
            ("/clients/0/id", "machine-client"),
            ("/browserApps/0/id", "portal-app"),
            ("/users/0/id", "officer"),
        ] {
            for (id, accepted) in [
                (valid, true),
                ("Case-Portal", false),
                ("case portal", false),
                ("", false),
            ] {
                deployment_judged(member, json!(id), accepted);
            }
        }
    }

    #[test]
    fn grants_are_judged_alike_by_schema_and_reader() {
        let grant = json!({"product": "breg", "accessProfiles": ["case-read"]});
        let many: Vec<Value> = (0..=crate::identity_deployment::MAXIMUM_GRANTS)
            .map(|index| json!({"product": format!("product-{index}"), "accessProfiles": ["a"]}))
            .collect();
        for (grants, accepted) in [
            (json!([grant]), true),
            (json!([]), false),
            (Value::Array(many), false),
        ] {
            deployment_judged("/clients/0/grants", grants, accepted);
        }
    }

    #[test]
    fn identity_schemas_are_closed() {
        for file in [IDENTITY_FACTS_SCHEMA_FILE, IDENTITY_DEPLOYMENT_SCHEMA_FILE] {
            let schema: Value = serde_json::from_str(&schema_documents().unwrap()[file]).unwrap();
            assert_eq!(schema["additionalProperties"], json!(false), "{file}");
        }
        let mut document = identity_example("identity-facts.yaml");
        document["surprise"] = json!(true);
        identity_judged_alike(
            IDENTITY_FACTS_SCHEMA_FILE,
            reads_facts,
            &document,
            false,
            "an unknown member",
        );
    }
}
