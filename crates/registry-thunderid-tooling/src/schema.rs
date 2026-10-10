//! The generated JSON Schema for the task connection file.
//!
//! The schema is derived from the type `dev grant` and `dev check` read,
//! never written by hand. Regenerate the committed document in
//! `products/platform/schemas` with:
//!
//! ```bash
//! cargo run -p registry-thunderid-tooling --features schema \
//!   --example task-connection-schema -- --output products/platform/schemas
//! ```

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::task_connection::{TaskConnection, API_VERSION, KIND};

/// The `$id` of the task connection schema.
pub const TASK_CONNECTION_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/platform/task-connection/task-connection.v1alpha1.schema.json";

pub const TASK_CONNECTION_SCHEMA_FILE: &str = "task-connection.schema.json";

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
    Ok([(
        TASK_CONNECTION_SCHEMA_FILE,
        render(
            connection,
            TASK_CONNECTION_SCHEMA_ID,
            "Registry Stack task connection",
        )?,
    )]
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
                 task-connection-schema -- --output products/platform/schemas`"
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
}
