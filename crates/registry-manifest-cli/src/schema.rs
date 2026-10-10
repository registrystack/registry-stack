// SPDX-License-Identifier: Apache-2.0
//! Generated JSON Schemas for the metadata manifest and the profile
//! descriptor.
//!
//! Each schema is derived from the types `registry-manifest validate` and
//! `registry-manifest validate-profiles` read, never written by hand.
//! Regenerate the committed documents in `products/manifest/schemas` with:
//!
//! ```bash
//! cargo run -p registry-manifest-cli --features schema --example manifest-schema -- \
//!   --output products/manifest/schemas
//! ```

use std::collections::BTreeMap;

use registry_manifest_core::MetadataManifestFields;
use serde_json::{json, Value};

use crate::profile::ProfileDescriptor;
use crate::METADATA_SCHEMA_VERSION;

/// The `$id` of the metadata manifest schema.
pub const METADATA_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/manifest/metadata/metadata.v1.schema.json";
/// The `$id` of the profile descriptor schema.
pub const PROFILE_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/manifest/profile/profile.v1.schema.json";

pub const METADATA_SCHEMA_FILE: &str = "metadata.schema.json";
pub const PROFILE_SCHEMA_FILE: &str = "profile.schema.json";

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every generated schema, by file name, as the bytes to commit.
pub fn schema_documents() -> Result<BTreeMap<&'static str, String>, serde_json::Error> {
    let mut metadata = serde_json::to_value(schemars::schema_for!(MetadataManifestFields))?;
    without_null(&mut metadata);
    install_metadata_constraints(&mut metadata);
    let mut profile = serde_json::to_value(schemars::schema_for!(ProfileDescriptor))?;
    without_null(&mut profile);
    install_profile_constraints(&mut profile);
    Ok([
        (
            METADATA_SCHEMA_FILE,
            render(
                metadata,
                METADATA_SCHEMA_ID,
                "Registry Manifest metadata manifest",
            )?,
        ),
        (
            PROFILE_SCHEMA_FILE,
            render(
                profile,
                PROFILE_SCHEMA_ID,
                "Registry Manifest profile descriptor",
            )?,
        ),
    ]
    .into())
}

/// Take `null` out of every member: the reader refuses `null` everywhere
/// (CFG-EMPTY-1), so an optional member is either absent or holds a value.
/// schemars writes an optional member as a type list with `null`, or as an
/// `anyOf` with a `null` branch, and gives it `default: null`; a defaulted
/// struct's `default` lists its absent members as `null`.
fn without_null(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            match object.get_mut("default") {
                Some(Value::Null) => {
                    object.remove("default");
                }
                Some(Value::Object(default)) => default.retain(|_, member| !member.is_null()),
                _ => {}
            }
            if let Some(Value::Array(types)) = object.get_mut("type") {
                types.retain(|kind| kind != "null");
                if let [only] = types.as_slice() {
                    let only = only.clone();
                    object.insert("type".to_owned(), only);
                }
            }
            let is_null = |branch: &Value| branch.get("type") == Some(&json!("null"));
            if let Some(Value::Array(branches)) = object.get("anyOf") {
                if let [first, second] = branches.as_slice() {
                    let kept = match (is_null(first), is_null(second)) {
                        (false, true) => Some(first.clone()),
                        (true, false) => Some(second.clone()),
                        _ => None,
                    };
                    if let Some(Value::Object(kept)) = kept {
                        object.remove("anyOf");
                        object.extend(kept);
                    }
                }
            }
            object.values_mut().for_each(without_null);
        }
        Value::Array(items) => items.iter_mut().for_each(without_null),
        _ => {}
    }
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

/// State in the schema what `read_metadata` enforces beyond the types: the
/// one schema version it reads.
fn install_metadata_constraints(schema: &mut Value) {
    if let Some(member) = schema
        .pointer_mut("/properties/schema_version")
        .and_then(Value::as_object_mut)
    {
        member.insert(
            "const".to_owned(),
            Value::String(METADATA_SCHEMA_VERSION.to_owned()),
        );
    }
}

/// State in the schema what `check_profiles` enforces beyond the types: a
/// version with text, at least one entry in each required list, and a
/// fixture path that is relative and has no `..` segment. That the profile
/// id names the descriptor's directory and that `min` is at most `max` are
/// left to the check, and the members' descriptions say so.
fn install_profile_constraints(schema: &mut Value) {
    for list in [
        "supported_input_artifacts",
        "conformance_checks",
        "fixtures",
    ] {
        if let Some(member) = schema
            .pointer_mut(&format!("/properties/{list}"))
            .and_then(Value::as_object_mut)
        {
            member.insert("minItems".to_owned(), json!(1));
        }
    }
    if let Some(member) = schema
        .pointer_mut("/$defs/ProfileIdentity/properties/version")
        .and_then(Value::as_object_mut)
    {
        member.insert("minLength".to_owned(), json!(1));
    }
    if let Some(member) = schema
        .pointer_mut("/$defs/ProfileFixture/properties/path")
        .and_then(Value::as_object_mut)
    {
        member.insert("minLength".to_owned(), json!(1));
        member.insert("not".to_owned(), json!({"pattern": "^/|(^|/)\\.\\.(/|$)"}));
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use jsonschema::{Draft, JSONSchema};
    use registry_platform_yaml::Reader;

    use super::*;
    use crate::{check_profiles, read_metadata};

    const PRODUCT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../products/manifest");

    fn validator(file: &str) -> JSONSchema {
        let schema: Value = serde_json::from_str(&schema_documents().unwrap()[file]).unwrap();
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{file} compiles as Draft 2020-12: {error}"))
    }

    fn as_json(file: &str, bytes: &[u8]) -> Value {
        Reader::new(file)
            .scan(bytes)
            .expect("the file is YAML")
            .expect("the file is not empty")
            .to_json_value()
    }

    fn profile_directories() -> Vec<PathBuf> {
        let mut directories = std::fs::read_dir(Path::new(PRODUCT).join("profiles"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("profile.yaml").is_file())
            .collect::<Vec<_>>();
        directories.sort();
        directories
    }

    #[test]
    fn committed_schemas_match_generated_bytes() {
        for (name, generated) in schema_documents().unwrap() {
            let committed = std::fs::read_to_string(Path::new(PRODUCT).join("schemas").join(name))
                .unwrap_or_else(|error| panic!("{name} reads: {error}"));
            assert_eq!(
                committed, generated,
                "{name} drifted from its generator; regenerate it with \
                 `cargo run -p registry-manifest-cli --features schema --example manifest-schema -- \
                 --output products/manifest/schemas`"
            );
        }
    }

    #[test]
    fn every_committed_descriptor_and_fixture_is_accepted_by_schema_and_reader() {
        let profiles = validator(PROFILE_SCHEMA_FILE);
        let metadata = validator(METADATA_SCHEMA_FILE);
        let check = check_profiles(&Path::new(PRODUCT).join("profiles"));
        assert!(
            check.report.diagnostics().is_empty(),
            "{:?}",
            check.report.diagnostics()
        );
        let mut fixtures = 0;
        for directory in profile_directories() {
            let bytes = std::fs::read(directory.join("profile.yaml")).unwrap();
            assert!(
                profiles.is_valid(&as_json("profile.yaml", &bytes)),
                "{}",
                directory.display()
            );
            for fixture in std::fs::read_dir(directory.join("fixtures")).unwrap() {
                let fixture = fixture.unwrap().path();
                let bytes = std::fs::read(&fixture).unwrap();
                read_metadata("metadata.yaml", &bytes).expect("the reader accepts the fixture");
                assert!(
                    metadata.is_valid(&as_json("metadata.yaml", &bytes)),
                    "{}",
                    fixture.display()
                );
                fixtures += 1;
            }
        }
        assert!(fixtures > 0, "the profiles carry fixtures");
    }

    #[test]
    fn the_schema_version_is_judged_alike_by_schema_and_reader() {
        let validator = validator(METADATA_SCHEMA_FILE);
        for (version, accepted) in [
            ("registry-manifest/v1", true),
            ("registry-manifest/v2", false),
            ("registry-manifest-profile/v1", false),
        ] {
            let document = json!({
                "schema_version": version,
                "catalog": {
                    "id": "demo",
                    "base_url": "https://metadata.example.test",
                    "title": "Demo",
                    "publisher": {"name": "Publisher"}
                }
            });
            let text = serde_json::to_string(&document).unwrap();
            assert_eq!(
                read_metadata("metadata.yaml", text.as_bytes()).is_ok(),
                accepted,
                "reader: {version}"
            );
            assert_eq!(validator.is_valid(&document), accepted, "schema: {version}");
        }
    }

    #[test]
    fn null_is_refused_by_schema_and_reader() {
        let validator = validator(METADATA_SCHEMA_FILE);
        let document = json!({
            "schema_version": METADATA_SCHEMA_VERSION,
            "catalog": {
                "id": "demo",
                "base_url": "https://metadata.example.test",
                "title": "Demo",
                "description": null,
                "publisher": {"name": "Publisher"}
            }
        });
        let text = serde_json::to_string(&document).unwrap();
        let refused = read_metadata("metadata.yaml", text.as_bytes())
            .err()
            .expect("the reader refuses null");
        assert_eq!(refused[0].code, "config.null-value");
        assert!(!validator.is_valid(&document));
    }

    #[test]
    fn descriptor_members_are_judged_alike_by_schema_and_check() {
        let validator = validator(PROFILE_SCHEMA_FILE);
        let descriptor = |version: &str, path: &str, min: u32, artifacts: Value| {
            json!({
                "schema_version": "registry-manifest-profile/v1",
                "profile": {"id": "demo", "version": version},
                "supported_input_artifacts": artifacts,
                "cardinality_expectations": [
                    {"entity": "person", "field": "person_id", "min": min, "max": 1}
                ],
                "conformance_checks": [{"id": "demo.check"}],
                "fixtures": [{"path": path}]
            })
        };
        let artifacts = json!([{"kind": "metadata_manifest"}]);
        let cases = [
            (
                descriptor("1", "fixtures/metadata.yaml", 1, artifacts.clone()),
                true,
            ),
            (
                descriptor("", "fixtures/metadata.yaml", 1, artifacts.clone()),
                false,
            ),
            (descriptor("1", "", 1, artifacts.clone()), false),
            (
                descriptor("1", "/fixtures/metadata.yaml", 1, artifacts.clone()),
                false,
            ),
            (
                descriptor("1", "../metadata.yaml", 1, artifacts.clone()),
                false,
            ),
            (
                descriptor("1", "fixtures/../metadata.yaml", 1, artifacts.clone()),
                false,
            ),
            (
                descriptor("1", "fixtures/metadata.yaml", 2, artifacts.clone()),
                false,
            ),
            (
                descriptor("1", "fixtures/metadata.yaml", 1, json!([])),
                false,
            ),
        ];
        let temporary =
            std::env::temp_dir().join(format!("registry-manifest-schema-{}", std::process::id()));
        for (document, accepted) in cases {
            let root = temporary.join("profiles");
            let directory = root.join("demo");
            std::fs::create_dir_all(directory.join("fixtures")).unwrap();
            std::fs::write(
                directory.join("profile.yaml"),
                serde_json::to_string_pretty(&document).unwrap(),
            )
            .unwrap();
            std::fs::write(
                directory.join("fixtures/metadata.yaml"),
                "schema_version: registry-manifest/v1\ncatalog:\n  id: demo\n  \
                 base_url: https://metadata.example.test\n  title: Demo\n  publisher:\n    \
                 name: Publisher\nprofiles:\n  - id: demo\n    version: \"1\"\ndatasets:\n  \
                 - id: people\n    title: People\n    entities:\n      - name: person\n        \
                 fields:\n          - name: person_id\n            type: string\n",
            )
            .unwrap();
            let check = check_profiles(&root);
            let errors = check.report.error_count();
            std::fs::remove_dir_all(&temporary).unwrap();
            assert_eq!(
                errors == 0,
                accepted,
                "check: {document}\n{:?}",
                check.report.diagnostics()
            );
            assert_eq!(
                validator.is_valid(&document),
                accepted,
                "schema: {document}"
            );
        }
    }

    /// The rules a schema cannot state are left to the check, and the
    /// member's description names them (CFG-SCHEMA-9).
    #[test]
    fn the_directory_id_and_the_bound_order_are_named_in_descriptions() {
        let documents = schema_documents().unwrap();
        let profile: Value = serde_json::from_str(&documents[PROFILE_SCHEMA_FILE]).unwrap();
        let description = |pointer: &str| {
            profile
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{pointer} has a description"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let id = description("/$defs/ProfileIdentity/properties/id/description");
        assert!(id.contains("names the directory"), "{id}");
        let bounds = description("/$defs/CardinalityExpectation/description");
        assert!(bounds.contains("`min` is at most `max`"), "{bounds}");
    }
}
