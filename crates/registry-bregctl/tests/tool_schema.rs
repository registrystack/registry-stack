// SPDX-License-Identifier: Apache-2.0
//! The generated tool schemas accept each format's committed example and
//! refuse the shapes the reader refuses.

use std::path::Path;

use jsonschema::{Draft, JSONSchema};
use registry_bregctl::tool_schema::documents;
use serde_json::Value;

/// Each generated schema and the committed minimal example of its format.
const EXAMPLES: &[(&str, &str)] = &[
    (
        "journeys.v1.schema.json",
        "products/breg/acceptance/asset-site-placement/tests/journeys.yaml",
    ),
    (
        "schema-test-credentials.v1.schema.json",
        "products/breg/examples/formats/credentials.yaml",
    ),
    (
        "model-selection.v1alpha1.schema.json",
        "crates/registry-linkml/publicschema/starters/household.yaml",
    ),
    (
        "example-scenarios.v1alpha1.schema.json",
        "products/breg/starters/seed-lots/core/examples/scenarios.json",
    ),
    (
        "backup-binding.v1alpha1.schema.json",
        "products/breg/examples/formats/retire-legacy-field-binding.json",
    ),
];

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate lives two levels below the repository root")
}

fn compile(document: &str) -> JSONSchema {
    let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&value)
        .expect("a generated schema compiles as 2020-12")
}

fn example(path: &str) -> Value {
    let text = std::fs::read_to_string(repository_root().join(path))
        .expect("the committed example is readable");
    // A JSON document is also YAML, so one parser reads every example.
    serde_norway::from_str(&text).expect("the committed example parses")
}

#[test]
fn every_committed_example_satisfies_its_generated_schema() {
    let documents = documents().expect("the tool schemas generate");
    assert_eq!(documents.len(), EXAMPLES.len());
    for (file, path) in EXAMPLES {
        let schema = compile(&documents[*file]);
        let instance = example(path);
        let problems = match schema.validate(&instance) {
            Ok(()) => Vec::new(),
            Err(errors) => errors
                .map(|error| format!("{} at {}", error, error.instance_path))
                .collect(),
        };
        assert!(problems.is_empty(), "{path} under {file}: {problems:?}");
    }
}

/// Every committed file under `root` named `name`, outside hidden
/// directories.
fn committed(root: &str, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![repository_root().join(root)];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("the directory is readable") {
            let path = entry.expect("the directory entry is readable").path();
            let hidden = path
                .file_name()
                .and_then(|file| file.to_str())
                .is_some_and(|file| file.starts_with('.'));
            if hidden {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().and_then(|file| file.to_str()) == Some(name) {
                let relative = path
                    .strip_prefix(repository_root())
                    .expect("the walk stays under the repository root");
                found.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    found.sort();
    found
}

/// Committed journeys files `bregctl test` refuses, which the schema refuses
/// as well: the record conformance project carries an empty suite, and a
/// suite holds 1 to 128 journeys.
const REFUSED: &[&str] =
    &["products/breg/acceptance/registry-record-conformance/tests/journeys.yaml"];

/// An editor mapped to a generated schema must not mark a file the reader
/// accepts, so every committed journeys file and example catalogue passes,
/// apart from the files the reader refuses.
#[test]
fn every_committed_journeys_file_and_example_catalogue_satisfies_its_schema() {
    let documents = documents().expect("the tool schemas generate");
    for (file, root, name, least) in [
        (
            "journeys.v1.schema.json",
            "products/breg",
            "journeys.yaml",
            20,
        ),
        (
            "example-scenarios.v1alpha1.schema.json",
            "products/breg",
            "scenarios.json",
            4,
        ),
    ] {
        let schema = compile(&documents[file]);
        let paths = committed(root, name);
        assert!(paths.len() >= least, "{name}: found {}", paths.len());
        for path in paths {
            let instance = example(&path);
            if REFUSED.contains(&path.as_str()) {
                assert!(!schema.is_valid(&instance), "{path} was accepted");
                continue;
            }
            let problems: Vec<String> = match schema.validate(&instance) {
                Ok(()) => Vec::new(),
                Err(errors) => errors
                    .map(|error| format!("{} at {}", error, error.instance_path))
                    .collect(),
            };
            assert!(problems.is_empty(), "{path} under {file}: {problems:?}");
        }
    }
}

#[test]
fn a_wrong_header_a_missing_header_and_an_explicit_null_are_refused() {
    let documents = documents().expect("the tool schemas generate");
    let schema = compile(&documents["backup-binding.v1alpha1.schema.json"]);
    let valid = example("products/breg/examples/formats/retire-legacy-field-binding.json");
    assert!(schema.is_valid(&valid));
    for (member, value) in [
        (
            "apiVersion",
            Value::from("id.registrystack.org/formats/breg/backup-binding/v1"),
        ),
        ("kind", Value::from("BRegJourneys")),
        ("createdAt", Value::Null),
    ] {
        let mut changed = valid.clone();
        changed[member] = value;
        assert!(!schema.is_valid(&changed), "{member} was accepted");
    }
    let mut headerless = valid.clone();
    headerless
        .as_object_mut()
        .expect("the example is a mapping")
        .remove("kind");
    assert!(!schema.is_valid(&headerless));
}

#[test]
fn each_identifier_names_the_format_and_its_version() {
    for (file, document) in documents().expect("the tool schemas generate") {
        let value: Value = serde_json::from_str(&document).expect("a generated schema is JSON");
        let format = file.split('.').next().expect("a file name has a stem");
        assert_eq!(
            value["$id"],
            format!("https://id.registrystack.org/schemas/breg/{format}/{file}")
        );
        assert_eq!(
            value["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}
