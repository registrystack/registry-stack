#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0
//! The generated tool schemas accept each format's committed example and
//! refuse the shapes the reader refuses.

use std::path::Path;

use jsonschema::{Draft, JSONSchema};
use registry_breg::migration_plan::read_migration_descriptor;
use registry_bregctl::tool_schema::documents;
use serde_json::{json, Value};

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
        "dev-clients.v1alpha1.schema.json",
        "products/breg/acceptance/facility/dev-clients.yaml",
    ),
    (
        "example-scenarios.v1alpha1.schema.json",
        "products/breg/starters/seed-lots/core/examples/scenarios.json",
    ),
    (
        "backup-binding.v1alpha1.schema.json",
        "products/breg/examples/formats/retire-legacy-field-binding.json",
    ),
    ("migration-descriptor.v1alpha1.schema.json", DESCRIPTOR),
];

const DESCRIPTOR: &str = "products/breg/examples/formats/reviewed-migrations/modules/asset-site-placement-core/migrations/read-maintenance-note/descriptor.json";

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

/// An editor mapped to a generated schema must not mark a file the reader
/// accepts, so every committed journeys file and example catalogue passes.
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
            "dev-clients.v1alpha1.schema.json",
            "products/breg",
            "dev-clients.yaml",
            5,
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

/// A suite holds at least one journey: the reader refuses an empty one, so
/// the schema refuses it as well.
#[test]
fn the_journeys_schema_refuses_an_empty_suite() {
    let documents = documents().expect("the tool schemas generate");
    let schema = compile(&documents["journeys.v1.schema.json"]);
    let mut suite = example("products/breg/acceptance/asset-site-placement/tests/journeys.yaml");
    assert!(schema.is_valid(&suite));
    suite["journeys"] = Value::Array(Vec::new());
    assert!(!schema.is_valid(&suite), "an empty suite was accepted");
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

/// The identifiers the catalog records, in file-name order.
const IDENTIFIERS: [&str; 7] = [
    "https://id.registrystack.org/schemas/breg/backup-binding/backup-binding.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/breg/dev-clients/dev-clients.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/breg/example-scenarios/example-scenarios.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/breg/journeys/journeys.v1.schema.json",
    "https://id.registrystack.org/schemas/breg/migration-descriptor/migration-descriptor.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/breg/model-selection/model-selection.v1alpha1.schema.json",
    "https://id.registrystack.org/schemas/breg/schema-test-credentials/schema-test-credentials.v1.schema.json",
];

#[test]
fn each_identifier_names_the_format_and_its_version() {
    let documents = documents().expect("the tool schemas generate");
    assert_eq!(documents.len(), IDENTIFIERS.len());
    for ((file, document), identifier) in documents.iter().zip(IDENTIFIERS) {
        let value: Value = serde_json::from_str(document).expect("a generated schema is JSON");
        let format = file.split('.').next().expect("a file name has a stem");
        assert!(identifier.ends_with(&format!("/{format}/{file}")));
        assert_eq!(value["$id"], identifier);
        assert_eq!(
            value["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
}

#[test]
fn the_dev_clients_schema_refuses_an_unknown_member_and_a_retired_key() {
    let documents = documents().expect("the tool schemas generate");
    let schema = compile(&documents["dev-clients.v1alpha1.schema.json"]);
    let valid = example("products/breg/acceptance/facility/dev-clients.yaml");
    assert!(schema.is_valid(&valid));
    for (member, value) in [
        ("unknownMember", Value::from(true)),
        ("version", Value::from(1)),
    ] {
        let mut changed = valid.clone();
        changed[member] = value;
        assert!(!schema.is_valid(&changed), "{member} was accepted");
    }
}

/// A descriptor that uses every member the format has, so each enumerated
/// word has a position to be read at.
fn full_descriptor() -> Value {
    let object = json!({
        "schema": "registry_data",
        "table": "asset",
        "entity": "asset",
        "kind": "field",
        "member": "batch",
        "physicalName": "batch",
    });
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/migration-descriptor/v1alpha1",
        "kind": "BRegMigrationDescriptor",
        "id": "seal-batch",
        "changeClass": "destructive-or-irreversible",
        "covers": [{
            "code": "field-encryption-changed",
            "target": {"kind": "field", "entityId": "asset", "memberId": "batch"},
        }],
        "recovery": "exact-target-resume",
        "lockTimeoutMilliseconds": 1000,
        "statementTimeoutMilliseconds": 60000,
        "steps": [
            {
                "type": "transactional-sql",
                "id": "prepare",
                "sqlPath": "modules/core/migrations/seal-batch/steps/prepare.sql",
                "objects": [object],
                "affectedRows": {"minimum": 0, "maximum": 10},
            },
            {
                "type": "chunked-backfill",
                "id": "backfill",
                "entity": "asset",
                "sqlPath": "modules/core/migrations/seal-batch/steps/backfill.sql",
                "objects": [object],
                "cursor": "record-id-uuid-array",
                "chunkSize": 100,
                "maximumTotalRows": 1000,
                "lockTimeoutMilliseconds": 1000,
                "statementTimeoutMilliseconds": 10000,
                "exactAffectedRows": true,
            },
            {
                "type": "field-encryption-backfill",
                "id": "seal",
                "entity": "asset",
                "objects": [object],
                "cursor": "record-id-uuid-array",
                "chunkSize": 100,
                "maximumTotalRows": 1000,
                "lockTimeoutMilliseconds": 1000,
                "statementTimeoutMilliseconds": 10000,
            },
        ],
        "preAssertions": [
            {"id": "pre", "sqlPath": "modules/core/migrations/seal-batch/assertions/pre.sql"},
        ],
        "postAssertions": [
            {"id": "post", "sqlPath": "modules/core/migrations/seal-batch/assertions/post.sql"},
        ],
        "rehearsalReceiptPath": "modules/core/migrations/seal-batch/rehearsal.json",
        "backupBindingPath": "modules/core/migrations/seal-batch/binding.json",
        "history": "erase-and-rebaseline",
    })
}

/// Where a full descriptor writes each word list the schema defines. A step's
/// `type` is the one list written inline, so it has its own row.
const DESCRIPTOR_WORD_LISTS: &[(&str, &str)] = &[
    ("ReviewedMigrationChangeClass", "/changeClass"),
    ("CompiledRegistryChangeCode", "/covers/0/code"),
    ("CompiledRegistryChangeTargetKind", "/covers/0/target/kind"),
    ("ReviewedMigrationRecovery", "/recovery"),
    ("ReviewedFieldEncryptionHistory", "/history"),
    ("ReviewedMigrationObjectKind", "/steps/0/objects/0/kind"),
    ("ChunkCursorProtocol", "/steps/1/cursor"),
];

/// Every word `schema` enumerates directly: an `enum` list, or the `const`
/// alternatives of a `oneOf` that documents each word.
fn enumerated_words(schema: &Value) -> Vec<String> {
    let mut words = Vec::new();
    for word in schema["enum"].as_array().into_iter().flatten() {
        words.push(word.as_str().expect("a word is text").to_owned());
    }
    for alternative in schema["oneOf"].as_array().into_iter().flatten() {
        if let Some(word) = alternative["const"].as_str() {
            words.push(word.to_owned());
        }
        words.extend(enumerated_words(alternative));
    }
    words
}

fn is_kebab_case(word: &str) -> bool {
    !word.is_empty()
        && word.starts_with(|first: char| first.is_ascii_lowercase())
        && word.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        })
}

fn read_descriptor(descriptor: &Value) -> Result<(), Vec<(String, String)>> {
    let bytes = serde_json::to_vec(descriptor).expect("a descriptor serializes");
    read_migration_descriptor("descriptor.json", &bytes)
        .map(|_| ())
        .map_err(|report| {
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
                .collect()
        })
}

/// The schema and the reader hold one vocabulary: every word the schema
/// lists is kebab-case (CFG-NAME-2) and is read where the format writes it,
/// and every word list the schema defines is covered here.
#[test]
fn the_reader_accepts_every_word_the_migration_descriptor_schema_enumerates() {
    let documents = documents().expect("the tool schemas generate");
    let document: Value =
        serde_json::from_str(&documents["migration-descriptor.v1alpha1.schema.json"])
            .expect("a generated schema is JSON");
    let schema = compile(&documents["migration-descriptor.v1alpha1.schema.json"]);
    let full = full_descriptor();
    assert!(schema.is_valid(&full), "the full descriptor is refused");
    assert_eq!(read_descriptor(&full), Ok(()));

    let definitions = document["$defs"]
        .as_object()
        .expect("the schema names its definitions");
    let listed: Vec<&str> = definitions
        .iter()
        .filter(|(name, definition)| {
            *name != "ReviewedMigrationStepDescriptor" && !enumerated_words(definition).is_empty()
        })
        .map(|(name, _)| name.as_str())
        .collect();
    let mut covered: Vec<&str> = DESCRIPTOR_WORD_LISTS
        .iter()
        .map(|(name, _)| *name)
        .collect();
    covered.sort_unstable();
    assert_eq!(listed, covered, "a word list has no position in this test");

    let mut checked = 0;
    for (name, pointer) in DESCRIPTOR_WORD_LISTS {
        let words = enumerated_words(&definitions[*name]);
        for word in words {
            assert!(
                is_kebab_case(&word),
                "{name} lists a word that is not kebab-case"
            );
            let mut changed = full.clone();
            *changed.pointer_mut(pointer).expect("the member is written") =
                Value::from(word.as_str());
            assert!(schema.is_valid(&changed), "{pointer}: {word}");
            assert_eq!(read_descriptor(&changed), Ok(()), "{pointer}: {word}");
            checked += 1;
        }
    }
    // 3 change classes, 63 change codes, 14 target kinds, 1 recovery,
    // 2 history choices, 4 object kinds, and 1 cursor protocol.
    assert_eq!(checked, 88);

    let steps = &definitions["ReviewedMigrationStepDescriptor"]["oneOf"];
    let types: Vec<&str> = steps
        .as_array()
        .expect("a step is one of its forms")
        .iter()
        .map(|form| {
            form["properties"]["type"]["const"]
                .as_str()
                .expect("a form names its type")
        })
        .collect();
    assert_eq!(
        types,
        [
            "transactional-sql",
            "chunked-backfill",
            "field-encryption-backfill"
        ]
    );
}

/// Additive changes need no reviewed descriptor, and unsupported changes
/// cannot be made executable by describing them as reviewed migration work.
#[test]
fn reviewed_migration_schema_refuses_classes_the_checker_refuses() {
    use registry_breg::migration_plan::{check_migration_descriptor, MIGRATION_DESCRIPTOR_FORMAT};
    use registry_platform_yaml::{Expect, Reader};

    let documents = documents().expect("the tool schemas generate");
    let schema = compile(&documents["migration-descriptor.v1alpha1.schema.json"]);
    for (class, accepted) in [
        ("compatible-additive", false),
        ("data-backfill-required", true),
        ("access-or-disclosure-change", true),
        ("destructive-or-irreversible", true),
        ("unsupported", false),
    ] {
        let mut descriptor = example(DESCRIPTOR);
        descriptor["changeClass"] = Value::from(class);
        let bytes = serde_json::to_vec(&descriptor).expect("descriptor serializes");
        let document = Reader::new("descriptor.json")
            .read(&bytes, &Expect::one(&MIGRATION_DESCRIPTOR_FORMAT))
            .expect("the descriptor has the current envelope");
        let findings =
            check_migration_descriptor(&document, None).expect("the checker reads the descriptor");
        let class_refused = findings.iter().any(|diagnostic| {
            diagnostic.code == "breg.migration.change-class" && diagnostic.path == "/changeClass"
        });
        assert_eq!(class_refused, !accepted, "checker class: {class}");
        assert_eq!(
            schema.is_valid(&descriptor),
            accepted,
            "schema class: {class}"
        );
    }
}

/// The schema refuses what the reader refuses, at the same member: an
/// unknown member, a removed key, and each enumerated word in snake_case.
#[test]
fn the_migration_descriptor_schema_and_reader_refuse_the_same_shapes() {
    let documents = documents().expect("the tool schemas generate");
    let schema = compile(&documents["migration-descriptor.v1alpha1.schema.json"]);
    let valid = example(DESCRIPTOR);
    assert!(schema.is_valid(&valid));
    assert_eq!(read_descriptor(&valid), Ok(()));

    for (pointer, value, code) in [
        (
            "/changeClass",
            "access_or_disclosure_change",
            "config.unknown-variant",
        ),
        (
            "/covers/0/code",
            "access_profile_changed",
            "config.unknown-variant",
        ),
        (
            "/covers/0/target/kind",
            "access_profile",
            "config.unknown-variant",
        ),
        ("/recovery", "exact_target_resume", "config.unknown-variant"),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).expect("the member is written") = Value::from(value);
        assert!(!schema.is_valid(&changed), "{pointer} was accepted");
        assert_eq!(
            read_descriptor(&changed),
            Err(vec![(code.to_owned(), pointer.to_owned())])
        );
    }

    for (parent, member, value, code) in [
        ("", "unknownMember", Value::from(true), "config.unknown-key"),
        (
            "/covers/0",
            "unknownMember",
            Value::from(true),
            "config.unknown-key",
        ),
        (
            "/covers/0/target",
            "unknownMember",
            Value::from(true),
            "config.unknown-key",
        ),
        ("", "lockTimeoutMs", Value::from(1000), "config.removed-key"),
        ("", "history", Value::Null, "config.null-value"),
    ] {
        let mut changed = valid.clone();
        changed.pointer_mut(parent).expect("the mapping is written")[member] = value;
        assert!(!schema.is_valid(&changed), "{parent}/{member} was accepted");
        assert_eq!(
            read_descriptor(&changed),
            Err(vec![(code.to_owned(), format!("{parent}/{member}"))])
        );
    }
}
