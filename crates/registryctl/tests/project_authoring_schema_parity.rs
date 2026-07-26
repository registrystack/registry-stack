// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use registryctl::ProjectSchemaKind;
use registryctl::{
    check_registry_project_with_context, ProjectAuthoringDiagnostics, ProjectCheckOptions,
    ProjectExecutionContext,
};
use serde::Deserialize;
use serde_json::Value;

#[path = "../src/project_authoring/knowledge.rs"]
mod field_knowledge;

use field_knowledge::{
    index_published_field_knowledge, published_field_knowledge_index,
    reachable_published_field_paths, FieldKnowledgeCatalog, FieldPathKind, PublishedSchema,
    SchemaKind, SemanticRule, Sensitivity,
};

const COVERAGE_FILE: &str = "schemas/project-authoring/parity-coverage.json";
const KNOWN_EVIDENCE: [&str; 3] = [
    "schemas_compile_and_all_catalog_documents_pass_schema_and_runtime",
    "closed_object_policy_has_only_named_map_exceptions",
    "representative_mutations_fail_schema_and_runtime",
];
const SCHEMA_METADATA_KEYWORDS: [&str; 11] = [
    "$comment",
    "$id",
    "$schema",
    "default",
    "deprecated",
    "description",
    "examples",
    "readOnly",
    "title",
    "writeOnly",
    "x-registry-field",
];

fn check_registry_project(
    options: &ProjectCheckOptions,
) -> anyhow::Result<registryctl::ProjectCommandReport> {
    let context = ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides the real registryctl executable");
    check_registry_project_with_context(options, &context)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityCoverage {
    version: u8,
    schemas: Vec<SchemaEntry>,
    field_knowledge: FieldKnowledgeCatalog,
    rule_coverage: Vec<RuleCoverage>,
    open_object_exceptions: Vec<OpenObjectException>,
    parity_cases: Vec<ParityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaEntry {
    kind: String,
    file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleCoverage {
    keywords: Vec<String>,
    evidence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenObjectException {
    schema: String,
    pointer: String,
    kind: OpenObjectKind,
    rationale: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OpenObjectKind {
    TypedMap,
    ExtensionMap,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParityCase {
    id: String,
    dimension: String,
    schema: String,
    source: String,
    document: String,
    mutation: Mutation,
    #[serde(default)]
    expected_error_code: Option<String>,
    #[serde(default)]
    expected_remediation: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    operation: MutationOperation,
    pointer: String,
    #[serde(default)]
    value: Option<Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationOperation {
    Set,
    Remove,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyCatalog {
    version: u8,
    workspaces: Vec<Journey>,
}

#[derive(Debug, Deserialize)]
struct Journey {
    id: String,
    source: String,
    environment: String,
    #[serde(flatten)]
    metadata: BTreeMap<String, serde_norway::Value>,
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repository_root() -> PathBuf {
    crate_root().join("../..")
}

fn schema_root() -> PathBuf {
    crate_root().join("schemas/project-authoring")
}

fn coverage() -> ParityCoverage {
    serde_json::from_slice(
        &std::fs::read(crate_root().join(COVERAGE_FILE)).expect("parity coverage asset reads"),
    )
    .expect("parity coverage asset parses")
}

fn compile_schema(file: &str) -> (Value, jsonschema::JSONSchema) {
    let document: Value = serde_json::from_slice(
        &std::fs::read(schema_root().join(file))
            .unwrap_or_else(|error| panic!("{file} reads: {error}")),
    )
    .unwrap_or_else(|error| panic!("{file} parses: {error}"));
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&document)
        .unwrap_or_else(|error| panic!("{file} compiles as draft 2020-12: {error}"));
    (document, compiled)
}

fn field_schema_kind(kind: &str) -> SchemaKind {
    match kind {
        "project" => SchemaKind::Project,
        "environment" => SchemaKind::Environment,
        "integration" => SchemaKind::Integration,
        "fixture" => SchemaKind::Fixture,
        "entity" => SchemaKind::Entity,
        other => panic!("unknown published field-knowledge schema: {other}"),
    }
}

fn knowledge_documents(coverage: &ParityCoverage) -> Vec<(SchemaKind, Value)> {
    coverage
        .schemas
        .iter()
        .map(|schema| {
            (
                field_schema_kind(&schema.kind),
                compile_schema(&schema.file).0,
            )
        })
        .collect()
}

fn published_schemas(documents: &[(SchemaKind, Value)]) -> Vec<PublishedSchema<'_>> {
    documents
        .iter()
        .map(|(kind, document)| PublishedSchema {
            kind: *kind,
            document,
        })
        .collect()
}

fn read_yaml_json(path: &Path) -> Value {
    let yaml: serde_norway::Value = serde_norway::from_slice(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{} reads: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{} parses: {error}", path.display()));
    serde_json::to_value(yaml)
        .unwrap_or_else(|error| panic!("{} converts to JSON: {error}", path.display()))
}

fn validate_document(schema: &jsonschema::JSONSchema, path: &Path) {
    let document = read_yaml_json(path);
    if let Err(errors) = schema.validate(&document) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("schema rejected {}: {messages:?}", path.display());
    };
}

fn sorted_yaml_files(directory: &Path) -> Vec<PathBuf> {
    if !directory.is_dir() {
        return Vec::new();
    }
    let mut paths = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} reads: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry reads").path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn referenced_files(project: &Value, field: &str) -> BTreeSet<PathBuf> {
    project
        .get(field)
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|references| references.values())
        .map(|reference| {
            PathBuf::from(
                reference["file"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{field} reference file is a string")),
            )
        })
        .collect()
}

#[test]
fn published_field_knowledge_is_complete_typed_reachable_and_editor_exact() {
    let coverage = coverage();
    let documents = knowledge_documents(&coverage);
    let schemas = published_schemas(&documents);
    let index = index_published_field_knowledge(&coverage.field_knowledge, &schemas)
        .expect("all published field knowledge is typed, complete, and internally resolvable");

    assert_eq!(
        index.coverage_by_schema(),
        [
            (SchemaKind::Project, 160),
            (SchemaKind::Environment, 191),
            (SchemaKind::Integration, 138),
            (SchemaKind::Fixture, 40),
            (SchemaKind::Entity, 35),
        ]
        .into_iter()
        .collect(),
        "all five roots, including entity, retain an exact reviewed path count"
    );
    assert_eq!(
        index.coverage_by_path_kind(),
        [
            (FieldPathKind::Root, 5),
            (FieldPathKind::Property, 388),
            (FieldPathKind::MapKey, 23),
            (FieldPathKind::MapValue, 29),
            (FieldPathKind::ArrayItem, 27),
            (FieldPathKind::Branch, 92),
        ]
        .into_iter()
        .collect(),
        "properties, arbitrary map keys/values, array items, and branch-only nodes are explicit"
    );
    assert_eq!(
        index.coverage_by_sensitivity(),
        [
            (Sensitivity::Public, 6),
            (Sensitivity::Internal, 353),
            (Sensitivity::Sensitive, 64),
            (Sensitivity::SecretReference, 14),
            (Sensitivity::RedactedFixture, 30),
            (Sensitivity::Structural, 97),
        ]
        .into_iter()
        .collect(),
        "reportability classifications remain exact and conservative"
    );
    assert_eq!(
        index.by_path().len(),
        564,
        "the field-knowledge gate covers every published schema path"
    );
    assert_eq!(
        index.references().len(),
        201,
        "every published local reference remains resolved in the deterministic reference index"
    );
    assert_eq!(
        published_field_knowledge_index()
            .expect("embedded producer field-knowledge source is valid")
            .by_path(),
        index.by_path(),
        "producer and parity-gate indexes are exact"
    );

    let reachable = schemas
        .iter()
        .map(reachable_published_field_paths)
        .collect::<Result<Vec<_>, _>>()
        .expect("all local references resolve safely")
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        index.by_path().keys().cloned().collect::<BTreeSet<_>>(),
        reachable,
        "every annotation is reachable and every reachable published leaf or structural path is annotated"
    );

    assert!(index.by_path().values().all(|knowledge| {
        knowledge
            .semantic_rules
            .contains(&SemanticRule::KnowledgeOnly)
            && knowledge
                .semantic_rules
                .contains(&SemanticRule::GeneratedDocsNeverLoadCountryValues)
    }));
    assert!(index.by_path().values().all(|knowledge| {
        !matches!(
            knowledge.sensitivity,
            Sensitivity::SecretReference
                | Sensitivity::SecretValue
                | Sensitivity::RedactedFixture
                | Sensitivity::Sensitive
        ) || !knowledge.sensitivity.value_is_reportable(false)
    }));
    assert_eq!(
        index.coverage_by_sensitivity()[&Sensitivity::SecretReference],
        14,
        "secret-reference values and names remain explicitly never-reportable"
    );
    assert_eq!(
        index.coverage_by_sensitivity()[&Sensitivity::RedactedFixture],
        30,
        "fixture request, response, input, body, and expected values remain redacted"
    );
    walk_schema(
        &documents
            .iter()
            .find(|(kind, _)| *kind == SchemaKind::Environment)
            .expect("environment schema is published")
            .1,
        "",
        &mut |node, pointer| {
            if node.get("$ref").and_then(Value::as_str) == Some("#/$defs/secret") {
                assert_eq!(
                    node.get("x-registry-field").and_then(Value::as_str),
                    Some("secret_reference_property"),
                    "environment#{pointer} carries a secret-reference name and must never be reportable"
                );
            }
        },
    );
    for pointer in [
        "/properties/relay/properties/origin",
        "/properties/relay/properties/jwks_url",
        "/$defs/oid4vci/properties/authorization_server/properties/token_url",
        "/$defs/oid4vci/properties/client/properties/id",
        "/$defs/privateCidrs/items",
        "/$defs/oid4vci/properties/access_token/properties/signing_kid",
        "/$defs/credential/oneOf/3/properties/generation",
        "/properties/notary_state/properties/postgresql/properties/root_certificate_path",
    ] {
        assert!(
            matches!(
                index.by_path()[&field_knowledge::FieldPath {
                    schema: SchemaKind::Environment,
                    pointer: pointer.to_string(),
                }]
                    .sensitivity,
                Sensitivity::Sensitive
            ),
            "environment#{pointer} must retain conservative operational sensitivity"
        );
    }

    for (entry, kind) in coverage.schemas.iter().zip([
        ProjectSchemaKind::Project,
        ProjectSchemaKind::Environment,
        ProjectSchemaKind::Integration,
        ProjectSchemaKind::Fixture,
        ProjectSchemaKind::Entity,
    ]) {
        assert_eq!(entry.file, kind.filename());
        assert_eq!(
            std::fs::read(schema_root().join(&entry.file)).expect("published schema reads"),
            kind.document().as_bytes(),
            "{} editor-emitted schema must be byte-exact with the field-knowledge source",
            entry.kind
        );
    }
}

#[test]
fn field_knowledge_gate_rejects_missing_malformed_unknown_duplicate_and_unresolved_paths() {
    let coverage = coverage();

    let assert_rejected = |documents: &[(SchemaKind, Value)], expected: &str| {
        let error = index_published_field_knowledge(
            &coverage.field_knowledge,
            &published_schemas(documents),
        )
        .expect_err("field-knowledge corruption must fail closed");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in {error}"
        );
    };

    let mut missing = knowledge_documents(&coverage);
    missing[0]
        .1
        .as_object_mut()
        .expect("project schema is an object")
        .remove("x-registry-field");
    assert_rejected(&missing, "without x-registry-field");

    let mut malformed = knowledge_documents(&coverage);
    malformed[0].1["x-registry-field"] = serde_json::json!({ "profile": "root" });
    assert_rejected(&malformed, "must be a classification string");

    let mut unknown = knowledge_documents(&coverage);
    unknown[0].1["x-registry-field"] = Value::String("unreviewed".to_string());
    assert_rejected(&unknown, "unknown field classification");

    let mut unresolved = knowledge_documents(&coverage);
    unresolved[0].1["properties"]["starter"]["$ref"] =
        Value::String("#/$defs/doesNotExist".to_string());
    assert_rejected(&unresolved, "unresolved local $ref");

    let documents = knowledge_documents(&coverage);
    let mut duplicated = published_schemas(&documents);
    duplicated.push(PublishedSchema {
        kind: SchemaKind::Project,
        document: &documents[0].1,
    });
    let error = index_published_field_knowledge(&coverage.field_knowledge, &duplicated)
        .expect_err("duplicate schema root is a duplicate field path");
    assert!(error
        .to_string()
        .contains("duplicate published schema kind"));
}

#[test]
fn schemas_compile_and_all_catalog_documents_pass_schema_and_runtime() {
    let coverage = coverage();
    assert_eq!(coverage.version, 1);
    assert_eq!(
        coverage
            .schemas
            .iter()
            .map(|entry| (entry.kind.as_str(), entry.file.as_str()))
            .collect::<Vec<_>>(),
        [
            ("project", "project.schema.json"),
            ("environment", "environment.schema.json"),
            ("integration", "integration.schema.json"),
            ("fixture", "fixture.schema.json"),
            ("entity", "entity.schema.json"),
        ],
        "the parity gate must enumerate the exact published five-schema catalog"
    );
    let compiled = coverage
        .schemas
        .iter()
        .map(|entry| (entry.kind.as_str(), compile_schema(&entry.file).1))
        .collect::<BTreeMap<_, _>>();

    let catalog: JourneyCatalog = serde_norway::from_slice(
        &std::fs::read(crate_root().join("tests/fixtures/project-authoring-journeys.yaml"))
            .expect("journey catalog reads"),
    )
    .expect("journey catalog parses");
    assert_eq!(catalog.version, 1);
    assert!(!catalog.workspaces.is_empty());

    for journey in catalog.workspaces {
        assert!(
            !journey.metadata.is_empty(),
            "{} retains its maintained journey metadata",
            journey.id
        );
        let root = repository_root().join(&journey.source);
        let project_path = root.join("registry-stack.yaml");
        validate_document(&compiled["project"], &project_path);
        let project = read_yaml_json(&project_path);

        let entity_references = referenced_files(&project, "entities");
        let authored_entities = sorted_yaml_files(&root.join("entities"))
            .into_iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .expect("entity is below project root")
                    .to_path_buf()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            entity_references, authored_entities,
            "{} must reference every maintained entity document exactly once",
            journey.id
        );
        for relative in entity_references {
            validate_document(&compiled["entity"], &root.join(relative));
        }

        let integration_references = referenced_files(&project, "integrations");
        let authored_integrations = if root.join("integrations").is_dir() {
            let mut paths = std::fs::read_dir(root.join("integrations"))
                .expect("integrations directory reads")
                .map(|entry| {
                    entry
                        .expect("integration directory entry reads")
                        .path()
                        .join("integration.yaml")
                })
                .filter(|path| path.is_file())
                .map(|path| {
                    path.strip_prefix(&root)
                        .expect("integration is below project root")
                        .to_path_buf()
                })
                .collect::<Vec<_>>();
            paths.sort();
            paths.into_iter().collect()
        } else {
            BTreeSet::new()
        };
        assert_eq!(
            integration_references, authored_integrations,
            "{} must reference every maintained integration document exactly once",
            journey.id
        );
        for relative in integration_references {
            let integration_path = root.join(&relative);
            validate_document(&compiled["integration"], &integration_path);
            for fixture in sorted_yaml_files(
                integration_path
                    .parent()
                    .expect("integration has a parent")
                    .join("fixtures")
                    .as_path(),
            ) {
                validate_document(&compiled["fixture"], &fixture);
            }
        }

        let environments = sorted_yaml_files(&root.join("environments"));
        assert!(
            !environments.is_empty(),
            "{} has at least one maintained environment",
            journey.id
        );
        for environment_path in environments {
            validate_document(&compiled["environment"], &environment_path);
            let environment = environment_path
                .file_stem()
                .and_then(|name| name.to_str())
                .expect("environment filename is Unicode");
            let report = check_registry_project(&ProjectCheckOptions {
                project_directory: root.clone(),
                environment: environment.to_string(),
                explain: false,
                against: None,
                anchor: None,
            })
            .unwrap_or_else(|error| {
                panic!(
                    "{} failed the production check path for {environment}: {error:#}",
                    journey.id
                )
            });
            assert_eq!(report.status, "valid", "{} production check", journey.id);
        }
        assert!(
            sorted_yaml_files(&root.join("environments"))
                .iter()
                .any(|path| {
                    path.file_stem().and_then(|name| name.to_str())
                        == Some(journey.environment.as_str())
                }),
            "{} catalog environment is maintained",
            journey.id
        );
    }
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn walk_schema(schema: &Value, pointer: &str, visit: &mut impl FnMut(&Value, &str)) {
    visit(schema, pointer);
    let Some(object) = schema.as_object() else {
        return;
    };
    for container in ["$defs", "properties", "dependentSchemas"] {
        if let Some(children) = object.get(container).and_then(Value::as_object) {
            for (name, child) in children {
                walk_schema(
                    child,
                    &format!("{pointer}/{container}/{}", escape_pointer_segment(name)),
                    visit,
                );
            }
        }
    }
    for keyword in [
        "additionalProperties",
        "contains",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
    ] {
        if object.get(keyword).is_some_and(Value::is_object) {
            walk_schema(&object[keyword], &format!("{pointer}/{keyword}"), visit);
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                walk_schema(child, &format!("{pointer}/{keyword}/{index}"), visit);
            }
        }
    }
}

fn is_object_schema(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(kind)) => kind == "object",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some("object")),
        _ => false,
    }
}

#[test]
fn closed_object_policy_has_only_named_map_exceptions() {
    let coverage = coverage();
    let schema_files = coverage
        .schemas
        .iter()
        .map(|schema| (schema.kind.as_str(), schema.file.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeMap::new();
    for exception in &coverage.open_object_exceptions {
        assert!(
            schema_files.contains_key(exception.schema.as_str()),
            "unknown schema in open-object exception: {}",
            exception.schema
        );
        assert!(
            exception.pointer.starts_with('/'),
            "exception pointer must be absolute: {}",
            exception.pointer
        );
        assert!(
            exception.rationale.len() >= 32,
            "{} {} needs a concrete rationale",
            exception.schema,
            exception.pointer
        );
        assert!(
            expected
                .insert(
                    (exception.schema.as_str(), exception.pointer.as_str()),
                    exception.kind,
                )
                .is_none(),
            "duplicate open-object exception: {} {}",
            exception.schema,
            exception.pointer
        );
    }

    let mut actual = BTreeMap::new();
    let metadata_keywords = SCHEMA_METADATA_KEYWORDS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut encountered_keywords = BTreeSet::new();
    for schema in &coverage.schemas {
        let (document, _) = compile_schema(&schema.file);
        walk_schema(&document, "", &mut |node, pointer| {
            let Some(object) = node.as_object() else {
                return;
            };
            encountered_keywords.extend(
                object
                    .keys()
                    .filter(|keyword| !metadata_keywords.contains(keyword.as_str()))
                    .cloned(),
            );
            if !is_object_schema(node)
                || object.get("additionalProperties") == Some(&Value::Bool(false))
            {
                return;
            }
            let kind = match object.get("additionalProperties") {
                Some(Value::Object(_)) => OpenObjectKind::TypedMap,
                None | Some(Value::Bool(true)) => OpenObjectKind::ExtensionMap,
                other => panic!(
                    "{}{pointer} has unsupported additionalProperties form {other:?}",
                    schema.kind
                ),
            };
            assert!(
                actual
                    .insert((schema.kind.as_str(), pointer.to_string()), kind)
                    .is_none(),
                "duplicate schema node {}{pointer}",
                schema.kind
            );
        });
    }

    let expected_owned = expected
        .into_iter()
        .map(|((schema, pointer), kind)| ((schema, pointer.to_string()), kind))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual, expected_owned,
        "every object schema must be closed or have one exact named map/extension exception"
    );

    let mut covered_keywords = BTreeMap::new();
    for rule in &coverage.rule_coverage {
        assert!(
            KNOWN_EVIDENCE.contains(&rule.evidence.as_str()),
            "unknown rule evidence: {}",
            rule.evidence
        );
        assert!(!rule.keywords.is_empty(), "rule evidence cannot be empty");
        for keyword in &rule.keywords {
            assert!(
                covered_keywords
                    .insert(keyword.as_str(), rule.evidence.as_str())
                    .is_none(),
                "schema rule keyword is covered twice: {keyword}"
            );
        }
    }
    assert_eq!(
        encountered_keywords,
        covered_keywords
            .keys()
            .map(|keyword| (*keyword).to_string())
            .collect(),
        "adding or removing a published schema rule requires named parity evidence"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("{} creates: {error}", destination.display()));
    let mut entries = std::fs::read_dir(source)
        .unwrap_or_else(|error| panic!("{} reads: {error}", source.display()))
        .map(|entry| entry.expect("source entry reads"))
        .collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("source entry type reads").is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "{} copies to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        }
    }
}

fn decode_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn mutate(document: &mut Value, mutation: &Mutation) {
    assert!(
        mutation.pointer.starts_with('/'),
        "mutation pointer must be absolute: {}",
        mutation.pointer
    );
    let (parent_pointer, segment) = mutation
        .pointer
        .rsplit_once('/')
        .expect("absolute mutation pointer has a parent");
    let segment = decode_pointer_segment(segment);
    let parent = document
        .pointer_mut(parent_pointer)
        .unwrap_or_else(|| panic!("mutation parent exists: {parent_pointer}"));
    match mutation.operation {
        MutationOperation::Set => {
            let value = mutation
                .value
                .clone()
                .expect("set mutation supplies a value");
            match parent {
                Value::Object(object) => {
                    object.insert(segment, value);
                }
                Value::Array(array) => {
                    let index = segment.parse::<usize>().expect("array index is numeric");
                    *array.get_mut(index).expect("array mutation index exists") = value;
                }
                _ => panic!("set mutation parent is an object or array"),
            }
        }
        MutationOperation::Remove => {
            assert!(
                mutation.value.is_none(),
                "remove mutation does not supply a value"
            );
            match parent {
                Value::Object(object) => {
                    assert!(
                        object.remove(&segment).is_some(),
                        "removed field exists: {}",
                        mutation.pointer
                    );
                }
                Value::Array(array) => {
                    let index = segment.parse::<usize>().expect("array index is numeric");
                    assert!(index < array.len(), "removed array index exists");
                    array.remove(index);
                }
                _ => panic!("remove mutation parent is an object or array"),
            }
        }
    }
}

#[test]
fn representative_mutations_fail_schema_and_runtime() {
    let coverage = coverage();
    let schemas = coverage
        .schemas
        .iter()
        .map(|entry| (entry.kind.as_str(), compile_schema(&entry.file).1))
        .collect::<BTreeMap<_, _>>();
    let mut ids = BTreeSet::new();
    let mut dimensions = BTreeMap::<&str, BTreeSet<&str>>::new();

    for case in &coverage.parity_cases {
        assert!(
            ids.insert(case.id.as_str()),
            "duplicate case id: {}",
            case.id
        );
        let schema = schemas
            .get(case.schema.as_str())
            .unwrap_or_else(|| panic!("{} names a published schema", case.id));
        dimensions
            .entry(case.dimension.as_str())
            .or_default()
            .insert(case.schema.as_str());

        let temporary = tempfile::tempdir().expect("temporary directory creates");
        let project = temporary.path().join("project");
        copy_tree(&repository_root().join(&case.source), &project);
        let document_path = project.join(&case.document);
        let mut document = read_yaml_json(&document_path);
        assert!(
            schema.is_valid(&document),
            "{} starts from a schema-valid maintained document",
            case.id
        );
        mutate(&mut document, &case.mutation);
        assert!(
            !schema.is_valid(&document),
            "{} mutation must fail the published {} schema",
            case.id,
            case.schema
        );
        std::fs::write(
            &document_path,
            serde_norway::to_string(&document).expect("mutated document serializes as YAML"),
        )
        .expect("mutated document writes");

        let error = match check_registry_project(&ProjectCheckOptions {
            project_directory: project,
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        }) {
            Ok(_) => panic!(
                "{} failed its schema but was accepted by the production loader/check path",
                case.id
            ),
            Err(error) => error,
        };
        match (&case.expected_error_code, &case.expected_remediation) {
            (Some(expected_code), Some(expected_remediation)) => {
                let report = error
                    .downcast_ref::<ProjectAuthoringDiagnostics>()
                    .unwrap_or_else(|| {
                        panic!("{} returns typed authoring diagnostics: {error:#}", case.id)
                    });
                assert!(
                    report.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code == expected_code
                            && diagnostic.remediation == expected_remediation
                    }),
                    "{} must return the exact safe remediation: {report:#?}",
                    case.id
                );
            }
            (None, None) => {}
            _ => panic!(
                "{} must declare both expected_error_code and expected_remediation",
                case.id
            ),
        }
    }

    let all_schemas = ["entity", "environment", "fixture", "integration", "project"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    for dimension in ["unknown_field", "missing_required", "type", "boundary"] {
        assert_eq!(
            dimensions.get(dimension),
            Some(&all_schemas),
            "{dimension} must retain a representative mutation for every schema kind"
        );
    }
    assert_eq!(
        dimensions.get("conditional"),
        Some(
            &["environment", "fixture", "integration", "project"]
                .into_iter()
                .collect()
        ),
        "every schema with a maintained conditional union needs a representative mutation"
    );
    assert_eq!(
        dimensions.keys().copied().collect::<BTreeSet<_>>(),
        [
            "boundary",
            "conditional",
            "missing_required",
            "type",
            "unknown_field"
        ]
        .into_iter()
        .collect(),
        "new parity dimensions require an explicit gate assertion"
    );
}
