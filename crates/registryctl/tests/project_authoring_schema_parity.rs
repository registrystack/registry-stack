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
    expected_failing_keywords: Vec<String>,
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
            (SchemaKind::Project, 219),
            (SchemaKind::Environment, 198),
            (SchemaKind::Integration, 142),
            (SchemaKind::Fixture, 62),
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
            (FieldPathKind::Property, 460),
            (FieldPathKind::MapKey, 25),
            (FieldPathKind::MapValue, 32),
            (FieldPathKind::ArrayItem, 33),
            (FieldPathKind::Branch, 101),
        ]
        .into_iter()
        .collect(),
        "properties, arbitrary map keys/values, array items, and branch-only nodes are explicit"
    );
    assert_eq!(
        index.coverage_by_sensitivity(),
        [
            (Sensitivity::Public, 6),
            (Sensitivity::Internal, 413),
            (Sensitivity::Sensitive, 67),
            (Sensitivity::SecretReference, 14),
            (Sensitivity::RedactedFixture, 50),
            (Sensitivity::Structural, 106),
        ]
        .into_iter()
        .collect(),
        "reportability classifications remain exact and conservative"
    );
    assert_eq!(
        index.by_path().len(),
        656,
        "the field-knowledge gate covers every published schema path"
    );
    assert_eq!(
        index.references().len(),
        260,
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
        50,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PublishedStructuralInventory {
    nodes: usize,
    local_refs: usize,
    union_nodes: usize,
    union_branches: usize,
    conditionals: usize,
    objects: usize,
    closed_objects: usize,
    typed_maps: usize,
    open_maps: usize,
    arrays: usize,
    scalar_types: usize,
    nullable_nodes: usize,
    integer_lower_bounds: usize,
    integer_upper_bounds: usize,
    string_length_bounds: usize,
    string_patterns: usize,
    array_size_bounds: usize,
    unique_arrays: usize,
    object_size_bounds: usize,
    property_name_constraints: usize,
    enums: usize,
    consts: usize,
    defaults: usize,
    deprecations: usize,
}

fn published_structural_inventory(schema: &Value) -> PublishedStructuralInventory {
    let mut inventory = PublishedStructuralInventory::default();
    walk_schema(schema, "", &mut |node, _| {
        inventory.nodes += 1;
        let Some(object) = node.as_object() else {
            return;
        };
        inventory.local_refs += usize::from(object.contains_key("$ref"));
        for keyword in ["anyOf", "oneOf"] {
            if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
                inventory.union_nodes += 1;
                inventory.union_branches += branches.len();
            }
        }
        inventory.conditionals += usize::from(object.contains_key("if"));
        inventory.arrays += usize::from(match object.get("type") {
            Some(Value::String(kind)) => kind == "array",
            Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some("array")),
            _ => false,
        });
        let types = match object.get("type") {
            Some(Value::String(kind)) => vec![kind.as_str()],
            Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        inventory.scalar_types += types
            .iter()
            .filter(|kind| matches!(**kind, "null" | "boolean" | "integer" | "number" | "string"))
            .count();
        inventory.nullable_nodes += usize::from(types.contains(&"null"));
        if types.contains(&"integer") {
            inventory.integer_lower_bounds += usize::from(
                object.contains_key("minimum") || object.contains_key("exclusiveMinimum"),
            );
            inventory.integer_upper_bounds += usize::from(
                object.contains_key("maximum") || object.contains_key("exclusiveMaximum"),
            );
        }
        inventory.string_length_bounds +=
            usize::from(object.contains_key("minLength") || object.contains_key("maxLength"));
        inventory.string_patterns += usize::from(object.contains_key("pattern"));
        inventory.array_size_bounds +=
            usize::from(object.contains_key("minItems") || object.contains_key("maxItems"));
        inventory.unique_arrays +=
            usize::from(object.get("uniqueItems") == Some(&Value::Bool(true)));
        inventory.object_size_bounds += usize::from(
            object.contains_key("minProperties") || object.contains_key("maxProperties"),
        );
        inventory.property_name_constraints += usize::from(object.contains_key("propertyNames"));
        inventory.enums += usize::from(object.contains_key("enum"));
        inventory.consts += usize::from(object.contains_key("const"));
        inventory.defaults += usize::from(object.contains_key("default"));
        inventory.deprecations += usize::from(object.contains_key("deprecated"));
        if is_object_schema(node) {
            inventory.objects += 1;
            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => inventory.closed_objects += 1,
                Some(Value::Object(_)) => inventory.typed_maps += 1,
                None | Some(Value::Bool(true)) => inventory.open_maps += 1,
                other => panic!("unsupported additionalProperties shape: {other:?}"),
            }
        }
    });
    inventory
}

#[test]
fn exact_published_structural_contract_inventory_is_release_gated() {
    let coverage = coverage();
    let actual = coverage
        .schemas
        .iter()
        .map(|entry| {
            (
                entry.kind.as_str(),
                published_structural_inventory(&compile_schema(&entry.file).0),
            )
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        actual,
        [
            (
                "project",
                PublishedStructuralInventory {
                    nodes: 252,
                    local_refs: 123,
                    union_nodes: 9,
                    union_branches: 19,
                    conditionals: 0,
                    objects: 51,
                    closed_objects: 36,
                    typed_maps: 15,
                    open_maps: 0,
                    arrays: 11,
                    scalar_types: 30,
                    nullable_nodes: 0,
                    integer_lower_bounds: 9,
                    integer_upper_bounds: 9,
                    string_length_bounds: 10,
                    string_patterns: 12,
                    array_size_bounds: 9,
                    unique_arrays: 8,
                    object_size_bounds: 17,
                    property_name_constraints: 14,
                    enums: 12,
                    consts: 8,
                    defaults: 0,
                    deprecations: 0,
                },
            ),
            (
                "environment",
                PublishedStructuralInventory {
                    nodes: 223,
                    local_refs: 85,
                    union_nodes: 6,
                    union_branches: 16,
                    conditionals: 7,
                    objects: 40,
                    closed_objects: 36,
                    typed_maps: 4,
                    open_maps: 0,
                    arrays: 5,
                    scalar_types: 42,
                    nullable_nodes: 0,
                    integer_lower_bounds: 16,
                    integer_upper_bounds: 16,
                    string_length_bounds: 17,
                    string_patterns: 14,
                    array_size_bounds: 5,
                    unique_arrays: 5,
                    object_size_bounds: 5,
                    property_name_constraints: 4,
                    enums: 2,
                    consts: 6,
                    defaults: 2,
                    deprecations: 0,
                },
            ),
            (
                "integration",
                PublishedStructuralInventory {
                    nodes: 165,
                    local_refs: 35,
                    union_nodes: 10,
                    union_branches: 23,
                    conditionals: 0,
                    objects: 33,
                    closed_objects: 27,
                    typed_maps: 6,
                    open_maps: 0,
                    arrays: 9,
                    scalar_types: 50,
                    nullable_nodes: 0,
                    integer_lower_bounds: 16,
                    integer_upper_bounds: 16,
                    string_length_bounds: 14,
                    string_patterns: 20,
                    array_size_bounds: 9,
                    unique_arrays: 8,
                    object_size_bounds: 8,
                    property_name_constraints: 3,
                    enums: 10,
                    consts: 14,
                    defaults: 3,
                    deprecations: 0,
                },
            ),
            (
                "fixture",
                PublishedStructuralInventory {
                    nodes: 71,
                    local_refs: 10,
                    union_nodes: 4,
                    union_branches: 8,
                    conditionals: 0,
                    objects: 21,
                    closed_objects: 11,
                    typed_maps: 7,
                    open_maps: 3,
                    arrays: 4,
                    scalar_types: 36,
                    nullable_nodes: 4,
                    integer_lower_bounds: 1,
                    integer_upper_bounds: 1,
                    string_length_bounds: 9,
                    string_patterns: 7,
                    array_size_bounds: 4,
                    unique_arrays: 0,
                    object_size_bounds: 10,
                    property_name_constraints: 4,
                    enums: 2,
                    consts: 1,
                    defaults: 0,
                    deprecations: 0,
                },
            ),
            (
                "entity",
                PublishedStructuralInventory {
                    nodes: 40,
                    local_refs: 7,
                    union_nodes: 3,
                    union_branches: 6,
                    conditionals: 0,
                    objects: 5,
                    closed_objects: 4,
                    typed_maps: 1,
                    open_maps: 0,
                    arrays: 3,
                    scalar_types: 13,
                    nullable_nodes: 0,
                    integer_lower_bounds: 8,
                    integer_upper_bounds: 8,
                    string_length_bounds: 1,
                    string_patterns: 4,
                    array_size_bounds: 3,
                    unique_arrays: 3,
                    object_size_bounds: 1,
                    property_name_constraints: 1,
                    enums: 2,
                    consts: 6,
                    defaults: 0,
                    deprecations: 0,
                },
            ),
        ]
        .into_iter()
        .collect(),
        "every finite schema node, local reference, union/conditional, object/map shape, scalar/null type, numeric/string/array/object constraint, enum/const, default, and deprecation is release-gated"
    );
}

fn normalized_rust_source(source: &str) -> String {
    source.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_production_ingress_inventory(
    project_source: &str,
    output_source: &str,
    diagnostics_source: &str,
    schema_authority_source: &str,
) -> Result<(), String> {
    let project = normalized_rust_source(project_source);
    let output = normalized_rust_source(output_source);
    let diagnostics = normalized_rust_source(diagnostics_source);
    let schema_authority = normalized_rust_source(schema_authority_source);
    let routes = [
        (
            "loader/project",
            &project,
            "let project: RegistryProject = parse_yaml(&project_bytes, PROJECT_FILE)",
        ),
        (
            "loader/entity",
            &project,
            "let document: EntityDefinition = parse_yaml(&bytes, relative)",
        ),
        (
            "loader/integration",
            &project,
            "let authored: AuthoredIntegrationDocument = parse_yaml(&bytes, &reference.file.display().to_string())",
        ),
        (
            "loader/environment",
            &project,
            "let document: EnvironmentDocument = parse_yaml(&bytes, &relative.display().to_string())",
        ),
        (
            "loader/fixture",
            &output,
            "let authored: AuthoredFixtureDocument = parse_yaml(&bytes, relative)",
        ),
        (
            "diagnostics/project",
            &diagnostics,
            "diagnostic_parse_yaml(&project_bytes, PROJECT_FILE, \"project\", PROJECT_SCHEMA_HINT)",
        ),
        (
            "diagnostics/entity",
            &diagnostics,
            "diagnostic_parse_yaml(&bytes, &file, \"entity\", ENTITY_SCHEMA_HINT)",
        ),
        (
            "diagnostics/integration",
            &diagnostics,
            "diagnostic_parse_yaml(&bytes, &file, \"integration\", INTEGRATION_SCHEMA_HINT)",
        ),
        (
            "diagnostics/environment",
            &diagnostics,
            "diagnostic_parse_yaml(&bytes, &file, \"environment\", ENVIRONMENT_SCHEMA_HINT)",
        ),
        (
            "diagnostics/fixture",
            &diagnostics,
            "diagnostic_parse_yaml(&bytes, &file, \"fixture\", FIXTURE_SCHEMA_HINT)",
        ),
    ];
    for (route, source, needle) in routes {
        let count = source.matches(needle).count();
        if count != 1 {
            return Err(format!(
                "{route} must occur exactly once in the production ingress inventory; found {count}"
            ));
        }
    }

    let project_production = project_source
        .split("#[cfg(test)]")
        .next()
        .expect("project source has a production prefix");
    if project_production.matches("parse_yaml(").count() != 4 {
        return Err("project loader must retain exactly four direct authored routes".to_string());
    }
    if output_source.matches("parse_yaml(").count() != 1
        || output_source.matches("fn parse_yaml<").count() != 1
    {
        return Err(
            "output module must retain exactly one fixture route and one central parse helper"
                .to_string(),
        );
    }
    let diagnostic_production = diagnostics_source
        .split("#[cfg(test)]")
        .next()
        .expect("diagnostics source has a production prefix");
    if diagnostic_production
        .matches("diagnostic_parse_yaml(")
        .count()
        != 5
        || diagnostic_production
            .matches("fn diagnostic_parse_yaml<")
            .count()
            != 1
    {
        return Err(
            "diagnostics must retain five authored routes and one central diagnostic helper"
                .to_string(),
        );
    }
    for (rust_type, kind) in [
        ("RegistryProject", "Project"),
        ("EnvironmentDocument", "Environment"),
        ("AuthoredIntegrationDocument", "Integration"),
        ("AuthoredFixtureDocument", "Fixture"),
        ("EntityDefinition", "Entity"),
    ] {
        let mapping = format!(
            "impl CurrentAuthoringDocument for {rust_type} {{ const KIND: ProjectSchemaKind = ProjectSchemaKind::{kind}; }}"
        );
        if schema_authority.matches(&mapping).count() != 1 {
            return Err(format!(
                "typed schema-authority mapping must occur exactly once: {mapping}"
            ));
        }
    }
    if output
        .matches("parse_current_authoring_document(bytes)")
        .count()
        != 1
        || diagnostics
            .matches("parse_current_authoring_document(bytes)")
            .count()
            != 1
    {
        return Err(
            "both loader and diagnostic ingress helpers must route through canonical schema authority"
                .to_string(),
        );
    }
    Ok(())
}

fn collect_project_authoring_rust_sources(
    directory: &Path,
    sources: &mut Vec<(PathBuf, String)>,
) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_project_authoring_rust_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push((path.clone(), std::fs::read_to_string(path)?));
        }
    }
    Ok(())
}

fn direct_current_document_deserializers(sources: &[(PathBuf, String)]) -> Vec<String> {
    const PARSERS: [&str; 5] = [
        "serde_norway::from_slice",
        "serde_norway::from_str",
        "serde_json::from_slice",
        "serde_json::from_str",
        "serde_json::from_value",
    ];
    const CURRENT_DOCUMENTS: [&str; 5] = [
        "RegistryProject",
        "EnvironmentDocument",
        "AuthoredIntegrationDocument",
        "AuthoredFixtureDocument",
        "EntityDefinition",
    ];

    let mut violations = Vec::new();
    for (path, source) in sources {
        if path
            .file_name()
            .is_some_and(|name| name == "schema_authority.rs")
        {
            continue;
        }
        let production = source.split("\n#[cfg(test)]").next().unwrap_or(source);
        let normalized = normalized_rust_source(production);
        for statement in normalized.split(';') {
            let Some(parser) = PARSERS.iter().find(|parser| statement.contains(**parser)) else {
                continue;
            };
            for document in CURRENT_DOCUMENTS {
                if contains_rust_identifier(statement, document) {
                    violations.push(format!(
                        "{} directly deserializes {document} with {parser}",
                        path.display()
                    ));
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

fn contains_rust_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(start, matched)| {
        let before = source[..start].chars().next_back();
        let after = source[start + matched.len()..].chars().next();
        before.is_none_or(|character| !(character.is_alphanumeric() || character == '_'))
            && after.is_none_or(|character| !(character.is_alphanumeric() || character == '_'))
    })
}

#[test]
fn every_production_current_format_ingress_routes_through_schema_authority() {
    let project = include_str!("../src/project_authoring/project.rs");
    let output = include_str!("../src/project_authoring/output.rs");
    let diagnostics = include_str!("../src/project_authoring/diagnostics.rs");
    let schema_authority = include_str!("../src/project_authoring/schema_authority.rs");
    validate_production_ingress_inventory(project, output, diagnostics, schema_authority)
        .expect("the production ingress inventory is exact");

    let missing_route = project.replacen("AuthoredIntegrationDocument", "EntityDefinition", 1);
    assert!(
        validate_production_ingress_inventory(
            &missing_route,
            output,
            diagnostics,
            schema_authority
        )
        .expect_err("route-kind drift must fail closed")
        .contains("loader/integration"),
        "the route inventory has a planted negative control"
    );

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    collect_project_authoring_rust_sources(
        &manifest_dir.join("src/project_authoring"),
        &mut sources,
    )
    .expect("project-authoring Rust sources are readable");
    let root_module = manifest_dir.join("src/project_authoring.rs");
    sources.push((
        root_module.clone(),
        std::fs::read_to_string(root_module).expect("project-authoring root is readable"),
    ));
    assert!(
        direct_current_document_deserializers(&sources).is_empty(),
        "current authoring DTOs must not bypass schema authority: {:#?}",
        direct_current_document_deserializers(&sources)
    );

    let planted_bypass = vec![(
        PathBuf::from("new_loader.rs"),
        "let project: RegistryProject = serde_norway::from_slice(bytes)?;".to_string(),
    )];
    assert_eq!(
        direct_current_document_deserializers(&planted_bypass),
        vec!["new_loader.rs directly deserializes RegistryProject with \
             serde_norway::from_slice"
            .to_string()],
        "the repository-wide ingress guard has a planted negative control"
    );
}

#[test]
fn published_schema_vocabulary_and_open_object_exceptions_are_explicit() {
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

    assert_eq!(
        encountered_keywords,
        [
            "$defs",
            "$ref",
            "additionalProperties",
            "allOf",
            "anyOf",
            "const",
            "else",
            "enum",
            "exclusiveMinimum",
            "format",
            "if",
            "items",
            "maxItems",
            "maxLength",
            "maxProperties",
            "maximum",
            "minItems",
            "minLength",
            "minProperties",
            "minimum",
            "not",
            "oneOf",
            "pattern",
            "prefixItems",
            "properties",
            "propertyNames",
            "required",
            "then",
            "type",
            "uniqueItems",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        "published schema vocabulary changed; update the inventory and add exact evidence where a rule is exercised"
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
    let mut observed_keyword_evidence = BTreeMap::new();

    for case in &coverage.parity_cases {
        assert!(
            ids.insert(case.id.as_str()),
            "duplicate case id: {}",
            case.id
        );
        assert!(
            !case.expected_failing_keywords.is_empty(),
            "{} must name at least one observed failing schema keyword",
            case.id
        );
        assert!(
            case.expected_failing_keywords
                .windows(2)
                .all(|keywords| keywords[0] < keywords[1]),
            "{} failing schema keywords must be unique and sorted",
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
        let observed_failing_keywords = schema
            .validate(&document)
            .expect_err("maintained mutation must fail its published schema")
            .map(|error| {
                error
                    .schema_path
                    .to_string()
                    .rsplit('/')
                    .next()
                    .filter(|keyword| !keyword.is_empty())
                    .unwrap_or("<root>")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
        observed_keyword_evidence.insert(case.id.as_str(), observed_failing_keywords);
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
    assert_eq!(
        observed_keyword_evidence,
        coverage
            .parity_cases
            .iter()
            .map(|case| {
                (
                    case.id.as_str(),
                    case.expected_failing_keywords.iter().cloned().collect(),
                )
            })
            .collect(),
        "each maintained mutation must name the exact schema keywords observed to fail"
    );
}
