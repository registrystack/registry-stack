// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use registry_notary_core::{
    ClaimEvidenceMode, RelayOutputContract, StandaloneRegistryNotaryConfig,
    MAX_RELAY_OUTPUT_EXPANDED_NODES_V1,
};
use registry_relay::rhai_worker::{
    OutputSchema, TypedValue, WorkerError, WorkerLimits, WorkerOutcome, WorkerOutput,
    WorkerProcess, WorkerRequest,
};
use registryctl::ProjectSchemaKind;
use registryctl::{
    build_registry_project_with_context, check_registry_project_with_context,
    ProjectAuthoringDiagnostics, ProjectBuildOptions, ProjectCheckOptions, ProjectExecutionContext,
};
use serde::Deserialize;
use serde_json::{json, Value};

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
            (SchemaKind::Project, 220),
            (SchemaKind::Environment, 213),
            (SchemaKind::Integration, 177),
            (SchemaKind::Fixture, 63),
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
            (FieldPathKind::Property, 490),
            (FieldPathKind::MapKey, 26),
            (FieldPathKind::MapValue, 33),
            (FieldPathKind::ArrayItem, 38),
            (FieldPathKind::Branch, 116),
        ]
        .into_iter()
        .collect(),
        "properties, arbitrary map keys/values, array items, and branch-only nodes are explicit"
    );
    assert_eq!(
        index.coverage_by_sensitivity(),
        [
            (Sensitivity::Public, 6),
            (Sensitivity::Internal, 447),
            (Sensitivity::Sensitive, 69),
            (Sensitivity::SecretReference, 14),
            (Sensitivity::RedactedFixture, 51),
            (Sensitivity::Structural, 121),
        ]
        .into_iter()
        .collect(),
        "reportability classifications remain exact and conservative"
    );
    assert_eq!(
        index.by_path().len(),
        708,
        "the field-knowledge gate covers every published schema path"
    );
    assert_eq!(
        index.references().len(),
        281,
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
        51,
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
                    nodes: 253,
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
                    enums: 13,
                    consts: 8,
                    defaults: 0,
                    deprecations: 0,
                },
            ),
            (
                "environment",
                PublishedStructuralInventory {
                    nodes: 239,
                    local_refs: 92,
                    union_nodes: 6,
                    union_branches: 17,
                    conditionals: 7,
                    objects: 42,
                    closed_objects: 38,
                    typed_maps: 4,
                    open_maps: 0,
                    arrays: 6,
                    scalar_types: 46,
                    nullable_nodes: 0,
                    integer_lower_bounds: 19,
                    integer_upper_bounds: 19,
                    string_length_bounds: 17,
                    string_patterns: 15,
                    array_size_bounds: 6,
                    unique_arrays: 6,
                    object_size_bounds: 5,
                    property_name_constraints: 4,
                    enums: 3,
                    consts: 6,
                    defaults: 4,
                    deprecations: 0,
                },
            ),
            (
                "integration",
                PublishedStructuralInventory {
                    nodes: 208,
                    local_refs: 48,
                    union_nodes: 14,
                    union_branches: 33,
                    conditionals: 1,
                    objects: 38,
                    closed_objects: 31,
                    typed_maps: 7,
                    open_maps: 0,
                    arrays: 11,
                    scalar_types: 57,
                    nullable_nodes: 0,
                    integer_lower_bounds: 22,
                    integer_upper_bounds: 22,
                    string_length_bounds: 14,
                    string_patterns: 20,
                    array_size_bounds: 11,
                    unique_arrays: 8,
                    object_size_bounds: 9,
                    property_name_constraints: 4,
                    enums: 11,
                    consts: 21,
                    defaults: 3,
                    deprecations: 0,
                },
            ),
            (
                "fixture",
                PublishedStructuralInventory {
                    nodes: 72,
                    local_refs: 11,
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

// ---------------------------------------------------------------------------
// Boundary parity: one authored structured output, three product boundaries.
//
// Registryctl compiles an authored `outputs` declaration into the public Relay
// consultation contract and into the Notary evidence configuration. The two
// runtime products then read that declaration through independent Rust types
// (`registry_relay::rhai_worker::OutputSchema` and
// `registry_notary_core::RelayOutputContract`). The tests below pin the shared
// wire shape, the shared value verdicts, and the exact places where the two
// platform bounds deliberately differ.
// ---------------------------------------------------------------------------

const OPENCRVS_FIXTURE: &str = "crates/registryctl/tests/fixtures/project-authoring/opencrvs";
const OPENCRVS_INTEGRATION: &str = "integrations/birth-record/integration.yaml";
const RELAY_CONSULTATION_CONTRACT: &str = "private/relay-consultation/config/artifacts/consultation-contracts/birth-verification-birth.json";
const NOTARY_CONFIG: &str = "private/notary/config/notary.yaml";
/// The claim whose authored output is the structured array of objects.
const STRUCTURED_OUTPUT: &str = "parents";
/// The synthesized output name used to drive both product boundaries.
const PROBE_OUTPUT: &str = "probe";

/// Reviewed echo program: whatever the host supplies as `probe` is returned as
/// the `probe` output, so the worker validates a real value against the
/// compiler-produced declaration instead of against a literal.
const ECHO_PROGRAM: &str = "fn consult(ctx) { result.match(#{ probe: ctx.input.probe }) }";

/// Reviewed program that produces no outputs, so a worker verdict reports only
/// whether the declared output schema itself was accepted.
const NO_OUTPUT_PROGRAM: &str = "fn consult(ctx) { result.no_match() }";

/// The two product views of one authored `outputs` block.
struct BoundaryOutputs {
    /// `spec.output` from the generated Relay consultation contract.
    relay: BTreeMap<String, Value>,
    /// The generated Notary consultation outputs, re-serialized from the
    /// production `RelayOutputContract` model rather than from raw YAML.
    notary: BTreeMap<String, Value>,
    /// The generated Notary configuration as plain data, so a parity case can
    /// splice one probe declaration into it and revalidate.
    notary_document: Value,
}

fn build_opencrvs_outputs(edit: impl FnOnce(&mut Value)) -> BoundaryOutputs {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("project");
    copy_tree(&repository_root().join(OPENCRVS_FIXTURE), &project);
    let integration_path = project.join(OPENCRVS_INTEGRATION);
    let mut integration = read_yaml_json(&integration_path);
    edit(&mut integration);
    std::fs::write(
        &integration_path,
        serde_norway::to_string(&integration).expect("integration document serializes as YAML"),
    )
    .expect("integration document writes");

    let context = ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides the real registryctl executable");
    let report = build_registry_project_with_context(
        &ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        },
        &context,
    )
    .expect("the opencrvs project builds");
    let output = project.join(report.output.expect("build reports an output directory"));

    let contract: Value = serde_json::from_slice(
        &std::fs::read(output.join(RELAY_CONSULTATION_CONTRACT))
            .expect("Relay consultation contract reads"),
    )
    .expect("Relay consultation contract parses");
    let relay = contract["spec"]["output"]
        .as_object()
        .expect("the Relay contract declares an output map")
        .iter()
        .map(|(name, declaration)| (name.clone(), declaration.clone()))
        .collect::<BTreeMap<_, _>>();

    let notary_path = output.join(NOTARY_CONFIG);
    let notary_config: StandaloneRegistryNotaryConfig =
        serde_norway::from_slice(&std::fs::read(&notary_path).expect("Notary config reads"))
            .expect("the generated Notary config parses through its production model");
    notary_config
        .validate()
        .expect("the generated Notary config passes its own platform validation");
    let notary = structured_consultation_outputs(&notary_config)
        .iter()
        .map(|(name, contract)| {
            (
                name.clone(),
                serde_json::to_value(contract).expect("a Notary output contract serializes"),
            )
        })
        .collect::<BTreeMap<_, _>>();

    BoundaryOutputs {
        relay,
        notary,
        notary_document: read_yaml_json(&notary_path),
    }
}

fn structured_consultation_outputs(
    config: &StandaloneRegistryNotaryConfig,
) -> &BTreeMap<String, RelayOutputContract> {
    let claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == STRUCTURED_OUTPUT)
        .expect("the structured-output claim is generated");
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        panic!("the structured-output claim remains registry backed");
    };
    &consultations
        .values()
        .next()
        .expect("the structured-output claim has one consultation")
        .outputs
}

/// Aligns the worker string ceiling with the Notary platform ceiling so a
/// rejection can only come from the declaration, never from a narrower
/// per-deployment budget.
fn boundary_worker_limits() -> WorkerLimits {
    WorkerLimits {
        max_string_bytes: 64 * 1024,
        max_call_levels: 16,
        max_expr_depth: 16,
        ..WorkerLimits::default()
    }
}

fn relay_verdict(request: &WorkerRequest) -> bool {
    let worker = WorkerProcess::with_program(env!("CARGO_BIN_EXE_registryctl"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    match runtime.block_on(worker.evaluate(request)) {
        Ok(WorkerOutput::Success { outcome, .. }) => {
            assert_ne!(
                outcome,
                WorkerOutcome::Ambiguous,
                "the reviewed parity program is never ambiguous"
            );
            true
        }
        Ok(WorkerOutput::Failure { failure }) => {
            panic!("the reviewed parity program never fails: {failure:?}")
        }
        Err(WorkerError::ContractViolation) => false,
        Err(error) => panic!("the Relay worker did not reach a contract verdict: {error}"),
    }
}

/// Wraps a probe value in the worker's typed input envelope using the declared
/// output type, so a null probe still crosses the boundary with its type.
fn typed_probe(declaration: &Value, value: &Value) -> TypedValue {
    match declaration["type"]
        .as_str()
        .expect("every output declaration names one type")
    {
        "string" => TypedValue::String {
            value: value.as_str().map(str::to_owned),
        },
        "date" => TypedValue::Date {
            value: value.as_str().map(str::to_owned),
        },
        "boolean" => TypedValue::Boolean {
            value: value.as_bool(),
        },
        "integer" => TypedValue::Integer {
            value: value.as_i64(),
        },
        "object" => TypedValue::Object {
            value: (!value.is_null()).then(|| value.clone()),
        },
        "array" => TypedValue::Array {
            value: (!value.is_null()).then(|| value.clone()),
        },
        other => panic!("unknown declared output type: {other}"),
    }
}

fn relay_accepts_value(declaration: &Value, value: &Value) -> bool {
    let schema: OutputSchema = serde_json::from_value(declaration.clone())
        .expect("the declaration decodes into the Relay worker output contract");
    let mut request = WorkerRequest::v1(ECHO_PROGRAM, "consult", boundary_worker_limits());
    request.input = BTreeMap::from([(PROBE_OUTPUT.to_string(), typed_probe(declaration, value))]);
    request.output_schema = BTreeMap::from([(PROBE_OUTPUT.to_string(), schema)]);
    relay_verdict(&request)
}

fn notary_accepts_value(declaration: &Value, value: &Value) -> bool {
    let contract: RelayOutputContract = serde_json::from_value(declaration.clone())
        .expect("the declaration decodes into the Notary Relay output contract");
    contract.validates_value(value)
}

fn relay_accepts_declaration(declaration: &Value) -> bool {
    let Ok(schema) = serde_json::from_value::<OutputSchema>(declaration.clone()) else {
        return false;
    };
    let mut request = WorkerRequest::v1(NO_OUTPUT_PROGRAM, "consult", boundary_worker_limits());
    request.output_schema = BTreeMap::from([(PROBE_OUTPUT.to_string(), schema)]);
    relay_verdict(&request)
}

/// Splices one probe output into every generated consultation and revalidates
/// the whole Notary configuration, which is the only public path to the
/// platform output-schema bounds.
fn notary_accepts_declaration(document: &Value, declaration: &Value) -> bool {
    let mut document = document.clone();
    for claim in document["evidence"]["claims"]
        .as_array_mut()
        .expect("the generated Notary config declares claims")
    {
        for consultation in claim["evidence_mode"]["consultations"]
            .as_object_mut()
            .expect("every generated claim is registry backed")
            .values_mut()
        {
            consultation["outputs"]
                .as_object_mut()
                .expect("every generated consultation declares outputs")
                .insert(PROBE_OUTPUT.to_string(), declaration.clone());
        }
    }
    let yaml = serde_norway::to_string(&document).expect("the Notary config serializes as YAML");
    serde_norway::from_str::<StandaloneRegistryNotaryConfig>(&yaml)
        .is_ok_and(|config| config.validate().is_ok())
}

/// Reports whether the Registryctl authoring stage rejects an authored output.
///
/// The maintained adapter script never produces an extra output, so a project
/// carrying one always fails somewhere; the authoring verdict is which stage
/// fails. An accepted declaration reaches fixture execution, and a rejected one
/// stops at authoring with a diagnostic that names the offending output path.
fn authoring_rejects_output(name: &str, declaration: &Value) -> bool {
    let error = check_authored_output(name, declaration)
        .expect_err("an extra authored output never reaches a clean check");
    if let Some(report) = error.downcast_ref::<ProjectAuthoringDiagnostics>() {
        let pointer = format!("/outputs/{name}");
        assert!(
            report.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "registryctl.authoring.integration.invalid"
                    && diagnostic
                        .addresses
                        .iter()
                        .any(|address| address.pointer.starts_with(&pointer))
            }),
            "an authoring rejection must name the offending output path: {error:#} PROBE {:?}",
            report
                .diagnostics
                .iter()
                .flat_map(|diagnostic| diagnostic.addresses.iter())
                .map(|address| address.pointer.clone())
                .collect::<Vec<_>>()
        );
        return true;
    }
    assert!(
        format!("{error:#}").contains("project integration fixtures failed"),
        "an authoring acceptance must reach fixture execution: {error:#}"
    );
    false
}

/// Runs the production check path over an authored project that declares one
/// extra structured output.
fn check_authored_output(name: &str, declaration: &Value) -> anyhow::Result<()> {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("project");
    copy_tree(&repository_root().join(OPENCRVS_FIXTURE), &project);
    let integration_path = project.join(OPENCRVS_INTEGRATION);
    let mut integration = read_yaml_json(&integration_path);
    integration["outputs"]
        .as_object_mut()
        .expect("the maintained integration declares outputs")
        .insert(name.to_string(), declaration.clone());
    std::fs::write(
        &integration_path,
        serde_norway::to_string(&integration).expect("integration document serializes as YAML"),
    )
    .expect("integration document writes");
    check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .map(|_| ())
}

/// A chain of `nodes` schema nodes: `nodes - 1` nested arrays around a boolean.
fn array_layers(nodes: usize) -> Value {
    assert!(nodes > 0);
    let mut schema = json!({ "type": "boolean", "nullable": false });
    for _ in 1..nodes {
        schema = json!({
            "type": "array",
            "nullable": false,
            "max_bytes": 65_536,
            "max_items": 1,
            "items": schema,
        });
    }
    schema
}

/// The fixed nodes the Notary decoder reserves for the Relay result envelope
/// before it reads any consultation output.
const RELAY_RESULT_ENVELOPE_NODES: usize = 20;

/// The shared expansion formula both products implement: a scalar expands to
/// itself, an object to itself plus its fields, and an array to its item
/// expansion repeated `max_items` times plus itself.
fn expanded_nodes(declaration: &Value) -> usize {
    match declaration["type"]
        .as_str()
        .expect("every declaration names one type")
    {
        "object" => declaration["fields"]
            .as_object()
            .expect("an object declaration carries fields")
            .values()
            .map(|field| expanded_nodes(&field["schema"]))
            .sum::<usize>()
            .checked_add(1)
            .expect("the expansion fits"),
        "array" => expanded_nodes(&declaration["items"])
            .checked_mul(
                declaration["max_items"]
                    .as_u64()
                    .expect("an array declaration carries max_items") as usize,
            )
            .and_then(|expanded| expanded.checked_add(1))
            .expect("the expansion fits"),
        _ => 1,
    }
}

/// Builds an object declaration that expands to exactly `target` nodes, using
/// bounded arrays of booleans as the adjustable field weights.
fn expanded_object(target: usize) -> Value {
    let mut remaining = target
        .checked_sub(1)
        .expect("an object expands to at least one node");
    let mut fields = serde_json::Map::new();
    while remaining > 0 {
        let weight = remaining.min(257);
        let schema = if weight == 1 {
            json!({ "type": "boolean", "nullable": false })
        } else {
            json!({
                "type": "array",
                "nullable": false,
                "max_bytes": 65_536,
                "max_items": weight - 1,
                "items": { "type": "boolean", "nullable": false },
            })
        };
        fields.insert(
            format!("field_{}", fields.len()),
            json!({ "required": true, "schema": schema }),
        );
        remaining -= weight;
    }
    json!({
        "type": "object",
        "nullable": false,
        "max_bytes": 65_536,
        "fields": fields,
    })
}

fn boolean_object(fields: usize) -> Value {
    json!({
        "type": "object",
        "nullable": false,
        "max_bytes": 65_536,
        "fields": (0..fields)
            .map(|index| {
                (
                    format!("field_{index}"),
                    json!({ "required": true, "schema": { "type": "boolean", "nullable": false } }),
                )
            })
            .collect::<serde_json::Map<_, _>>(),
    })
}

#[test]
fn authored_structured_output_reaches_relay_and_notary_as_one_declaration() {
    let baseline = build_opencrvs_outputs(|_| {});
    let structured = baseline
        .relay
        .get(STRUCTURED_OUTPUT)
        .expect("the Relay contract carries the structured output");
    assert_eq!(
        Some(structured),
        baseline.notary.get(STRUCTURED_OUTPUT),
        "one authored structured declaration must reach Relay and Notary as the same declaration"
    );
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<OutputSchema>(structured.clone())
                .expect("the structured declaration decodes into the Relay worker contract")
        )
        .expect("the Relay worker contract re-serializes"),
        *structured,
        "the Relay worker type must round-trip the compiler-produced declaration exactly"
    );
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<RelayOutputContract>(structured.clone())
                .expect("the structured declaration decodes into the Notary output contract")
        )
        .expect("the Notary output contract re-serializes"),
        *structured,
        "the Notary type must round-trip the compiler-produced declaration exactly"
    );

    // The public Relay contract keeps the authored `maxLength` on a date so the
    // published surface stays self-describing; neither runtime type carries it.
    // Every other output must be identical on both sides.
    let divergent = baseline
        .relay
        .iter()
        .filter(|(name, declaration)| baseline.notary.get(*name) != Some(*declaration))
        .map(|(name, declaration)| {
            let mut relay_only = declaration.clone();
            let notary = baseline
                .notary
                .get(name)
                .expect("Relay and Notary declare the same output names");
            relay_only
                .as_object_mut()
                .expect("an output declaration is an object")
                .retain(|key, value| notary.get(key) != Some(value));
            (name.clone(), relay_only)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        divergent,
        BTreeMap::from([("date_of_birth".to_string(), json!({ "max_bytes": 10 }))]),
        "only the documented date byte hint may differ between the two product views"
    );
    assert_eq!(
        baseline.relay.keys().collect::<Vec<_>>(),
        baseline.notary.keys().collect::<Vec<_>>(),
        "both products must receive the same output names"
    );

    // The one authored nullability idiom must lower to `nullable: true` at both
    // boundaries and at every level of a recursive declaration.
    assert_eq!(structured["nullable"], json!(false));
    assert_eq!(structured["items"]["nullable"], json!(false));
    let nullable = build_opencrvs_outputs(|integration| {
        integration["outputs"][STRUCTURED_OUTPUT]["type"] = json!(["array", "null"]);
        integration["outputs"][STRUCTURED_OUTPUT]["items"]["type"] = json!(["object", "null"]);
    });
    let nullable_structured = nullable
        .relay
        .get(STRUCTURED_OUTPUT)
        .expect("the nullable Relay contract carries the structured output");
    assert_eq!(
        Some(nullable_structured),
        nullable.notary.get(STRUCTURED_OUTPUT),
        "the nullable union idiom must reach Relay and Notary as the same declaration"
    );
    assert_eq!(nullable_structured["nullable"], json!(true));
    assert_eq!(nullable_structured["items"]["nullable"], json!(true));
    assert_eq!(
        nullable_structured["items"]["fields"], structured["items"]["fields"],
        "declaring the composite nullable must not change any nested field"
    );
}

#[test]
fn structured_output_values_agree_at_the_relay_and_notary_boundaries() {
    let built = build_opencrvs_outputs(|_| {});
    let parents = built
        .relay
        .get(STRUCTURED_OUTPUT)
        .expect("the Relay contract carries the structured output")
        .clone();
    let item = parents["items"].clone();
    // Authored `maxLength: 16` on the item's `type` field lowers to 64 bytes.
    let type_field_bytes = item["fields"]["type"]["schema"]["max_bytes"]
        .as_u64()
        .expect("the item type field declares a byte ceiling") as usize;
    let item_bytes = item["max_bytes"]
        .as_u64()
        .expect("the item declares a byte ceiling") as usize;

    // A UTF-8 byte ceiling is measured in bytes, not characters.
    let at_scalar_cap = "é".repeat(type_field_bytes / 2);
    let over_scalar_cap = "é".repeat(type_field_bytes / 2 + 1);
    assert_eq!(at_scalar_cap.len(), type_field_bytes);
    assert_eq!(over_scalar_cap.len(), type_field_bytes + 2);
    let ascii_under_cap = "a".repeat(type_field_bytes - 1);
    let ascii_at_cap = "a".repeat(type_field_bytes);
    let ascii_over_cap = "a".repeat(type_field_bytes + 1);

    // Pad the item's `name` so the serialized item lands exactly on its cap.
    let padding = |extra: isize| {
        let empty = json!({ "type": "mother", "name": "", "identifier": "P-1" });
        let base = serde_json::to_vec(&empty)
            .expect("the probe item serializes")
            .len();
        let width = usize::try_from(item_bytes as isize - base as isize + extra)
            .expect("the padded item stays positive");
        json!({ "type": "mother", "name": "n".repeat(width), "identifier": "P-1" })
    };
    assert_eq!(
        serde_json::to_vec(&padding(0))
            .expect("the padded item serializes")
            .len(),
        item_bytes
    );

    // A synthesized array reaches its own byte ceiling, which the authored
    // declaration cannot: two items of at most 384 bytes never reach 1024.
    let capped_array = json!({
        "type": "array",
        "nullable": false,
        "max_bytes": 64,
        "max_items": 8,
        "items": { "type": "string", "nullable": false, "max_bytes": 64 },
    });
    let array_at_cap = json!(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    assert_eq!(
        serde_json::to_vec(&array_at_cap)
            .expect("the capped array serializes")
            .len(),
        64
    );
    let array_over_cap = json!(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    let array_under_cap = json!(["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);

    let json_safe_integer = json!({
        "type": "integer",
        "nullable": false,
        "minimum": -9_007_199_254_740_991_i64,
        "maximum": 9_007_199_254_740_991_i64,
    });
    let nullable_integer = json!({
        "type": "integer",
        "nullable": true,
        "minimum": 0,
        "maximum": 10,
    });

    for (case, declaration, value, accepted) in [
        (
            "two conforming items",
            &parents,
            json!([
                { "type": "mother", "name": "Mira Example", "identifier": "PARENT-0001" },
                { "type": "father", "name": "Noah Example", "identifier": "PARENT-0002" },
            ]),
            true,
        ),
        (
            "more items than the declared maximum",
            &parents,
            json!([
                { "type": "mother", "name": "Mira Example" },
                { "type": "father", "name": "Noah Example" },
                { "type": "guardian", "name": "Ada Example" },
            ]),
            false,
        ),
        (
            "absent optional nested field",
            &parents,
            json!([{ "type": "mother", "name": "Mira Example" }]),
            true,
        ),
        (
            "null optional nested field",
            &parents,
            json!([{ "type": "mother", "name": "Mira Example", "identifier": null }]),
            true,
        ),
        (
            "absent required nested field",
            &parents,
            json!([{ "type": "mother", "identifier": "PARENT-0001" }]),
            false,
        ),
        (
            "null required nested field",
            &parents,
            json!([{ "type": "mother", "name": null }]),
            false,
        ),
        (
            "null value for a non-nullable composite",
            &parents,
            Value::Null,
            false,
        ),
        (
            "unknown ASCII nested key",
            &parents,
            json!([{ "type": "mother", "name": "Mira Example", "age": "41" }]),
            false,
        ),
        (
            "unknown non-ASCII nested key",
            &parents,
            json!([{ "type": "mother", "name": "Mira Example", "prénom": "Mira" }]),
            false,
        ),
        (
            "non-ASCII string value",
            &parents,
            json!([{ "type": "mother", "name": "José Mará Ñuñez" }]),
            true,
        ),
        (
            "escaped control characters in a string value",
            &parents,
            json!([{ "type": "mother", "name": "Mira\u{0001}\u{0007}\nExample" }]),
            true,
        ),
        (
            "string one byte below the scalar byte ceiling",
            &parents,
            json!([{ "type": ascii_under_cap, "name": "Mira Example" }]),
            true,
        ),
        (
            "string exactly on the scalar byte ceiling",
            &parents,
            json!([{ "type": ascii_at_cap, "name": "Mira Example" }]),
            true,
        ),
        (
            "string one byte past the scalar byte ceiling",
            &parents,
            json!([{ "type": ascii_over_cap, "name": "Mira Example" }]),
            false,
        ),
        (
            "non-ASCII string exactly on the scalar byte ceiling",
            &parents,
            json!([{ "type": at_scalar_cap, "name": "Mira Example" }]),
            true,
        ),
        (
            "non-ASCII string one byte pair past the scalar byte ceiling",
            &parents,
            json!([{ "type": over_scalar_cap, "name": "Mira Example" }]),
            false,
        ),
        (
            "serialized item one byte below its ceiling",
            &parents,
            json!([padding(-1)]),
            true,
        ),
        (
            "serialized item exactly on its ceiling",
            &parents,
            json!([padding(0)]),
            true,
        ),
        (
            "serialized item one byte past its ceiling",
            &parents,
            json!([padding(1)]),
            false,
        ),
        (
            "serialized array one byte below its ceiling",
            &capped_array,
            array_under_cap,
            true,
        ),
        (
            "serialized array exactly on its ceiling",
            &capped_array,
            array_at_cap,
            true,
        ),
        (
            "serialized array one byte past its ceiling",
            &capped_array,
            array_over_cap,
            false,
        ),
        (
            "exact JSON-safe maximum integer",
            &json_safe_integer,
            json!(9_007_199_254_740_991_i64),
            true,
        ),
        (
            "one past the JSON-safe maximum integer",
            &json_safe_integer,
            json!(9_007_199_254_740_992_i64),
            false,
        ),
        (
            "exact JSON-safe minimum integer",
            &json_safe_integer,
            json!(-9_007_199_254_740_991_i64),
            true,
        ),
        (
            "one past the JSON-safe minimum integer",
            &json_safe_integer,
            json!(-9_007_199_254_740_992_i64),
            false,
        ),
        (
            "integer exactly on a narrow declared maximum",
            &nullable_integer,
            json!(10),
            true,
        ),
        (
            "integer one past a narrow declared maximum",
            &nullable_integer,
            json!(11),
            false,
        ),
        (
            "null value for a nullable scalar",
            &nullable_integer,
            Value::Null,
            true,
        ),
    ] {
        let relay = relay_accepts_value(declaration, &value);
        let notary = notary_accepts_value(declaration, &value);
        assert_eq!(
            relay, notary,
            "Relay and Notary must reach the same verdict for {case}"
        );
        assert_eq!(relay, accepted, "unexpected boundary verdict for {case}");
    }
}

#[test]
fn platform_output_schema_bounds_agree_across_registryctl_relay_and_notary() {
    let built = build_opencrvs_outputs(|_| {});

    // The Notary decoder wraps consultation outputs in the Relay result root
    // (three levels) and reserves the twenty fixed envelope nodes. Registryctl
    // reserves the same envelope when it validates an authored declaration, so
    // Notary is the binding bound and Relay, which validates only the bare
    // output map, is deliberately more permissive.
    assert!(
        relay_accepts_declaration(&array_layers(6)),
        "six schema levels fit inside the Relay worker depth bound"
    );
    assert!(
        notary_accepts_declaration(&built.notary_document, &array_layers(6)),
        "six schema levels fit beneath the reserved Notary result envelope"
    );
    assert!(
        !authoring_rejects_output("nested", &authored_array_layers(6)),
        "six schema levels are authorable"
    );
    assert!(
        relay_accepts_declaration(&array_layers(7)),
        "seven schema levels still fit the Relay worker depth bound"
    );
    assert!(
        !notary_accepts_declaration(&built.notary_document, &array_layers(7)),
        "seven schema levels exceed the reserved Notary result envelope"
    );
    assert!(
        authoring_rejects_output("nested", &authored_array_layers(7)),
        "Registryctl reserves the same result envelope as the Notary platform"
    );
    assert!(
        !relay_accepts_declaration(&array_layers(9)),
        "nine schema levels exceed the Relay worker depth bound"
    );
    assert!(
        !notary_accepts_declaration(&built.notary_document, &array_layers(9)),
        "nine schema levels exceed the Notary depth bound"
    );

    for (case, declaration, accepted) in [
        ("thirty-two object fields", boolean_object(32), true),
        ("thirty-three object fields", boolean_object(33), false),
        (
            "two hundred and fifty-six array items",
            json!({
                "type": "array",
                "nullable": false,
                "max_bytes": 65_536,
                "max_items": 256,
                "items": { "type": "boolean", "nullable": false },
            }),
            true,
        ),
        (
            "two hundred and fifty-seven array items",
            json!({
                "type": "array",
                "nullable": false,
                "max_bytes": 65_536,
                "max_items": 257,
                "items": { "type": "boolean", "nullable": false },
            }),
            false,
        ),
        (
            "declared field name carrying a control character",
            json!({
                "type": "object",
                "nullable": false,
                "max_bytes": 65_536,
                "fields": {
                    "wrapped\u{0001}name": {
                        "required": true,
                        "schema": { "type": "boolean", "nullable": false },
                    },
                },
            }),
            false,
        ),
        (
            "declared non-ASCII field name",
            json!({
                "type": "object",
                "nullable": false,
                "max_bytes": 65_536,
                "fields": {
                    "prénom": {
                        "required": true,
                        "schema": { "type": "boolean", "nullable": false },
                    },
                },
            }),
            true,
        ),
        (
            "string byte ceiling exactly on the platform bound",
            json!({ "type": "string", "nullable": false, "max_bytes": 65_536 }),
            true,
        ),
        (
            "string byte ceiling one byte past the platform bound",
            json!({ "type": "string", "nullable": false, "max_bytes": 65_537 }),
            false,
        ),
    ] {
        let relay = relay_accepts_declaration(&declaration);
        let notary = notary_accepts_declaration(&built.notary_document, &declaration);
        assert_eq!(
            relay, notary,
            "Relay and Notary must reach the same declaration verdict for {case}"
        );
        assert_eq!(relay, accepted, "unexpected declaration verdict for {case}");
    }

    // The expanded-node budget is a whole-consultation budget, and the Notary
    // decoder spends the reserved result envelope inside it before reading any
    // output. A worker request that carries one output therefore admits a
    // larger single declaration than the same declaration inside a generated
    // consultation. Both products expand a declaration identically; only the
    // reserve differs.
    let reserved =
        RELAY_RESULT_ENVELOPE_NODES + built.notary.values().map(expanded_nodes).sum::<usize>();
    let notary_budget = MAX_RELAY_OUTPUT_EXPANDED_NODES_V1 - reserved;
    for (case, target, relay_accepts, notary_accepts) in [
        (
            "the generated consultation budget",
            notary_budget,
            true,
            true,
        ),
        (
            "one node past the generated consultation budget",
            notary_budget + 1,
            true,
            false,
        ),
        (
            "the bare platform expanded-node bound",
            MAX_RELAY_OUTPUT_EXPANDED_NODES_V1,
            true,
            false,
        ),
        (
            "one node past the platform expanded-node bound",
            MAX_RELAY_OUTPUT_EXPANDED_NODES_V1 + 1,
            false,
            false,
        ),
    ] {
        let declaration = expanded_object(target);
        assert_eq!(
            expanded_nodes(&declaration),
            target,
            "the parity builder must expand to exactly {target} nodes for {case}"
        );
        assert_eq!(
            relay_accepts_declaration(&declaration),
            relay_accepts,
            "unexpected Relay expanded-node verdict for {case}"
        );
        assert_eq!(
            notary_accepts_declaration(&built.notary_document, &declaration),
            notary_accepts,
            "unexpected Notary expanded-node verdict for {case}"
        );
    }

    // Registryctl is the strictest of the three gates: the published authoring
    // grammar rejects declared field names that both runtime products accept.
    assert!(
        authoring_rejects_output(
            "named",
            &json!({
                "type": "object",
                "max_bytes": 1_024,
                "fields": {
                    "prénom": { "required": true, "schema": { "type": "boolean" } },
                },
            }),
        ),
        "a non-ASCII declared field name is outside the published authoring grammar"
    );
}

/// The authored form of [`array_layers`]: the authoring surface omits the
/// lowered `nullable` flag and expresses the leaf as a scalar declaration.
fn authored_array_layers(nodes: usize) -> Value {
    assert!(nodes > 0);
    let mut schema = json!({ "type": "boolean" });
    for _ in 1..nodes {
        schema = json!({
            "type": "array",
            "max_bytes": 65_536,
            "max_items": 1,
            "items": schema,
        });
    }
    schema
}
