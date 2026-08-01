// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{json, Value};

#[path = "../src/project_authoring/documentation.rs"]
mod documentation;
#[path = "../src/project_authoring/knowledge.rs"]
mod knowledge;

use documentation::{
    configuration_reference_coverage, generate_configuration_reference,
    runtime_configuration_intent_gaps, ConfigurationSchemaKind, ConfigurationState,
    DocumentationDomainIntent, DocumentationIntentCatalog, DocumentationIntentPolicy,
    DocumentationSchema, EnvironmentBehavior, HumanIntentSource, ProhibitedIntentSource,
    RuntimeIntentCatalog, StructuralIntent, StructuralIntentReview, ValidationStage,
    CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID, CONFIGURATION_REFERENCE_SCHEMA_ID,
};
use knowledge::{
    Availability, Consumer, FieldClassification, FieldKnowledgeCatalog, FieldKnowledgeDefaults,
    FieldPathKind, GeneratedArtifact, HumanOwner, Migration, Product, PublishedSchema, ReviewClass,
    SchemaDomain, SchemaKind, SemanticOwner, SemanticRule, Sensitivity, Stability,
};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: impl Into<PathBuf>) -> Value {
    let path = path.into();
    serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("{} reads: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{} parses: {error}", path.display()))
}

fn compile_schema(document: &Value) -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(document)
        .unwrap_or_else(|error| panic!("documentation schema compiles: {error}"))
}

fn assert_valid(schema: &jsonschema::JSONSchema, value: &Value, context: &str) {
    if let Err(errors) = schema.validate(value) {
        panic!(
            "{context} failed schema validation: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
}

fn miniature_catalog() -> FieldKnowledgeCatalog {
    FieldKnowledgeCatalog {
        version: 1,
        defaults: FieldKnowledgeDefaults {
            introduced_in: "0.13.0".to_owned(),
            availability: Availability::Published,
            stability: Stability::Experimental,
            semantic_rules: vec![
                SemanticRule::KnowledgeOnly,
                SemanticRule::GeneratedDocsNeverLoadCountryValues,
            ],
        },
        schema_domains: vec![SchemaDomain {
            schema: SchemaKind::Project,
            semantic_owner: SemanticOwner::AuthoringContract,
            human_owner: HumanOwner::RegistryMaintainers,
            products: vec![Product::Registryctl, Product::Docs],
            migration: Migration::RebuildProject,
            consumers: vec![Consumer::RegistryctlAuthoring, Consumer::DocsGenerator],
            generated_artifacts: vec![
                GeneratedArtifact::EditorSchemas,
                GeneratedArtifact::FieldReference,
            ],
            review_classes: vec![ReviewClass::Contract, ReviewClass::Documentation],
        }],
        classifications: vec![
            FieldClassification {
                id: "root".to_owned(),
                path_kind: FieldPathKind::Root,
                sensitivity: Sensitivity::Structural,
                review_classes: vec![ReviewClass::Contract],
                semantic_rules: vec![SemanticRule::KnowledgeOnly],
            },
            FieldClassification {
                id: "property".to_owned(),
                path_kind: FieldPathKind::Property,
                sensitivity: Sensitivity::Internal,
                review_classes: vec![ReviewClass::Documentation],
                semantic_rules: vec![SemanticRule::KnowledgeOnly],
            },
        ],
    }
}

fn miniature_structural_catalog() -> FieldKnowledgeCatalog {
    let mut catalog = miniature_catalog();
    catalog.classifications.extend([
        FieldClassification {
            id: "map_key".to_owned(),
            path_kind: FieldPathKind::MapKey,
            sensitivity: Sensitivity::Internal,
            review_classes: vec![ReviewClass::Contract, ReviewClass::Documentation],
            semantic_rules: vec![SemanticRule::ArbitraryMapKeysNotFixedProperties],
        },
        FieldClassification {
            id: "map_value".to_owned(),
            path_kind: FieldPathKind::MapValue,
            sensitivity: Sensitivity::Internal,
            review_classes: vec![ReviewClass::Contract, ReviewClass::Documentation],
            semantic_rules: vec![SemanticRule::ArbitraryMapKeysNotFixedProperties],
        },
        FieldClassification {
            id: "array_item".to_owned(),
            path_kind: FieldPathKind::ArrayItem,
            sensitivity: Sensitivity::Internal,
            review_classes: vec![ReviewClass::Contract, ReviewClass::Documentation],
            semantic_rules: vec![SemanticRule::ArrayItemsShareElementContract],
        },
        FieldClassification {
            id: "branch".to_owned(),
            path_kind: FieldPathKind::Branch,
            sensitivity: Sensitivity::Structural,
            review_classes: vec![ReviewClass::Contract, ReviewClass::Compatibility],
            semantic_rules: vec![SemanticRule::BranchHasNoAuthoredValue],
        },
    ]);
    catalog
}

fn miniature_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://registrystack.example/tests/documentation-miniature.v1.json",
        "type": "object",
        "description": "Defines the complete miniature documentation-reference contract used by the generator test.",
        "x-registry-field": "root",
        "additionalProperties": false,
        "required": ["version"],
        "properties": {
            "version": {
                "description": "Selects the authored miniature contract version used by this deterministic test.",
                "type": "string",
                "const": "1",
                "examples": ["COUNTRY_VALUE_SENTINEL"],
                "x-registry-field": "property"
            },
            "mode": {
                "description": "Selects the optional safe mode and documents its committed schema default.",
                "type": "string",
                "enum": ["safe", "strict"],
                "default": "safe",
                "x-registry-field": "property"
            }
        }
    })
}

fn miniature_schema_with_unreviewed_structural_paths() -> Value {
    let mut document = miniature_schema();
    document["properties"]["structural_map"] = json!({
        "description": "Defines a miniature typed map whose structural paths require exact review.",
        "type": "object",
        "propertyNames": {
            "type": "string",
            "x-registry-field": "map_key"
        },
        "additionalProperties": {
            "type": "string",
            "x-registry-field": "map_value"
        },
        "x-registry-field": "property"
    });
    document["properties"]["structural_list"] = json!({
        "description": "Defines a miniature ordered list whose item path requires exact review.",
        "type": "array",
        "items": {
            "type": "string",
            "x-registry-field": "array_item"
        },
        "x-registry-field": "property"
    });
    document["properties"]["structural_choice"] = json!({
        "description": "Defines a miniature conditional value whose branch requires exact review.",
        "not": {
            "const": "blocked",
            "x-registry-field": "branch"
        },
        "x-registry-field": "property"
    });
    document
}

fn miniature_structural_reviews() -> Vec<StructuralIntentReview> {
    [
        (
            "/properties/structural_map/propertyNames",
            FieldPathKind::MapKey,
        ),
        (
            "/properties/structural_map/additionalProperties",
            FieldPathKind::MapValue,
        ),
        (
            "/properties/structural_list/items",
            FieldPathKind::ArrayItem,
        ),
        ("/properties/structural_choice/not", FieldPathKind::Branch),
    ]
    .into_iter()
    .map(|(pointer, path_kind)| StructuralIntentReview {
        schema: SchemaKind::Project,
        pointer: pointer.to_owned(),
        path_kind,
    })
    .collect()
}

fn miniature_intent() -> DocumentationIntentCatalog {
    DocumentationIntentCatalog {
        schema: Some(
            "https://id.registrystack.org/schemas/registryctl/project-authoring/documentation-intent.v1.schema.json"
                .to_owned(),
        ),
        format_version: "1.0".to_owned(),
        policy: DocumentationIntentPolicy {
            human_sources: vec![
                HumanIntentSource::SchemaDescription,
                HumanIntentSource::ReviewedOverride,
                HumanIntentSource::StructuralTaxonomy,
            ],
            prohibited_sources: vec![
                ProhibitedIntentSource::CountryWorkspace,
                ProhibitedIntentSource::CountryValue,
                ProhibitedIntentSource::RuntimeConfiguration,
                ProhibitedIntentSource::DerivedFieldLabel,
            ],
            prose_required_for: vec![
                FieldPathKind::Root,
                FieldPathKind::Property,
                FieldPathKind::MapKey,
                FieldPathKind::MapValue,
                FieldPathKind::ArrayItem,
                FieldPathKind::Branch,
            ],
        },
        structural_intents: [
            (
                FieldPathKind::MapKey,
                StructuralIntent {
                    purpose: "Documents the authored key contract for a miniature typed map."
                        .to_owned(),
                },
            ),
            (
                FieldPathKind::MapValue,
                StructuralIntent {
                    purpose: "Documents the authored value contract for a miniature typed map."
                        .to_owned(),
                },
            ),
            (
                FieldPathKind::ArrayItem,
                StructuralIntent {
                    purpose: "Documents the authored item contract for a miniature ordered list."
                        .to_owned(),
                },
            ),
            (
                FieldPathKind::Branch,
                StructuralIntent {
                    purpose:
                        "Documents a miniature validation branch that has no standalone value."
                            .to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
        structural_reviews: Vec::new(),
        domains: vec![DocumentationDomainIntent {
            schema: SchemaKind::Project,
            scope: "A miniature authored project contract used only to prove deterministic documentation generation."
                .to_owned(),
            state: ConfigurationState::Authored,
            environment_behavior: EnvironmentBehavior::EnvironmentIndependent,
            validation_stages: vec![
                ValidationStage::JsonSchema,
                ValidationStage::RustDeserialization,
            ],
            diagnostic: "registryctl.authoring.project.invalid".to_owned(),
            migration_note:
                "Revalidate the miniature document after changing this test-only authored contract."
                    .to_owned(),
            example_guidance:
                "Use only the committed synthetic miniature values supplied by this contract test."
                    .to_owned(),
        }],
        overrides: Vec::new(),
    }
}

#[test]
fn human_intent_sidecar_and_documentation_contracts_are_strict_schemas() {
    let schema_root = crate_root().join("schemas");
    let intent_schema_document =
        read_json(schema_root.join("project-authoring/documentation-intent.schema.json"));
    let intent_schema = compile_schema(&intent_schema_document);
    let intent = read_json(schema_root.join("project-authoring/documentation-intent.json"));
    assert_valid(&intent_schema, &intent, "documentation intent sidecar");
    assert_eq!(intent["structural_reviews"].as_array().unwrap().len(), 213);

    for file in [
        "registry.project.configuration_reference.v1.schema.json",
        "registry.project.configuration_reference_coverage.v1.schema.json",
        "registry.runtime.configuration_intent.v1.schema.json",
    ] {
        let document = read_json(schema_root.join("project-documentation").join(file));
        compile_schema(&document);
    }

    let mut unknown_review = intent.clone();
    unknown_review["structural_reviews"][0]["unexpected"] = json!(true);
    assert!(intent_schema.validate(&unknown_review).is_err());
    assert!(
        serde_json::from_value::<DocumentationIntentCatalog>(unknown_review).is_err(),
        "the DTO rejects an unknown structural-review field"
    );

    let mut unknown_intent = intent;
    unknown_intent["unexpected"] = json!(true);
    assert!(intent_schema.validate(&unknown_intent).is_err());
    assert!(
        serde_json::from_value::<DocumentationIntentCatalog>(unknown_intent).is_err(),
        "the DTO rejects an unknown top-level field"
    );

    let runtime_intent_schema = compile_schema(&read_json(
        schema_root
            .join("project-documentation")
            .join("registry.runtime.configuration_intent.v1.schema.json"),
    ));
    for path in [
        crate_root().join("../registry-relay/config/documentation-intent.json"),
        crate_root().join("../registry-notary-core/config/documentation-intent.json"),
    ] {
        let runtime_intent = read_json(path);
        assert_valid(
            &runtime_intent_schema,
            &runtime_intent,
            "product-owned runtime intent",
        );
        let mut cross_product = runtime_intent.clone();
        cross_product["profiles"][0]["semantic_owner"] =
            if cross_product["runtime_schema"] == "relay" {
                json!("notary_runtime")
            } else {
                json!("relay_runtime")
            };
        assert!(
            runtime_intent_schema.validate(&cross_product).is_err(),
            "the strict runtime intent schema rejects cross-product profile ownership"
        );
        let mut unknown_assignment = runtime_intent;
        unknown_assignment["assignments"][0]["unexpected"] = json!(true);
        assert!(runtime_intent_schema.validate(&unknown_assignment).is_err());
        assert!(
            serde_json::from_value::<RuntimeIntentCatalog>(unknown_assignment).is_err(),
            "the runtime intent DTO rejects unknown assignment fields"
        );
    }
}

#[test]
fn complete_miniature_reference_is_deterministic_strict_and_value_free() {
    let catalog = miniature_catalog();
    let document = miniature_schema();
    let schema = [DocumentationSchema {
        published: PublishedSchema {
            kind: SchemaKind::Project,
            document: &document,
        },
        source_name: "project.schema.json",
    }];
    let intent = miniature_intent();

    let first = generate_configuration_reference(&catalog, &schema, &intent)
        .expect("complete miniature reference generates");
    let second = generate_configuration_reference(&catalog, &schema, &intent)
        .expect("rerun generates the same reference");
    assert_eq!(first, second);
    assert_eq!(first.schema_id, CONFIGURATION_REFERENCE_SCHEMA_ID);
    assert_eq!(first.coverage.path_count, 3);
    assert_eq!(first.fields.len(), 3);

    let value = serde_json::to_value(&first).expect("reference serializes");
    assert_eq!(
        value,
        read_json(
            crate_root()
                .join("tests/fixtures/project-documentation")
                .join("configuration-reference.miniature.v1.json")
        ),
        "the canonical miniature documentation artifact is byte-model exact"
    );
    let bytes = serde_json::to_vec(&value).expect("reference has canonical JSON data");
    assert!(
        !bytes
            .windows(b"COUNTRY_VALUE_SENTINEL".len())
            .any(|window| window == b"COUNTRY_VALUE_SENTINEL"),
        "schema examples are described by availability and never copied as country-like values"
    );
    let output_schema = compile_schema(&read_json(
        crate_root()
            .join("schemas/project-documentation")
            .join("registry.project.configuration_reference.v1.schema.json"),
    ));
    assert_valid(&output_schema, &value, "generated configuration reference");
    let mut unknown = value;
    unknown["fields"][0]["unexpected"] = json!(true);
    assert!(
        output_schema.validate(&unknown).is_err(),
        "the strict reference contract rejects an unknown nested field"
    );
}

#[test]
fn embedded_coverage_is_complete_and_generates_the_canonical_reference() {
    let coverage = documentation::embedded_configuration_reference_coverage()
        .expect("embedded coverage audit succeeds without opening a workspace");
    assert_eq!(
        coverage.schema_id,
        CONFIGURATION_REFERENCE_COVERAGE_SCHEMA_ID
    );
    assert_eq!(coverage.coverage.schema_count, 7);
    assert_eq!(coverage.coverage.path_count, 1835);
    assert_eq!(
        coverage.coverage.by_schema,
        [
            (ConfigurationSchemaKind::Project, 220),
            (ConfigurationSchemaKind::Environment, 213),
            (ConfigurationSchemaKind::Integration, 177),
            (ConfigurationSchemaKind::Fixture, 63),
            (ConfigurationSchemaKind::Entity, 35),
            (ConfigurationSchemaKind::Relay, 593),
            (ConfigurationSchemaKind::Notary, 534),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        coverage.coverage.by_path_kind,
        [
            (FieldPathKind::Root, 7),
            (FieldPathKind::Property, 1_456),
            (FieldPathKind::MapKey, 26),
            (FieldPathKind::MapValue, 48),
            (FieldPathKind::ArrayItem, 182),
            (FieldPathKind::Branch, 116),
        ]
        .into_iter()
        .collect(),
        "the exact reviewed structural taxonomy remains release-gated"
    );
    assert_eq!(coverage.reviewed_intent_assignment_required_count, 1835);
    assert_eq!(
        coverage.reviewed_intent_assignment_covered_count + coverage.missing_intent.len(),
        coverage.reviewed_intent_assignment_required_count
    );
    assert_eq!(coverage.reviewed_intent_assignment_covered_count, 1835);
    assert!(
        coverage.distinct_reviewed_intent_count < coverage.reviewed_intent_assignment_covered_count,
        "assignment coverage must not imply one unique explanation per path"
    );
    assert!(
        coverage.distinct_reviewed_intents_reused_count > 0
            && coverage.reviewed_intent_assignments_using_reused_intent_count
                > coverage.distinct_reviewed_intents_reused_count,
        "the coverage report must expose reuse separately from assignment completeness"
    );
    assert_eq!(
        (
            coverage.distinct_reviewed_intent_count,
            coverage.distinct_reviewed_intents_reused_count,
            coverage.reviewed_intent_assignments_using_reused_intent_count,
        ),
        (627, 86, 1_294),
        "the exact intent-text reuse baseline must change intentionally with reviewed documentation"
    );
    assert_eq!(
        coverage.coverage.by_intent_profile.values().sum::<usize>(),
        1127,
        "every Relay and Notary path, including both roots, records its exact reviewed profile"
    );
    assert_eq!(
        coverage.missing_intent.len(),
        0,
        "every published field must have exact reviewed human intent"
    );
    assert_eq!(
        coverage
            .missing_intent
            .iter()
            .map(|address| (&address.schema, &address.pointer, &address.key_path))
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        coverage.missing_intent.len(),
        "every unresolved human-intent gap has an exact unique address"
    );

    let value = serde_json::to_value(&coverage).expect("coverage serializes");
    let coverage_schema = compile_schema(&read_json(
        crate_root()
            .join("schemas/project-documentation")
            .join("registry.project.configuration_reference_coverage.v1.schema.json"),
    ));
    assert_valid(
        &coverage_schema,
        &value,
        "embedded configuration-reference coverage",
    );
    let mut unknown = value;
    unknown["unexpected"] = json!(true);
    assert!(
        coverage_schema.validate(&unknown).is_err(),
        "the strict coverage contract rejects an unknown top-level field"
    );

    let reference = documentation::embedded_configuration_reference()
        .expect("complete reviewed prose permits canonical reference generation");
    assert_eq!(reference.coverage, coverage.coverage);
    assert_eq!(
        reference.fields.len(),
        coverage.reviewed_intent_assignment_required_count
    );
    assert_eq!(
        reference.reference_baseline, coverage.reference_baseline,
        "reference and coverage must publish the same unreleased baseline provenance"
    );
    assert_eq!(
        reference.reference_baseline.generator_lifecycle,
        documentation::GeneratorLifecycle::Unreleased
    );
    assert_eq!(
        reference.reference_baseline.field_history_status,
        documentation::FieldHistoryStatus::NotVerified
    );
    assert_eq!(reference.reference_baseline.published_release, None);
    assert_eq!(
        reference.reference_baseline.history_verification_method,
        None
    );
    assert!(reference.reference_baseline.compared_releases.is_empty());
    assert!(reference.fields.iter().all(|field| {
        field.history_status == documentation::FieldHistoryStatus::NotVerified
            && field.introduced_in.is_none()
            && field.version_history.is_empty()
            && field.default.source_version.is_none()
    }));
    let duration_field = |schema, pointer: &str| {
        reference
            .fields
            .iter()
            .find(|field| field.address.schema == schema && field.address.pointer == pointer)
            .unwrap_or_else(|| panic!("{schema} reference contains {pointer}"))
    };
    let freshness = duration_field(
        ConfigurationSchemaKind::Integration,
        "/$defs/capability/oneOf/2/properties/snapshot/properties/freshness",
    );
    assert!(freshness.purpose.contains("31-day ceiling"));
    let entity_refresh = duration_field(
        ConfigurationSchemaKind::Entity,
        "/properties/materialization/properties/refresh",
    );
    assert!(entity_refresh.purpose.contains("no greater than 30 days"));
    for (schema, pointer, maximum, over_ceiling) in [
        (
            ConfigurationSchemaKind::Integration,
            "/$defs/capability/oneOf/2/properties/snapshot/properties/freshness",
            "31d",
            "32d",
        ),
        (
            ConfigurationSchemaKind::Entity,
            "/properties/materialization/properties/refresh/oneOf/1",
            "30d",
            "31d",
        ),
    ] {
        let field = duration_field(schema, pointer);
        let pattern = field
            .constraints
            .iter()
            .find(|constraint| constraint.keyword == "pattern")
            .map(|constraint| constraint.value.clone())
            .unwrap_or_else(|| panic!("{schema}#{pointer} publishes its duration pattern"));
        let validator = compile_schema(&json!({"type": "string", "pattern": pattern}));
        assert!(
            validator.is_valid(&json!(maximum)),
            "{schema}#{pointer} reference must accept its product-owned ceiling"
        );
        assert!(
            !validator.is_valid(&json!(over_ceiling)),
            "{schema}#{pointer} reference must reject an over-ceiling duration"
        );
    }
    assert_eq!(
        (
            reference
                .fields
                .iter()
                .filter(|field| field.empty_behavior == documentation::EmptyBehavior::Allowed)
                .count(),
            reference
                .fields
                .iter()
                .filter(|field| field.empty_behavior == documentation::EmptyBehavior::Rejected)
                .count(),
            reference
                .fields
                .iter()
                .filter(|field| {
                    field.empty_behavior == documentation::EmptyBehavior::Conditional
                })
                .count(),
            reference
                .fields
                .iter()
                .filter(|field| {
                    field.empty_behavior == documentation::EmptyBehavior::NotApplicable
                })
                .count(),
        ),
        (528, 315, 0, 992),
        "the exact empty-string semantic coverage prevents constrained strings from regressing to allowed"
    );
    assert_eq!(
        reference
            .fields
            .iter()
            .filter(|field| {
                field.empty_behavior == documentation::EmptyBehavior::Rejected
                    && !field.constraints.iter().any(|constraint| {
                        constraint.keyword == "minLength"
                            && constraint
                                .value
                                .as_u64()
                                .is_some_and(|minimum| minimum >= 1)
                    })
            })
            .count(),
        214,
        "schema semantics must retain rejections that the former minLength-only heuristic missed"
    );
    let intent_counts =
        reference
            .fields
            .iter()
            .fold(BTreeMap::<&str, usize>::new(), |mut counts, field| {
                *counts.entry(field.purpose.as_str()).or_default() += 1;
                counts
            });
    assert_eq!(coverage.distinct_reviewed_intent_count, intent_counts.len());
    assert_eq!(
        coverage.distinct_reviewed_intents_reused_count,
        intent_counts.values().filter(|count| **count > 1).count()
    );
    assert_eq!(
        coverage.reviewed_intent_assignments_using_reused_intent_count,
        intent_counts
            .values()
            .filter(|count| **count > 1)
            .sum::<usize>()
    );
    for removed in [
        "/$defs/recordAttributeReleaseProfile/properties/subject/properties/input",
        "/$defs/recordAttributeReleaseProfile/properties/response",
        "/$defs/recordAttributeReleaseProfile/properties/response/properties/max_age_seconds",
    ] {
        assert!(
            reference.fields.iter().all(|field| {
                field.address.schema != ConfigurationSchemaKind::Project
                    || field.address.pointer != removed
            }),
            "removed project path {removed} must not survive in the reference"
        );
    }
    for removed in [
        "datasets[].entities[].attribute_release_profiles[].claims[].shareable",
        "datasets[].entities[].attribute_release_profiles[].release_conditions.denied_code",
        "datasets[].entities[].attribute_release_profiles[].response.max_age_seconds",
        "datasets[].entities[].attribute_release_profiles[].subject.cardinality",
        "datasets[].entities[].attribute_release_profiles[].subject.input",
    ] {
        assert!(
            reference.fields.iter().all(|field| {
                field.address.schema != ConfigurationSchemaKind::Relay
                    || field.address.key_path.as_deref() != Some(removed)
            }),
            "removed Relay path {removed} must not survive in the reference"
        );
    }
    for (pointer, required_prose) in [
        (
            "/$defs/recordsApi/properties/required_principal_filters",
            "must be empty when attribute-release profiles are configured",
        ),
        (
            "/$defs/recordsApi/properties/pagination/properties/max_limit",
            "must be at least 2 when attribute-release profiles are configured",
        ),
        (
            "/$defs/recordAttributeReleaseProfile/properties/version",
            "portable path-segment version matching [A-Za-z0-9][A-Za-z0-9._-]{0,63}",
        ),
        (
            "/$defs/recordAttributeReleaseProfile/properties/purpose",
            "bounded visible-ASCII header token",
        ),
        (
            "/$defs/recordAttributeReleaseProfile/properties/release_scope",
            "exact entity-bound <entity_id>:identity_release scope",
        ),
        (
            "/$defs/recordAttributeReleaseProfile/properties/subject",
            "projected source field and identifier type",
        ),
        (
            "/$defs/recordAttributeReleaseProfile/properties/subject/properties/source_field",
            "projected entity field whose value is matched for exact-one subject resolution",
        ),
    ] {
        let field = reference
            .fields
            .iter()
            .find(|field| {
                field.address.schema == ConfigurationSchemaKind::Project
                    && field.address.pointer == pointer
            })
            .unwrap_or_else(|| panic!("project reference contains {pointer}"));
        assert!(
            field.purpose.contains(required_prose),
            "project path {pointer} must explain {required_prose:?}, got {:?}",
            field.purpose
        );
        assert!(
            !field.purpose.contains("request input"),
            "project path {pointer} must not describe the removed request input"
        );
    }
    assert!(
        reference
            .fields
            .iter()
            .all(|field| !field.example.contains_country_values),
        "all configuration documentation entries remain value-free"
    );
    assert!(
        reference.fields.iter().all(|field| {
            let runtime = matches!(
                field.address.schema,
                ConfigurationSchemaKind::Relay | ConfigurationSchemaKind::Notary
            );
            runtime == field.address.key_path.is_some()
                && (field.address.pointer.is_empty() || field.address.pointer.starts_with('/'))
        }),
        "runtime entries keep their configuration key path separate from the authoritative JSON Schema pointer"
    );
    let reference_value = serde_json::to_value(&reference).expect("reference serializes");
    let reference_schema = compile_schema(&read_json(
        crate_root()
            .join("schemas/project-documentation")
            .join("registry.project.configuration_reference.v1.schema.json"),
    ));
    assert_valid(
        &reference_schema,
        &reference_value,
        "embedded configuration reference",
    );
    let mut fabricated_history = reference_value.clone();
    fabricated_history["fields"][0]["introduced_in"] = json!("0.13.0");
    assert!(
        reference_schema.validate(&fabricated_history).is_err(),
        "not-verified history cannot carry a fabricated introduced version"
    );
    let mut missing_runtime_key_path = reference_value;
    let runtime_field = missing_runtime_key_path["fields"]
        .as_array_mut()
        .expect("reference fields are an array")
        .iter_mut()
        .find(|field| field["address"]["schema"] == "relay")
        .expect("embedded reference has Relay fields");
    runtime_field["address"]
        .as_object_mut()
        .expect("field address is an object")
        .remove("key_path");
    assert!(
        reference_schema.validate(&missing_runtime_key_path).is_err(),
        "the strict reference contract requires a runtime key path separately from the schema pointer"
    );
}

#[test]
fn coverage_gate_reports_drift_instead_of_deriving_prose_from_a_field_name() {
    let catalog = miniature_catalog();
    let mut document = miniature_schema();
    document["properties"]["mode"]
        .as_object_mut()
        .expect("mode is an object")
        .remove("description");
    let schema = [DocumentationSchema {
        published: PublishedSchema {
            kind: SchemaKind::Project,
            document: &document,
        },
        source_name: "project.schema.json",
    }];
    let intent = miniature_intent();

    let coverage = configuration_reference_coverage(&catalog, &schema, &intent)
        .expect("coverage report remains available when prose is missing");
    assert_eq!(coverage.reviewed_intent_assignment_required_count, 3);
    assert_eq!(coverage.reviewed_intent_assignment_covered_count, 2);
    assert_eq!(coverage.missing_intent.len(), 1);
    assert_eq!(coverage.missing_intent[0].pointer, "/properties/mode");
    assert!(generate_configuration_reference(&catalog, &schema, &intent)
        .expect_err("reference generation fails closed")
        .to_string()
        .contains("project#/properties/mode"));
}

#[test]
fn structural_taxonomy_requires_exact_path_reviews_and_rejects_invalid_reviews() {
    let catalog = miniature_structural_catalog();
    let document = miniature_schema_with_unreviewed_structural_paths();
    let schema = [DocumentationSchema {
        published: PublishedSchema {
            kind: SchemaKind::Project,
            document: &document,
        },
        source_name: "project.schema.json",
    }];
    let mut intent = miniature_intent();

    let coverage = configuration_reference_coverage(&catalog, &schema, &intent)
        .expect("unreviewed structural paths produce an incomplete coverage report");
    assert_eq!(coverage.reviewed_intent_assignment_required_count, 10);
    assert_eq!(coverage.reviewed_intent_assignment_covered_count, 6);
    assert_eq!(
        coverage
            .missing_intent
            .iter()
            .map(|address| (address.pointer.as_str(), address.path_kind))
            .collect::<BTreeMap<_, _>>(),
        [
            (
                "/properties/structural_choice/not",
                FieldPathKind::Branch,
            ),
            (
                "/properties/structural_list/items",
                FieldPathKind::ArrayItem,
            ),
            (
                "/properties/structural_map/additionalProperties",
                FieldPathKind::MapValue,
            ),
            (
                "/properties/structural_map/propertyNames",
                FieldPathKind::MapKey,
            ),
        ]
        .into_iter()
        .collect(),
        "generic taxonomy prose cannot silently cover a new branch, array item, map key, or map value"
    );
    assert!(generate_configuration_reference(&catalog, &schema, &intent).is_err());

    intent.structural_reviews = miniature_structural_reviews();
    let reviewed = generate_configuration_reference(&catalog, &schema, &intent)
        .expect("exact reviewed structural addresses unlock shared taxonomy prose");
    assert_eq!(reviewed.fields.len(), 10);
    assert_eq!(
        reviewed
            .fields
            .iter()
            .filter(|field| matches!(
                field.address.path_kind,
                FieldPathKind::MapKey
                    | FieldPathKind::MapValue
                    | FieldPathKind::ArrayItem
                    | FieldPathKind::Branch
            ))
            .filter(|field| field.purpose_source == HumanIntentSource::StructuralTaxonomy)
            .count(),
        4
    );

    let mut duplicate = miniature_intent();
    duplicate.structural_reviews = miniature_structural_reviews();
    let duplicate_review = duplicate.structural_reviews[0].clone();
    duplicate.structural_reviews.push(duplicate_review);
    assert!(
        configuration_reference_coverage(&catalog, &schema, &duplicate)
            .expect_err("duplicate exact structural review fails closed")
            .to_string()
            .contains("duplicate structural review")
    );

    let mut mismatched = miniature_intent();
    mismatched.structural_reviews = miniature_structural_reviews();
    mismatched.structural_reviews[0].path_kind = FieldPathKind::Branch;
    assert!(
        configuration_reference_coverage(&catalog, &schema, &mismatched)
            .expect_err("declared structural kind must match the schema path")
            .to_string()
            .contains("schema path is MapKey")
    );

    let mut unknown = miniature_intent();
    unknown.structural_reviews = vec![StructuralIntentReview {
        schema: SchemaKind::Project,
        pointer: "/properties/not_reviewed/items".to_owned(),
        path_kind: FieldPathKind::ArrayItem,
    }];
    assert!(
        configuration_reference_coverage(&catalog, &schema, &unknown)
            .expect_err("review of an unknown structural path fails closed")
            .to_string()
            .contains("targets unknown path")
    );

    let mut nonstructural = miniature_intent();
    nonstructural.structural_reviews = vec![StructuralIntentReview {
        schema: SchemaKind::Project,
        pointer: "/properties/version".to_owned(),
        path_kind: FieldPathKind::Property,
    }];
    assert!(
        configuration_reference_coverage(&catalog, &schema, &nonstructural)
            .expect_err("nonstructural review kind fails closed")
            .to_string()
            .contains("must use a structural path kind")
    );
}

#[test]
fn runtime_intent_requires_exact_assignments_and_new_paths_cannot_inherit_profiles() {
    let intent: RuntimeIntentCatalog = serde_json::from_value(read_json(
        crate_root().join("../registry-relay/config/documentation-intent.json"),
    ))
    .expect("Relay runtime intent parses");
    let document = registry_relay::config::schema::document();
    assert_eq!(
        runtime_configuration_intent_gaps(&document, &intent)
            .expect("current Relay runtime intent is exact"),
        []
    );

    let mut expanded = document.clone();
    expanded["properties"]["unreviewed_runtime_field"] = json!({
        "type": "string",
        "description": "A newly introduced Relay runtime field that has not received product-owned intent review."
    });
    let gaps = runtime_configuration_intent_gaps(&expanded, &intent)
        .expect("coverage remains reportable for an unassigned new runtime path");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].schema, ConfigurationSchemaKind::Relay);
    assert_eq!(gaps[0].pointer, "/properties/unreviewed_runtime_field");
    assert_eq!(
        gaps[0].key_path.as_deref(),
        Some("unreviewed_runtime_field")
    );
    assert_eq!(gaps[0].path_kind, FieldPathKind::Property);

    let mut duplicate = intent.clone();
    duplicate.assignments.push(duplicate.assignments[0].clone());
    assert!(runtime_configuration_intent_gaps(&document, &duplicate)
        .expect_err("duplicate runtime assignment fails closed")
        .to_string()
        .contains("duplicate"));

    let mut unknown_profile = intent.clone();
    unknown_profile.assignments[0].profile = "unreviewed_profile".to_owned();
    assert!(
        runtime_configuration_intent_gaps(&document, &unknown_profile)
            .expect_err("unknown runtime profile fails closed")
            .to_string()
            .contains("unknown profile")
    );

    let mut wrong_schema = intent.clone();
    wrong_schema.assignments[0].schema = ConfigurationSchemaKind::Notary;
    assert!(runtime_configuration_intent_gaps(&document, &wrong_schema)
        .expect_err("wrong runtime schema identity fails closed")
        .to_string()
        .contains("wrong product schema"));

    let mut stale_key_path = intent.clone();
    stale_key_path.assignments[0].key_path = "unreviewed_runtime_field".to_owned();
    assert!(
        runtime_configuration_intent_gaps(&document, &stale_key_path)
            .expect_err("stale runtime key path fails closed")
            .to_string()
            .contains("stale key path")
    );

    let mut stale_pointer = intent.clone();
    stale_pointer.assignments[0].pointer = "/properties/unreviewed_runtime_field".to_owned();
    assert!(runtime_configuration_intent_gaps(&document, &stale_pointer)
        .expect_err("stale runtime schema pointer fails closed")
        .to_string()
        .contains("stale pointer"));

    let map_assignment = intent
        .assignments
        .iter()
        .find(|assignment| assignment.path_kind == FieldPathKind::MapValue)
        .expect("Relay publishes reviewed open maps");
    let mut missing_map_semantics = intent.clone();
    missing_map_semantics
        .profiles
        .iter_mut()
        .find(|profile| profile.id == map_assignment.profile)
        .expect("open-map profile exists")
        .open_map_semantics = None;
    assert!(
        runtime_configuration_intent_gaps(&document, &missing_map_semantics)
            .expect_err("open map without exact extension semantics fails closed")
            .to_string()
            .contains("lacks exact extension semantics")
    );

    let mut cross_product_diagnostic = intent.clone();
    cross_product_diagnostic.profiles[0].diagnostic = "registry.notary.config.invalid".to_owned();
    assert!(
        runtime_configuration_intent_gaps(&document, &cross_product_diagnostic)
            .expect_err("cross-product diagnostic code fails closed")
            .to_string()
            .contains("cross-product diagnostic code")
    );

    let mut wrong_kind = intent;
    wrong_kind.assignments[0].path_kind = FieldPathKind::Branch;
    assert!(runtime_configuration_intent_gaps(&document, &wrong_kind)
        .expect_err("wrong runtime path kind fails closed")
        .to_string()
        .contains("wrong path kind"));
}
