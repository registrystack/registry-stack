// SPDX-License-Identifier: Apache-2.0
//! Typed, deterministic knowledge attached to the published project-authoring schemas.
//!
//! This module deliberately does not interpret JSON Schema validation keywords. The schema is
//! the validation authority; `x-registry-field` only selects documentation, ownership, review,
//! migration, and redaction knowledge from the closed catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const FIELD_ANNOTATION_KEY: &str = "x-registry-field";
const FIELD_KNOWLEDGE_COVERAGE: &str =
    include_str!("../../schemas/project-authoring/parity-coverage.json");
const PROJECT_SCHEMA: &str = include_str!("../../schemas/project-authoring/project.schema.json");
const ENVIRONMENT_SCHEMA: &str =
    include_str!("../../schemas/project-authoring/environment.schema.json");
const INTEGRATION_SCHEMA: &str =
    include_str!("../../schemas/project-authoring/integration.schema.json");
const FIXTURE_SCHEMA: &str = include_str!("../../schemas/project-authoring/fixture.schema.json");
const ENTITY_SCHEMA: &str = include_str!("../../schemas/project-authoring/entity.schema.json");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaKind {
    Project,
    Environment,
    Integration,
    Fixture,
    Entity,
}

impl fmt::Display for SchemaKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Project => "project",
            Self::Environment => "environment",
            Self::Integration => "integration",
            Self::Fixture => "fixture",
            Self::Entity => "entity",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPathKind {
    Root,
    Property,
    MapKey,
    MapValue,
    ArrayItem,
    Branch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticOwner {
    AuthoringContract,
    DeploymentSecurity,
    IntegrationContract,
    FixtureHarness,
    EntityContract,
    RelayRuntime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
// The suffix is part of the published ownership vocabulary and keeps these
// roles distinct from product and semantic owners.
#[allow(clippy::enum_variant_names)]
pub enum HumanOwner {
    RegistryMaintainers,
    SecurityMaintainers,
    IntegrationMaintainers,
    TestMaintainers,
    DataModelMaintainers,
    RelayMaintainers,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Sensitive,
    SecretReference,
    SecretValue,
    RedactedFixture,
    Structural,
}

impl Sensitivity {
    /// Returns whether a classifier-safe value may enter a value-bearing report.
    ///
    /// Public values are reportable without an extra semantic decision. Internal and structural
    /// values require explicit semantic approval from the producer. Approval can never override
    /// sensitive, secret, or fixture-redaction classifications. Generated field-reference
    /// documentation consumes schemas and this knowledge index, never country configuration
    /// values.
    pub const fn value_is_reportable(self, semantic_approved: bool) -> bool {
        match self {
            Self::Public => true,
            Self::Internal | Self::Structural => semantic_approved,
            Self::Sensitive | Self::SecretReference | Self::SecretValue | Self::RedactedFixture => {
                false
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Registryctl,
    Relay,
    Editor,
    Docs,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Published,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    Experimental,
    Stable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Migration {
    RegenerateEditorSchemas,
    RebuildProject,
    CoordinateDeployment,
    UpdateFixtures,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Consumer {
    RegistryctlAuthoring,
    RegistryRelay,
    EditorTooling,
    DocsGenerator,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedArtifact {
    EditorSchemas,
    ProjectBuild,
    RelayConfig,
    FixtureReport,
    FieldReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClass {
    Contract,
    Security,
    Privacy,
    Relay,
    Compatibility,
    Documentation,
    Testing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRule {
    KnowledgeOnly,
    GeneratedDocsNeverLoadCountryValues,
    SecretNeverReportable,
    SyntheticFixtureValueRedacted,
    SensitiveOperationalMetadata,
    ArbitraryMapKeysNotFixedProperties,
    ArrayItemsShareElementContract,
    BranchHasNoAuthoredValue,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldKnowledgeCatalog {
    pub version: u8,
    pub defaults: FieldKnowledgeDefaults,
    pub schema_domains: Vec<SchemaDomain>,
    pub classifications: Vec<FieldClassification>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldKnowledgeDefaults {
    pub introduced_in: String,
    pub availability: Availability,
    pub stability: Stability,
    pub semantic_rules: Vec<SemanticRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDomain {
    pub schema: SchemaKind,
    pub semantic_owner: SemanticOwner,
    pub human_owner: HumanOwner,
    pub products: Vec<Product>,
    pub migration: Migration,
    pub consumers: Vec<Consumer>,
    pub generated_artifacts: Vec<GeneratedArtifact>,
    pub review_classes: Vec<ReviewClass>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldClassification {
    pub id: String,
    pub path_kind: FieldPathKind,
    pub sensitivity: Sensitivity,
    pub review_classes: Vec<ReviewClass>,
    pub semantic_rules: Vec<SemanticRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldKnowledge {
    pub path_kind: FieldPathKind,
    pub semantic_owner: SemanticOwner,
    pub human_owner: HumanOwner,
    pub sensitivity: Sensitivity,
    pub products: Vec<Product>,
    pub introduced_in: String,
    pub availability: Availability,
    pub stability: Stability,
    pub migration: Migration,
    pub consumers: Vec<Consumer>,
    pub generated_artifacts: Vec<GeneratedArtifact>,
    pub review_classes: Vec<ReviewClass>,
    pub semantic_rules: Vec<SemanticRule>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FieldPath {
    pub schema: SchemaKind,
    /// RFC 6901 pointer to the annotated schema node. The empty string identifies the root.
    pub pointer: String,
}

impl fmt::Display for FieldPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}#{}", self.schema, self.pointer)
    }
}

#[derive(Debug)]
pub struct PublishedSchema<'a> {
    pub kind: SchemaKind,
    pub document: &'a Value,
}

#[derive(Clone, Debug, Default)]
pub struct FieldKnowledgeIndex {
    by_path: BTreeMap<FieldPath, FieldKnowledge>,
    references: BTreeMap<FieldPath, FieldPath>,
}

impl FieldKnowledgeIndex {
    pub fn by_path(&self) -> &BTreeMap<FieldPath, FieldKnowledge> {
        &self.by_path
    }

    pub fn references(&self) -> &BTreeMap<FieldPath, FieldPath> {
        &self.references
    }

    pub fn coverage_by_schema(&self) -> BTreeMap<SchemaKind, usize> {
        let mut counts = BTreeMap::new();
        for path in self.by_path.keys() {
            *counts.entry(path.schema).or_default() += 1;
        }
        counts
    }

    pub fn coverage_by_path_kind(&self) -> BTreeMap<FieldPathKind, usize> {
        let mut counts = BTreeMap::new();
        for knowledge in self.by_path.values() {
            *counts.entry(knowledge.path_kind).or_default() += 1;
        }
        counts
    }

    pub fn coverage_by_sensitivity(&self) -> BTreeMap<Sensitivity, usize> {
        let mut counts = BTreeMap::new();
        for knowledge in self.by_path.values() {
            *counts.entry(knowledge.sensitivity).or_default() += 1;
        }
        counts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldKnowledgeError(String);

impl fmt::Display for FieldKnowledgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FieldKnowledgeError {}

fn knowledge_error(message: impl Into<String>) -> FieldKnowledgeError {
    FieldKnowledgeError(message.into())
}

/// Builds the deterministic field-knowledge index and fails closed on any catalog, annotation,
/// path, or local-reference inconsistency.
pub fn index_published_field_knowledge(
    catalog: &FieldKnowledgeCatalog,
    schemas: &[PublishedSchema<'_>],
) -> Result<FieldKnowledgeIndex, FieldKnowledgeError> {
    if catalog.version != 1 {
        return Err(knowledge_error(format!(
            "unsupported field-knowledge catalog version {}",
            catalog.version
        )));
    }
    validate_introduced_in(&catalog.defaults.introduced_in)?;
    if !catalog
        .defaults
        .semantic_rules
        .contains(&SemanticRule::KnowledgeOnly)
    {
        return Err(knowledge_error(
            "field-knowledge defaults must state that knowledge is not validation authority",
        ));
    }
    if !catalog
        .defaults
        .semantic_rules
        .contains(&SemanticRule::GeneratedDocsNeverLoadCountryValues)
    {
        return Err(knowledge_error(
            "field-knowledge defaults must prohibit generated docs from loading country values",
        ));
    }

    let domains = unique_domains(&catalog.schema_domains)?;
    let classifications = unique_classifications(&catalog.classifications)?;
    let mut index = FieldKnowledgeIndex::default();
    let mut schema_kinds = BTreeSet::new();
    let mut used_classifications = BTreeSet::new();

    for schema in schemas {
        if !schema_kinds.insert(schema.kind) {
            return Err(knowledge_error(format!(
                "duplicate published schema kind: {}",
                schema.kind
            )));
        }
        let domain = domains.get(&schema.kind).ok_or_else(|| {
            knowledge_error(format!(
                "published {} schema has no field-knowledge domain",
                schema.kind
            ))
        })?;
        validate_references(schema, &mut index.references)?;
        walk_schema(schema.document, "", &mut |node, pointer| {
            let path = FieldPath {
                schema: schema.kind,
                pointer: pointer.to_owned(),
            };
            let expected_kind = published_path_kind(pointer);
            let annotation = node.get(FIELD_ANNOTATION_KEY);

            if let Some(object) = node.as_object() {
                if let Some(key) = object.keys().find(|key| {
                    key.starts_with(FIELD_ANNOTATION_KEY) && key.as_str() != FIELD_ANNOTATION_KEY
                }) {
                    return Err(knowledge_error(format!(
                        "{path} uses unknown field annotation keyword {key}"
                    )));
                }
            }

            match (expected_kind, annotation) {
                (None, None) => Ok(()),
                (None, Some(_)) => Err(knowledge_error(format!(
                    "{path} annotates a node that is not a published field, map key/value, array item, or branch"
                ))),
                (Some(kind), None) => Err(knowledge_error(format!(
                    "{path} is a published {kind:?} path without {FIELD_ANNOTATION_KEY}"
                ))),
                (Some(kind), Some(annotation)) => {
                    let classification_id = annotation.as_str().ok_or_else(|| {
                        knowledge_error(format!(
                            "{path} {FIELD_ANNOTATION_KEY} must be a classification string"
                        ))
                    })?;
                    let classification =
                        classifications.get(classification_id).ok_or_else(|| {
                            knowledge_error(format!(
                                "{path} uses unknown field classification {classification_id:?}"
                            ))
                        })?;
                    if classification.path_kind != kind {
                        return Err(knowledge_error(format!(
                            "{path} is {kind:?} but classification {classification_id:?} is {:?}",
                            classification.path_kind
                        )));
                    }
                    validate_classification_rules(path.clone(), classification)?;
                    used_classifications.insert(classification_id.to_owned());
                    let knowledge =
                        resolve_knowledge(&catalog.defaults, domain, classification);
                    if index.by_path.insert(path.clone(), knowledge).is_some() {
                        return Err(knowledge_error(format!(
                            "duplicate field-knowledge path: {path}"
                        )));
                    }
                    Ok(())
                }
            }
        })?;
    }

    let domain_kinds = domains.keys().copied().collect::<BTreeSet<_>>();
    if schema_kinds != domain_kinds {
        return Err(knowledge_error(format!(
            "field-knowledge domains and published schemas differ: schemas={schema_kinds:?}, domains={domain_kinds:?}"
        )));
    }
    let classification_ids = classifications
        .keys()
        .map(|id| (*id).to_owned())
        .collect::<BTreeSet<_>>();
    if used_classifications != classification_ids {
        return Err(knowledge_error(format!(
            "field classifications must be exact and used: used={used_classifications:?}, catalog={classification_ids:?}"
        )));
    }
    Ok(index)
}

/// Parses the embedded release assets and returns the exact index used by report and docs
/// producers. No project or country configuration file is opened by this function.
pub fn published_field_knowledge_index() -> Result<FieldKnowledgeIndex, FieldKnowledgeError> {
    #[derive(Deserialize)]
    struct CoverageAsset {
        field_knowledge: FieldKnowledgeCatalog,
    }

    let coverage: CoverageAsset = serde_json::from_str(FIELD_KNOWLEDGE_COVERAGE)
        .map_err(|error| knowledge_error(format!("embedded field-knowledge catalog: {error}")))?;
    let documents = [
        (SchemaKind::Project, PROJECT_SCHEMA),
        (SchemaKind::Environment, ENVIRONMENT_SCHEMA),
        (SchemaKind::Integration, INTEGRATION_SCHEMA),
        (SchemaKind::Fixture, FIXTURE_SCHEMA),
        (SchemaKind::Entity, ENTITY_SCHEMA),
    ]
    .into_iter()
    .map(|(kind, document)| {
        serde_json::from_str(document)
            .map(|document| (kind, document))
            .map_err(|error| knowledge_error(format!("embedded {kind} authoring schema: {error}")))
    })
    .collect::<Result<Vec<(SchemaKind, Value)>, _>>()?;
    let schemas = documents
        .iter()
        .map(|(kind, document)| PublishedSchema {
            kind: *kind,
            document,
        })
        .collect::<Vec<_>>();
    index_published_field_knowledge(&coverage.field_knowledge, &schemas)
}

/// Returns canonical schema locations reachable from the document root, following only safe local
/// references. Definitions are not treated as authored fields merely because they are declared;
/// they become reachable through a published `$ref`.
pub fn reachable_published_field_paths(
    schema: &PublishedSchema<'_>,
) -> Result<BTreeSet<FieldPath>, FieldKnowledgeError> {
    let mut paths = BTreeSet::new();
    let mut visited = BTreeSet::new();
    walk_reachable_schema(schema, schema.document, "", &mut visited, &mut paths)?;
    Ok(paths)
}

fn walk_reachable_schema(
    schema: &PublishedSchema<'_>,
    node: &Value,
    pointer: &str,
    visited: &mut BTreeSet<String>,
    paths: &mut BTreeSet<FieldPath>,
) -> Result<(), FieldKnowledgeError> {
    if !visited.insert(pointer.to_owned()) {
        return Ok(());
    }
    if published_path_kind(pointer).is_some() {
        paths.insert(FieldPath {
            schema: schema.kind,
            pointer: pointer.to_owned(),
        });
    }
    let Some(object) = node.as_object() else {
        return Ok(());
    };
    if let Some(reference) = object.get("$ref") {
        let reference = reference.as_str().ok_or_else(|| {
            knowledge_error(format!("{}#{pointer} has a non-string $ref", schema.kind))
        })?;
        let target_pointer = reference.strip_prefix('#').ok_or_else(|| {
            knowledge_error(format!(
                "{}#{pointer} uses external $ref {reference:?}",
                schema.kind
            ))
        })?;
        let target = schema.document.pointer(target_pointer).ok_or_else(|| {
            knowledge_error(format!(
                "{}#{pointer} has unresolved local $ref {reference:?}",
                schema.kind
            ))
        })?;
        walk_reachable_schema(schema, target, target_pointer, visited, paths)?;
    }
    for container in ["properties", "dependentSchemas"] {
        if let Some(children) = object.get(container).and_then(Value::as_object) {
            for (name, child) in children {
                let child_pointer =
                    format!("{pointer}/{container}/{}", escape_pointer_segment(name));
                walk_reachable_schema(schema, child, &child_pointer, visited, paths)?;
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
        if let Some(child) = object.get(keyword).filter(|child| child.is_object()) {
            let child_pointer = format!("{pointer}/{keyword}");
            walk_reachable_schema(schema, child, &child_pointer, visited, paths)?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                let child_pointer = format!("{pointer}/{keyword}/{index}");
                walk_reachable_schema(schema, child, &child_pointer, visited, paths)?;
            }
        }
    }
    Ok(())
}

fn unique_domains(
    domains: &[SchemaDomain],
) -> Result<BTreeMap<SchemaKind, &SchemaDomain>, FieldKnowledgeError> {
    let mut indexed = BTreeMap::new();
    for domain in domains {
        if domain.products.is_empty()
            || domain.consumers.is_empty()
            || domain.generated_artifacts.is_empty()
            || domain.review_classes.is_empty()
        {
            return Err(knowledge_error(format!(
                "{} field-knowledge domain has an empty required knowledge set",
                domain.schema
            )));
        }
        if indexed.insert(domain.schema, domain).is_some() {
            return Err(knowledge_error(format!(
                "duplicate field-knowledge domain for {}",
                domain.schema
            )));
        }
    }
    Ok(indexed)
}

fn unique_classifications(
    classifications: &[FieldClassification],
) -> Result<BTreeMap<&str, &FieldClassification>, FieldKnowledgeError> {
    let mut indexed = BTreeMap::new();
    for classification in classifications {
        if classification.id.is_empty()
            || classification.review_classes.is_empty()
            || classification.semantic_rules.is_empty()
        {
            return Err(knowledge_error(
                "field classification id, review_classes, and semantic_rules are required",
            ));
        }
        if indexed
            .insert(classification.id.as_str(), classification)
            .is_some()
        {
            return Err(knowledge_error(format!(
                "duplicate field classification: {}",
                classification.id
            )));
        }
    }
    Ok(indexed)
}

fn validate_introduced_in(version: &str) -> Result<(), FieldKnowledgeError> {
    let parts = version.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(knowledge_error(format!(
            "introduced_in must be a numeric major.minor.patch version, got {version:?}"
        )));
    }
    Ok(())
}

fn validate_classification_rules(
    path: FieldPath,
    classification: &FieldClassification,
) -> Result<(), FieldKnowledgeError> {
    let rules = classification
        .semantic_rules
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required = match classification.path_kind {
        FieldPathKind::MapKey | FieldPathKind::MapValue => {
            Some(SemanticRule::ArbitraryMapKeysNotFixedProperties)
        }
        FieldPathKind::ArrayItem => Some(SemanticRule::ArrayItemsShareElementContract),
        FieldPathKind::Branch => Some(SemanticRule::BranchHasNoAuthoredValue),
        FieldPathKind::Root | FieldPathKind::Property => None,
    };
    if required.is_some_and(|rule| !rules.contains(&rule)) {
        return Err(knowledge_error(format!(
            "{path} classification is missing its path-kind semantic rule"
        )));
    }
    let sensitivity_rule = match classification.sensitivity {
        Sensitivity::SecretReference | Sensitivity::SecretValue => {
            Some(SemanticRule::SecretNeverReportable)
        }
        Sensitivity::RedactedFixture => Some(SemanticRule::SyntheticFixtureValueRedacted),
        Sensitivity::Sensitive => Some(SemanticRule::SensitiveOperationalMetadata),
        Sensitivity::Public | Sensitivity::Internal | Sensitivity::Structural => None,
    };
    if sensitivity_rule.is_some_and(|rule| !rules.contains(&rule)) {
        return Err(knowledge_error(format!(
            "{path} classification is missing its sensitivity semantic rule"
        )));
    }
    Ok(())
}

fn resolve_knowledge(
    defaults: &FieldKnowledgeDefaults,
    domain: &SchemaDomain,
    classification: &FieldClassification,
) -> FieldKnowledge {
    let mut review_classes = domain
        .review_classes
        .iter()
        .chain(&classification.review_classes)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    review_classes.sort();
    let mut semantic_rules = defaults
        .semantic_rules
        .iter()
        .chain(&classification.semantic_rules)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    semantic_rules.sort();
    FieldKnowledge {
        path_kind: classification.path_kind,
        semantic_owner: domain.semantic_owner,
        human_owner: domain.human_owner,
        sensitivity: classification.sensitivity,
        products: sorted_unique(&domain.products),
        introduced_in: defaults.introduced_in.clone(),
        availability: defaults.availability,
        stability: defaults.stability,
        migration: domain.migration,
        consumers: sorted_unique(&domain.consumers),
        generated_artifacts: sorted_unique(&domain.generated_artifacts),
        review_classes,
        semantic_rules,
    }
}

fn sorted_unique<T: Copy + Ord>(values: &[T]) -> Vec<T> {
    values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn published_path_kind(pointer: &str) -> Option<FieldPathKind> {
    if pointer.is_empty() {
        return Some(FieldPathKind::Root);
    }
    let segments = pointer.split('/').skip(1).collect::<Vec<_>>();
    if segments.len() >= 2 && segments[segments.len() - 2] == "properties" {
        return Some(FieldPathKind::Property);
    }
    match segments.last().copied() {
        Some("propertyNames") => Some(FieldPathKind::MapKey),
        Some("additionalProperties") => Some(FieldPathKind::MapValue),
        Some("items") => Some(FieldPathKind::ArrayItem),
        Some("if" | "then" | "else" | "not") => Some(FieldPathKind::Branch),
        Some(_) if segments.len() >= 2 => match segments[segments.len() - 2] {
            "prefixItems" => Some(FieldPathKind::ArrayItem),
            "allOf" | "anyOf" | "oneOf" => Some(FieldPathKind::Branch),
            _ => None,
        },
        _ => None,
    }
}

fn validate_references(
    schema: &PublishedSchema<'_>,
    references: &mut BTreeMap<FieldPath, FieldPath>,
) -> Result<(), FieldKnowledgeError> {
    let mut local = BTreeMap::<String, String>::new();
    walk_schema(schema.document, "", &mut |node, pointer| {
        let Some(reference) = node.get("$ref") else {
            return Ok(());
        };
        let reference = reference.as_str().ok_or_else(|| {
            knowledge_error(format!("{}#{pointer} has a non-string $ref", schema.kind))
        })?;
        let target_pointer = reference.strip_prefix('#').ok_or_else(|| {
            knowledge_error(format!(
                "{}#{pointer} uses external $ref {reference:?}; published authoring schemas permit local references only",
                schema.kind
            ))
        })?;
        if !target_pointer.is_empty() && !target_pointer.starts_with('/') {
            return Err(knowledge_error(format!(
                "{}#{pointer} has malformed local $ref {reference:?}",
                schema.kind
            )));
        }
        let target = schema.document.pointer(target_pointer).ok_or_else(|| {
            knowledge_error(format!(
                "{}#{pointer} has unresolved local $ref {reference:?}",
                schema.kind
            ))
        })?;
        if !target.is_object() {
            return Err(knowledge_error(format!(
                "{}#{pointer} local $ref {reference:?} does not resolve to a schema object",
                schema.kind
            )));
        }
        if local
            .insert(pointer.to_owned(), target_pointer.to_owned())
            .is_some()
        {
            return Err(knowledge_error(format!(
                "{}#{pointer} records a duplicate local reference path",
                schema.kind
            )));
        }
        let from = FieldPath {
            schema: schema.kind,
            pointer: pointer.to_owned(),
        };
        let to = FieldPath {
            schema: schema.kind,
            pointer: target_pointer.to_owned(),
        };
        if references.insert(from.clone(), to).is_some() {
            return Err(knowledge_error(format!(
                "duplicate resolved reference path: {from}"
            )));
        }
        Ok(())
    })?;

    for start in local.keys() {
        let mut seen = BTreeSet::new();
        let mut current = start.as_str();
        while let Some(target) = local.get(current) {
            if !seen.insert(current.to_owned()) {
                return Err(knowledge_error(format!(
                    "{}#{start} participates in a cyclic direct $ref chain",
                    schema.kind
                )));
            }
            current = target;
        }
    }
    Ok(())
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn walk_schema(
    schema: &Value,
    pointer: &str,
    visit: &mut impl FnMut(&Value, &str) -> Result<(), FieldKnowledgeError>,
) -> Result<(), FieldKnowledgeError> {
    visit(schema, pointer)?;
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    for container in ["$defs", "properties", "dependentSchemas"] {
        if let Some(children) = object.get(container).and_then(Value::as_object) {
            for (name, child) in children {
                walk_schema(
                    child,
                    &format!("{pointer}/{container}/{}", escape_pointer_segment(name)),
                    visit,
                )?;
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
            walk_schema(&object[keyword], &format!("{pointer}/{keyword}"), visit)?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(keyword).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                walk_schema(child, &format!("{pointer}/{keyword}/{index}"), visit)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Sensitivity;

    #[test]
    fn reportability_requires_both_safe_sensitivity_and_semantic_approval() {
        assert!(Sensitivity::Public.value_is_reportable(false));
        assert!(Sensitivity::Public.value_is_reportable(true));

        for sensitivity in [Sensitivity::Internal, Sensitivity::Structural] {
            assert!(!sensitivity.value_is_reportable(false));
            assert!(sensitivity.value_is_reportable(true));
        }

        for sensitivity in [
            Sensitivity::Sensitive,
            Sensitivity::SecretReference,
            Sensitivity::SecretValue,
            Sensitivity::RedactedFixture,
        ] {
            assert!(!sensitivity.value_is_reportable(false));
            assert!(!sensitivity.value_is_reportable(true));
        }
    }
}
