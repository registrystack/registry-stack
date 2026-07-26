// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::OnceLock;

use jsonschema::error::ValidationErrorKind;
use jsonschema::output::BasicOutput;

/// A safe authoring-boundary failure.
///
/// This type intentionally records only locations and validation classes. It
/// never retains the rejected instance, authored scalar values, or the
/// `jsonschema` error because those can contain country configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthoringDocumentError {
    Syntax {
        line: Option<usize>,
        column: Option<usize>,
    },
    Schema {
        instance_path: String,
        schema_path: String,
        keyword: &'static str,
        reserved_fixture_body: bool,
        unsafe_authored_path: bool,
        line: Option<usize>,
        column: Option<usize>,
    },
    TypedModel {
        kind: ProjectSchemaKind,
    },
}

impl AuthoringDocumentError {
    const fn is_syntax(&self) -> bool {
        matches!(self, Self::Syntax { .. })
    }

    const fn keyword(&self) -> Option<&'static str> {
        match self {
            Self::Schema { keyword, .. } => Some(keyword),
            Self::Syntax { .. } | Self::TypedModel { .. } => None,
        }
    }

    fn instance_path(&self) -> Option<&str> {
        match self {
            Self::Schema { instance_path, .. } if !instance_path.is_empty() => {
                Some(instance_path)
            }
            Self::Schema { .. } | Self::Syntax { .. } | Self::TypedModel { .. } => None,
        }
    }

    const fn location(&self) -> (Option<usize>, Option<usize>) {
        match self {
            Self::Syntax { line, column } => (*line, *column),
            Self::Schema { line, column, .. } => (*line, *column),
            Self::TypedModel { .. } => (None, None),
        }
    }

    fn set_location(&mut self, line: Option<usize>, column: Option<usize>) {
        if let Self::Schema {
            line: schema_line,
            column: schema_column,
            ..
        } = self
        {
            *schema_line = line;
            *schema_column = column;
        }
    }

    const fn is_reserved_fixture_body(&self) -> bool {
        matches!(
            self,
            Self::Schema {
                reserved_fixture_body: true,
                ..
            }
        )
    }

    const fn is_unsafe_authored_path(&self) -> bool {
        matches!(
            self,
            Self::Schema {
                unsafe_authored_path: true,
                ..
            }
        )
    }
}

impl fmt::Display for AuthoringDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { line, column } => {
                write!(formatter, "invalid authored YAML syntax")?;
                if let (Some(line), Some(column)) = (line, column) {
                    write!(formatter, " at line {line}, column {column}")?;
                }
                Ok(())
            }
            Self::Schema {
                unsafe_authored_path: true,
                ..
            } => {
                write!(
                    formatter,
                    "authored path must be normalized and cannot traverse"
                )?;
                write_safe_location(formatter, self)
            }
            Self::Schema {
                schema_path,
                keyword: "additionalProperties",
                ..
            } => {
                write!(
                    formatter,
                    "authored document contains an unknown field and failed canonical schema \
                     validation"
                )?;
                write_safe_location(formatter, self)?;
                write!(
                    formatter,
                    ": schema_path={schema_path} keyword=additionalProperties"
                )
            }
            Self::Schema {
                schema_path,
                keyword,
                ..
            } => {
                write!(
                    formatter,
                    "authored document failed canonical schema validation"
                )?;
                write_safe_location(formatter, self)?;
                write!(
                    formatter,
                    ": schema_path={schema_path} keyword={keyword}"
                )
            }
            Self::TypedModel { kind } => write!(
                formatter,
                "canonical {} schema accepted a document the typed authoring model rejected",
                kind.name()
            ),
        }
    }
}

impl std::error::Error for AuthoringDocumentError {}

fn write_safe_location(
    formatter: &mut fmt::Formatter<'_>,
    error: &AuthoringDocumentError,
) -> fmt::Result {
    if let (Some(line), Some(column)) = error.location() {
        write!(formatter, " at line {line}, column {column}")?;
    }
    Ok(())
}

static PROJECT_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();
static ENVIRONMENT_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();
static INTEGRATION_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();
static FIXTURE_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();
static ENTITY_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();
static FIXTURE_BODY_VALIDATOR: OnceLock<jsonschema::JSONSchema> = OnceLock::new();

fn validator(kind: ProjectSchemaKind) -> Result<&'static jsonschema::JSONSchema> {
    let slot = match kind {
        ProjectSchemaKind::Project => &PROJECT_VALIDATOR,
        ProjectSchemaKind::Environment => &ENVIRONMENT_VALIDATOR,
        ProjectSchemaKind::Integration => &INTEGRATION_VALIDATOR,
        ProjectSchemaKind::Fixture => &FIXTURE_VALIDATOR,
        ProjectSchemaKind::Entity => &ENTITY_VALIDATOR,
    };
    if let Some(validator) = slot.get() {
        return Ok(validator);
    }
    let schema: Value = serde_json::from_str(kind.document())
        .with_context(|| format!("embedded {} authoring schema is invalid JSON", kind.name()))?;
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .map_err(|_| anyhow!("embedded {} authoring schema is invalid", kind.name()))?;
    // A racing thread may initialize the same byte-identical schema first.
    let _ = slot.set(compiled);
    slot.get()
        .ok_or_else(|| anyhow!("embedded {} authoring schema is unavailable", kind.name()))
}

fn validation_keyword(kind: &ValidationErrorKind) -> &'static str {
    match kind {
        ValidationErrorKind::AdditionalItems { .. } => "additionalItems",
        ValidationErrorKind::AdditionalProperties { .. } => "additionalProperties",
        ValidationErrorKind::AnyOf => "anyOf",
        ValidationErrorKind::BacktrackLimitExceeded { .. } => "pattern",
        ValidationErrorKind::Constant { .. } => "const",
        ValidationErrorKind::Contains => "contains",
        ValidationErrorKind::ContentEncoding { .. } => "contentEncoding",
        ValidationErrorKind::ContentMediaType { .. } => "contentMediaType",
        ValidationErrorKind::Custom { .. } => "custom",
        ValidationErrorKind::Enum { .. } => "enum",
        ValidationErrorKind::ExclusiveMaximum { .. } => "exclusiveMaximum",
        ValidationErrorKind::ExclusiveMinimum { .. } => "exclusiveMinimum",
        ValidationErrorKind::FalseSchema => "false",
        ValidationErrorKind::FileNotFound { .. }
        | ValidationErrorKind::InvalidReference { .. }
        | ValidationErrorKind::InvalidURL { .. }
        | ValidationErrorKind::JSONParse { .. }
        | ValidationErrorKind::Resolver { .. }
        | ValidationErrorKind::Schema
        | ValidationErrorKind::UnknownReferenceScheme { .. }
        | ValidationErrorKind::Utf8 { .. } => "schema",
        ValidationErrorKind::Format { .. } => "format",
        ValidationErrorKind::FromUtf8 { .. } => "contentEncoding",
        ValidationErrorKind::MaxItems { .. } => "maxItems",
        ValidationErrorKind::Maximum { .. } => "maximum",
        ValidationErrorKind::MaxLength { .. } => "maxLength",
        ValidationErrorKind::MaxProperties { .. } => "maxProperties",
        ValidationErrorKind::MinItems { .. } => "minItems",
        ValidationErrorKind::Minimum { .. } => "minimum",
        ValidationErrorKind::MinLength { .. } => "minLength",
        ValidationErrorKind::MinProperties { .. } => "minProperties",
        ValidationErrorKind::MultipleOf { .. } => "multipleOf",
        ValidationErrorKind::Not { .. } => "not",
        ValidationErrorKind::OneOfMultipleValid | ValidationErrorKind::OneOfNotValid => "oneOf",
        ValidationErrorKind::Pattern { .. } => "pattern",
        ValidationErrorKind::PropertyNames { .. } => "propertyNames",
        ValidationErrorKind::Required { .. } => "required",
        ValidationErrorKind::Type { .. } => "type",
        ValidationErrorKind::UnevaluatedProperties { .. } => "unevaluatedProperties",
        ValidationErrorKind::UniqueItems => "uniqueItems",
    }
}

fn is_reserved_fixture_body_path(kind: ProjectSchemaKind, instance_path: &str) -> bool {
    if kind != ProjectSchemaKind::Fixture {
        return false;
    }
    let mut segments = instance_path.split('/').skip(1);
    let candidate = matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some("interactions"), Some(index), Some("expect" | "respond"))
            if index.parse::<usize>().is_ok()
    );
    candidate && matches!(segments.next(), None | Some("body"))
}

fn fixture_body_validator() -> Result<&'static jsonschema::JSONSchema> {
    if let Some(validator) = FIXTURE_BODY_VALIDATOR.get() {
        return Ok(validator);
    }
    let schema: Value = serde_json::from_str(ProjectSchemaKind::Fixture.document())
        .context("embedded fixture authoring schema is invalid JSON")?;
    let body_schema = schema
        .pointer("/$defs/fixtureBody")
        .cloned()
        .ok_or_else(|| anyhow!("embedded fixture authoring schema has no fixtureBody definition"))?;
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&body_schema)
        .map_err(|_| anyhow!("embedded fixtureBody authoring schema is invalid"))?;
    let _ = FIXTURE_BODY_VALIDATOR.set(compiled);
    FIXTURE_BODY_VALIDATOR
        .get()
        .ok_or_else(|| anyhow!("embedded fixtureBody authoring schema is unavailable"))
}

fn fixture_body_uses_reserved_file_key(
    kind: ProjectSchemaKind,
    instance_path: &str,
    document: &Value,
) -> bool {
    if kind != ProjectSchemaKind::Fixture {
        return false;
    }
    let selected_body = if is_reserved_fixture_body_path(kind, instance_path) {
        let mut segments = instance_path.split('/').skip(1);
        let _interactions = segments.next();
        segments
            .next()
            .and_then(|segment| segment.parse::<usize>().ok())
            .zip(segments.next())
            .and_then(|(index, side)| {
                document
                    .get("interactions")
                    .and_then(|interactions| interactions.get(index))
                    .and_then(|interaction| interaction.get(side))
                    .and_then(|message| message.get("body"))
            })
    } else {
        None
    };
    let body_is_invalid_reserved_reference = |body: &Value| {
        body.as_object()
            .is_some_and(|object| object.contains_key("file"))
            && fixture_body_validator().is_ok_and(|validator| !validator.is_valid(body))
    };
    if selected_body.is_some_and(body_is_invalid_reserved_reference) {
        return true;
    }
    document
        .get("interactions")
        .and_then(Value::as_array)
        .is_some_and(|interactions| {
            interactions.iter().any(|interaction| {
                ["expect", "respond"].iter().any(|side| {
                    interaction
                        .get(side)
                        .and_then(|message| message.get("body"))
                        .is_some_and(body_is_invalid_reserved_reference)
                })
            })
        })
}

fn is_unsafe_authored_path_constraint(
    kind: ProjectSchemaKind,
    schema_path: &str,
) -> bool {
    let authored_path_definition = match kind {
        ProjectSchemaKind::Project | ProjectSchemaKind::Integration => "relativePath",
        ProjectSchemaKind::Environment => "absolutePath",
        ProjectSchemaKind::Fixture | ProjectSchemaKind::Entity => return false,
    };
    let Some((constraint_parent, _keyword)) = schema_path.rsplit_once('/') else {
        return false;
    };
    if constraint_parent == format!("/$defs/{authored_path_definition}") {
        return true;
    }
    let Ok(schema) = serde_json::from_str::<Value>(kind.document()) else {
        return false;
    };
    schema
        .pointer(constraint_parent)
        .and_then(|node| node.get("$ref"))
        .and_then(Value::as_str)
        == Some(format!("#/$defs/{authored_path_definition}").as_str())
}

fn schema_validation_error(
    kind: ProjectSchemaKind,
    document: &Value,
    error: jsonschema::ValidationError<'_>,
    instance_path: String,
) -> AuthoringDocumentError {
    let schema_path = error.schema_path.to_string();
    let unsafe_authored_path = is_unsafe_authored_path_constraint(kind, &schema_path);
    let reserved_fixture_body =
        fixture_body_uses_reserved_file_key(kind, &instance_path, document);
    AuthoringDocumentError::Schema {
        instance_path,
        schema_path,
        keyword: validation_keyword(&error.kind),
        reserved_fixture_body,
        unsafe_authored_path,
        line: None,
        column: None,
    }
}

fn most_specific_validation_instance_path(
    validator: &jsonschema::JSONSchema,
    document: &Value,
) -> Option<String> {
    let BasicOutput::Invalid(errors) = validator.apply(document).basic() else {
        return None;
    };
    errors
        .iter()
        .map(|error| error.instance_location().to_string())
        .max_by(|left, right| {
            left.matches('/')
                .count()
                .cmp(&right.matches('/').count())
                .then_with(|| left.len().cmp(&right.len()))
                .then_with(|| right.as_bytes().cmp(left.as_bytes()))
        })
}

fn escape_json_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn project_target_request_mapping_validation_instance_path(
    services: &serde_json::Map<String, Value>,
    definitions: &Value,
) -> Option<String> {
    let mut mapping_schema = definitions.get("targetRequestMapping")?.clone();
    let mapping_schema_object = mapping_schema.as_object_mut()?;
    mapping_schema_object.insert(
        "$schema".to_string(),
        Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
    );
    mapping_schema_object.insert("$defs".to_string(), definitions.clone());
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&mapping_schema)
        .ok()?;

    for (service_id, service) in services {
        let Some(consultations) = service.get("consultations").and_then(Value::as_object) else {
            continue;
        };
        for (consultation_id, consultation) in consultations {
            let Some(inputs) = consultation.get("input").and_then(Value::as_object) else {
                continue;
            };
            for (input_id, mapping) in inputs {
                if !validator.is_valid(mapping) {
                    return Some(format!(
                        "/services/{}/consultations/{}/input/{}",
                        escape_json_pointer_segment(service_id),
                        escape_json_pointer_segment(consultation_id),
                        escape_json_pointer_segment(input_id),
                    ));
                }
            }
        }
    }
    None
}

fn project_service_validation_instance_path(document: &Value) -> Option<String> {
    let services = document.get("services")?.as_object()?;
    let root_schema: Value = serde_json::from_str(ProjectSchemaKind::Project.document()).ok()?;
    let definitions = root_schema.get("$defs")?.clone();
    if let Some(pointer) =
        project_target_request_mapping_validation_instance_path(services, &definitions)
    {
        return Some(pointer);
    }
    for (service_id, service) in services {
        let branch = match service.get("kind").and_then(Value::as_str) {
            Some("evidence") => "evidenceService",
            Some("records_api") => "recordsService",
            Some(_) => {
                return Some(format!(
                    "/services/{}/kind",
                    escape_json_pointer_segment(service_id)
                ));
            }
            None => continue,
        };
        let mut branch_schema = definitions.get(branch)?.clone();
        let branch_object = branch_schema.as_object_mut()?;
        branch_object.insert(
            "$schema".to_string(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
        );
        branch_object.insert("$defs".to_string(), definitions.clone());
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&branch_schema)
            .ok()?;
        if validator.is_valid(service) {
            continue;
        }
        let nested = most_specific_validation_instance_path(&validator, service)
            .or_else(|| {
                validator
                    .validate(service)
                    .err()
                    .and_then(|mut errors| errors.next())
                    .map(|error| error.instance_path.to_string())
            })
            .unwrap_or_default();
        return Some(format!(
            "/services/{}{}",
            escape_json_pointer_segment(service_id),
            nested
        ));
    }
    None
}

fn parse_authoring_value(
    bytes: &[u8],
    kind: ProjectSchemaKind,
) -> std::result::Result<Value, AuthoringDocumentError> {
    let yaml: serde_norway::Value = serde_norway::from_slice(bytes).map_err(|error| {
        let location = error.location();
        AuthoringDocumentError::Syntax {
            line: location.as_ref().map(serde_norway::Location::line),
            column: location.as_ref().map(serde_norway::Location::column),
        }
    })?;
    let value =
        serde_json::to_value(yaml).map_err(|_| AuthoringDocumentError::Syntax {
            line: None,
            column: None,
        })?;
    let validator = validator(kind).map_err(|_| AuthoringDocumentError::Schema {
        instance_path: String::new(),
        schema_path: String::new(),
        keyword: "schema",
        reserved_fixture_body: false,
        unsafe_authored_path: false,
        line: None,
        column: None,
    })?;
    if let Err(mut errors) = validator.validate(&value) {
        let error = errors.next().expect("schema validation returned an error");
        let collapsed_project_union = kind == ProjectSchemaKind::Project
            && matches!(&error.kind, ValidationErrorKind::OneOfNotValid);
        let instance_path = if collapsed_project_union {
            project_service_validation_instance_path(&value)
        } else {
            None
        }
        .unwrap_or_else(|| error.instance_path.to_string());
        return Err(schema_validation_error(kind, &value, error, instance_path));
    }
    Ok(value)
}

trait CurrentAuthoringDocument: DeserializeOwned {
    const KIND: ProjectSchemaKind;
}

impl CurrentAuthoringDocument for RegistryProject {
    const KIND: ProjectSchemaKind = ProjectSchemaKind::Project;
}

impl CurrentAuthoringDocument for EnvironmentDocument {
    const KIND: ProjectSchemaKind = ProjectSchemaKind::Environment;
}

impl CurrentAuthoringDocument for AuthoredIntegrationDocument {
    const KIND: ProjectSchemaKind = ProjectSchemaKind::Integration;
}

impl CurrentAuthoringDocument for AuthoredFixtureDocument {
    const KIND: ProjectSchemaKind = ProjectSchemaKind::Fixture;
}

impl CurrentAuthoringDocument for EntityDefinition {
    const KIND: ProjectSchemaKind = ProjectSchemaKind::Entity;
}

fn parse_current_authoring_document<T: CurrentAuthoringDocument>(
    bytes: &[u8],
) -> std::result::Result<T, AuthoringDocumentError> {
    let value = match parse_authoring_value(bytes, T::KIND) {
        Ok(value) => value,
        Err(mut error) => {
            if matches!(&error, AuthoringDocumentError::Schema { .. }) {
                if let Err(typed_error) = serde_norway::from_slice::<T>(bytes) {
                    let location = typed_error.location();
                    error.set_location(
                        location.as_ref().map(serde_norway::Location::line),
                        location.as_ref().map(serde_norway::Location::column),
                    );
                }
            }
            return Err(error);
        }
    };
    serde_json::from_value(value).map_err(|_| AuthoringDocumentError::TypedModel { kind: T::KIND })
}

#[cfg(test)]
fn assert_current_authoring_value_reaches_typed_model(
    kind: ProjectSchemaKind,
    value: Value,
) -> std::result::Result<(), AuthoringDocumentError> {
    validator(kind)
        .map_err(|_| AuthoringDocumentError::Schema {
            instance_path: String::new(),
            schema_path: String::new(),
            keyword: "schema",
            reserved_fixture_body: false,
            unsafe_authored_path: false,
            line: None,
            column: None,
        })?
        .validate(&value)
        .map_err(|mut errors| {
            let error = errors.next().expect("schema validation returned an error");
            let instance_path = error.instance_path.to_string();
            schema_validation_error(kind, &value, error, instance_path)
        })?;
    match kind {
        ProjectSchemaKind::Project => {
            serde_json::from_value::<RegistryProject>(value).map(drop)
        }
        ProjectSchemaKind::Environment => {
            serde_json::from_value::<EnvironmentDocument>(value).map(drop)
        }
        ProjectSchemaKind::Integration => {
            serde_json::from_value::<AuthoredIntegrationDocument>(value).map(drop)
        }
        ProjectSchemaKind::Fixture => {
            serde_json::from_value::<AuthoredFixtureDocument>(value).map(drop)
        }
        ProjectSchemaKind::Entity => {
            serde_json::from_value::<EntityDefinition>(value).map(drop)
        }
    }
    .map_err(|_| AuthoringDocumentError::TypedModel { kind })
}

#[cfg(test)]
mod schema_authority_tests {
    use super::*;

    const SUPPORTED_SCHEMA_KEYWORDS: &[&str] = &[
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "$comment",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "default",
        "deprecated",
        "description",
        "else",
        "enum",
        "examples",
        "exclusiveMaximum",
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
        "readOnly",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
        "writeOnly",
        "x-registry-field",
    ];

    fn dto_schema(kind: ProjectSchemaKind) -> Value {
        let schema = match kind {
            ProjectSchemaKind::Project => schemars::schema_for!(RegistryProject),
            ProjectSchemaKind::Environment => schemars::schema_for!(EnvironmentDocument),
            ProjectSchemaKind::Integration => {
                schemars::schema_for!(AuthoredIntegrationDocument)
            }
            ProjectSchemaKind::Fixture => schemars::schema_for!(AuthoredFixtureDocument),
            ProjectSchemaKind::Entity => schemars::schema_for!(EntityDefinition),
        };
        serde_json::to_value(schema).expect("mechanically derived DTO schema serializes")
    }

    fn dto_rust_root(kind: ProjectSchemaKind) -> &'static str {
        match kind {
            ProjectSchemaKind::Project => "RegistryProject",
            ProjectSchemaKind::Environment => "EnvironmentDocument",
            ProjectSchemaKind::Integration => "AuthoredIntegrationDocument",
            ProjectSchemaKind::Fixture => "AuthoredFixtureDocument",
            ProjectSchemaKind::Entity => "EntityDefinition",
        }
    }

    fn generated_dto_shape_contract() -> Vec<u8> {
        let roots = ProjectSchemaKind::ALL
            .into_iter()
            .map(|kind| {
                json!({
                    "kind": kind.name(),
                    "rust_type": dto_rust_root(kind),
                    "schema": dto_schema(kind),
                })
            })
            .collect::<Vec<_>>();
        let contract = json!({
            "contract": "registryctl.dto-shape-contract",
            "version": 1,
            "generator": {
                "name": "schemars",
                "version": "1.2.1",
                "draft": "https://json-schema.org/draft/2020-12/schema"
            },
            "roots": roots
        });
        let mut bytes =
            serde_json::to_vec_pretty(&contract).expect("DTO shape contract serializes");
        bytes.push(b'\n');
        bytes
    }

    const DTO_SHAPE_CONTRACT_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schemas/project-authoring/dto-shape-contract.v1.json"
    );

    #[test]
    #[ignore = "explicit maintainer regeneration; the byte-exact check runs by default"]
    fn regenerate_dto_shape_contract_from_five_rust_roots() {
        std::fs::write(DTO_SHAPE_CONTRACT_PATH, generated_dto_shape_contract())
            .expect("DTO shape contract writes");
    }

    #[test]
    fn committed_dto_shape_contract_is_byte_exact_generated_output() {
        assert!(
            include_str!("../../../../Cargo.toml")
                .lines()
                .any(|line| line.trim() == r#"schemars = { version = "=1.2.1" }"#),
            "DTO contract generator metadata must match the exact workspace schemars pin"
        );
        let committed = include_bytes!(
            "../../schemas/project-authoring/dto-shape-contract.v1.json"
        )
        .as_slice();
        let generated = generated_dto_shape_contract();
        assert!(
            committed == generated,
            "run `cargo test -p registryctl --lib \
             project_authoring::schema_authority_tests::\
             regenerate_dto_shape_contract_from_five_rust_roots \
             -- --ignored --exact` and review the complete DTO-shape diff \
             (committed bytes: {}, generated bytes: {})",
            committed.len(),
            generated.len()
        );
    }

    fn audit_schema_node(
        node: &Value,
        root: &Value,
        address: &str,
        visited_refs: &mut BTreeSet<String>,
        visited_nodes: &mut BTreeSet<String>,
    ) -> std::result::Result<(), String> {
        if let Value::Bool(_) = node {
            visited_nodes.insert(address.to_string());
            return Ok(());
        }
        let object = node
            .as_object()
            .ok_or_else(|| format!("{address}: schema node is neither object nor boolean"))?;
        visited_nodes.insert(address.to_string());
        for keyword in object.keys() {
            if !SUPPORTED_SCHEMA_KEYWORDS.contains(&keyword.as_str()) {
                return Err(format!("{address}: unsupported schema keyword {keyword}"));
            }
        }
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            if !reference.starts_with("#/") {
                return Err(format!("{address}: only local references are supported"));
            }
            let narrowing_siblings = object.keys().filter(|keyword| {
                !matches!(
                    keyword.as_str(),
                    "$ref"
                        | "$comment"
                        | "default"
                        | "deprecated"
                        | "description"
                        | "examples"
                        | "readOnly"
                        | "title"
                        | "writeOnly"
                        | "x-registry-field"
                )
            });
            if let Some(keyword) = narrowing_siblings.into_iter().next() {
                return Err(format!(
                    "{address}: $ref sibling {keyword} is not included in the containment proof"
                ));
            }
            let target = root
                .pointer(&reference[1..])
                .ok_or_else(|| format!("{address}: unresolved local reference {reference}"))?;
            if visited_refs.insert(reference.to_string()) {
                audit_schema_node(
                    target,
                    root,
                    &format!("{address}->$ref({reference})"),
                    visited_refs,
                    visited_nodes,
                )?;
            }
        }
        for container in ["$defs", "properties"] {
            if let Some(children) = object.get(container) {
                let children = children
                    .as_object()
                    .ok_or_else(|| format!("{address}/{container}: expected object"))?;
                for (name, child) in children {
                    audit_schema_node(
                        child,
                        root,
                        &format!("{address}/{container}/{name}"),
                        visited_refs,
                        visited_nodes,
                    )?;
                }
            }
        }
        for keyword in [
            "additionalProperties",
            "else",
            "if",
            "items",
            "not",
            "propertyNames",
            "then",
        ] {
            if let Some(child) = object.get(keyword) {
                audit_schema_node(
                    child,
                    root,
                    &format!("{address}/{keyword}"),
                    visited_refs,
                    visited_nodes,
                )?;
            }
        }
        for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(children) = object.get(keyword) {
                let children = children
                    .as_array()
                    .ok_or_else(|| format!("{address}/{keyword}: expected array"))?;
                if keyword != "prefixItems" && children.is_empty() {
                    return Err(format!("{address}/{keyword}: empty union is unsupported"));
                }
                for (index, child) in children.iter().enumerate() {
                    audit_schema_node(
                        child,
                        root,
                        &format!("{address}/{keyword}/{index}"),
                        visited_refs,
                        visited_nodes,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn resolve<'a>(
        mut node: &'a Value,
        root: &'a Value,
    ) -> std::result::Result<&'a Value, String> {
        let mut seen = BTreeSet::new();
        while let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            if !reference.starts_with("#/") || !seen.insert(reference) {
                return Err(format!("unsupported or cyclic local reference {reference}"));
            }
            node = root
                .pointer(&reference[1..])
                .ok_or_else(|| format!("unresolved local reference {reference}"))?;
        }
        Ok(node)
    }

    fn alternatives(node: &Value) -> Option<&Vec<Value>> {
        node.get("oneOf")
            .or_else(|| node.get("anyOf"))
            .and_then(Value::as_array)
    }

    fn has_base_shape(node: &Value) -> bool {
        [
            "type",
            "const",
            "enum",
            "properties",
            "additionalProperties",
            "propertyNames",
            "required",
            "minProperties",
            "maxProperties",
            "items",
            "prefixItems",
            "minItems",
            "maxItems",
            "uniqueItems",
            "minLength",
            "maxLength",
            "pattern",
            "format",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "not",
        ]
            .iter()
            .any(|keyword| node.get(*keyword).is_some())
    }

    fn json_type(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    fn type_set(node: &Value) -> BTreeSet<&str> {
        if let Some(types) = node.get("type") {
            return match types {
                Value::String(kind) => BTreeSet::from([kind.as_str()]),
                Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
                _ => BTreeSet::new(),
            };
        }
        if let Some(value) = node.get("const") {
            return BTreeSet::from([json_type(value)]);
        }
        node.get("enum")
            .and_then(Value::as_array)
            .map(|values| values.iter().map(json_type).collect())
            .unwrap_or_default()
    }

    fn accepted_literals(node: &Value) -> Option<BTreeSet<String>> {
        if let Some(value) = node.get("const") {
            return Some(BTreeSet::from([value.to_string()]));
        }
        node.get("enum")
            .and_then(Value::as_array)
            .map(|values| values.iter().map(Value::to_string).collect())
    }

    fn additional_schema(node: &Value) -> Value {
        node.get("additionalProperties")
            .cloned()
            .unwrap_or(Value::Bool(true))
    }

    #[derive(Clone, Copy, Debug)]
    enum ExactNumber {
        Integer(i128),
        Float(f64),
    }

    impl ExactNumber {
        fn from_value(value: &Value) -> Option<Self> {
            let number = value.as_number()?;
            if let Some(value) = number.as_i64() {
                return Some(Self::Integer(i128::from(value)));
            }
            if let Some(value) = number.as_u64() {
                return Some(Self::Integer(i128::from(value)));
            }
            number.as_f64().map(Self::Float)
        }

        fn compare(self, other: Self) -> Option<std::cmp::Ordering> {
            match (self, other) {
                (Self::Integer(left), Self::Integer(right)) => Some(left.cmp(&right)),
                (Self::Float(left), Self::Float(right)) => left.partial_cmp(&right),
                // Do not round an integer through f64. A mixed representation is
                // uncommon in these derived DTOs and cannot establish containment
                // without an exact decimal implementation, so fail closed.
                (Self::Integer(_), Self::Float(_))
                | (Self::Float(_), Self::Integer(_)) => None,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct NumericBound {
        value: ExactNumber,
        exclusive: bool,
    }

    fn stronger_lower(
        left: NumericBound,
        right: NumericBound,
    ) -> Option<NumericBound> {
        match left.value.compare(right.value)? {
            std::cmp::Ordering::Greater => Some(left),
            std::cmp::Ordering::Less => Some(right),
            std::cmp::Ordering::Equal if left.exclusive => Some(left),
            std::cmp::Ordering::Equal => Some(right),
        }
    }

    fn stronger_upper(
        left: NumericBound,
        right: NumericBound,
    ) -> Option<NumericBound> {
        match left.value.compare(right.value)? {
            std::cmp::Ordering::Less => Some(left),
            std::cmp::Ordering::Greater => Some(right),
            std::cmp::Ordering::Equal if left.exclusive => Some(left),
            std::cmp::Ordering::Equal => Some(right),
        }
    }

    fn format_bounds(
        format: Option<&str>,
    ) -> (Option<NumericBound>, Option<NumericBound>) {
        let inclusive = |value| {
            Some(NumericBound {
                value: ExactNumber::Integer(value),
                exclusive: false,
            })
        };
        match format {
            Some("uint8") => (inclusive(0), inclusive(i128::from(u8::MAX))),
            Some("uint16") => (inclusive(0), inclusive(i128::from(u16::MAX))),
            Some("uint32") => (inclusive(0), inclusive(i128::from(u32::MAX))),
            Some("uint64") => (inclusive(0), inclusive(i128::from(u64::MAX))),
            Some("int8") => (
                inclusive(i128::from(i8::MIN)),
                inclusive(i128::from(i8::MAX)),
            ),
            Some("int16") => (
                inclusive(i128::from(i16::MIN)),
                inclusive(i128::from(i16::MAX)),
            ),
            Some("int32") => (
                inclusive(i128::from(i32::MIN)),
                inclusive(i128::from(i32::MAX)),
            ),
            Some("int64") => (
                inclusive(i128::from(i64::MIN)),
                inclusive(i128::from(i64::MAX)),
            ),
            _ => (None, None),
        }
    }

    fn literal_numeric_bounds(
        node: &Value,
    ) -> (Option<NumericBound>, Option<NumericBound>) {
        let mut lower = None;
        let mut upper = None;
        for value in node.get("const").into_iter().chain(
            node.get("enum")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        ) {
            let Some(value) = ExactNumber::from_value(value) else {
                continue;
            };
            let bound = NumericBound {
                value,
                exclusive: false,
            };
            lower = match lower {
                Some(current) => stronger_upper(current, bound),
                None => Some(bound),
            };
            upper = match upper {
                Some(current) => stronger_lower(current, bound),
                None => Some(bound),
            };
        }
        (lower, upper)
    }

    fn combine_lower(
        left: Option<NumericBound>,
        right: Option<NumericBound>,
    ) -> Option<NumericBound> {
        match (left, right) {
            (Some(left), Some(right)) => stronger_lower(left, right),
            (bound @ Some(_), None) | (None, bound @ Some(_)) => bound,
            (None, None) => None,
        }
    }

    fn combine_upper(
        left: Option<NumericBound>,
        right: Option<NumericBound>,
    ) -> Option<NumericBound> {
        match (left, right) {
            (Some(left), Some(right)) => stronger_upper(left, right),
            (bound @ Some(_), None) | (None, bound @ Some(_)) => bound,
            (None, None) => None,
        }
    }

    fn lower_bound(node: &Value) -> Option<NumericBound> {
        let inclusive = node
            .get("minimum")
            .and_then(ExactNumber::from_value)
            .map(|value| NumericBound {
                value,
                exclusive: false,
            });
        let exclusive = node
            .get("exclusiveMinimum")
            .and_then(ExactNumber::from_value)
            .map(|value| NumericBound {
                value,
                exclusive: true,
            });
        let format = format_bounds(node.get("format").and_then(Value::as_str)).0;
        let literal = literal_numeric_bounds(node).0;
        combine_lower(combine_lower(inclusive, exclusive), combine_lower(format, literal))
    }

    fn upper_bound(node: &Value) -> Option<NumericBound> {
        let inclusive = node
            .get("maximum")
            .and_then(ExactNumber::from_value)
            .map(|value| NumericBound {
                value,
                exclusive: false,
            });
        let exclusive = node
            .get("exclusiveMaximum")
            .and_then(ExactNumber::from_value)
            .map(|value| NumericBound {
                value,
                exclusive: true,
            });
        let format = format_bounds(node.get("format").and_then(Value::as_str)).1;
        let literal = literal_numeric_bounds(node).1;
        combine_upper(combine_upper(inclusive, exclusive), combine_upper(format, literal))
    }

    fn lower_is_at_least(published: NumericBound, dto: NumericBound) -> bool {
        match published.value.compare(dto.value) {
            Some(std::cmp::Ordering::Greater) => true,
            Some(std::cmp::Ordering::Equal) => {
                published.exclusive || !dto.exclusive
            }
            Some(std::cmp::Ordering::Less) | None => false,
        }
    }

    fn upper_is_at_most(published: NumericBound, dto: NumericBound) -> bool {
        match published.value.compare(dto.value) {
            Some(std::cmp::Ordering::Less) => true,
            Some(std::cmp::Ordering::Equal) => {
                published.exclusive || !dto.exclusive
            }
            Some(std::cmp::Ordering::Greater) | None => false,
        }
    }

    fn unsigned_constraint(node: &Value, keyword: &str) -> Option<u64> {
        node.get(keyword).and_then(Value::as_u64)
    }

    fn prove_scalar_constraints(
        published: &Value,
        dto: &Value,
        address: &str,
    ) -> std::result::Result<(), String> {
        if let Some(dto_lower) = lower_bound(dto) {
            let published_lower = lower_bound(published).ok_or_else(|| {
                format!("{address}: DTO has a lower numeric bound but the published schema does not")
            })?;
            if !lower_is_at_least(published_lower, dto_lower) {
                return Err(format!(
                    "{address}: published lower numeric bound is weaker than the DTO"
                ));
            }
        }
        if let Some(dto_upper) = upper_bound(dto) {
            let published_upper = upper_bound(published).ok_or_else(|| {
                format!("{address}: DTO has an upper numeric bound but the published schema does not")
            })?;
            if !upper_is_at_most(published_upper, dto_upper) {
                return Err(format!(
                    "{address}: published upper numeric bound is weaker than the DTO"
                ));
            }
        }
        for (minimum, maximum) in [
            ("minLength", "maxLength"),
            ("minItems", "maxItems"),
            ("minProperties", "maxProperties"),
        ] {
            if let Some(dto_minimum) = unsigned_constraint(dto, minimum) {
                let published_minimum =
                    unsigned_constraint(published, minimum).unwrap_or(0);
                if published_minimum < dto_minimum {
                    return Err(format!(
                        "{address}: published {minimum} {published_minimum} is weaker than DTO {dto_minimum}"
                    ));
                }
            }
            if let Some(dto_maximum) = unsigned_constraint(dto, maximum) {
                let published_maximum =
                    unsigned_constraint(published, maximum).unwrap_or(u64::MAX);
                if published_maximum > dto_maximum {
                    return Err(format!(
                        "{address}: published {maximum} {published_maximum} is weaker than DTO {dto_maximum}"
                    ));
                }
            }
        }
        if dto.get("uniqueItems").and_then(Value::as_bool) == Some(true)
            && published.get("uniqueItems").and_then(Value::as_bool) != Some(true)
        {
            return Err(format!(
                "{address}: DTO requires uniqueItems but the published schema does not"
            ));
        }
        if let Some(dto_pattern) = dto.get("pattern").and_then(Value::as_str) {
            let exact_pattern =
                published.get("pattern").and_then(Value::as_str) == Some(dto_pattern);
            let literals_match = accepted_literals(published).is_some_and(|literals| {
                regex::Regex::new(dto_pattern).is_ok_and(|pattern| {
                    literals.iter().all(|literal| {
                        serde_json::from_str::<Value>(literal)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_string))
                            .is_some_and(|value| pattern.is_match(&value))
                    })
                })
            });
            if !exact_pattern && !literals_match {
                return Err(format!(
                    "{address}: DTO pattern is not matched exactly by the published schema"
                ));
            }
        }
        if let Some(dto_format) = dto.get("format").and_then(Value::as_str) {
            let numeric_format = matches!(
                dto_format,
                "int8"
                    | "int16"
                    | "int32"
                    | "int64"
                    | "uint8"
                    | "uint16"
                    | "uint32"
                    | "uint64"
                    | "float"
                    | "double"
            );
            if !numeric_format
                && published.get("format").and_then(Value::as_str) != Some(dto_format)
            {
                return Err(format!(
                    "{address}: DTO format {dto_format} is absent or different in the published schema"
                ));
            }
        }
        Ok(())
    }

    fn prove_contained(
        published: &Value,
        dto: &Value,
        published_root: &Value,
        dto_root: &Value,
        address: &str,
        active: &mut BTreeSet<(usize, usize)>,
    ) -> std::result::Result<(), String> {
        let published = resolve(published, published_root)?;
        let dto = resolve(dto, dto_root)?;
        if published == &Value::Bool(false) || dto == &Value::Bool(true) {
            return Ok(());
        }
        if published == &Value::Bool(true) {
            return (dto == &Value::Bool(true))
                .then_some(())
                .ok_or_else(|| format!("{address}: unconstrained published value exceeds DTO"));
        }
        if dto == &Value::Bool(false) {
            return Err(format!("{address}: non-empty published language exceeds false DTO"));
        }

        let identity = (published as *const Value as usize, dto as *const Value as usize);
        if !active.insert(identity) {
            return Ok(());
        }
        let result = prove_contained_inner(
            published,
            dto,
            published_root,
            dto_root,
            address,
            active,
        );
        active.remove(&identity);
        result
    }

    fn schema_without(node: &Value, keywords: &[&str]) -> Value {
        let mut node = node.clone();
        if let Some(object) = node.as_object_mut() {
            for keyword in keywords {
                object.remove(*keyword);
            }
        }
        node
    }

    fn array_allows_index(node: &Value, index: usize) -> bool {
        effective_max_items(node)
            .is_none_or(|maximum| (index as u128) < u128::from(maximum))
    }

    fn effective_max_items(node: &Value) -> Option<u64> {
        let explicit = unsigned_constraint(node, "maxItems");
        let closed_prefix =
            (node.get("items") == Some(&Value::Bool(false))).then(|| {
                node.get("prefixItems")
                    .and_then(Value::as_array)
                    .map_or(0, |prefix| prefix.len() as u64)
            });
        match (explicit, closed_prefix) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (maximum @ Some(_), None) | (None, maximum @ Some(_)) => maximum,
            (None, None) => None,
        }
    }

    fn prove_array_items(
        published: &Value,
        dto: &Value,
        published_root: &Value,
        dto_root: &Value,
        address: &str,
        active: &mut BTreeSet<(usize, usize)>,
    ) -> std::result::Result<(), String> {
        let published_prefix = published
            .get("prefixItems")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let dto_prefix = dto
            .get("prefixItems")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let unconstrained_published_items = Value::Bool(true);
        let unconstrained_dto_items = Value::Bool(true);
        let published_items = published
            .get("items")
            .unwrap_or(&unconstrained_published_items);
        let dto_items = dto.get("items").unwrap_or(&unconstrained_dto_items);
        if let Some(dto_maximum) = effective_max_items(dto) {
            let published_maximum =
                effective_max_items(published).unwrap_or(u64::MAX);
            if published_maximum > dto_maximum {
                return Err(format!(
                    "{address}: published array can exceed DTO maximum length {dto_maximum}"
                ));
            }
        }
        let explicit_positions = published_prefix.len().max(dto_prefix.len());
        for index in 0..explicit_positions {
            if !array_allows_index(published, index) {
                continue;
            }
            let published_item = published_prefix.get(index).unwrap_or(published_items);
            if published_item == &Value::Bool(false) {
                continue;
            }
            let dto_item = dto_prefix.get(index).unwrap_or(dto_items);
            prove_contained(
                published_item,
                dto_item,
                published_root,
                dto_root,
                &format!("{address}/items/{index}"),
                active,
            )?;
        }
        let tail_index = explicit_positions;
        if array_allows_index(published, tail_index)
            && published_items != &Value::Bool(false)
        {
            prove_contained(
                published_items,
                dto_items,
                published_root,
                dto_root,
                &format!("{address}/items/tail"),
                active,
            )?;
        }
        Ok(())
    }

    fn prove_discriminated_object_union(
        published: &Value,
        branches: &[Value],
        published_root: &Value,
        dto_root: &Value,
        address: &str,
        active: &mut BTreeSet<(usize, usize)>,
    ) -> Option<std::result::Result<(), String>> {
        let published_properties = published.get("properties")?.as_object()?;
        let first_branch = resolve(branches.first()?, dto_root).ok()?;
        let first_properties = first_branch.get("properties")?.as_object()?;
        for discriminator in first_properties.keys() {
            let Some(published_discriminator) = published_properties.get(discriminator) else {
                continue;
            };
            let Ok(published_discriminator) =
                resolve(published_discriminator, published_root)
            else {
                continue;
            };
            let Some(published_literals) =
                accepted_literals(published_discriminator)
            else {
                continue;
            };
            let mut branch_literals = Vec::with_capacity(branches.len());
            let mut every_branch_has_literals = true;
            for branch in branches {
                let property = resolve(branch, dto_root)
                    .ok()
                    .and_then(|branch| branch.get("properties"))
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get(discriminator))
                    .and_then(|property| resolve(property, dto_root).ok())
                    .and_then(accepted_literals);
                let Some(property_literals) = property else {
                    every_branch_has_literals = false;
                    break;
                };
                branch_literals.push(property_literals);
            }
            if !every_branch_has_literals {
                continue;
            }
            let accepted_by_union = branch_literals
                .iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            if !published_literals.is_subset(&accepted_by_union) {
                continue;
            }

            for literal in published_literals {
                let literal_value: Value = serde_json::from_str(&literal).ok()?;
                let mut published_variant = published.clone();
                published_variant["properties"][discriminator.as_str()] =
                    json!({ "const": literal_value });
                let mut failures = Vec::new();
                let mut matched = false;
                for (index, branch) in branches.iter().enumerate() {
                    match prove_contained(
                        &published_variant,
                        branch,
                        published_root,
                        dto_root,
                        &format!(
                            "{address}->dto-discriminator-{discriminator}-branch-{index}"
                        ),
                        active,
                    ) {
                        Ok(()) => {
                            matched = true;
                            break;
                        }
                        Err(error) => failures.push(error),
                    }
                }
                if !matched {
                    return Some(Err(format!(
                        "{address}: discriminator {discriminator} value fits no DTO arm: {}",
                        failures.join(" | ")
                    )));
                }
            }
            return Some(Ok(()));
        }
        None
    }

    fn prove_contained_inner(
        published: &Value,
        dto: &Value,
        published_root: &Value,
        dto_root: &Value,
        address: &str,
        active: &mut BTreeSet<(usize, usize)>,
    ) -> std::result::Result<(), String> {
        if let Some(branches) = alternatives(published) {
            if !has_base_shape(published) {
                for (index, branch) in branches.iter().enumerate() {
                    prove_contained(
                        branch,
                        dto,
                        published_root,
                        dto_root,
                        &format!("{address}->published-branch-{index}"),
                        active,
                    )?;
                }
                return Ok(());
            }
        }
        if let Some(branches) = alternatives(dto) {
            if has_base_shape(dto) {
                let dto_base = schema_without(dto, &["anyOf", "oneOf"]);
                prove_contained(
                    published,
                    &dto_base,
                    published_root,
                    dto_root,
                    &format!("{address}->dto-union-base"),
                    active,
                )?;
            }
            if let Some(result) = prove_discriminated_object_union(
                published,
                branches,
                published_root,
                dto_root,
                address,
                active,
            ) {
                return result;
            }
            let mut failures = Vec::new();
            for (index, branch) in branches.iter().enumerate() {
                match prove_contained(
                    published,
                    branch,
                    published_root,
                    dto_root,
                    &format!("{address}->dto-branch-{index}"),
                    active,
                ) {
                    Ok(()) => return Ok(()),
                    Err(error) => failures.push(error),
                }
            }
            return Err(format!(
                "{address}: published language fits no DTO union arm: {}",
                failures.join(" | ")
            ));
        }
        if let Some(branches) = dto.get("allOf").and_then(Value::as_array) {
            for (index, branch) in branches.iter().enumerate() {
                prove_contained(
                    published,
                    branch,
                    published_root,
                    dto_root,
                    &format!("{address}->dto-allOf-{index}"),
                    active,
                )?;
            }
            let dto_base = schema_without(dto, &["allOf"]);
            prove_contained(
                published,
                &dto_base,
                published_root,
                dto_root,
                &format!("{address}->dto-allOf-base"),
                active,
            )?;
            return Ok(());
        }
        if ["if", "then", "else"]
            .iter()
            .any(|keyword| dto.get(*keyword).is_some())
        {
            return Err(format!(
                "{address}: derived DTO uses an unsupported conditional narrowing keyword"
            ));
        }
        if let Some(dto_not) = dto.get("not") {
            let published_not = published.get("not").ok_or_else(|| {
                format!("{address}: DTO exclusion has no equivalent published exclusion")
            })?;
            prove_contained(
                dto_not,
                published_not,
                dto_root,
                published_root,
                &format!("{address}->reversed-not"),
                active,
            )?;
        } else if published.get("not").is_some() && !has_base_shape(published) {
            return Err(format!(
                "{address}: a published exclusion alone cannot prove containment in a constrained DTO"
            ));
        }
        if let Some(branches) = published.get("allOf").and_then(Value::as_array) {
            if !has_base_shape(published) {
                let mut failures = Vec::new();
                for (index, branch) in branches.iter().enumerate() {
                    match prove_contained(
                        branch,
                        dto,
                        published_root,
                        dto_root,
                        &format!("{address}->published-allOf-{index}"),
                        active,
                    ) {
                        Ok(()) => return Ok(()),
                        Err(error) => failures.push(error),
                    }
                }
                return Err(format!(
                    "{address}: no allOf narrowing arm fits DTO: {}",
                    failures.join(" | ")
                ));
            }
        }

        let published_types = type_set(published);
        let dto_types = type_set(dto);
        if !dto_types.is_empty() && published_types.is_empty() {
            return Err(format!(
                "{address}: unconstrained published type exceeds DTO types {dto_types:?}"
            ));
        }
        if !dto_types.is_empty()
            && !published_types.iter().all(|kind| {
                dto_types.contains(kind)
                    || (*kind == "integer" && dto_types.contains("number"))
            })
        {
            return Err(format!(
                "{address}: published types {published_types:?} exceed DTO types {dto_types:?}"
            ));
        }
        match (accepted_literals(published), accepted_literals(dto)) {
            (Some(published_values), Some(dto_values))
                if !published_values.is_subset(&dto_values) =>
            {
                return Err(format!(
                    "{address}: published literals {published_values:?} exceed DTO literals {dto_values:?}"
                ));
            }
            (None, Some(dto_values)) => {
                return Err(format!(
                    "{address}: unconstrained published literals exceed DTO literals {dto_values:?}"
                ));
            }
            _ => {}
        }
        prove_scalar_constraints(published, dto, address)?;

        if published_types.contains("object")
            || published.get("properties").is_some()
            || published.get("additionalProperties").is_some()
        {
            let published_required = published
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            let dto_required = dto
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            if !dto_required.is_subset(&published_required) {
                return Err(format!(
                    "{address}: DTO requires fields absent from published requirement {:?}",
                    dto_required.difference(&published_required).collect::<Vec<_>>()
                ));
            }
            if let Some(dto_property_names) = dto.get("propertyNames") {
                let unconstrained_property_names = Value::Bool(true);
                let published_property_names = published
                    .get("propertyNames")
                    .unwrap_or(&unconstrained_property_names);
                prove_contained(
                    published_property_names,
                    dto_property_names,
                    published_root,
                    dto_root,
                    &format!("{address}/propertyNames"),
                    active,
                )?;
            }
            let dto_properties = dto
                .get("properties")
                .and_then(Value::as_object);
            let dto_additional = additional_schema(dto);
            if let Some(properties) = published.get("properties").and_then(Value::as_object) {
                for (name, property) in properties {
                    let target = dto_properties
                        .and_then(|properties| properties.get(name))
                        .unwrap_or(&dto_additional);
                    prove_contained(
                        property,
                        target,
                        published_root,
                        dto_root,
                        &format!("{address}/properties/{name}"),
                        active,
                    )?;
                }
            }
            let published_additional = additional_schema(published);
            if published_additional != Value::Bool(false) {
                prove_contained(
                    &published_additional,
                    &dto_additional,
                    published_root,
                    dto_root,
                    &format!("{address}/additionalProperties"),
                    active,
                )?;
            }
        }
        if published_types.contains("array")
            || published.get("items").is_some()
            || published.get("prefixItems").is_some()
        {
            prove_array_items(
                published,
                dto,
                published_root,
                dto_root,
                address,
                active,
            )?;
        }
        Ok(())
    }

    fn maintained_document(kind: ProjectSchemaKind) -> &'static [u8] {
        match kind {
            ProjectSchemaKind::Project => PROJECT_STARTERS
                .get_file("bounded-http/registry-stack.yaml")
                .expect("bounded HTTP project is embedded")
                .contents(),
            ProjectSchemaKind::Environment => PROJECT_STARTERS
                .get_file("bounded-http/environments/local.yaml")
                .expect("bounded HTTP environment is embedded")
                .contents(),
            ProjectSchemaKind::Integration => PROJECT_STARTERS
                .get_file("bounded-http/integrations/person-record/integration.yaml")
                .expect("bounded HTTP integration is embedded")
                .contents(),
            ProjectSchemaKind::Fixture => PROJECT_STARTERS
                .get_file(
                    "bounded-http/integrations/person-record/fixtures/active.yaml",
                )
                .expect("bounded HTTP fixture is embedded")
                .contents(),
            ProjectSchemaKind::Entity => SNAPSHOT_STARTER
                .get_file("entities/people.yaml")
                .expect("SnapshotExact entity is embedded")
                .contents(),
        }
    }

    #[test]
    fn canonical_schema_language_is_structurally_contained_by_derived_dtos() {
        for kind in ProjectSchemaKind::ALL {
            let published: Value = serde_json::from_str(kind.document())
                .unwrap_or_else(|error| panic!("{} schema parses: {error}", kind.name()));
            let dto = dto_schema(kind);
            let mut published_refs = BTreeSet::new();
            let mut published_nodes = BTreeSet::new();
            audit_schema_node(
                &published,
                &published,
                kind.name(),
                &mut published_refs,
                &mut published_nodes,
            )
            .unwrap_or_else(|error| panic!("{} published inventory: {error}", kind.name()));
            let mut dto_refs = BTreeSet::new();
            let mut dto_nodes = BTreeSet::new();
            audit_schema_node(
                &dto,
                &dto,
                &format!("{}-dto", kind.name()),
                &mut dto_refs,
                &mut dto_nodes,
            )
            .unwrap_or_else(|error| panic!("{} DTO inventory: {error}", kind.name()));
            assert!(
                !published_nodes.is_empty() && !dto_nodes.is_empty(),
                "{} inventories both finite structural languages",
                kind.name()
            );
            prove_contained(
                &published,
                &dto,
                &published,
                &dto,
                kind.name(),
                &mut BTreeSet::new(),
            )
            .unwrap_or_else(|error| panic!("{} containment failed: {error}", kind.name()));
        }
    }

    #[test]
    fn containment_proof_fails_closed_on_every_soundness_boundary() {
        let prove = |published: Value, dto: Value| {
            prove_contained(
                &published,
                &dto,
                &published,
                &dto,
                "negative-control",
                &mut BTreeSet::new(),
            )
        };

        prove(
            json!({"oneOf": [{"type": "string"}, {"type": "integer", "minimum": 0, "maximum": 10}]}),
            json!({"oneOf": [{"type": "integer", "minimum": 0, "maximum": 10}, {"type": "string"}]}),
        )
        .expect("different published union arms may fit different DTO arms");
        assert!(prove(
            json!({"type": "integer", "minimum": 0, "maximum": 300}),
            json!({"type": "integer", "format": "uint8", "minimum": 0, "maximum": 255}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "array"}),
            json!({"type": "array", "items": {"type": "string"}}),
        )
        .is_err());
        assert!(prove(
            json!({"const": "a"}),
            json!({"allOf": [{"type": "string"}, {"const": "b"}]}),
        )
        .is_err());
        assert!(prove(json!({"type": "string"}), json!({"enum": ["a", "b"]})).is_err());
        assert!(prove(json!({}), json!({"type": "string"})).is_err());
        assert!(prove(
            json!({"type": "string"}),
            json!({"type": "string", "not": {"const": "blocked"}}),
        )
        .is_err());

        let tuple = json!({
            "type": "array",
            "prefixItems": [{"type": "string"}]
        });
        assert!(audit_schema_node(
            &tuple,
            &tuple,
            "tuple",
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
        )
        .is_ok());
        assert!(prove(
            json!({
                "type": "array",
                "prefixItems": [{"type": "integer"}],
                "items": false,
                "minItems": 1,
                "maxItems": 1
            }),
            json!({
                "type": "array",
                "prefixItems": [{"type": "string"}],
                "items": false,
                "minItems": 1,
                "maxItems": 1
            }),
        )
        .is_err());
        assert!(prove(
            json!({"type": "string", "maxLength": 32}),
            json!({"type": "string", "maxLength": 16}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "array", "maxItems": 4}),
            json!({"type": "array", "maxItems": 4, "uniqueItems": true}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "object", "maxProperties": 8}),
            json!({"type": "object", "maxProperties": 4}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "object"}),
            json!({"type": "object", "propertyNames": {"pattern": "^[a-z]+$"}}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "array", "minItems": 1}),
            json!({"type": "array", "minItems": 2}),
        )
        .is_err());
        assert!(prove(
            json!({"type": "string", "pattern": "^[a-z]+$"}),
            json!({"type": "string", "pattern": "^[a-z][a-z0-9]+$"}),
        )
        .is_err());
        assert!(prove(
            json!({
                "type": "array",
                "prefixItems": [{"type": "string"}],
                "items": {"type": "string"}
            }),
            json!({
                "type": "array",
                "prefixItems": [{"type": "string"}],
                "items": false
            }),
        )
        .is_err());

        prove(
            json!({"type": "integer", "minimum": 0, "maximum": u64::MAX}),
            json!({"type": "integer", "format": "uint64"}),
        )
        .expect("u64 maximum is compared without f64 rounding");
        assert!(prove(
            json!({"type": "integer", "minimum": 0, "maximum": u64::MAX}),
            json!({"type": "integer", "minimum": 0, "maximum": u64::MAX - 1}),
        )
        .is_err());
        prove(
            json!({"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX}),
            json!({"type": "integer", "format": "int64"}),
        )
        .expect("i64 endpoints are compared exactly");
        assert!(prove(
            json!({"type": "integer", "minimum": i64::MIN, "maximum": i64::MAX}),
            json!({"type": "integer", "minimum": i64::MIN + 1, "maximum": i64::MAX}),
        )
        .is_err());

        let narrowed_ref_sibling = json!({
            "$defs": {"text": {"type": "string"}},
            "$ref": "#/$defs/text",
            "minLength": 1
        });
        assert!(audit_schema_node(
            &narrowed_ref_sibling,
            &narrowed_ref_sibling,
            "ref-sibling",
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
        )
        .is_err());
    }

    #[test]
    fn default_and_deprecation_policy_is_exact_and_runtime_defaults_are_equivalent() {
        let mut defaults = Vec::new();
        let mut deprecated = Vec::new();
        for kind in ProjectSchemaKind::ALL {
            let schema: Value = serde_json::from_str(kind.document()).expect("schema parses");
            collect_keyword_addresses(&schema, "", "default", &mut defaults);
            collect_keyword_addresses(&schema, "", "deprecated", &mut deprecated);
        }
        defaults.sort();
        assert_eq!(
            defaults,
            [
                "/$defs/integrationRequestByteSize",
                "/$defs/integrationResponseByteSize",
                "/$defs/integrationSourceByteSize",
                "/$defs/oid4vci/properties/tx_code/properties/required",
                "/properties/issuance/properties/algorithm",
            ]
        );
        assert!(
            deprecated.is_empty(),
            "deprecated authoring fields require an explicit reviewed inventory and policy"
        );

        let integration_schema: Value =
            serde_json::from_str(ProjectSchemaKind::Integration.document())
                .expect("integration schema parses");
        for (pointer, parser, expected_bytes) in [
            (
                "/$defs/integrationResponseByteSize/default",
                parse_integration_response_bytes as fn(&AuthoredByteSize) -> Result<u64>,
                DEFAULT_INTEGRATION_RESPONSE_BYTES,
            ),
            (
                "/$defs/integrationRequestByteSize/default",
                parse_integration_request_bytes,
                DEFAULT_INTEGRATION_REQUEST_BYTES,
            ),
            (
                "/$defs/integrationSourceByteSize/default",
                parse_integration_source_bytes,
                DEFAULT_INTEGRATION_SOURCE_BYTES,
            ),
        ] {
            let authored: AuthoredByteSize = serde_json::from_value(
                integration_schema
                    .pointer(pointer)
                    .unwrap_or_else(|| panic!("integration schema contains {pointer}"))
                    .clone(),
            )
            .unwrap_or_else(|error| panic!("{pointer} default parses: {error}"));
            assert_eq!(
                parser(&authored).unwrap_or_else(|error| panic!("{pointer} default validates: {error}")),
                expected_bytes,
                "{pointer} matches the runtime default"
            );
        }

        let issuance_omitted: IssuanceBinding = serde_json::from_value(json!({
            "issuer": "https://issuer.invalid",
            "signing_key": {"secret": "ISSUER_KEY"},
            "signing_kid": "issuer-key",
            "generation": 1
        }))
        .expect("omitted issuance algorithm parses");
        let issuance_explicit: IssuanceBinding = serde_json::from_value(json!({
            "issuer": "https://issuer.invalid",
            "signing_key": {"secret": "ISSUER_KEY"},
            "signing_kid": "issuer-key",
            "algorithm": "EdDSA",
            "generation": 1
        }))
        .expect("explicit issuance algorithm parses");
        assert_eq!(
            serde_json::to_value(issuance_omitted).expect("issuance serializes"),
            serde_json::to_value(issuance_explicit).expect("issuance serializes")
        );

        let tx_omitted: Oid4vciTxCodeBinding =
            serde_json::from_value(json!({})).expect("omitted tx-code default parses");
        let tx_explicit: Oid4vciTxCodeBinding = serde_json::from_value(json!({"required": true}))
            .expect("explicit tx-code default parses");
        assert_eq!(
            serde_json::to_value(tx_omitted).expect("tx code serializes"),
            serde_json::to_value(tx_explicit).expect("tx code serializes")
        );
    }

    fn collect_keyword_addresses(
        node: &Value,
        address: &str,
        keyword: &str,
        output: &mut Vec<String>,
    ) {
        let Some(object) = node.as_object() else {
            return;
        };
        if object.contains_key(keyword) {
            output.push(address.to_string());
        }
        for container in ["$defs", "properties"] {
            if let Some(children) = object.get(container).and_then(Value::as_object) {
                for (name, child) in children {
                    collect_keyword_addresses(
                        child,
                        &format!("{address}/{container}/{name}"),
                        keyword,
                        output,
                    );
                }
            }
        }
        for child_keyword in [
            "additionalProperties",
            "else",
            "if",
            "items",
            "not",
            "propertyNames",
            "then",
        ] {
            if let Some(child) = object.get(child_keyword) {
                collect_keyword_addresses(
                    child,
                    &format!("{address}/{child_keyword}"),
                    keyword,
                    output,
                );
            }
        }
        for child_keyword in ["allOf", "anyOf", "oneOf"] {
            if let Some(children) = object.get(child_keyword).and_then(Value::as_array) {
                for (index, child) in children.iter().enumerate() {
                    collect_keyword_addresses(
                        child,
                        &format!("{address}/{child_keyword}/{index}"),
                        keyword,
                        output,
                    );
                }
            }
        }
    }

    #[test]
    fn explicit_ingress_kind_validates_noncanonical_integration_filename() {
        let mut document: Value =
            serde_norway::from_slice(maintained_document(ProjectSchemaKind::Integration))
                .expect("integration fixture parses");
        document["schema_authority_unknown"] = Value::Bool(true);
        let bytes = serde_norway::to_string(&document)
            .expect("mutated integration serializes")
            .into_bytes();
        let error = parse_yaml::<AuthoredIntegrationDocument>(
            &bytes,
            "integrations/person-record/main.yaml",
        )
        .expect_err("canonical integration schema rejects an unknown field");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("unknown field"), "{rendered}");
        assert!(rendered.contains("additionalProperties"), "{rendered}");
        assert!(!rendered.contains("schema_authority_unknown"));
    }

    #[test]
    fn maintained_documents_pass_schema_before_reaching_each_typed_model() {
        for kind in ProjectSchemaKind::ALL {
            let value = parse_authoring_value(maintained_document(kind), kind)
                .unwrap_or_else(|error| panic!("{} schema accepts its example: {error}", kind.name()));
            assert_current_authoring_value_reaches_typed_model(kind, value)
                .unwrap_or_else(|error| panic!("{} DTO accepts its example: {error}", kind.name()));
        }
    }

    #[test]
    fn schema_failure_text_drops_dynamic_instance_paths_and_property_names() {
        let mut value: Value =
            serde_norway::from_slice(maintained_document(ProjectSchemaKind::Project))
                .expect("maintained project parses");
        let services = value["services"]
            .as_object_mut()
            .expect("maintained services is an object");
        let mut service = services
            .remove("person-verification")
            .expect("maintained service exists");
        service["kind"] = json!("country-sentinel-invalid-kind");
        services.insert("country-sensitive-service-sentinel".to_string(), service);
        value["country-sensitive-field-sentinel"] = json!(true);

        let raw_errors = validator(ProjectSchemaKind::Project)
            .expect("project schema compiles")
            .validate(&value)
            .expect_err("planted project is schema-invalid")
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            raw_errors.contains("country-sensitive-service-sentinel")
                || raw_errors.contains("country-sensitive-field-sentinel"),
            "negative control must plant a sentinel in raw validator output"
        );

        let bytes = serde_norway::to_string(&value)
            .expect("planted project serializes")
            .into_bytes();
        let error = parse_authoring_value(&bytes, ProjectSchemaKind::Project)
            .expect_err("planted project is rejected");
        let rendered = error.to_string();
        assert!(!rendered.contains("country-sensitive-service-sentinel"));
        assert!(!rendered.contains("country-sensitive-field-sentinel"));
        assert!(!rendered.contains("country-sentinel-invalid-kind"));
        assert!(!rendered.contains("instance_path"));
    }

    #[test]
    fn authored_path_classification_is_static_and_drops_the_received_path() {
        let mut project: Value =
            serde_norway::from_slice(maintained_document(ProjectSchemaKind::Project))
                .expect("maintained project parses");
        project["integrations"]["person-record"]["file"] =
            json!("../country-sensitive-path-sentinel/integration.yaml");
        let bytes = serde_norway::to_string(&project)
            .expect("invalid project serializes")
            .into_bytes();
        let error = parse_current_authoring_document::<RegistryProject>(&bytes)
            .expect_err("traversing path is rejected by the canonical schema");
        assert!(error.is_unsafe_authored_path(), "{error}");
        let rendered = error.to_string();
        assert!(rendered.contains("cannot traverse"));
        assert!(!rendered.contains("country-sensitive-path-sentinel"));
        assert!(!rendered.contains("instance_path"));
    }

    #[test]
    fn only_exact_fixture_interaction_body_paths_receive_reserved_classification() {
        for (path, expected) in [
            ("/interactions/0/expect/body", true),
            ("/interactions/13/respond/body/file", true),
            ("/interactions/country-key/respond/body", false),
            ("/interactions/0/respond/country-body", false),
            ("/expect/body", false),
        ] {
            assert_eq!(
                is_reserved_fixture_body_path(ProjectSchemaKind::Fixture, path),
                expected,
                "{path}"
            );
            assert!(!is_reserved_fixture_body_path(
                ProjectSchemaKind::Project,
                path
            ));
        }
    }

    #[test]
    fn reserved_fixture_body_classification_requires_the_reserved_file_key() {
        let mut fixture: Value =
            serde_norway::from_slice(maintained_document(ProjectSchemaKind::Fixture))
                .expect("maintained fixture parses");
        fixture["interactions"][0]["respond"]["body"] = json!({
            "file": "bodies/active.json",
            "country-sensitive-extra-field": true
        });
        let bytes = serde_norway::to_string(&fixture)
            .expect("invalid fixture serializes")
            .into_bytes();
        let error = parse_authoring_value(&bytes, ProjectSchemaKind::Fixture)
            .expect_err("ambiguous reserved file-reference shape is rejected");
        assert!(error.is_reserved_fixture_body());
        assert!(!error
            .to_string()
            .contains("country-sensitive-extra-field"));

        fixture["interactions"][0]["respond"]["body"] = json!({
            "file_description": "inline JSON remains an ordinary body"
        });
        let bytes = serde_norway::to_string(&fixture)
            .expect("inline fixture serializes")
            .into_bytes();
        parse_current_authoring_document::<AuthoredFixtureDocument>(&bytes)
        .expect("inline JSON without the reserved file key remains valid");
    }
}
