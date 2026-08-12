//! Lossless OpenAPI discovery for the local source mock.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context as _, Result};
use chrono::NaiveDate;
use jsonschema::{Draft, JSONSchema};
use registry_evidence_authoring::openapi::{
    openapi::Spec,
    types::{OperationKey, OperationParameter, ParameterLocation, RECURSIVE_REF_KEY},
};
use registry_platform_crypto::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use super::generator::{
    self, GeneratedDocument, GenerationContext, PathParameter, ReferenceDataset,
    GENERATOR_CONTRACT, MAX_STRING_CHARS,
};
use super::plan::MAX_OPERATIONS;

pub(super) const DEFAULT_SEED: u64 = 0;
pub(super) const DEFAULT_AS_OF: &str = "2025-01-01";

#[derive(Debug)]
pub(super) struct PreparedOpenApi {
    pub operations: Vec<CompatibleOperation>,
    pub skipped: Vec<SkippedOperation>,
    pub normalized_digest: [u8; 32],
    pub datasets: BTreeMap<String, ReferenceDataset>,
}

#[derive(Debug)]
pub(super) struct CompatibleOperation {
    pub key: OperationKey,
    pub operation_id: Option<String>,
    pub schema: Value,
    pub path_parameters: Vec<PathParameterSpec>,
    pub projection_digest: [u8; 32],
}

#[derive(Debug)]
pub(super) struct PathParameterSpec {
    pub name: String,
    pub schema: Value,
    kind: PathParameterKind,
    example: Option<Value>,
    default: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathParameterKind {
    String,
    Integer,
}

#[derive(Debug)]
pub(super) struct SkippedOperation {
    pub key: OperationKey,
    pub reason: &'static str,
}

impl PreparedOpenApi {
    pub fn operation(&self, key: &OperationKey) -> Option<&CompatibleOperation> {
        self.operations
            .iter()
            .find(|operation| same_operation(&operation.key, key))
    }

    pub fn referenced_dataset_ids(&self) -> Result<BTreeSet<String>> {
        let mut identifiers = BTreeSet::new();
        for operation in &self.operations {
            collect_dataset_references(&operation.schema, &mut identifiers)?;
        }
        Ok(identifiers)
    }

    pub fn isolate_undeclared_datasets(
        &mut self,
        undeclared: &BTreeSet<String>,
        selected: Option<&OperationKey>,
    ) -> Result<()> {
        if undeclared.is_empty() {
            return Ok(());
        }
        let mut retained = Vec::with_capacity(self.operations.len());
        for operation in self.operations.drain(..) {
            let referenced = operation.referenced_dataset_ids()?;
            if referenced.is_disjoint(undeclared) {
                retained.push(operation);
                continue;
            }
            if selected.is_some_and(|selected| same_operation(selected, &operation.key)) {
                bail!("selected operation references an undeclared mock dataset");
            }
            self.skipped.push(SkippedOperation {
                key: operation.key,
                reason: "undeclared reference dataset",
            });
        }
        if retained.is_empty() {
            bail!("OpenAPI document has no compatible GET 200 application/json operation");
        }
        self.normalized_digest = operation_surface_digest(retained.iter())?;
        self.operations = retained;
        Ok(())
    }

    pub fn normalized_digest_for(&self, keys: &BTreeSet<(String, String)>) -> Result<[u8; 32]> {
        let selected = self
            .operations
            .iter()
            .filter(|operation| {
                keys.contains(&(operation.key.method.clone(), operation.key.path.clone()))
            })
            .collect::<Vec<_>>();
        if selected.len() != keys.len() {
            bail!("a configured operation is no longer compatible with source mock V1");
        }
        operation_surface_digest(selected)
    }

    pub fn generate(
        &self,
        operation: &CompatibleOperation,
        parameters: &BTreeMap<String, String>,
        seed: u64,
        as_of: NaiveDate,
    ) -> Result<(GeneratedDocument, Vec<u8>)> {
        let typed = operation.typed_parameters(parameters).with_context(|| {
            format!(
                "validating parameters for {} {}",
                operation.key.method, operation.key.path
            )
        })?;
        let context = GenerationContext {
            contract: GENERATOR_CONTRACT,
            seed,
            generation_projection_digest: operation.projection_digest,
            method: &operation.key.method,
            route_template: &operation.key.path,
            status: 200,
            media_type: "application/json",
            path_parameters: &typed,
            as_of,
            datasets: &self.datasets,
        };
        let generated = generator::generate(&operation.schema, &context).with_context(|| {
            format!("generating {} {}", operation.key.method, operation.key.path)
        })?;
        let bytes = generator::to_pretty_json(&generated.value)
            .context("serializing generated response")?;
        if bytes.len() > super::files::MAX_MOCK_BODY_BYTES as usize {
            bail!("generated response exceeds the standalone byte limit");
        }
        Ok((generated, bytes))
    }
}

fn collect_dataset_references(value: &Value, identifiers: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(extension) = object.get("x-evidencectl-mock") {
                if let Some(identifier) = extension
                    .get("reference")
                    .and_then(|reference| reference.get("dataset"))
                    .and_then(Value::as_str)
                {
                    identifiers.insert(identifier.to_owned());
                }
            }
            for child in object.values() {
                collect_dataset_references(child, identifiers)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_dataset_references(child, identifiers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl CompatibleOperation {
    fn referenced_dataset_ids(&self) -> Result<BTreeSet<String>> {
        let mut identifiers = BTreeSet::new();
        collect_dataset_references(&self.schema, &mut identifiers)?;
        Ok(identifiers)
    }

    pub fn accepts_parameters(&self, raw: &BTreeMap<String, String>) -> bool {
        self.typed_parameters(raw).is_ok_and(|parameters| {
            from_request_values_satisfy(&self.schema, &parameters).unwrap_or(false)
        })
    }

    pub fn witness_parameters(&self) -> Result<BTreeMap<String, String>> {
        self.path_parameters
            .iter()
            .map(|parameter| {
                let witness = parameter.witness().with_context(|| {
                    format!(
                        "path parameter `{}` needs an explicit value",
                        parameter.name
                    )
                })?;
                Ok((parameter.name.clone(), witness))
            })
            .collect()
    }

    pub fn plan_parameters(
        &self,
        raw: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, Value>> {
        if raw.len() != self.path_parameters.len() {
            bail!("request does not bind the operation's exact path-parameter set");
        }
        self.path_parameters
            .iter()
            .map(|parameter| {
                let raw_value = raw
                    .get(&parameter.name)
                    .context("request is missing a declared path parameter")?;
                let value = match parameter.kind {
                    PathParameterKind::String => Value::String(raw_value.clone()),
                    PathParameterKind::Integer => {
                        let number = raw_value
                            .parse::<i64>()
                            .context("path parameter is not a canonical integer")?;
                        if number.to_string() != *raw_value {
                            bail!("path parameter is not a canonical integer");
                        }
                        json!(number)
                    }
                };
                if !schema_accepts(&parameter.schema, &value)? {
                    bail!("path parameter does not satisfy its declared schema");
                }
                Ok((parameter.name.clone(), value))
            })
            .collect()
    }

    pub fn authored_parameters(
        &self,
        values: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, String>> {
        if values.len() != self.path_parameters.len() {
            bail!("request does not bind the operation's exact path-parameter set");
        }
        self.path_parameters
            .iter()
            .map(|parameter| {
                let value = values
                    .get(&parameter.name)
                    .context("request is missing a declared path parameter")?;
                let raw = match (parameter.kind, value) {
                    (PathParameterKind::String, Value::String(value)) => value.clone(),
                    (PathParameterKind::Integer, Value::Number(value)) => value
                        .as_i64()
                        .map(|value| value.to_string())
                        .context("an integer path parameter must be an exact signed integer")?,
                    _ => bail!("a configured path parameter has the wrong JSON type"),
                };
                if !schema_accepts(&parameter.schema, value)? {
                    bail!("path parameter does not satisfy its declared schema");
                }
                Ok((parameter.name.clone(), raw))
            })
            .collect()
    }

    fn typed_parameters(
        &self,
        raw: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, PathParameter>> {
        if raw.len() != self.path_parameters.len() {
            bail!("request does not bind the operation's exact path-parameter set");
        }
        self.path_parameters
            .iter()
            .map(|parameter| {
                let raw_value = raw
                    .get(&parameter.name)
                    .context("request is missing a declared path parameter")?;
                let (json_value, typed) = match parameter.kind {
                    PathParameterKind::String => (
                        Value::String(raw_value.clone()),
                        PathParameter::String(raw_value.clone()),
                    ),
                    PathParameterKind::Integer => {
                        let number = raw_value
                            .parse::<i64>()
                            .context("path parameter is not a canonical integer")?;
                        if number.to_string() != *raw_value {
                            bail!("path parameter is not a canonical integer");
                        }
                        (json!(number), PathParameter::Integer(number))
                    }
                };
                if !schema_accepts(&parameter.schema, &json_value)? {
                    bail!("path parameter does not satisfy its declared schema");
                }
                Ok((parameter.name.clone(), typed))
            })
            .collect()
    }
}

fn from_request_values_satisfy(
    schema: &Value,
    parameters: &BTreeMap<String, PathParameter>,
) -> Result<bool> {
    if let Some(name) = schema
        .get("x-evidencectl-mock")
        .and_then(|extension| extension.get("fromRequest"))
        .and_then(|recipe| recipe.get("pathParameter"))
        .and_then(Value::as_str)
    {
        let value = match parameters.get(name) {
            Some(PathParameter::String(value)) => Value::String(value.clone()),
            Some(PathParameter::Integer(value)) => json!(value),
            None => return Ok(false),
        };
        if !schema_accepts(schema, &value)? {
            return Ok(false);
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for child in properties.values() {
            if !from_request_values_satisfy(child, parameters)? {
                return Ok(false);
            }
        }
    }
    if let Some(items) = schema.get("items") {
        return from_request_values_satisfy(items, parameters);
    }
    Ok(true)
}

impl PathParameterSpec {
    fn witness(&self) -> Result<String> {
        let authored = self
            .schema
            .get("const")
            .into_iter()
            .chain(self.example.as_ref())
            .chain(self.default.as_ref())
            .chain(
                self.schema
                    .get("enum")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            );
        for value in authored {
            if let Some(witness) = self.witness_value(value)? {
                return Ok(witness);
            }
        }

        match self.kind {
            PathParameterKind::String => {
                let format = self.schema.get("format").and_then(Value::as_str);
                let candidates: &[&str] = match format {
                    Some("uuid") => &["00000000-0000-4000-8000-000000000001"],
                    Some("date") => &["2025-01-01"],
                    Some("date-time") => &["2025-01-01T00:00:00Z"],
                    _ => &["mock-1", "mock", "1", "a"],
                };
                for candidate in candidates {
                    if schema_accepts(&self.schema, &Value::String((*candidate).to_owned()))? {
                        return Ok((*candidate).to_owned());
                    }
                }
                let minimum = self
                    .schema
                    .get("minLength")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(1)
                    .max(1);
                let maximum = self
                    .schema
                    .get("maxLength")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(minimum);
                if minimum <= maximum && minimum <= MAX_STRING_CHARS {
                    let mut candidate = "mock-1".chars().take(minimum).collect::<String>();
                    candidate.extend(std::iter::repeat_n('x', minimum - candidate.len()));
                    if schema_accepts(&self.schema, &Value::String(candidate.clone()))? {
                        return Ok(candidate);
                    }
                }
            }
            PathParameterKind::Integer => {
                let minimum = self
                    .schema
                    .get("minimum")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let maximum = self
                    .schema
                    .get("maximum")
                    .and_then(Value::as_i64)
                    .unwrap_or(minimum.saturating_add(16));
                for candidate in [minimum, 0, 1, maximum] {
                    if schema_accepts(&self.schema, &json!(candidate))? {
                        return Ok(candidate.to_string());
                    }
                }
            }
        }
        bail!("no bounded synthetic witness satisfies this path parameter")
    }

    fn witness_value(&self, value: &Value) -> Result<Option<String>> {
        if !schema_accepts(&self.schema, value)? {
            return Ok(None);
        }
        match (self.kind, value) {
            (PathParameterKind::String, Value::String(value))
                if !value.is_empty()
                    && !value.contains('/')
                    && !value.chars().any(char::is_control) =>
            {
                Ok(Some(value.clone()))
            }
            (PathParameterKind::Integer, Value::Number(value)) => {
                Ok(value.as_i64().map(|value| value.to_string()))
            }
            _ => Ok(None),
        }
    }
}

/// Discover every compatible GET and classify every other declared GET.
pub(super) fn discover(
    bytes: &[u8],
    origin: &str,
    selected: Option<&OperationKey>,
) -> Result<PreparedOpenApi> {
    let text = std::str::from_utf8(bytes).context("OpenAPI document must be UTF-8")?;
    let spec = Spec::parse(text, origin)?;
    let declared = spec.declared_operations()?;
    let mut operations = Vec::new();
    let mut skipped = Vec::new();
    let candidates = declared
        .into_iter()
        .filter(|key| key.method == "GET")
        .filter(|key| selected.is_none_or(|selected| same_operation(selected, key)))
        .collect::<Vec<_>>();
    if candidates.len() > MAX_OPERATIONS {
        bail!("OpenAPI discovery exceeds the {MAX_OPERATIONS}-operation limit");
    }

    for key in candidates {
        match compatible_operation(&spec, key.clone()) {
            Ok(operation) => operations.push(operation),
            Err(reason) => skipped.push(SkippedOperation { key, reason }),
        }
    }

    if let Some(selected) = selected {
        if operations.is_empty() {
            if skipped
                .iter()
                .any(|item| same_operation(&item.key, selected))
            {
                bail!("selected operation is incompatible with local synthetic serving");
            }
            bail!("selected GET operation is not declared by this OpenAPI document");
        }
    }
    if operations.is_empty() {
        bail!("OpenAPI document has no compatible GET 200 application/json operation");
    }

    let normalized_digest = operation_surface_digest(operations.iter())?;

    Ok(PreparedOpenApi {
        operations,
        skipped,
        normalized_digest,
        datasets: BTreeMap::new(),
    })
}

fn operation_surface_digest<'a>(
    operations: impl IntoIterator<Item = &'a CompatibleOperation>,
) -> Result<[u8; 32]> {
    let surface = Value::Array(operations.into_iter().map(operation_surface).collect());
    let canonical = canonicalize_json(&surface).context("canonicalizing mock operation surface")?;
    Ok(Sha256::digest(canonical).into())
}

fn compatible_operation(
    spec: &Spec,
    key: OperationKey,
) -> std::result::Result<CompatibleOperation, &'static str> {
    let resolved = spec
        .response_schema(&key, "200", "application/json")
        .map_err(|_| "no exact 200 application/json response schema")?;
    let mut response_schema = resolved.schema.0;
    normalize_response_schema(&mut response_schema);
    if contains_recursive_marker(&response_schema) {
        return Err("recursive response schema");
    }
    generator::validate_schema(&response_schema).map_err(|_| "unsupported response schema")?;
    let parameters = spec
        .operation_parameters(&key)
        .map_err(|_| "invalid operation parameters")?;
    if parameters
        .iter()
        .any(|parameter| parameter.location != ParameterLocation::Path && parameter.required)
    {
        return Err("required non-path parameter");
    }
    let template_names =
        template_parameter_names(&key.path).map_err(|_| "invalid path template")?;
    let path_parameters = parameters
        .into_iter()
        .filter(|parameter| parameter.location == ParameterLocation::Path)
        .map(path_parameter)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let declared_names = path_parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<BTreeSet<_>>();
    if declared_names != template_names {
        return Err("path-template parameter mismatch");
    }
    validate_from_request_recipes(&response_schema, &path_parameters)?;

    let operation = spec.operation(&key).map_err(|_| "invalid operation")?;
    if operation.get("x-evidencectl-mock").is_some() {
        return Err("mock extension has an unsupported placement");
    }
    let operation_id = operation
        .get("operationId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let surface = json!({
        "method": key.method,
        "path": key.path,
        "status": 200,
        "mediaType": "application/json",
        "schema": generation_schema_projection(&response_schema),
        "pathParameters": path_parameters.iter().map(|parameter| json!({
            "name": parameter.name,
            "schema": generation_schema_projection(&parameter.schema),
        })).collect::<Vec<_>>(),
    });
    let canonical =
        canonicalize_json(&surface).map_err(|_| "response schema is not canonicalizable")?;
    let projection_digest = Sha256::digest(canonical).into();
    Ok(CompatibleOperation {
        key,
        operation_id,
        schema: response_schema,
        path_parameters,
        projection_digest,
    })
}

fn normalize_response_schema(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    let mut removed = BTreeSet::new();
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        properties.retain(|name, child| {
            let retained = child.get("writeOnly").and_then(Value::as_bool) != Some(true);
            if !retained {
                removed.insert(name.clone());
            }
            retained
        });
        for child in properties.values_mut() {
            normalize_response_schema(child);
        }
    }
    if !removed.is_empty() {
        if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|name| name.as_str().is_none_or(|name| !removed.contains(name)));
        }
    }
    if let Some(items) = object.get_mut("items") {
        normalize_response_schema(items);
    }
}

fn validate_from_request_recipes(
    schema: &Value,
    parameters: &[PathParameterSpec],
) -> std::result::Result<(), &'static str> {
    if let Some(name) = schema
        .get("x-evidencectl-mock")
        .and_then(|extension| extension.get("fromRequest"))
        .and_then(|recipe| recipe.get("pathParameter"))
        .and_then(Value::as_str)
    {
        let parameter = parameters
            .iter()
            .find(|parameter| parameter.name == name)
            .ok_or("fromRequest names an unavailable path parameter")?;
        let response_kind = match schema.get("type") {
            Some(Value::String(kind)) if kind == "string" => Some(PathParameterKind::String),
            Some(Value::String(kind)) if kind == "integer" => Some(PathParameterKind::Integer),
            Some(Value::Array(kinds)) => kinds.iter().find_map(|kind| match kind.as_str() {
                Some("string") => Some(PathParameterKind::String),
                Some("integer") => Some(PathParameterKind::Integer),
                _ => None,
            }),
            None => None,
            _ => return Err("fromRequest has an incompatible response schema"),
        };
        if response_kind.is_some_and(|kind| kind != parameter.kind) {
            return Err("fromRequest has an incompatible response schema");
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for child in properties.values() {
            validate_from_request_recipes(child, parameters)?;
        }
    }
    if let Some(items) = schema.get("items") {
        validate_from_request_recipes(items, parameters)?;
    }
    Ok(())
}

/// Retain only normalized schema material that can affect generated values.
/// Descriptions, examples, defaults, titles, and other annotations must not
/// perturb deterministic synthetic bytes.
fn generation_schema_projection(schema: &Value) -> Value {
    let Some(node) = schema.as_object() else {
        return schema.clone();
    };
    let mut projected = serde_json::Map::new();
    for key in [
        "type",
        "const",
        "enum",
        "required",
        "additionalProperties",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "format",
        "x-evidencectl-mock",
        RECURSIVE_REF_KEY,
    ] {
        if let Some(value) = node.get(key) {
            let value = if key == "required" {
                let mut required = value.as_array().cloned().unwrap_or_default();
                required.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                Value::Array(required)
            } else {
                value.clone()
            };
            projected.insert(key.to_owned(), value);
        }
    }
    if let Some(properties) = node.get("properties").and_then(Value::as_object) {
        projected.insert(
            "properties".to_owned(),
            Value::Object(
                properties
                    .iter()
                    .map(|(key, value)| (key.clone(), generation_schema_projection(value)))
                    .collect(),
            ),
        );
    }
    if let Some(items) = node.get("items") {
        projected.insert("items".to_owned(), generation_schema_projection(items));
    }
    Value::Object(projected)
}

fn path_parameter(
    parameter: OperationParameter,
) -> std::result::Result<PathParameterSpec, &'static str> {
    let schema = parameter.schema.0;
    if schema.get("x-evidencectl-mock").is_some() {
        return Err("mock extension has an unsupported placement");
    }
    let kind = match schema.get("type") {
        Some(Value::String(kind)) if kind == "string" => PathParameterKind::String,
        Some(Value::String(kind)) if kind == "integer" => PathParameterKind::Integer,
        _ => return Err("unsupported path-parameter schema"),
    };
    Ok(PathParameterSpec {
        name: parameter.name,
        schema,
        kind,
        example: parameter.example,
        default: parameter.default,
    })
}

fn operation_surface(operation: &CompatibleOperation) -> Value {
    json!({
        "method": operation.key.method,
        "path": operation.key.path,
        "status": 200,
        "mediaType": "application/json",
        "schema": operation.schema,
        "pathParameters": operation.path_parameters.iter().map(|parameter| json!({
            "name": parameter.name,
            "schema": parameter.schema,
        })).collect::<Vec<_>>(),
    })
}

fn template_parameter_names(path: &str) -> Result<BTreeSet<&str>> {
    if !path.starts_with('/') || path.contains(['?', '#', '\\']) {
        bail!("invalid route template");
    }
    if path == "/" {
        return Ok(BTreeSet::new());
    }
    let mut names = BTreeSet::new();
    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            bail!("invalid route template");
        }
        if segment.contains(['{', '}']) {
            let name = segment
                .strip_prefix('{')
                .and_then(|name| name.strip_suffix('}'))
                .filter(|name| !name.is_empty())
                .context("path parameter must occupy one whole segment")?;
            if !names.insert(name) {
                bail!("route template repeats a path parameter");
            }
        }
    }
    Ok(names)
}

fn contains_recursive_marker(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(RECURSIVE_REF_KEY) || object.values().any(contains_recursive_marker)
        }
        Value::Array(values) => values.iter().any(contains_recursive_marker),
        _ => false,
    }
}

fn schema_accepts(schema: &Value, value: &Value) -> Result<bool> {
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| anyhow!("parameter schema is invalid"))?;
    Ok(validator.is_valid(value))
}

pub(super) fn parse_operation(raw: &str) -> Result<OperationKey> {
    let (method, path) = raw
        .split_once(' ')
        .context("--operation must use `METHOD /path/template`")?;
    if method != "GET" || path.is_empty() || path.contains(' ') {
        bail!("source mock operations must use `GET /path/template`");
    }
    template_parameter_names(path)?;
    Ok(OperationKey {
        method: method.to_owned(),
        path: path.to_owned(),
    })
}

fn same_operation(left: &OperationKey, right: &OperationKey) -> bool {
    left.method == right.method && left.path == right.path
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
openapi: 3.1.0
info: {title: Mock, version: 1.0.0}
paths:
  /pets/special:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [name]
                properties:
                  name: {type: string, minLength: 1, maxLength: 40}
  /pets/{pet_id}:
    get:
      parameters:
        - name: pet_id
          in: path
          required: true
          schema: {type: integer, minimum: 1, maximum: 99}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [pet_id, firstName]
                properties:
                  pet_id:
                    type: integer
                    x-evidencectl-mock: {fromRequest: {pathParameter: pet_id}}
                  firstName: {type: string, minLength: 1, maxLength: 40}
  /search:
    get:
      parameters:
        - name: q
          in: query
          required: true
          schema: {type: string}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, properties: {ok: {type: boolean}}}
"#;

    #[test]
    fn discovers_all_compatible_gets_and_classifies_required_query_routes() {
        let prepared = discover(SPEC.as_bytes(), "test", None).expect("discover");
        assert_eq!(prepared.operations.len(), 2);
        assert_eq!(prepared.skipped.len(), 1);
        assert_eq!(prepared.skipped[0].reason, "required non-path parameter");
        assert_eq!(
            prepared.operations[1].witness_parameters().unwrap()["pet_id"],
            "1"
        );
    }

    #[test]
    fn generation_is_stable_and_path_values_are_typed() {
        let prepared = discover(SPEC.as_bytes(), "test", None).expect("discover");
        let operation = prepared
            .operations
            .iter()
            .find(|operation| operation.key.path == "/pets/{pet_id}")
            .unwrap();
        let parameters = BTreeMap::from([("pet_id".to_owned(), "7".to_owned())]);
        let as_of = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        let first = prepared
            .generate(operation, &parameters, 0, as_of)
            .unwrap()
            .1;
        let second = prepared
            .generate(operation, &parameters, 0, as_of)
            .unwrap()
            .1;
        assert_eq!(first, second);
        assert_eq!(
            serde_json::from_slice::<Value>(&first).unwrap()["pet_id"],
            7
        );
    }

    #[test]
    fn operation_selection_is_exact_and_value_free() {
        let selected = parse_operation("GET /missing/{secret}").unwrap();
        let error = discover(SPEC.as_bytes(), "test", Some(&selected)).unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[test]
    fn string_path_witness_respects_a_declared_minimum_length() {
        let spec = SPEC
            .replace(
                "schema: {type: integer, minimum: 1, maximum: 99}",
                "schema: {type: string, minLength: 20}",
            )
            .replace(
                "pet_id:\n                    type: integer",
                "pet_id:\n                    type: string",
            );
        let prepared = discover(spec.as_bytes(), "string path witness", None).unwrap();
        let operation = prepared
            .operations
            .iter()
            .find(|operation| operation.key.path == "/pets/{pet_id}")
            .unwrap();
        let witness = operation.witness_parameters().unwrap();

        assert_eq!(witness["pet_id"].chars().count(), 20);
        assert!(operation.accepts_parameters(&witness));
    }

    #[test]
    fn openapi31_ref_annotation_siblings_remain_mockable() {
        let spec = r#"
openapi: 3.1.0
info: {title: Annotated ref, version: 1.0.0}
paths:
  /record:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Record'
                description: Local response description
components:
  schemas:
    Record:
      type: object
      required: [id]
      properties:
        id: {type: integer}
"#;

        let prepared = discover(spec.as_bytes(), "annotated ref", None).unwrap();

        assert_eq!(prepared.operations.len(), 1);
        assert_eq!(prepared.operations[0].schema["type"], "object");
        assert!(prepared.operations[0].schema.get("allOf").is_none());
    }

    #[test]
    fn root_operations_are_discoverable_and_selectable() {
        let spec = r#"
openapi: 3.1.0
info: {title: Root mock, version: 1.0.0}
paths:
  /:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [ok]
                properties:
                  ok: {type: boolean}
"#;
        let selected = parse_operation("GET /").unwrap();
        let prepared = discover(spec.as_bytes(), "root test", Some(&selected)).unwrap();

        assert_eq!(prepared.operations.len(), 1);
        assert_eq!(prepared.operations[0].key.path, "/");
        assert!(prepared.operations[0]
            .witness_parameters()
            .unwrap()
            .is_empty());
        let (_, body) = prepared
            .generate(
                &prepared.operations[0],
                &BTreeMap::new(),
                0,
                NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            )
            .unwrap();
        assert!(serde_json::from_slice::<Value>(&body).unwrap()["ok"].is_boolean());
    }

    #[test]
    fn ignored_annotations_do_not_perturb_generation_projection() {
        let annotated = SPEC.replace(
            "name: {type: string, minLength: 1, maxLength: 40}",
            "name: {type: string, minLength: 1, maxLength: 40, description: ignored, example: ignored, default: ignored}",
        );
        let baseline = discover(SPEC.as_bytes(), "baseline", None).unwrap();
        let changed = discover(annotated.as_bytes(), "annotated", None).unwrap();
        assert_eq!(
            baseline.operations[0].projection_digest,
            changed.operations[0].projection_digest
        );
    }

    #[test]
    fn response_projection_omits_write_only_properties_and_required_entries() {
        let spec = r#"
openapi: 3.1.0
info: {title: Write-only response, version: 1.0.0}
paths:
  /account:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id, password]
                properties:
                  id: {type: string}
                  password: {type: string, writeOnly: true}
                  nested:
                    type: object
                    required: [visible, secret]
                    properties:
                      visible: {type: boolean}
                      secret: {type: string, writeOnly: true}
"#;
        let prepared = discover(spec.as_bytes(), "write-only response", None).unwrap();
        let operation = &prepared.operations[0];

        assert!(operation.schema["properties"].get("password").is_none());
        assert_eq!(operation.schema["required"], json!(["id"]));
        assert!(operation.schema["properties"]["nested"]["properties"]
            .get("secret")
            .is_none());
        assert_eq!(
            operation.schema["properties"]["nested"]["required"],
            json!(["visible"])
        );
        let (_, body) = prepared
            .generate(
                operation,
                &BTreeMap::new(),
                0,
                NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            )
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body.get("password").is_none());
        assert!(body["nested"].get("secret").is_none());
    }

    #[test]
    fn unselected_discovery_enforces_the_materialized_operation_ceiling_early() {
        let paths = (0..=MAX_OPERATIONS)
            .map(|index| {
                (
                    format!("/records/{index}"),
                    json!({
                        "get": {
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {"type": "object", "properties": {}}
                                        }
                                    }
                                }
                            }
                        }
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let document = json!({
            "openapi": "3.1.0",
            "info": {"title": "bounded discovery", "version": "1.0.0"},
            "paths": paths,
        });
        let bytes = serde_json::to_vec(&document).unwrap();

        let error = discover(&bytes, "operation ceiling", None).unwrap_err();
        assert!(error.to_string().contains("256-operation limit"));

        let selected = parse_operation("GET /records/0").unwrap();
        let prepared = discover(&bytes, "selected operation", Some(&selected)).unwrap();
        assert_eq!(prepared.operations.len(), 1);
    }
}
