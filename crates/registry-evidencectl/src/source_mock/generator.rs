// SPDX-License-Identifier: Apache-2.0
//! Deterministic, bounded generation for the source-mock authoring surface.

use std::collections::BTreeMap;
use std::fmt;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{Datelike as _, Duration, NaiveDate};
use fake::faker::address::en::{CityName, CountryCode, CountryName, PostCode};
use fake::faker::company::en::CompanyName;
use fake::faker::internet::en::{SafeEmail, Username};
use fake::faker::lorem::en::Word;
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::faker::phone_number::en::PhoneNumber;
use fake::Fake as _;
use jsonschema::{Draft, JSONSchema};
use rand::Rng as _;
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;
use registry_platform_crypto::domain_separated_sha256;
use serde_json::{Map, Number, Value};

use super::infer::{infer, InferenceDecision, InferredRecipe};

pub(crate) const GENERATOR_CONTRACT: &str = "evidencectl-source-mock-v1";
pub(crate) const FAKER_REGISTRY_ID: &str = "evidencectl-faker-v1";
pub(crate) const FORMAT_REGISTRY_ID: &str = "evidencectl-format-v1";

const SEED_DOMAIN: &[u8] = b"evidencectl-source-mock-value-v1\0";
const DEFAULT_AS_OF_YEAR_MIN: i32 = 1900;
const DEFAULT_AS_OF_YEAR_MAX: i32 = 9999;
const MAX_DEPTH: usize = 32;
const MAX_PROPERTIES: usize = 256;
const MAX_ARRAY_ITEMS: usize = 256;
const DEFAULT_ARRAY_MAX: usize = 3;
const MAX_STRING_CHARS: usize = 4096;
const DEFAULT_STRING_MAX: usize = 16;
const MAX_ATTEMPTS: u64 = 16;
const MAX_GENERATED_NODES: usize = 16 * 1024;
const MAX_GENERATED_COMPACT_BYTES: usize = 512 * 1024;
const DATE_START_YEAR: i32 = 2000;
const DATE_END_YEAR: i32 = 2030;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathParameter {
    String(String),
    Integer(i64),
}

impl PathParameter {
    fn canonical_value(&self) -> Value {
        match self {
            Self::String(value) => Value::Object(Map::from_iter([
                ("type".to_owned(), Value::String("string".to_owned())),
                ("value".to_owned(), Value::String(value.clone())),
            ])),
            Self::Integer(value) => Value::Object(Map::from_iter([
                ("type".to_owned(), Value::String("integer".to_owned())),
                ("value".to_owned(), Value::Number(Number::from(*value))),
            ])),
        }
    }

    fn json_value(&self) -> Value {
        match self {
            Self::String(value) => Value::String(value.clone()),
            Self::Integer(value) => Value::Number(Number::from(*value)),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceDataset {
    pub(crate) digest: [u8; 32],
    pub(crate) rows: Vec<Map<String, Value>>,
}

#[derive(Debug)]
pub(crate) struct GenerationContext<'a> {
    pub(crate) contract: &'a str,
    pub(crate) seed: u64,
    pub(crate) generation_projection_digest: [u8; 32],
    pub(crate) method: &'a str,
    pub(crate) route_template: &'a str,
    pub(crate) status: u16,
    pub(crate) media_type: &'a str,
    pub(crate) path_parameters: &'a BTreeMap<String, PathParameter>,
    pub(crate) as_of: NaiveDate,
    pub(crate) datasets: &'a BTreeMap<String, ReferenceDataset>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GenerationCounts {
    pub(crate) explicit: usize,
    pub(crate) inferred: usize,
    pub(crate) format: usize,
    pub(crate) generic: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplainedInference {
    pub(crate) schema_pointer: String,
    pub(crate) decision: InferenceDecision,
}

#[derive(Debug, Clone)]
pub(crate) struct GeneratedDocument {
    pub(crate) value: Value,
    pub(crate) inference: Vec<ExplainedInference>,
    pub(crate) counts: GenerationCounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueValidationFailure {
    pub(crate) instance_pointer: String,
    pub(crate) schema_pointer: String,
    pub(crate) rule: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationErrorKind {
    InvalidSchema,
    UnsupportedSchema,
    InvalidRecipe,
    IncompatibleRecipe,
    MissingPathParameter,
    MissingDataset,
    InvalidDataset,
    UnsatisfiedBounds,
    InvalidAsOf,
    GeneratedValueInvalid,
    OutputLimit,
    Serialization,
}

/// Errors carry only a schema pointer and a closed reason. They never retain a
/// request, dataset, authored value, or generated value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenerationError {
    pub(crate) schema_pointer: String,
    pub(crate) kind: GenerationErrorKind,
    detail: &'static str,
}

impl GenerationError {
    fn at(pointer: &str, kind: GenerationErrorKind, detail: &'static str) -> Self {
        Self {
            schema_pointer: pointer.to_owned(),
            kind,
            detail,
        }
    }
}

impl fmt::Display for GenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "schema node `{}`: {}",
            display_pointer(&self.schema_pointer),
            self.detail
        )
    }
}

impl std::error::Error for GenerationError {}

/// Generate one complete response document in memory.
pub(crate) fn generate(
    schema: &Value,
    context: &GenerationContext<'_>,
) -> Result<GeneratedDocument, GenerationError> {
    if context.contract != GENERATOR_CONTRACT {
        return Err(GenerationError::at(
            "",
            GenerationErrorKind::UnsupportedSchema,
            "the generator contract is unsupported",
        ));
    }
    if !(DEFAULT_AS_OF_YEAR_MIN..=DEFAULT_AS_OF_YEAR_MAX).contains(&context.as_of.year()) {
        return Err(GenerationError::at(
            "",
            GenerationErrorKind::InvalidAsOf,
            "asOf is outside the supported year range",
        ));
    }
    validate_supported_schema(schema, "", 0)?;
    let mut state = State {
        context,
        inference: Vec::new(),
        counts: GenerationCounts::default(),
        generated_nodes: 0,
        generated_compact_bytes: 0,
    };
    let value = state.generate_node(schema, "", None, None, 0)?;
    if !schema_accepts(schema, &value) {
        return Err(GenerationError::at(
            "",
            GenerationErrorKind::GeneratedValueInvalid,
            "the generated document does not satisfy the response schema",
        ));
    }
    Ok(GeneratedDocument {
        value,
        inference: state.inference,
        counts: state.counts,
    })
}

/// Serialize with stable key order, two-space pretty JSON, and one newline.
pub(crate) fn to_pretty_json(value: &Value) -> Result<Vec<u8>, GenerationError> {
    let sorted = sort_json(value);
    let mut bytes = serde_json::to_vec_pretty(&sorted).map_err(|_| {
        GenerationError::at(
            "",
            GenerationErrorKind::Serialization,
            "the generated document could not be serialized",
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Validate an edited materialized body against the same closed schema and
/// format vocabulary used by generation.
#[cfg(test)]
pub(crate) fn value_satisfies(schema: &Value, value: &Value) -> bool {
    validate_value(schema, value).is_ok()
}

pub(crate) fn validate_value(schema: &Value, value: &Value) -> Result<(), ValueValidationFailure> {
    validate_supported_schema(schema, "", 0).map_err(|_| ValueValidationFailure {
        instance_pointer: String::new(),
        schema_pointer: String::new(),
        rule: "supported-schema",
    })?;
    let validator = compile_validator(schema).map_err(|_| ValueValidationFailure {
        instance_pointer: String::new(),
        schema_pointer: String::new(),
        rule: "schema-compilation",
    })?;
    if let Err(mut errors) = validator.validate(value) {
        if let Some(error) = errors.next() {
            return Err(ValueValidationFailure {
                instance_pointer: error.instance_path.to_string(),
                schema_pointer: error.schema_path.to_string(),
                rule: "json-schema",
            });
        }
    }
    validate_value_formats(schema, value, "", "")
}

/// Classify the response schema before a route is advertised as compatible.
pub(crate) fn validate_schema(schema: &Value) -> Result<(), GenerationError> {
    validate_supported_schema(schema, "", 0)?;
    compile_validator(schema).map_err(|_| {
        GenerationError::at(
            "",
            GenerationErrorKind::InvalidSchema,
            "the response schema cannot be compiled",
        )
    })?;
    Ok(())
}

fn validate_value_formats(
    schema: &Value,
    value: &Value,
    instance_pointer: &str,
    schema_pointer: &str,
) -> Result<(), ValueValidationFailure> {
    if value.is_null() {
        return Ok(());
    }
    if let (Some(format), Some(text)) =
        (schema.get("format").and_then(Value::as_str), value.as_str())
    {
        if !format_valid(format, text) {
            return Err(ValueValidationFailure {
                instance_pointer: instance_pointer.to_owned(),
                schema_pointer: push_pointer(schema_pointer, "format"),
                rule: "format",
            });
        }
    }
    match (schema.get("properties").and_then(Value::as_object), value) {
        (Some(properties), Value::Object(object)) => {
            for (key, child_schema) in properties {
                if let Some(child) = object.get(key) {
                    validate_value_formats(
                        child_schema,
                        child,
                        &push_pointer(instance_pointer, key),
                        &push_pointer(&push_pointer(schema_pointer, "properties"), key),
                    )?;
                }
            }
        }
        _ => {
            if let (Some(items), Value::Array(values)) = (schema.get("items"), value) {
                for (index, child) in values.iter().enumerate() {
                    validate_value_formats(
                        items,
                        child,
                        &push_pointer(instance_pointer, &index.to_string()),
                        &push_pointer(schema_pointer, "items"),
                    )?;
                }
            }
        }
    }
    Ok(())
}

struct State<'a, 'context> {
    context: &'a GenerationContext<'context>,
    inference: Vec<ExplainedInference>,
    counts: GenerationCounts,
    generated_nodes: usize,
    generated_compact_bytes: usize,
}

impl State<'_, '_> {
    fn generate_node(
        &mut self,
        schema: &Value,
        pointer: &str,
        property_key: Option<&str>,
        parent_property: Option<&str>,
        depth: usize,
    ) -> Result<Value, GenerationError> {
        if depth > MAX_DEPTH {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "the schema exceeds the generation depth ceiling",
            ));
        }
        self.generated_nodes = self.generated_nodes.saturating_add(1);
        if self.generated_nodes > MAX_GENERATED_NODES {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::OutputLimit,
                "the generated document exceeds its node ceiling",
            ));
        }
        let node = schema.as_object().ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidSchema,
                "the schema node is not an object",
            )
        })?;
        if let Some(value) = node.get("const") {
            ensure_value(schema, value, pointer, GenerationErrorKind::InvalidSchema)?;
            self.charge_json(value, pointer)?;
            return Ok(value.clone());
        }
        if let Some(extension) = node.get("x-evidencectl-mock") {
            self.counts.explicit += 1;
            let value = self.generate_explicit(schema, extension, pointer)?;
            self.charge_json(&value, pointer)?;
            return Ok(value);
        }
        if let Some(values) = node.get("enum") {
            let value = self.generate_enum(schema, values, pointer)?;
            self.charge_json(&value, pointer)?;
            return Ok(value);
        }

        let node_type = node_type(node);
        let value = match node_type {
            NodeType::Object => {
                self.counts.generic += 1;
                self.generate_object(schema, pointer, property_key, depth)
            }
            NodeType::Array => {
                self.generate_array(schema, pointer, property_key, parent_property, depth)
            }
            NodeType::String | NodeType::Untyped => {
                self.generate_string(schema, pointer, property_key, parent_property)
            }
            NodeType::Integer => {
                self.counts.generic += 1;
                self.generate_integer(schema, pointer)
            }
            NodeType::Number => {
                self.counts.generic += 1;
                self.generate_number(schema, pointer)
            }
            NodeType::Boolean => {
                self.counts.generic += 1;
                Ok(self.generate_boolean(pointer))
            }
            NodeType::Null => {
                self.counts.generic += 1;
                Ok(Value::Null)
            }
            NodeType::Unsupported => Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "the schema type is outside the closed generator subset",
            )),
        }?;
        if !matches!(node_type, NodeType::Object | NodeType::Array) {
            self.charge_json(&value, pointer)?;
        }
        Ok(value)
    }

    fn generate_object(
        &mut self,
        schema: &Value,
        pointer: &str,
        property_key: Option<&str>,
        depth: usize,
    ) -> Result<Value, GenerationError> {
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                GenerationError::at(
                    pointer,
                    GenerationErrorKind::UnsupportedSchema,
                    "a generated object needs declared properties",
                )
            })?;
        if properties.len() > MAX_PROPERTIES {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "the object exceeds the property ceiling",
            ));
        }
        self.charge_bytes(2, pointer)?;
        let mut output = Map::new();
        for (index, (key, child_schema)) in properties.iter().enumerate() {
            if index > 0 {
                self.charge_bytes(1, pointer)?;
            }
            self.charge_json(&Value::String(key.clone()), pointer)?;
            self.charge_bytes(1, pointer)?;
            let child_pointer = push_pointer(pointer, key);
            let value = self.generate_node(
                child_schema,
                &child_pointer,
                Some(key),
                property_key,
                depth + 1,
            )?;
            output.insert(key.clone(), value);
        }
        Ok(Value::Object(output))
    }

    fn generate_array(
        &mut self,
        schema: &Value,
        pointer: &str,
        property_key: Option<&str>,
        parent_property: Option<&str>,
        depth: usize,
    ) -> Result<Value, GenerationError> {
        let items = schema.get("items").ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "a generated array needs one item schema",
            )
        })?;
        let minimum = usize_keyword(schema, "minItems", pointer)?.unwrap_or(1);
        let maximum = usize_keyword(schema, "maxItems", pointer)?.unwrap_or(DEFAULT_ARRAY_MAX);
        if minimum > maximum || maximum > MAX_ARRAY_ITEMS {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the array bounds are incompatible or exceed the ceiling",
            ));
        }
        let mut rng = self.rng(pointer, "generic:array-length", 0, None, None);
        let length = rng.random_range(minimum..=maximum);
        self.charge_bytes(2 + length.saturating_sub(1), pointer)?;
        let mut output = Vec::with_capacity(length);
        for index in 0..length {
            let child_pointer = push_pointer(pointer, &index.to_string());
            output.push(self.generate_node(
                items,
                &child_pointer,
                property_key,
                parent_property,
                depth + 1,
            )?);
        }
        self.counts.generic += 1;
        Ok(Value::Array(output))
    }

    fn charge_json(&mut self, value: &Value, pointer: &str) -> Result<(), GenerationError> {
        let mut counter = CountingWriter::default();
        serde_json::to_writer(&mut counter, value).map_err(|_| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::Serialization,
                "the generated value could not be measured",
            )
        })?;
        self.charge_bytes(counter.bytes, pointer)
    }

    fn charge_bytes(&mut self, bytes: usize, pointer: &str) -> Result<(), GenerationError> {
        self.generated_compact_bytes = self.generated_compact_bytes.saturating_add(bytes);
        if self.generated_compact_bytes > MAX_GENERATED_COMPACT_BYTES {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::OutputLimit,
                "the generated document exceeds its aggregate byte ceiling",
            ));
        }
        Ok(())
    }

    fn generate_string(
        &mut self,
        schema: &Value,
        pointer: &str,
        property_key: Option<&str>,
        parent_property: Option<&str>,
    ) -> Result<Value, GenerationError> {
        if let Some(key) = property_key {
            let mut decision = infer(key, parent_property, schema);
            if let Some(recipe) = decision.recipe {
                let identifier = decision
                    .seed_identifier()
                    .expect("selected inference has an identifier");
                if let Some(value) = self.try_inferred(schema, pointer, recipe, &identifier)? {
                    self.counts.inferred += 1;
                    self.inference.push(ExplainedInference {
                        schema_pointer: pointer.to_owned(),
                        decision,
                    });
                    return Ok(value);
                }
                decision.record_generator_fallback();
                self.inference.push(ExplainedInference {
                    schema_pointer: pointer.to_owned(),
                    decision,
                });
            } else {
                self.inference.push(ExplainedInference {
                    schema_pointer: pointer.to_owned(),
                    decision,
                });
            }
        }
        if let Some(format) = schema.get("format").and_then(Value::as_str) {
            let format = FormatKind::parse(format).ok_or_else(|| {
                GenerationError::at(
                    pointer,
                    GenerationErrorKind::UnsupportedSchema,
                    "the asserted string format is unsupported",
                )
            })?;
            let value = self.generate_format(
                schema,
                pointer,
                format,
                &format!("format:{FORMAT_REGISTRY_ID}:{}", format.id()),
            )?;
            self.counts.format += 1;
            return Ok(Value::String(value));
        }
        self.counts.generic += 1;
        self.generate_generic_string(schema, pointer, "generic:string")
            .map(Value::String)
    }

    fn try_inferred(
        &self,
        schema: &Value,
        pointer: &str,
        recipe: InferredRecipe,
        identifier: &str,
    ) -> Result<Option<Value>, GenerationError> {
        match recipe {
            InferredRecipe::Faker(kind) => {
                let Some(kind) = FakerKind::parse(kind) else {
                    return Ok(None);
                };
                self.try_faker(schema, pointer, kind, identifier)
                    .map(|value| value.map(Value::String))
            }
            InferredRecipe::Format(format) => {
                let Some(format) = FormatKind::parse(format) else {
                    return Ok(None);
                };
                match self.generate_format(schema, pointer, format, identifier) {
                    Ok(value) => Ok(Some(Value::String(value))),
                    Err(error) if error.kind == GenerationErrorKind::UnsatisfiedBounds => Ok(None),
                    Err(error) => Err(error),
                }
            }
            InferredRecipe::Age { min, max } => {
                match self.generate_age(schema, pointer, min, max, identifier) {
                    Ok(value) => Ok(Some(Value::String(value))),
                    Err(error) if error.kind == GenerationErrorKind::UnsatisfiedBounds => Ok(None),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn generate_explicit(
        &self,
        schema: &Value,
        extension: &Value,
        pointer: &str,
    ) -> Result<Value, GenerationError> {
        let recipe = Recipe::parse(extension, pointer)?;
        match recipe {
            Recipe::FromRequest { path_parameter } => {
                let value = self
                    .context
                    .path_parameters
                    .get(path_parameter)
                    .ok_or_else(|| {
                        GenerationError::at(
                            pointer,
                            GenerationErrorKind::MissingPathParameter,
                            "the requested path parameter is unavailable",
                        )
                    })?
                    .json_value();
                ensure_value(
                    schema,
                    &value,
                    pointer,
                    GenerationErrorKind::IncompatibleRecipe,
                )?;
                Ok(value)
            }
            Recipe::Faker { kind } => {
                require_string_schema(schema, pointer, kind.accepted_format())?;
                self.try_faker(
                    schema,
                    pointer,
                    kind,
                    &format!("explicit:faker:{}:{}", FAKER_REGISTRY_ID, kind.id()),
                )?
                .map(Value::String)
                .ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::UnsatisfiedBounds,
                        "the explicit faker cannot satisfy the string bounds",
                    )
                })
            }
            Recipe::Age { min, max } => {
                if schema.get("format").and_then(Value::as_str) != Some("date") {
                    return Err(GenerationError::at(
                        pointer,
                        GenerationErrorKind::IncompatibleRecipe,
                        "the age recipe requires a date-formatted string",
                    ));
                }
                self.generate_age(
                    schema,
                    pointer,
                    min,
                    max,
                    &format!("explicit:distribution:age:{min}:{max}"),
                )
                .map(Value::String)
            }
            Recipe::Reference { dataset, field } => {
                let snapshot = self.context.datasets.get(dataset).ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::MissingDataset,
                        "the referenced dataset snapshot is unavailable",
                    )
                })?;
                if snapshot.rows.is_empty() {
                    return Err(GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidDataset,
                        "the referenced dataset is empty",
                    ));
                }
                let validator = compile_validator(schema).map_err(|()| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidDataset,
                        "the referenced node schema cannot be validated",
                    )
                })?;
                let mut candidates = Vec::with_capacity(snapshot.rows.len());
                for row in &snapshot.rows {
                    let value = row.get(field).ok_or_else(|| {
                        GenerationError::at(
                            pointer,
                            GenerationErrorKind::InvalidDataset,
                            "a dataset row lacks the referenced field",
                        )
                    })?;
                    if !is_scalar(value)
                        || !validator.is_valid(value)
                        || !schema_format_accepts(schema, value)
                    {
                        return Err(GenerationError::at(
                            pointer,
                            GenerationErrorKind::InvalidDataset,
                            "a referenced dataset value is incompatible with the schema",
                        ));
                    }
                    candidates.push(value);
                }
                let identifier = format!("explicit:reference:{dataset}:{field}");
                let mut rng = self.rng(pointer, &identifier, 0, None, Some(snapshot.digest));
                let selected = rng.random_range(0..candidates.len());
                Ok(candidates[selected].clone())
            }
        }
    }

    fn generate_enum(
        &self,
        schema: &Value,
        values: &Value,
        pointer: &str,
    ) -> Result<Value, GenerationError> {
        let values = values
            .as_array()
            .filter(|values| !values.is_empty())
            .ok_or_else(|| {
                GenerationError::at(
                    pointer,
                    GenerationErrorKind::InvalidSchema,
                    "enum must be a nonempty array",
                )
            })?;
        let compatible = values
            .iter()
            .filter(|value| schema_accepts(schema, value))
            .collect::<Vec<_>>();
        if compatible.is_empty() {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidSchema,
                "enum has no member compatible with its retained constraints",
            ));
        }
        let mut rng = self.rng(pointer, "schema:enum", 0, None, None);
        Ok((*compatible[rng.random_range(0..compatible.len())]).clone())
    }

    fn try_faker(
        &self,
        schema: &Value,
        pointer: &str,
        kind: FakerKind,
        identifier: &str,
    ) -> Result<Option<String>, GenerationError> {
        for retry in 0..MAX_ATTEMPTS {
            let mut rng = self.rng(pointer, identifier, retry, None, None);
            let candidate = kind.generate(&mut rng);
            if schema_accepts(schema, &Value::String(candidate.clone())) {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    fn generate_age(
        &self,
        schema: &Value,
        pointer: &str,
        min: u16,
        max: u16,
        identifier: &str,
    ) -> Result<String, GenerationError> {
        if min > max || max > 150 {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::IncompatibleRecipe,
                "the age bounds are outside the closed range",
            ));
        }
        let start_year = self.context.as_of.year() - i32::from(max) - 1;
        let start = NaiveDate::from_ymd_opt(start_year, 1, 1).ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidAsOf,
                "asOf and the age bounds exceed calendar arithmetic",
            )
        })?;
        let days = (self.context.as_of - start).num_days();
        let mut candidates = Vec::new();
        for offset in 0..=days {
            let birth = start + Duration::days(offset);
            let age = completed_age(birth, self.context.as_of);
            if (min..=max).contains(&age) {
                candidates.push(birth);
            }
        }
        if candidates.is_empty() {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the age recipe cannot satisfy the date bounds",
            ));
        }
        let mut rng = self.rng(pointer, identifier, 0, Some(self.context.as_of), None);
        let selected = candidates[rng.random_range(0..candidates.len())]
            .format("%Y-%m-%d")
            .to_string();
        if schema_accepts(schema, &Value::String(selected.clone())) {
            Ok(selected)
        } else {
            Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the age recipe cannot satisfy the date bounds",
            ))
        }
    }

    fn generate_format(
        &self,
        schema: &Value,
        pointer: &str,
        format: FormatKind,
        identifier: &str,
    ) -> Result<String, GenerationError> {
        let mut rng = self.rng(pointer, identifier, 0, None, None);
        let candidate = format.generate(&mut rng);
        if schema_accepts(schema, &Value::String(candidate.clone())) {
            Ok(candidate)
        } else {
            Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the format generator cannot satisfy the string bounds",
            ))
        }
    }

    fn generate_generic_string(
        &self,
        schema: &Value,
        pointer: &str,
        identifier: &str,
    ) -> Result<String, GenerationError> {
        let minimum = usize_keyword(schema, "minLength", pointer)?.unwrap_or(1);
        let maximum = usize_keyword(schema, "maxLength", pointer)?.unwrap_or(DEFAULT_STRING_MAX);
        if minimum > maximum || maximum > MAX_STRING_CHARS {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the string bounds are incompatible or exceed the ceiling",
            ));
        }
        let mut rng = self.rng(pointer, identifier, 0, None, None);
        let length = rng.random_range(minimum..=maximum);
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let candidate: String = (0..length)
            .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
            .collect();
        if schema_accepts(schema, &Value::String(candidate.clone())) {
            Ok(candidate)
        } else {
            Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the generic string generator cannot satisfy the schema",
            ))
        }
    }

    fn generate_integer(&self, schema: &Value, pointer: &str) -> Result<Value, GenerationError> {
        let (minimum, maximum) = integer_bounds(schema, pointer)?;
        let mut rng = self.rng(pointer, "generic:integer", 0, None, None);
        Ok(Value::Number(Number::from(
            rng.random_range(minimum..=maximum),
        )))
    }

    fn generate_number(&self, schema: &Value, pointer: &str) -> Result<Value, GenerationError> {
        let (minimum, maximum) = number_bounds(schema, pointer)?;
        let mut rng = self.rng(pointer, "generic:number", 0, None, None);
        let value = if minimum == maximum {
            minimum
        } else {
            rng.random_range(minimum..=maximum)
        };
        let number = Number::from_f64(value).ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the numeric bounds do not produce a finite JSON number",
            )
        })?;
        Ok(Value::Number(number))
    }

    fn generate_boolean(&self, pointer: &str) -> Value {
        let mut rng = self.rng(pointer, "generic:boolean", 0, None, None);
        Value::Bool(rng.random())
    }

    fn rng(
        &self,
        pointer: &str,
        generator: &str,
        retry: u64,
        as_of: Option<NaiveDate>,
        dataset_digest: Option<[u8; 32]>,
    ) -> ChaCha20Rng {
        let mut payload = SeedPayload::default();
        payload.utf8("contract", self.context.contract);
        payload.unsigned("seed", self.context.seed);
        payload.digest("projection", self.context.generation_projection_digest);
        payload.utf8("method", self.context.method);
        payload.utf8("route", self.context.route_template);
        payload.unsigned("status", u64::from(self.context.status));
        payload.utf8("media-type", self.context.media_type);
        payload.utf8(
            "path-parameters",
            &canonical_path_parameters(self.context.path_parameters),
        );
        payload.utf8("pointer", pointer);
        payload.utf8("generator", generator);
        payload.unsigned("retry", retry);
        if let Some(as_of) = as_of {
            payload.utf8("as-of", &as_of.format("%Y-%m-%d").to_string());
        }
        if let Some(digest) = dataset_digest {
            payload.digest("dataset", digest);
        }
        ChaCha20Rng::from_seed(domain_separated_sha256(SEED_DOMAIN, &payload.bytes))
    }
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct SeedPayload {
    bytes: Vec<u8>,
}

impl SeedPayload {
    fn utf8(&mut self, label: &str, value: &str) {
        self.component(label, 0x01, value.as_bytes());
    }

    fn unsigned(&mut self, label: &str, value: u64) {
        self.component(label, 0x02, &value.to_be_bytes());
    }

    fn digest(&mut self, label: &str, value: [u8; 32]) {
        self.component(label, 0x03, &value);
    }

    fn component(&mut self, label: &str, tag: u8, value: &[u8]) {
        let label_length = u16::try_from(label.len()).expect("seed labels are fixed and bounded");
        let value_length = u64::try_from(value.len()).expect("seed components fit u64");
        self.bytes.extend_from_slice(&label_length.to_be_bytes());
        self.bytes.extend_from_slice(label.as_bytes());
        self.bytes.push(tag);
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FakerKind {
    LoremWord,
    FirstName,
    LastName,
    FullName,
    SafeEmail,
    Username,
    PhoneNumber,
    City,
    PostalCode,
    CountryName,
    CountryCode,
    CompanyName,
}

impl FakerKind {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "lorem.word" => Self::LoremWord,
            "person.firstName" => Self::FirstName,
            "person.lastName" => Self::LastName,
            "person.fullName" => Self::FullName,
            "internet.safeEmail" => Self::SafeEmail,
            "internet.username" => Self::Username,
            "phone.number" => Self::PhoneNumber,
            "address.city" => Self::City,
            "address.postalCode" => Self::PostalCode,
            "address.countryName" => Self::CountryName,
            "address.countryCode" => Self::CountryCode,
            "company.name" => Self::CompanyName,
            _ => return None,
        })
    }

    const fn id(self) -> &'static str {
        match self {
            Self::LoremWord => "lorem.word",
            Self::FirstName => "person.firstName",
            Self::LastName => "person.lastName",
            Self::FullName => "person.fullName",
            Self::SafeEmail => "internet.safeEmail",
            Self::Username => "internet.username",
            Self::PhoneNumber => "phone.number",
            Self::City => "address.city",
            Self::PostalCode => "address.postalCode",
            Self::CountryName => "address.countryName",
            Self::CountryCode => "address.countryCode",
            Self::CompanyName => "company.name",
        }
    }

    const fn accepted_format(self) -> Option<&'static str> {
        match self {
            Self::SafeEmail => Some("email"),
            _ => None,
        }
    }

    fn generate(self, rng: &mut ChaCha20Rng) -> String {
        match self {
            Self::LoremWord => Word().fake_with_rng(rng),
            Self::FirstName => FirstName().fake_with_rng(rng),
            Self::LastName => LastName().fake_with_rng(rng),
            Self::FullName => Name().fake_with_rng(rng),
            Self::SafeEmail => SafeEmail().fake_with_rng(rng),
            Self::Username => Username().fake_with_rng(rng),
            Self::PhoneNumber => PhoneNumber().fake_with_rng(rng),
            Self::City => CityName().fake_with_rng(rng),
            Self::PostalCode => PostCode().fake_with_rng(rng),
            Self::CountryName => CountryName().fake_with_rng(rng),
            Self::CountryCode => CountryCode().fake_with_rng(rng),
            Self::CompanyName => CompanyName().fake_with_rng(rng),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatKind {
    Date,
    DateTime,
    Time,
    Duration,
    Email,
    Uuid,
    Uri,
    Url,
    UriReference,
    Hostname,
    Ipv4,
    Ipv6,
    Byte,
    JsonPointer,
    RelativeJsonPointer,
}

impl FormatKind {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "date" => Self::Date,
            "date-time" => Self::DateTime,
            "time" => Self::Time,
            "duration" => Self::Duration,
            "email" => Self::Email,
            "uuid" => Self::Uuid,
            "uri" => Self::Uri,
            "url" => Self::Url,
            "uri-reference" => Self::UriReference,
            "hostname" => Self::Hostname,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "byte" => Self::Byte,
            "json-pointer" => Self::JsonPointer,
            "relative-json-pointer" => Self::RelativeJsonPointer,
            _ => return None,
        })
    }

    const fn id(self) -> &'static str {
        match self {
            Self::Date => "date",
            Self::DateTime => "date-time",
            Self::Time => "time",
            Self::Duration => "duration",
            Self::Email => "email",
            Self::Uuid => "uuid",
            Self::Uri => "uri",
            Self::Url => "url",
            Self::UriReference => "uri-reference",
            Self::Hostname => "hostname",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Byte => "byte",
            Self::JsonPointer => "json-pointer",
            Self::RelativeJsonPointer => "relative-json-pointer",
        }
    }

    fn generate(self, rng: &mut ChaCha20Rng) -> String {
        match self {
            Self::Date => random_date(rng).format("%Y-%m-%d").to_string(),
            Self::DateTime => {
                let date = random_date(rng);
                let seconds = rng.random_range(0..86_400_u32);
                format!(
                    "{}T{:02}:{:02}:{:02}Z",
                    date.format("%Y-%m-%d"),
                    seconds / 3600,
                    (seconds % 3600) / 60,
                    seconds % 60
                )
            }
            Self::Time => {
                let seconds = rng.random_range(0..86_400_u32);
                format!(
                    "{:02}:{:02}:{:02}Z",
                    seconds / 3600,
                    (seconds % 3600) / 60,
                    seconds % 60
                )
            }
            Self::Duration => format!("P{}D", rng.random_range(1..=3650_u16)),
            Self::Email => SafeEmail().fake_with_rng(rng),
            Self::Uuid => random_uuid(rng),
            Self::Uri | Self::Url => format!("https://example.invalid/mock/{}", random_hex(rng, 8)),
            Self::UriReference | Self::JsonPointer => format!("/mock/{}", random_hex(rng, 8)),
            Self::RelativeJsonPointer => format!("0/mock/{}", random_hex(rng, 8)),
            Self::Hostname => format!("mock-{}.example.invalid", random_hex(rng, 6)),
            Self::Ipv4 => Ipv4Addr::new(192, 0, 2, rng.random_range(1..=254)).to_string(),
            Self::Ipv6 => Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, rng.random()).to_string(),
            Self::Byte => {
                let mut bytes = [0_u8; 12];
                rng.fill(&mut bytes);
                BASE64_STANDARD.encode(bytes)
            }
        }
    }
}

enum Recipe<'a> {
    FromRequest { path_parameter: &'a str },
    Faker { kind: FakerKind },
    Age { min: u16, max: u16 },
    Reference { dataset: &'a str, field: &'a str },
}

impl<'a> Recipe<'a> {
    fn parse(extension: &'a Value, pointer: &str) -> Result<Self, GenerationError> {
        let object = extension.as_object().ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidRecipe,
                "the mock recipe is not an object",
            )
        })?;
        if object.len() != 1 {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidRecipe,
                "the mock extension must contain exactly one recipe",
            ));
        }
        let (kind, body) = object.iter().next().expect("nonempty recipe object");
        let body = body.as_object().ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidRecipe,
                "the selected mock recipe is not an object",
            )
        })?;
        match kind.as_str() {
            "fromRequest" => {
                require_exact_keys(body, &["pathParameter"], pointer)?;
                let path_parameter = body
                    .get("pathParameter")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        GenerationError::at(
                            pointer,
                            GenerationErrorKind::InvalidRecipe,
                            "fromRequest needs one pathParameter name",
                        )
                    })?;
                Ok(Self::FromRequest { path_parameter })
            }
            "faker" => {
                require_exact_keys(body, &["kind"], pointer)?;
                let value = body.get("kind").and_then(Value::as_str).ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidRecipe,
                        "faker needs one closed kind",
                    )
                })?;
                let kind = FakerKind::parse(value).ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidRecipe,
                        "the faker kind is unsupported",
                    )
                })?;
                Ok(Self::Faker { kind })
            }
            "distribution" => {
                require_exact_keys(body, &["kind", "max", "min"], pointer)?;
                if body.get("kind").and_then(Value::as_str) != Some("age") {
                    return Err(GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidRecipe,
                        "the distribution kind is unsupported",
                    ));
                }
                let min = body
                    .get("min")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| {
                        GenerationError::at(
                            pointer,
                            GenerationErrorKind::InvalidRecipe,
                            "age min is not a supported integer",
                        )
                    })?;
                let max = body
                    .get("max")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| {
                        GenerationError::at(
                            pointer,
                            GenerationErrorKind::InvalidRecipe,
                            "age max is not a supported integer",
                        )
                    })?;
                Ok(Self::Age { min, max })
            }
            "reference" => {
                require_exact_keys(body, &["dataset", "field"], pointer)?;
                let dataset = body.get("dataset").and_then(Value::as_str).ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidRecipe,
                        "reference needs one dataset identifier",
                    )
                })?;
                let field = body.get("field").and_then(Value::as_str).ok_or_else(|| {
                    GenerationError::at(
                        pointer,
                        GenerationErrorKind::InvalidRecipe,
                        "reference needs one field name",
                    )
                })?;
                Ok(Self::Reference { dataset, field })
            }
            _ => Err(GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidRecipe,
                "the mock recipe is unsupported",
            )),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeType {
    Object,
    Array,
    String,
    Integer,
    Number,
    Boolean,
    Null,
    Untyped,
    Unsupported,
}

fn node_type(node: &Map<String, Value>) -> NodeType {
    let kind = match node.get("type") {
        Some(Value::String(kind)) => Some(kind.as_str()),
        Some(Value::Array(kinds))
            if kinds.len() == 2
                && kinds
                    .iter()
                    .filter(|kind| kind.as_str() == Some("null"))
                    .count()
                    == 1 =>
        {
            kinds.iter().find_map(|kind| {
                let kind = kind.as_str()?;
                (kind != "null").then_some(kind)
            })
        }
        Some(_) => return NodeType::Unsupported,
        None => None,
    };
    match kind {
        Some("object") => NodeType::Object,
        Some("array") => NodeType::Array,
        Some("string") => NodeType::String,
        Some("integer") => NodeType::Integer,
        Some("number") => NodeType::Number,
        Some("boolean") => NodeType::Boolean,
        Some("null") => NodeType::Null,
        Some(_) => NodeType::Unsupported,
        None if node.contains_key("properties") => NodeType::Object,
        None if node.contains_key("items") => NodeType::Array,
        None if node.keys().any(|key| {
            matches!(
                key.as_str(),
                "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf"
            )
        }) =>
        {
            NodeType::Number
        }
        None => NodeType::Untyped,
    }
}

fn validate_supported_schema(
    schema: &Value,
    pointer: &str,
    depth: usize,
) -> Result<(), GenerationError> {
    if depth > MAX_DEPTH {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::UnsupportedSchema,
            "the schema exceeds the generation depth ceiling",
        ));
    }
    let node = schema.as_object().ok_or_else(|| {
        GenerationError::at(
            pointer,
            GenerationErrorKind::InvalidSchema,
            "the schema node is not an object",
        )
    })?;
    if node.contains_key("pattern")
        || node.contains_key("multipleOf")
        || node.contains_key("allOf")
        || node.contains_key("anyOf")
        || node.contains_key("oneOf")
        || node.contains_key("not")
        || node.contains_key("$recursiveRef")
        || node.contains_key("x-registry-recursive-ref")
    {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::UnsupportedSchema,
            "the schema uses an unsupported composition, pattern, numeric step, or recursion",
        ));
    }
    if node.contains_key("const") && node.contains_key("x-evidencectl-mock") {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::InvalidRecipe,
            "const and a mock recipe cannot appear together",
        ));
    }
    if let Some(extension) = node.get("x-evidencectl-mock") {
        match Recipe::parse(extension, pointer)? {
            Recipe::Faker { kind } => {
                require_string_schema(schema, pointer, kind.accepted_format())?;
            }
            Recipe::Age { min, max } => {
                if min > max
                    || max > 150
                    || schema.get("format").and_then(Value::as_str) != Some("date")
                {
                    return Err(GenerationError::at(
                        pointer,
                        GenerationErrorKind::IncompatibleRecipe,
                        "the age recipe has incompatible bounds or schema",
                    ));
                }
            }
            Recipe::Reference { .. } => {
                if matches!(
                    node_type(node),
                    NodeType::Object | NodeType::Array | NodeType::Unsupported
                ) {
                    return Err(GenerationError::at(
                        pointer,
                        GenerationErrorKind::IncompatibleRecipe,
                        "the reference recipe requires a scalar-compatible schema",
                    ));
                }
            }
            Recipe::FromRequest { .. } => {}
        }
    }
    if let Some(format) = node.get("format") {
        let format = format.as_str().ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::InvalidSchema,
                "format is not a string",
            )
        })?;
        if FormatKind::parse(format).is_none() {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "the asserted string format is unsupported",
            ));
        }
    }
    if node_type(node) == NodeType::Object {
        if node
            .get("additionalProperties")
            .is_some_and(|value| value != &Value::Bool(false))
        {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "a generated object cannot require free-form additional properties",
            ));
        }
        let properties = node
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                GenerationError::at(
                    pointer,
                    GenerationErrorKind::UnsupportedSchema,
                    "a generated object needs declared properties",
                )
            })?;
        if properties.len() > MAX_PROPERTIES {
            return Err(GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "the object exceeds the property ceiling",
            ));
        }
        for (key, child) in properties {
            validate_supported_schema(child, &push_pointer(pointer, key), depth + 1)?;
        }
    } else if node_type(node) == NodeType::Array {
        let items = node.get("items").ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::UnsupportedSchema,
                "a generated array needs one item schema",
            )
        })?;
        validate_supported_schema(items, &push_pointer(pointer, "0"), depth + 1)?;
    }
    Ok(())
}

fn require_string_schema(
    schema: &Value,
    pointer: &str,
    accepted_format: Option<&str>,
) -> Result<(), GenerationError> {
    let node = schema.as_object().ok_or_else(|| {
        GenerationError::at(
            pointer,
            GenerationErrorKind::InvalidSchema,
            "the schema node is not an object",
        )
    })?;
    if !matches!(node_type(node), NodeType::String | NodeType::Untyped) {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::IncompatibleRecipe,
            "the faker recipe requires a string-compatible schema",
        ));
    }
    match node.get("format").and_then(Value::as_str) {
        None => Ok(()),
        Some(format) if Some(format) == accepted_format => Ok(()),
        Some(_) => Err(GenerationError::at(
            pointer,
            GenerationErrorKind::IncompatibleRecipe,
            "the faker recipe conflicts with the asserted format",
        )),
    }
}

fn ensure_value(
    schema: &Value,
    value: &Value,
    pointer: &str,
    kind: GenerationErrorKind,
) -> Result<(), GenerationError> {
    if schema_accepts(schema, value) {
        Ok(())
    } else {
        Err(GenerationError::at(
            pointer,
            kind,
            "the selected recipe value does not satisfy the schema",
        ))
    }
}

fn schema_accepts(schema: &Value, value: &Value) -> bool {
    let Ok(compiled) = compile_validator(schema) else {
        return false;
    };
    compiled.is_valid(value) && schema_format_accepts(schema, value)
}

fn compile_validator(schema: &Value) -> Result<JSONSchema, ()> {
    let mut options = JSONSchema::options();
    options
        .with_draft(Draft::Draft202012)
        .should_validate_formats(false);
    options.compile(schema).map_err(|_| ())
}

fn schema_format_accepts(schema: &Value, value: &Value) -> bool {
    let current_format_accepts =
        schema
            .get("format")
            .and_then(Value::as_str)
            .is_none_or(|format| {
                value
                    .as_str()
                    .is_none_or(|value| format_valid(format, value))
            });
    if !current_format_accepts {
        return false;
    }
    if value.is_null() {
        return true;
    }

    let Some(node) = schema.as_object() else {
        return false;
    };
    match node_type(node) {
        NodeType::Object => {
            let Some(properties) = node.get("properties").and_then(Value::as_object) else {
                return false;
            };
            let Some(object) = value.as_object() else {
                return false;
            };
            properties.iter().all(|(key, child_schema)| {
                object
                    .get(key)
                    .is_none_or(|child_value| schema_format_accepts(child_schema, child_value))
            })
        }
        NodeType::Array => {
            let Some(items) = node.get("items") else {
                return false;
            };
            let Some(array) = value.as_array() else {
                return false;
            };
            array.iter().all(|item| schema_format_accepts(items, item))
        }
        _ => true,
    }
}

fn format_valid(format: &str, value: &str) -> bool {
    match format {
        "date" => NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok(),
        "date-time" => chrono::DateTime::parse_from_rfc3339(value).is_ok(),
        "time" => {
            chrono::NaiveTime::parse_from_str(value.trim_end_matches('Z'), "%H:%M:%S").is_ok()
                && value.ends_with('Z')
        }
        "duration" => {
            value.starts_with('P')
                && value.ends_with('D')
                && value[1..value.len().saturating_sub(1)]
                    .parse::<u16>()
                    .is_ok()
        }
        "email" => value.split_once('@').is_some_and(|(local, host)| {
            !local.is_empty() && host.contains('.') && !host.contains(' ')
        }),
        "uuid" => uuid_shape(value),
        "uri" | "url" => url::Url::parse(value).is_ok(),
        "uri-reference" => value.starts_with('/'),
        "hostname" => {
            value.len() <= 253
                && value.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        }
        "ipv4" => value.parse::<Ipv4Addr>().is_ok(),
        "ipv6" => value.parse::<Ipv6Addr>().is_ok(),
        "byte" => BASE64_STANDARD.decode(value).is_ok(),
        "json-pointer" => {
            value.is_empty() || (value.starts_with('/') && valid_pointer_escapes(value))
        }
        "relative-json-pointer" => value.split_once('/').is_some_and(|(prefix, rest)| {
            prefix.parse::<u64>().is_ok() && valid_pointer_escapes(rest)
        }),
        _ => false,
    }
}

fn valid_pointer_escapes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

fn uuid_shape(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
        && value.as_bytes().get(14) == Some(&b'4')
        && value
            .as_bytes()
            .get(19)
            .is_some_and(|byte| matches!(byte, b'8' | b'9' | b'a' | b'b'))
}

fn completed_age(birth: NaiveDate, as_of: NaiveDate) -> u16 {
    let anniversary_day = if birth.month() == 2
        && birth.day() == 29
        && NaiveDate::from_ymd_opt(as_of.year(), 2, 29).is_none()
    {
        28
    } else {
        birth.day()
    };
    let anniversary = NaiveDate::from_ymd_opt(as_of.year(), birth.month(), anniversary_day)
        .expect("anniversary is a valid Gregorian date");
    let years = as_of.year() - birth.year() - i32::from(as_of < anniversary);
    u16::try_from(years.max(0)).expect("supported age fits u16")
}

fn random_date(rng: &mut ChaCha20Rng) -> NaiveDate {
    let start = NaiveDate::from_ymd_opt(DATE_START_YEAR, 1, 1).expect("fixed valid date");
    let end = NaiveDate::from_ymd_opt(DATE_END_YEAR, 12, 31).expect("fixed valid date");
    start + Duration::days(rng.random_range(0..=(end - start).num_days()))
}

fn random_hex(rng: &mut ChaCha20Rng, bytes: usize) -> String {
    let mut output = vec![0_u8; bytes];
    rng.fill(output.as_mut_slice());
    hex::encode(output)
}

fn random_uuid(rng: &mut ChaCha20Rng) -> String {
    let mut bytes = [0_u8; 16];
    rng.fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn integer_bounds(schema: &Value, pointer: &str) -> Result<(i64, i64), GenerationError> {
    let mut minimum = integer_limit(schema, "minimum", pointer, f64::ceil)?.unwrap_or(0);
    let mut maximum = integer_limit(schema, "maximum", pointer, f64::floor)?.unwrap_or(1000);
    if let Some(bound) = integer_limit(schema, "exclusiveMinimum", pointer, f64::floor)? {
        minimum = bound.checked_add(1).ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the integer minimum overflows",
            )
        })?;
    }
    if let Some(bound) = integer_limit(schema, "exclusiveMaximum", pointer, f64::ceil)? {
        maximum = bound.checked_sub(1).ok_or_else(|| {
            GenerationError::at(
                pointer,
                GenerationErrorKind::UnsatisfiedBounds,
                "the integer maximum underflows",
            )
        })?;
    }
    if minimum > maximum {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::UnsatisfiedBounds,
            "the integer bounds are contradictory",
        ));
    }
    Ok((minimum, maximum))
}

fn integer_limit(
    schema: &Value,
    keyword: &str,
    pointer: &str,
    round: fn(f64) -> f64,
) -> Result<Option<i64>, GenerationError> {
    let Some(raw) = schema.get(keyword) else {
        return Ok(None);
    };
    let value = raw.as_f64().map(round).filter(|value| {
        value.is_finite() && *value >= i64::MIN as f64 && *value <= i64::MAX as f64
    });
    value.map(|value| Some(value as i64)).ok_or_else(|| {
        GenerationError::at(
            pointer,
            GenerationErrorKind::InvalidSchema,
            "an integer bound is not a finite supported number",
        )
    })
}

fn number_bounds(schema: &Value, pointer: &str) -> Result<(f64, f64), GenerationError> {
    let minimum = schema.get("minimum").and_then(Value::as_f64).unwrap_or(0.0);
    let maximum = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .unwrap_or(1000.0);
    if !minimum.is_finite()
        || !maximum.is_finite()
        || minimum > maximum
        || schema.get("exclusiveMinimum").is_some()
        || schema.get("exclusiveMaximum").is_some()
        || schema.get("multipleOf").is_some()
    {
        return Err(GenerationError::at(
            pointer,
            GenerationErrorKind::UnsatisfiedBounds,
            "the number bounds are unsupported or contradictory",
        ));
    }
    Ok((minimum, maximum))
}

fn usize_keyword(
    schema: &Value,
    keyword: &str,
    pointer: &str,
) -> Result<Option<usize>, GenerationError> {
    match schema.get(keyword) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                GenerationError::at(
                    pointer,
                    GenerationErrorKind::InvalidSchema,
                    "a size bound is not a supported unsigned integer",
                )
            }),
    }
}

fn require_exact_keys(
    object: &Map<String, Value>,
    keys: &[&str],
    pointer: &str,
) -> Result<(), GenerationError> {
    if object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(GenerationError::at(
            pointer,
            GenerationErrorKind::InvalidRecipe,
            "the mock recipe has missing or unknown keys",
        ))
    }
}

fn canonical_path_parameters(parameters: &BTreeMap<String, PathParameter>) -> String {
    let object = Map::from_iter(
        parameters
            .iter()
            .map(|(key, value)| (key.clone(), value.canonical_value())),
    );
    serde_json::to_string(&Value::Object(object)).expect("typed path parameters always serialize")
}

fn sort_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .iter()
                .map(|(key, value)| (key.clone(), sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(Map::from_iter(sorted))
        }
        Value::Array(values) => Value::Array(values.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

fn push_pointer(pointer: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    format!("{pointer}/{escaped}")
}

fn display_pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "/"
    } else {
        pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context<'a>(
        paths: &'a BTreeMap<String, PathParameter>,
        datasets: &'a BTreeMap<String, ReferenceDataset>,
    ) -> GenerationContext<'a> {
        GenerationContext {
            contract: GENERATOR_CONTRACT,
            seed: 0,
            generation_projection_digest: [7; 32],
            method: "GET",
            route_template: "/people/{person_id}",
            status: 200,
            media_type: "application/json",
            path_parameters: paths,
            as_of: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            datasets,
        }
    }

    fn closed(properties: Value) -> Value {
        json!({"type": "object", "additionalProperties": false, "properties": properties})
    }

    #[test]
    fn same_inputs_produce_same_bytes_and_seed_changes_output() {
        let schema = closed(json!({
            "firstName": {"type": "string", "minLength": 1, "maxLength": 100},
            "score": {"type": "integer", "minimum": 1, "maximum": 100}
        }));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let first = generate(&schema, &context(&paths, &datasets)).unwrap();
        let second = generate(&schema, &context(&paths, &datasets)).unwrap();
        assert_eq!(
            to_pretty_json(&first.value).unwrap(),
            to_pretty_json(&second.value).unwrap()
        );
        let mut changed = context(&paths, &datasets);
        changed.seed = 1;
        assert_ne!(first.value, generate(&schema, &changed).unwrap().value);
    }

    #[test]
    fn property_order_does_not_change_node_values() {
        let left = closed(json!({"alpha": {"type": "string"}, "email": {"type": "string"}}));
        let right = closed(json!({"email": {"type": "string"}, "alpha": {"type": "string"}}));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        assert_eq!(
            generate(&left, &context(&paths, &datasets)).unwrap().value,
            generate(&right, &context(&paths, &datasets)).unwrap().value
        );
    }

    #[test]
    fn fake_rs_is_driven_by_the_derived_rng_and_inference_is_explained() {
        let schema = closed(
            json!({"emailAddress": {"type": "string", "format": "email", "maxLength": 100}}),
        );
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let generated = generate(&schema, &context(&paths, &datasets)).unwrap();
        assert!(generated.value["emailAddress"]
            .as_str()
            .unwrap()
            .contains('@'));
        assert_eq!(generated.counts.inferred, 1);
        assert_eq!(
            generated.inference[0].decision.rule_id,
            Some("field.email.v1")
        );
    }

    #[test]
    fn inferred_faker_falls_back_but_explicit_faker_fails() {
        let inferred =
            closed(json!({"firstName": {"type": "string", "minLength": 0, "maxLength": 0}}));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let generated = generate(&inferred, &context(&paths, &datasets)).unwrap();
        assert!(generated.value["firstName"].as_str().unwrap().is_empty());
        assert_eq!(
            generated.inference[0].decision.fallback,
            Some(super::super::infer::InferenceFallback::GeneratorCouldNotSatisfySchema)
        );

        let explicit = closed(
            json!({"firstName": {"type": "string", "minLength": 0, "maxLength": 0, "x-evidencectl-mock": {"faker": {"kind": "person.firstName"}}}}),
        );
        assert_eq!(
            generate(&explicit, &context(&paths, &datasets))
                .unwrap_err()
                .kind,
            GenerationErrorKind::UnsatisfiedBounds
        );
    }

    #[test]
    fn an_explicit_recipe_takes_precedence_over_enum() {
        let schema = closed(json!({
            "firstName": {
                "type": "string",
                "enum": ["fixed"],
                "x-evidencectl-mock": {"faker": {"kind": "person.firstName"}}
            }
        }));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        assert_eq!(
            generate(&schema, &context(&paths, &datasets))
                .unwrap_err()
                .kind,
            GenerationErrorKind::UnsatisfiedBounds
        );
    }

    #[test]
    fn aggregate_output_budget_stops_wide_large_schemas_during_the_walk() {
        let properties = (0..MAX_PROPERTIES)
            .map(|index| {
                (
                    format!("field_{index}"),
                    json!({"type": "string", "minLength": 4096, "maxLength": 4096}),
                )
            })
            .collect();
        let schema = closed(Value::Object(properties));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        assert_eq!(
            generate(&schema, &context(&paths, &datasets))
                .unwrap_err()
                .kind,
            GenerationErrorKind::OutputLimit
        );
    }

    #[test]
    fn explicit_path_and_reference_recipes_use_only_snapshotted_inputs() {
        let schema = closed(json!({
            "person_id": {"type": "string", "x-evidencectl-mock": {"fromRequest": {"pathParameter": "person_id"}}},
            "code": {"type": "string", "x-evidencectl-mock": {"reference": {"dataset": "places", "field": "code"}}}
        }));
        let paths = BTreeMap::from([(
            "person_id".to_owned(),
            PathParameter::String("person-123".to_owned()),
        )]);
        let datasets = BTreeMap::from([(
            "places".to_owned(),
            ReferenceDataset {
                digest: [9; 32],
                rows: vec![
                    Map::from_iter([("code".to_owned(), json!("A"))]),
                    Map::from_iter([("code".to_owned(), json!("B"))]),
                ],
            },
        )]);
        let generated = generate(&schema, &context(&paths, &datasets)).unwrap();
        assert_eq!(generated.value["person_id"], "person-123");
        assert!(matches!(generated.value["code"].as_str(), Some("A" | "B")));
    }

    #[test]
    fn age_uses_the_february_28_anniversary_predicate() {
        let birth = NaiveDate::from_ymd_opt(2004, 2, 29).unwrap();
        assert_eq!(
            completed_age(birth, NaiveDate::from_ymd_opt(2025, 2, 27).unwrap()),
            20
        );
        assert_eq!(
            completed_age(birth, NaiveDate::from_ymd_opt(2025, 2, 28).unwrap()),
            21
        );

        let schema = closed(
            json!({"birthDate": {"type": "string", "format": "date", "x-evidencectl-mock": {"distribution": {"kind": "age", "min": 21, "max": 21}}}}),
        );
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let mut generation_context = context(&paths, &datasets);
        generation_context.as_of = NaiveDate::from_ymd_opt(2025, 2, 28).unwrap();
        let generated = generate(&schema, &generation_context).unwrap();
        let generated_birth =
            NaiveDate::parse_from_str(generated.value["birthDate"].as_str().unwrap(), "%Y-%m-%d")
                .unwrap();
        assert_eq!(completed_age(generated_birth, generation_context.as_of), 21);
    }

    #[test]
    fn closed_formats_are_valid_and_documentation_scoped() {
        let properties = [
            "date",
            "date-time",
            "time",
            "duration",
            "email",
            "uuid",
            "uri",
            "url",
            "uri-reference",
            "hostname",
            "ipv4",
            "ipv6",
            "byte",
            "json-pointer",
            "relative-json-pointer",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, format)| {
            (
                format!("field{index}"),
                json!({"type": "string", "format": format}),
            )
        })
        .collect::<Map<_, _>>();
        let schema = closed(Value::Object(properties));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let generated = generate(&schema, &context(&paths, &datasets)).unwrap();
        for (index, format) in [
            "date",
            "date-time",
            "time",
            "duration",
            "email",
            "uuid",
            "uri",
            "url",
            "uri-reference",
            "hostname",
            "ipv4",
            "ipv6",
            "byte",
            "json-pointer",
            "relative-json-pointer",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                format_valid(
                    format,
                    generated.value[format!("field{index}")].as_str().unwrap()
                ),
                "{format}"
            );
        }
        assert!(generated.value["field6"]
            .as_str()
            .unwrap()
            .contains("example.invalid"));
        assert!(generated.value["field10"]
            .as_str()
            .unwrap()
            .starts_with("192.0.2."));
        assert!(generated.value["field11"]
            .as_str()
            .unwrap()
            .starts_with("2001:db8:"));
    }

    #[test]
    fn seed_payload_is_tagged_and_domain_separated() {
        let mut left = SeedPayload::default();
        left.utf8("a", "bc");
        let mut right = SeedPayload::default();
        right.utf8("ab", "c");
        assert_ne!(left.bytes, right.bytes);
        assert_ne!(
            domain_separated_sha256(SEED_DOMAIN, &left.bytes),
            domain_separated_sha256(b"other\0", &left.bytes)
        );
    }

    #[test]
    fn pretty_json_sorts_keys_and_has_one_newline() {
        let bytes = to_pretty_json(&json!({"z": 1, "a": {"y": 2, "b": 3}})).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\n  \"a\": {\n    \"b\": 3,\n    \"y\": 2\n  },\n  \"z\": 1\n}\n"
        );
    }

    #[test]
    fn pointers_escape_raw_property_keys_and_decimal_integer_bounds_are_respected() {
        let schema = closed(json!({
            "a/b~c": {"type": "string"},
            "count": {"type": "integer", "minimum": 1.2, "maximum": 2.8}
        }));
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let generated = generate(&schema, &context(&paths, &datasets)).unwrap();
        assert_eq!(generated.inference[0].schema_pointer, "/a~1b~0c");
        assert_eq!(generated.value["count"], 2);
    }

    #[test]
    fn materialized_value_validation_checks_nested_owned_formats() {
        let schema = closed(json!({
            "profile": {
                "type": "object",
                "additionalProperties": false,
                "required": ["email"],
                "properties": {"email": {"type": "string", "format": "email"}}
            }
        }));
        assert!(value_satisfies(
            &schema,
            &json!({"profile": {"email": "person@example.invalid"}})
        ));
        assert!(!value_satisfies(
            &schema,
            &json!({"profile": {"email": "not-an-email"}})
        ));
        assert!(!value_satisfies(
            &schema,
            &json!({"profile": {"email": "person@example.invalid", "extra": true}})
        ));

        let nullable = json!({"type": ["string", "null"], "format": "email"});
        assert!(value_satisfies(&nullable, &Value::Null));
    }

    #[test]
    fn failures_do_not_render_values() {
        let schema = closed(
            json!({"secret": {"type": "string", "x-evidencectl-mock": {"fromRequest": {"pathParameter": "canary-secret"}}}}),
        );
        let paths = BTreeMap::new();
        let datasets = BTreeMap::new();
        let rendered = generate(&schema, &context(&paths, &datasets))
            .unwrap_err()
            .to_string();
        assert!(!rendered.contains("canary-secret"));
    }
}
