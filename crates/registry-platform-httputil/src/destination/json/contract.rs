// SPDX-License-Identifier: Apache-2.0
//! Bounded closed-schema and projection contract compilation.

use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;

use crate::destination::DataDestinationBody;

use super::decode::{decode_body, ClosedJsonDecodeError, ClosedJsonOutcome};

/// Maximum nesting accepted in a closed response schema.
pub const MAX_CLOSED_JSON_SCHEMA_DEPTH: usize = 8;
/// Maximum distinct nodes retained by a closed response schema.
pub const MAX_CLOSED_JSON_SCHEMA_NODES: usize = 256;
/// Maximum runtime-expanded nodes across bounded arrays.
pub const MAX_CLOSED_JSON_EXPANDED_NODES: usize = 4_096;
/// Maximum fields in one closed response object.
pub const MAX_CLOSED_JSON_OBJECT_FIELDS: usize = 32;
/// Maximum items in one schema-bounded response array.
pub const MAX_CLOSED_JSON_ARRAY_ITEMS: u16 = 256;
/// Maximum scalar projections released from one record.
pub const MAX_CLOSED_JSON_PROJECTIONS: usize = 64;
/// Maximum bytes in a field, projection name, or decoded pointer token.
pub const MAX_CLOSED_JSON_NAME_BYTES: usize = 128;
/// Maximum bytes retained by one projected response string.
pub const MAX_CLOSED_JSON_STRING_BYTES: u32 = 64 * 1_024;

const MAX_EXACT_JSON_INTEGER: i64 = 9_007_199_254_740_991;
// Preserve the decoder's existing value-free syntax, contract, and cardinality
// classifications for small near-boundary failures while keeping parser work
// within a fixed factor of the largest closed-schema response.
const PREFLIGHT_TOKEN_HEADROOM_MULTIPLIER: usize = 2;

type ProjectionTokens = Box<[Box<str>]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClosedJsonDecoderBuildError {
    #[error("closed JSON schema is outside platform bounds")]
    InvalidSchema,
    #[error("closed JSON record normalization does not match its schema")]
    InvalidNormalization,
    #[error("closed JSON scalar projection is invalid")]
    InvalidProjection,
}

/// One required or optional field in a closed object schema.
pub struct ClosedJsonField {
    pub(super) name: Box<str>,
    pub(super) required: bool,
    pub(super) schema: ClosedJsonSchema,
}

impl ClosedJsonField {
    /// Compile one bounded field name and child schema.
    pub fn new(
        name: &str,
        required: bool,
        schema: ClosedJsonSchema,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        if !valid_name(name) {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        Ok(Self {
            name: name.into(),
            required,
            schema,
        })
    }
}

impl fmt::Debug for ClosedJsonField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedJsonField")
            .field("name", &"[REDACTED]")
            .field("required", &self.required)
            .field("schema", &self.schema)
            .finish()
    }
}

/// Opaque recursive schema for a completely closed JSON response.
pub struct ClosedJsonSchema {
    pub(super) node: ClosedJsonSchemaNode,
}

pub(super) enum ClosedJsonSchemaNode {
    Object {
        nullable: bool,
        fields: Box<[ClosedJsonField]>,
    },
    Array {
        nullable: bool,
        max_items: u16,
        items: Box<ClosedJsonSchema>,
    },
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

impl ClosedJsonSchema {
    /// Compile a non-empty object whose fields are the complete accepted set.
    pub fn object(
        nullable: bool,
        fields: Vec<ClosedJsonField>,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        if fields.is_empty() || fields.len() > MAX_CLOSED_JSON_OBJECT_FIELDS {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        let mut names = BTreeSet::new();
        if fields
            .iter()
            .any(|field| !names.insert(field.name.as_ref()))
        {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        Ok(Self {
            node: ClosedJsonSchemaNode::Object {
                nullable,
                fields: fields.into_boxed_slice(),
            },
        })
    }

    /// Compile an array with a non-zero item ceiling.
    pub fn array(
        nullable: bool,
        max_items: u16,
        items: ClosedJsonSchema,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        if !(1..=MAX_CLOSED_JSON_ARRAY_ITEMS).contains(&max_items) {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        Ok(Self {
            node: ClosedJsonSchemaNode::Array {
                nullable,
                max_items,
                items: Box::new(items),
            },
        })
    }

    /// Compile a byte-bounded JSON string.
    pub fn string(nullable: bool, max_bytes: u32) -> Result<Self, ClosedJsonDecoderBuildError> {
        if !(1..=MAX_CLOSED_JSON_STRING_BYTES).contains(&max_bytes) {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        Ok(Self {
            node: ClosedJsonSchemaNode::String {
                nullable,
                max_bytes,
            },
        })
    }

    /// Compile a JSON boolean.
    #[must_use]
    pub const fn boolean(nullable: bool) -> Self {
        Self {
            node: ClosedJsonSchemaNode::Boolean { nullable },
        }
    }

    /// Compile an exact bounded JSON integer.
    pub fn integer(
        nullable: bool,
        minimum: i64,
        maximum: i64,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        validate_numeric_bounds(minimum, maximum)?;
        Ok(Self {
            node: ClosedJsonSchemaNode::Integer {
                nullable,
                minimum,
                maximum,
            },
        })
    }

    /// Compile a finite JSON number with exact integer bounds.
    pub fn number(
        nullable: bool,
        minimum: i64,
        maximum: i64,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        validate_numeric_bounds(minimum, maximum)?;
        Ok(Self {
            node: ClosedJsonSchemaNode::Number {
                nullable,
                minimum,
                maximum,
            },
        })
    }

    pub(super) fn nullable(&self) -> bool {
        match &self.node {
            ClosedJsonSchemaNode::Object { nullable, .. }
            | ClosedJsonSchemaNode::Array { nullable, .. }
            | ClosedJsonSchemaNode::String { nullable, .. }
            | ClosedJsonSchemaNode::Boolean { nullable }
            | ClosedJsonSchemaNode::Integer { nullable, .. }
            | ClosedJsonSchemaNode::Number { nullable, .. } => *nullable,
        }
    }
}

impl fmt::Debug for ClosedJsonSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, child_count) = match &self.node {
            ClosedJsonSchemaNode::Object { fields, .. } => ("object", fields.len()),
            ClosedJsonSchemaNode::Array { .. } => ("array", 1),
            ClosedJsonSchemaNode::String { .. } => ("string", 0),
            ClosedJsonSchemaNode::Boolean { .. } => ("boolean", 0),
            ClosedJsonSchemaNode::Integer { .. } => ("integer", 0),
            ClosedJsonSchemaNode::Number { .. } => ("number", 0),
        };
        formatter
            .debug_struct("ClosedJsonSchema")
            .field("kind", &kind)
            .field("nullable", &self.nullable())
            .field("child_count", &child_count)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Reviewed record-root normalization.
pub enum ClosedJsonRecordRoot {
    /// One root object is the record.
    Object,
    /// A root array contains zero, one, or two records.
    ArrayProbeTwo,
    /// A designated root-object field contains zero, one, or two records.
    ObjectArrayProbeTwo { field_index: usize },
}

/// One named decoded pointer to a scalar relative to the normalized record.
pub struct ClosedJsonScalarProjection {
    name: Box<str>,
    tokens: Box<[Box<str>]>,
}

impl ClosedJsonScalarProjection {
    /// Compile already-decoded JSON Pointer tokens.
    pub fn new<'a>(
        name: &str,
        tokens: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        let (name, tokens) = projection_path(name, tokens)?;
        Ok(Self { name, tokens })
    }
}

/// One named decoded pointer whose non-null presence may be released.
///
/// The decoded value is a boolean. It is `true` only when every path segment
/// exists and the selected value is not JSON `null`; no selected value escapes
/// the decoder.
pub struct ClosedJsonPresenceProjection {
    name: Box<str>,
    tokens: Box<[Box<str>]>,
}

impl ClosedJsonPresenceProjection {
    /// Compile already-decoded JSON Pointer tokens.
    pub fn new<'a>(
        name: &str,
        tokens: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        let (name, tokens) = projection_path(name, tokens)?;
        Ok(Self { name, tokens })
    }
}

impl fmt::Debug for ClosedJsonPresenceProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedJsonPresenceProjection")
            .field("name", &"[REDACTED]")
            .field("token_count", &self.tokens.len())
            .finish()
    }
}

impl fmt::Debug for ClosedJsonScalarProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedJsonScalarProjection")
            .field("name", &"[REDACTED]")
            .field("token_count", &self.tokens.len())
            .finish()
    }
}

/// Immutable decoder contract compiled before sensitive data exists.
pub struct ClosedJsonDecoder {
    pub(super) schema: ClosedJsonSchema,
    pub(super) root: CompiledRecordRoot,
    pub(super) projections: Box<[CompiledScalarProjection]>,
    pub(super) presence_projections: Box<[CompiledPresenceProjection]>,
    pub(super) preflight_token_limit: usize,
    pub(super) preflight_depth_limit: usize,
}

impl ClosedJsonDecoder {
    /// Validate the schema, normalization, and scalar projections together.
    pub fn new(
        schema: ClosedJsonSchema,
        root: ClosedJsonRecordRoot,
        projections: Vec<ClosedJsonScalarProjection>,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        Self::new_with_presence(schema, root, projections, Vec::new())
    }

    /// Validate a decoder with scalar and value-free non-null projections.
    pub fn new_with_presence(
        schema: ClosedJsonSchema,
        root: ClosedJsonRecordRoot,
        projections: Vec<ClosedJsonScalarProjection>,
        presence_projections: Vec<ClosedJsonPresenceProjection>,
    ) -> Result<Self, ClosedJsonDecoderBuildError> {
        let mut nodes = 0;
        let expanded = validate_schema_contract(&schema, 1, &mut nodes)?;
        if expanded > MAX_CLOSED_JSON_EXPANDED_NODES {
            return Err(ClosedJsonDecoderBuildError::InvalidSchema);
        }
        if projections
            .len()
            .checked_add(presence_projections.len())
            .filter(|count| *count <= MAX_CLOSED_JSON_PROJECTIONS)
            .is_none()
        {
            return Err(ClosedJsonDecoderBuildError::InvalidProjection);
        }
        let preflight_token_limit = maximum_runtime_tokens(&schema)?
            .checked_mul(PREFLIGHT_TOKEN_HEADROOM_MULTIPLIER)
            .ok_or(ClosedJsonDecoderBuildError::InvalidSchema)?;
        let preflight_depth_limit = maximum_runtime_depth(&schema);
        let compiled_root = compile_record_root(&schema, root)?;
        let record_schema = normalized_record_schema(&schema, root)?;
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let projections = projections
            .into_iter()
            .map(|projection| {
                if !names.insert(projection.name.clone()) {
                    return Err(ClosedJsonDecoderBuildError::InvalidProjection);
                }
                let compiled = compile_projection(record_schema, projection)?;
                if !paths.insert(compiled.steps.clone()) {
                    return Err(ClosedJsonDecoderBuildError::InvalidProjection);
                }
                Ok(compiled)
            })
            .collect::<Result<Box<[_]>, _>>()?;
        let mut presence_paths = BTreeSet::new();
        let presence_projections = presence_projections
            .into_iter()
            .map(|projection| {
                if !names.insert(projection.name.clone()) {
                    return Err(ClosedJsonDecoderBuildError::InvalidProjection);
                }
                let compiled = compile_presence_projection(record_schema, projection)?;
                if !presence_paths.insert(compiled.steps.clone()) {
                    return Err(ClosedJsonDecoderBuildError::InvalidProjection);
                }
                Ok(compiled)
            })
            .collect::<Result<Box<[_]>, _>>()?;
        Ok(Self {
            schema,
            root: compiled_root,
            projections,
            presence_projections,
            preflight_token_limit,
            preflight_depth_limit,
        })
    }

    /// Consume a registry-data body and release only normalized projections.
    ///
    /// ```compile_fail
    /// use registry_platform_httputil::destination::json::ClosedJsonDecoder;
    /// use registry_platform_httputil::destination::CredentialDestinationBody;
    ///
    /// fn credential_bytes_cannot_enter(
    ///     decoder: &ClosedJsonDecoder,
    ///     body: CredentialDestinationBody,
    /// ) {
    ///     let _ = decoder.decode(body);
    /// }
    /// ```
    pub fn decode(
        &self,
        body: DataDestinationBody,
    ) -> Result<ClosedJsonOutcome, ClosedJsonDecodeError> {
        decode_body(self, body)
    }
}

impl fmt::Debug for ClosedJsonDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedJsonDecoder")
            .field("schema", &self.schema)
            .field("root", &self.root)
            .field("projection_count", &self.projections.len())
            .field(
                "presence_projection_count",
                &self.presence_projections.len(),
            )
            .field("projections", &"[REDACTED]")
            .field("preflight_token_limit", &self.preflight_token_limit)
            .field("preflight_depth_limit", &self.preflight_depth_limit)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ProjectionStep {
    Object(Box<str>),
    Array(usize),
}

pub(super) struct CompiledScalarProjection {
    pub(super) name: Box<str>,
    pub(super) steps: Box<[ProjectionStep]>,
    pub(super) scalar: ScalarContract,
}

pub(super) struct CompiledPresenceProjection {
    pub(super) name: Box<str>,
    pub(super) steps: Box<[ProjectionStep]>,
}

pub(super) enum CompiledRecordRoot {
    Object,
    ArrayProbeTwo,
    ObjectArrayProbeTwo { field: Box<str> },
}

impl fmt::Debug for CompiledRecordRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Object => formatter.write_str("Object"),
            Self::ArrayProbeTwo => formatter.write_str("ArrayProbeTwo"),
            Self::ObjectArrayProbeTwo { .. } => formatter
                .debug_struct("ObjectArrayProbeTwo")
                .field("field", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum ScalarContract {
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

impl ScalarContract {
    pub(super) const fn nullable(self) -> bool {
        match self {
            Self::String { nullable, .. }
            | Self::Boolean { nullable }
            | Self::Integer { nullable, .. }
            | Self::Number { nullable, .. } => nullable,
        }
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLOSED_JSON_NAME_BYTES
        && !value.chars().any(char::is_control)
}

fn projection_path<'a>(
    name: &str,
    tokens: impl IntoIterator<Item = &'a str>,
) -> Result<(Box<str>, ProjectionTokens), ClosedJsonDecoderBuildError> {
    if !valid_name(name) {
        return Err(ClosedJsonDecoderBuildError::InvalidProjection);
    }
    let tokens = tokens
        .into_iter()
        .map(|token| {
            valid_name(token)
                .then(|| Box::<str>::from(token))
                .ok_or(ClosedJsonDecoderBuildError::InvalidProjection)
        })
        .collect::<Result<Box<[_]>, _>>()?;
    if tokens.is_empty() || tokens.len() > MAX_CLOSED_JSON_SCHEMA_DEPTH {
        return Err(ClosedJsonDecoderBuildError::InvalidProjection);
    }
    Ok((name.into(), tokens))
}

fn validate_numeric_bounds(minimum: i64, maximum: i64) -> Result<(), ClosedJsonDecoderBuildError> {
    if minimum > maximum
        || minimum.unsigned_abs() > MAX_EXACT_JSON_INTEGER as u64
        || maximum.unsigned_abs() > MAX_EXACT_JSON_INTEGER as u64
    {
        return Err(ClosedJsonDecoderBuildError::InvalidSchema);
    }
    Ok(())
}

fn validate_schema_contract(
    schema: &ClosedJsonSchema,
    depth: usize,
    nodes: &mut usize,
) -> Result<usize, ClosedJsonDecoderBuildError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(ClosedJsonDecoderBuildError::InvalidSchema)?;
    if depth > MAX_CLOSED_JSON_SCHEMA_DEPTH || *nodes > MAX_CLOSED_JSON_SCHEMA_NODES {
        return Err(ClosedJsonDecoderBuildError::InvalidSchema);
    }
    match &schema.node {
        ClosedJsonSchemaNode::Object { fields, .. } => {
            if fields.is_empty() || fields.len() > MAX_CLOSED_JSON_OBJECT_FIELDS {
                return Err(ClosedJsonDecoderBuildError::InvalidSchema);
            }
            let mut names = BTreeSet::new();
            let mut expanded = 1_usize;
            for field in fields {
                if !valid_name(&field.name) || !names.insert(field.name.as_ref()) {
                    return Err(ClosedJsonDecoderBuildError::InvalidSchema);
                }
                expanded = expanded
                    .checked_add(validate_schema_contract(&field.schema, depth + 1, nodes)?)
                    .ok_or(ClosedJsonDecoderBuildError::InvalidSchema)?;
            }
            Ok(expanded)
        }
        ClosedJsonSchemaNode::Array {
            max_items, items, ..
        } => {
            if !(1..=MAX_CLOSED_JSON_ARRAY_ITEMS).contains(max_items) {
                return Err(ClosedJsonDecoderBuildError::InvalidSchema);
            }
            validate_schema_contract(items, depth + 1, nodes)?
                .checked_mul(usize::from(*max_items))
                .and_then(|expanded| expanded.checked_add(1))
                .ok_or(ClosedJsonDecoderBuildError::InvalidSchema)
        }
        ClosedJsonSchemaNode::String { max_bytes, .. }
            if (1..=MAX_CLOSED_JSON_STRING_BYTES).contains(max_bytes) =>
        {
            Ok(1)
        }
        ClosedJsonSchemaNode::Boolean { .. } => Ok(1),
        ClosedJsonSchemaNode::Integer {
            minimum, maximum, ..
        }
        | ClosedJsonSchemaNode::Number {
            minimum, maximum, ..
        } => {
            validate_numeric_bounds(*minimum, *maximum)?;
            Ok(1)
        }
        ClosedJsonSchemaNode::String { .. } => Err(ClosedJsonDecoderBuildError::InvalidSchema),
    }
}

/// Count every runtime JSON value plus every object key that a response
/// conforming to this schema can contain. Every parser-owned string or map
/// entry has a counted key/value token, and every sequence entry and `Value`
/// node has a counted value token. The byte preflight uses this fixed-factor
/// allocation bound before any parser allocation.
fn maximum_runtime_tokens(schema: &ClosedJsonSchema) -> Result<usize, ClosedJsonDecoderBuildError> {
    match &schema.node {
        ClosedJsonSchemaNode::Object { fields, .. } => {
            fields.iter().try_fold(1_usize, |tokens, field| {
                let child_tokens = maximum_runtime_tokens(&field.schema)?;
                tokens
                    .checked_add(1)
                    .and_then(|tokens| tokens.checked_add(child_tokens))
                    .ok_or(ClosedJsonDecoderBuildError::InvalidSchema)
            })
        }
        ClosedJsonSchemaNode::Array {
            max_items, items, ..
        } => maximum_runtime_tokens(items)?
            .checked_mul(usize::from(*max_items))
            .and_then(|tokens| tokens.checked_add(1))
            .ok_or(ClosedJsonDecoderBuildError::InvalidSchema),
        ClosedJsonSchemaNode::String { .. }
        | ClosedJsonSchemaNode::Boolean { .. }
        | ClosedJsonSchemaNode::Integer { .. }
        | ClosedJsonSchemaNode::Number { .. } => Ok(1),
    }
}

fn maximum_runtime_depth(schema: &ClosedJsonSchema) -> usize {
    match &schema.node {
        ClosedJsonSchemaNode::Object { fields, .. } => {
            fields
                .iter()
                .map(|field| maximum_runtime_depth(&field.schema))
                .max()
                .unwrap_or(0)
                + 1
        }
        ClosedJsonSchemaNode::Array { items, .. } => maximum_runtime_depth(items) + 1,
        ClosedJsonSchemaNode::String { .. }
        | ClosedJsonSchemaNode::Boolean { .. }
        | ClosedJsonSchemaNode::Integer { .. }
        | ClosedJsonSchemaNode::Number { .. } => 1,
    }
}

fn normalized_record_schema(
    schema: &ClosedJsonSchema,
    root: ClosedJsonRecordRoot,
) -> Result<&ClosedJsonSchema, ClosedJsonDecoderBuildError> {
    match (root, &schema.node) {
        (
            ClosedJsonRecordRoot::Object,
            ClosedJsonSchemaNode::Object {
                nullable: false, ..
            },
        ) => Ok(schema),
        (
            ClosedJsonRecordRoot::ArrayProbeTwo,
            ClosedJsonSchemaNode::Array {
                nullable: false,
                max_items: 2,
                items,
            },
        ) if non_nullable_object(items) => Ok(items),
        (
            ClosedJsonRecordRoot::ObjectArrayProbeTwo { field_index },
            ClosedJsonSchemaNode::Object {
                nullable: false,
                fields,
            },
        ) => {
            let field = fields
                .get(field_index)
                .ok_or(ClosedJsonDecoderBuildError::InvalidNormalization)?;
            if !field.required
                || fields.iter().enumerate().any(|(index, candidate)| {
                    index != field_index
                        && matches!(candidate.schema.node, ClosedJsonSchemaNode::Array { .. })
                })
            {
                return Err(ClosedJsonDecoderBuildError::InvalidNormalization);
            }
            match &field.schema.node {
                ClosedJsonSchemaNode::Array {
                    nullable: false,
                    max_items: 2,
                    items,
                } if non_nullable_object(items) => Ok(items),
                _ => Err(ClosedJsonDecoderBuildError::InvalidNormalization),
            }
        }
        _ => Err(ClosedJsonDecoderBuildError::InvalidNormalization),
    }
}

fn compile_record_root(
    schema: &ClosedJsonSchema,
    root: ClosedJsonRecordRoot,
) -> Result<CompiledRecordRoot, ClosedJsonDecoderBuildError> {
    normalized_record_schema(schema, root)?;
    Ok(match root {
        ClosedJsonRecordRoot::Object => CompiledRecordRoot::Object,
        ClosedJsonRecordRoot::ArrayProbeTwo => CompiledRecordRoot::ArrayProbeTwo,
        ClosedJsonRecordRoot::ObjectArrayProbeTwo { field_index } => {
            let ClosedJsonSchemaNode::Object { fields, .. } = &schema.node else {
                return Err(ClosedJsonDecoderBuildError::InvalidNormalization);
            };
            CompiledRecordRoot::ObjectArrayProbeTwo {
                field: fields
                    .get(field_index)
                    .ok_or(ClosedJsonDecoderBuildError::InvalidNormalization)?
                    .name
                    .clone(),
            }
        }
    })
}

fn non_nullable_object(schema: &ClosedJsonSchema) -> bool {
    matches!(
        schema.node,
        ClosedJsonSchemaNode::Object {
            nullable: false,
            ..
        }
    )
}

fn compile_projection(
    record_schema: &ClosedJsonSchema,
    projection: ClosedJsonScalarProjection,
) -> Result<CompiledScalarProjection, ClosedJsonDecoderBuildError> {
    let (projected_schema, steps) = compile_projection_steps(record_schema, &projection.tokens)?;
    Ok(CompiledScalarProjection {
        name: projection.name,
        steps,
        scalar: scalar_contract(projected_schema)?,
    })
}

fn compile_presence_projection(
    record_schema: &ClosedJsonSchema,
    projection: ClosedJsonPresenceProjection,
) -> Result<CompiledPresenceProjection, ClosedJsonDecoderBuildError> {
    let (_, steps) = compile_projection_steps(record_schema, &projection.tokens)?;
    Ok(CompiledPresenceProjection {
        name: projection.name,
        steps,
    })
}

fn compile_projection_steps<'schema>(
    record_schema: &'schema ClosedJsonSchema,
    tokens: &[Box<str>],
) -> Result<(&'schema ClosedJsonSchema, Box<[ProjectionStep]>), ClosedJsonDecoderBuildError> {
    let mut current = record_schema;
    let mut steps = Vec::with_capacity(tokens.len());
    for token in tokens {
        current = match &current.node {
            ClosedJsonSchemaNode::Object { fields, .. } => {
                let field = fields
                    .iter()
                    .find(|field| field.name.as_ref() == token.as_ref())
                    .ok_or(ClosedJsonDecoderBuildError::InvalidProjection)?;
                steps.push(ProjectionStep::Object(field.name.clone()));
                &field.schema
            }
            ClosedJsonSchemaNode::Array {
                max_items, items, ..
            } => {
                let index = canonical_array_index(token)
                    .filter(|index| *index < usize::from(*max_items))
                    .ok_or(ClosedJsonDecoderBuildError::InvalidProjection)?;
                steps.push(ProjectionStep::Array(index));
                items
            }
            ClosedJsonSchemaNode::String { .. }
            | ClosedJsonSchemaNode::Boolean { .. }
            | ClosedJsonSchemaNode::Integer { .. }
            | ClosedJsonSchemaNode::Number { .. } => {
                return Err(ClosedJsonDecoderBuildError::InvalidProjection);
            }
        };
    }
    Ok((current, steps.into_boxed_slice()))
}

fn canonical_array_index(token: &str) -> Option<usize> {
    if token.is_empty() || (token.len() > 1 && token.starts_with('0')) {
        return None;
    }
    token
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| token.parse::<u16>().ok().map(usize::from))
        .flatten()
}

fn scalar_contract(
    schema: &ClosedJsonSchema,
) -> Result<ScalarContract, ClosedJsonDecoderBuildError> {
    match schema.node {
        ClosedJsonSchemaNode::String {
            nullable,
            max_bytes,
        } => Ok(ScalarContract::String {
            nullable,
            max_bytes,
        }),
        ClosedJsonSchemaNode::Boolean { nullable } => Ok(ScalarContract::Boolean { nullable }),
        ClosedJsonSchemaNode::Integer {
            nullable,
            minimum,
            maximum,
        } => Ok(ScalarContract::Integer {
            nullable,
            minimum,
            maximum,
        }),
        ClosedJsonSchemaNode::Number {
            nullable,
            minimum,
            maximum,
        } => Ok(ScalarContract::Number {
            nullable,
            minimum,
            maximum,
        }),
        ClosedJsonSchemaNode::Object { .. } | ClosedJsonSchemaNode::Array { .. } => {
            Err(ClosedJsonDecoderBuildError::InvalidProjection)
        }
    }
}
