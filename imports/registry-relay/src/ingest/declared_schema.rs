// SPDX-License-Identifier: Apache-2.0
//! Compiled, decoder-friendly view of a configured resource schema.
//!
//! Built once from a [`crate::config::SchemaConfig`] at `IngestPlan`
//! construction and shared across refreshes via `Arc`. Decoders read it
//! through [`crate::format::FormatHints`] for type coercion;
//! [`crate::ingest::validation`] reads it for the §4 rule table.
//!
//! `concept_uri / codelist / unit / language` are carried through even
//! though they don't drive any Wave 1 behaviour: Wave 3's CSVW renderer
//! consumes them off the registered schema (architect note §9 risk #9).

use std::sync::Arc;

use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};

use crate::config::{FieldType, SchemaConfig};

/// Declared schema for one resource. Built once from the config at
/// `IngestPlan` construction and shared across refreshes via `Arc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSchema {
    pub strict: bool,
    pub fields: Vec<DeclaredField>,
}

/// One declared field. Decoders consult `ty` for type coercion when the
/// underlying format has no native type (CSV) or returns a sloppy type
/// (XLSX cells).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredField {
    pub name: String,
    pub ty: FieldType,
    pub nullable: bool,
    pub concept_uri: Option<String>,
    pub codelist: Option<String>,
    pub unit: Option<String>,
    pub language: Option<String>,
}

impl DeclaredSchema {
    /// Empty placeholder used by the architect's precondition tests and
    /// by decoder unit tests that don't care about declared types.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            strict: false,
            fields: Vec::new(),
        })
    }

    /// Look up a declared field by name. Case-sensitive (the §4 rule
    /// table treats field-name case mismatch as a hard fail).
    pub fn field(&self, name: &str) -> Option<&DeclaredField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Arrow schema that the declared types correspond to. Order is
    /// preserved (Arrow schemas are position-sensitive). Used by the
    /// validator's `ProjectionPlan` to know the target column order and
    /// types of the post-cast batch.
    ///
    /// Type mapping:
    /// - `String`    -> `Utf8`
    /// - `Integer`   -> `Int64`
    /// - `Number`    -> `Float64`
    /// - `Boolean`   -> `Boolean`
    /// - `Date`      -> `Date32`
    /// - `Timestamp` -> `Timestamp(Millisecond, "UTC")`
    pub fn to_arrow_schema(&self) -> SchemaRef {
        let fields: Vec<Field> = self
            .fields
            .iter()
            .map(|f| Field::new(&f.name, declared_type_to_arrow(f.ty), f.nullable))
            .collect();
        Arc::new(Schema::new(fields))
    }
}

/// Maps a declared physical type to its Arrow [`DataType`] equivalent.
/// Kept here so both the validator and the decoder builders share one
/// authoritative mapping.
pub(crate) fn declared_type_to_arrow(ty: FieldType) -> DataType {
    match ty {
        FieldType::String => DataType::Utf8,
        FieldType::Integer => DataType::Int64,
        FieldType::Number => DataType::Float64,
        FieldType::Boolean => DataType::Boolean,
        FieldType::Date => DataType::Date32,
        FieldType::Timestamp => DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
    }
}

impl From<&SchemaConfig> for DeclaredSchema {
    /// Walk the [`SchemaConfig`] and lift it into a [`DeclaredSchema`].
    /// Field order is preserved; semantic annotations
    /// (`concept_uri / codelist / unit / language`) are cloned through
    /// so Wave 3's CSVW renderer can read them.
    fn from(cfg: &SchemaConfig) -> Self {
        let fields = cfg
            .fields
            .iter()
            .map(|f| DeclaredField {
                name: f.name.clone(),
                ty: f.r#type,
                nullable: f.nullable,
                concept_uri: f.concept_uri.clone(),
                codelist: f.codelist.clone(),
                unit: f.unit.clone(),
                language: f.language.clone(),
            })
            .collect();
        Self {
            strict: cfg.strict,
            fields,
        }
    }
}
