// SPDX-License-Identifier: Apache-2.0
//! Optional PublicSchema.org CEL mapping support for entity-record VCs.
//!
//! The config model is always parsed, but the runtime mapper is compiled
//! only when the crate is built with `publicschema-cel`.

use serde_json::Value;

use crate::config::Config;
use crate::error::{ConfigError, Error};

#[derive(Debug, Clone)]
pub struct PublicSchemaMappedCredential {
    pub subject_uri: String,
    pub credential_subject: Value,
    pub context_url: String,
    pub schema_url: String,
    pub credential_type: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublicSchemaIssueError {
    #[error("publicschema mapping failed")]
    MappingFailed,
    #[error("publicschema mapping did not produce a subject id")]
    MissingSubjectId,
    #[error("publicschema subject id mismatch")]
    SubjectIdMismatch { expected: String, actual: String },
    #[error("publicschema schema validation failed")]
    SchemaValidationFailed(Vec<String>),
}

#[cfg(feature = "publicschema-cel")]
mod enabled {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use crosswalk_core::{
        CompiledPublicSchemaMapping, MappingError, MappingRuntime, PrivacyMode,
        PublicSchemaDirection, PublicSchemaEvaluateOptions, PublicSchemaEvaluationInput,
        RuntimeOptions,
    };
    use jsonschema::error::{ValidationError, ValidationErrorKind};
    use serde_json::json;

    const DEFAULT_PUBLICSCHEMA_CONTEXT_URL: &str = "https://publicschema.org/ctx/draft.jsonld";
    const DEFAULT_PUBLICSCHEMA_SCHEMA_BASE: &str = "https://publicschema.org/schemas";

    struct PublicSchemaVcProfile {
        compiled: Arc<CompiledPublicSchemaMapping>,
        compiled_schema: Option<Arc<jsonschema::JSONSchema>>,
        context_url: String,
        schema_url: String,
        credential_type: String,
    }

    #[derive(Clone, Default)]
    pub struct PublicSchemaVcRegistry {
        profiles: Arc<BTreeMap<(String, String), Arc<PublicSchemaVcProfile>>>,
    }

    impl std::fmt::Debug for PublicSchemaVcRegistry {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PublicSchemaVcRegistry")
                .field("profile_count", &self.profiles.len())
                .finish()
        }
    }

    impl PublicSchemaVcRegistry {
        pub fn is_empty(&self) -> bool {
            self.profiles.is_empty()
        }

        pub fn mapped_entity_credential(
            &self,
            dataset: &str,
            entity: &str,
            expected_subject_uri: &str,
            record: Value,
        ) -> Result<Option<PublicSchemaMappedCredential>, PublicSchemaIssueError> {
            let Some(profile) = self
                .profiles
                .get(&(dataset.to_string(), entity.to_string()))
            else {
                return Ok(None);
            };
            let rt = MappingRuntime::new(RuntimeOptions::default());
            let transform = rt.evaluate_publicschema_mapping(
                &profile.compiled,
                PublicSchemaEvaluationInput {
                    source: record,
                    context: json!({
                        "dataset": dataset,
                        "entity": entity,
                        "subject_uri": expected_subject_uri,
                    }),
                    options: PublicSchemaEvaluateOptions {
                        direction: PublicSchemaDirection::ToTarget,
                        errors_mode: Some("collect".to_string()),
                        privacy: PrivacyMode::Production,
                    },
                },
            );
            if !transform.ok {
                tracing::error!(
                    errors = ?mapping_issue_diagnostics(&transform.errors, "error"),
                    "publicschema.mapping_failed"
                );
                return Err(PublicSchemaIssueError::MappingFailed);
            }
            if !transform.warnings.is_empty() {
                tracing::warn!(
                    warnings = ?mapping_issue_diagnostics(&transform.warnings, "warning"),
                    "publicschema.mapping_warnings"
                );
            }
            if let Some(schema) = &profile.compiled_schema {
                if let Err(errors) = schema.validate(&transform.output) {
                    let messages = schema_validation_diagnostics(errors);
                    tracing::error!(
                        errors = ?messages,
                        "publicschema.schema_validation_failed"
                    );
                    return Err(PublicSchemaIssueError::SchemaValidationFailed(messages));
                }
            }
            let mapped_subject_uri = transform
                .output
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    tracing::error!("publicschema.mapping_missing_subject_id");
                    PublicSchemaIssueError::MissingSubjectId
                })?
                .to_string();
            if mapped_subject_uri != expected_subject_uri {
                tracing::error!(
                    expected = %expected_subject_uri,
                    actual = %mapped_subject_uri,
                    "publicschema.subject_id_mismatch"
                );
                return Err(PublicSchemaIssueError::SubjectIdMismatch {
                    expected: expected_subject_uri.to_string(),
                    actual: mapped_subject_uri,
                });
            }

            Ok(Some(PublicSchemaMappedCredential {
                subject_uri: expected_subject_uri.to_string(),
                credential_subject: transform.output,
                context_url: profile.context_url.clone(),
                schema_url: profile.schema_url.clone(),
                credential_type: profile.credential_type.clone(),
            }))
        }
    }

    pub fn build_publicschema_registry(
        config: &Config,
    ) -> Result<Option<PublicSchemaVcRegistry>, Error> {
        let rt = MappingRuntime::new(RuntimeOptions::default());
        let mut profiles = BTreeMap::new();
        for dataset in &config.datasets {
            for entity in &dataset.entities {
                let Some(publicschema) = &entity.publicschema else {
                    continue;
                };
                let mapping_text =
                    std::fs::read_to_string(&publicschema.mapping_path).map_err(|err| {
                        tracing::error!(
                            code = "publicschema.config.mapping_read_failed",
                            dataset_id = %dataset.id,
                            entity = %entity.name,
                            path = %publicschema.mapping_path.display(),
                            error = %err,
                            "failed to read publicschema mapping",
                        );
                        Error::from(ConfigError::ValidationError)
                    })?;
                let compiled = rt
                    .compile_publicschema_mapping(&mapping_text, Default::default())
                    .map_err(|err| {
                        tracing::error!(
                            code = "publicschema.config.mapping_compile_failed",
                            dataset_id = %dataset.id,
                            entity = %entity.name,
                            path = %publicschema.mapping_path.display(),
                            error = %err,
                            "failed to compile publicschema mapping",
                        );
                        Error::from(ConfigError::ValidationError)
                    })?;
                let target = publicschema.target.trim();
                let schema_url = publicschema.schema_url.clone().unwrap_or_else(|| {
                    format!("{DEFAULT_PUBLICSCHEMA_SCHEMA_BASE}/{target}.schema.json")
                });
                let credential_type = publicschema
                    .credential_type
                    .clone()
                    .unwrap_or_else(|| target.to_string());
                let compiled_schema = match &publicschema.schema_validation_path {
                    Some(path) => {
                        let raw_schema = std::fs::read_to_string(path).map_err(|err| {
                            tracing::error!(
                                code = "publicschema.config.schema_read_failed",
                                dataset_id = %dataset.id,
                                entity = %entity.name,
                                path = %path.display(),
                                error = %err,
                                "failed to read publicschema validation schema",
                            );
                            Error::from(ConfigError::ValidationError)
                        })?;
                        let schema_json: Value =
                            serde_json::from_str(&raw_schema).map_err(|err| {
                                tracing::error!(
                                    code = "publicschema.config.schema_parse_failed",
                                    dataset_id = %dataset.id,
                                    entity = %entity.name,
                                    path = %path.display(),
                                    error = %err,
                                    "failed to parse publicschema validation schema",
                                );
                                Error::from(ConfigError::ValidationError)
                            })?;
                        Some(Arc::new(
                            jsonschema::JSONSchema::compile(&schema_json).map_err(|err| {
                                tracing::error!(
                                    code = "publicschema.config.schema_compile_failed",
                                    dataset_id = %dataset.id,
                                    entity = %entity.name,
                                    path = %path.display(),
                                    error = %err,
                                    "failed to compile publicschema validation schema",
                                );
                                Error::from(ConfigError::ValidationError)
                            })?,
                        ))
                    }
                    None => None,
                };
                profiles.insert(
                    (dataset.id.to_string(), entity.name.clone()),
                    Arc::new(PublicSchemaVcProfile {
                        compiled: Arc::new(compiled),
                        compiled_schema,
                        context_url: publicschema
                            .context_url
                            .clone()
                            .unwrap_or_else(|| DEFAULT_PUBLICSCHEMA_CONTEXT_URL.to_string()),
                        schema_url,
                        credential_type,
                    }),
                );
            }
        }
        if profiles.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PublicSchemaVcRegistry {
                profiles: Arc::new(profiles),
            }))
        }
    }

    // Mirrors the value-free diagnostics in `crate::spdci`. Entity rows are
    // PII, so validation errors must report only the failing instance/schema
    // paths and the error kind, never the offending instance value embedded in
    // `ValidationError`'s `Display`. Kept local because `crate::spdci` is gated
    // behind the `spdci-api-standards` feature and these helpers are private to
    // that module.
    pub(super) fn schema_validation_diagnostics<'a>(
        errors: impl IntoIterator<Item = ValidationError<'a>>,
    ) -> Vec<String> {
        errors
            .into_iter()
            .map(|error| {
                format!(
                    "instance_path={} schema_path={} kind={}",
                    error.instance_path,
                    error.schema_path,
                    schema_validation_kind(&error.kind)
                )
            })
            .collect()
    }

    fn schema_validation_kind(kind: &ValidationErrorKind) -> &'static str {
        match kind {
            ValidationErrorKind::AdditionalItems { .. } => "additional_items",
            ValidationErrorKind::AdditionalProperties { .. } => "additional_properties",
            ValidationErrorKind::AnyOf => "any_of",
            ValidationErrorKind::BacktrackLimitExceeded { .. } => "backtrack_limit_exceeded",
            ValidationErrorKind::Constant { .. } => "constant",
            ValidationErrorKind::Contains => "contains",
            ValidationErrorKind::ContentEncoding { .. } => "content_encoding",
            ValidationErrorKind::ContentMediaType { .. } => "content_media_type",
            ValidationErrorKind::Custom { .. } => "custom",
            ValidationErrorKind::Enum { .. } => "enum",
            ValidationErrorKind::ExclusiveMaximum { .. } => "exclusive_maximum",
            ValidationErrorKind::ExclusiveMinimum { .. } => "exclusive_minimum",
            ValidationErrorKind::FalseSchema => "false_schema",
            ValidationErrorKind::FileNotFound { .. } => "file_not_found",
            ValidationErrorKind::Format { .. } => "format",
            ValidationErrorKind::FromUtf8 { .. } => "from_utf8",
            ValidationErrorKind::Utf8 { .. } => "utf8",
            ValidationErrorKind::JSONParse { .. } => "json_parse",
            ValidationErrorKind::InvalidReference { .. } => "invalid_reference",
            ValidationErrorKind::InvalidURL { .. } => "invalid_url",
            ValidationErrorKind::MaxItems { .. } => "max_items",
            ValidationErrorKind::Maximum { .. } => "maximum",
            ValidationErrorKind::MaxLength { .. } => "max_length",
            ValidationErrorKind::MaxProperties { .. } => "max_properties",
            ValidationErrorKind::MinItems { .. } => "min_items",
            ValidationErrorKind::Minimum { .. } => "minimum",
            ValidationErrorKind::MinLength { .. } => "min_length",
            ValidationErrorKind::MinProperties { .. } => "min_properties",
            ValidationErrorKind::MultipleOf { .. } => "multiple_of",
            ValidationErrorKind::Not { .. } => "not",
            ValidationErrorKind::OneOfMultipleValid => "one_of_multiple_valid",
            ValidationErrorKind::OneOfNotValid => "one_of_not_valid",
            ValidationErrorKind::Pattern { .. } => "pattern",
            ValidationErrorKind::PropertyNames { .. } => "property_names",
            ValidationErrorKind::Required { .. } => "required",
            ValidationErrorKind::Schema => "schema",
            ValidationErrorKind::Type { .. } => "type",
            ValidationErrorKind::UnevaluatedProperties { .. } => "unevaluated_properties",
            ValidationErrorKind::UniqueItems => "unique_items",
            ValidationErrorKind::UnknownReferenceScheme { .. } => "unknown_reference_scheme",
            ValidationErrorKind::Resolver { .. } => "resolver",
        }
    }

    // `MappingError::message` is free-form and can echo row values, so log only
    // the failing path and the issue kind. Mirrors `crate::spdci`'s
    // `mapping_issue_diagnostics`.
    pub(super) fn mapping_issue_diagnostics(issues: &[MappingError], kind: &str) -> Vec<String> {
        issues
            .iter()
            .map(|issue| format!("path={} kind={kind}", issue.path.as_deref().unwrap_or("$")))
            .collect()
    }
}

#[cfg(not(feature = "publicschema-cel"))]
mod disabled {
    use super::*;

    #[derive(Debug, Clone, Default)]
    pub struct PublicSchemaVcRegistry;

    impl PublicSchemaVcRegistry {
        pub fn is_empty(&self) -> bool {
            true
        }

        pub fn mapped_entity_credential(
            &self,
            _dataset: &str,
            _entity: &str,
            _subject_uri: &str,
            _record: Value,
        ) -> Result<Option<PublicSchemaMappedCredential>, PublicSchemaIssueError> {
            Ok(None)
        }
    }

    pub fn build_publicschema_registry(
        config: &Config,
    ) -> Result<Option<PublicSchemaVcRegistry>, Error> {
        if config
            .datasets
            .iter()
            .flat_map(|dataset| &dataset.entities)
            .any(|entity| entity.publicschema.is_some())
        {
            return Err(Error::from(ConfigError::PublicSchemaFeatureDisabled));
        }
        Ok(None)
    }
}

#[cfg(not(feature = "publicschema-cel"))]
pub use disabled::{build_publicschema_registry, PublicSchemaVcRegistry};
#[cfg(feature = "publicschema-cel")]
pub use enabled::{build_publicschema_registry, PublicSchemaVcRegistry};

#[cfg(all(test, feature = "publicschema-cel"))]
mod tests {
    use super::enabled::{mapping_issue_diagnostics, schema_validation_diagnostics};
    use crosswalk_core::{ErrorCode, MappingError};
    use serde_json::json;

    #[test]
    fn schema_validation_diagnostics_omit_instance_values() {
        let schema = json!({
            "type": "object",
            "properties": {
                "member_identifier": { "type": "number" }
            }
        });
        let record = json!({
            "member_identifier": "SECRET-ROW-VALUE-451123"
        });
        let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
        let errors = compiled
            .validate(&record)
            .expect_err("record should fail schema validation");
        let formatted = schema_validation_diagnostics(errors).join("\n");

        assert!(formatted.contains("instance_path=/member_identifier"));
        assert!(formatted.contains("schema_path=/properties/member_identifier/type"));
        assert!(formatted.contains("kind=type"));
        assert!(!formatted.contains("SECRET-ROW-VALUE-451123"));
    }

    #[test]
    fn mapping_issue_diagnostics_omit_instance_values() {
        let issues = vec![MappingError::error(
            ErrorCode::ValidationError,
            "failed while reading SECRET-ROW-VALUE-451123",
            Some("records.disabled_person.fields.member_identifier".to_string()),
            None,
        )];
        let formatted = mapping_issue_diagnostics(&issues, "error").join("\n");

        assert!(formatted.contains("path=records.disabled_person.fields.member_identifier"));
        assert!(formatted.contains("kind=error"));
        assert!(!formatted.contains("SECRET-ROW-VALUE-451123"));
    }
}
