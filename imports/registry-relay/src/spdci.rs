// SPDX-License-Identifier: Apache-2.0
//! SP DCI response mapping runtime.
//!
//! The HTTP adapter owns request parsing and route authorization. This module
//! owns response shaping from Registry Relay entity rows into configured SP DCI
//! record shapes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "standards-cel-mapping")]
use serde_json::json;
use serde_json::{Map, Value};

use crate::config::{Config, SpdciRegistryConfig};
use crate::error::{ConfigError, Error};

#[cfg(feature = "standards-cel-mapping")]
use crosswalk_core::{CompiledMapping, EvaluationInput, MappingRuntime, RuntimeOptions};

#[derive(Debug, Clone, Default)]
pub struct SpdciResponseMapper {
    profiles: Arc<BTreeMap<String, Arc<SpdciResponseProfile>>>,
}

struct SpdciResponseProfile {
    registry: String,
    dataset: String,
    entity: String,
    #[cfg(feature = "standards-cel-mapping")]
    registry_type: String,
    #[cfg(feature = "standards-cel-mapping")]
    record_type: String,
    response_fields: BTreeMap<String, String>,
    #[cfg(feature = "standards-cel-mapping")]
    mapping: Option<Arc<CompiledMapping>>,
    #[cfg(feature = "standards-cel-mapping")]
    runtime: Option<Arc<MappingRuntime>>,
    #[cfg(feature = "standards-cel-mapping")]
    mapping_path: Option<PathBuf>,
    schema: Option<Arc<jsonschema::JSONSchema>>,
    schema_path: Option<PathBuf>,
}

impl std::fmt::Debug for SpdciResponseProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SpdciResponseProfile");
        s.field("registry", &self.registry)
            .field("dataset", &self.dataset)
            .field("entity", &self.entity);
        #[cfg(feature = "standards-cel-mapping")]
        s.field("registry_type", &self.registry_type)
            .field("record_type", &self.record_type);
        s.field("response_fields", &self.response_fields);
        #[cfg(feature = "standards-cel-mapping")]
        s.field("mapping", &self.mapping.as_ref().map(|_| "<compiled>"))
            .field("runtime", &self.runtime.as_ref().map(|_| "<runtime>"))
            .field("mapping_path", &self.mapping_path);
        s.field("schema", &self.schema.as_ref().map(|_| "<schema>"))
            .field("schema_path", &self.schema_path)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpdciResponseMappingError {
    #[error("SP DCI response mapping failed")]
    MappingFailed,
    #[error("SP DCI response schema validation failed")]
    SchemaValidationFailed,
}

pub fn build_spdci_response_mapper(config: &Config) -> Result<Option<SpdciResponseMapper>, Error> {
    let Some(spdci) = &config.standards.spdci else {
        return Ok(None);
    };

    let mut profiles = BTreeMap::new();
    for (name, registry) in &spdci.registries {
        if registry.response_fields.is_empty()
            && registry.response_mapping_path.is_none()
            && registry.response_schema_path.is_none()
        {
            continue;
        }
        profiles.insert(
            name.clone(),
            Arc::new(SpdciResponseProfile::build(name, registry)?),
        );
    }

    if profiles.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SpdciResponseMapper {
            profiles: Arc::new(profiles),
        }))
    }
}

impl SpdciResponseMapper {
    pub fn project_record(
        &self,
        registry: &str,
        config: &SpdciRegistryConfig,
        row: Value,
    ) -> Result<Value, SpdciResponseMappingError> {
        let Some(profile) = self.profiles.get(registry) else {
            return project_without_profile(config, row);
        };
        profile.project(row)
    }
}

impl SpdciResponseProfile {
    fn build(registry: &str, config: &SpdciRegistryConfig) -> Result<Self, Error> {
        let mapping_path = config.response_mapping_path.clone();

        #[cfg(not(feature = "standards-cel-mapping"))]
        if mapping_path.is_some() {
            return Err(ConfigError::SpdciMappingFeatureDisabled.into());
        }

        #[cfg(feature = "standards-cel-mapping")]
        let (mapping, runtime) = match &mapping_path {
            Some(path) => {
                let mapping_text = read_file(path, registry, config, "mapping")?;
                let rt = Arc::new(MappingRuntime::new(RuntimeOptions::default()));
                let compiled = rt.compile_mapping(&mapping_text).map_err(|err| {
                    tracing::error!(
                        code = "spdci.config.mapping_compile_failed",
                        registry,
                        dataset_id = %config.dataset,
                        entity = %config.entity,
                        path = %path.display(),
                        error = %err,
                        "failed to compile SP DCI response mapping"
                    );
                    Error::from(ConfigError::ValidationError)
                })?;
                (Some(Arc::new(compiled)), Some(rt))
            }
            None => (None, None),
        };

        let (schema, schema_path) = match &config.response_schema_path {
            Some(path) => {
                let schema_text = read_file(path, registry, config, "schema")?;
                let schema_json: Value = serde_json::from_str(&schema_text).map_err(|err| {
                    tracing::error!(
                        code = "spdci.config.schema_parse_failed",
                        registry,
                        dataset_id = %config.dataset,
                        entity = %config.entity,
                        path = %path.display(),
                        error = %err,
                        "failed to parse SP DCI response schema"
                    );
                    Error::from(ConfigError::ValidationError)
                })?;
                let schema = jsonschema::JSONSchema::compile(&schema_json).map_err(|err| {
                    tracing::error!(
                        code = "spdci.config.schema_compile_failed",
                        registry,
                        dataset_id = %config.dataset,
                        entity = %config.entity,
                        path = %path.display(),
                        error = %err,
                        "failed to compile SP DCI response schema"
                    );
                    Error::from(ConfigError::ValidationError)
                })?;
                (Some(Arc::new(schema)), Some(path.clone()))
            }
            None => (None, None),
        };

        Ok(Self {
            registry: registry.to_string(),
            dataset: config.dataset.to_string(),
            entity: config.entity.clone(),
            #[cfg(feature = "standards-cel-mapping")]
            registry_type: config.registry_type.clone(),
            #[cfg(feature = "standards-cel-mapping")]
            record_type: config.record_type.clone(),
            response_fields: config.response_fields.clone(),
            #[cfg(feature = "standards-cel-mapping")]
            mapping,
            #[cfg(feature = "standards-cel-mapping")]
            runtime,
            #[cfg(feature = "standards-cel-mapping")]
            mapping_path,
            schema,
            schema_path,
        })
    }

    fn project(&self, row: Value) -> Result<Value, SpdciResponseMappingError> {
        #[cfg(feature = "standards-cel-mapping")]
        let record = match (&self.mapping, &self.runtime) {
            (Some(mapping), Some(runtime)) => self.project_cel(runtime, mapping, row)?,
            _ => project_response_fields_or_raw(&self.response_fields, row)?,
        };

        #[cfg(not(feature = "standards-cel-mapping"))]
        let record = project_response_fields_or_raw(&self.response_fields, row)?;

        self.validate(&record)?;
        Ok(record)
    }

    #[cfg(feature = "standards-cel-mapping")]
    fn project_cel(
        &self,
        runtime: &MappingRuntime,
        mapping: &CompiledMapping,
        row: Value,
    ) -> Result<Value, SpdciResponseMappingError> {
        let out = runtime.evaluate(
            mapping,
            EvaluationInput {
                source: row,
                context: json!({
                    "dataset": self.dataset,
                    "entity": self.entity,
                    "registry": self.registry,
                    "registry_type": self.registry_type,
                    "record_type": self.record_type,
                }),
            },
        );
        if !out.errors.is_empty() {
            tracing::error!(
                registry = %self.registry,
                dataset_id = %self.dataset,
                entity = %self.entity,
                mapping_path = ?self.mapping_path,
                errors = ?out.errors,
                "SP DCI response mapping failed"
            );
            return Err(SpdciResponseMappingError::MappingFailed);
        }
        if !out.warnings.is_empty() {
            tracing::warn!(
                registry = %self.registry,
                dataset_id = %self.dataset,
                entity = %self.entity,
                mapping_path = ?self.mapping_path,
                warnings = ?out.warnings,
                "SP DCI response mapping produced warnings"
            );
        }
        one_record(out.records).ok_or_else(|| {
            tracing::error!(
                registry = %self.registry,
                dataset_id = %self.dataset,
                entity = %self.entity,
                mapping_path = ?self.mapping_path,
                "SP DCI response mapping must produce exactly one record per row"
            );
            SpdciResponseMappingError::MappingFailed
        })
    }

    fn validate(&self, record: &Value) -> Result<(), SpdciResponseMappingError> {
        let Some(schema) = &self.schema else {
            return Ok(());
        };
        if let Err(errors) = schema.validate(record) {
            let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
            tracing::error!(
                registry = %self.registry,
                dataset_id = %self.dataset,
                entity = %self.entity,
                schema_path = ?self.schema_path,
                errors = ?messages,
                "SP DCI response schema validation failed"
            );
            return Err(SpdciResponseMappingError::SchemaValidationFailed);
        }
        Ok(())
    }
}

fn read_file(
    path: &Path,
    registry: &str,
    config: &SpdciRegistryConfig,
    kind: &str,
) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|err| {
        tracing::error!(
            code = "config.validation_error",
            registry,
            dataset_id = %config.dataset,
            entity = %config.entity,
            path = %path.display(),
            error = %err,
            "failed to read SP DCI response {kind}"
        );
        Error::from(ConfigError::ValidationError)
    })
}

fn project_without_profile(
    config: &SpdciRegistryConfig,
    row: Value,
) -> Result<Value, SpdciResponseMappingError> {
    if config.response_mapping_path.is_some() || config.response_schema_path.is_some() {
        tracing::error!(
            dataset_id = %config.dataset,
            entity = %config.entity,
            "SP DCI response mapper was not installed for a configured mapping or schema"
        );
        return Err(SpdciResponseMappingError::MappingFailed);
    }
    project_response_fields_or_raw(&config.response_fields, row)
}

fn project_response_fields_or_raw(
    response_fields: &BTreeMap<String, String>,
    row: Value,
) -> Result<Value, SpdciResponseMappingError> {
    if response_fields.is_empty() {
        return Ok(row);
    }
    let row_object = row
        .as_object()
        .ok_or(SpdciResponseMappingError::MappingFailed)?;
    let mut output = Map::new();
    for (target, source) in response_fields {
        let value = row_object
            .get(source)
            .cloned()
            .ok_or(SpdciResponseMappingError::MappingFailed)?;
        insert_dotted(&mut output, target, value)?;
    }
    Ok(Value::Object(output))
}

fn insert_dotted(
    output: &mut Map<String, Value>,
    target: &str,
    value: Value,
) -> Result<(), SpdciResponseMappingError> {
    let parts: Vec<&str> = target.split('.').collect();
    let mut current = output;
    for part in &parts[..parts.len().saturating_sub(1)] {
        let entry = current
            .entry((*part).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let Value::Object(next) = entry else {
            return Err(SpdciResponseMappingError::MappingFailed);
        };
        current = next;
    }
    let Some(last) = parts.last() else {
        return Err(SpdciResponseMappingError::MappingFailed);
    };
    if current.insert((*last).to_string(), value).is_some() {
        return Err(SpdciResponseMappingError::MappingFailed);
    }
    Ok(())
}

#[cfg(feature = "standards-cel-mapping")]
fn one_record(records: BTreeMap<String, Vec<Value>>) -> Option<Value> {
    let mut values = records.into_values().flatten();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}
