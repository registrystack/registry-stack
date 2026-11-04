// SPDX-License-Identifier: Apache-2.0

//! Project-owned transformation of one already-validated public write value
//! into the source route's private input object.

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use registry_adapter_core::{BindingTransform, ProjectScript};
    use registry_platform_config::sha256_uri;
    use registry_platform_yaml::{Digest, LocalId};
    use serde_json::json;

    use crate::artifacts::ProjectArtifactBytes;
    use crate::scripts::CodeMaps;

    use super::*;

    fn compiled(source: &[u8]) -> CompiledProjectInputTransform {
        let script = ProjectScript {
            id: LocalId::new("write-input").expect("local id"),
            file: "transforms/write-input.rhai".to_owned(),
            digest: Digest::new(sha256_uri(source)).expect("digest"),
        };
        let transform = BindingTransform {
            script: script.id.clone(),
            entrypoint: "prepare".to_owned(),
        };
        let artifacts = ProjectArtifactBytes::new([(script.file.clone(), source.to_vec())]);
        CompiledProjectInputTransform::compile_parts(
            "create-person",
            &script,
            &transform,
            &artifacts,
        )
        .expect("input transform compiles")
    }

    #[test]
    fn transform_receives_only_the_domain_value_and_returns_an_object() {
        let transform = compiled(br#"fn prepare(source) { #{person: #{name: source.name}} }"#);

        let output = transform
            .apply(
                &CodeMaps::default(),
                &json!({"name": "Ada"}),
                Instant::now() + Duration::from_secs(1),
            )
            .expect("object output");

        assert_eq!(output, json!({"person": {"name": "Ada"}}));
    }

    #[test]
    fn transform_refuses_non_object_source_input_without_an_internal_schema() {
        let transform = compiled(br#"fn prepare(source) { [source] }"#);

        assert_eq!(
            transform.apply(
                &CodeMaps::default(),
                &json!({"name": "Ada"}),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ProjectInputTransformError::OutputNotObject)
        );
    }

    #[test]
    fn transform_is_bound_by_the_callers_absolute_deadline() {
        let transform = compiled(br#"fn prepare(source) { source }"#);

        assert_eq!(
            transform.apply(&CodeMaps::default(), &json!({}), Instant::now()),
            Err(ProjectInputTransformError::Budget)
        );
    }
}

use std::path::Path;
use std::time::Instant;

use registry_adapter_core::{AdapterProject, BindingTransform, ProjectScript};
use registry_platform_config::sha256_uri;
use serde_json::Value;
use thiserror::Error;

use crate::artifacts::{ArtifactReadError, ArtifactSource, ProjectArtifactBytes};
use crate::scripts::{CodeMaps, ScriptFailure, ScriptLoadError, ScriptSet};

/// A value-free refusal at the public-write to source-input boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProjectInputTransformError {
    #[error("the binding has no project input transformation")]
    TransformMissing,
    #[error("the project input transformation names no inventoried script")]
    ScriptMissing,
    #[error("the project input transformation script is unavailable, changed, or invalid")]
    ScriptInvalid,
    #[error("the project input transformation exhausted its shared deadline or execution budget")]
    Budget,
    #[error("the project input transformation failed")]
    Failed,
    #[error("the project input transformation did not return a JSON object")]
    OutputNotObject,
}

/// One digest-pinned project transformation from a validated public domain
/// value to the source route's private JSON object.
pub struct CompiledProjectInputTransform {
    transform: BindingTransform,
    script: ProjectScript,
    scripts: ScriptSet,
    closure_digest: String,
}

impl std::fmt::Debug for CompiledProjectInputTransform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledProjectInputTransform")
            .field("closure_digest", &self.closure_digest)
            .finish_non_exhaustive()
    }
}

impl CompiledProjectInputTransform {
    /// Compile the binding's existing project transformation without treating
    /// a public schema as the schema of source-private fields.
    pub fn compile(
        project: &AdapterProject,
        binding: &str,
        artifacts: &ProjectArtifactBytes,
    ) -> Result<Self, ProjectInputTransformError> {
        compile_from(project, binding, artifacts)
    }

    /// File-backed convenience used by the maintained facade host.
    pub fn compile_from_directory(
        project: &AdapterProject,
        binding: &str,
        project_directory: &Path,
    ) -> Result<Self, ProjectInputTransformError> {
        compile_from(project, binding, project_directory)
    }

    /// Compile from already-selected project parts for bounded embedding
    /// hosts and deterministic tests.
    pub fn compile_parts(
        identity: &str,
        script: &ProjectScript,
        transform: &BindingTransform,
        artifacts: &ProjectArtifactBytes,
    ) -> Result<Self, ProjectInputTransformError> {
        compile_parts_from(identity, script, transform, artifacts)
    }

    #[must_use]
    pub fn closure_digest(&self) -> &str {
        &self.closure_digest
    }

    /// Run the pinned function over only the already-validated domain value.
    /// The output has no project-authored schema because its private members
    /// belong to the source route; it must still be one bounded JSON object.
    pub fn apply(
        &self,
        code_maps: &CodeMaps,
        domain_value: &Value,
        deadline: Instant,
    ) -> Result<Value, ProjectInputTransformError> {
        if Instant::now() >= deadline {
            return Err(ProjectInputTransformError::Budget);
        }
        let output = self
            .scripts
            .call_project_transform(
                code_maps,
                &self.script,
                &self.transform,
                domain_value,
                deadline,
            )
            .map_err(script_failure)?;
        if Instant::now() > deadline {
            return Err(ProjectInputTransformError::Budget);
        }
        if !output.is_object() {
            return Err(ProjectInputTransformError::OutputNotObject);
        }
        if serde_json::to_vec(&output).map_or(true, |bytes| {
            bytes.len() > crate::exchange::MAXIMUM_EXCHANGE_BYTES
        }) {
            return Err(ProjectInputTransformError::Budget);
        }
        Ok(output)
    }
}

fn compile_from<S: ArtifactSource + ?Sized>(
    project: &AdapterProject,
    binding: &str,
    artifacts: &S,
) -> Result<CompiledProjectInputTransform, ProjectInputTransformError> {
    let transform = project
        .binding_transforms
        .iter()
        .find(|(id, _)| id.as_str() == binding)
        .map(|(_, transform)| transform)
        .ok_or(ProjectInputTransformError::TransformMissing)?;
    let script = project
        .artifacts
        .scripts
        .get(transform.script.as_str())
        .ok_or(ProjectInputTransformError::ScriptMissing)?;
    compile_parts_from(binding, script, transform, artifacts)
}

fn compile_parts_from<S: ArtifactSource + ?Sized>(
    identity: &str,
    script: &ProjectScript,
    transform: &BindingTransform,
    artifacts: &S,
) -> Result<CompiledProjectInputTransform, ProjectInputTransformError> {
    let mut scripts = ScriptSet::default();
    scripts
        .add_project_transform_from(artifacts, script, transform)
        .map_err(script_load)?;
    let script_bytes = artifacts
        .read_bounded(
            &script.file,
            crate::scripts::SCRIPT_PROFILE.maximum_source_bytes,
        )
        .map_err(|error| match error {
            ArtifactReadError::TooLarge => ProjectInputTransformError::Budget,
            ArtifactReadError::Unavailable => ProjectInputTransformError::ScriptInvalid,
        })?;
    let closure_digest = closure_digest(identity, transform, script, &script_bytes);
    Ok(CompiledProjectInputTransform {
        transform: transform.clone(),
        script: script.clone(),
        scripts,
        closure_digest,
    })
}

fn closure_digest(
    binding: &str,
    transform: &BindingTransform,
    script: &ProjectScript,
    script_bytes: &[u8],
) -> String {
    let members: [&[u8]; 4] = [
        binding.as_bytes(),
        transform.entrypoint.as_bytes(),
        script.id.as_str().as_bytes(),
        script_bytes,
    ];
    let mut framed = Vec::new();
    for member in members {
        framed.extend_from_slice(&(member.len() as u64).to_be_bytes());
        framed.extend_from_slice(member);
    }
    sha256_uri(&framed)
}

fn script_load(error: ScriptLoadError) -> ProjectInputTransformError {
    match error {
        ScriptLoadError::TooLarge(_) => ProjectInputTransformError::Budget,
        _ => ProjectInputTransformError::ScriptInvalid,
    }
}

fn script_failure(error: ScriptFailure) -> ProjectInputTransformError {
    match error {
        ScriptFailure::Budget => ProjectInputTransformError::Budget,
        ScriptFailure::Failed | ScriptFailure::Unmapped(_) => ProjectInputTransformError::Failed,
    }
}
