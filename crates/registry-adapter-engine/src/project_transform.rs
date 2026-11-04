// SPDX-License-Identifier: Apache-2.0

//! Project-owned, schema-bound transformation of one acquired source value.
//! The primitive is listener-free and product-neutral: facade and Evidence
//! hosts can reuse it without inheriting either product's authorization or
//! release policy.

use std::path::Path;
use std::time::Instant;

use registry_adapter_core::{AdapterProject, BindingTransform, ProjectSchema, ProjectScript};
use registry_platform_config::sha256_uri;
use serde_json::Value;
use thiserror::Error;

use crate::artifacts::{ArtifactReadError, ArtifactSource, ProjectArtifactBytes};
use crate::public_schema::{check_public_schema, CheckedPublicSchema};
use crate::scripts::{CodeMaps, ScriptFailure, ScriptLoadError, ScriptSet};

const MAXIMUM_SCHEMA_BYTES: usize = 256 * 1024;

/// A value-free refusal at the project transformation boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProjectTransformError {
    #[error("the binding has no project transformation")]
    TransformMissing,
    #[error("the project transformation names no inventoried script")]
    ScriptMissing,
    #[error("the selected collection names no inventoried data schema")]
    SchemaMissing,
    #[error("the project transformation script is unavailable, changed, or invalid")]
    ScriptInvalid,
    #[error("the project data schema is unavailable, changed, or invalid")]
    SchemaInvalid,
    #[error("the project transformation exhausted its shared deadline or execution budget")]
    Budget,
    #[error("the project transformation failed")]
    Failed,
    #[error("the project transformation output does not satisfy the selected data schema")]
    OutputInvalid,
}

/// A preview refusal: the categorical error and, when the script failed, the
/// innermost string it threw.
#[derive(Debug)]
pub struct PreviewRefusal {
    pub error: ProjectTransformError,
    /// Script-authored text that may carry source values. An authoring tool
    /// shows it only after matching it against a shape it knows is value-free.
    pub thrown: Option<String>,
}

/// One compiled binding transformation and its exact selected public schema.
pub struct CompiledProjectTransform {
    transform: BindingTransform,
    script: ProjectScript,
    scripts: ScriptSet,
    schema: CheckedPublicSchema,
    closure_digest: String,
}

impl std::fmt::Debug for CompiledProjectTransform {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledProjectTransform")
            .field("schema", &self.schema.identity())
            .field("closure_digest", &self.closure_digest)
            .finish_non_exhaustive()
    }
}

impl CompiledProjectTransform {
    /// Compile one binding against the single data schema its collection/view
    /// selects. All bytes come from the supplied project closure.
    pub fn compile(
        project: &AdapterProject,
        binding: &str,
        data_schema: &str,
        artifacts: &ProjectArtifactBytes,
    ) -> Result<Self, ProjectTransformError> {
        compile_from(project, binding, data_schema, artifacts)
    }

    /// File-based convenience for the maintained Adapter loader. Paths in the
    /// project inventory resolve against the project document's directory.
    pub fn compile_from_directory(
        project: &AdapterProject,
        binding: &str,
        data_schema: &str,
        project_directory: &Path,
    ) -> Result<Self, ProjectTransformError> {
        compile_from(project, binding, data_schema, project_directory)
    }

    /// Compile from already-resolved project-owned parts. Embedding hosts such
    /// as Evidence use this form when their governed package stores the same
    /// script/schema pins without constructing an Adapter facade project.
    pub fn compile_parts(
        script: &ProjectScript,
        transform: &BindingTransform,
        schema: &ProjectSchema,
        artifacts: &ProjectArtifactBytes,
    ) -> Result<Self, ProjectTransformError> {
        compile_parts_from("projected-source", script, transform, schema, artifacts)
    }

    #[must_use]
    pub fn schema(&self) -> &CheckedPublicSchema {
        &self.schema
    }

    /// Digest over the exact selected script and schema bytes plus the
    /// binding-local entrypoint. Cursor and deployment identities include
    /// this value so a projection or public-schema change invalidates old
    /// continuation context.
    #[must_use]
    pub fn closure_digest(&self) -> &str {
        &self.closure_digest
    }

    /// Transform exactly one source item value under the caller's absolute
    /// deadline, then validate it before any host can wrap or disclose it.
    pub fn apply(
        &self,
        code_maps: &CodeMaps,
        source: &Value,
        deadline: Instant,
    ) -> Result<Value, ProjectTransformError> {
        self.apply_for_preview(code_maps, source, deadline)
            .map_err(|refusal| refusal.error)
    }

    /// `apply` for authoring preview: a script failure also returns the
    /// innermost string the script threw. Runtime hosts use `apply`, whose
    /// refusal stays categorical and value-free.
    pub fn apply_for_preview(
        &self,
        code_maps: &CodeMaps,
        source: &Value,
        deadline: Instant,
    ) -> Result<Value, PreviewRefusal> {
        let refuse = |error| PreviewRefusal {
            error,
            thrown: None,
        };
        if Instant::now() >= deadline {
            return Err(refuse(ProjectTransformError::Budget));
        }
        let output = self
            .scripts
            .call_project_transform(code_maps, &self.script, &self.transform, source, deadline)
            .map_err(|(failure, thrown)| {
                let error = script_failure(failure);
                PreviewRefusal {
                    error,
                    thrown: thrown.filter(|_| error == ProjectTransformError::Failed),
                }
            })?;
        if Instant::now() > deadline {
            return Err(refuse(ProjectTransformError::Budget));
        }
        if serde_json::to_vec(&output).map_or(true, |bytes| {
            bytes.len() > crate::exchange::MAXIMUM_EXCHANGE_BYTES
        }) {
            return Err(refuse(ProjectTransformError::Budget));
        }
        let valid = self.schema.validates(&output);
        if Instant::now() > deadline {
            return Err(refuse(ProjectTransformError::Budget));
        }
        if !valid {
            return Err(refuse(ProjectTransformError::OutputInvalid));
        }
        Ok(output)
    }
}

/// Load and compile one digest-pinned project schema from its project
/// directory. Consultation uses this for selector and Search input schemas,
/// which share the same offline, no-remote-resolution boundary as outputs.
pub fn compile_project_schema_from_directory(
    schema: &ProjectSchema,
    project_directory: &Path,
) -> Result<CheckedPublicSchema, ProjectTransformError> {
    let bytes = read_checked_schema(project_directory, schema)?;
    compile_schema_bytes(&bytes)
}

fn compile_from<S: ArtifactSource + ?Sized>(
    project: &AdapterProject,
    binding: &str,
    data_schema: &str,
    artifacts: &S,
) -> Result<CompiledProjectTransform, ProjectTransformError> {
    let transform = project
        .binding_transforms
        .iter()
        .find(|(id, _)| id.as_str() == binding)
        .map(|(_, transform)| transform)
        .ok_or(ProjectTransformError::TransformMissing)?;
    let script = project
        .artifacts
        .scripts
        .get(transform.script.as_str())
        .ok_or(ProjectTransformError::ScriptMissing)?;
    let schema = project
        .artifacts
        .schemas
        .get(data_schema)
        .ok_or(ProjectTransformError::SchemaMissing)?;
    compile_parts_from(binding, script, transform, schema, artifacts)
}

fn compile_parts_from<S: ArtifactSource + ?Sized>(
    identity: &str,
    script: &ProjectScript,
    transform: &BindingTransform,
    schema: &ProjectSchema,
    artifacts: &S,
) -> Result<CompiledProjectTransform, ProjectTransformError> {
    let schema_bytes = read_checked_schema(artifacts, schema)?;
    let schema = compile_schema_bytes(&schema_bytes)?;

    let mut scripts = ScriptSet::default();
    scripts
        .add_project_transform_from(artifacts, script, transform)
        .map_err(script_load)?;
    let script_bytes = artifacts
        .read_bounded(
            &script.file,
            crate::scripts::SCRIPT_PROFILE.maximum_source_bytes,
        )
        .map_err(|_| ProjectTransformError::ScriptInvalid)?;
    let closure_digest = closure_digest(
        identity,
        transform,
        script,
        &script_bytes,
        schema.identity(),
        &schema_bytes,
    );
    Ok(CompiledProjectTransform {
        transform: transform.clone(),
        script: script.clone(),
        scripts,
        schema,
        closure_digest,
    })
}

fn compile_schema_bytes(bytes: &[u8]) -> Result<CheckedPublicSchema, ProjectTransformError> {
    let schema_value =
        serde_json::from_slice(bytes).map_err(|_| ProjectTransformError::SchemaInvalid)?;
    check_public_schema(schema_value).map_err(|_| ProjectTransformError::SchemaInvalid)
}

fn read_checked_schema<S: ArtifactSource + ?Sized>(
    artifacts: &S,
    schema: &ProjectSchema,
) -> Result<Vec<u8>, ProjectTransformError> {
    let bytes = match artifacts.read_bounded(&schema.file, MAXIMUM_SCHEMA_BYTES) {
        Ok(bytes) => bytes,
        Err(ArtifactReadError::Unavailable | ArtifactReadError::TooLarge) => {
            return Err(ProjectTransformError::SchemaInvalid)
        }
    };
    if sha256_uri(&bytes) != schema.digest.as_str() {
        return Err(ProjectTransformError::SchemaInvalid);
    }
    Ok(bytes)
}

fn closure_digest(
    binding: &str,
    transform: &BindingTransform,
    script: &ProjectScript,
    script_bytes: &[u8],
    schema_identity: &str,
    schema_bytes: &[u8],
) -> String {
    let members: [&[u8]; 6] = [
        binding.as_bytes(),
        transform.entrypoint.as_bytes(),
        script.id.as_str().as_bytes(),
        script_bytes,
        schema_identity.as_bytes(),
        schema_bytes,
    ];
    let mut framed = Vec::new();
    for member in members {
        framed.extend_from_slice(&(member.len() as u64).to_be_bytes());
        framed.extend_from_slice(member);
    }
    sha256_uri(&framed)
}

fn script_load(error: ScriptLoadError) -> ProjectTransformError {
    match error {
        ScriptLoadError::TooLarge(_) => ProjectTransformError::Budget,
        _ => ProjectTransformError::ScriptInvalid,
    }
}

fn script_failure(error: ScriptFailure) -> ProjectTransformError {
    match error {
        ScriptFailure::Budget => ProjectTransformError::Budget,
        ScriptFailure::Failed | ScriptFailure::Unmapped(_) => ProjectTransformError::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::{PinnedRef, ProjectArtifacts, ProjectIdentity};
    use registry_platform_yaml::{Digest, LocalId, UniqueIdList};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn digest(bytes: &[u8]) -> Digest {
        Digest::new(sha256_uri(bytes)).expect("digest")
    }

    fn project(
        scripts: Vec<(&str, &str, &[u8])>,
        schemas: Vec<(&str, &str, &[u8])>,
    ) -> (AdapterProject, ProjectArtifactBytes) {
        let artifacts = ProjectArtifactBytes::new(
            scripts
                .iter()
                .map(|(_, path, bytes)| ((*path).to_owned(), bytes.to_vec()))
                .chain(
                    schemas
                        .iter()
                        .map(|(_, path, bytes)| ((*path).to_owned(), bytes.to_vec())),
                ),
        );
        let project = AdapterProject {
            project: ProjectIdentity {
                id: LocalId::new("two-views").unwrap(),
                version: "1".to_owned(),
            },
            profile: None,
            consultation: None,
            write: None,
            pack: PinnedRef {
                id: LocalId::new("source-pack").unwrap(),
                version: "1".to_owned(),
                digest: digest(b"pack"),
            },
            record_types: UniqueIdList::default(),
            templated_routes: UniqueIdList::default(),
            bindings: UniqueIdList::default(),
            access_profiles: UniqueIdList::default(),
            artifacts: ProjectArtifacts {
                scripts: UniqueIdList::new(
                    scripts
                        .iter()
                        .map(|(id, file, bytes)| ProjectScript {
                            id: LocalId::new(*id).unwrap(),
                            file: (*file).to_owned(),
                            digest: digest(bytes),
                        })
                        .collect(),
                )
                .unwrap(),
                schemas: UniqueIdList::new(
                    schemas
                        .iter()
                        .map(|(id, file, bytes)| ProjectSchema {
                            id: LocalId::new(*id).unwrap(),
                            file: (*file).to_owned(),
                            digest: digest(bytes),
                        })
                        .collect(),
                )
                .unwrap(),
            },
            binding_transforms: BTreeMap::new(),
            parameterized_parts: BTreeMap::new(),
        };
        (project, artifacts)
    }

    #[test]
    fn one_source_value_can_feed_two_independent_schema_bound_views() {
        let public_script = b"fn project(source) { #{name: source.name} }";
        let eligibility_script = b"fn project(source) { #{eligible: source.score >= 10} }";
        let public_schema = br#"{"$id":"https://registry.example/schemas/person-public/1.0.0","type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}"#;
        let eligibility_schema = br#"{"$id":"https://registry.example/schemas/person-eligibility/1.0.0","type":"object","additionalProperties":false,"required":["eligible"],"properties":{"eligible":{"type":"boolean"}}}"#;
        let (mut project, artifacts) = project(
            vec![
                ("public-view", "transforms/public.rhai", public_script),
                (
                    "eligibility-view",
                    "transforms/eligibility.rhai",
                    eligibility_script,
                ),
            ],
            vec![
                ("public-schema", "schemas/public.json", public_schema),
                (
                    "eligibility-schema",
                    "schemas/eligibility.json",
                    eligibility_schema,
                ),
            ],
        );
        project.binding_transforms.insert(
            LocalId::new("public-binding").unwrap(),
            BindingTransform {
                script: LocalId::new("public-view").unwrap(),
                entrypoint: "project".to_owned(),
            },
        );
        project.binding_transforms.insert(
            LocalId::new("eligibility-binding").unwrap(),
            BindingTransform {
                script: LocalId::new("eligibility-view").unwrap(),
                entrypoint: "project".to_owned(),
            },
        );

        let public = CompiledProjectTransform::compile(
            &project,
            "public-binding",
            "public-schema",
            &artifacts,
        )
        .expect("public transform");
        let eligibility = CompiledProjectTransform::compile(
            &project,
            "eligibility-binding",
            "eligibility-schema",
            &artifacts,
        )
        .expect("eligibility transform");
        let source = json!({"name":"Ada", "score":12, "privateCanary":"do-not-disclose"});
        let maps = Arc::new(BTreeMap::new());
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            public.apply(&maps, &source, deadline).unwrap(),
            json!({"name":"Ada"})
        );
        assert_eq!(
            eligibility.apply(&maps, &source, deadline).unwrap(),
            json!({"eligible":true})
        );
        assert_ne!(public.closure_digest(), eligibility.closure_digest());
    }

    #[test]
    fn digest_mismatch_undeclared_output_and_expired_shared_deadline_refuse() {
        let script = b"fn project(source) { #{name: source.name, canary: source.privateCanary} }";
        let schema = br#"{"$id":"https://registry.example/schemas/person-public/1.0.0","type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}"#;
        let (mut project, mut artifacts) = project(
            vec![("public-view", "transforms/public.rhai", script)],
            vec![("public-schema", "schemas/public.json", schema)],
        );
        project.binding_transforms.insert(
            LocalId::new("public-binding").unwrap(),
            BindingTransform {
                script: LocalId::new("public-view").unwrap(),
                entrypoint: "project".to_owned(),
            },
        );
        let compiled = CompiledProjectTransform::compile(
            &project,
            "public-binding",
            "public-schema",
            &artifacts,
        )
        .expect("compile");
        let maps = Arc::new(BTreeMap::new());
        let source = json!({"name":"Ada", "privateCanary":"secret"});
        assert_eq!(
            compiled
                .apply(&maps, &source, Instant::now() + Duration::from_secs(1))
                .unwrap_err(),
            ProjectTransformError::OutputInvalid
        );
        assert_eq!(
            compiled.apply(&maps, &source, Instant::now()).unwrap_err(),
            ProjectTransformError::Budget
        );

        artifacts.insert("schemas/public.json", b"{}".to_vec());
        assert_eq!(
            CompiledProjectTransform::compile(
                &project,
                "public-binding",
                "public-schema",
                &artifacts,
            )
            .unwrap_err(),
            ProjectTransformError::SchemaInvalid
        );
    }

    #[test]
    fn changed_schema_bytes_change_the_closure_digest_after_repinning() {
        let script = b"fn project(source) { #{name: source.name} }";
        let first = br#"{"$id":"https://registry.example/schemas/person-public/1.0.0","type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}}}"#;
        let second = br#"{"$id":"https://registry.example/schemas/person-public/1.0.1","type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"}}}"#;
        let (mut project, artifacts) = project(
            vec![("public-view", "transforms/public.rhai", script)],
            vec![("public-schema", "schemas/public.json", first)],
        );
        project.binding_transforms.insert(
            LocalId::new("public-binding").unwrap(),
            BindingTransform {
                script: LocalId::new("public-view").unwrap(),
                entrypoint: "project".to_owned(),
            },
        );
        let first_compiled = CompiledProjectTransform::compile(
            &project,
            "public-binding",
            "public-schema",
            &artifacts,
        )
        .unwrap();
        let first_digest = first_compiled.closure_digest().to_owned();

        let changed = ProjectArtifactBytes::new([
            ("transforms/public.rhai".to_owned(), script.to_vec()),
            ("schemas/public.json".to_owned(), second.to_vec()),
        ]);
        let mut schemas = project
            .artifacts
            .schemas
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        schemas
            .iter_mut()
            .find(|schema| schema.id.as_str() == "public-schema")
            .unwrap()
            .digest = digest(second);
        project.artifacts.schemas = UniqueIdList::new(schemas).unwrap();
        let second_compiled = CompiledProjectTransform::compile(
            &project,
            "public-binding",
            "public-schema",
            &changed,
        )
        .unwrap();
        assert_ne!(first_digest, second_compiled.closure_digest());
    }
}
