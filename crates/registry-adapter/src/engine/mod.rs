// SPDX-License-Identifier: Apache-2.0

//! The engine boundary: the bounded Camel core a facade deployment
//! and a governed-ingestion job both compile through
//! (`products/adapter/CONCEPT.md` sections 8.1 and 17.2).
//!
//! The modules below share one boundary: no file under `engine/` names
//! a facade module (`cli`, `facade`, `idempotent`, `journal`,
//! `notifier`, `read_request`, `serve`) or a facade-only
//! dependency (axum, tokio-postgres, deadpool-postgres,
//! tokio-postgres-rustls, jsonwebtoken, registry-platform-oidc,
//! registry-platform-authcommon). The facade compiles the same engine
//! state a job compiles, and adds serving around it; the later crate
//! split moves this directory into `registry-adapter-engine` as a pure
//! move.

use registry_adapter_core::{AdapterJob, AdapterPack, AdapterProfile, AdapterProject};
use registry_platform_config::{SecretProvider, SecretResolver};

use crate::engine::route::is_served_auth;

pub mod auth;
pub mod component;
#[cfg(feature = "job-file")]
pub mod decoder;
pub mod effective_contract;
pub mod egress;
pub mod envelope;
pub mod errorhandler;
pub mod exchange;
pub mod job;
pub mod job_sources;
pub mod language;
pub mod load;
pub mod processor;
pub mod read_request;
pub mod replay;
pub mod resilience;
pub mod route;
pub mod scripts;

/// The named compile profiles the boundary serves: `facade`, the
/// deployment assembly a live serving compiles, and `job`, the governed
/// ingestion assembly the page run compiles (CONCEPT 17.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineProfileKind {
    Facade,
    Job,
}

/// The in-memory artifacts one compile runs over: the parsed authored
/// documents, the endpoint bindings the runtime states (core's shape),
/// the job definition and job sources block when the profile is job,
/// the artifact bytes the digest pins verify, and the pack directory
/// beside which the inventory's script and query files load.
pub struct CompileInputs<'a> {
    pub pack: &'a AdapterPack,
    pub profile: &'a AdapterProfile,
    pub project: &'a AdapterProject,
    pub job: Option<&'a AdapterJob>,
    pub bindings: &'a registry_adapter_core::AdapterEndpointBindings,
    pub sources: Option<&'a job_sources::JobSources>,
    pub pack_bytes: &'a [u8],
    pub profile_bytes: &'a [u8],
    pub project_bytes: &'a [u8],
    pub pack_directory: &'a std::path::Path,
}

/// The compiled program the boundary returns.
#[derive(Debug)]
pub enum CompiledProgram {
    /// The governed-ingestion job's runnable program.
    Job(Box<job::JobProgram>),
    /// The facade deployment's compiled authored state, which a live
    /// serving turns into served operations with its transport
    /// installed. Boxed: the authored state is far larger than the job
    /// program.
    Facade(Box<load::CompiledAuthoring>),
}

/// The boundary's compile entry: the parsed artifacts compile under the
/// named profile to a reusable program, with no file I/O for the
/// artifacts below it (the inventory's script and query files load by
/// their pinned paths beside `CompileInputs::pack_directory`, the way
/// the pack names them). `compile_job` parses its files and calls this
/// entry; the facade's `load` assembles its serving state over the same
/// authored compiler.
///
/// # Errors
///
/// Every refusal carries its closed code: the workspace and job
/// checks', or the engine's own codes for an ungated job source, an
/// unknown direct target, or an unbound source.
pub fn compile(
    inputs: &CompileInputs<'_>,
    kind: EngineProfileKind,
) -> Result<CompiledProgram, crate::engine::job::JobError> {
    match kind {
        EngineProfileKind::Job => {
            let Some(job) = inputs.job else {
                return Err(job::JobError {
                    diagnostics: vec![registry_platform_yaml::Diagnostic::error(
                        job::JOB_ENGINE_CODES[0],
                        "AdapterJob",
                        "",
                        "the job profile names no job document to compile; pass the job document, or compile under the facade profile",
                    )],
                });
            };
            Ok(CompiledProgram::Job(Box::new(
                job::compile_job_from_artifacts(
                    inputs.pack,
                    job,
                    inputs.profile,
                    inputs.project,
                    inputs.pack_bytes,
                    inputs.profile_bytes,
                    inputs.project_bytes,
                    inputs.pack_directory,
                    inputs.bindings,
                    inputs.sources,
                )?,
            )))
        }
        EngineProfileKind::Facade => {
            let resolver = SecretResolver::new([SecretProvider::Environment], "").map_err(
                |_|
                    job::JobError {
                        diagnostics: vec![registry_platform_yaml::Diagnostic::error(
                            "platform.runtime-config.refused",
                            "AdapterRuntimeConfig",
                            "",
                            "the secret resolver could not start; run where the platform secret providers are configured",
                        )],
                    },
            )?;
            let authored = load::compile_authored_with(
                inputs.project,
                inputs.profile,
                inputs.pack,
                inputs.pack_directory,
                "",
                false,
                |declared| {
                    let id = declared.id.as_str();
                    let Some(binding) = inputs.bindings.endpoints.get(id) else {
                        return Ok(load::EndpointCompilation::Absent);
                    };
                    let plan =
                        crate::engine::auth::AuthPlan::compile(&declared.authentication, binding)
                            .map_err(|fault| {
                            load::LoadError::Runtime(format!(
                                "endpoint {id} authentication was refused: {fault:?}"
                            ))
                        })?;
                    if !is_served_auth(plan.kind()) {
                        return Ok(load::EndpointCompilation::Unserved {
                            reason: load::UnservedReason::SourceAuthenticationUnsupported,
                            detail: "its authentication is not served by this runtime".to_owned(),
                        });
                    }
                    let egress = crate::engine::egress::EndpointEgress::compile(
                        binding,
                        declared,
                        inputs.bindings,
                        &resolver,
                    )
                    .map_err(|fault| {
                        load::LoadError::Runtime(format!(
                            "endpoint {id} outbound state was refused: {fault}"
                        ))
                    })?;
                    Ok(load::EndpointCompilation::Served(Box::new(egress)))
                },
            )
            .map_err(|error| crate::engine::job::JobError {
                diagnostics: vec![registry_platform_yaml::Diagnostic::error(
                    "platform.runtime-config.refused",
                    "AdapterRuntimeConfig",
                    "",
                    format!("the facade deployment could not compile: {error}"),
                )],
            })?;
            Ok(CompiledProgram::Facade(Box::new(authored)))
        }
    }
}

#[cfg(test)]
mod compile_entry_tests {
    use super::*;
    use registry_platform_config::sha256_uri;
    use registry_platform_yaml::Digest;
    use std::collections::BTreeMap;

    fn pack_digest(bytes: &str) -> Digest {
        Digest::new(sha256_uri(bytes.as_bytes())).expect("digest")
    }

    /// A minimal pack: one http endpoint, one source route that sends
    /// and shapes the page through the query's own reply envelope, no
    /// script inventory.
    fn pack_yaml() -> String {
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: memory-pack
version: "1"
testedVersions: []
endpoints:
  - id: source
    component: http
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 65536
sourceRoutes:
  - id: memory-page
    scan: finite
    nextRecovery: exact-replay
    edits: ordered
    steps:
      - to:
          uri: http:source
          parameters:
            httpMethod: GET
            path: /v1/records
      - setBody:
          constant:
            items: []
routes: []
capabilities: {}
"#
        .to_owned()
    }

    fn profile_yaml() -> String {
        r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: memory
version: "1"
operations: []
problems:
  - code: memory.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: memory.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: memory.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted, outcome, facade]
  - code: memory.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected]
problemEnvelope: '{"family": "{{problemCode}}"}'
"#
        .to_owned()
    }

    fn project_yaml(profile_digest: &str, pack_digest: &str) -> String {
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: memory-example
  version: "1"
profile:
  id: memory
  version: "1"
  digest: {profile_digest}
pack:
  id: memory-pack
  version: "1"
  digest: {pack_digest}
recordTypes: []
bindings: []
"#
        )
    }

    fn job_yaml(pack_digest: &str) -> String {
        format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: memory-daily
  version: "1"
source:
  pack:
    id: memory-pack
    version: "1"
    digest: {pack_digest}
  route: memory-page
projection:
  fields:
    - id
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 60000
  maximumResponseBytes: 65536
  maximumPageItems: 100
  maximumPageBytes: 65536
  maximumUpstreamCalls: 4
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: 100
"#
        )
    }

    /// The parsed in-memory artifacts: no file below the entry reads
    /// them back. The pack directory points at a scratch directory the
    /// pack's empty inventory never touches.
    fn artifacts() -> (
        AdapterPack,
        AdapterProfile,
        AdapterProject,
        Option<AdapterJob>,
        registry_adapter_core::AdapterEndpointBindings,
        String,
        String,
        String,
        String,
        tempfile::TempDir,
    ) {
        let pack_text = pack_yaml();
        let profile_text = profile_yaml();
        let profile_digest = pack_digest(&profile_text);
        let pack_digest = pack_digest(&pack_text);
        let project_text = project_yaml(profile_digest.as_str(), pack_digest.as_str());
        let job_text = job_yaml(pack_digest.as_str());
        let pack: AdapterPack = registry_platform_yaml::Reader::new("pack.yaml")
            .decode::<AdapterPack>(
                pack_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::engine::load::format_spec(
                    registry_adapter_core::ADAPTER_PACK_KIND,
                    registry_adapter_core::ADAPTER_PACK_API_VERSION,
                )),
            )
            .expect("the pack parses")
            .value;
        let profile: AdapterProfile = registry_platform_yaml::Reader::new("profile.yaml")
            .decode::<AdapterProfile>(
                profile_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::engine::load::format_spec(
                    registry_adapter_core::ADAPTER_PROFILE_KIND,
                    registry_adapter_core::ADAPTER_PROFILE_API_VERSION,
                )),
            )
            .expect("the profile parses")
            .value;
        let project: AdapterProject = registry_platform_yaml::Reader::new("project.yaml")
            .decode::<AdapterProject>(
                project_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::engine::load::format_spec(
                    registry_adapter_core::ADAPTER_PROJECT_KIND,
                    registry_adapter_core::ADAPTER_PROJECT_API_VERSION,
                )),
            )
            .expect("the project parses")
            .value;
        let job: AdapterJob = registry_platform_yaml::Reader::new("job.yaml")
            .decode::<AdapterJob>(
                job_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::engine::load::format_spec(
                    registry_adapter_core::ADAPTER_JOB_KIND,
                    registry_adapter_core::ADAPTER_JOB_API_VERSION,
                )),
            )
            .expect("the job parses")
            .value;
        let bindings: registry_adapter_core::AdapterEndpointBindings = serde_json::from_str(
            r#"{
                    "id": "memory-deployment",
                    "endpoints": [
                        {
                            "endpoint": "source",
                            "baseUrl": "http://127.0.0.1:9",
                            "credential": {"type": "none"}
                        }
                    ],
                    "allowedPrivateCidrs": ["192.168.0.0/16"]
                }"#,
        )
        .expect("the bindings parse");
        let directory = tempfile::tempdir().expect("the scratch pack directory");
        (
            pack,
            profile,
            project,
            Some(job),
            bindings,
            pack_text,
            profile_text,
            project_text,
            job_text,
            directory,
        )
    }

    /// The boundary's compile entry compiles both profile kinds from
    /// in-memory artifacts: the facade profile returns the compiled
    /// authored state, the job profile returns the runnable job
    /// program, and neither reads an artifact file back.
    #[test]
    fn the_entry_compiles_both_kinds_from_memory() {
        let (
            pack,
            profile,
            project,
            job,
            bindings,
            pack_text,
            profile_text,
            project_text,
            _job_text,
            _directory,
        ) = artifacts();
        let inputs = CompileInputs {
            pack: &pack,
            profile: &profile,
            project: &project,
            job: job.as_ref(),
            bindings: &bindings,
            sources: None,
            pack_bytes: pack_text.as_bytes(),
            profile_bytes: profile_text.as_bytes(),
            project_bytes: project_text.as_bytes(),
            pack_directory: _directory.path(),
        };
        let job_program = match compile(&inputs, EngineProfileKind::Job).expect("the job compiles")
        {
            CompiledProgram::Job(program) => *program,
            CompiledProgram::Facade(_) => panic!("the job profile returned the facade program"),
        };
        assert_eq!(job_program.job.job.id.as_str(), "memory-daily");
        let facade = match compile(&inputs, EngineProfileKind::Facade)
            .expect("the facade authored state compiles")
        {
            CompiledProgram::Facade(authored) => *authored,
            CompiledProgram::Job(_) => panic!("the facade profile returned the job program"),
        };
        assert!(
            facade.served.is_empty(),
            "no binding serves an operation in this deployment"
        );
        let _ = BTreeMap::<String, String>::new();
    }

    /// The entry holds the pack pin: a job whose pinned pack digest does
    /// not match the pack bytes refuses with the pin mismatch code.
    #[test]
    fn the_entry_holds_the_pack_pin() {
        let (
            pack,
            profile,
            project,
            job,
            bindings,
            pack_text,
            profile_text,
            project_text,
            _job_text,
            _directory,
        ) = artifacts();
        let inputs = CompileInputs {
            pack: &pack,
            profile: &profile,
            project: &project,
            job: job.as_ref(),
            bindings: &bindings,
            sources: None,
            // The bytes carry one changed byte, so the pinned digest in
            // the job document no longer matches the pack bytes.
            pack_bytes: pack_text.as_bytes(),
            profile_bytes: profile_text.as_bytes(),
            project_bytes: project_text.as_bytes(),
            pack_directory: _directory.path(),
        };
        let mut pinned = pack_text.clone();
        pinned.push(' ');
        let job: AdapterJob = registry_platform_yaml::Reader::new("job.yaml")
            .decode::<AdapterJob>(
                job_yaml(&pack_digest(&pinned)).as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::engine::load::format_spec(
                    registry_adapter_core::ADAPTER_JOB_KIND,
                    registry_adapter_core::ADAPTER_JOB_API_VERSION,
                )),
            )
            .expect("the repinned job parses")
            .value;
        let inputs = CompileInputs {
            job: Some(&job),
            pack_bytes: pack_text.as_bytes(),
            ..inputs
        };
        let error = compile(&inputs, EngineProfileKind::Job).expect_err("the pin holds");
        assert!(
            error
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "adapter.project.pin-digest-mismatch"),
            "the pin refusal carries its code: {:?}",
            error.diagnostics
        );
    }
}
