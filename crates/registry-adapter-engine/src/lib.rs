// SPDX-License-Identifier: Apache-2.0

//! Listener-free bounded Camel core compiled by facade, ingestion, and
//! Evidence hosts
//! (`products/adapter/CONCEPT.md` sections 8.1 and 17.2).
//!
//! The crate has no listener, inbound OIDC, PostgreSQL client, product client,
//! journal, or idempotency-store dependency. Hosts compile the same engine
//! state and add their own admission, durable custody, and release policy.

use registry_adapter_core::{AdapterJob, AdapterPack, AdapterProfile, AdapterProject};
use registry_platform_config::{SecretProvider, SecretResolver};

use crate::route::is_served_auth;

pub mod artifacts;
pub mod async_completion;
pub mod auth;
pub mod component;
#[cfg(feature = "job-file")]
pub mod decoder;
pub mod effective_contract;
pub mod egress;
pub mod envelope;
pub mod errorhandler;
pub mod evidence;
pub mod exchange;
pub mod host_protocol;
pub mod inbound_transform;
pub mod job;
pub mod job_sources;
pub(crate) mod json_bounds;
pub mod language;
pub mod load;
pub mod processor;
pub mod project_transform;
pub mod public_schema;
pub mod rabbitmq_config;
pub mod read_request;
pub mod replay;
pub mod resilience;
mod resume;
pub mod route;
pub mod scripts;
pub mod target;

pub use resume::ResumeValue;

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
/// the artifact bytes the digest pins verify, and the supplied bytes for every
/// inventory script or query the compiled closure consumes.
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
    pub pack_artifacts: &'a artifacts::PackArtifactBytes,
    /// Bytes for job-owned destination mappings, keyed by their exact path
    /// relative to the job document. Facade compiles may pass an empty set.
    pub job_artifacts: &'a artifacts::PackArtifactBytes,
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
/// artifacts below it. Inventory scripts and queries are read only from
/// `CompileInputs::pack_artifacts`, by the exact paths the pack pins. The
/// maintained facade and job file loaders assemble the same compiler over a
/// directory source as a convenience for binary hosts.
///
/// # Errors
///
/// Every refusal carries its closed code: the workspace and job
/// checks', or the engine's own codes for an ungated job source, an
/// unknown direct target, or an unbound source.
pub fn compile(
    inputs: &CompileInputs<'_>,
    kind: EngineProfileKind,
) -> Result<CompiledProgram, crate::job::JobError> {
    match kind {
        EngineProfileKind::Job => {
            let Some(job) = inputs.job else {
                return Err(compile_refusal(
                    job::JOB_ENGINE_CODES[0],
                    "AdapterJob",
                    "the job profile names no job document to compile",
                    "Pass the job document, or compile under the facade profile.",
                ));
            };
            Ok(CompiledProgram::Job(Box::new(
                job::compile_job_from_supplied_artifacts(
                    inputs.pack,
                    job,
                    inputs.profile,
                    inputs.project,
                    inputs.pack_bytes,
                    inputs.profile_bytes,
                    inputs.project_bytes,
                    inputs.pack_artifacts,
                    inputs.job_artifacts,
                    inputs.bindings,
                    inputs.sources,
                )?,
            )))
        }
        EngineProfileKind::Facade => {
            if inputs.project.consultation.is_some() {
                return Err(compile_refusal(
                    "adapter.engine.target-attachment-required",
                    "AdapterProject",
                    "the in-memory facade compiler has no host target attachment",
                    "Use the maintained host loader with the target's governed artifact closure.",
                ));
            }
            let resolver =
                SecretResolver::new([SecretProvider::Environment], "").map_err(|_| {
                    compile_refusal(
                        "platform.runtime-config.refused",
                        "AdapterRuntimeConfig",
                        "the secret resolver could not start",
                        "Run where the platform secret providers are configured.",
                    )
                })?;
            let authored = load::compile_authored_with_artifacts(
                inputs.project,
                inputs.profile,
                inputs.pack,
                inputs.pack_artifacts,
                "",
                false,
                |declared| {
                    let id = declared.id.as_str();
                    let Some(binding) = inputs.bindings.endpoints.get(id) else {
                        return Ok(load::EndpointCompilation::Absent);
                    };
                    let plan = crate::auth::AuthPlan::compile(&declared.authentication, binding)
                        .map_err(|fault| {
                            load::LoadError::Runtime(format!(
                                "endpoint {id} authentication was refused: {fault}"
                            ))
                        })?;
                    if !is_served_auth(plan.kind()) {
                        return Ok(load::EndpointCompilation::Unserved {
                            reason: load::UnservedReason::SourceAuthenticationUnsupported,
                            detail: "its authentication is not served by this runtime".to_owned(),
                        });
                    }
                    let egress = crate::egress::EndpointEgress::compile(
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
            .map_err(|error| {
                compile_refusal(
                    "platform.runtime-config.refused",
                    "AdapterRuntimeConfig",
                    &format!("the facade deployment could not compile: {error}"),
                    "Fix the artifact or runtime binding the message names.",
                )
            })?;
            Ok(CompiledProgram::Facade(Box::new(authored)))
        }
    }
}

/// One compile-entry refusal: the closed code, the artifact kind it
/// points into, the fixed text, and the next step.
fn compile_refusal(
    code: &str,
    artifact: &str,
    message: &str,
    action: &str,
) -> crate::job::JobError {
    let mut diagnostic = registry_platform_yaml::Diagnostic::error(code, "", message, action);
    diagnostic.artifact = Some(artifact.to_owned());
    crate::job::JobError {
        diagnostics: vec![diagnostic],
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

    fn script_source() -> &'static str {
        "fn transform(exchange) { exchange.body }\n"
    }

    fn pack_artifacts() -> artifacts::PackArtifactBytes {
        artifacts::PackArtifactBytes::new([(
            "scripts/transform.rhai".to_owned(),
            script_source().as_bytes().to_vec(),
        )])
    }

    /// A minimal pack: one http endpoint, one source route that sends,
    /// and one digest-pinned script used by a direct route.
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
routes:
  - id: transform
    from:
      uri: direct:transform
    steps:
      - setBody:
          rhai:
            file: scripts/transform.rhai
            entrypoint: transform
scripts:
  - path: scripts/transform.rhai
    digest: SCRIPT_DIGEST
capabilities: {}
"#
        .replace(
            "SCRIPT_DIGEST",
            &registry_platform_config::sha256_uri(script_source().as_bytes()),
        )
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
destination:
  type: signed-coordinator-event
  binding: coordinator-test
  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:case-daily
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1
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
                &registry_platform_yaml::Expect::one(&crate::load::format_spec(
                    registry_adapter_core::ADAPTER_PACK_KIND,
                    registry_adapter_core::ADAPTER_PACK_API_VERSION,
                )),
            )
            .expect("the pack parses")
            .value;
        let profile: AdapterProfile = registry_platform_yaml::Reader::new("profile.yaml")
            .decode::<AdapterProfile>(
                profile_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::load::format_spec(
                    registry_adapter_core::ADAPTER_PROFILE_KIND,
                    registry_adapter_core::ADAPTER_PROFILE_API_VERSION,
                )),
            )
            .expect("the profile parses")
            .value;
        let project: AdapterProject = registry_platform_yaml::Reader::new("project.yaml")
            .decode::<AdapterProject>(
                project_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::load::format_spec(
                    registry_adapter_core::ADAPTER_PROJECT_KIND,
                    registry_adapter_core::ADAPTER_PROJECT_API_VERSION,
                )),
            )
            .expect("the project parses")
            .value;
        let job: AdapterJob = registry_platform_yaml::Reader::new("job.yaml")
            .decode::<AdapterJob>(
                job_text.as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::load::format_spec(
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
        let scripts = directory.path().join("scripts");
        std::fs::create_dir(&scripts).expect("the scripts directory is created");
        std::fs::write(scripts.join("transform.rhai"), script_source())
            .expect("the pinned script is written");
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
        let pack_artifacts = pack_artifacts();
        let job_artifacts = artifacts::PackArtifactBytes::default();
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
            pack_artifacts: &pack_artifacts,
            job_artifacts: &job_artifacts,
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

    #[test]
    fn the_in_memory_facade_entry_never_returns_an_unattached_target_plan() {
        let (
            pack,
            profile,
            mut project,
            job,
            bindings,
            pack_text,
            profile_text,
            project_text,
            _job_text,
            _directory,
        ) = artifacts();
        project.profile = None;
        project.consultation = Some(
            serde_json::from_value(serde_json::json!({
                "contract": "https://registry.example/contracts/1.0.0/openapi.yaml",
                "collections": []
            }))
            .expect("consultation"),
        );
        let pack_artifacts = pack_artifacts();
        let job_artifacts = artifacts::PackArtifactBytes::default();
        let error = compile(
            &CompileInputs {
                pack: &pack,
                profile: &profile,
                project: &project,
                job: job.as_ref(),
                bindings: &bindings,
                sources: None,
                pack_bytes: pack_text.as_bytes(),
                profile_bytes: profile_text.as_bytes(),
                project_bytes: project_text.as_bytes(),
                pack_artifacts: &pack_artifacts,
                job_artifacts: &job_artifacts,
            },
            EngineProfileKind::Facade,
        )
        .expect_err("a fixed target cannot compile without its host attachment");
        assert_eq!(
            error.diagnostics[0].code,
            "adapter.engine.target-attachment-required"
        );
    }

    /// A library host supplies the governed artifact bytes once. Compilation
    /// must not reopen the original pack directory after those bytes are in
    /// memory, while the script inventory digest still closes over the exact
    /// source that is compiled.
    #[test]
    fn the_entry_compiles_a_pinned_script_after_its_directory_is_unavailable() {
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
            directory,
        ) = artifacts();
        let removed_directory = directory.path().to_path_buf();
        directory
            .close()
            .expect("the original directory is removed");
        assert!(!removed_directory.exists());
        let pack_artifacts = pack_artifacts();
        let job_artifacts = artifacts::PackArtifactBytes::default();
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
            pack_artifacts: &pack_artifacts,
            job_artifacts: &job_artifacts,
        };

        compile(&inputs, EngineProfileKind::Facade)
            .expect("supplied pinned bytes compile without the source directory");
    }

    /// The supplied set is not a way around the governed closure: a referenced
    /// script must be present and must carry the digest the pack pins.
    #[test]
    fn the_entry_holds_the_supplied_script_closure_and_digest() {
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
        let pinned = pack
            .scripts
            .iter()
            .find(|script| script.path == "scripts/transform.rhai")
            .expect("the pack pins the script")
            .digest
            .as_str()
            .to_owned();
        let changed = b"fn transform(exchange) { 42 }\n".to_vec();
        let actual = registry_platform_config::sha256_uri(&changed);
        let cases = [
            (
                "missing",
                artifacts::PackArtifactBytes::default(),
                vec!["script scripts/transform.rhai could not be read".to_owned()],
            ),
            (
                "digest mismatch",
                artifacts::PackArtifactBytes::new([("scripts/transform.rhai".to_owned(), changed)]),
                vec![
                    "script scripts/transform.rhai does not match its pinned digest".to_owned(),
                    format!("the pin is {pinned}"),
                    format!("the file has {actual}"),
                    format!("after reviewing the change, update the pin to {actual}"),
                ],
            ),
        ];
        let job_artifacts = artifacts::PackArtifactBytes::default();

        for (case, pack_artifacts, expected) in cases {
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
                pack_artifacts: &pack_artifacts,
                job_artifacts: &job_artifacts,
            };
            let error = match compile(&inputs, EngineProfileKind::Facade) {
                Err(error) => error,
                Ok(_) => panic!("{case} should be refused"),
            };
            assert!(
                error.diagnostics.iter().any(|diagnostic| expected
                    .iter()
                    .all(|needle| diagnostic.message.contains(needle.as_str()))),
                "{case} carries the artifact refusal: {:?}",
                error.diagnostics
            );
        }
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
        let pack_artifacts = pack_artifacts();
        let job_artifacts = artifacts::PackArtifactBytes::default();
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
            pack_artifacts: &pack_artifacts,
            job_artifacts: &job_artifacts,
        };
        let mut pinned = pack_text.clone();
        pinned.push(' ');
        let job: AdapterJob = registry_platform_yaml::Reader::new("job.yaml")
            .decode::<AdapterJob>(
                job_yaml(&pack_digest(&pinned)).as_bytes(),
                &registry_platform_yaml::Expect::one(&crate::load::format_spec(
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
        let refusal = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "adapter.project.pin-digest-mismatch")
            .unwrap_or_else(|| panic!("the pin refusal carries its code: {:?}", error.diagnostics));
        let actual = pack_digest(&pack_text);
        assert!(
            refusal.message.contains(pack_digest(&pinned).as_str())
                && refusal.message.contains(actual.as_str())
                && refusal.suggested_action.contains(actual.as_str()),
            "the pin refusal names both digests: {refusal:?}"
        );
        let job_pin = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.path == "/source/pack/digest")
            .expect("the job's own pack pin is refused at its member");
        let computed = sha256_uri(pack_text.as_bytes());
        assert!(
            job_pin.suggested_action.contains(&computed),
            "the refusal names the digest to pin: {}",
            job_pin.suggested_action
        );
    }

    /// An authentication refusal renders the fault's fixed operator text,
    /// never its Rust variant name, on both profile kinds.
    #[test]
    fn an_authentication_refusal_renders_its_fixed_text_not_a_variant_name() {
        let (
            pack,
            profile,
            project,
            job,
            _bindings,
            pack_text,
            profile_text,
            project_text,
            _job_text,
            _directory,
        ) = artifacts();
        let bindings: registry_adapter_core::AdapterEndpointBindings =
            serde_json::from_value(serde_json::json!({
                "id": "memory-deployment",
                "endpoints": [{
                    "endpoint": "source",
                    "baseUrl": "http://127.0.0.1:9",
                    "credential": {"type": "static-api-key", "valueRef": "secret:env/UNUSED"}
                }],
                "allowedPrivateCidrs": []
            }))
            .expect("the bindings parse");
        let pack_artifacts = pack_artifacts();
        let job_artifacts = artifacts::PackArtifactBytes::default();
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
            pack_artifacts: &pack_artifacts,
            job_artifacts: &job_artifacts,
        };
        for kind in [EngineProfileKind::Facade, EngineProfileKind::Job] {
            let error = compile(&inputs, kind).expect_err("a mismatched credential is refused");
            let rendered = error
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            // The job's own credential check refuses first with a typed
            // code; the facade compile carries the endpoint id. Both name
            // the two kinds.
            let expected = match kind {
                EngineProfileKind::Facade => {
                    "endpoint source authentication was refused: the runtime credential's kind \
                     (`static-api-key`) does not match the endpoint's declared kind (`none`)"
                }
                EngineProfileKind::Job => {
                    "the runtime credential's kind (`static-api-key`) does not match the endpoint's declared kind (`none`)"
                }
            };
            assert!(
                rendered.contains(expected),
                "the refusal carries the fixed text under {kind:?}: {:?}",
                error.diagnostics
            );
            assert!(!rendered.contains("KindMismatch"), "{rendered}");
        }
    }
}
