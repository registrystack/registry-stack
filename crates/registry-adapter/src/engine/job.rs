// SPDX-License-Identifier: Apache-2.0

//! The governed-ingestion job compiler and page entry
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2).
//!
//! A job pairs one pack source route with an explicit, bounded profile.
//! [`compile_job`] loads the pack, the `AdapterJob` definition, the
//! operator runtime config, and the profile and project the pack's
//! directory carries, runs the authoring checks the runtime stands on,
//! and compiles the source route into a [`JobProgram`] with no listener,
//! no database, no OIDC issuer, and no served facade operation. The
//! route interpreter is not rewritten: [`run_job_page`] runs the source
//! route through the ordinary engine with the profile's page deadline
//! and validates the final body against the item contract before it is
//! returned.
//!
//! The exchange starts with a null body and the page cursor under the
//! read-only [`ADAPTER_JOB_CURSOR_PROPERTY`] property. The name sits
//! under the engine's reserved `Adapter` prefix, so the same closed rule
//! that guards the facade's engine properties refuses every
//! `setProperty` and `removeProperty` naming it; a route carries its
//! resumption cursor out through its own body, and the entry validates
//! the page like every other page member.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use registry_adapter_core::{
    check_endpoint_bindings, check_job, check_project_pins, check_workspace, AdapterJob,
    AdapterPack, AdapterProfile, AdapterProject, ComponentKind, Step, Workspace,
    ADAPTER_JOB_API_VERSION, ADAPTER_JOB_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND, ADAPTER_REMOVED_KEYS, ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::{
    sha256_uri, RuntimeConfigLoader, RuntimeEnvelope, SecretProvider, SecretResolver,
};
use registry_platform_yaml::{Diagnostic, Severity};
use serde_json::Value;

use crate::engine::exchange::Exchange;
use crate::engine::load::{
    artifact_path, compile_authored_with, format_spec, preflight_endpoint_credential, read,
    step_aggregation_strategies, step_expressions, EndpointCompilation, LoadError,
};
use crate::engine::resilience::ResilienceRuntime;
use crate::engine::route::{
    check_job_servable, is_served_auth, run_job_route, EndpointRuntime, RouteContext, RouteTable,
};
use crate::engine::scripts::{CodeMaps, ScriptSet};

/// The exchange property carrying the page cursor into the source route.
/// The name sits under the engine's reserved `Adapter` prefix, so the
/// authoring checks refuse every `setProperty` and `removeProperty`
/// naming it and the value stays read-only for scripts and expressions.
pub const ADAPTER_JOB_CURSOR_PROPERTY: &str = "AdapterJobCursor";

/// The job page exchange's identifier. It is engine-owned and bounded:
/// it names nothing from the job, the pack, or the page.
const JOB_PAGE_EXCHANGE_ID: &str = "job-page";

/// The journal event a read raises when its decoder skipped malformed
/// input, carrying only a count. The item page shape is closed, so the
/// count leaves the page through this side channel and the entry
/// returns it beside the page.
pub(crate) const JOB_PAGE_DECODE_FAULTS_EVENT: &str = "jobPageDecodeFaults";

/// The engine-side additions to the job vocabulary. The authoring codes
/// live in `registry_adapter_core::JobCode`; these name the conditions
/// only the engine sees, and the list is closed like the core's.
pub const JOB_ENGINE_CODES: &[&str] = &[
    "adapter.job.component-unavailable",
    "adapter.job.decoder-row",
    "adapter.job.direct-unknown",
    "adapter.job.postgres-query-refused",
    "adapter.job.read-bound",
    "adapter.job.source-unbound",
];

/// Why a compiled job was refused. Every diagnostic carries its closed
/// code and fixed text, never a value read from an artifact, a source,
/// or a page.
#[derive(Debug)]
pub struct JobError {
    /// The findings, each with its closed code and artifact kind.
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Display for JobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rendered = self
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{} {}", diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>()
            .join("; ");
        write!(formatter, "the job was refused: {rendered}")
    }
}

impl std::error::Error for JobError {}

fn job_error(diagnostics: Vec<Diagnostic>) -> JobError {
    JobError { diagnostics }
}

/// One finding of the job compiler: the closed code, the artifact kind
/// it points into, and the fixed text.
fn job_finding(
    code: &str,
    artifact: &'static str,
    path: &str,
    message: &str,
    action: &str,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, path, message, action);
    diagnostic.artifact = Some(artifact.to_owned());
    diagnostic
}

/// The compiled job: the checked definition, the source route it runs,
/// and every endpoint, script, and route the source route can reach,
/// with no listener, no database requirement, and no facade serving
/// state. `Debug` prints no member: the compiled state carries
/// credential plans and origins the diagnostics never repeat.
pub struct JobProgram {
    /// The checked job definition.
    pub job: AdapterJob,
    /// The source route's steps, the one list every page run
    /// interprets.
    pub steps: Arc<Vec<Step>>,
    pub(crate) endpoints: BTreeMap<String, EndpointRuntime>,
    pub(crate) scripts: ScriptSet,
    pub(crate) code_maps: CodeMaps,
    pub(crate) resilience: ResilienceRuntime,
    pub(crate) routes: RouteTable,
    pub(crate) resolver: SecretResolver,
    /// The compiled governed-ingestion sources the page runs read.
    pub(crate) job_state: crate::engine::job_sources::JobPageState,
}

impl JobProgram {
    /// The checked job profile the program enforces at every page run.
    #[must_use]
    pub fn profile(&self) -> &registry_adapter_core::JobProfile {
        &self.job.profile
    }
}

impl fmt::Debug for JobProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobProgram")
            .field("job", &self.job.job.id.as_str())
            .finish_non_exhaustive()
    }
}

/// The success path of one page run: the validated page and the count
/// of malformed input lines its decoders skipped, which the page's
/// closed shape cannot carry.
#[derive(Clone, Debug)]
pub struct JobPageResult {
    /// The validated item page.
    pub page: registry_adapter_core::ItemPage,
    /// How many malformed input lines the reads skipped, value-free.
    pub malformed_lines: u32,
}

/// Why a page run failed: the route failure's class when the route
/// raised one, or the closed page-fault or engine-read code when the
/// entry or a decoder refused the page. Never a value.
#[derive(Clone, Debug)]
pub struct JobPageFailure {
    /// The route failure's class, when a route failure ended the run.
    pub class: Option<registry_adapter_core::ErrorClass>,
    /// The value-free page-fault or engine-read code, when the failure
    /// is the page's or a read's own.
    pub code: Option<&'static str>,
}

impl JobPageFailure {
    fn of_class(class: registry_adapter_core::ErrorClass) -> Self {
        Self {
            class: Some(class),
            code: None,
        }
    }

    fn of_code(code: &'static str) -> Self {
        Self {
            class: None,
            code: Some(code),
        }
    }
}

/// Compile a job the way the facade loader compiles a deployment: read
/// the artifacts, run the authoring checks, and assemble the runnable
/// program. `pack_path` names the pack; the profile and project the
/// workspace checks run over are read from beside it, exactly as the
/// loader defaults them beside a project. No facade serving state is
/// compiled: no binding is served, no listener is opened, and no
/// database or issuer is contacted.
///
/// # Errors
///
/// Every refusal carries its closed code: the reader's, the workspace
/// and job checks', or the engine's own
/// `adapter.job.component-unavailable` for a job source this runtime
/// cannot serve.
pub fn compile_job(
    pack_path: &Path,
    job_path: &Path,
    runtime_path: &Path,
) -> Result<JobProgram, JobError> {
    let pack_directory = artifact_directory(pack_path)?;
    let profile_path = artifact_path(None, &pack_directory, "profile.yaml", "--profile")
        .map_err(|error| artifact_error(LoadError::Runtime(error.to_string())))?;
    let project_path = artifact_path(None, &pack_directory, "project.yaml", "--project")
        .map_err(|error| artifact_error(LoadError::Runtime(error.to_string())))?;
    compile_job_with(
        pack_path,
        job_path,
        runtime_path,
        &profile_path,
        &project_path,
    )
}

/// The same compile with the profile and project paths named: the form
/// an offline check takes when its artifacts sit beside the job instead
/// of beside the pack. Every refusal carries the closed code the
/// beside-pack form carries.
///
/// # Errors
///
/// The same refusals [`compile_job`] raises.
pub fn compile_job_with(
    pack_path: &Path,
    job_path: &Path,
    runtime_path: &Path,
    profile_path: &Path,
    project_path: &Path,
) -> Result<JobProgram, JobError> {
    let pack_directory = artifact_directory(pack_path)?;
    let (pack, pack_bytes): (AdapterPack, _) = read(
        pack_path,
        &format_spec(ADAPTER_PACK_KIND, ADAPTER_PACK_API_VERSION),
    )
    .map_err(artifact_error)?;
    let (job, _): (AdapterJob, _) = read(
        job_path,
        &format_spec(ADAPTER_JOB_KIND, ADAPTER_JOB_API_VERSION),
    )
    .map_err(artifact_error)?;
    let (profile, profile_bytes): (AdapterProfile, _) = read(
        profile_path,
        &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
    )
    .map_err(artifact_error)?;
    let (project, project_bytes): (AdapterProject, _) = read(
        project_path,
        &format_spec(ADAPTER_PROJECT_KIND, ADAPTER_PROJECT_API_VERSION),
    )
    .map_err(artifact_error)?;
    let absolute_runtime =
        std::fs::canonicalize(runtime_path).map_err(|_| runtime_error(UNREADABLE_RUNTIME))?;
    let job_runtime = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: ADAPTER_RUNTIME_API_VERSION,
        kind: ADAPTER_RUNTIME_KIND,
    })
    .removed_keys(ADAPTER_REMOVED_KEYS)
    .load::<crate::engine::job_sources::JobRuntimeConfig>(&absolute_runtime)
    .map_err(|error| runtime_error(&format!("the runtime config was refused: {error}")))?;
    let runtime = job_runtime.config.core;
    let sources = job_runtime.config.sources;
    compile_job_from_artifacts(
        &pack,
        &job,
        &profile,
        &project,
        &pack_bytes,
        &profile_bytes,
        &project_bytes,
        &pack_directory,
        &runtime,
        sources.as_ref(),
    )
}

/// The engine boundary's in-memory job compile: the parsed artifacts
/// (pack, job, profile, project, the runtime bindings core, the job
/// sources block) compile to a runnable [`JobProgram`] with no file I/O
/// for the artifacts themselves. `compile_job` and `compile_job_with`
/// parse their files and call this entry; a unit test compiles a
/// job-profile program from in-memory artifacts only. Script and query
/// files load by their pinned paths beside `pack_directory`, the way
/// the pack inventory names them.
///
/// # Errors
///
/// Every refusal carries its closed code: the reader's, the workspace
/// and job checks', or the engine's own codes for an ungated source, an
/// unknown direct target, or an unbound source.
#[allow(clippy::too_many_arguments)]
pub fn compile_job_from_artifacts(
    pack: &AdapterPack,
    job: &AdapterJob,
    profile: &AdapterProfile,
    project: &AdapterProject,
    pack_bytes: &[u8],
    profile_bytes: &[u8],
    project_bytes: &[u8],
    pack_directory: &Path,
    runtime: &registry_adapter_core::AdapterEndpointBindings,
    sources: Option<&crate::engine::job_sources::JobSources>,
) -> Result<JobProgram, JobError> {
    let mut findings: Vec<Diagnostic> = Vec::new();
    // The workspace runtime check demands a binding for every pack
    // endpoint, which the facade-bound components carry. A job source
    // (file, sftp, postgres) binds through the runtime config's sources
    // block instead of an endpoint binding, so the coverage finding is
    // held only for the endpoints the facade shape actually binds: when
    // every unbound endpoint is a job source, the coverage rule is
    // replaced by this compiler's own, which refuses a source endpoint
    // the runtime config binds no source state for.
    let bound: std::collections::BTreeSet<&str> = runtime
        .endpoints
        .iter()
        .map(|binding| binding.endpoint.as_str())
        .collect();
    let unbound_sources_only = pack.endpoints.iter().all(|endpoint| {
        bound.contains(endpoint.id.as_str())
            || matches!(
                endpoint.component,
                ComponentKind::File | ComponentKind::Postgres | ComponentKind::Sftp
            )
    });
    // The job pins its pack by version and digest exactly as a project
    // pins one (CFG-ID-4); the digest pins the bytes, and the bytes
    // carry the id, so version and digest are the whole pin.
    let pack_digest = digest_of(pack_bytes);
    if job.source.pack.version != pack.version {
        findings.push(job_finding(
            registry_adapter_core::CheckCode::ProjectPinVersionMismatch.code(),
            ADAPTER_JOB_KIND,
            "/source/pack/version",
            "the pinned pack version does not match the pack bytes",
            "Pin the version the pack artifact's bytes carry.",
        ));
    }
    if job.source.pack.digest != pack_digest {
        findings.push(job_finding(
            registry_adapter_core::CheckCode::ProjectPinDigestMismatch.code(),
            ADAPTER_JOB_KIND,
            "/source/pack/digest",
            "the pinned pack digest does not match the pack bytes",
            "Pin the sha256 digest of the pack artifact's bytes.",
        ));
    }
    for diagnostic in check_project_pins(
        project,
        &profile.version,
        &digest_of(profile_bytes),
        &pack.version,
        &pack_digest,
    ) {
        findings.push(diagnostic);
    }
    // The workspace checks run with no facade runtime: the bindings
    // check the job path runs instead is the core-owned
    // check_endpoint_bindings over the job document's bindings core,
    // which is check_runtime minus the OIDC block the facade alone
    // configures.
    let workspace = Workspace {
        profile,
        pack,
        project,
        runtime: None,
        fixtures: &[],
    };
    let mut runtime_findings = check_endpoint_bindings(&workspace, runtime);
    for diagnostic in check_workspace(&workspace) {
        runtime_findings.push(diagnostic);
    }
    for diagnostic in runtime_findings {
        if diagnostic.severity != Severity::Error {
            continue;
        }
        if unbound_sources_only
            && diagnostic.code == registry_adapter_core::CheckCode::RuntimeMissingEndpoint.code()
        {
            continue;
        }
        findings.push(diagnostic);
    }
    findings.extend(check_job(job, pack));
    if !findings.is_empty() {
        return Err(job_error(findings));
    }

    let resolver = SecretResolver::new([SecretProvider::Environment], "").map_err(|_| {
        runtime_error("the secret resolver could not start; run where the platform secret providers are configured")
    })?;

    // The deployment digest frames the compiled artifacts.
    let deployment = sha256_uri(
        &[project_bytes, profile_bytes, pack_bytes]
            .iter()
            .flat_map(|bytes| {
                let mut framed = (bytes.len() as u64).to_be_bytes().to_vec();
                framed.extend_from_slice(bytes);
                framed
            })
            .collect::<Vec<u8>>(),
    );

    // The served-operation compile runs over the project with its
    // bindings withdrawn: a job compile serves no facade operation.
    // The workspace checks above ran over the full project, so a job
    // whose route a facade binding reaches was already refused under
    // its own job code.
    let mut unserved_project = project.clone();
    unserved_project.bindings =
        registry_platform_yaml::UniqueIdList::new(Vec::new()).expect("an empty list is unique");
    let authored = compile_authored_with(
        &unserved_project,
        profile,
        pack,
        pack_directory,
        &deployment,
        false,
        |declared| {
            let id = declared.id.as_str();
            if matches!(
                declared.component,
                ComponentKind::File | ComponentKind::Sftp | ComponentKind::Postgres
            ) {
                // A job source endpoint compiles below, from the job's
                // own source state; the facade endpoint compile has no
                // binding for it and needs none.
                return Ok(EndpointCompilation::Absent);
            }
            let Some(binding) = runtime.endpoints.get(id) else {
                return Ok(EndpointCompilation::Absent);
            };
            let plan = crate::engine::auth::AuthPlan::compile(&declared.authentication, binding)
                .map_err(|fault| {
                    LoadError::Runtime(format!(
                        "endpoint {id} authentication was refused: {fault:?}"
                    ))
                })?;
            if !is_served_auth(plan.kind()) {
                return Ok(EndpointCompilation::Unserved {
                    reason: crate::engine::load::UnservedReason::SourceAuthenticationUnsupported,
                    detail: "its authentication is not served by this runtime".to_owned(),
                });
            }
            let egress = crate::engine::egress::EndpointEgress::compile(
                binding, declared, runtime, &resolver,
            )
            .map_err(|fault| {
                LoadError::Runtime(format!("endpoint {id} outbound state was refused: {fault}"))
            })?;
            preflight_endpoint_credential(id, egress.plan(), &resolver)?;
            Ok(EndpointCompilation::Served(Box::new(egress)))
        },
    )
    .map_err(|error| runtime_error(&format!("the job's workspace could not compile: {error}")))?;
    let endpoints = authored.endpoints;
    let job_state = compile_job_sources(pack, pack_directory, sources)?;

    let Some(source) = pack.source_routes.get(job.source.route.as_str()) else {
        // The job checks refused the unknown route already; the same
        // refusal is held again so the compiler never indexes past its
        // own checks.
        return Err(job_error(vec![job_finding(
            registry_adapter_core::JobCode::RouteUnknown.code(),
            ADAPTER_JOB_KIND,
            "/source/route",
            "the job names no source route its pinned pack declares",
            "Name a sourceRoutes id of the pinned pack.",
        )]));
    };
    let steps = Arc::new(source.steps.clone());
    let route_index = pack
        .source_routes
        .iter()
        .position(|route| route.id.as_str() == job.source.route)
        .unwrap_or_default();
    let reached_bodies = check_job_route_graph(
        &steps,
        &authored.routes,
        &format!("/sourceRoutes/{route_index}/steps"),
    )?;

    let mut scripts = authored.scripts;
    compile_source_scripts(pack, pack_directory, &steps, &mut scripts).map_err(|error| {
        runtime_error(&format!("a source route script could not compile: {error}"))
    })?;
    ensure_sends_resolve(&endpoints, &steps, &authored.routes)?;

    // The resilience state covers the source steps and every internal
    // route body a direct send can reach: the processors key their
    // breaker and throttle nodes by the step's address in these very
    // lists, so a body the compile never absorbed would fail its first
    // lookup at page run.
    let mut resilience = ResilienceRuntime::compile(&steps);
    for body in &reached_bodies {
        resilience.absorb(body);
    }
    Ok(JobProgram {
        job: job.clone(),
        steps,
        endpoints,
        scripts,
        code_maps: authored.code_maps,
        resilience,
        routes: authored.routes,
        resolver,
        job_state,
    })
}

impl JobProgram {
    /// Register the host's client for one compiled postgres source. The
    /// engine boundary carries no client; the host
    /// (`registry-adapter-job`, or a test fixture) supplies one per
    /// source endpoint before the first page run. A source whose client
    /// never registers refuses its send at run, uncatchably, never
    /// silently.
    ///
    /// # Errors
    ///
    /// A source endpoint the compile never planned.
    #[cfg(feature = "job-postgres")]
    pub fn register_postgres_source(
        &mut self,
        endpoint: &str,
        source: std::sync::Arc<dyn crate::engine::component::postgres::PostgresSource>,
    ) -> Result<(), JobError> {
        let plan = self.job_state.postgres.get(endpoint).ok_or_else(|| {
            source_unbound(
                &format!("/endpoints/{endpoint}"),
                "the host registers a client for a source endpoint the job does not declare",
            )
        })?;
        let _ = plan;
        self.job_state
            .postgres_clients
            .insert(endpoint.to_owned(), source);
        Ok(())
    }
}

const UNREADABLE_RUNTIME: &str =
    "the runtime config could not be read; pass the absolute path of the operator runtime config file";

fn runtime_error(reason: &str) -> JobError {
    job_error(vec![job_finding(
        "platform.runtime-config.refused",
        ADAPTER_RUNTIME_KIND,
        "",
        &format!("the job's runtime state was refused: {reason}"),
        "Read the refusal and fix the runtime state.",
    )])
}

fn artifact_error(error: LoadError) -> JobError {
    job_error(vec![job_finding(
        "adapter.artifact.refused",
        ADAPTER_JOB_KIND,
        "",
        &format!("a job artifact was refused: {error}"),
        "Read the reader's refusal and fix the artifact.",
    )])
}

fn artifact_directory(path: &Path) -> Result<PathBuf, JobError> {
    let absolute = std::fs::canonicalize(path).map_err(|_| {
        job_error(vec![job_finding(
            "adapter.artifact.unreadable",
            ADAPTER_JOB_KIND,
            "",
            "the artifact could not be read",
            "Pass the path of an existing artifact file.",
        )])
    })?;
    Ok(absolute
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")))
}

fn digest_of(bytes: &[u8]) -> registry_platform_yaml::Digest {
    registry_platform_yaml::Digest::new(sha256_uri(bytes))
        .expect("a computed sha256 uri is a valid digest")
}

/// Compile the job's source endpoints into the page state the runs
/// carry. A job source this build does not serve refuses under
/// `adapter.job.component-unavailable`: the component exists in the
/// model, the runtime just cannot serve it. The `file` source compiles
/// from the runtime config's `sources.file` block only with the
/// `job-file` feature; the read-only `postgres` send compiles the same
/// way from `sources.postgres` with `job-postgres`. Both gates are off
/// by default, so the facade binary and default builds compile neither.
/// The `sftp` source waits on the SSH dependency review of section 17.6
/// in every build. The coverage rule the endpoint-binding checks hand
/// over holds here: every source endpoint carries its source binding,
/// and every source binding names a declared endpoint of its kind,
/// under `adapter.job.source-unbound`.
fn compile_job_sources(
    pack: &AdapterPack,
    pack_directory: &Path,
    sources: Option<&crate::engine::job_sources::JobSources>,
) -> Result<crate::engine::job_sources::JobPageState, JobError> {
    let declared_file: std::collections::BTreeSet<&str> = pack
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.component, ComponentKind::File))
        .map(|endpoint| endpoint.id.as_str())
        .collect();
    if let Some(sources) = sources {
        for id in sources.file.keys() {
            if !declared_file.contains(id.as_str()) {
                return Err(source_unbound(
                    &format!("/sources/file/{id}"),
                    "the runtime config binds a file source no pack endpoint declares",
                ));
            }
        }
    }
    #[cfg_attr(not(feature = "job-file"), allow(unused_mut))]
    let mut files = std::collections::BTreeMap::new();
    #[cfg(feature = "job-postgres")]
    let mut postgres: std::collections::BTreeMap<
        String,
        std::sync::Arc<crate::engine::component::postgres::PostgresPlan>,
    > = std::collections::BTreeMap::new();
    #[cfg(feature = "job-postgres")]
    let postgres_clients = std::collections::BTreeMap::new();
    for declared in pack.endpoints.iter() {
        match declared.component {
            ComponentKind::File => {
                #[cfg(feature = "job-file")]
                {
                    let id = declared.id.as_str();
                    let Some(config) = sources.and_then(|sources| sources.file.get(id)) else {
                        return Err(source_unbound(
                            &format!("/endpoints/{id}"),
                            "the pack declares a file source the runtime config binds no directory for",
                        ));
                    };
                    // The resolved lock shape holds at compile, never at
                    // the first read: a lock name outside the closed
                    // pair, or a lock bound beside no changed lock,
                    // refuses the job.
                    config.read_lock().map_err(|reason| {
                        runtime_error(&format!("endpoint {id} source was refused: {reason}"))
                    })?;
                    files.insert(id.to_owned(), config.clone());
                }
                #[cfg(not(feature = "job-file"))]
                {
                    return Err(unavailable(
                        declared,
                        "serve the file source by building with the job-file feature",
                    ));
                }
            }
            ComponentKind::Postgres => {
                #[cfg(feature = "job-postgres")]
                {
                    let id = declared.id.as_str();
                    let Some(config) = sources.and_then(|sources| sources.postgres.get(id)) else {
                        return Err(source_unbound(
                            &format!("/endpoints/{id}"),
                            "the pack declares a postgres source the runtime config binds no connection for",
                        ));
                    };
                    let Some(query_file) = &declared.query_file else {
                        return Err(unavailable(
                            declared,
                            "the postgres endpoint names no query file",
                        ));
                    };
                    let digest = pack
                        .pinned_file(query_file)
                        .ok_or_else(|| {
                            unavailable(
                                declared,
                                "the postgres endpoint names no pinned query file",
                            )
                        })?
                        .clone();
                    let query_path = pack_directory.join(query_file);
                    let bytes = std::fs::read(&query_path).map_err(|_| {
                        unavailable(declared, "the pinned query file could not be read")
                    })?;
                    if registry_platform_config::sha256_uri(&bytes) != digest.as_str() {
                        return Err(unavailable(
                            declared,
                            "the pinned query file's bytes do not carry the pack's digest",
                        ));
                    }
                    let text = String::from_utf8(bytes)
                        .map_err(|_| unavailable(declared, "the pinned query file is not UTF-8"))?;
                    // The engine compiles the query and holds the plan;
                    // the credential, the pool, and the connection are
                    // the host's, supplied beside the plan.
                    let plan = crate::engine::component::postgres::compile_plan(
                        config.namespace.clone(),
                        &text,
                        Duration::from_millis(declared.attempt_timeout_milliseconds.get()),
                    )
                    .map_err(|reason| {
                        runtime_error(&format!(
                            "endpoint {id} postgres source was refused: {reason}"
                        ))
                    })?;
                    postgres.insert(id.to_owned(), std::sync::Arc::new(plan));
                }
                #[cfg(not(feature = "job-postgres"))]
                {
                    return Err(unavailable(
                        declared,
                        "serve the postgres source by building with the job-postgres feature",
                    ));
                }
            }
            ComponentKind::Sftp => {
                return Err(unavailable(
                    declared,
                    "the sftp source waits on the SSH dependency review",
                ));
            }
            ComponentKind::Direct
            | ComponentKind::GraphQl
            | ComponentKind::Http
            | ComponentKind::Rest => {}
        }
    }
    #[cfg(not(feature = "job-postgres"))]
    {
        let _ = pack_directory;
    }
    Ok(crate::engine::job_sources::JobPageState {
        profile: None,
        files,
        #[cfg(feature = "job-postgres")]
        postgres,
        #[cfg(feature = "job-postgres")]
        postgres_clients,
    })
}

/// The source coverage refusal: a source endpoint or a source binding
/// whose counterpart the artifacts name nothing for.
fn source_unbound(path: &str, message: &str) -> JobError {
    job_error(vec![job_finding(
        "adapter.job.source-unbound",
        ADAPTER_RUNTIME_KIND,
        path,
        message,
        "Bind every source endpoint in the runtime config's sources block, and declare every bound endpoint in the pack.",
    )])
}

fn unavailable(declared: &registry_adapter_core::Endpoint, reason: &str) -> JobError {
    job_error(vec![job_finding(
        "adapter.job.component-unavailable",
        ADAPTER_PACK_KIND,
        &format!("/endpoints/{}", declared.id.as_str()),
        "a job source endpoint is not served by this runtime",
        &format!("{reason}; serve it with its feature gate or drop the endpoint from the pack."),
    )])
}

/// Hold the served-shape walk over the source route and every route its
/// `direct:` sends can reach: the job compiler serves the pollEnrich
/// read step where the facade never does, so a poll hidden behind a
/// direct hop is held to the same shape as one on the source route
/// itself; a direct target the pack declares no body for refuses under
/// `adapter.job.direct-unknown` (the route table check a facade load
/// runs covers its bound routes' bodies, and a job's source entry steps
/// reach it through no binding); and the walk returns the bodies it
/// reached, so the resilience state can absorb them. The direct graph is
/// acyclic and every resolved target names a body, so the visited set is
/// a guard, not the bound.
fn check_job_route_graph(
    steps: &[Step],
    routes: &RouteTable,
    pointer_base: &str,
) -> Result<Vec<Arc<Vec<Step>>>, JobError> {
    let mut bodies: Vec<Arc<Vec<Step>>> = Vec::new();
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut queue: Vec<(&str, String)> = direct_targets(steps, pointer_base);
    while let Some((name, pointer)) = queue.pop() {
        if !visited.insert(name) {
            continue;
        }
        let Some(body) = routes.get(name) else {
            return Err(job_error(vec![job_finding(
                "adapter.job.direct-unknown",
                ADAPTER_PACK_KIND,
                &pointer,
                "the source route sends to a direct route the pack declares no body for",
                "Declare the direct route in the pack's routes, or send to a declared route id.",
            )]));
        };
        // A body inside the table is a pack route or an instantiated
        // template, so its own direct targets carry the route's pointer.
        let body_base = format!("{pointer_base}/direct:{name}");
        queue.extend(direct_targets(body, &body_base));
        bodies.push(Arc::clone(body));
    }
    let unserved = |reason: String| {
        runtime_error(&format!(
            "the source route names a step this engine does not serve: {reason}"
        ))
    };
    check_job_servable(steps).map_err(unserved)?;
    for body in &bodies {
        check_job_servable(body).map_err(unserved)?;
    }
    Ok(bodies)
}

/// The `direct:` route ids one body sends to, through `to:` and
/// `enrich:` steps, each with the step's pointer under `base` for a
/// value-free refusal path.
fn direct_targets<'a>(steps: &'a [Step], base: &str) -> Vec<(&'a str, String)> {
    let mut targets = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, pointer| {
        for uri in [
            match step {
                Step::To(sent) => Some(&sent.uri),
                _ => None,
            },
            match step {
                Step::Enrich(enrich) => Some(&enrich.uri),
                _ => None,
            },
        ]
        .into_iter()
        .flatten()
        {
            if uri.component == registry_adapter_core::SendComponent::Direct {
                targets.push((uri.id.as_str(), format!("{base}{pointer}")));
            }
        }
    });
    targets
}

/// Compile the Rhai scripts and aggregation strategies a source route's
/// steps name, the way the loader compiles a bound route's.
fn compile_source_scripts(
    pack: &AdapterPack,
    pack_directory: &Path,
    steps: &[Step],
    scripts: &mut ScriptSet,
) -> Result<(), String> {
    let mut script_uses: Vec<(String, String)> = Vec::new();
    let mut strategy_uses: Vec<(String, String)> = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, _pointer| {
        for expression in step_expressions(step) {
            if let registry_adapter_core::Expression::Rhai(script) = expression {
                script_uses.push((script.file.clone(), script.entrypoint.clone()));
            }
        }
        for strategy in step_aggregation_strategies(step) {
            if let registry_adapter_core::AggregationStrategy::Rhai { expression: script } =
                strategy
            {
                strategy_uses.push((script.file.clone(), script.entrypoint.clone()));
            }
        }
    });
    for (file, entrypoint) in script_uses {
        scripts
            .add(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| error.to_string())?;
    }
    for (file, entrypoint) in strategy_uses {
        scripts
            .add_aggregation(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Hold the loader's line at job compile: every http or graphql send
/// the source route reaches, through its direct expansions, resolves to
/// a compiled endpoint, so a page run never fails an endpoint lookup
/// the compile could have refused.
fn ensure_sends_resolve(
    endpoints: &BTreeMap<String, EndpointRuntime>,
    steps: &[Step],
    routes: &RouteTable,
) -> Result<(), JobError> {
    let mut missing: Vec<String> = Vec::new();
    let mut walk = |body: &[Step]| {
        registry_adapter_core::walk_steps(body, &mut |step, _pointer| {
            let destination = match step {
                Step::To(sent)
                    if sent.uri.component != registry_adapter_core::SendComponent::Direct =>
                {
                    Some(&sent.uri)
                }
                Step::Enrich(enrich)
                    if enrich.uri.component != registry_adapter_core::SendComponent::Direct =>
                {
                    Some(&enrich.uri)
                }
                _ => None,
            };
            if let Some(uri) = destination {
                // A postgres source send resolves through the job's own
                // source table, which the source compile has validated;
                // an http or graphql send resolves through the loader's
                // endpoint bindings.
                if uri.component == registry_adapter_core::SendComponent::Postgres {
                    return;
                }
                if !endpoints.contains_key(&uri.id) && !missing.contains(&uri.id) {
                    missing.push(uri.id.clone());
                }
            }
        });
    };
    walk(steps);
    for body in routes.values() {
        walk(body);
    }
    if let Some(id) = missing.first() {
        return Err(runtime_error(&format!(
            "endpoint {id} is not bound by the runtime config, and a source route sends through it"
        )));
    }
    Ok(())
}

/// Run one page of the job's source route: the exchange starts with a
/// null body and the cursor under the read-only
/// [`ADAPTER_JOB_CURSOR_PROPERTY`] property, the route runs within the
/// profile's page deadline, and the final body is validated against the
/// item contract under the profile before it is returned. The route
/// interpreter is the engine's own; no fake request is invented and no
/// facade state is consulted.
///
/// # Errors
///
/// A route failure keeps its class (`budget.exhausted` for a deadline
/// that passes first); a page the contract refuses carries its closed
/// `adapter.job.page-*` code.
pub async fn run_job_page(
    program: &JobProgram,
    cursor: Option<Value>,
) -> Result<JobPageResult, JobPageFailure> {
    let profile = &program.job.profile;
    let mut exchange = Exchange::new(JOB_PAGE_EXCHANGE_ID.to_owned());
    if let Some(cursor) = cursor {
        exchange.set_property(ADAPTER_JOB_CURSOR_PROPERTY, cursor);
    }
    let context = RouteContext {
        endpoints: &program.endpoints,
        scripts: &program.scripts,
        resolver: &program.resolver,
        resilience: &program.resilience,
        routes: &program.routes,
        code_maps: program.code_maps.clone(),
        // The profile's own upstream-call budget, which the compile's
        // authoring check holds above the source route's static worst
        // case; the runtime holds the same number at the edge.
        maximum_upstream_calls: profile.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState {
            profile: Some(profile.clone()),
            files: program.job_state.files.clone(),
            #[cfg(feature = "job-postgres")]
            postgres: program.job_state.postgres.clone(),
            #[cfg(feature = "job-postgres")]
            postgres_clients: program.job_state.postgres_clients.clone(),
        },
    };
    // The exchange bound follows the profile: the page and every
    // intermediate body of the run share the response bound, which a
    // source-route-only endpoint may declare up to the platform cap.
    let maximum_exchange_bytes =
        usize::try_from(profile.maximum_response_bytes).unwrap_or(usize::MAX);
    let deadline = Duration::from_millis(profile.page_deadline_milliseconds);
    let outcome = run_job_route(
        &context,
        &program.steps,
        exchange,
        deadline,
        maximum_exchange_bytes,
    )
    .await;
    let exchange = match outcome.result {
        Err(failure) => {
            return Err(match failure.code {
                Some(code) => JobPageFailure {
                    class: Some(failure.class),
                    code: Some(code),
                },
                None => JobPageFailure::of_class(failure.class),
            })
        }
        Ok(exchange) => exchange,
    };
    let malformed_lines = outcome
        .events
        .iter()
        .filter(|event| event.kind == JOB_PAGE_DECODE_FAULTS_EVENT)
        .filter_map(|event| event.detail.get("malformedLines").and_then(Value::as_u64))
        .sum::<u64>();
    let malformed_lines = u32::try_from(malformed_lines).unwrap_or(u32::MAX);
    let page = registry_adapter_core::ItemPage::from_value(&exchange.message.body, profile)
        .map_err(|fault| JobPageFailure::of_code(fault.code()))?;
    Ok(JobPageResult {
        page,
        malformed_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine's additions to the job vocabulary stay closed,
    /// sorted, value-free, and three-segment, and none collides with a
    /// core authoring code.
    #[test]
    fn engine_job_codes_are_closed_sorted_and_three_segment() {
        let mut codes = JOB_ENGINE_CODES.to_vec();
        let expected = codes.clone();
        codes.sort_unstable();
        assert_eq!(codes, expected, "JOB_ENGINE_CODES stays in string order");
        for code in JOB_ENGINE_CODES {
            let mut segments = code.split('.');
            assert_eq!(segments.next(), Some("adapter"));
            assert_eq!(segments.next(), Some("job"));
            assert!(segments.next().is_some(), "{code} names a condition");
            assert_eq!(segments.next(), None, "{code} stays three-segment");
            assert!(
                registry_adapter_core::JobCode::from_code(code).is_none(),
                "{code} must not collide with a core code"
            );
        }
    }

    /// The cursor property stays under the reserved prefix, so the
    /// authoring checks refuse every route write to it.
    #[test]
    fn the_cursor_property_is_reserved_against_route_writes() {
        assert!(registry_adapter_core::is_route_unwritable_property_name(
            ADAPTER_JOB_CURSOR_PROPERTY
        ));
        assert_eq!(ADAPTER_JOB_CURSOR_PROPERTY, "AdapterJobCursor");
    }
}
