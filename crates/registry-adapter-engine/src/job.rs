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
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use registry_adapter_core::{
    check_endpoint_bindings, check_job, check_project_pins, check_workspace, AdapterJob,
    AdapterPack, AdapterProfile, AdapterProject, ComponentKind, DestinationMapping, JobDestination,
    RecordLocator, Step, Workspace, ADAPTER_JOB_API_VERSION, ADAPTER_JOB_KIND,
    ADAPTER_JOB_RUNTIME_KIND, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND, FILE_ROW_IDENTITY_VERSION,
};
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use registry_platform_yaml::{Diagnostic, Severity};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::artifacts::{ArtifactReadError, ArtifactSource, PackArtifactBytes};
use crate::exchange::Exchange;
use crate::load::{
    artifact_path, format_spec, preflight_endpoint_credential, read_located,
    step_aggregation_strategies, step_expressions, EndpointCompilation, LoadError, ReadRefusal,
};
use crate::resilience::ResilienceRuntime;
use crate::route::{
    check_job_servable, is_served_auth, run_job_route, EndpointRuntime, RouteContext, RouteTable,
};
use crate::scripts::{CodeMaps, ScriptFailure, ScriptLoadError, ScriptSet};

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
    "adapter.job.decoder-key-duplicate",
    "adapter.job.decoder-key-invalid",
    "adapter.job.decoder-key-missing",
    "adapter.job.decoder-row",
    "adapter.job.direct-unknown",
    "adapter.job.postgres-column-type",
    "adapter.job.postgres-key-null",
    "adapter.job.postgres-query-refused",
    "adapter.job.rabbitmq-delivery-mode",
    "adapter.job.rabbitmq-page-shape",
    "adapter.job.rabbitmq-topology",
    "adapter.job.rabbitmq-unavailable",
    "adapter.job.read-bound",
    "adapter.job.read-timeout",
    "adapter.job.sftp-authentication",
    "adapter.job.sftp-connection",
    "adapter.job.sftp-credential",
    "adapter.job.sftp-host-key",
    "adapter.job.sftp-malformed",
    "adapter.job.sftp-path",
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
    /// The source route's declaration, resolved from the pinned pack:
    /// the scan, recovery, and edit semantics the host's triggers read,
    /// so they never re-read the pack file.
    pub source_route: registry_adapter_core::SourceRouteDecl,
    /// The source route's steps, the one list every page run
    /// interprets.
    pub steps: Arc<Vec<Step>>,
    pub(crate) endpoints: BTreeMap<String, EndpointRuntime>,
    pub(crate) scripts: ScriptSet,
    pub(crate) code_maps: CodeMaps,
    pub(crate) resilience: ResilienceRuntime,
    pub(crate) routes: RouteTable,
    pub(crate) resolver: Arc<SecretResolver>,
    /// The compiled governed-ingestion sources the page runs read.
    pub(crate) job_state: crate::job_sources::JobPageState,
    /// The conservative source identity contract of reachable file and SFTP
    /// polls. It covers key semantics plus the selected route and provider
    /// endpoint, so a source rebinding is explicit while unrelated pack and
    /// runtime tuning remains outside the fence.
    item_identity_digest: Option<[u8; 32]>,
    /// The reader's warnings over the authored artifacts the compile
    /// read from files. A run proceeds past them; an offline check that
    /// denies warnings refuses on them.
    pub warnings: Vec<Diagnostic>,
}

impl JobProgram {
    /// The checked job profile the program enforces at every page run.
    #[must_use]
    pub fn profile(&self) -> &registry_adapter_core::JobProfile {
        &self.job.profile
    }

    /// The semantic identity contract the item store must bind before a file
    /// or SFTP page is read. `None` means this job reaches no file-like poll,
    /// so HTTP, PostgreSQL, RabbitMQ, and other jobs need no migration state.
    #[must_use]
    pub fn item_identity_digest(&self) -> Option<[u8; 32]> {
        self.item_identity_digest
    }

    /// Run the job's already compiled, digest-pinned destination mapping
    /// over one declared projection. The host supplies only the selected
    /// mapping reference and projection; destination clients and runtime
    /// authority remain outside the engine.
    ///
    /// # Errors
    ///
    /// The script's bounded runtime failure, including an unknown mapping
    /// reference that was not part of this compiled job.
    pub fn map_destination(
        &self,
        mapping: &DestinationMapping,
        projection: &Value,
    ) -> Result<Value, ScriptFailure> {
        self.scripts
            .call_job_mapping(&self.code_maps, mapping, projection)
    }

    /// The selected source route's captured PostgreSQL connection
    /// bindings. The host activates this compile-time snapshot and has
    /// no runtime path to read again.
    #[cfg(feature = "job-postgres")]
    pub fn postgres_source_bindings(
        &self,
    ) -> impl Iterator<Item = &crate::job_sources::PostgresSourceBinding> {
        self.job_state.postgres_bindings.values()
    }

    /// The selected source route's captured SFTP connection bindings.
    #[cfg(feature = "job-sftp")]
    pub fn sftp_source_bindings(
        &self,
    ) -> impl Iterator<Item = &crate::job_sources::SftpSourceBinding> {
        self.job_state.sftp_bindings.values()
    }

    /// The selected source route's captured RabbitMQ connection bindings.
    #[cfg(feature = "job-rabbitmq")]
    pub fn rabbitmq_source_bindings(
        &self,
    ) -> impl Iterator<Item = &crate::job_sources::RabbitMqSourceBinding> {
        self.job_state.rabbitmq_bindings.values()
    }

    /// Whether this program would acquire a broker delivery. A queue dry run
    /// checks this before it opens the item store or runs the source route,
    /// because AMQP 0-9-1 has no side-effect-free peek.
    #[must_use]
    pub fn has_rabbitmq_source(&self) -> bool {
        #[cfg(feature = "job-rabbitmq")]
        {
            !self.job_state.rabbitmq.is_empty()
        }
        #[cfg(not(feature = "job-rabbitmq"))]
        {
            false
        }
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
#[derive(Debug)]
pub struct JobPageResult {
    /// The validated item page.
    pub page: registry_adapter_core::ItemPage,
    /// How many malformed input lines the reads skipped, value-free.
    pub malformed_lines: u32,
    /// The source-owned manual settlement receipt for a one-message queue
    /// page. It is process-only and never enters page JSON or durable state.
    #[cfg(feature = "job-rabbitmq")]
    pub source_receipt: Option<crate::component::rabbitmq::RabbitMqPageReceipt>,
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
    /// The exact value-free source record ordinal, when a row decoder
    /// refused one record.
    pub record: Option<RecordLocator>,
}

impl JobPageFailure {
    fn of_class(class: registry_adapter_core::ErrorClass) -> Self {
        Self {
            class: Some(class),
            code: None,
            record: None,
        }
    }

    fn of_code(code: &'static str) -> Self {
        Self {
            class: None,
            code: Some(code),
            record: None,
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
    let job_runtime =
        crate::job_sources::JobRuntimeConfig::load(runtime_path).map_err(|error| {
            let mut diagnostics = error.diagnostics().to_vec();
            if let Some(hint) =
                crate::job_sources::JobRuntimeConfig::facade_kind_hint(runtime_path, &error)
            {
                for diagnostic in &mut diagnostics {
                    if diagnostic.code == "config.wrong-kind" {
                        diagnostic.suggested_action = hint.clone();
                    }
                }
            }
            job_error(located_in(diagnostics, ADAPTER_JOB_RUNTIME_KIND))
        })?;
    let resolver = Arc::new(
        job_runtime
            .secret_resolver()
            .map_err(|error| secret_providers_refusal(&error))?,
    );
    compile_job_with_runtime(
        pack_path,
        job_path,
        &job_runtime,
        resolver,
        profile_path,
        project_path,
    )
}

/// Compile from one host-supplied process-lifetime runtime snapshot and its
/// one resolver. The runtime file is never re-read through this entry.
///
/// # Errors
///
/// The same refusals [`compile_job_with`] raises after reading the runtime.
pub fn compile_job_with_runtime(
    pack_path: &Path,
    job_path: &Path,
    job_runtime: &crate::job_sources::JobRuntimeConfig,
    resolver: Arc<SecretResolver>,
    profile_path: &Path,
    project_path: &Path,
) -> Result<JobProgram, JobError> {
    let pack_directory = artifact_directory(pack_path)?;
    let job_directory = artifact_directory(job_path)?;
    let mut warnings = Vec::new();
    let (pack, pack_bytes): (AdapterPack, _) = read_job_artifact(
        pack_path,
        ADAPTER_PACK_KIND,
        ADAPTER_PACK_API_VERSION,
        &mut warnings,
    )?;
    let (job, _): (AdapterJob, _) = read_job_artifact(
        job_path,
        ADAPTER_JOB_KIND,
        ADAPTER_JOB_API_VERSION,
        &mut warnings,
    )?;
    let (profile, profile_bytes): (AdapterProfile, _) = read_job_artifact(
        profile_path,
        ADAPTER_PROFILE_KIND,
        ADAPTER_PROFILE_API_VERSION,
        &mut warnings,
    )?;
    let (project, project_bytes): (AdapterProject, _) = read_job_artifact(
        project_path,
        ADAPTER_PROJECT_KIND,
        ADAPTER_PROJECT_API_VERSION,
        &mut warnings,
    )?;
    let mut program = compile_job_from_sources(
        &pack,
        &job,
        &profile,
        &project,
        &pack_bytes,
        &profile_bytes,
        &project_bytes,
        &pack_directory,
        &job_directory,
        &job_runtime.core,
        job_runtime.sources.as_ref(),
        resolver,
    )?;
    program.warnings = warnings;
    Ok(program)
}

/// The engine boundary's in-memory job compile: the parsed artifacts
/// (pack, job, profile, project, the runtime bindings core, the job
/// sources block) compile to a runnable [`JobProgram`] with no file I/O
/// for the artifacts themselves. `compile_job` and `compile_job_with`
/// parse their files and call this entry. Script and query files load by their
/// pinned paths beside `pack_directory`; the public engine compile entry uses
/// the same core with host-supplied bytes instead.
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
    job_directory: &Path,
    runtime: &registry_adapter_core::AdapterEndpointBindings,
    sources: Option<&crate::job_sources::JobSources>,
) -> Result<JobProgram, JobError> {
    let resolver = environment_secret_resolver()?;
    compile_job_from_sources(
        pack,
        job,
        profile,
        project,
        pack_bytes,
        profile_bytes,
        project_bytes,
        pack_directory,
        job_directory,
        runtime,
        sources,
        resolver,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_job_from_sources(
    pack: &AdapterPack,
    job: &AdapterJob,
    profile: &AdapterProfile,
    project: &AdapterProject,
    pack_bytes: &[u8],
    profile_bytes: &[u8],
    project_bytes: &[u8],
    pack_directory: &Path,
    job_directory: &Path,
    runtime: &registry_adapter_core::AdapterEndpointBindings,
    sources: Option<&crate::job_sources::JobSources>,
    resolver: Arc<SecretResolver>,
) -> Result<JobProgram, JobError> {
    let job_artifacts = JobArtifactDirectory(job_directory);
    compile_job_from_source(
        pack,
        job,
        profile,
        project,
        pack_bytes,
        profile_bytes,
        project_bytes,
        pack_directory,
        &job_artifacts,
        runtime,
        sources,
        resolver,
    )
}

/// The file-based job artifact boundary. A clean authored path is necessary
/// but not sufficient: canonical containment also refuses an intermediate or
/// final symlink that resolves outside the job directory.
struct JobArtifactDirectory<'a>(&'a Path);

impl ArtifactSource for JobArtifactDirectory<'_> {
    fn read_bounded(&self, path: &str, limit: usize) -> Result<Vec<u8>, ArtifactReadError> {
        let root = std::fs::canonicalize(self.0).map_err(|_| ArtifactReadError::Unavailable)?;
        let candidate =
            std::fs::canonicalize(self.0.join(path)).map_err(|_| ArtifactReadError::Unavailable)?;
        if !candidate.starts_with(&root) {
            return Err(ArtifactReadError::Unavailable);
        }
        let file = std::fs::File::open(candidate).map_err(|_| ArtifactReadError::Unavailable)?;
        let length = file
            .metadata()
            .map_err(|_| ArtifactReadError::Unavailable)?
            .len();
        if length > limit as u64 {
            return Err(ArtifactReadError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(limit.min(length as usize));
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactReadError::Unavailable)?;
        if bytes.len() > limit {
            Err(ArtifactReadError::TooLarge)
        } else {
            Ok(bytes)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_job_from_supplied_artifacts(
    pack: &AdapterPack,
    job: &AdapterJob,
    profile: &AdapterProfile,
    project: &AdapterProject,
    pack_bytes: &[u8],
    profile_bytes: &[u8],
    project_bytes: &[u8],
    artifacts: &PackArtifactBytes,
    job_artifacts: &PackArtifactBytes,
    runtime: &registry_adapter_core::AdapterEndpointBindings,
    sources: Option<&crate::job_sources::JobSources>,
) -> Result<JobProgram, JobError> {
    let resolver = environment_secret_resolver()?;
    compile_job_from_source(
        pack,
        job,
        profile,
        project,
        pack_bytes,
        profile_bytes,
        project_bytes,
        artifacts,
        job_artifacts,
        runtime,
        sources,
        resolver,
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_job_from_source<S: ArtifactSource + ?Sized, J: ArtifactSource + ?Sized>(
    pack: &AdapterPack,
    job: &AdapterJob,
    profile: &AdapterProfile,
    project: &AdapterProject,
    pack_bytes: &[u8],
    profile_bytes: &[u8],
    project_bytes: &[u8],
    artifacts: &S,
    job_artifacts: &J,
    runtime: &registry_adapter_core::AdapterEndpointBindings,
    sources: Option<&crate::job_sources::JobSources>,
    resolver: Arc<SecretResolver>,
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
                ComponentKind::File
                    | ComponentKind::Postgres
                    | ComponentKind::RabbitMq
                    | ComponentKind::Sftp
                    | ComponentKind::SqliteExtract
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
            &format!(
                "the pinned pack digest {} does not match the pack bytes, which hash to {}",
                job.source.pack.digest.as_str(),
                pack_digest.as_str()
            ),
            &format!(
                "Pin {}, the sha256 digest of the pack artifact's bytes, after reviewing the change.",
                pack_digest.as_str()
            ),
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
    let authored = crate::load::compile_authored_from(
        &unserved_project,
        profile,
        pack,
        artifacts,
        &deployment,
        false,
        |declared| {
            let id = declared.id.as_str();
            if matches!(
                declared.component,
                ComponentKind::File
                    | ComponentKind::Postgres
                    | ComponentKind::RabbitMq
                    | ComponentKind::Sftp
            ) {
                // A job source endpoint compiles below, from the job's
                // own source state; the facade endpoint compile has no
                // binding for it and needs none.
                return Ok(EndpointCompilation::Absent);
            }
            let Some(binding) = runtime.endpoints.get(id) else {
                return Ok(EndpointCompilation::Absent);
            };
            let plan = crate::auth::AuthPlan::compile(&declared.authentication, binding).map_err(
                |fault| {
                    LoadError::Runtime(format!("endpoint {id} authentication was refused: {fault}"))
                },
            )?;
            if !is_served_auth(plan.kind()) {
                return Ok(EndpointCompilation::Unserved {
                    reason: crate::load::UnservedReason::SourceAuthenticationUnsupported,
                    detail: "its authentication is not served by this runtime".to_owned(),
                });
            }
            let egress =
                crate::egress::EndpointEgress::compile(binding, declared, runtime, &resolver)
                    .map_err(|fault| {
                        LoadError::Runtime(format!(
                            "endpoint {id} outbound state was refused: {fault}"
                        ))
                    })?;
            preflight_endpoint_credential(id, egress.plan(), &resolver)?;
            Ok(EndpointCompilation::Served(Box::new(egress)))
        },
    )
    .map_err(|error| runtime_error(&format!("the job's workspace could not compile: {error}")))?;
    let endpoints = authored.endpoints;

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
    let reachable_sources = reachable_job_source_ids(&steps, &reached_bodies);
    let job_state = compile_job_sources(pack, artifacts, sources, &reachable_sources)?;
    let item_identity_digest =
        file_item_identity_digest(source.id.as_str(), &steps, &reached_bodies, &job_state);

    let mut scripts = authored.scripts;
    compile_source_scripts(pack, artifacts, &steps, &mut scripts).map_err(|error| {
        runtime_error(&format!("a source route script could not compile: {error}"))
    })?;
    compile_destination_script(job_artifacts, &job.destination, &mut scripts)?;
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
        source_route: source.clone(),
        steps,
        endpoints,
        scripts,
        code_maps: authored.code_maps,
        resilience,
        routes: authored.routes,
        resolver,
        job_state,
        item_identity_digest,
        warnings: Vec::new(),
    })
}

fn environment_secret_resolver() -> Result<Arc<SecretResolver>, JobError> {
    SecretResolver::new([SecretProvider::Environment], "")
        .map(Arc::new)
        .map_err(|error| secret_providers_refusal(&error))
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
        source: std::sync::Arc<dyn crate::component::postgres::PostgresSource>,
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

    /// Register the host's read-only client for one compiled SFTP source.
    #[cfg(feature = "job-sftp")]
    pub fn register_sftp_source(
        &mut self,
        endpoint: &str,
        source: std::sync::Arc<dyn crate::component::sftp::SftpSource>,
    ) -> Result<(), JobError> {
        if !self.job_state.sftp.contains_key(endpoint) {
            return Err(source_unbound(
                &format!("/endpoints/{endpoint}"),
                "the host registers a client for an SFTP endpoint the job does not declare",
            ));
        }
        self.job_state
            .sftp_clients
            .insert(endpoint.to_owned(), source);
        Ok(())
    }

    /// Register the host's manual-settlement RabbitMQ source.
    #[cfg(feature = "job-rabbitmq")]
    pub fn register_rabbitmq_source(
        &mut self,
        endpoint: &str,
        source: std::sync::Arc<dyn crate::component::rabbitmq::RabbitMqSource>,
    ) -> Result<(), JobError> {
        if !self.job_state.rabbitmq.contains_key(endpoint) {
            return Err(source_unbound(
                &format!("/endpoints/{endpoint}"),
                "the host registers a client for a RabbitMQ endpoint the job does not declare",
            ));
        }
        self.job_state
            .rabbitmq_clients
            .insert(endpoint.to_owned(), source);
        Ok(())
    }
}

fn runtime_error(reason: &str) -> JobError {
    runtime_refusal("", reason, "Read the refusal and fix the runtime state.")
}

/// A runtime refusal located at the runtime config member to correct
/// (`path`, an RFC 6901 pointer) with the fix for it.
fn runtime_refusal(path: &str, reason: &str, fix: &str) -> JobError {
    job_error(vec![job_finding(
        "platform.runtime-config.refused",
        ADAPTER_JOB_RUNTIME_KIND,
        path,
        &format!("the job's runtime state was refused: {reason}"),
        fix,
    )])
}

/// The refusal for a secret resolver that could not start. The cause is
/// the resolver's own value-free sentence.
fn secret_providers_refusal(error: &registry_platform_config::SecretError) -> JobError {
    runtime_refusal(
        "/secretProviders",
        &format!("the secret resolver could not start from the configured platform secret providers: {error}"),
        "Declare at least one provider under secretProviders; secretProviders.file.root must be an absolute directory, and secretProviders.environment takes no members.",
    )
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

/// Read one job artifact, refusing with the reader's own located
/// findings: the code, pointer, and position of each problem, under the
/// artifact kind the finding points into. The document's warnings join
/// `warnings` under the same kind.
fn read_job_artifact<T: serde::de::DeserializeOwned>(
    path: &Path,
    kind: &'static str,
    api_version: &'static str,
    warnings: &mut Vec<Diagnostic>,
) -> Result<(T, Vec<u8>), JobError> {
    let (value, bytes, found) =
        read_located(path, &format_spec(kind, api_version)).map_err(|refusal| match refusal {
            ReadRefusal::Unreadable(error) => artifact_error(error),
            ReadRefusal::Refused { diagnostics, .. } => job_error(located_in(diagnostics, kind)),
        })?;
    warnings.extend(located_in(found, kind));
    Ok((value, bytes))
}

/// Name the artifact kind on every finding that does not name one.
fn located_in(mut diagnostics: Vec<Diagnostic>, kind: &'static str) -> Vec<Diagnostic> {
    for diagnostic in &mut diagnostics {
        if diagnostic.artifact.is_none() {
            diagnostic.artifact = Some(kind.to_owned());
        }
    }
    diagnostics
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
/// `job-file` feature; the read-only `postgres` and `sftp` sends compile
/// the same way from their source blocks with their protocol features.
/// All three gates are off by default, so default builds compile none.
/// Cargo unifies features across one build, so a build that includes
/// `registry-adapterctl` (which turns the file and postgres gates on), a
/// workspace build among them, compiles those into every unit of this
/// crate it links, the facade binary included.
/// The coverage rule the endpoint-binding checks hand over holds here:
/// every source endpoint carries its source binding, and every source
/// binding names a declared endpoint of its kind, under
/// `adapter.job.source-unbound`.
fn compile_job_sources<S: ArtifactSource + ?Sized>(
    pack: &AdapterPack,
    artifacts: &S,
    sources: Option<&crate::job_sources::JobSources>,
    reachable: &std::collections::BTreeSet<String>,
) -> Result<crate::job_sources::JobPageState, JobError> {
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
    let declared_sftp: std::collections::BTreeSet<&str> = pack
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.component, ComponentKind::Sftp))
        .map(|endpoint| endpoint.id.as_str())
        .collect();
    if let Some(sources) = sources {
        for id in sources.sftp.keys() {
            if !declared_sftp.contains(id.as_str()) {
                return Err(source_unbound(
                    &format!("/sources/sftp/{id}"),
                    "the runtime config binds an SFTP source no pack endpoint declares",
                ));
            }
        }
    }
    let declared_postgres: std::collections::BTreeSet<&str> = pack
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.component, ComponentKind::Postgres))
        .map(|endpoint| endpoint.id.as_str())
        .collect();
    if let Some(sources) = sources {
        for id in sources.postgres.keys() {
            if !declared_postgres.contains(id.as_str()) {
                return Err(source_unbound(
                    &format!("/sources/postgres/{id}"),
                    "the runtime config binds a postgres source no pack endpoint declares",
                ));
            }
        }
    }
    let declared_rabbitmq: std::collections::BTreeSet<&str> = pack
        .endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint.component, ComponentKind::RabbitMq))
        .map(|endpoint| endpoint.id.as_str())
        .collect();
    if let Some(sources) = sources {
        for id in sources.rabbitmq.keys() {
            if !declared_rabbitmq.contains(id.as_str()) {
                return Err(source_unbound(
                    &format!("/sources/rabbitmq/{id}"),
                    "the runtime config binds a RabbitMQ source no pack endpoint declares",
                ));
            }
        }
    }
    #[cfg_attr(not(feature = "job-file"), allow(unused_mut))]
    let mut files = std::collections::BTreeMap::new();
    #[cfg(feature = "job-postgres")]
    let mut postgres: std::collections::BTreeMap<
        String,
        std::sync::Arc<crate::component::postgres::PostgresPlan>,
    > = std::collections::BTreeMap::new();
    #[cfg(feature = "job-postgres")]
    let postgres_clients = std::collections::BTreeMap::new();
    #[cfg(feature = "job-postgres")]
    let mut postgres_bindings = std::collections::BTreeMap::new();
    #[cfg(feature = "job-sftp")]
    let mut sftp = std::collections::BTreeMap::new();
    #[cfg(feature = "job-sftp")]
    let sftp_clients = std::collections::BTreeMap::new();
    #[cfg(feature = "job-sftp")]
    let mut sftp_bindings = std::collections::BTreeMap::new();
    #[cfg(feature = "job-rabbitmq")]
    let mut rabbitmq = std::collections::BTreeMap::new();
    #[cfg(feature = "job-rabbitmq")]
    let rabbitmq_clients = std::collections::BTreeMap::new();
    #[cfg(feature = "job-rabbitmq")]
    let mut rabbitmq_bindings = std::collections::BTreeMap::new();
    for id in reachable {
        let Some(declared) = pack
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id.as_str() == id)
        else {
            return Err(source_unbound(
                &format!("/endpoints/{id}"),
                "the selected source route names no declared source endpoint",
            ));
        };
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
                        runtime_refusal(
                            &format!("/sources/file/{id}"),
                            &format!("endpoint {id} source was refused: {reason}"),
                            "Set readLock to none or changed; readLockTimeoutMilliseconds and readLockCheckIntervalMilliseconds apply only with readLock: changed.",
                        )
                    })?;
                    config.completion_declared().map_err(|reason| {
                        runtime_refusal(
                            &format!("/sources/file/{id}"),
                            &format!("endpoint {id} source was refused: {reason}"),
                            "Declare how the source knows a file is complete: doneFileName for a done-file convention, readLock: changed for a file whose size and time must settle, or producerAtomicHandover: true when the producer renames each finished file into the directory.",
                        )
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
                    let bytes = artifacts
                        .read_bounded(
                            query_file,
                            crate::component::graphql::MAXIMUM_QUERY_FILE_BYTES,
                        )
                        .map_err(|failure| match failure {
                            ArtifactReadError::Unavailable => {
                                unavailable(declared, "the pinned query file could not be read")
                            }
                            ArtifactReadError::TooLarge => unavailable(
                                declared,
                                "the pinned query file is over the engine's bound",
                            ),
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
                    let attempt_timeout = declared
                        .attempt_timeout_milliseconds
                        .ok_or_else(|| {
                            unavailable(declared, "the postgres source declares no attempt timeout")
                        })?
                        .get();
                    let Some(key_column) = declared.key_column.as_ref() else {
                        return Err(job_error(vec![job_finding(
                            registry_adapter_core::JobCode::PostgresKeyRequired.code(),
                            ADAPTER_PACK_KIND,
                            &format!("/endpoints/{id}/keyColumn"),
                            "the postgres endpoint names no stable key column",
                            "Declare the scalar result column whose value remains stable across source-row edits.",
                        )]));
                    };
                    let parameter_order = declared
                        .parameter_order
                        .iter()
                        .flat_map(|parameters| parameters.iter())
                        .map(|name| name.as_str().to_owned())
                        .collect::<Vec<_>>();
                    let plan = crate::component::postgres::compile_plan(
                        config.namespace.clone(),
                        key_column.as_str().to_owned(),
                        parameter_order,
                        &text,
                        Duration::from_millis(attempt_timeout),
                    )
                    .map_err(|refused| match refused {
                        crate::component::postgres::QueryRefused::Parameters(message) => {
                            job_error(vec![job_finding(
                                registry_adapter_core::JobCode::PostgresParametersRequired.code(),
                                ADAPTER_PACK_KIND,
                                &format!("/endpoints/{id}/parameterOrder"),
                                message,
                                "Declare the ordered parameter names for every $1-onward position, or omit parameterOrder only when the query has none.",
                            )])
                        }
                        crate::component::postgres::QueryRefused::Query(message) => {
                            job_error(vec![job_finding(
                                "adapter.job.postgres-query-refused",
                                ADAPTER_PACK_KIND,
                                &format!("/endpoints/{id}/queryFile"),
                                message,
                                "Fix the digest-pinned query so it is one reviewed, ordered, read-only SELECT.",
                            )])
                        }
                    })?;
                    postgres.insert(id.to_owned(), std::sync::Arc::new(plan));
                    postgres_bindings.insert(id.to_owned(), config.host_binding(id));
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
                #[cfg(feature = "job-sftp")]
                {
                    let id = declared.id.as_str();
                    let Some(config) = sources.and_then(|sources| sources.sftp.get(id)) else {
                        return Err(source_unbound(
                            &format!("/endpoints/{id}"),
                            "the pack declares an SFTP source the runtime config does not bind",
                        ));
                    };
                    let binding = config.host_binding(id);
                    sftp.insert(id.to_owned(), std::sync::Arc::new(binding.plan.clone()));
                    sftp_bindings.insert(id.to_owned(), binding);
                }
                #[cfg(not(feature = "job-sftp"))]
                {
                    return Err(unavailable(
                        declared,
                        "serve the SFTP source by building with the job-sftp feature",
                    ));
                }
            }
            ComponentKind::SqliteExtract => {
                return Err(unavailable(
                    declared,
                    "the sqlite-extract source is served only by an Evidence acquisition",
                ));
            }
            ComponentKind::RabbitMq => {
                #[cfg(feature = "job-rabbitmq")]
                {
                    let id = declared.id.as_str();
                    let Some(config) = sources.and_then(|sources| sources.rabbitmq.get(id)) else {
                        return Err(source_unbound(
                            &format!("/endpoints/{id}"),
                            "the pack declares a RabbitMQ source the runtime config does not bind",
                        ));
                    };
                    let binding = config.host_binding(id);
                    rabbitmq.insert(
                        id.to_owned(),
                        std::sync::Arc::new(crate::component::rabbitmq::RabbitMqPlan {
                            namespace: binding.namespace.clone(),
                        }),
                    );
                    rabbitmq_bindings.insert(id.to_owned(), binding);
                }
                #[cfg(not(feature = "job-rabbitmq"))]
                {
                    return Err(unavailable(
                        declared,
                        "serve the RabbitMQ source by building with the job-rabbitmq feature",
                    ));
                }
            }
            ComponentKind::Direct
            | ComponentKind::GraphQl
            | ComponentKind::Http
            | ComponentKind::Rest => {}
        }
    }
    #[cfg(not(feature = "job-postgres"))]
    {
        let _ = artifacts;
    }
    Ok(crate::job_sources::JobPageState {
        profile: None,
        ongoing_scan: false,
        files,
        #[cfg(feature = "job-postgres")]
        postgres,
        #[cfg(feature = "job-postgres")]
        postgres_clients,
        #[cfg(feature = "job-postgres")]
        postgres_bindings,
        #[cfg(feature = "job-sftp")]
        sftp,
        #[cfg(feature = "job-sftp")]
        sftp_clients,
        #[cfg(feature = "job-sftp")]
        sftp_bindings,
        #[cfg(feature = "job-rabbitmq")]
        rabbitmq,
        #[cfg(feature = "job-rabbitmq")]
        rabbitmq_clients,
        #[cfg(feature = "job-rabbitmq")]
        rabbitmq_bindings,
        #[cfg(feature = "job-rabbitmq")]
        rabbitmq_receipt: Default::default(),
    })
}

/// The source coverage refusal: a source endpoint or a source binding
/// whose counterpart the artifacts name nothing for.
fn source_unbound(path: &str, message: &str) -> JobError {
    job_error(vec![job_finding(
        "adapter.job.source-unbound",
        ADAPTER_JOB_RUNTIME_KIND,
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

/// Source endpoints the selected source route can reach, including
/// nested steps and the direct-route bodies the checked graph resolved.
/// A declared source on another route remains inert: its credential is
/// parsed but never resolved or installed into the runnable program.
fn reachable_job_source_ids(
    steps: &[Step],
    reached_bodies: &[Arc<Vec<Step>>],
) -> std::collections::BTreeSet<String> {
    let mut reached = std::collections::BTreeSet::new();
    let mut absorb = |body: &[Step]| {
        registry_adapter_core::walk_steps(body, &mut |step, _pointer| {
            let mut admit = |uri: &registry_adapter_core::SendUri| {
                if matches!(
                    uri.component,
                    registry_adapter_core::SendComponent::File
                        | registry_adapter_core::SendComponent::RabbitMq
                        | registry_adapter_core::SendComponent::Sftp
                        | registry_adapter_core::SendComponent::Postgres
                ) {
                    reached.insert(uri.id.clone());
                }
            };
            match step {
                Step::To(send) => admit(&send.uri),
                Step::Enrich(enrich) => admit(&enrich.uri),
                Step::PollEnrich(poll) => {
                    if let Some(uri) = registry_adapter_core::SendUri::parse(&poll.uri) {
                        admit(&uri);
                    }
                }
                _ => {}
            }
        });
    };
    absorb(steps);
    for body in reached_bodies {
        absorb(body);
    }
    reached
}

/// One file-like poll's conservative source identity. Sorting these
/// descriptors makes the digest insensitive to route traversal order while
/// retaining duplicate polls, key semantics, and provider rebinding.
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct FileItemIdentity {
    component: &'static str,
    endpoint: String,
    namespace: String,
    decoder: Vec<u8>,
    key_pointer: Option<String>,
}

fn file_item_identity_digest(
    source_route: &str,
    steps: &[Step],
    reached_bodies: &[Arc<Vec<Step>>],
    state: &crate::job_sources::JobPageState,
) -> Option<[u8; 32]> {
    let mut identities = Vec::new();
    let mut absorb = |body: &[Step]| {
        registry_adapter_core::walk_steps(body, &mut |step, _pointer| {
            let Step::PollEnrich(poll) = step else {
                return;
            };
            let Some(uri) = registry_adapter_core::SendUri::parse(&poll.uri) else {
                return;
            };
            let (component, namespace) = match uri.component {
                registry_adapter_core::SendComponent::File => {
                    let Some(config) = state.files.get(uri.id.as_str()) else {
                        return;
                    };
                    ("file", config.namespace.clone())
                }
                registry_adapter_core::SendComponent::Sftp => {
                    #[cfg(feature = "job-sftp")]
                    {
                        let Some(plan) = state.sftp.get(uri.id.as_str()) else {
                            return;
                        };
                        ("sftp", plan.namespace.clone())
                    }
                    #[cfg(not(feature = "job-sftp"))]
                    {
                        return;
                    }
                }
                _ => return,
            };
            identities.push(FileItemIdentity {
                component,
                endpoint: uri.id,
                namespace,
                decoder: normalized_file_decoder(poll.decoder.as_ref()),
                key_pointer: poll.key_pointer.clone(),
            });
        });
    };
    absorb(steps);
    for body in reached_bodies {
        absorb(body);
    }
    if identities.is_empty() {
        return None;
    }
    identities.sort();

    let mut digest = Sha256::new();
    digest_frame(&mut digest, b"adapter-file-item-identity-v1");
    digest_frame(&mut digest, FILE_ROW_IDENTITY_VERSION.as_bytes());
    digest_frame(&mut digest, source_route.as_bytes());
    digest_frame(&mut digest, &(identities.len() as u64).to_be_bytes());
    for identity in identities {
        digest_frame(&mut digest, identity.component.as_bytes());
        digest_frame(&mut digest, identity.endpoint.as_bytes());
        digest_frame(&mut digest, identity.namespace.as_bytes());
        digest_frame(&mut digest, &identity.decoder);
        match identity.key_pointer {
            Some(pointer) => {
                digest_frame(&mut digest, b"present");
                digest_frame(&mut digest, pointer.as_bytes());
            }
            None => digest_frame(&mut digest, b"absent"),
        }
    }
    Some(digest.finalize().into())
}

/// Normalize the two equivalent CSV authoring forms to the same decoder
/// bytes, while retaining every CSV option that can change row parsing.
fn normalized_file_decoder(decoder: Option<&registry_adapter_core::PollDecoder>) -> Vec<u8> {
    match decoder {
        None => b"raw".to_vec(),
        Some(registry_adapter_core::PollDecoder::Csv(options)) => {
            let mut bytes = b"csv:".to_vec();
            bytes.extend(
                serde_json::to_vec(options)
                    .expect("the closed CSV decoder always serializes to JSON"),
            );
            bytes
        }
        Some(registry_adapter_core::PollDecoder::Named(name)) if name == "csv" => {
            normalized_file_decoder(Some(&registry_adapter_core::PollDecoder::Csv(
                registry_adapter_core::CsvDecoder::default(),
            )))
        }
        Some(registry_adapter_core::PollDecoder::Named(name)) => name.as_bytes().to_vec(),
    }
}

fn digest_frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

/// Compile the Rhai scripts and aggregation strategies a source route's
/// steps name, the way the loader compiles a bound route's.
fn compile_source_scripts<S: ArtifactSource + ?Sized>(
    pack: &AdapterPack,
    artifacts: &S,
    steps: &[Step],
    scripts: &mut ScriptSet,
) -> Result<(), String> {
    crate::load::compile_step_schemas(artifacts, steps, scripts)
        .map_err(|error| error.to_string())?;
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
            .add_from(pack, artifacts, &file, &entrypoint)
            .map_err(|error| error.to_string())?;
    }
    for (file, entrypoint) in strategy_uses {
        scripts
            .add_aggregation_from(pack, artifacts, &file, &entrypoint)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Add the one destination-owned entrypoint to the compiled script closure.
/// Signed events have no mapping program; direct BReg never loads one lazily
/// at hand-off time.
/// Compile the job-owned destination mapping. A stale digest pin is refused
/// at the pin, with the command that repins it.
fn compile_destination_script<S: ArtifactSource + ?Sized>(
    artifacts: &S,
    destination: &JobDestination,
    scripts: &mut ScriptSet,
) -> Result<(), JobError> {
    let compile_error = |reason: &str| {
        runtime_error(&format!(
            "the destination mapping could not compile: {reason}"
        ))
    };
    if let JobDestination::DirectBreg { mapping, .. } = destination {
        if !clean_job_artifact_path(&mapping.file) {
            return Err(compile_error(
                "the mapping path is not a clean job-relative artifact path",
            ));
        }
        match scripts.add_job_mapping_from(artifacts, mapping) {
            Ok(()) => {}
            Err(ScriptLoadError::DigestMismatch {
                path,
                pinned,
                actual,
            }) => {
                return Err(job_error(vec![job_finding(
                    registry_adapter_core::CheckCode::ProjectPinDigestMismatch.code(),
                    ADAPTER_JOB_KIND,
                    "/destination/mapping/digest",
                    &format!(
                        "the pinned mapping digest {pinned} does not match {path}, which hashes to {actual}"
                    ),
                    "Run adapterctl job lock on the job after reviewing the script change.",
                )]))
            }
            Err(error) => return Err(compile_error(&error.to_string())),
        }
    }
    Ok(())
}

fn clean_job_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
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
        return Err(runtime_refusal(
            &format!("/endpoints/{id}"),
            &format!(
                "endpoint {id} is not bound by the runtime config, and a source route sends through it"
            ),
            "Bind the endpoint under endpoints in the runtime config, or remove the send that reaches it.",
        ));
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
    #[cfg(feature = "job-rabbitmq")]
    let rabbitmq_receipt = std::sync::Arc::new(std::sync::Mutex::new(None));
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
        maximum_upstream_calls: profile.maximum_upstream_calls.get(),
        job: crate::job_sources::JobPageState {
            profile: Some(profile.clone()),
            ongoing_scan: program.source_route.scan
                == Some(registry_adapter_core::SourceScan::Ongoing),
            files: program.job_state.files.clone(),
            #[cfg(feature = "job-postgres")]
            postgres: program.job_state.postgres.clone(),
            #[cfg(feature = "job-postgres")]
            postgres_clients: program.job_state.postgres_clients.clone(),
            #[cfg(feature = "job-postgres")]
            postgres_bindings: program.job_state.postgres_bindings.clone(),
            #[cfg(feature = "job-sftp")]
            sftp: program.job_state.sftp.clone(),
            #[cfg(feature = "job-sftp")]
            sftp_clients: program.job_state.sftp_clients.clone(),
            #[cfg(feature = "job-sftp")]
            sftp_bindings: program.job_state.sftp_bindings.clone(),
            #[cfg(feature = "job-rabbitmq")]
            rabbitmq: program.job_state.rabbitmq.clone(),
            #[cfg(feature = "job-rabbitmq")]
            rabbitmq_clients: program.job_state.rabbitmq_clients.clone(),
            #[cfg(feature = "job-rabbitmq")]
            rabbitmq_bindings: program.job_state.rabbitmq_bindings.clone(),
            #[cfg(feature = "job-rabbitmq")]
            rabbitmq_receipt: std::sync::Arc::clone(&rabbitmq_receipt),
        },
    };
    // The exchange bound follows the profile: the page and every
    // intermediate body of the run share the response bound, which a
    // source-route-only endpoint may declare up to the platform cap.
    let maximum_exchange_bytes =
        usize::try_from(profile.maximum_response_bytes.get()).unwrap_or(usize::MAX);
    let deadline = Duration::from_millis(profile.page_deadline_milliseconds.get());
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
                    record: failure.record.map(|record| *record),
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
    #[cfg(feature = "job-rabbitmq")]
    let source_receipt = {
        let receipt = rabbitmq_receipt
            .lock()
            .map_err(|_| JobPageFailure::of_code("adapter.job.rabbitmq-page-shape"))?
            .take();
        if let Some(receipt) = &receipt {
            let matches_identity = matches!(
                page.items.as_slice(),
                [item]
                    if item.key == receipt.expected_key()
                        && item.revision.as_deref() == Some(receipt.expected_revision())
            );
            let no_cursor = page.next.as_ref().is_none_or(Value::is_null);
            if !matches_identity || !no_cursor {
                return Err(JobPageFailure::of_code("adapter.job.rabbitmq-page-shape"));
            }
        }
        receipt
    };
    Ok(JobPageResult {
        page,
        malformed_lines,
        #[cfg(feature = "job-rabbitmq")]
        source_receipt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_adapter_core::{DestinationMapping, JobDestination};
    use registry_platform_config::sha256_uri;
    use serde_json::json;

    /// A runtime refusal names the runtime member and the fix, and the
    /// secret-provider start failure keeps the value-free cause.
    #[test]
    fn runtime_refusals_name_the_runtime_member_and_the_fix() {
        let refused = runtime_refusal(
            "/sources/file/dropbox",
            "endpoint dropbox source was refused: the lock is wrong",
            "Remove the member.",
        );
        let finding = &refused.diagnostics[0];
        assert_eq!(finding.path, "/sources/file/dropbox");
        assert_eq!(finding.suggested_action, "Remove the member.");

        let refused = secret_providers_refusal(
            &registry_platform_config::SecretError::InvalidProviderConfiguration,
        );
        let finding = &refused.diagnostics[0];
        assert_eq!(finding.path, "/secretProviders");
        assert!(
            finding
                .message
                .contains("the secret provider configuration is invalid"),
            "{finding:?}"
        );
        assert!(
            finding
                .suggested_action
                .contains("secretProviders.file.root"),
            "{finding:?}"
        );
    }

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

    #[test]
    fn file_item_identity_tracks_key_semantics_and_source_rebinding() {
        let source: crate::job_sources::FileSourceConfig = serde_json::from_value(json!({
            "directory": "/tmp",
            "namespace": "people"
        }))
        .expect("the file source parses");
        let state = crate::job_sources::JobPageState {
            files: BTreeMap::from([("source".to_owned(), source)]),
            ..Default::default()
        };
        let step = |uri: &str, timeout: u64, decoder: Value, key_pointer: Option<&str>| {
            let mut poll = serde_json::Map::from_iter([
                ("uri".to_owned(), json!(uri)),
                ("timeoutMilliseconds".to_owned(), json!(timeout)),
                ("decoder".to_owned(), decoder),
            ]);
            if let Some(pointer) = key_pointer {
                poll.insert("keyPointer".to_owned(), json!(pointer));
            }
            serde_json::from_value::<Step>(json!({"pollEnrich": poll}))
                .expect("the poll step parses")
        };

        let raw = file_item_identity_digest(
            "source-route",
            &[step("file:source", 1_000, json!("raw"), None)],
            &[],
            &state,
        )
        .expect("a file poll has an identity digest");
        let csv = file_item_identity_digest(
            "source-route",
            &[step("file:source", 1_000, json!("csv"), Some("/id"))],
            &[],
            &state,
        )
        .expect("a CSV poll has an identity digest");
        let csv_other_timeout = file_item_identity_digest(
            "source-route",
            &[step("file:source", 9_000, json!({}), Some("/id"))],
            &[],
            &state,
        )
        .expect("the equivalent CSV poll has an identity digest");
        let csv_other_pointer = file_item_identity_digest(
            "source-route",
            &[step("file:source", 1_000, json!("csv"), Some("/caseId"))],
            &[],
            &state,
        )
        .expect("the other selector has an identity digest");

        assert_ne!(raw, csv, "raw-to-row transitions must be fenced");
        assert_eq!(
            csv, csv_other_timeout,
            "timeouts and equivalent CSV authoring forms do not reinterpret keys"
        );
        assert_ne!(csv, csv_other_pointer, "the selector interprets row keys");
        assert_ne!(
            csv,
            file_item_identity_digest(
                "renamed-route",
                &[step("file:source", 1_000, json!("csv"), Some("/id"))],
                &[],
                &state,
            )
            .expect("the renamed route has an identity digest"),
            "route rebinding is a deliberate conservative fence"
        );
        #[cfg(feature = "job-sftp")]
        {
            let mut sftp_state = state.clone();
            sftp_state.sftp.insert(
                "source".to_owned(),
                Arc::new(crate::component::sftp::SftpPlan {
                    namespace: "people".to_owned(),
                    include: None,
                    completion: crate::component::sftp::SftpCompletion::CompletedName,
                    maximum_listing_entries: 10,
                }),
            );
            let sftp = file_item_identity_digest(
                "source-route",
                &[step("sftp:source", 1_000, json!("csv"), Some("/id"))],
                &[],
                &sftp_state,
            )
            .expect("the SFTP poll has an identity digest");
            assert_ne!(csv, sftp, "provider rebinding is fenced");

            sftp_state.sftp.insert(
                "source".to_owned(),
                Arc::new(crate::component::sftp::SftpPlan {
                    namespace: "other-people".to_owned(),
                    include: None,
                    completion: crate::component::sftp::SftpCompletion::CompletedName,
                    maximum_listing_entries: 10,
                }),
            );
            let other_namespace = file_item_identity_digest(
                "source-route",
                &[step("sftp:source", 1_000, json!("csv"), Some("/id"))],
                &[],
                &sftp_state,
            )
            .expect("the other SFTP namespace has an identity digest");
            assert_ne!(sftp, other_namespace, "the namespace interprets row keys");
        }
        assert_eq!(
            file_item_identity_digest("source-route", &[], &[], &state),
            None,
            "a job with no file-like poll needs no store migration state"
        );
    }

    #[cfg(unix)]
    #[test]
    fn job_artifact_reader_refuses_a_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("the job artifact directory");
        let external = tempfile::tempdir().expect("an external directory");
        std::fs::write(external.path().join("mapping.rhai"), b"outside")
            .expect("the external mapping");
        symlink(external.path(), root.path().join("mappings"))
            .expect("the escaping directory symlink");

        let artifacts = JobArtifactDirectory(root.path());
        assert!(matches!(
            artifacts.read_bounded("mappings/mapping.rhai", 1024),
            Err(ArtifactReadError::Unavailable)
        ));
    }

    /// A direct-BReg mapping belongs to the compiled job closure even when
    /// no route step names it. The public host seam runs only that already
    /// compiled entrypoint over the declared projection.
    #[test]
    fn direct_breg_destination_mapping_is_job_owned_pinned_and_callable() {
        let source = br#"fn map_destination(exchange) {
    #{ "action": "register-household", "input": exchange }
}"#;
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "destination-mapping",
            "version": "1",
            "testedVersions": ["1"],
            "sourceRoutes": [{
                "id": "source",
                "scan": "ongoing",
                "nextRecovery": "key-deduplicated",
                "edits": "ordered",
                "steps": [],
            }],
        }))
        .expect("the pack parses");
        let mapping: DestinationMapping = serde_json::from_value(json!({
            "file": "mappings/destination.rhai",
            "entrypoint": "map_destination",
            "digest": sha256_uri(source),
        }))
        .expect("the mapping parses");
        let destination = JobDestination::DirectBreg {
            binding: registry_platform_yaml::LocalId::new("household-registry")
                .expect("binding id"),
            access_profile: "caseworker".to_owned(),
            action: "register-household".to_owned(),
            mode: registry_adapter_core::DirectBregMode::Immediate,
            mapping: mapping.clone(),
            receipt_retention_days: 30,
        };
        let absent = PackArtifactBytes::default();
        let mut scripts = ScriptSet::default();
        assert!(
            compile_destination_script(&absent, &destination, &mut scripts).is_err(),
            "the destination mapping bytes are required independently of the pack"
        );

        let tampered = PackArtifactBytes::new([(
            "mappings/destination.rhai".to_owned(),
            b"fn map_destination(exchange) { exchange }".to_vec(),
        )]);
        assert!(
            compile_destination_script(&tampered, &destination, &mut scripts).is_err(),
            "mapping bytes that miss the job pin are refused"
        );

        let traversal_mapping: DestinationMapping = serde_json::from_value(json!({
            "file": "../destination.rhai",
            "entrypoint": "map_destination",
            "digest": sha256_uri(source),
        }))
        .expect("the traversal shape parses before the compile boundary");
        let traversal = JobDestination::DirectBreg {
            binding: registry_platform_yaml::LocalId::new("household-registry")
                .expect("binding id"),
            access_profile: "caseworker".to_owned(),
            action: "register-household".to_owned(),
            mode: registry_adapter_core::DirectBregMode::Immediate,
            mapping: traversal_mapping,
            receipt_retention_days: 30,
        };
        assert!(
            compile_destination_script(&absent, &traversal, &mut scripts).is_err(),
            "a parent path is refused before artifact access"
        );

        let artifacts =
            PackArtifactBytes::new([("mappings/destination.rhai".to_owned(), source.to_vec())]);
        compile_destination_script(&artifacts, &destination, &mut scripts)
            .expect("the exact pinned mapping compiles");
        let job: AdapterJob = serde_json::from_value(json!({
            "apiVersion": ADAPTER_JOB_API_VERSION,
            "kind": ADAPTER_JOB_KIND,
            "job": {"id": "household-import", "version": "1"},
            "source": {
                "pack": {
                    "id": "destination-mapping",
                    "version": "1",
                    "digest": "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9"
                },
                "route": "source"
            },
            "destination": destination,
            "projection": {"fields": ["household.id"]},
            "triggers": [{"kind": "interval"}],
            "profile": {
                "pageDeadlineMilliseconds": 30000,
                "maximumResponseBytes": 1048576,
                "maximumPageItems": 100,
                "maximumPageBytes": 1048576,
                "maximumUpstreamCalls": 1,
                "read": {
                    "maximumFileBytes": 1048576,
                    "maximumRowBytes": 65536,
                    "maximumFieldBytes": 8192,
                    "maximumRowsPerPage": 100
                }
            }
        }))
        .expect("the job parses");
        let program = JobProgram {
            job,
            source_route: pack.source_routes[0].clone(),
            steps: Arc::new(Vec::new()),
            endpoints: BTreeMap::new(),
            scripts,
            code_maps: Arc::new(BTreeMap::new()),
            resilience: ResilienceRuntime::empty(),
            routes: BTreeMap::new(),
            resolver: Arc::new(
                SecretResolver::new([SecretProvider::Environment], "")
                    .expect("the resolver starts"),
            ),
            job_state: crate::job_sources::JobPageState::default(),
            item_identity_digest: None,
            warnings: Vec::new(),
        };
        let projection = json!({"household": {"id": "HH-1"}});

        assert_eq!(
            program
                .map_destination(&mapping, &projection)
                .expect("the compiled mapping runs"),
            json!({
                "action": "register-household",
                "input": {"household": {"id": "HH-1"}}
            })
        );
    }
}
