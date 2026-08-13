//! Evidence Version 1 operator CLI and serving process.

use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::File,
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
};

use chrono::{DateTime, NaiveDate, SecondsFormat, TimeZone, Utc};
use chrono_tz::Tz;
use clap::Parser;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use registry_evidence::cli::{Cli, Command, ExplainFormat};
use registry_evidence::{
    audit::{
        verified_last_local_audit_operation, verify_audit_chain, AuditChainSummary,
        EvidenceAuditError,
    },
    bundle::{
        ArtifactFault, Bundle, BundleError, DeploymentInputs, RuntimeDocument, SourceExtract,
    },
    config::{
        AcquisitionConfig, ArtifactPath, AssuranceProfile, ConfigError, EvidenceConfig,
        OutboundTlsConfig, SchemaFault, SelectorInput, StageRole,
    },
    kernel::{
        EvidenceConstruction, EvidenceScope, KernelError, KernelOutcome, OfflineKernel,
        ValidatedValues, ValueProjection,
    },
    local_verification::{prepare_local_relying_procedure, LocalRelyingProcedureInput},
    model::{
        JwksDocument, LookupResult, PublicValue, ScalarOrEntityReference, SelectorValue,
        SubjectBinding,
    },
    problem::ProblemCode,
    rhai_runtime::{DerivedConceptValue, DerivedValue},
    runtime::{
        source_failure_problem, validate_secret_material, AuditInitializationFault,
        EvidenceRuntime, RuntimeInitializationError,
    },
    secrets::{SecretProvider, SecretResolver},
    selector::{
        resolve_offline_fixture_authorization, resolve_offline_fixture_subjects,
        OfflineFixtureError, ResolvedAuthorization, ResolvedSelectorValue,
    },
    server,
    signing::{jwks_document, EvidenceSigner},
    source::{
        project_fixture_response, statement_inputs, MaterializedSourceRequest,
        PreparedSourceRequest, ResolvedSourceSelector, SourceError, SourceExecutor, SourceStatus,
        StatementExtract, StatementInputs,
    },
    source_sqlite::{cause as sqlite_cause, check_statement_offline, materialize_seed_extract},
    trace::{json_type, name_list, object_keys, FixtureReport, FixtureTrace, Stage, StageStatus},
    verifier::{
        verify_flattened_jws, verify_flattened_jws_report, verify_sd_jwt_vc_presentation_report,
        verify_sd_jwt_vc_report, EvidenceVerificationPolicy, EvidenceVerificationPolicyDocument,
        HolderBoundPresentationPolicyDocument, VerificationError,
    },
};
use registry_platform_audit::{
    AuditChainHasher, AuditChainProfile, AuditHashSecret, OptionalHashHex,
};
use registry_platform_crypto::{canonicalize_json, parse_json_strict, LocalJwkSigner, PrivateJwk};
use serde_json::{Map as JsonMap, Value};
use zeroize::Zeroizing;

const OFFLINE_AUDIENCE: &str = "urn:registry-evidence:offline-evaluation";
const OFFLINE_BINDING_KEY: [u8; 32] = [0x45; 32];
const ANTI_RECONSTRUCTION_FIXTURE: &[u8] =
    include_bytes!("../../../products/evidence/fixtures/conformance/anti-reconstruction.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError(&'static str);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CliError {}

/// A command failure: a fixed operator message, or one artifact diagnostic.
///
/// The diagnostic names a bundle-relative artifact, a schema path, and a text
/// location so an operator can find the defect. It carries no document value,
/// which is what keeps a failed `check` safe to paste into a ticket.
///
/// A service failure carries an owned message instead, because the operating
/// system decides both the address and the reason and neither is known when
/// this enum is written. Those two are the whole diagnosis of a failed start,
/// so a fixed string here would cost an operator the port and the cause.
#[derive(Debug, PartialEq, Eq)]
enum CommandError {
    Cli(CliError),
    Deployment(&'static str, ArtifactFault),
    /// One or more governed extract sources cannot answer at check time.
    ///
    /// Source identifiers come from the reviewed bundle. Publisher metadata
    /// and filesystem paths stay out of the diagnostic.
    StaleExtracts(Vec<String>),
    /// The audit boundary refused, with the value-free cause it reported.
    ///
    /// It is the one startup boundary that separates its causes, because a
    /// permission bit, a chain that no longer verifies, and a second writer
    /// holding the sink lock have nothing in common but the moment they fail.
    Audit(&'static str, AuditInitializationFault),
    Service(String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => fmt::Display::fmt(error, formatter),
            Self::Deployment(message, fault) => write!(formatter, "{message}: {fault}"),
            Self::StaleExtracts(sources) => write!(
                formatter,
                "bound extract is stale for source{} {}",
                if sources.len() == 1 { "" } else { "s" },
                sources.join(", ")
            ),
            Self::Audit(message, fault) => write!(formatter, "{message}: {fault}"),
            Self::Service(reason) => write!(formatter, "service failed: {reason}"),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<CliError> for CommandError {
    fn from(error: CliError) -> Self {
        Self::Cli(error)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct FixtureSummary {
    evaluated_cases: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("evidence: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CommandError> {
    match cli.command {
        Command::Check {
            require_runtime_dependencies,
        } => {
            let deployment = DeploymentInputs::load(&cli.runtime).map_err(deployment_load_error)?;
            let runtime = deployment.runtime;
            let bundle = Arc::new(deployment.bundle);
            OfflineKernel::compile(Arc::clone(&bundle))
                .map_err(|error| kernel_compile_error("bundle compilation failed", error))?;
            let source_plans = compile_source_plans(&bundle, &runtime)?;
            let stale_sources = source_plans
                .iter()
                .filter(|(_, source)| source.extract_is_stale(Utc::now()))
                .map(|(source_id, _)| source_id.clone())
                .collect::<Vec<_>>();
            if !stale_sources.is_empty() {
                return Err(CommandError::StaleExtracts(stale_sources));
            }
            // Deployment secret material is validated exactly as startup
            // validates it, without opening the audit chain, so a deployment
            // the server would refuse fails check instead of first start.
            // Source credentials stay unresolved: readiness owns them.
            let secrets = SecretResolver::new(
                [SecretProvider::File],
                &runtime.config.secret_providers.file.root,
            )
            .map_err(|_| runtime_initialization_error(RuntimeInitializationError::Secrets))?;
            validate_secret_material(&bundle, &runtime.config, &secrets)
                .await
                .map_err(runtime_initialization_error)?;
            if require_runtime_dependencies {
                let serving = EvidenceRuntime::initialize(&cli.runtime)
                    .await
                    .map_err(runtime_initialization_error)?;
                if !serving.key_source_ready().await || !serving.ready().await {
                    return Err(CliError("a required runtime dependency is unavailable").into());
                }
            }
            println!(
                "Evidence deployment {} / {} passed check ({} requirements)",
                bundle.revision(),
                runtime.revision(),
                bundle.config.requirements.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Evaluate {
            fixture,
            case,
            explain,
            explain_format,
        } => {
            let deployment = DeploymentInputs::load(&cli.runtime).map_err(deployment_load_error)?;
            let runtime = deployment.runtime;
            let bundle = Arc::new(deployment.bundle);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).map_err(|error| {
                kernel_compile_error("fixture bundle compilation failed", error)
            })?;
            let source_plans = compile_source_plans(&bundle, &runtime)?;
            let mut trace = FixtureTrace::default();
            let summary = evaluate_fixture(
                &bundle,
                &kernel,
                &source_plans,
                &fixture,
                case.as_deref(),
                true,
                &mut trace,
            )
            .await;
            // Checked here rather than at the end of the evaluation, and before
            // the render below. A run that stopped on an error never reaches
            // that end, and it is the run whose trace gets read; a trace found
            // prohibited and printed anyway would disclose the value its own
            // fixture named.
            validate_trace_canaries(&trace)?;
            // The trace is printed before the failure is returned. The failure
            // is a fixed message that says a case failed but never which one or
            // why; `CliError` carries no dynamic payload and does not gain one
            // here. Attributing that message to the case that was still running
            // is what joins the two without changing either.
            if explain {
                if let Err(error) = &summary {
                    trace.fail(error.0);
                }
                match explain_format.unwrap_or_default() {
                    ExplainFormat::Text => print!("{}", trace.render()),
                    // The JSON document is the whole of standard output, so the
                    // summary line below is not printed in this form and the
                    // count it carries moves inside the document. A reader pipes
                    // the output without stripping a trailing human line. The
                    // exit code and the operator message on standard error are
                    // the same in both forms.
                    ExplainFormat::Json => {
                        println!("{}", fixture_report_json(&trace, summary.as_ref())?);
                        summary?;
                        return Ok(ExitCode::SUCCESS);
                    }
                }
            }
            println!(
                "Evidence fixture passed ({} evaluated cases)",
                summary?.evaluated_cases
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::BundleCheck { bundle } => {
            let bundle = Arc::new(Bundle::load(&bundle).map_err(deployment_load_error)?);
            OfflineKernel::compile(Arc::clone(&bundle))
                .map_err(|error| kernel_compile_error("bundle compilation failed", error))?;
            let _source_plans = compile_bundle_source_plans(&bundle)?;
            println!(
                "Evidence bundle {} passed check ({} requirements)",
                bundle.revision(),
                bundle.config.requirements.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::BundleEvaluate {
            bundle,
            fixture,
            case,
            explain,
        } => {
            let bundle = Arc::new(Bundle::load(&bundle).map_err(deployment_load_error)?);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).map_err(|error| {
                kernel_compile_error("fixture bundle compilation failed", error)
            })?;
            let source_plans = compile_bundle_source_plans(&bundle)?;
            // This hidden seam is driven by Evidencectl. It uses the same trace
            // type and privacy-canary gate as deployment evaluation so an
            // editable project can be diagnosed before it has a runtime file.
            let mut trace = FixtureTrace::default();
            let summary = evaluate_fixture(
                &bundle,
                &kernel,
                &source_plans,
                &fixture,
                case.as_deref(),
                false,
                &mut trace,
            )
            .await;
            validate_trace_canaries(&trace)?;
            if explain {
                if let Err(error) = &summary {
                    trace.fail(error.0);
                }
                print!("{}", trace.render());
            }
            let summary = summary?;
            println!(
                "Evidence fixture passed ({} evaluated cases)",
                summary.evaluated_cases
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::RenderDiscoveryDescription { config } => {
            let bytes = fs::read(config)
                .map_err(|_| CliError("Evidence discovery description rendering failed"))?;
            let config = EvidenceConfig::parse_yaml(&bytes)
                .map_err(|_| CliError("Evidence discovery description rendering failed"))?;
            if let Some(rendered) = registry_evidence::discovery::render(&config)
                .map_err(|_| CliError("Evidence discovery description rendering failed"))?
            {
                std::io::stdout()
                    .write_all(&rendered)
                    .map_err(|_| CliError("Evidence discovery description rendering failed"))?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve => {
            install_operational_logging();
            let runtime = Arc::new(
                EvidenceRuntime::initialize(&cli.runtime)
                    .await
                    .map_err(runtime_initialization_error)?,
            );
            // The startup announcement belongs to the server, which makes it
            // after both listeners are held. Nothing is reported here, because
            // a start reported before the bind describes a service that may
            // never have got its port.
            server::serve(runtime, shutdown_signal())
                .await
                .map_err(|error| CommandError::Service(error.to_string()))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify {
            jws,
            sd_jwt_vc,
            jwks,
            policy,
            at,
        } => {
            let stored = jws
                .map(StoredResponse::SignedJws)
                .or_else(|| sd_jwt_vc.map(StoredResponse::SdJwtVc))
                .ok_or(CommandError::Cli(CliError(
                    "verify requires one stored response file",
                )))?;
            Ok(verify_stored_response(
                &stored,
                &jwks,
                &policy,
                at.as_deref(),
            )?)
        }
        Command::VerifyPresentation {
            sd_jwt_vc_presentation,
            jwks,
            policy,
            at,
        } => Ok(verify_stored_presentation(
            &sd_jwt_vc_presentation,
            &jwks,
            &policy,
            at.as_deref(),
        )?),
        Command::VerifyAudit => run_verify_audit(&cli.runtime),
        Command::PrepareLocalRelyingProcedure { input } => {
            prepare_local_relying_procedure_command(&cli.runtime, &input).await
        }
        Command::LocalAuditLastOperation => local_audit_last_operation_command(&cli.runtime),
    }
}

/// Report a startup failure with the artifact diagnostic it carries.
///
/// The failure class stays a fixed operator message. When the loader knew
/// which artifact failed, the value-free diagnostic is appended so that
/// `evidence check` names a file, a schema path, and a text location instead
/// of only a class. Public HTTP problems are unaffected and stay generic.
fn deployment_load_error(error: BundleError) -> CommandError {
    let message = match &error {
        BundleError::Unavailable => "deployment input is unavailable",
        BundleError::NotImmutable(_) => "deployment input is not immutable",
        BundleError::UnsupportedEntry => "deployment contains an unsupported entry",
        BundleError::InvalidPath => "deployment contains an invalid path binding",
        BundleError::UnknownFile(_) => "deployment artifact closure is invalid",
        BundleError::TooLarge => "deployment exceeds a Version 1 size bound",
        BundleError::Config(_) => "deployment configuration is invalid",
        BundleError::InvalidArtifact(_) => "deployment artifact is invalid",
        BundleError::InvalidScript(_) => "deployment script is invalid",
    };
    match error.artifact_fault() {
        Some(fault) => CommandError::Deployment(message, fault.clone()),
        None => CommandError::Cli(CliError(message)),
    }
}

/// Report a kernel compilation failure with the artifact diagnostic it carries.
///
/// The kernel is the first pass that reads every reviewed artifact under the
/// hardened script grammar and the full schema draft, so it is where an
/// adopter learns that a file the loader accepted is still refused. The
/// failure class stays a fixed operator message and the value-free diagnostic
/// names the file, exactly as a load failure does.
fn kernel_compile_error(message: &'static str, error: KernelError) -> CommandError {
    match error.artifact_fault() {
        Some(fault) => CommandError::Deployment(message, fault.clone()),
        None => CommandError::Cli(CliError(message)),
    }
}

fn runtime_initialization_error(error: RuntimeInitializationError) -> CommandError {
    match error {
        RuntimeInitializationError::Bundle => {
            CliError("runtime bundle initialization failed").into()
        }
        RuntimeInitializationError::Secrets => {
            CliError("runtime secret initialization failed").into()
        }
        RuntimeInitializationError::Audit(fault) => {
            CommandError::Audit("runtime audit initialization failed", fault)
        }
        RuntimeInitializationError::Signing => {
            CliError("runtime signing initialization failed").into()
        }
        RuntimeInitializationError::Source => {
            CliError("runtime source initialization failed").into()
        }
        RuntimeInitializationError::RateLimit => {
            CliError("runtime rate-limit initialization failed").into()
        }
    }
}

/// Bind every statement source in a bundle to the material its transport needs
/// from outside its own configuration.
///
/// `extracts` carries the runtime document's extract bindings where one was
/// loaded, and is absent where the caller has a bundle and nothing else.
fn source_statements<'a>(
    bundle: &'a Bundle,
    extracts: Option<&'a BTreeMap<String, SourceExtract>>,
) -> Result<BTreeMap<String, StatementInputs<'a>>, CommandError> {
    let mut statements = BTreeMap::new();
    for (source_id, source) in bundle.config.sources.iter() {
        if let Some(inputs) =
            statement_inputs(source, bundle, extracts).map_err(source_plan_error)?
        {
            statements.insert(source_id.to_owned(), inputs);
        }
    }
    Ok(statements)
}

/// Report a source plan failure as the artifact it names, where it named one.
///
/// A statement that will not prepare, an extract nothing mounted, and a
/// statement whose result leaves its declared contract are all faults in one
/// file an adopter can open. Saying only that plan compilation failed would
/// leave them to find that file themselves.
fn source_plan_error(error: SourceError) -> CommandError {
    match error.artifact_fault() {
        Some(fault) => CommandError::Deployment("source plan compilation failed", fault.clone()),
        None => CliError("source plan compilation failed").into(),
    }
}

fn compile_source_plans(
    bundle: &Bundle,
    runtime: &RuntimeDocument,
) -> Result<BTreeMap<String, SourceExecutor>, CommandError> {
    compile_source_plans_with_runtime(
        &bundle.config,
        &source_statements(bundle, Some(&runtime.source_extracts))?,
        &runtime.config.secret_providers.file.root,
        &runtime.config.outbound_tls,
        &runtime.ca_bundles,
    )
}

fn compile_source_plans_with_runtime(
    config: &EvidenceConfig,
    statements: &BTreeMap<String, StatementInputs<'_>>,
    secret_root: &str,
    outbound_tls: &OutboundTlsConfig,
    ca_bundles: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, SourceExecutor>, CommandError> {
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], secret_root)
            .map_err(|_| CliError("source plan compilation failed"))?,
    );
    let mut plans = BTreeMap::new();
    for (source_id, source) in config.sources.iter() {
        let allowed_selector_sets = config.source_selector_sets(source_id);
        let plan = SourceExecutor::new_with_selector_sets_and_tls(
            source,
            &allowed_selector_sets,
            outbound_tls,
            ca_bundles,
            statements.get(source_id).copied(),
            Arc::clone(&secrets),
        )
        .map_err(source_plan_error)?;
        plans.insert(source_id.to_owned(), plan);
    }
    Ok(plans)
}

fn compile_bundle_source_plans(
    bundle: &Bundle,
) -> Result<BTreeMap<String, SourceExecutor>, CommandError> {
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], "/")
            .map_err(|_| CliError("source plan compilation failed"))?,
    );
    // A bundle arrives without a deployment, so no extract is mounted and a
    // statement source is checked as far as a bundle alone allows.
    let statements = source_statements(bundle, None)?;
    let mut plans = BTreeMap::new();
    for (source_id, source) in bundle.config.sources.iter() {
        let allowed_selector_sets = bundle.config.source_selector_sets(source_id);
        let plan = SourceExecutor::new_for_offline_fixture(
            source,
            &allowed_selector_sets,
            statements.get(source_id).copied(),
            Arc::clone(&secrets),
        )
        .map_err(source_plan_error)?;
        plans.insert(source_id.to_owned(), plan);
    }
    Ok(plans)
}

/// Install the operational log subscriber for the serving process.
///
/// Records are line-delimited JSON on stdout so a collector can read them
/// without a parsing convention of its own. `EVIDENCE_LOG` selects verbosity
/// and defaults to `info`, which is the level the request boundary emits at.
/// Offline commands print their own result and install nothing, so no command
/// gains log output it did not have.
fn install_operational_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("EVIDENCE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .init();
}

/// Resolve on the first operator stop signal.
///
/// A service manager and a container runtime both stop a process with
/// SIGTERM, and an interactive operator uses Ctrl-C. Both resolve here, so the
/// same drain runs either way: the server stops accepting, finishes its
/// in-flight evaluations, and closes the audit chain before the process exits.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                eprintln!(
                    "evidence: SIGTERM handler unavailable ({error}); stopping on Ctrl-C only"
                );
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Longest accepted verification input.
///
/// A stored response, a pinned key set, and a relying-procedure policy are all
/// small documents, so a larger file is refused before it is read rather than
/// pulled into memory because a path was mistyped.
const MAX_VERIFY_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_LOCAL_REQUEST_BYTES: u64 = 64 * 1024;

/// Exit status for a response that is authentic but no longer current.
const NOT_CURRENT_EXIT_CODE: u8 = 3;

/// The one class reported for an input document that cannot be read or parsed.
const VERIFY_MALFORMED: CliError = CliError("stored response verification failed (malformed)");
const LOCAL_RELYING_PROCEDURE_FAILED: CliError =
    CliError("local relying procedure preparation failed");
const LOCAL_AUDIT_FAILED: CliError = CliError("local audit inspection failed");

/// Close trusted local procedure metadata and exact request-origin bindings.
///
/// This command has no bearer input. Authorization remains exclusively on the
/// running service's HTTP request boundary.
async fn prepare_local_relying_procedure_command(
    runtime_path: &Path,
    input_path: &Path,
) -> Result<ExitCode, CommandError> {
    let deployment =
        DeploymentInputs::load(runtime_path).map_err(|_| LOCAL_RELYING_PROCEDURE_FAILED)?;
    let input_bytes = read_owner_only_input(
        input_path,
        MAX_LOCAL_REQUEST_BYTES,
        LOCAL_RELYING_PROCEDURE_FAILED,
    )?;
    let input_value =
        parse_json_strict(&input_bytes).map_err(|_| LOCAL_RELYING_PROCEDURE_FAILED)?;
    let input: LocalRelyingProcedureInput =
        serde_json::from_value(input_value).map_err(|_| LOCAL_RELYING_PROCEDURE_FAILED)?;
    let procedure = prepare_local_relying_procedure(&deployment, &input)
        .await
        .map_err(|_| LOCAL_RELYING_PROCEDURE_FAILED)?;
    write_canonical_json_line(&procedure, LOCAL_RELYING_PROCEDURE_FAILED)?;
    Ok(ExitCode::SUCCESS)
}

/// Open one operator input without following a symlink, then enforce the same
/// owner, mode, link-count, and bounded-read posture as secret files.
fn read_owner_only_input(
    path: &Path,
    maximum_bytes: u64,
    failure: CliError,
) -> Result<Vec<u8>, CliError> {
    read_bounded_regular_input(path, maximum_bytes, true, failure)
}

fn read_bounded_regular_input(
    path: &Path,
    maximum_bytes: u64,
    require_owner_only: bool,
    failure: CliError,
) -> Result<Vec<u8>, CliError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| failure)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| failure)?;
    if !metadata.is_file()
        || (require_owner_only
            && (metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o7777 != 0o600))
        || metadata.nlink() != 1
        || metadata.len() > maximum_bytes
    {
        return Err(failure);
    }
    let mut bytes = Vec::new();
    file.take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(failure);
    }
    Ok(bytes)
}

fn write_canonical_json_line<T: serde::Serialize>(
    value: &T,
    failure: CliError,
) -> Result<(), CliError> {
    let value = serde_json::to_value(value).map_err(|_| failure)?;
    let bytes = canonicalize_json(&value).map_err(|_| failure)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes).map_err(|_| failure)?;
    stdout.write_all(b"\n").map_err(|_| failure)
}

/// Inspect the last local audit operation only after the writer has stopped.
///
/// Every failure is deliberately collapsed to one value-free class. The view
/// is written only after the entire retained chain and its native events have
/// verified, so stdout can never contain a partial or unverified operation.
fn local_audit_last_operation_command(runtime_path: &Path) -> Result<ExitCode, CommandError> {
    let deployment = DeploymentInputs::load(runtime_path).map_err(|_| LOCAL_AUDIT_FAILED)?;
    if deployment.bundle.config.assurance_profile != AssuranceProfile::Local {
        return Err(LOCAL_AUDIT_FAILED.into());
    }
    let secrets = SecretResolver::new(
        [SecretProvider::File],
        &deployment.runtime.config.secret_providers.file.root,
    )
    .map_err(|_| LOCAL_AUDIT_FAILED)?;
    let audit_secret = secrets
        .resolve(deployment.bundle.config.audit.hash_secret_ref.as_str())
        .map_err(|_| LOCAL_AUDIT_FAILED)?;
    let master_secret =
        derived_audit_chain_secret(audit_secret.expose_secret()).map_err(|_| LOCAL_AUDIT_FAILED)?;
    let view = verified_last_local_audit_operation(
        Path::new(&deployment.runtime.config.audit_storage.path),
        &master_secret,
    )
    .map_err(|_| LOCAL_AUDIT_FAILED)?;
    write_canonical_json_line(&view, LOCAL_AUDIT_FAILED)?;
    Ok(ExitCode::SUCCESS)
}

/// The one stored response an operator named, and the format its bytes are
/// parsed under. The format is an operator statement, never a guess from the
/// file's contents.
enum StoredResponse {
    SignedJws(PathBuf),
    SdJwtVc(PathBuf),
}

impl StoredResponse {
    fn path(&self) -> &Path {
        match self {
            Self::SignedJws(path) | Self::SdJwtVc(path) => path,
        }
    }
}

/// Re-verify one stored signed response offline.
///
/// The pinned key set file is the complete trust set: this command opens no
/// socket, resolves no metadata, and fetches no key. Every expectation comes
/// from the operator's policy document, which belongs to independently
/// retained trusted state such as the original request and an accepted
/// original transaction. The printed lines are the verification instant, the
/// authenticity answer, and, for an authentic response, current usability.
/// A failure reports only its closed class, so re-verification never becomes
/// an oracle for which hidden comparison failed.
fn verify_stored_response(
    stored: &StoredResponse,
    jwks_path: &Path,
    policy_path: &Path,
    at: Option<&str>,
) -> Result<ExitCode, CliError> {
    let instant = verification_instant(at)?;
    println!(
        "verified-at: {}",
        instant.to_rfc3339_opts(SecondsFormat::Secs, true)
    );

    let response = read_verification_input(stored.path())?;
    let trusted: JwksDocument = serde_json::from_value(
        parse_json_strict(&read_verification_input(jwks_path)?).map_err(|_| VERIFY_MALFORMED)?,
    )
    .map_err(|_| VERIFY_MALFORMED)?;
    let document: EvidenceVerificationPolicyDocument =
        serde_norway::from_slice(&read_verification_input(policy_path)?)
            .map_err(|_| VERIFY_MALFORMED)?;
    // A policy stating a time bound the contract forbids is an unusable input
    // document. Reading it already refuses it; this is the same refusal for the
    // conversion, and both are the malformed-input class rather than a
    // verification outcome.
    let policy = document
        .try_into_policy(instant)
        .map_err(|_| VERIFY_MALFORMED)?;

    // One policy document, one set of expectations, and one report shape serve
    // both response formats; only the serialization the operator named is
    // parsed.
    let report = match stored {
        StoredResponse::SignedJws(_) => verify_flattened_jws_report(&response, &trusted, &policy),
        StoredResponse::SdJwtVc(_) => verify_sd_jwt_vc_report(&response, &trusted, &policy),
    };

    match report {
        Ok(report) => {
            println!("authentic: yes");
            if !report.currently_valid {
                println!("currently-valid: no");
                return Ok(ExitCode::from(NOT_CURRENT_EXIT_CODE));
            }
            println!("currently-valid: yes");
            // Inspection output for the operator who already holds the stored
            // response. It appears only once the trusted key signed the exact
            // payload, every expectation held, and the assertion is current.
            let inspected = serde_json::to_string_pretty(&report.evidence)
                .map_err(|_| verification_error_class(VerificationError::Payload))?;
            println!("{inspected}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            println!("authentic: no");
            Err(verification_error_class(error))
        }
    }
}

/// Exactly what a verified presentation proves, and what it does not.
///
/// It is printed rather than left to documentation because the two answers are
/// easy to conflate: the expected challenge is compared, never consumed, so an
/// operator who read `authentic: yes` as "these bytes had not been presented
/// before" would be reading a guarantee this command cannot give.
const POSSESSION_STATEMENT: &str =
    "proven when the key-binding JWT was signed; not proof that the presentation is fresh, single-use, or unreplayed";

/// Re-verify one stored holder-bound presentation offline.
///
/// This is the holder-bound counterpart of [`verify_stored_response`] and keeps
/// the same posture: the pinned key set file is the complete trust set, no
/// socket is opened, no metadata is resolved, no key is fetched, and every
/// expectation comes from the operator's own policy document. Here that
/// document also carries the challenge the relying party issued and retained.
/// A failure reports only its closed class, so re-verification never becomes an
/// oracle for which hidden comparison failed.
///
/// The printed lines are the verification instant, the authenticity answer,
/// what possession the run proved, and, for an authentic presentation, current
/// usability. Comparing the expected challenge does not retire it and this
/// command holds no state between runs, so the same file verifies again under
/// the same policy; deciding that a challenge is spent belongs to the relying
/// party's own challenge lifecycle.
fn verify_stored_presentation(
    presentation_path: &Path,
    jwks_path: &Path,
    policy_path: &Path,
    at: Option<&str>,
) -> Result<ExitCode, CliError> {
    let instant = verification_instant(at)?;
    println!(
        "verified-at: {}",
        instant.to_rfc3339_opts(SecondsFormat::Secs, true)
    );

    let presentation = read_verification_input(presentation_path)?;
    let trusted: JwksDocument = serde_json::from_value(
        parse_json_strict(&read_verification_input(jwks_path)?).map_err(|_| VERIFY_MALFORMED)?,
    )
    .map_err(|_| VERIFY_MALFORMED)?;
    // The holder-bound document is closed and declares its own mode, so a
    // Version 1 policy never parses here and this policy never parses there.
    let document: HolderBoundPresentationPolicyDocument =
        serde_norway::from_slice(&read_verification_input(policy_path)?)
            .map_err(|_| VERIFY_MALFORMED)?;
    // As on the Version 1 path, a policy stating a bound the contract forbids
    // is an unusable input document rather than a verification outcome.
    let policy = document
        .try_into_policy(instant)
        .map_err(|_| VERIFY_MALFORMED)?;

    match verify_sd_jwt_vc_presentation_report(&presentation, &trusted, &policy) {
        Ok(report) => {
            println!("authentic: yes");
            println!("possession: {POSSESSION_STATEMENT}");
            if !report.currently_valid {
                println!("currently-valid: no");
                return Ok(ExitCode::from(NOT_CURRENT_EXIT_CODE));
            }
            println!("currently-valid: yes");
            // Inspection output for the operator who already holds the stored
            // presentation. It appears only once the trusted key signed the
            // exact payload, the holder proved possession, every expectation
            // held, and the assertion is current.
            let inspected = serde_json::to_string_pretty(&report.evidence)
                .map_err(|_| verification_error_class(VerificationError::Payload))?;
            println!("{inspected}");
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            println!("authentic: no");
            Err(verification_error_class(error))
        }
    }
}

/// Resolve the verification instant from `--at`, or from system time.
///
/// `--at` is strict RFC 3339 at zero offset, so an operator cannot silently
/// re-verify against a local wall clock and read the result as UTC.
fn verification_instant(at: Option<&str>) -> Result<DateTime<Utc>, CliError> {
    const NOT_UTC: CliError = CliError("verification instant is not strict RFC 3339 UTC");

    let Some(text) = at else {
        return Ok(Utc::now());
    };
    let parsed = DateTime::parse_from_rfc3339(text).map_err(|_| NOT_UTC)?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(NOT_UTC);
    }
    Ok(parsed.with_timezone(&Utc))
}

/// Read one bounded verification input file.
fn read_verification_input(path: &Path) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|_| VERIFY_MALFORMED)?;
    if !metadata.is_file() || metadata.len() > MAX_VERIFY_INPUT_BYTES {
        return Err(VERIFY_MALFORMED);
    }
    fs::read(path).map_err(|_| VERIFY_MALFORMED)
}

/// Report one verification failure as its closed class and nothing more.
fn verification_error_class(error: VerificationError) -> CliError {
    match error {
        VerificationError::MalformedJws => VERIFY_MALFORMED,
        VerificationError::ProtectedHeader => {
            CliError("stored response verification failed (protected-header)")
        }
        VerificationError::Key => CliError("stored response verification failed (key)"),
        VerificationError::Signature => CliError("stored response verification failed (signature)"),
        VerificationError::Payload => CliError("stored response verification failed (payload)"),
        VerificationError::Policy => CliError("stored response verification failed (policy)"),
        VerificationError::Time => CliError("stored response verification failed (time)"),
        VerificationError::Disclosure => {
            CliError("stored response verification failed (disclosure)")
        }
        VerificationError::KeyBinding => {
            CliError("stored response verification failed (key-binding)")
        }
    }
}

/// Run a full out-of-band audit verification pass for the deployment named by
/// one closed operator runtime file.
///
/// The audit storage path and hash secret are read from the same runtime
/// document and secret provider the serving process uses; this command takes
/// no path or secret flags of its own, so it can never be pointed at an audit
/// chain the deployment does not own.
fn run_verify_audit(runtime_path: &Path) -> Result<ExitCode, CommandError> {
    let deployment = DeploymentInputs::load(runtime_path).map_err(deployment_load_error)?;
    let secrets = SecretResolver::new(
        [SecretProvider::File],
        &deployment.runtime.config.secret_providers.file.root,
    )
    .map_err(|_| CliError("audit verification secret resolver failed"))?;
    let audit_secret = secrets
        .resolve(deployment.bundle.config.audit.hash_secret_ref.as_str())
        .map_err(|_| CliError("audit verification secret resolution failed"))?;
    let master_secret = derived_audit_chain_secret(audit_secret.expose_secret())
        .map_err(|_| CliError("audit verification secret is invalid"))?;
    verify_audit_with_secret(
        Path::new(&deployment.runtime.config.audit_storage.path),
        &master_secret,
    )
}

/// Verify one audit chain and print the operator report.
///
/// Split from [`run_verify_audit`] so the report and the failure
/// classification can be exercised directly against a constructed chain,
/// without a full deployment bundle and runtime document on disk.
fn verify_audit_with_secret(
    audit_path: &Path,
    master_secret: &AuditHashSecret,
) -> Result<ExitCode, CommandError> {
    match verify_audit_chain(audit_path, master_secret) {
        Ok(summary) => {
            println!("{}", audit_chain_report(&summary));
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            let (detail, class) = audit_verification_failure(error);
            println!("{detail}");
            Err(CommandError::Cli(class))
        }
    }
}

fn derived_audit_chain_secret(master_secret: &[u8]) -> Result<AuditHashSecret, ()> {
    let profile =
        AuditChainProfile::production_from_secret_bytes(Zeroizing::new(master_secret.to_vec()))
            .map_err(|_| ())?;
    match profile.hasher() {
        AuditChainHasher::Keyed(secret) => Ok(secret),
        AuditChainHasher::UnkeyedDevOnly => Err(()),
    }
}

/// Render an out-of-band audit verification result for an operator.
///
/// The head hash and the segment and record counts carry no request content,
/// so they are safe to print; nothing secret-derived beyond the chain head
/// appears here. When the active segment could not be verified, the report
/// says so plainly rather than reading as a pass of the whole chain.
fn audit_chain_report(summary: &AuditChainSummary) -> String {
    let sealed_sequence = match (summary.first_sequence, summary.last_sequence) {
        (Some(first), Some(last)) => format!("{first}-{last}"),
        _ => "none".to_owned(),
    };
    let active_segment = if summary.active_verified {
        "verified".to_owned()
    } else {
        "not verified: a running writer holds it, so only sealed history was proven".to_owned()
    };
    format!(
        "segments: {}\nrecords: {}\nsealed-sequence: {sealed_sequence}\nhead: {}\nactive-segment: {active_segment}",
        summary.segments,
        summary.records,
        OptionalHashHex(summary.head),
    )
}

/// Classify an audit verification failure for the operator report and exit.
///
/// A gap in the sealed sequence is archived-or-missing history, not a hash
/// break, so it is reported in those terms and kept distinguishable from
/// every other verification failure, which is corruption.
fn audit_verification_failure(error: EvidenceAuditError) -> (String, CliError) {
    match error {
        EvidenceAuditError::SegmentMissing { sequence } => (
            format!(
                "sealed segment {sequence} is archived or missing from the chain; \
                 this is not corruption"
            ),
            CliError("audit chain is missing sealed history"),
        ),
        _ => (
            "audit chain verification failed".to_owned(),
            CliError("audit chain verification failed"),
        ),
    }
}

/// Render one fixture run as the single JSON document the JSON form prints.
///
/// The verdict comes from the run's own result rather than from the trace, so a
/// document can never report a pass the command did not report.
fn fixture_report_json(
    trace: &FixtureTrace,
    summary: Result<&FixtureSummary, &CliError>,
) -> Result<String, CliError> {
    let report = FixtureReport {
        passed: summary.is_ok(),
        evaluated_cases: summary.ok().map(|summary| summary.evaluated_cases),
        trace,
    };
    serde_json::to_string_pretty(&report)
        .map_err(|_| CliError("fixture trace is not representable"))
}

/// The run-time diagnostic surfaces a fixture's own canaries are checked against.
///
/// Rendered whether or not the operator asked for the trace. A check that only
/// ran under `--explain` would leave the leak it exists to catch sitting in
/// every run nobody explained.
///
/// Both rendered forms are taken. They carry the same strings today, so this is
/// not redundancy against a leak but against drift: a field that becomes
/// serialized but not rendered, or the reverse, stays covered without anyone
/// having to remember to widen the check.
fn explain_surfaces(trace: &FixtureTrace) -> Result<Vec<String>, CliError> {
    Ok(vec![
        trace.render(),
        serde_json::to_string(trace).map_err(|_| CliError("fixture trace is not representable"))?,
    ])
}

/// Check a trace against the canaries of the fixture that built it.
///
/// Separate from the fixture's whole privacy expectation because that one is a
/// verdict on a run that finished, while this one has to hold on a run that
/// stopped early. A case that raises an error never reaches the end of the
/// evaluation, and that is exactly the run whose trace an operator reads.
fn validate_trace_canaries(trace: &FixtureTrace) -> Result<(), CliError> {
    let surfaces = explain_surfaces(trace)?;
    for prohibited in trace.canaries() {
        if surfaces
            .iter()
            .any(|surface| surface.contains(prohibited.as_str()))
        {
            return Err(CliError("fixture prohibited diagnostic is present"));
        }
    }
    Ok(())
}

/// The canaries a fixture declares, read before any of its cases run.
///
/// An absent or malformed expectation is an error rather than an empty list.
/// Returning nothing would drop the check for precisely the fixture whose
/// declaration nobody can read.
fn declared_canaries(
    fixture: &JsonMap<String, Value>,
    expectation_key: &str,
    exclude_key: &str,
) -> Result<Vec<String>, CliError> {
    let expectation = fixture
        .get(expectation_key)
        .and_then(Value::as_object)
        .ok_or(CliError("fixture privacy expectation is unavailable"))?;
    Ok(expectation_strings(expectation, exclude_key)?
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Whether a fixture case identifier can be written into a trace as it stands.
///
/// The identifier is fixture-controlled and the text trace puts it on a line of
/// its own, so a control character in one would let a fixture write lines that
/// read as stages the run never reached. Refused here rather than escaped at the
/// render, which would quote every ordinary identifier to contain the one kind
/// that has no legitimate use in an authored name.
fn is_renderable_case_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.contains(char::is_control)
}

async fn evaluate_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, SourceExecutor>,
    fixture_path: &Path,
    selected_case: Option<&str>,
    exercise_signing: bool,
    trace: &mut FixtureTrace,
) -> Result<FixtureSummary, CliError> {
    let signer = if exercise_signing {
        Some(offline_fixture_signer().await?)
    } else {
        None
    };
    let fixture_name = safe_fixture_name(fixture_path)?;
    let referenced = bundle
        .config
        .requirements
        .iter()
        .filter(|requirement| {
            requirement
                .fixtures
                .as_ref()
                .is_some_and(|fixtures| fixtures.as_str() == fixture_name)
        })
        .collect::<Vec<_>>();
    if referenced.len() != 1 {
        return Err(CliError(
            "fixture must be a captured artifact referenced by exactly one requirement",
        ));
    }
    let requirement = referenced[0];
    let fixture = bundle
        .fixtures
        .get(fixture_name)
        .ok_or(CliError("fixture artifact is not captured by the bundle"))?;
    let fixture = serde_json::to_value(fixture)
        .map_err(|_| CliError("fixture contract is not representable"))?;
    let object = fixture
        .as_object()
        .ok_or(CliError("fixture contract must be an object"))?;
    if object.get("synthetic_only") != Some(&Value::Bool(true)) {
        return Err(CliError("fixture is not an approved synthetic definition"));
    }
    if object.get("coequal_acceptance_definition") != Some(&Value::Bool(true)) {
        if object
            .get("fixture")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("registry.evidence.reference.") && id.ends_with("/v1"))
        {
            return evaluate_reference_fixture(
                bundle,
                kernel,
                source_plans,
                signer.as_ref(),
                requirement,
                (object, selected_case),
                trace,
            )
            .await;
        }
        return Err(CliError(
            "fixture is not an approved synthetic acceptance definition",
        ));
    }
    trace.declare_canaries(declared_canaries(
        object,
        "privacy_expectation",
        "diagnostics_exclude",
    )?);
    let common = object.get("common").and_then(Value::as_object);
    let cases = object
        .get("cases")
        .and_then(Value::as_array)
        .ok_or(CliError("fixture cases are unavailable"))?;
    if cases.is_empty() || cases.len() > 256 {
        return Err(CliError("fixture case count is invalid"));
    }
    if selected_case.is_some_and(|selected| {
        !cases
            .iter()
            .any(|case| case.get("id").and_then(Value::as_str) == Some(selected))
    }) {
        return Err(CliError("selected fixture case is unavailable"));
    }

    let mut summary = FixtureSummary::default();
    let mut successful_values = Vec::new();
    for case in cases {
        let case = case
            .as_object()
            .ok_or(CliError("fixture case is not an object"))?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| is_renderable_case_identifier(value))
            .ok_or(CliError("fixture case identifier is invalid"))?;
        if selected_case.is_some_and(|selected| selected != id) {
            continue;
        }
        trace.begin_case(id);

        if case.get("subjects").is_some() {
            require_expected(case, "pre-source-selector-rejection")?;
            match resolve_offline_fixture_subjects(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            ) {
                Ok(_) => return Err(CliError("fixture selector rejection did not occur")),
                Err(OfflineFixtureError::Purpose) => {
                    return Err(CliError(FIXTURE_PURPOSE_FAILURE));
                }
                Err(OfflineFixtureError::Authorization(_)) => {}
            }
            trace.record(
                Stage::Prepare,
                StageStatus::Ok,
                "the selector was refused before any source, as the case states",
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        if let Some(expected_roles) = case.get("expected_subject_roles") {
            let expected_roles = expected_roles
                .as_array()
                .ok_or(CliError("fixture subject-role expectation is invalid"))?
                .iter()
                .map(|role| {
                    role.as_str()
                        .map(ToOwned::to_owned)
                        .ok_or(CliError("fixture subject-role expectation is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let actual_roles = resolve_offline_fixture_subjects(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| fixture_failure(error, "fixture subjects did not resolve"))?;
            if actual_roles != expected_roles {
                return Err(CliError("fixture subject roles did not match"));
            }
        }
        let observed_at =
            fixture_observed_at(case, common, requirement.observation_timezone.as_deref())?;

        if case.get("source").is_some() || case.get("sources").is_some() {
            let resolved = resolve_offline_fixture_authorization(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| fixture_failure(error, "fixture subjects did not resolve"))?;
            let derivation_selectors =
                fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
            trace.record(
                Stage::Prepare,
                StageStatus::Ok,
                format!(
                    "selector roles {}, derivation selector roles {}",
                    name_list(
                        &resolved
                            .subjects
                            .iter()
                            .map(|subject| subject.role.clone())
                            .collect::<Vec<_>>()
                    ),
                    name_list(&object_keys(&derivation_selectors))
                ),
            );
            if let Some(expected) = case
                .get("derivationSelectorInputs")
                .or_else(|| common.and_then(|common| common.get("derivationSelectorInputs")))
            {
                if expected != &derivation_selectors {
                    return Err(CliError(
                        "fixture derivation selector projection did not match",
                    ));
                }
            }
            let outcome = evaluate_fixture_acquisition(
                bundle,
                kernel,
                requirement,
                case,
                &derivation_selectors,
                observed_at,
                trace,
            )?;
            if let Some(values) = validate_case_outcome(case, outcome, trace)? {
                successful_values.push(
                    sign_and_verify_fixture_evidence(
                        bundle,
                        kernel,
                        signer.as_ref(),
                        requirement,
                        &resolved,
                        values,
                        observed_at,
                    )
                    .await?,
                );
                trace.record(
                    Stage::Sign,
                    StageStatus::Ok,
                    if signer.is_some() {
                        "the payload was constructed, signed, and verified offline"
                    } else {
                        "the payload was constructed; this seam does not sign"
                    },
                );
            }
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        if let Some(injected) = case.get("injected_derivation") {
            validate_injected_rejection(kernel, requirement, injected, trace)?;
            require_expected(case, "output-gate-rejection")?;
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        if let Some(source_failure) = case.get("source_failure") {
            validate_source_failure(case, source_failure)?;
            trace.record(
                Stage::Acquire,
                StageStatus::Failed,
                format!(
                    "the source failed as {}, which the case states",
                    source_failure.as_str().unwrap_or("an unnamed category")
                ),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        if let Some(companion) = case.get("companion_bundle") {
            validate_companion_rejection(bundle, requirement, case, companion)?;
            trace.record(
                Stage::Prepare,
                StageStatus::Ok,
                format!(
                    "the companion bundle {:?} was refused, as the case states",
                    companion.as_str().unwrap_or_default()
                ),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        return Err(CliError(
            "fixture case has no closed Version 1 evaluation form",
        ));
    }
    validate_privacy_expectation(
        object,
        requirement,
        &successful_values,
        &explain_surfaces(trace)?,
    )?;
    Ok(summary)
}

/// Run one case's acquisition, recording each stage it reaches.
///
/// The single-source branch runs extraction and derivation as two calls rather
/// than the one `evaluate_with_selectors` that composes them. That composition
/// is exactly extraction then derivation, so both the outcome and every error
/// value are unchanged; splitting it is what lets the lookup result and the
/// fact shape be recorded between the two.
fn evaluate_fixture_acquisition(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    requirement: &registry_evidence::config::RequirementConfig,
    case: &JsonMap<String, Value>,
    derivation_selectors: &Value,
    observed_at: DateTime<Utc>,
    trace: &mut FixtureTrace,
) -> Result<Result<KernelOutcome, KernelError>, CliError> {
    let projection = || ValueProjection {
        scope: EvidenceScope::AudienceScoped {
            audience: OFFLINE_AUDIENCE,
            request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
        },
        binding_key: &OFFLINE_BINDING_KEY,
        binding_key_version: 1,
    };
    match &requirement.acquisition {
        AcquisitionConfig::Single { source } => {
            if case.contains_key("sources") {
                return Err(CliError("single fixture must use source"));
            }
            let response = case
                .get("source")
                .ok_or(CliError("single fixture source is unavailable"))?;
            let source_config = bundle
                .config
                .sources
                .get(source)
                .ok_or(CliError("fixture source is unavailable"))?;
            let projected = match project_fixture_response(source_config, response) {
                Ok(projected) => projected,
                Err(_) => {
                    trace.record(
                        Stage::Acquire,
                        StageStatus::Failed,
                        format!("source {source:?} response failed its declared projection"),
                    );
                    return Ok(Err(KernelError::SourceProtocol));
                }
            };
            trace.record(
                Stage::Acquire,
                StageStatus::Ok,
                format!(
                    "1 response from source {source:?}, projected keys {}",
                    name_list(&object_keys(&projected))
                ),
            );
            let facts = match record_lookup(
                trace,
                kernel.extract(&requirement.id, &projected),
                &projected,
            ) {
                Ok(facts) => facts,
                Err(outcome) => return Ok(outcome),
            };
            Ok(record_derivation(
                trace,
                kernel.derive_and_validate_with_selectors(
                    &requirement.id,
                    &facts,
                    derivation_selectors,
                    observed_at,
                    projection(),
                ),
                requirement,
            ))
        }
        AcquisitionConfig::SearchThenFetch { search, fetch } => {
            if case.contains_key("source") {
                return Err(CliError("search-then-fetch fixture must use sources"));
            }
            let responses = case
                .get("sources")
                .and_then(Value::as_object)
                .ok_or(CliError("chained fixture sources are unavailable"))?;
            if responses.len() != 2
                || !responses.contains_key(search)
                || !responses.contains_key(fetch)
            {
                return Err(CliError("chained fixture sources are not exact"));
            }
            let search_config = bundle
                .config
                .sources
                .get(search)
                .ok_or(CliError("fixture search source is unavailable"))?;
            let search_response = match project_fixture_response(
                search_config,
                responses
                    .get(search)
                    .ok_or(CliError("fixture search response is unavailable"))?,
            ) {
                Ok(response) => response,
                Err(_) => {
                    trace.record(
                        Stage::Acquire,
                        StageStatus::Failed,
                        format!("search source {search:?} response failed its declared projection"),
                    );
                    return Ok(Err(KernelError::SourceProtocol));
                }
            };
            trace.record(
                Stage::Acquire,
                StageStatus::Ok,
                format!(
                    "search response from {search:?}, projected keys {}",
                    name_list(&object_keys(&search_response))
                ),
            );
            let search_facts = match record_lookup(
                trace,
                kernel.extract_source(search, &search_response, &BTreeMap::new()),
                &search_response,
            ) {
                Ok(facts) => facts,
                Err(outcome) => return Ok(outcome),
            };
            let fetch_config = bundle
                .config
                .sources
                .get(fetch)
                .ok_or(CliError("fixture fetch source is unavailable"))?;
            let fetch_response = match project_fixture_response(
                fetch_config,
                responses
                    .get(fetch)
                    .ok_or(CliError("fixture fetch response is unavailable"))?,
            ) {
                Ok(response) => response,
                Err(_) => {
                    trace.record(
                        Stage::Acquire,
                        StageStatus::Failed,
                        format!("fetch source {fetch:?} response failed its declared projection"),
                    );
                    return Ok(Err(KernelError::SourceProtocol));
                }
            };
            trace.record(
                Stage::Acquire,
                StageStatus::Ok,
                format!(
                    "fetch response from {fetch:?}, projected keys {}",
                    name_list(&object_keys(&fetch_response))
                ),
            );
            let facts = match record_dependent_lookup(
                trace,
                kernel.extract_source(fetch, &fetch_response, &search_facts),
                &fetch_response,
                "fetch",
            ) {
                Ok(facts) => facts,
                Err(outcome) => return Ok(outcome),
            };
            Ok(record_derivation(
                trace,
                kernel.derive_and_validate_with_selectors(
                    &requirement.id,
                    &facts,
                    derivation_selectors,
                    observed_at,
                    projection(),
                ),
                requirement,
            ))
        }
        AcquisitionConfig::SearchThenFetchSet { .. } => {
            // The two frozen forms above read their sources from the config
            // directly, because their stage lists are one and two entries long
            // and their derivation inputs differ. This form walks the plan
            // instead, so that the offline harness and the serving runtime
            // agree on stage order, on what each stage receives, and on where
            // an unresolved stage stops, by consuming one derivation rather
            // than by two implementations happening to match.
            if case.contains_key("source") {
                return Err(CliError("search-then-fetch-set fixture must use sources"));
            }
            let responses = case
                .get("sources")
                .and_then(Value::as_object)
                .ok_or(CliError("chained fixture sources are unavailable"))?;
            let plan = requirement.acquisition.plan();
            if responses.len() != plan.stages.len()
                || !plan
                    .stages
                    .iter()
                    .all(|stage| responses.contains_key(&stage.source))
            {
                return Err(CliError("chained fixture sources are not exact"));
            }
            // The search FactSet each member projects from, and the union the
            // derivation receives. They are separate because a member reads
            // only the search, never an earlier member: facts flow forward,
            // never sideways.
            let mut search_facts = BTreeMap::new();
            let mut union = BTreeMap::new();
            for stage in &plan.stages {
                // Each stage is traced as it is walked, so a chain reports
                // which call the case reached rather than reporting the whole
                // acquisition as one step. Which call stopped a case is the
                // question this acquisition kind exists to raise.
                let role = match stage.role {
                    StageRole::Search => "search",
                    StageRole::Member => "member",
                };
                let source_config = bundle
                    .config
                    .sources
                    .get(&stage.source)
                    .ok_or(CliError("fixture source is unavailable"))?;
                let source = &stage.source;
                let response = match project_fixture_response(
                    source_config,
                    responses
                        .get(&stage.source)
                        .ok_or(CliError("fixture source response is unavailable"))?,
                ) {
                    Ok(response) => response,
                    Err(_) => {
                        trace.record(
                            Stage::Acquire,
                            StageStatus::Failed,
                            format!(
                                "{role} source {source:?} response failed its declared projection"
                            ),
                        );
                        return Ok(Err(KernelError::SourceProtocol));
                    }
                };
                trace.record(
                    Stage::Acquire,
                    StageStatus::Ok,
                    format!(
                        "{role} response from {source:?}, projected keys {}",
                        name_list(&object_keys(&response))
                    ),
                );
                let prior_facts = stage.inputs.project(&search_facts);
                let lookup = kernel.extract_source(&stage.source, &response, &prior_facts);
                // The search collapses structurally; a member that does not
                // resolve after a unique search match is a dependency
                // inconsistency, and the stages declared after it are never
                // evaluated. The two roles are recorded as differently as they
                // are treated, so the trace does not report an unresolved
                // member as an outcome the requirement can settle on.
                let facts = match stage.role {
                    StageRole::Search => match record_lookup(trace, lookup, &response) {
                        Ok(facts) => facts,
                        Err(outcome) => return Ok(outcome),
                    },
                    StageRole::Member => {
                        match record_dependent_lookup(trace, lookup, &response, role) {
                            Ok(facts) => facts,
                            Err(outcome) => return Ok(outcome),
                        }
                    }
                };
                if stage.role == StageRole::Search {
                    search_facts = facts.clone();
                }
                // Lossless: the bundle proved the stage fact names pairwise
                // disjoint before it was allowed to load.
                union.extend(facts);
            }
            Ok(record_derivation(
                trace,
                kernel.derive_and_validate_with_selectors(
                    &requirement.id,
                    &union,
                    derivation_selectors,
                    observed_at,
                    projection(),
                ),
                requirement,
            ))
        }
    }
}

/// Record one acquisition, yielding the projected response to carry on with.
///
/// A response the source contract refuses is an acquisition that was reached
/// and failed, so it is recorded before the failure travels on. Left
/// unrecorded, the trace of the refused case would end at the preparation
/// before it and read as though the case never called its source at all.
///
/// The cause is not reported. What made a response unacceptable is a statement
/// about that response, and the trace is read by whoever could not see it.
fn record_projection(
    trace: &mut FixtureTrace,
    projected: Result<Value, SourceError>,
    acquired: &str,
    failure: CliError,
) -> Result<Value, CliError> {
    match projected {
        Ok(projected) => {
            trace.record(
                Stage::Acquire,
                StageStatus::Ok,
                format!(
                    "{acquired}, projected keys {}",
                    name_list(&object_keys(&projected))
                ),
            );
            Ok(projected)
        }
        Err(_) => {
            trace.record(
                Stage::Acquire,
                StageStatus::Failed,
                format!("{acquired}, and the source contract refused it"),
            );
            Err(failure)
        }
    }
}

/// Record one lookup, yielding either facts to carry on with or a settled
/// outcome for the caller to return unchanged.
///
/// On an unresolved lookup the response members are the whole diagnosis: the
/// script saw that shape and recognized nothing in it. `no_match` has no
/// Rust-side cause to report, because it is only ever what the script returned.
fn record_lookup(
    trace: &mut FixtureTrace,
    lookup: Result<LookupResult, KernelError>,
    response: &Value,
) -> Result<BTreeMap<String, Value>, Result<KernelOutcome, KernelError>> {
    let available = vec![format!(
        "response keys available {}",
        name_list(&object_keys(response))
    )];
    match lookup {
        Ok(LookupResult::Match(facts)) => {
            trace.record(
                Stage::Extract,
                StageStatus::Ok,
                format!("fact keys {}", name_list(&fact_keys(&facts))),
            );
            Ok(facts)
        }
        Ok(LookupResult::NoMatch) => {
            trace.record_with(
                Stage::Extract,
                StageStatus::NoMatch,
                "the extraction script reported no match",
                available,
            );
            Err(Ok(KernelOutcome::NoMatch))
        }
        Ok(LookupResult::Ambiguous) => {
            trace.record_with(
                Stage::Extract,
                StageStatus::Ambiguous,
                "the extraction script reported more than one candidate",
                available,
            );
            Err(Ok(KernelOutcome::Ambiguous))
        }
        Err(error) => {
            trace.record_with(
                Stage::Extract,
                StageStatus::Failed,
                format!("the extraction failed: {error}"),
                available,
            );
            Err(Err(error))
        }
    }
}

/// Record one lookup that may only resolve uniquely.
///
/// A stage that runs on a reference an earlier stage already resolved has no
/// unresolved answer available to it: the subject is settled, so a source that
/// cannot find it contradicts the one that could. That is a dependency
/// inconsistency rather than an outcome the requirement can settle on, and it
/// is recorded as a failure of the stage rather than as a verdict. `role` names
/// the stage in the vocabulary of the acquisition kind that called it.
fn record_dependent_lookup(
    trace: &mut FixtureTrace,
    lookup: Result<LookupResult, KernelError>,
    response: &Value,
    role: &str,
) -> Result<BTreeMap<String, Value>, Result<KernelOutcome, KernelError>> {
    match lookup {
        Ok(LookupResult::Match(facts)) => {
            trace.record(
                Stage::Extract,
                StageStatus::Ok,
                format!("fact keys {}", name_list(&fact_keys(&facts))),
            );
            Ok(facts)
        }
        Ok(LookupResult::NoMatch) | Ok(LookupResult::Ambiguous) => {
            trace.record_with(
                Stage::Extract,
                StageStatus::Failed,
                format!("a {role} may only resolve uniquely, and this one did not"),
                vec![format!(
                    "{role} response keys available {}",
                    name_list(&object_keys(response))
                )],
            );
            Err(Err(KernelError::SourceProtocol))
        }
        Err(error) => {
            trace.record(
                Stage::Extract,
                StageStatus::Failed,
                format!("the {role} extraction failed: {error}"),
            );
            Err(Err(error))
        }
    }
}

/// Record derivation and the output gate, which share one collapsed error.
///
/// `KernelError::Output` is every output-gate rejection at once, so the gate's
/// own reason cannot be recovered here. What can be said is which side failed
/// and what the gate was checking against: the declared concepts, their forms,
/// and whether each is required. That is where an author has to look.
fn record_derivation(
    trace: &mut FixtureTrace,
    derived: Result<ValidatedValues, KernelError>,
    requirement: &registry_evidence::config::RequirementConfig,
) -> Result<KernelOutcome, KernelError> {
    match derived {
        Ok(values) => {
            trace.record(
                Stage::Derive,
                StageStatus::Ok,
                format!(
                    "the derivation script produced {} value(s)",
                    values.as_slice().len()
                ),
            );
            trace.record(
                Stage::Validate,
                StageStatus::Ok,
                format!(
                    "the output gate accepted concepts {}",
                    name_list(
                        &values
                            .as_slice()
                            .iter()
                            .map(|value| value.provides_value_for.clone())
                            .collect::<Vec<_>>()
                    )
                ),
            );
            Ok(KernelOutcome::Match(values))
        }
        Err(KernelError::Output) => {
            trace.record(
                Stage::Derive,
                StageStatus::Ok,
                "the derivation script ran and returned values",
            );
            trace.record_with(
                Stage::Validate,
                StageStatus::Failed,
                "the output gate rejected the derived values",
                declared_concept_lines(requirement),
            );
            Err(KernelError::Output)
        }
        Err(error) => {
            trace.record(
                Stage::Derive,
                StageStatus::Failed,
                format!("the derivation failed: {error}"),
            );
            Err(error)
        }
    }
}

/// Describe what the output gate checks each derived value against.
fn declared_concept_lines(
    requirement: &registry_evidence::config::RequirementConfig,
) -> Vec<String> {
    requirement
        .concepts
        .iter()
        .map(|concept| {
            format!(
                "the gate requires concept {:?} in declared form {:?}{}",
                concept.id,
                concept.form,
                if concept.required {
                    ", and it is required"
                } else {
                    ", and it is optional"
                }
            )
        })
        .collect()
}

/// Name the members of an extracted fact set, never their values.
fn fact_keys(facts: &BTreeMap<String, Value>) -> Vec<String> {
    facts.keys().cloned().collect()
}

/// The extract a statement fixture materialized, for as long as its cases run.
///
/// A fixture commits its extract as a text seed, so the file itself is built
/// for one evaluation and removed with it. Nothing outside this process ever
/// sees it, which is what lets the reviewed statement run for real without the
/// run leaving state behind.
struct FixtureExtract {
    directory: PathBuf,
    path: PathBuf,
}

impl FixtureExtract {
    fn create() -> Result<Self, CliError> {
        let directory =
            std::env::temp_dir().join(format!("evidence-fixture-extract-{}", ulid::Ulid::new()));
        fs::create_dir_all(&directory)
            .map_err(|_| CliError("reference fixture extract directory is unavailable"))?;
        let path = directory.join("fixture.sqlite");
        Ok(Self { directory, path })
    }
}

impl Drop for FixtureExtract {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Refuse a requirement whose statement source is not the one a fixture runs.
///
/// A statement is proven by executing it, and a reference fixture executes only
/// the initial source's, against the single extract its seed describes. A later
/// stage would therefore be answered from the case's recorded response, and the
/// case would assert that stage's statement artifact and bound parameters while
/// the reviewed SQL never ran, which reads as coverage and is not. Refusing here
/// keeps the harness honest about which stages it proves, the same way the
/// fetch-set form is refused for having no reference-fixture shape at all.
///
/// This is a limit of the offline harness, not of the runtime: an acquisition
/// kind places no constraint on stage transport, and a deployment mixing them is
/// served normally. Lifting it means letting one case state two worlds at once,
/// a recorded response and an extract, which is a change to the fixture case
/// vocabulary rather than to a transport.
fn refuse_replayed_statement_stages(
    config: &EvidenceConfig,
    acquisition: &AcquisitionConfig,
) -> Result<(), CliError> {
    let executed = acquisition.initial_source();
    for source_id in acquisition.source_ids() {
        if source_id != executed
            && config
                .sources
                .get(source_id)
                .is_some_and(|source| source.statement().is_some())
        {
            return Err(CliError(
                "a replayed statement stage has no reference fixture form",
            ));
        }
    }
    Ok(())
}

/// Compile the statement source a fixture's cases run against, over the extract
/// its seed describes.
///
/// A statement fixture executes for real. An HTTP call needs a network, a
/// credential, and a live third party, so a fixture records what it returned;
/// reading a local extract needs none of those, so recording what the statement
/// would have returned would test everything except the statement. The extract
/// this builds is the fixture's own, in both the runtime and the bundle entry
/// points, so a fixture run answers from the world it states and never from a
/// file the deployment happens to have mounted.
///
/// A source on any other transport needs nothing here and returns nothing.
fn reference_statement_executor(
    bundle: &Bundle,
    source_id: &str,
    common: &JsonMap<String, Value>,
) -> Result<Option<(SourceExecutor, FixtureExtract)>, CliError> {
    let source = bundle
        .config
        .sources
        .get(source_id)
        .ok_or(CliError("reference fixture source is unavailable"))?;
    let Some(inputs) = statement_inputs(source, bundle, None)
        .map_err(|_| CliError("reference fixture statement is unavailable"))?
    else {
        return Ok(None);
    };
    let seed = common
        .get("extract")
        .and_then(Value::as_str)
        .ok_or(CliError("reference fixture extract seed is invalid"))?;
    let extract = FixtureExtract::create()?;
    materialize_seed_extract(&extract.path, seed)
        .map_err(|_| CliError("reference fixture extract seed did not materialize"))?;
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], "/")
            .map_err(|_| CliError("reference fixture source did not compile"))?,
    );
    let executor = SourceExecutor::new_for_offline_fixture(
        source,
        &bundle.config.source_selector_sets(source_id),
        Some(StatementInputs {
            extract: Some(StatementExtract::Fixture(&extract.path)),
            ..inputs
        }),
        secrets,
    )
    .map_err(|_| CliError("reference fixture source did not compile"))?;
    Ok(Some((executor, extract)))
}

async fn evaluate_reference_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, SourceExecutor>,
    signer: Option<&EvidenceSigner>,
    requirement: &registry_evidence::config::RequirementConfig,
    fixture_selection: (&JsonMap<String, Value>, Option<&str>),
    trace: &mut FixtureTrace,
) -> Result<FixtureSummary, CliError> {
    let (fixture, selected_case) = fixture_selection;
    // Asked before the fixture is read at all, because the requirement decides
    // this on its own and an author who has written an unprovable stage should
    // be told that, not that some key their case shape cannot supply is missing.
    refuse_replayed_statement_stages(&bundle.config, &requirement.acquisition)?;
    require_exact_keys(
        fixture,
        &[
            "fixture",
            "synthetic_only",
            "common",
            "cases",
            "privacyExpectation",
        ],
    )?;
    trace.declare_canaries(declared_canaries(
        fixture,
        "privacyExpectation",
        "diagnosticsExclude",
    )?);
    let common = fixture
        .get("common")
        .and_then(Value::as_object)
        .ok_or(CliError("reference fixture common block is invalid"))?;
    require_allowed_keys(
        common,
        &[
            "observed_at",
            "purpose",
            "selectors",
            "verified_token_claims",
            "derivationSelectorInputs",
            "extract",
            "expectedRequestParts",
            "expectedTransport",
            "expectedFetchRequestParts",
            "expectedFetchTransport",
        ],
    )?;
    let mut required_common = vec![
        "observed_at",
        "selectors",
        "expectedRequestParts",
        "expectedTransport",
    ];
    if bundle
        .config
        .sources
        .get(requirement.initial_source())
        .is_some_and(|source| source.statement().is_some())
    {
        required_common.push("extract");
    }
    if matches!(
        requirement.acquisition,
        AcquisitionConfig::SearchThenFetch { .. }
    ) {
        required_common.extend(["expectedFetchRequestParts", "expectedFetchTransport"]);
    }
    for required in required_common {
        if !common.contains_key(required) {
            return Err(CliError("reference fixture common block is incomplete"));
        }
    }
    // A statement fixture answers from the extract its own seed describes, so
    // the executor its cases run against is built here and belongs to this
    // evaluation alone.
    let statement_source =
        reference_statement_executor(bundle, requirement.initial_source(), common)?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .filter(|cases| !cases.is_empty() && cases.len() <= 256)
        .ok_or(CliError("reference fixture case count is invalid"))?;
    let mut identifiers = std::collections::BTreeSet::new();
    let mut successful_values = Vec::new();
    let mut summary = FixtureSummary::default();

    if selected_case.is_some_and(|selected| {
        !cases
            .iter()
            .any(|case| case.get("id").and_then(Value::as_str) == Some(selected))
    }) {
        return Err(CliError("selected fixture case is unavailable"));
    }

    for case in cases {
        let case = case
            .as_object()
            .ok_or(CliError("reference fixture case is not an object"))?;
        require_allowed_keys(
            case,
            &[
                "id",
                "purpose",
                "response",
                "responses",
                "selectors",
                "sourceFailure",
                "declaredUnresolved",
                "bundleMutation",
                "statementMutation",
                "requestMutation",
                "derivationMutation",
                "derivationParameterMutation",
                "selectorOverrides",
                "observed_at",
                "expected",
            ],
        )?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_renderable_case_identifier(id) && identifiers.insert(*id))
            .ok_or(CliError("reference fixture case identifier is invalid"))?;
        if selected_case.is_some_and(|selected| selected != id) {
            continue;
        }
        trace.begin_case(id);
        let expected = case
            .get("expected")
            .and_then(Value::as_object)
            .ok_or(CliError("reference fixture expectation is invalid"))?;
        require_allowed_keys(
            expected,
            &[
                "lookup",
                "facts",
                "value",
                "values",
                "entityReferenceCount",
                "rawReferencesDisclosed",
                "signed",
                "publicProblem",
                "error",
                "derivationRuns",
                "bundle",
                "outputGate",
                "rejectedBefore",
                "sourceRequestCount",
                "expectedTransport",
            ],
        )?;
        // A case states either the one concept value or the complete concept map,
        // never both, so neither expectation can weaken the other.
        if expected.contains_key("value") && expected.contains_key("values") {
            return Err(CliError("reference fixture states two value expectations"));
        }
        let forms = [
            "response",
            "responses",
            "selectors",
            "sourceFailure",
            "declaredUnresolved",
            "bundleMutation",
            "statementMutation",
            "requestMutation",
            "derivationMutation",
            "derivationParameterMutation",
            "selectorOverrides",
        ];
        let selected_forms = forms
            .iter()
            .filter(|name| case.contains_key(**name))
            .copied()
            .collect::<Vec<_>>();
        if selected_forms.len() != 1 {
            return Err(CliError("reference fixture case form is not closed"));
        }
        // A case states its world in the form its transport has. A recorded
        // response belongs to a source that answers over a network; a lookup
        // against the fixture's own extract belongs to one that does not. The
        // remaining forms describe the bundle or the authorized request and
        // read the same on either transport.
        let refused_here = match selected_forms[0] {
            "response" | "responses" | "declaredUnresolved" => statement_source.is_some(),
            "selectors" | "statementMutation" => statement_source.is_none(),
            _ => false,
        };
        if refused_here {
            return Err(CliError(
                "reference fixture case form is not this transport",
            ));
        }
        validate_reference_expectation_keys(selected_forms[0], expected)?;
        trace.record(
            Stage::Prepare,
            StageStatus::Ok,
            format!("the case is stated in the {:?} form", selected_forms[0]),
        );

        if let Some(mutation) = case.get("bundleMutation").and_then(Value::as_str) {
            if mutation != "duplicate-disclosure-family"
                || expected.get("bundle").and_then(Value::as_str) != Some("rejected")
            {
                return Err(CliError("reference bundle mutation is invalid"));
            }
            validate_reference_bundle_mutation(bundle, requirement)?;
            trace.record(
                Stage::Validate,
                StageStatus::Ok,
                format!("the {mutation:?} bundle mutation is refused, as the case requires"),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        if let Some(mutation) = case.get("statementMutation").and_then(Value::as_str) {
            if expected.get("bundle").and_then(Value::as_str) != Some("rejected") {
                return Err(CliError("reference statement mutation is invalid"));
            }
            validate_reference_statement_mutation(bundle, requirement, mutation)?;
            trace.record(
                Stage::Validate,
                StageStatus::Ok,
                format!("the {mutation:?} statement mutation is refused, as the case requires"),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        if let Some(mutation) = case.get("requestMutation").and_then(Value::as_str) {
            validate_reference_request_mutation(
                bundle,
                requirement,
                common,
                case,
                expected,
                mutation,
            )?;
            trace.record(
                Stage::Prepare,
                StageStatus::Ok,
                format!("the {mutation:?} request mutation is refused, as the case requires"),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        let resolved = resolve_offline_fixture_authorization(
            bundle,
            requirement,
            Some(common),
            case,
            OFFLINE_AUDIENCE,
        )
        .map_err(|error| fixture_failure(error, "reference fixture subjects did not resolve"))?;
        let source = bundle
            .config
            .sources
            .get(requirement.initial_source())
            .ok_or(CliError("reference fixture source is unavailable"))?;
        let source_plan = match &statement_source {
            Some((executor, _)) => executor,
            None => source_plans
                .get(requirement.initial_source())
                .ok_or(CliError("reference fixture source plan is unavailable"))?,
        };
        let preparation_selectors = fixture_selector_value(&resolved, source.selector_inputs())?;
        let prepared = match kernel.prepare(&requirement.id, &preparation_selectors) {
            Ok(prepared) => prepared,
            Err(error) if case.contains_key("selectorOverrides") => {
                trace.record(
                    Stage::Prepare,
                    StageStatus::Failed,
                    "the overridden selectors are refused before the credential boundary",
                );
                validate_reference_error(expected, error, false)?;
                if expected.get("rejectedBefore").and_then(Value::as_str) != Some("credential") {
                    return Err(CliError(
                        "reference preparation rejection boundary did not match",
                    ));
                }
                require_reference_request_count(expected, 0)?;
                summary.evaluated_cases += 1;
                trace.pass_case();
                continue;
            }
            Err(_) => return Err(CliError("reference fixture request preparation failed")),
        };
        if !case.contains_key("selectorOverrides") {
            validate_reference_request_parts(common, &prepared)?;
        }
        let source_selectors = reference_source_selectors(&resolved, source.selector_inputs())?;
        validate_reference_transport(
            source,
            source_plan,
            &source_selectors,
            &prepared,
            common
                .get("expectedTransport")
                .and_then(Value::as_object)
                .ok_or(CliError("reference transport expectation is invalid"))?,
        )?;
        if let Some(transport) = expected.get("expectedTransport").and_then(Value::as_object) {
            validate_reference_transport(
                source,
                source_plan,
                &source_selectors,
                &prepared,
                transport,
            )?;
        }
        trace.record(
            Stage::Prepare,
            StageStatus::Ok,
            format!(
                "the request for source {:?} matches its declared transport",
                requirement.initial_source()
            ),
        );
        if case.contains_key("selectorOverrides") {
            if expected.contains_key("error")
                || expected.contains_key("publicProblem")
                || expected.contains_key("rejectedBefore")
            {
                return Err(CliError(
                    "reference successful preparation contradicts its expectation",
                ));
            }
            require_reference_request_count(expected, 1)?;
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        let derivation_selectors =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
        if let Some(expected_selectors) = common.get("derivationSelectorInputs") {
            if expected_selectors != &derivation_selectors {
                return Err(CliError("reference derivation selectors did not match"));
            }
        } else if derivation_selectors != Value::Object(JsonMap::new()) {
            return Err(CliError(
                "reference derivation selectors were not minimized",
            ));
        }
        if let Some(failure) = case.get("sourceFailure").and_then(Value::as_str) {
            validate_reference_source_failure(source, failure, expected)?;
            trace.record(
                Stage::Acquire,
                StageStatus::Failed,
                format!("the source failed as {failure:?}, which the case states"),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        if let Some(declared) = case.get("declaredUnresolved") {
            validate_reference_declared_unresolved(source, declared, expected)?;
            trace.record(
                Stage::Acquire,
                StageStatus::Unresolved,
                "the source returned its exact declared unresolved outcome",
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        let observed_at = fixture_observed_at(
            case,
            Some(common),
            requirement.observation_timezone.as_deref(),
        )?;
        if let Some(mutation) = case.get("derivationMutation").and_then(Value::as_str) {
            validate_reference_derivation_mutation(kernel, requirement, expected, mutation)?;
            trace.record(
                Stage::Derive,
                StageStatus::Ok,
                format!("the {mutation:?} derivation mutation is refused, as the case requires"),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }
        if let Some(mutation) = case
            .get("derivationParameterMutation")
            .and_then(Value::as_object)
        {
            validate_reference_parameter_mutation(
                bundle,
                requirement,
                cases,
                mutation,
                &derivation_selectors,
                observed_at,
                expected,
            )?;
            trace.record(
                Stage::Derive,
                StageStatus::Ok,
                format!(
                    "the derivation parameter mutation over {} is refused, as the case requires",
                    name_list(&mutation.keys().cloned().collect::<Vec<_>>())
                ),
            );
            summary.evaluated_cases += 1;
            trace.pass_case();
            continue;
        }

        let response_context = ReferenceResponseContext {
            bundle,
            kernel,
            signer,
            requirement,
            resolved: &resolved,
        };
        let (values, source_request_count) = match &requirement.acquisition {
            AcquisitionConfig::Single { .. } => {
                let acquired = format!("1 response from source {:?}", requirement.initial_source());
                let projected = match &statement_source {
                    // The statement runs against the fixture's own extract, so
                    // what the extraction script sees is what the reviewed SQL
                    // actually returned rather than what a fixture said it would.
                    // A statement that will not complete is an outcome a case
                    // may state, because the extract it reads is stated too.
                    Some((executor, _)) => {
                        match executor
                            .execute(&source_selectors, &prepared, observed_at)
                            .await
                        {
                            Ok(response) => record_projection(
                                trace,
                                response.into_data().ok_or(SourceError::ProblemMismatch),
                                &acquired,
                                CliError("reference fixture source projection failed"),
                            )?,
                            Err(error) => {
                                trace.record(
                                    Stage::Acquire,
                                    StageStatus::Failed,
                                    format!("{acquired}, and the statement did not complete it"),
                                );
                                validate_reference_source_error(expected, &error)?;
                                require_reference_request_count(expected, 1)?;
                                summary.evaluated_cases += 1;
                                trace.pass_case();
                                continue;
                            }
                        }
                    }
                    None => {
                        let response = case
                            .get("response")
                            .ok_or(CliError("reference fixture response is unavailable"))?;
                        record_projection(
                            trace,
                            project_fixture_response(source, response),
                            &acquired,
                            CliError("reference fixture source projection failed"),
                        )?
                    }
                };
                (
                    validate_reference_response(
                        response_context,
                        &projected,
                        &derivation_selectors,
                        observed_at,
                        expected,
                        trace,
                    )
                    .await?,
                    1,
                )
            }
            AcquisitionConfig::SearchThenFetch { search, fetch } => {
                let responses = case
                    .get("responses")
                    .and_then(Value::as_object)
                    .ok_or(CliError("reference chained responses are unavailable"))?;
                if responses.len() != 2
                    || !responses.contains_key(search)
                    || !responses.contains_key(fetch)
                {
                    return Err(CliError("reference chained responses are not exact"));
                }
                let search_response = responses
                    .get(search)
                    .ok_or(CliError("reference search response is unavailable"))?;
                let projected_search = record_projection(
                    trace,
                    project_fixture_response(source, search_response),
                    &format!("search response from {search:?}"),
                    CliError("reference search response projection failed"),
                )?;
                let prior_facts = match record_lookup(
                    trace,
                    kernel.extract_source(search, &projected_search, &BTreeMap::new()),
                    &projected_search,
                ) {
                    Ok(facts) => facts,
                    Err(settled) => {
                        match settled {
                            Ok(KernelOutcome::NoMatch) => {
                                validate_reference_unresolved(expected, "no_match")?
                            }
                            Ok(KernelOutcome::Ambiguous) => {
                                validate_reference_unresolved(expected, "ambiguous")?
                            }
                            Ok(KernelOutcome::Match(_)) => {
                                return Err(CliError(
                                    "reference search settled on an unreachable outcome",
                                ));
                            }
                            Err(error) => validate_reference_error(expected, error, false)?,
                        }
                        require_reference_request_count(expected, 1)?;
                        summary.evaluated_cases += 1;
                        trace.pass_case();
                        continue;
                    }
                };
                let fetch_source = bundle
                    .config
                    .sources
                    .get(fetch)
                    .ok_or(CliError("reference fetch source is unavailable"))?;
                let fetch_plan = source_plans
                    .get(fetch)
                    .ok_or(CliError("reference fetch source plan is unavailable"))?;
                let fetch_preparation_selectors =
                    fixture_selector_value(&resolved, fetch_source.selector_inputs())?;
                let fetch_parts = kernel
                    .prepare_source(fetch, &fetch_preparation_selectors, &prior_facts)
                    .map_err(|_| CliError("reference fetch request preparation failed"))?;
                validate_reference_request_parts_named(
                    common,
                    "expectedFetchRequestParts",
                    &fetch_parts,
                )?;
                let fetch_selectors =
                    reference_source_selectors(&resolved, fetch_source.selector_inputs())?;
                validate_reference_transport_with_prior_facts(
                    fetch_source,
                    fetch_plan,
                    &fetch_selectors,
                    &prior_facts,
                    &fetch_parts,
                    common
                        .get("expectedFetchTransport")
                        .and_then(Value::as_object)
                        .ok_or(CliError("reference fetch transport expectation is invalid"))?,
                )?;
                let fetch_response = responses
                    .get(fetch)
                    .ok_or(CliError("reference fetch response is unavailable"))?;
                let projected_fetch = record_projection(
                    trace,
                    project_fixture_response(fetch_source, fetch_response),
                    &format!("fetch response from {fetch:?}"),
                    CliError("reference fetch response projection failed"),
                )?;
                let fetch_lookup =
                    match kernel.extract_source(fetch, &projected_fetch, &prior_facts) {
                        Ok(LookupResult::NoMatch | LookupResult::Ambiguous) => {
                            trace.record_with(
                                Stage::Extract,
                                StageStatus::Failed,
                                "a fetch may only resolve uniquely, and this one did not",
                                vec![format!(
                                    "fetch response keys available {}",
                                    name_list(&object_keys(&projected_fetch))
                                )],
                            );
                            validate_reference_error(expected, KernelError::SourceProtocol, false)?;
                            require_reference_request_count(expected, 2)?;
                            summary.evaluated_cases += 1;
                            trace.pass_case();
                            continue;
                        }
                        Ok(lookup) => lookup,
                        Err(error) => {
                            trace.record_with(
                                Stage::Extract,
                                StageStatus::Failed,
                                format!("the fetch extraction failed: {error}"),
                                vec![format!(
                                    "fetch response keys available {}",
                                    name_list(&object_keys(&projected_fetch))
                                )],
                            );
                            validate_reference_error(expected, error, false)?;
                            require_reference_request_count(expected, 2)?;
                            summary.evaluated_cases += 1;
                            trace.pass_case();
                            continue;
                        }
                    };
                (
                    validate_reference_lookup(
                        &response_context,
                        Ok(fetch_lookup),
                        &Value::Object(responses.clone()),
                        &derivation_selectors,
                        observed_at,
                        expected,
                        trace,
                    )
                    .await?,
                    2,
                )
            }
            // Reference fixtures replay one transport expectation per named
            // call, and the fetch-set form has no reference-fixture shape.
            AcquisitionConfig::SearchThenFetchSet { .. } => {
                return Err(CliError(
                    "fetch-set requirements have no reference fixture form",
                ));
            }
        };
        if let Some(values) = values {
            successful_values.push(values);
        }
        require_reference_request_count(expected, source_request_count)?;
        summary.evaluated_cases += 1;
        trace.pass_case();
    }

    validate_reference_privacy(
        fixture,
        requirement,
        &successful_values,
        &explain_surfaces(trace)?,
    )?;
    Ok(summary)
}

struct ReferenceResponseContext<'a> {
    bundle: &'a Bundle,
    kernel: &'a OfflineKernel,
    signer: Option<&'a EvidenceSigner>,
    requirement: &'a registry_evidence::config::RequirementConfig,
    resolved: &'a ResolvedAuthorization,
}

async fn validate_reference_response(
    context: ReferenceResponseContext<'_>,
    response: &Value,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
    trace: &mut FixtureTrace,
) -> Result<Option<Value>, CliError> {
    validate_reference_lookup(
        &context,
        context.kernel.extract(&context.requirement.id, response),
        response,
        selectors,
        observed_at,
        expected,
        trace,
    )
    .await
}

/// Check one reference lookup, recording it through the same helpers the
/// acceptance path records with.
///
/// A reader comparing an adopter's reference run against an acceptance run has
/// to see one vocabulary for one event, so the stage lines come from
/// `record_lookup` and `record_derivation` rather than from a second wording of
/// the same outcomes here.
async fn validate_reference_lookup(
    context: &ReferenceResponseContext<'_>,
    lookup: Result<LookupResult, KernelError>,
    protected_response: &Value,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
    trace: &mut FixtureTrace,
) -> Result<Option<Value>, CliError> {
    let facts = match record_lookup(trace, lookup, protected_response) {
        Ok(facts) => facts,
        Err(Ok(KernelOutcome::NoMatch)) => {
            validate_reference_unresolved(expected, "no_match")?;
            return Ok(None);
        }
        Err(Ok(KernelOutcome::Ambiguous)) => {
            validate_reference_unresolved(expected, "ambiguous")?;
            return Ok(None);
        }
        Err(Ok(KernelOutcome::Match(_))) => {
            return Err(CliError(
                "reference lookup settled on an unreachable outcome",
            ));
        }
        Err(Err(error)) => {
            validate_reference_error(expected, error, false)?;
            return Ok(None);
        }
    };
    if expected.get("lookup").and_then(Value::as_str) != Some("match") {
        return Err(CliError("reference lookup outcome did not match"));
    }
    if let Some(exact) = expected.get("facts") {
        let actual = serde_json::to_value(&facts)
            .map_err(|_| CliError("reference facts are not representable"))?;
        if exact != &actual {
            return Err(CliError("reference exact facts did not match"));
        }
    }
    let values = match record_derivation(
        trace,
        context.kernel.derive_and_validate_with_selectors(
            &context.requirement.id,
            &facts,
            selectors,
            observed_at,
            ValueProjection {
                scope: EvidenceScope::AudienceScoped {
                    audience: OFFLINE_AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                binding_key: &OFFLINE_BINDING_KEY,
                binding_key_version: 1,
            },
        ),
        context.requirement,
    ) {
        Ok(KernelOutcome::Match(values)) => values,
        Ok(_) => {
            return Err(CliError(
                "reference derivation settled on an unreachable outcome",
            ));
        }
        Err(error) => {
            validate_reference_error(expected, error, true)?;
            return Ok(None);
        }
    };
    if expected.get("derivationRuns").and_then(Value::as_bool) != Some(true) {
        return Err(CliError("reference derivation execution did not match"));
    }
    if let Some(exact) = expected.get("value") {
        if values.as_slice().len() != 1 || public_json(&values.as_slice()[0].value)? != *exact {
            return Err(CliError("reference scalar value did not match"));
        }
    }
    if let Some(exact) = expected.get("values") {
        let exact = exact
            .as_object()
            .ok_or(CliError("reference concept map is invalid"))?;
        if values.as_slice().len() != exact.len() {
            return Err(CliError("reference concept value did not match"));
        }
        for (concept, expected_value) in exact {
            let disclosed = values
                .as_slice()
                .iter()
                .find(|value| value.provides_value_for == *concept)
                .ok_or(CliError("reference concept value did not match"))?;
            if public_json(&disclosed.value)? != *expected_value {
                return Err(CliError("reference concept value did not match"));
            }
        }
    }
    if let Some(count) = expected.get("entityReferenceCount").and_then(Value::as_u64) {
        let actual = match values.as_slice() {
            [value] => match &value.value {
                PublicValue::List(items) => items
                    .iter()
                    .filter(|item| matches!(item, ScalarOrEntityReference::EntityReference(_)))
                    .count() as u64,
                _ => 0,
            },
            _ => 0,
        };
        if actual != count {
            return Err(CliError("reference entity-reference count did not match"));
        }
    }
    if expected
        .get("rawReferencesDisclosed")
        .and_then(Value::as_bool)
        == Some(false)
    {
        let encoded = serde_json::to_string(values.as_slice())
            .map_err(|_| CliError("reference values are not representable"))?;
        let mut protected_source_strings = Vec::new();
        collect_strings(protected_response, &mut protected_source_strings);
        if protected_source_strings
            .iter()
            .filter(|value| value.len() >= 8)
            .any(|value| encoded.contains(value))
        {
            return Err(CliError("reference raw source reference was disclosed"));
        }
    }
    if expected.get("signed").and_then(Value::as_bool) != Some(true) {
        return Err(CliError("reference signing expectation did not match"));
    }
    let evidence = sign_and_verify_fixture_evidence(
        context.bundle,
        context.kernel,
        context.signer,
        context.requirement,
        context.resolved,
        values,
        observed_at,
    )
    .await?;
    trace.record(
        Stage::Sign,
        StageStatus::Ok,
        if context.signer.is_some() {
            "the payload was constructed, signed, and verified offline"
        } else {
            "the payload was constructed; this seam does not sign"
        },
    );
    Ok(Some(evidence))
}

async fn sign_and_verify_fixture_evidence(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    signer: Option<&EvidenceSigner>,
    requirement: &registry_evidence::config::RequirementConfig,
    resolved: &ResolvedAuthorization,
    values: ValidatedValues,
    observed_at: DateTime<Utc>,
) -> Result<Value, CliError> {
    let subjects = resolved
        .subjects
        .iter()
        .map(|subject| {
            Ok(SubjectBinding {
                role: subject.role.clone(),
                binding: subject
                    .binding(
                        &OFFLINE_BINDING_KEY,
                        1,
                        &bundle.config.service.trust_domain,
                        registry_evidence::binding::SubjectBindingScope::Audience(OFFLINE_AUDIENCE),
                        &resolved.purpose,
                    )
                    .map_err(|_| CliError("fixture subject binding failed"))?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let issued_at = observed_at + chrono::Duration::seconds(1);
    let evidence_id = format!("urn:ulid:{}", ulid::Ulid::new());
    let evidence = kernel
        .construct_evidence(
            &requirement.id,
            values,
            EvidenceConstruction {
                evidence_id: &evidence_id,
                purpose: &resolved.purpose,
                scope: EvidenceScope::AudienceScoped {
                    audience: OFFLINE_AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                issued_at,
                observed_at,
                subjects,
            },
        )
        .map_err(|_| CliError("fixture evidence construction failed"))?;
    let Some(signer) = signer else {
        return serde_json::to_value(evidence)
            .map_err(|_| CliError("fixture evidence is not representable"));
    };
    let signed = signer
        .sign_json(&evidence)
        .await
        .map_err(|_| CliError("fixture evidence signing failed"))?;
    let jwks = jwks_document(signer.public_jwk(), [])
        .map_err(|_| CliError("fixture verification key construction failed"))?;
    let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &evidence,
        registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
        registry_evidence::verifier::MAXIMUM_ASSERTION_LIFETIME_SECONDS,
        issued_at,
        0,
    )
    .map_err(|_| CliError("fixture verification policy is outside its contract bounds"))?;
    policy.issued_by = bundle.config.issuer.id.clone();
    policy.provided_by = bundle.config.service.provider_id.clone();
    policy.requirement = requirement.id.clone();
    policy.evidence_type = requirement.evidence_type.clone();
    policy.purpose = resolved.purpose.clone();
    policy.audience = OFFLINE_AUDIENCE.to_owned();
    policy.configuration_revision = bundle
        .configuration_revision(&requirement.id)
        .ok_or(CliError(
            "fixture requirement has no configuration revision",
        ))?
        .to_owned();
    let verified = verify_flattened_jws(
        &serde_json::to_vec(&signed)
            .map_err(|_| CliError("fixture signed evidence is not representable"))?,
        &jwks,
        &policy,
    )
    .map_err(|_| CliError("fixture signed evidence verification failed"))?;
    serde_json::to_value(verified)
        .map_err(|_| CliError("fixture verified evidence is not representable"))
}

async fn offline_fixture_signer() -> Result<EvidenceSigner, CliError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let signing_key = SigningKey::random(&mut OsRng);
    let private_bytes = Zeroizing::new(signing_key.to_bytes());
    let public = signing_key.verifying_key().to_encoded_point(false);
    let mut private_jwk = PrivateJwk {
        kty: "EC".to_owned(),
        kid: None,
        alg: Some("ES256".to_owned()),
        crv: Some("P-256".to_owned()),
        d: Some(URL_SAFE_NO_PAD.encode(&private_bytes[..])),
        x: Some(
            URL_SAFE_NO_PAD.encode(
                public
                    .x()
                    .ok_or(CliError("offline fixture public key is invalid"))?,
            ),
        ),
        y: Some(
            URL_SAFE_NO_PAD.encode(
                public
                    .y()
                    .ok_or(CliError("offline fixture public key is invalid"))?,
            ),
        ),
        n: None,
        e: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
    };
    let key_id = private_jwk
        .public()
        .jkt()
        .map_err(|_| CliError("offline fixture key identifier derivation failed"))?;
    private_jwk.kid = Some(key_id.clone());
    let provider = Arc::new(
        LocalJwkSigner::new(private_jwk)
            .map_err(|_| CliError("offline fixture signer initialization failed"))?,
    );
    EvidenceSigner::initialize(provider, &key_id)
        .await
        .map_err(|_| CliError("offline fixture signer self-test failed"))
}

fn validate_reference_unresolved(
    expected: &JsonMap<String, Value>,
    lookup: &str,
) -> Result<(), CliError> {
    if expected.get("lookup").and_then(Value::as_str) != Some(lookup)
        || expected.get("derivationRuns").and_then(Value::as_bool) != Some(false)
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
        || expected.get("publicProblem").and_then(Value::as_str) != Some("evidence.unavailable")
    {
        return Err(CliError("reference unresolved outcome did not match"));
    }
    Ok(())
}

fn validate_reference_expectation_keys(
    form: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let allowed: &[&str] = match form {
        "response" | "responses" | "selectors" => &[
            "lookup",
            "facts",
            "value",
            "values",
            "entityReferenceCount",
            "rawReferencesDisclosed",
            "signed",
            "publicProblem",
            "error",
            "derivationRuns",
            "sourceRequestCount",
        ],
        "sourceFailure" => &["publicProblem", "signed", "sourceRequestCount"],
        "declaredUnresolved" => &[
            "publicProblem",
            "signed",
            "derivationRuns",
            "sourceRequestCount",
        ],
        "bundleMutation" | "statementMutation" => &["bundle"],
        "requestMutation" => &["rejectedBefore", "signed", "sourceRequestCount"],
        "derivationMutation" => &["outputGate", "signed"],
        "derivationParameterMutation" => &["error", "publicProblem", "signed", "derivationRuns"],
        "selectorOverrides" => &[
            "expectedTransport",
            "error",
            "publicProblem",
            "signed",
            "rejectedBefore",
            "sourceRequestCount",
        ],
        _ => return Err(CliError("reference fixture case form is unknown")),
    };
    require_allowed_keys(expected, allowed)
}

fn validate_reference_error(
    expected: &JsonMap<String, Value>,
    error: KernelError,
    derivation_ran: bool,
) -> Result<(), CliError> {
    let (internal, public_problem) = match error {
        KernelError::Preparation => ("adapter_input_error", "service.unavailable"),
        KernelError::SourceProtocol => ("source_protocol_error", "source.unavailable"),
        // Derivation-input inconsistency over a uniquely found record
        // collapses publicly with the unresolved classes; the internal
        // category stays a value-free operator diagnostic.
        KernelError::DerivationInput => ("derivation_input_error", "evidence.unavailable"),
        KernelError::Script if derivation_ran => ("derivation_input_error", "service.unavailable"),
        KernelError::Extraction => ("evidence_not_available", "evidence.unavailable"),
        _ => ("service_unavailable", "service.unavailable"),
    };
    let expected_error = expected.get("error").and_then(Value::as_str);
    let expected_problem = expected.get("publicProblem").and_then(Value::as_str);
    if expected_error.is_none() && expected_problem.is_none() {
        return Err(CliError("reference failing case has no exact expectation"));
    }
    if expected_error.is_some_and(|expected| expected != internal) {
        return Err(CliError("reference internal error did not match"));
    }
    if expected_problem.is_some_and(|expected| expected != public_problem) {
        return Err(CliError("reference public problem did not match"));
    }
    if expected.get("signed").and_then(Value::as_bool) != Some(false) {
        return Err(CliError(
            "reference failed case signing expectation did not match",
        ));
    }
    if expected.get("derivationRuns").and_then(Value::as_bool) != Some(derivation_ran) {
        return Err(CliError("reference derivation execution did not match"));
    }
    Ok(())
}

/// A prepared value as a fixture writes it.
fn selector_value_json(value: &SelectorValue) -> Value {
    match value {
        SelectorValue::String(text) => Value::String(text.clone()),
        SelectorValue::Integer(number) => Value::Number((*number).into()),
        SelectorValue::Boolean(flag) => Value::Bool(*flag),
    }
}

/// Compare a statement's parameters against a fixture expectation, exactly.
///
/// The runtime's own evaluation instant is never among them. It is bound where
/// the statement executes rather than where its parameters are assembled, so a
/// fixture neither states it nor could replace it.
fn validate_reference_statement_parameters(
    expected: &JsonMap<String, Value>,
    actual: &BTreeMap<String, SelectorValue>,
) -> Result<(), CliError> {
    if expected.len() != actual.len() {
        return Err(CliError("reference statement parameters did not match"));
    }
    for (name, value) in actual {
        if expected.get(name) != Some(&selector_value_json(value)) {
            return Err(CliError("reference statement parameters did not match"));
        }
    }
    Ok(())
}

fn validate_reference_request_parts(
    common: &JsonMap<String, Value>,
    actual: &PreparedSourceRequest,
) -> Result<(), CliError> {
    validate_reference_request_parts_named(common, "expectedRequestParts", actual)
}

fn validate_reference_request_parts_named(
    common: &JsonMap<String, Value>,
    expectation_name: &str,
    actual: &PreparedSourceRequest,
) -> Result<(), CliError> {
    let expected = common
        .get(expectation_name)
        .and_then(Value::as_object)
        .ok_or(CliError("reference request-parts expectation is invalid"))?;
    // Preparation produces what its transport consumes, so the expectation is
    // written in the same terms: a query and a body for an HTTP request, and
    // the parameters a statement will be given for a statement source. A source
    // whose parameters all come from declared bindings prepares none, and
    // stating that empty map is what proves no script added one.
    let actual = match actual {
        PreparedSourceRequest::Http(parts) => parts,
        PreparedSourceRequest::Statement(prepared) => {
            require_exact_keys(expected, &["parameters"])?;
            let parameters = expected
                .get("parameters")
                .and_then(Value::as_object)
                .ok_or(CliError("reference parameter expectation is invalid"))?;
            return validate_reference_statement_parameters(parameters, &prepared.parameters);
        }
    };
    require_exact_keys(expected, &["query", "body"])?;
    let query = expected
        .get("query")
        .and_then(Value::as_array)
        .ok_or(CliError("reference query expectation is invalid"))?;
    if query.len() != actual.query.len() {
        return Err(CliError("reference prepared query did not match"));
    }
    for (expected, actual) in query.iter().zip(&actual.query) {
        let expected = expected
            .as_object()
            .ok_or(CliError("reference query-pair expectation is invalid"))?;
        require_exact_keys(expected, &["name", "value"])?;
        if expected.get("name").and_then(Value::as_str) != Some(&actual.name)
            || expected.get("value").and_then(Value::as_str) != Some(&actual.value)
        {
            return Err(CliError("reference prepared query did not match"));
        }
    }
    let expected_body = expected.get("body").filter(|body| !body.is_null());
    if expected_body != actual.body.as_ref() {
        return Err(CliError("reference prepared body did not match"));
    }
    Ok(())
}

fn validate_reference_transport(
    source: &registry_evidence::config::SourceConfig,
    source_plan: &SourceExecutor,
    selectors: &[ResolvedSourceSelector],
    request: &PreparedSourceRequest,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    validate_reference_transport_with_prior_facts(
        source,
        source_plan,
        selectors,
        &BTreeMap::new(),
        request,
        expected,
    )
}

fn validate_reference_transport_with_prior_facts(
    source: &registry_evidence::config::SourceConfig,
    source_plan: &SourceExecutor,
    selectors: &[ResolvedSourceSelector],
    prior_facts: &BTreeMap<String, Value>,
    request: &PreparedSourceRequest,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let materialized = source_plan
        .materialize_request_with_prior_facts(selectors, prior_facts, request)
        .map_err(|_| CliError("reference transport materialization failed"))?;
    // A transport expectation names what actually crosses the boundary. For a
    // statement source that is the reviewed artifact and the values bound into
    // it, which is why the artifact path is asserted rather than its SQL: the
    // text is reviewed in the bundle, and restating it here would only give a
    // fixture a second copy to drift from.
    if let MaterializedSourceRequest::Sqlite { parameters, .. } = &materialized {
        require_allowed_keys(expected, &["statement", "parameters"])?;
        if let Some(statement) = expected.get("statement").and_then(Value::as_str) {
            if source.statement().map(ArtifactPath::as_str) != Some(statement) {
                return Err(CliError("reference statement artifact did not match"));
            }
        }
        if let Some(expected) = expected.get("parameters").and_then(Value::as_object) {
            validate_reference_statement_parameters(expected, parameters)?;
        }
        return Ok(());
    }
    require_allowed_keys(expected, &["path", "query", "body", "fixedHeaders"])?;
    if expected
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|path| materialized.path() != Some(path))
    {
        return Err(CliError("reference materialized path did not match"));
    }
    if let Some(query) = expected.get("query").and_then(Value::as_str) {
        if materialized.query().unwrap_or_default() != query {
            return Err(CliError("reference encoded query did not match"));
        }
    }
    if let Some(body) = expected.get("body").filter(|body| !body.is_null()) {
        if materialized.body() != Some(body) {
            return Err(CliError("reference transport body did not match"));
        }
    }
    if let Some(headers) = expected.get("fixedHeaders").and_then(Value::as_array) {
        if headers.len() != source.fixed_headers().len() {
            return Err(CliError("reference fixed headers did not match"));
        }
        for (expected, actual) in headers.iter().zip(source.fixed_headers()) {
            let expected = expected
                .as_object()
                .ok_or(CliError("reference fixed-header expectation is invalid"))?;
            require_exact_keys(expected, &["name", "value"])?;
            if expected.get("name").and_then(Value::as_str) != Some(&actual.name)
                || expected.get("value").and_then(Value::as_str) != Some(&actual.value)
            {
                return Err(CliError("reference fixed headers did not match"));
            }
        }
    }
    Ok(())
}

fn reference_source_selectors(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Vec<ResolvedSourceSelector>, CliError> {
    inputs
        .iter()
        .map(|input| {
            let subject = resolved
                .subjects
                .iter()
                .find(|subject| subject.role == input.role)
                .ok_or(CliError("reference source selector role is unavailable"))?;
            let alternative = input
                .alternatives
                .iter()
                .find(|alternative| alternative.profile == subject.selector_profile)
                .ok_or(CliError("reference source selector profile is invalid"))?;
            let values = alternative
                .fields
                .iter()
                .map(|name| {
                    let field = subject
                        .fields
                        .iter()
                        .find(|field| &field.name == name)
                        .ok_or(CliError("reference source selector field is unavailable"))?;
                    let value = match &field.value {
                        ResolvedSelectorValue::String(value)
                        | ResolvedSelectorValue::Date(value)
                        | ResolvedSelectorValue::ControlledCode(value) => {
                            SelectorValue::String(value.clone())
                        }
                        ResolvedSelectorValue::Integer(value) => SelectorValue::Integer(*value),
                        ResolvedSelectorValue::Boolean(value) => SelectorValue::Boolean(*value),
                    };
                    Ok((name.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>, CliError>>()?;
            Ok(ResolvedSourceSelector {
                role: input.role.clone(),
                profile: alternative.profile.clone(),
                values,
            })
        })
        .collect()
}

/// The closed mock failures a source may be stated to have, per transport.
///
/// A transport can only fail in the ways it has. A refused connection, a wrong
/// media type, and malformed JSON describe a network answer and say nothing
/// about a local file, so a statement source is refused those symbols rather
/// than passing a case that cannot happen. A timeout and an oversized result
/// belong to both, because both admit under a concurrency bound and both hold
/// the assembled result to a declared size.
///
/// Every symbol also has to be a failure a served request can reach. An extract
/// that cannot be opened, unusable extract metadata, and a statement the
/// authorizer refuses are all settled while the source is compiled, before a
/// listener binds, so they are startup failures with no request-time symbol
/// here: a case stating one would teach a served behaviour the runtime does not
/// have.
fn reference_source_failure_error(
    source: &registry_evidence::config::SourceConfig,
    failure: &str,
) -> Result<SourceError, CliError> {
    let statement = source.statement().map(ArtifactPath::as_str);
    let fault = |cause: &'static str| {
        ArtifactFault::new(statement.unwrap_or_default(), SchemaFault::because(cause))
    };
    Ok(match (failure, statement) {
        ("timeout", _) => SourceError::Timeout,
        ("oversized", _) => SourceError::ResponseTooLarge,
        ("connection-refused", None) => SourceError::Transport,
        ("invalid-media-type", None) => SourceError::WrongMediaType,
        ("malformed-json", None) => SourceError::InvalidJson,
        ("extract-too-old", Some(_)) => {
            SourceError::ExtractTooOld(fault(sqlite_cause::EXTRACT_TOO_OLD))
        }
        ("statement-parameter", Some(_)) => {
            SourceError::StatementParameter(fault(sqlite_cause::MISSING_PARAMETER))
        }
        ("statement-budget", Some(_)) => {
            SourceError::StatementBudget(fault(sqlite_cause::STEP_BUDGET_EXCEEDED))
        }
        ("statement-result", Some(_)) => {
            SourceError::StatementResult(fault(sqlite_cause::TOO_MANY_ROWS))
        }
        ("statement-unavailable", Some(_)) => SourceError::StatementUnavailable,
        _ => return Err(CliError("reference source-failure name is invalid")),
    })
}

fn validate_reference_source_failure(
    source: &registry_evidence::config::SourceConfig,
    failure: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let error = reference_source_failure_error(source, failure)?;
    validate_reference_source_error(expected, &error)?;
    require_reference_request_count(expected, 1)
}

/// Validate the data-free fixture representation of the exact configured
/// non-2xx outcome. The tuple and Problem Details members remain owned by the
/// source configuration and HTTP contract tests; a fixture cannot restate or
/// leak them into extraction, diagnostics, or an assertion.
fn validate_reference_declared_unresolved(
    source: &registry_evidence::config::SourceConfig,
    declared: &Value,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    if declared.as_bool() != Some(true) {
        return Err(CliError(
            "reference declared-unresolved marker must be true",
        ));
    }
    if source.unresolved_problem().is_none() {
        return Err(CliError(
            "reference declared unresolved without a source declaration",
        ));
    }
    if expected.get("publicProblem").and_then(Value::as_str) != Some("evidence.unavailable")
        || expected.get("derivationRuns").and_then(Value::as_bool) != Some(false)
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError(
            "reference declared-unresolved outcome did not match",
        ));
    }
    require_reference_request_count(expected, 1)
}

/// A source that did not complete carries one public class, whichever transport
/// it was and whether the case stated the failure or the run produced it.
fn validate_reference_source_error(
    expected: &JsonMap<String, Value>,
    error: &SourceError,
) -> Result<(), CliError> {
    if source_failure_problem(error) != ProblemCode::DependencyUnavailable
        || expected.get("publicProblem").and_then(Value::as_str) != Some("source.unavailable")
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
        || expected
            .get("derivationRuns")
            .is_some_and(|runs| runs.as_bool() != Some(false))
    {
        return Err(CliError("reference source-failure mapping is invalid"));
    }
    Ok(())
}

/// Refuse a statement the authorizer must never accept.
///
/// A refused statement is a bundle fault, not a request-time one: it is settled
/// while the source is compiled, before a listener binds and before any fixture
/// case runs. The mutation is applied to a disposable copy of the reviewed
/// statement, so the project's own artifact is untouched.
fn validate_reference_statement_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    mutation: &str,
) -> Result<(), CliError> {
    let source = bundle
        .config
        .sources
        .get(requirement.initial_source())
        .ok_or(CliError("reference fixture source is unavailable"))?;
    let mutated = match mutation {
        "attach-external-database" => "ATTACH DATABASE 'sidecar.sqlite' AS sidecar;",
        _ => return Err(CliError("reference statement mutation is unknown")),
    };
    let Err(error) = check_statement_offline(source, mutated) else {
        return Err(CliError("reference mutated statement was not refused"));
    };
    if error.cause() != Some(sqlite_cause::AUTHORIZER_REFUSED) {
        return Err(CliError(
            "reference mutated statement failed for another reason",
        ));
    }
    Ok(())
}

fn validate_reference_bundle_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
) -> Result<(), CliError> {
    let mut mutated = bundle.config.clone();
    let mut companion = requirement.clone();
    companion.handle.push_str("-fixture-companion");
    companion.id.push_str(":fixture-companion");
    companion.evidence_type.push_str(":fixture-companion");
    for concept in &mut companion.concepts {
        concept.handle.push_str("-fixture-companion");
        concept.id.push_str(":fixture-companion");
    }
    mutated.requirements.push(companion);
    if mutated.validate()
        != Err(ConfigError::Invalid(
            "enabled requirements share a disclosure family",
        ))
    {
        return Err(CliError(
            "reference unsafe bundle mutation was not rejected",
        ));
    }
    Ok(())
}

fn validate_reference_request_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    common: &JsonMap<String, Value>,
    case: &JsonMap<String, Value>,
    expected: &JsonMap<String, Value>,
    mutation: &str,
) -> Result<(), CliError> {
    if expected.get("rejectedBefore").and_then(Value::as_str) != Some("source") {
        return Err(CliError("reference request rejection boundary is invalid"));
    }
    let selectors = common
        .get("selectors")
        .and_then(Value::as_object)
        .ok_or(CliError("reference selectors are invalid"))?;
    let mut subjects = selectors
        .iter()
        .map(|(role, selector)| {
            let mut selector = selector
                .as_object()
                .cloned()
                .ok_or(CliError("reference selector is invalid"))?;
            selector.insert("role".to_owned(), Value::String(role.clone()));
            Ok(Value::Object(selector))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    match mutation {
        "swap-subject-roles" if subjects.len() == 2 => {
            let first = subjects[0]["role"].clone();
            subjects[0]["role"] = subjects[1]["role"].clone();
            subjects[1]["role"] = first;
        }
        "supply-grant-derived-candidate" => {}
        _ => return Err(CliError("reference request-mutation name is invalid")),
    }
    let mut mutated = case.clone();
    mutated.insert("subjects".to_owned(), Value::Array(subjects));
    match resolve_offline_fixture_authorization(
        bundle,
        requirement,
        Some(common),
        &mutated,
        OFFLINE_AUDIENCE,
    ) {
        Ok(_) => return Err(CliError("reference request mutation was authorized")),
        Err(OfflineFixtureError::Purpose) => return Err(CliError(FIXTURE_PURPOSE_FAILURE)),
        Err(OfflineFixtureError::Authorization(_)) => {}
    }
    if expected.get("signed").and_then(Value::as_bool) != Some(false) {
        return Err(CliError("reference rejected request requires signing"));
    }
    require_reference_request_count(expected, 0)
}

fn validate_reference_derivation_mutation(
    kernel: &OfflineKernel,
    requirement: &registry_evidence::config::RequirementConfig,
    expected: &JsonMap<String, Value>,
    mutation: &str,
) -> Result<(), CliError> {
    if mutation != "return-raw-reference"
        || expected.get("outputGate").and_then(Value::as_str) != Some("rejected")
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError("reference derivation mutation is invalid"));
    }
    let injected = vec![DerivedConceptValue {
        concept_id: requirement.concepts[0].id.clone(),
        value: DerivedValue::Json(Value::String("PROTECTED-REFERENCE".to_owned())),
    }];
    if kernel
        .validate_values(
            &requirement.id,
            injected,
            ValueProjection {
                scope: EvidenceScope::AudienceScoped {
                    audience: OFFLINE_AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                binding_key: &OFFLINE_BINDING_KEY,
                binding_key_version: 1,
            },
        )
        .is_ok()
    {
        return Err(CliError(
            "reference derivation mutation crossed the output gate",
        ));
    }
    Ok(())
}

fn validate_reference_parameter_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    cases: &[Value],
    mutation: &JsonMap<String, Value>,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let mut disposable = bundle.clone();
    let mut config = serde_json::to_value(&disposable.config)
        .map_err(|_| CliError("reference configuration is not representable"))?;
    let target = config["requirements"]
        .as_array_mut()
        .and_then(|requirements| {
            requirements
                .iter_mut()
                .find(|candidate| candidate["id"].as_str() == Some(&requirement.id))
        })
        .ok_or(CliError("reference disposable requirement is unavailable"))?;
    let parameters = target["derivation"]["parameters"]
        .as_object_mut()
        .ok_or(CliError("reference derivation parameters are invalid"))?;
    for (name, value) in mutation {
        if !parameters.contains_key(name) {
            return Err(CliError("reference parameter mutation is unknown"));
        }
        parameters.insert(name.clone(), value.clone());
    }
    disposable.config = serde_json::from_value(config)
        .map_err(|_| CliError("reference parameter mutation is invalid"))?;
    disposable
        .config
        .validate()
        .map_err(|_| CliError("reference parameter mutation broke configuration"))?;
    let disposable = Arc::new(disposable);
    let kernel = OfflineKernel::compile(Arc::clone(&disposable))
        .map_err(|_| CliError("reference disposable kernel did not compile"))?;
    let disposable_requirement = disposable
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == requirement.id)
        .ok_or(CliError("reference disposable requirement is unavailable"))?;
    let positive = cases
        .iter()
        .find(|case| case.get("id").and_then(Value::as_str) == Some("positive"))
        .and_then(Value::as_object)
        .ok_or(CliError("reference positive case is unavailable"))?;
    let (reference_field, fixture_field) = match &disposable_requirement.acquisition {
        AcquisitionConfig::Single { .. } => ("response", "source"),
        AcquisitionConfig::SearchThenFetch { .. } => ("responses", "sources"),
        AcquisitionConfig::SearchThenFetchSet { .. } => {
            return Err(CliError(
                "fetch-set requirements have no reference fixture form",
            ))
        }
    };
    let response = positive
        .get(reference_field)
        .ok_or(CliError("reference positive response is unavailable"))?;
    let acquisition_case = JsonMap::from_iter([(fixture_field.to_owned(), response.clone())]);
    // The stages here belong to a deliberately broken copy of the bundle, not
    // to the case, so they are recorded and dropped rather than attributed.
    let outcome = evaluate_fixture_acquisition(
        &disposable,
        &kernel,
        disposable_requirement,
        &acquisition_case,
        selectors,
        observed_at,
        &mut FixtureTrace::default(),
    )?;
    match outcome {
        Err(error) => validate_reference_error(expected, error, true),
        Ok(_) => Err(CliError("reference parameter mutation did not fail")),
    }
}

fn require_reference_request_count(
    expected: &JsonMap<String, Value>,
    actual: u64,
) -> Result<(), CliError> {
    if expected
        .get("sourceRequestCount")
        .and_then(Value::as_u64)
        .is_some_and(|count| count != actual)
        || actual > 2
    {
        return Err(CliError("reference source request count did not match"));
    }
    Ok(())
}

fn validate_reference_privacy(
    fixture: &JsonMap<String, Value>,
    requirement: &registry_evidence::config::RequirementConfig,
    successful_values: &[Value],
    diagnostics: &[String],
) -> Result<(), CliError> {
    let source = fixture
        .get("privacyExpectation")
        .and_then(Value::as_object)
        .ok_or(CliError("reference privacy expectation is invalid"))?;
    require_exact_keys(
        source,
        &["evidenceContains", "evidenceExcludes", "diagnosticsExclude"],
    )?;
    let mut expectation = JsonMap::new();
    for (source_name, target_name) in [
        ("evidenceContains", "evidence_contains"),
        ("evidenceExcludes", "evidence_excludes"),
        ("diagnosticsExclude", "diagnostics_exclude"),
    ] {
        expectation.insert(
            target_name.to_owned(),
            source
                .get(source_name)
                .cloned()
                .ok_or(CliError("reference privacy expectation is incomplete"))?,
        );
    }
    let projection = serde_json::json!({
        "supportsRequirement": requirement.id,
        "isConformantTo": requirement.evidence_type,
        "subjectRoles": requirement
            .subject_roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        "successfulValues": successful_values,
    });
    validate_privacy_projection(&expectation, &projection, diagnostics)
}

const FIXTURE_PURPOSE_FAILURE: &str = "fixture does not select one of the requirement's purposes";

/// Report an unselected fixture purpose as its own failure so a harness
/// omission is never presented as a rejected request.
fn fixture_failure(error: OfflineFixtureError, authorization: &'static str) -> CliError {
    match error {
        OfflineFixtureError::Purpose => CliError(FIXTURE_PURPOSE_FAILURE),
        OfflineFixtureError::Authorization(_) => CliError(authorization),
    }
}

fn require_exact_keys(object: &JsonMap<String, Value>, expected: &[&str]) -> Result<(), CliError> {
    require_allowed_keys(object, expected)?;
    if expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(CliError("reference fixture required key is missing"));
    }
    Ok(())
}

fn require_allowed_keys(object: &JsonMap<String, Value>, allowed: &[&str]) -> Result<(), CliError> {
    if object
        .keys()
        .any(|key| !allowed.iter().any(|allowed| key == allowed))
    {
        return Err(CliError("reference fixture contains an unknown key"));
    }
    Ok(())
}

fn fixture_selector_value(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Value, CliError> {
    let mut selectors = JsonMap::new();
    for input in inputs {
        let subject = resolved
            .subjects
            .iter()
            .find(|subject| subject.role == input.role)
            .ok_or(CliError("fixture selector input role is unavailable"))?;
        let alternative = input
            .alternatives
            .iter()
            .find(|alternative| alternative.profile == subject.selector_profile)
            .ok_or(CliError("fixture selector input profile is unavailable"))?;
        let mut values = JsonMap::new();
        for name in &alternative.fields {
            let field = subject
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or(CliError("fixture selector input field is unavailable"))?;
            values.insert(name.clone(), field.value.as_json());
        }
        let mut selector = JsonMap::new();
        selector.insert(
            "profile".to_owned(),
            Value::String(alternative.profile.clone()),
        );
        selector.insert("values".to_owned(), Value::Object(values));
        if selectors
            .insert(input.role.clone(), Value::Object(selector))
            .is_some()
        {
            return Err(CliError("fixture selector input role is duplicated"));
        }
    }
    Ok(Value::Object(selectors))
}

/// Say what a case declared for an optional boolean, including saying nothing.
fn stated_flag(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unstated",
    }
}

/// Compare what a case declared against what the pipeline did, and record it.
///
/// The stage status is the comparison's own verdict rather than the fact that
/// the comparison was reached, because a mismatch here is precisely the failure
/// the fixed operator message reports. Recording success before comparing would
/// print a satisfied expectation directly above the failure it caused, pointing
/// a reader at the pipeline stages instead of at the case they mis-stated.
fn validate_case_outcome(
    case: &serde_json::Map<String, Value>,
    outcome: Result<KernelOutcome, registry_evidence::kernel::KernelError>,
    trace: &mut FixtureTrace,
) -> Result<Option<ValidatedValues>, CliError> {
    // What the case says it expects, beside what the pipeline just did. The
    // pipeline half of it is already recorded above this line.
    let declared = format!(
        "the case expects lookup {:?}, public problem {:?}, derivation run {}, signed success {}",
        optional_string(case, "expected_lookup")?.unwrap_or("match"),
        optional_string(case, "expected_public_problem")?.unwrap_or("none"),
        stated_flag(optional_boolean(case, "derivation_runs")?),
        stated_flag(optional_boolean(case, "signed_success")?)
    );
    let compared = compare_case_outcome(case, outcome);
    trace.record(
        Stage::Expect,
        if compared.is_ok() {
            StageStatus::Ok
        } else {
            StageStatus::Failed
        },
        declared,
    );
    compared
}

/// Decide whether the outcome one case declared is the outcome it got.
fn compare_case_outcome(
    case: &serde_json::Map<String, Value>,
    outcome: Result<KernelOutcome, registry_evidence::kernel::KernelError>,
) -> Result<Option<ValidatedValues>, CliError> {
    let derivation_runs = optional_boolean(case, "derivation_runs")?;
    let signed_success = optional_boolean(case, "signed_success")?;
    let expected_problem = optional_string(case, "expected_public_problem")?;

    if let Some(expected_lookup @ ("no_match" | "ambiguous")) =
        optional_string(case, "expected_lookup")?
    {
        let matches = matches!(
            (expected_lookup, &outcome),
            ("no_match", Ok(KernelOutcome::NoMatch)) | ("ambiguous", Ok(KernelOutcome::Ambiguous))
        );
        if !matches {
            return Err(CliError(
                "fixture lookup outcome did not match its contract",
            ));
        }
        if signed_success != Some(false) || derivation_runs != Some(false) {
            return Err(CliError(
                "unresolved fixture must deny derivation and signed success",
            ));
        }
        if expected_problem != Some("evidence.unavailable") {
            return Err(CliError("unresolved fixture public problem is not exact"));
        }
        return Ok(None);
    }
    if optional_string(case, "expected_lookup")?.is_some_and(|lookup| lookup != "match") {
        return Err(CliError("fixture lookup expectation is invalid"));
    }

    if let Some(problem) = expected_problem {
        let exact = matches!(
            (problem, &outcome),
            (
                "evidence.unavailable",
                Err(registry_evidence::kernel::KernelError::Extraction
                    | registry_evidence::kernel::KernelError::DerivationInput)
            ) | (
                "source.unavailable",
                Err(registry_evidence::kernel::KernelError::SourceProtocol)
            ) | (
                "service.unavailable",
                Err(registry_evidence::kernel::KernelError::Script
                    | registry_evidence::kernel::KernelError::Output
                    | registry_evidence::kernel::KernelError::Bundle
                    | registry_evidence::kernel::KernelError::Artifact(_)
                    | registry_evidence::kernel::KernelError::Requirement
                    | registry_evidence::kernel::KernelError::Evidence)
            )
        );
        if !exact {
            return Err(CliError(
                "fixture kernel failure did not match its public problem",
            ));
        }
        let derivation_ran = !matches!(
            outcome,
            Err(registry_evidence::kernel::KernelError::Extraction
                | registry_evidence::kernel::KernelError::SourceProtocol)
        );
        if signed_success != Some(false) || derivation_runs != Some(derivation_ran) {
            return Err(CliError(
                "failing fixture execution expectations did not match",
            ));
        }
        return Ok(None);
    }

    let KernelOutcome::Match(values) =
        outcome.map_err(|_| CliError("fixture evaluation failed unexpectedly"))?
    else {
        return Err(CliError("fixture expected a unique match"));
    };
    if optional_string(case, "expected_lookup")? != Some("match") {
        return Err(CliError("matched fixture must require an exact match"));
    }
    if derivation_runs == Some(false) {
        return Err(CliError("matched fixture cannot deny derivation execution"));
    }
    if signed_success == Some(false) {
        return Err(CliError(
            "matched fixture cannot deny signed-success eligibility",
        ));
    }

    let expected_value = case.get("expected_value");
    let expected_values = case.get("expected_values");
    if expected_value.is_some() == expected_values.is_some() {
        return Err(CliError(
            "matched fixture must declare exactly one value expectation",
        ));
    }
    if let Some(expected) = expected_value {
        if values.as_slice().len() != 1 || public_json(&values.as_slice()[0].value)? != *expected {
            return Err(CliError("fixture value did not match its contract"));
        }
    }
    if let Some(expected) = expected_values.and_then(Value::as_object) {
        if values.as_slice().len() != expected.len() {
            return Err(CliError("fixture value set did not match its contract"));
        }
        for (name, expected_value) in expected {
            let actual = values
                .as_slice()
                .iter()
                .filter(|candidate| {
                    candidate.provides_value_for == *name
                        || candidate
                            .provides_value_for
                            .strip_suffix(name)
                            .is_some_and(|prefix| prefix.ends_with(':'))
                })
                .collect::<Vec<_>>();
            if actual.len() != 1 || public_json(&actual[0].value)? != *expected_value {
                return Err(CliError("fixture value set did not match its contract"));
            }
        }
    } else if expected_values.is_some() {
        return Err(CliError("fixture value-set expectation is invalid"));
    }
    if derivation_runs != Some(true) || signed_success != Some(true) {
        return Err(CliError(
            "matched fixture must require derivation and signed success",
        ));
    }
    Ok(Some(values))
}

fn validate_source_failure(
    case: &serde_json::Map<String, Value>,
    source_failure: &Value,
) -> Result<(), CliError> {
    let failure = match source_failure.as_str() {
        Some("timeout") => SourceError::Timeout,
        Some("redirect") => SourceError::Redirect,
        Some("http-503") => SourceError::Status(SourceStatus::ServerError),
        Some("wrong-media-type") => SourceError::WrongMediaType,
        _ => return Err(CliError("fixture source-failure category is invalid")),
    };
    if optional_string(case, "expected_public_problem")? != Some("source.unavailable")
        || optional_boolean(case, "signed_success")? != Some(false)
        || source_failure_problem(&failure) != ProblemCode::DependencyUnavailable
    {
        return Err(CliError("fixture source-failure mapping is invalid"));
    }
    Ok(())
}

fn validate_companion_rejection(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    case: &serde_json::Map<String, Value>,
    companion: &Value,
) -> Result<(), CliError> {
    let label = companion
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .ok_or(CliError("fixture companion-bundle label is invalid"))?;
    require_expected(case, "bundle-rejection")?;
    let matrix: Value = serde_norway::from_slice(ANTI_RECONSTRUCTION_FIXTURE)
        .map_err(|_| CliError("anti-reconstruction fixture is invalid"))?;
    let rejected = matrix
        .get("rejected_bundles")
        .and_then(Value::as_array)
        .ok_or(CliError("anti-reconstruction fixture is invalid"))?;
    let declaration = rejected
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(label))
        .and_then(Value::as_object)
        .ok_or(CliError("fixture companion-bundle label is unknown"))?;
    let shared_family = declaration
        .get("shared_disclosure_family")
        .and_then(Value::as_str)
        .ok_or(CliError("anti-reconstruction family is invalid"))?;
    let definitions = declaration
        .get("definitions")
        .and_then(Value::as_array)
        .filter(|definitions| definitions.len() >= 2)
        .ok_or(CliError(
            "anti-reconstruction combination must contain multiple definitions",
        ))?;
    let distinct_definitions = definitions
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|_| CliError("anti-reconstruction definition is invalid"))?;
    if distinct_definitions.len() != definitions.len()
        || !definitions.iter().all(Value::is_object)
        || declaration
            .get("threat")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || declaration
            .get("expected")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CliError(
            "anti-reconstruction combination declaration is incomplete",
        ));
    }

    let mut unsafe_config = bundle.config.clone();
    let original = unsafe_config
        .requirements
        .iter_mut()
        .find(|candidate| candidate.id == requirement.id)
        .ok_or(CliError("fixture requirement is missing"))?;
    original.disclosure_guard.families = vec![shared_family.to_owned()];
    for index in 1..definitions.len() {
        let suffix = format!(":fixture-companion-{index}");
        let handle_suffix = format!("-fixture-companion-{index}");
        let mut companion = requirement.clone();
        companion.handle.push_str(&handle_suffix);
        companion.id.push_str(&suffix);
        companion.evidence_type.push_str(&suffix);
        companion.disclosure_guard.families = vec![shared_family.to_owned()];
        companion.derivation.script = registry_evidence::config::ArtifactPath::parse(&format!(
            "derivations/fixture-companion-{index}.rhai"
        ))
        .map_err(|_| CliError("fixture companion path is invalid"))?;
        companion.fixtures = Some(
            registry_evidence::config::ArtifactPath::parse(&format!(
                "fixtures/fixture-companion-{index}.yaml"
            ))
            .map_err(|_| CliError("fixture companion path is invalid"))?,
        );
        for concept in &mut companion.concepts {
            concept.handle.push_str(&handle_suffix);
            concept.id.push_str(&suffix);
        }
        unsafe_config.requirements.push(companion);
    }
    if unsafe_config.validate()
        != Err(ConfigError::Invalid(
            "enabled requirements share a disclosure family",
        ))
    {
        return Err(CliError("unsafe companion bundle was not rejected"));
    }
    Ok(())
}

fn optional_boolean(
    case: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<bool>, CliError> {
    case.get(name)
        .map(|value| {
            value
                .as_bool()
                .ok_or(CliError("fixture boolean expectation is invalid"))
        })
        .transpose()
}

fn optional_string<'a>(
    case: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, CliError> {
    case.get(name)
        .map(|value| {
            value
                .as_str()
                .ok_or(CliError("fixture string expectation is invalid"))
        })
        .transpose()
}

fn validate_privacy_expectation(
    fixture: &serde_json::Map<String, Value>,
    requirement: &registry_evidence::config::RequirementConfig,
    successful_values: &[Value],
    diagnostics: &[String],
) -> Result<(), CliError> {
    let expectation = fixture
        .get("privacy_expectation")
        .and_then(Value::as_object)
        .ok_or(CliError("fixture privacy expectation is unavailable"))?;
    let projection = serde_json::json!({
        "supportsRequirement": requirement.id,
        "isConformantTo": requirement.evidence_type,
        "subjectRoles": requirement
            .subject_roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        "successfulValues": successful_values,
    });
    validate_privacy_projection(expectation, &projection, diagnostics)
}

/// Check one run's disclosure and diagnostics against the fixture's own canaries.
///
/// `diagnostics` carries the surfaces this run built at run time. It is separate
/// from the fixed templates below because those are the only two forms the
/// argument that they are safe rests on being static; anything assembled while
/// the run proceeds has to be handed in and read.
fn validate_privacy_projection(
    expectation: &serde_json::Map<String, Value>,
    projection: &Value,
    diagnostics: &[String],
) -> Result<(), CliError> {
    let mut disclosed_strings = Vec::new();
    collect_strings(projection, &mut disclosed_strings);

    for expected in expectation_strings(expectation, "evidence_contains")? {
        if !disclosed_strings.contains(&expected) {
            return Err(CliError("fixture required disclosure is absent"));
        }
    }
    for prohibited in expectation_strings(expectation, "evidence_excludes")? {
        if disclosed_strings.contains(&prohibited) {
            return Err(CliError("fixture prohibited disclosure is present"));
        }
    }
    // Operator messages are structurally static (`CliError(&'static str)`) and
    // the success line contains counts only. Still exercise every declared
    // diagnostic canary against the exact dynamic-free output templates so a
    // future template change cannot silently weaken this fixture assertion.
    //
    // The explained trace is the one diagnostic assembled while the run
    // proceeds, so it is read rather than argued about: a stage note or detail
    // that ever interpolated a document value would fail the fixture that
    // declared that value. The trace handed in is the one the run just built,
    // which reaches this check having settled every case the fixture declares,
    // including the cases whose expected outcome is a no-match, a source
    // failure, or a refused injected value. Those are what exercise the
    // failure-shaped stage lines.
    static TEMPLATES: [&str; 2] = [
        "Evidence fixture passed (0 evaluated cases)",
        "evidence: fixture evaluation failed",
    ];
    for prohibited in expectation_strings(expectation, "diagnostics_exclude")? {
        let disclosed = TEMPLATES.iter().any(|surface| surface.contains(prohibited))
            || diagnostics
                .iter()
                .any(|surface| surface.contains(prohibited));
        if disclosed {
            return Err(CliError("fixture prohibited diagnostic is present"));
        }
    }
    Ok(())
}

fn expectation_strings<'a>(
    expectation: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<&'a str>, CliError> {
    expectation
        .get(name)
        .and_then(Value::as_array)
        .ok_or(CliError("fixture privacy expectation is invalid"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(CliError("fixture privacy expectation is invalid"))
        })
        .collect()
}

fn collect_strings<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    match value {
        Value::String(value) => output.push(value),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, output);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                output.push(key);
                collect_strings(value, output);
            }
        }
        _ => {}
    }
}

/// Drive the output gate directly with values the case supplies, and record
/// what the gate was given against what the bundle declared.
///
/// This is the one offline seam where the gate's own subject is fully in hand
/// before the call: the value being judged and the form declared for it. The
/// collapsed `KernelError::Output` hides the reason everywhere else, so the
/// comparison is written down here rather than inferred from the error.
fn validate_injected_rejection(
    kernel: &OfflineKernel,
    requirement: &registry_evidence::config::RequirementConfig,
    injected: &Value,
    trace: &mut FixtureTrace,
) -> Result<(), CliError> {
    let injected = injected
        .as_array()
        .ok_or(CliError("injected derivation fixture must be an array"))?;
    let mut derived = Vec::with_capacity(injected.len());
    let mut compared = Vec::with_capacity(injected.len());
    for value in injected {
        let object = value
            .as_object()
            .ok_or(CliError("injected derivation member is invalid"))?;
        if object.len() != 2 {
            return Err(CliError("injected derivation member is not closed"));
        }
        let concept_id = object
            .get("concept_id")
            .and_then(Value::as_str)
            .ok_or(CliError("injected derivation concept is invalid"))?;
        let value = object
            .get("value")
            .cloned()
            .ok_or(CliError("injected derivation value is missing"))?;
        let declared = requirement
            .concepts
            .iter()
            .find(|concept| concept.id == concept_id)
            .map(|concept| format!("declares form {:?}", concept.form))
            .unwrap_or_else(|| "is not declared by this requirement".to_owned());
        compared.push(format!(
            "concept {concept_id:?} {declared}, and the injected value is a JSON {}",
            json_type(&value)
        ));
        derived.push(DerivedConceptValue {
            concept_id: concept_id.to_owned(),
            value: DerivedValue::Json(value),
        });
    }
    if kernel
        .validate_values(
            &requirement.id,
            derived,
            ValueProjection {
                scope: EvidenceScope::AudienceScoped {
                    audience: OFFLINE_AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                binding_key: &OFFLINE_BINDING_KEY,
                binding_key_version: 1,
            },
        )
        .is_ok()
    {
        trace.record_with(
            Stage::Validate,
            StageStatus::Failed,
            "the output gate accepted the injected values, which the case forbids",
            compared,
        );
        return Err(CliError("injected derivation was not rejected"));
    }
    trace.record_with(
        Stage::Validate,
        StageStatus::Ok,
        "the output gate refused the injected values, as the case states",
        compared,
    );
    Ok(())
}

fn public_json(value: &PublicValue) -> Result<Value, CliError> {
    serde_json::to_value(value).map_err(|_| CliError("fixture value is not representable"))
}

fn fixture_observed_at(
    case: &serde_json::Map<String, Value>,
    common: Option<&serde_json::Map<String, Value>>,
    timezone: Option<&str>,
) -> Result<DateTime<Utc>, CliError> {
    if let Some(observed) = case.get("observed_at").and_then(Value::as_str) {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = case.get("legal_local_date").and_then(Value::as_str) {
        return local_date_at_noon(local_date, timezone);
    }

    if let Some(observed) = common
        .and_then(|value| value.get("observed_at"))
        .and_then(Value::as_str)
    {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = common
        .and_then(|value| value.get("legal_local_date"))
        .and_then(Value::as_str)
    {
        return local_date_at_noon(local_date, timezone);
    }

    DateTime::parse_from_rfc3339("1970-01-01T12:00:00Z")
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CliError("fixed fixture time is invalid"))
}

fn local_date_at_noon(local_date: &str, timezone: Option<&str>) -> Result<DateTime<Utc>, CliError> {
    let date = NaiveDate::parse_from_str(local_date, "%Y-%m-%d")
        .map_err(|_| CliError("fixture legal local date is invalid"))?;
    let local_noon = date
        .and_hms_opt(12, 0, 0)
        .ok_or(CliError("fixture legal local date is invalid"))?;
    let timezone = timezone
        .map(Tz::from_str)
        .transpose()
        .map_err(|_| CliError("fixture observation timezone is invalid"))?
        .unwrap_or(Tz::UTC);
    timezone
        .from_local_datetime(&local_noon)
        .single()
        .map(|value| value.with_timezone(&Utc))
        .ok_or(CliError("fixture legal local date cannot be resolved"))
}

fn require_expected(case: &serde_json::Map<String, Value>, expected: &str) -> Result<(), CliError> {
    if case.get("expected").and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(CliError("fixture boundary expectation is invalid"))
    }
}

fn safe_fixture_name(path: &Path) -> Result<&str, CliError> {
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(CliError(
            "fixture path must be bundle-relative and normalized",
        ));
    }
    let name = path
        .to_str()
        .filter(|value| value.starts_with("fixtures/") && value.ends_with(".yaml"))
        .ok_or(CliError("fixture path is invalid"))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use registry_evidence::audit::{
        audit_segment_paths, AuditAuthority, AuditDecision, AuditPhase, AuditSubject,
        AuthorityKind, EvidenceAuditEvent, EvidenceAuditLog, ResponseProtection,
    };
    use registry_evidence::config::{AssuranceProfile, SubjectBindingMode};
    use registry_evidence::verifier::{ExpectedListItemForm, ExpectedValueForm};
    use std::fs;

    /// Every command that compiles a kernel renders the same two things: the
    /// failure class it owns, and the artifact diagnostic the kernel produced.
    #[test]
    fn every_kernel_compile_command_renders_the_artifact_and_its_cause() {
        use registry_evidence::bundle::ArtifactFault;
        use registry_evidence::config::SchemaFault;

        let fault = ArtifactFault::new(
            "derivations/adult-status.rhai",
            SchemaFault::because("script does not compile"),
        );
        for message in [
            "bundle compilation failed",
            "fixture bundle compilation failed",
        ] {
            let rendered =
                kernel_compile_error(message, KernelError::Artifact(fault.clone())).to_string();
            assert_eq!(
                rendered,
                format!(
                    "{message}: artifact derivations/adult-status.rhai: script does not compile"
                )
            );
        }
    }

    /// A kernel failure that names no artifact stays the class it was, so a
    /// command cannot report a file the kernel never blamed.
    #[test]
    fn a_kernel_failure_without_an_artifact_stays_a_fixed_message() {
        let rendered =
            kernel_compile_error("bundle compilation failed", KernelError::Bundle).to_string();

        assert_eq!(rendered, "bundle compilation failed");
    }

    #[test]
    fn local_shell_seams_are_hidden_from_adopter_help() {
        let command = Cli::command();
        for name in [
            "bundle-check",
            "bundle-evaluate",
            "prepare-local-relying-procedure",
            "local-audit-last-operation",
        ] {
            assert!(
                command
                    .get_subcommands()
                    .find(|candidate| candidate.get_name() == name)
                    .is_some_and(clap::Command::is_hide_set),
                "{name} remains an internal shell seam"
            );
        }
    }

    #[test]
    fn local_documents_require_one_owner_only_regular_file() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().expect("temporary directory");
        let safe = directory.path().join("request.json");
        fs::write(&safe, b"{}").expect("input is written");
        fs::set_permissions(&safe, fs::Permissions::from_mode(0o600))
            .expect("input becomes owner-only");
        assert_eq!(
            read_owner_only_input(&safe, 2, LOCAL_RELYING_PROCEDURE_FAILED)
                .expect("owner-only input reads"),
            b"{}"
        );

        fs::set_permissions(&safe, fs::Permissions::from_mode(0o640))
            .expect("input becomes group-readable");
        assert!(read_owner_only_input(&safe, 2, LOCAL_RELYING_PROCEDURE_FAILED).is_err());
        fs::set_permissions(&safe, fs::Permissions::from_mode(0o600))
            .expect("input becomes owner-only again");

        let link = directory.path().join("second-link.json");
        fs::hard_link(&safe, &link).expect("hard link is created");
        assert!(read_owner_only_input(&safe, 2, LOCAL_RELYING_PROCEDURE_FAILED).is_err());
        fs::remove_file(&link).expect("hard link is removed");

        let symbolic = directory.path().join("symbolic.json");
        symlink(&safe, &symbolic).expect("symbolic link is created");
        assert!(read_owner_only_input(&symbolic, 2, LOCAL_RELYING_PROCEDURE_FAILED).is_err());
        assert!(read_owner_only_input(&safe, 1, LOCAL_RELYING_PROCEDURE_FAILED).is_err());
    }

    /// Every expected form the published policy schema accepts must parse the
    /// way that schema writes it. The list form is a mapping under `list`, not
    /// a YAML tag, and it is the only form a list-valued concept can state.
    #[test]
    fn policy_documents_parse_every_expected_form_as_the_contract_writes_it() {
        for (written, expected) in [
            ("boolean", ExpectedValueForm::Boolean),
            ("integer", ExpectedValueForm::Integer),
            ("string", ExpectedValueForm::String),
            ("date-bucket", ExpectedValueForm::DateBucket),
            ("time-bucket", ExpectedValueForm::TimeBucket),
            ("entity-reference", ExpectedValueForm::EntityReference),
            ("structured", ExpectedValueForm::Structured),
            (
                "{list: {items: string, minimumItems: 1, maximumItems: 2, unique: true}}",
                ExpectedValueForm::List {
                    item_form: ExpectedListItemForm::String,
                    minimum_items: 1,
                    maximum_items: 2,
                    unique: true,
                },
            ),
        ] {
            let document = verification_policy_document(&format!("form: {written}"));
            let policy: EvidenceVerificationPolicyDocument = serde_norway::from_str(&document)
                .unwrap_or_else(|error| panic!("`{written}` is a policy form: {error}"));
            assert_eq!(
                policy
                    .try_into_policy(Utc::now())
                    .expect("the fixture policy states bounds the contract allows")
                    .expected_outputs[0]
                    .form,
                expected,
                "`{written}` parsed as a different form"
            );
        }
    }

    #[test]
    fn policy_documents_reject_forms_outside_the_closed_vocabulary() {
        for written in [
            "list",
            "{list: {minimumItems: 1}}",
            "{list: {minimumItems: 1, maximumItems: 2, extra: 3}}",
            "{set: {minimumItems: 1, maximumItems: 2}}",
            "date_bucket",
        ] {
            let document = verification_policy_document(&format!("form: {written}"));
            assert!(
                serde_norway::from_str::<EvidenceVerificationPolicyDocument>(&document).is_err(),
                "`{written}` is not a policy form but parsed as one"
            );
        }
    }

    /// One complete policy document whose single expected output states `form`.
    fn verification_policy_document(form: &str) -> String {
        format!(
            "expectedAssuranceProfile: evidence-grade\n\
             issuedBy: urn:example:issuer\n\
             providedBy: urn:example:provider\n\
             requirement: urn:example:requirement:v1\n\
             evidenceType: urn:example:evidence-type:v1\n\
             purpose: example-purpose\n\
             audience: https://relying-party.example\n\
             configurationRevision: sha256:0\n\
             requestNonce: example-nonce\n\
             expectedSubjects:\n\
             \x20 - {{role: subject, binding: urn:evidence:subject:v1_{binding}}}\n\
             expectedOutputs:\n\
             \x20 - handle: example-concept\n\
             \x20   concept: urn:example:concept\n\
             \x20   required: true\n\
             \x20   {form}\n\
             revokedKeyIds: []\n\
             maximumAssertionLifetimeSeconds: 86400\n\
             clockSkewSeconds: 30\n",
            binding = "A".repeat(43),
        )
    }

    #[test]
    fn fixture_paths_never_escape_the_captured_bundle() {
        assert_eq!(
            safe_fixture_name(Path::new("fixtures/cases.yaml")),
            Ok("fixtures/cases.yaml")
        );
        assert!(safe_fixture_name(Path::new("../fixtures/cases.yaml")).is_err());
        assert!(safe_fixture_name(Path::new("/tmp/cases.yaml")).is_err());
    }

    #[test]
    fn offline_dates_are_fixed_and_never_use_ambient_time() {
        let case = serde_json::json!({"legal_local_date": "2026-08-03"});
        let observed = fixture_observed_at(case.as_object().expect("object"), None, None)
            .expect("date converts");
        assert_eq!(observed.to_rfc3339(), "2026-08-03T12:00:00+00:00");
    }

    #[test]
    fn case_local_date_overrides_common_observation_time() {
        let case = serde_json::json!({"legal_local_date": "2026-08-01"});
        let common = serde_json::json!({"observed_at": "2026-08-02T00:00:00Z"});
        let observed = fixture_observed_at(
            case.as_object().expect("case object"),
            common.as_object(),
            Some("Asia/Bangkok"),
        )
        .expect("case-local date converts");
        assert_eq!(observed.to_rfc3339(), "2026-08-01T05:00:00+00:00");
    }

    #[test]
    fn symbolic_source_failures_use_the_production_public_mapper() {
        for category in ["timeout", "redirect", "http-503", "wrong-media-type"] {
            let case = serde_json::json!({
                "source_failure": category,
                "expected_public_problem": "source.unavailable",
                "signed_success": false
            });
            let object = case.as_object().expect("object");
            assert_eq!(
                validate_source_failure(object, &object["source_failure"]),
                Ok(())
            );
        }
    }

    #[test]
    fn public_unavailability_requires_an_extraction_failure() {
        let case = serde_json::json!({
            "expected_public_problem": "evidence.unavailable",
            "derivation_runs": false,
            "signed_success": false
        });
        let case = case.as_object().expect("object");
        assert!(validate_case_outcome(
            case,
            Ok(KernelOutcome::NoMatch),
            &mut FixtureTrace::default()
        )
        .is_err());
        assert!(validate_case_outcome(
            case,
            Err(registry_evidence::kernel::KernelError::Script),
            &mut FixtureTrace::default(),
        )
        .is_err());
        assert_eq!(
            validate_case_outcome(
                case,
                Err(registry_evidence::kernel::KernelError::Extraction),
                &mut FixtureTrace::default(),
            ),
            Ok(None)
        );
    }

    #[test]
    fn service_unavailability_requires_an_internal_kernel_failure() {
        let case = serde_json::json!({
            "expected_public_problem": "service.unavailable",
            "derivation_runs": true,
            "signed_success": false
        });
        let case = case.as_object().expect("object");
        assert_eq!(
            validate_case_outcome(
                case,
                Err(registry_evidence::kernel::KernelError::Script),
                &mut FixtureTrace::default(),
            ),
            Ok(None)
        );
        assert!(validate_case_outcome(
            case,
            Err(registry_evidence::kernel::KernelError::Extraction),
            &mut FixtureTrace::default(),
        )
        .is_err());
    }

    #[test]
    fn unresolved_lookup_rejects_derivation_or_signed_success_claims() {
        for declaration in [
            serde_json::json!({
                "expected_lookup": "no_match",
                "expected_public_problem": "evidence.unavailable",
                "derivation_runs": true
            }),
            serde_json::json!({
                "expected_lookup": "no_match",
                "expected_public_problem": "evidence.unavailable",
                "signed_success": true
            }),
        ] {
            assert!(validate_case_outcome(
                declaration.as_object().expect("object"),
                Ok(KernelOutcome::NoMatch),
                &mut FixtureTrace::default(),
            )
            .is_err());
        }
    }

    #[test]
    fn reference_fixture_forms_reject_irrelevant_expectations() {
        let bundle = serde_json::json!({"bundle": "rejected"});
        assert_eq!(
            validate_reference_expectation_keys(
                "bundleMutation",
                bundle.as_object().expect("object"),
            ),
            Ok(())
        );

        let irrelevant = serde_json::json!({"bundle": "rejected", "signed": false});
        assert!(validate_reference_expectation_keys(
            "bundleMutation",
            irrelevant.as_object().expect("object"),
        )
        .is_err());

        let transport = serde_json::json!({
            "expectedTransport": {"path": "/records"},
            "sourceRequestCount": 1
        });
        assert_eq!(
            validate_reference_expectation_keys(
                "selectorOverrides",
                transport.as_object().expect("object"),
            ),
            Ok(())
        );
        assert!(validate_reference_expectation_keys(
            "response",
            transport.as_object().expect("object"),
        )
        .is_err());

        let chained = serde_json::json!({
            "lookup": "match",
            "derivationRuns": true,
            "signed": true,
            "sourceRequestCount": 2
        });
        let chained = chained.as_object().expect("object");
        assert_eq!(
            validate_reference_expectation_keys("responses", chained),
            Ok(())
        );
        assert_eq!(require_reference_request_count(chained, 2), Ok(()));
        assert!(require_reference_request_count(chained, 1).is_err());
        assert!(require_reference_request_count(chained, 3).is_err());
    }

    #[test]
    fn reference_failures_require_exact_unsigned_stage_expectations() {
        let exact = serde_json::json!({
            "error": "source_protocol_error",
            "publicProblem": "source.unavailable",
            "derivationRuns": false,
            "signed": false
        });
        assert_eq!(
            validate_reference_error(
                exact.as_object().expect("object"),
                KernelError::SourceProtocol,
                false,
            ),
            Ok(())
        );

        let wrong_public = serde_json::json!({
            "error": "source_protocol_error",
            "publicProblem": "service.unavailable",
            "derivationRuns": false,
            "signed": false
        });
        assert!(validate_reference_error(
            wrong_public.as_object().expect("object"),
            KernelError::SourceProtocol,
            false,
        )
        .is_err());
    }

    /// The fixture can name only the transport outcome, not copy Problem
    /// Details members into a recorded body or mislabel the provider's hidden
    /// state as no-match or ambiguity.
    #[test]
    fn reference_declared_unresolved_form_is_data_free_and_source_bound() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml"
        ))
        .expect("reference configuration parses");
        let source = config
            .sources
            .get("registered-birth-date")
            .expect("HTTP source exists");
        let expected = serde_json::json!({
            "publicProblem": "evidence.unavailable",
            "derivationRuns": false,
            "signed": false,
            "sourceRequestCount": 1
        });
        let expected = expected.as_object().expect("expectation is an object");

        assert_eq!(
            validate_reference_declared_unresolved(source, &Value::Bool(true), expected),
            Err(CliError(
                "reference declared unresolved without a source declaration"
            ))
        );

        let mut declared = serde_json::to_value(source).expect("source is representable");
        declared["unresolvedProblem"] = serde_json::json!({
            "status": 404,
            "type": "https://id.example.invalid/problems/unresolved",
            "code": "lookup.unresolved"
        });
        let declared: registry_evidence::config::SourceConfig =
            serde_json::from_value(declared).expect("declared source parses");
        assert_eq!(
            validate_reference_declared_unresolved(&declared, &Value::Bool(true), expected),
            Ok(())
        );
        assert_eq!(
            validate_reference_declared_unresolved(&declared, &Value::Bool(false), expected),
            Err(CliError(
                "reference declared-unresolved marker must be true"
            ))
        );

        let leaking = serde_json::json!({
            "lookup": "no_match",
            "publicProblem": "evidence.unavailable",
            "derivationRuns": false,
            "signed": false,
            "sourceRequestCount": 1
        });
        assert!(validate_reference_expectation_keys(
            "declaredUnresolved",
            leaking.as_object().expect("expectation is an object")
        )
        .is_err());
    }

    /// The complete reference evaluator reaches the neutral case without
    /// projection or extraction, and its explain trace contains neither an
    /// invented lookup class nor any configured Problem Details member.
    #[cfg(unix)]
    #[tokio::test]
    async fn reference_fixture_evaluates_declared_unresolved_without_problem_data() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle",
        );
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let mut bundle = Bundle::load(directory.path()).expect("reference bundle loads");

        let requirement_id = "urn:gov:example:requirement:adult-status-from-birth:v1";
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)
            .expect("adult-status requirement exists");
        let fixture_path = requirement
            .fixtures
            .as_ref()
            .expect("fixture is declared")
            .as_str()
            .to_owned();
        let mut fixture = serde_json::to_value(
            bundle
                .fixtures
                .get(&fixture_path)
                .expect("fixture is captured"),
        )
        .expect("fixture is representable");
        let unresolved = fixture["cases"]
            .as_array_mut()
            .expect("cases are an array")
            .iter_mut()
            .find(|case| case["id"] == "no-match")
            .and_then(Value::as_object_mut)
            .expect("no-match case exists");
        unresolved.insert("id".to_owned(), Value::String("unresolved".to_owned()));
        unresolved
            .remove("response")
            .expect("recorded response exists");
        unresolved.insert("declaredUnresolved".to_owned(), Value::Bool(true));
        let expected = unresolved["expected"]
            .as_object_mut()
            .expect("expectation is an object");
        expected.remove("lookup").expect("lookup label exists");
        expected.insert("sourceRequestCount".to_owned(), Value::from(1));

        let mut config = serde_json::to_value(&bundle.config).expect("config is representable");
        config["sources"]["registered-birth-date"]["unresolvedProblem"] = serde_json::json!({
            "status": 404,
            "type": "https://id.example.invalid/problems/fixture-canary",
            "code": "fixture.canary"
        });
        bundle.config = serde_json::from_value(config).expect("declared config parses");
        bundle.config.validate().expect("declared config validates");

        let bundle = Arc::new(bundle);
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            &source_statements(&bundle, None).expect("source statements bind"),
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        let signer = offline_fixture_signer().await.expect("fixture signer");
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == requirement_id)
            .expect("adult-status requirement remains");
        let mut trace = FixtureTrace::default();
        let expected_cases = fixture["cases"].as_array().expect("cases").len();
        assert_eq!(
            evaluate_reference_fixture(
                &bundle,
                &kernel,
                &source_plans,
                Some(&signer),
                requirement,
                (fixture.as_object().expect("fixture is an object"), None),
                &mut trace,
            )
            .await,
            Ok(FixtureSummary {
                evaluated_cases: expected_cases,
            })
        );

        let selected = fixture["cases"][0]["id"].as_str().expect("case id");
        assert_eq!(
            evaluate_reference_fixture(
                &bundle,
                &kernel,
                &source_plans,
                Some(&signer),
                requirement,
                (
                    fixture.as_object().expect("fixture is an object"),
                    Some(selected)
                ),
                &mut FixtureTrace::default(),
            )
            .await,
            Ok(FixtureSummary { evaluated_cases: 1 })
        );
        assert_eq!(
            evaluate_reference_fixture(
                &bundle,
                &kernel,
                &source_plans,
                Some(&signer),
                requirement,
                (
                    fixture.as_object().expect("fixture is an object"),
                    Some("private-case-canary")
                ),
                &mut FixtureTrace::default(),
            )
            .await,
            Err(CliError("selected fixture case is unavailable"))
        );

        let rendered = serde_json::to_string(&trace).expect("trace is representable");
        assert!(rendered.contains("unresolved"));
        for prohibited in ["fixture-canary", "fixture.canary", "no-match case"] {
            assert!(
                !rendered.contains(prohibited),
                "trace leaked {prohibited:?}: {rendered}"
            );
        }

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[test]
    fn chained_reference_parameter_mutation_uses_final_fetch_facts() {
        let (bundle, fixture) = chained_reference_fixture_bundle();
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == REFERENCE_CHAINED_REQUIREMENT)
            .expect("chained reference requirement is captured");
        let fixture = fixture.as_object().expect("fixture is an object");
        let common = fixture["common"].as_object().expect("common is an object");
        let selectors = &common["derivationSelectorInputs"];
        let observed_at = fixture_observed_at(&JsonMap::new(), Some(common), None)
            .expect("observation time resolves");
        let mut cases = fixture["cases"]
            .as_array()
            .expect("cases are an array")
            .clone();
        let positive = cases
            .iter_mut()
            .find(|case| case["id"] == "positive")
            .and_then(Value::as_object_mut)
            .expect("positive case is an object");
        let response = positive
            .remove("response")
            .expect("positive response is available");
        positive.insert(
            "responses".to_owned(),
            serde_json::json!({
                REFERENCE_CHAINED_SEARCH: response,
                REFERENCE_CHAINED_FETCH: response,
            }),
        );
        let mutation_case = cases
            .iter()
            .find(|case| case["id"] == "namespace-mismatch")
            .and_then(Value::as_object)
            .expect("parameter mutation case is an object");

        assert_eq!(
            validate_reference_parameter_mutation(
                &bundle,
                requirement,
                &cases,
                mutation_case["derivationParameterMutation"]
                    .as_object()
                    .expect("mutation is an object"),
                selectors,
                observed_at,
                mutation_case["expected"]
                    .as_object()
                    .expect("expectation is an object"),
            ),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn chained_fixture_projection_failures_are_source_protocol_outcomes() {
        let (bundle, fixture) = chained_reference_fixture_bundle();
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == REFERENCE_CHAINED_REQUIREMENT)
            .expect("chained reference requirement is captured");
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let fixture = fixture.as_object().expect("fixture is an object");
        let common = fixture["common"].as_object().expect("common is an object");
        let selectors = &common["derivationSelectorInputs"];
        let positive = fixture["cases"]
            .as_array()
            .expect("cases are an array")
            .iter()
            .find(|case| case["id"] == "positive")
            .and_then(|case| case.get("response"))
            .expect("positive response is available")
            .clone();
        let rejected = serde_json::json!({"errors": []});
        let observed_at = DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
            .expect("fixed time parses")
            .with_timezone(&Utc);

        for (search_response, fetch_response) in
            [(rejected.clone(), positive.clone()), (positive, rejected)]
        {
            let case = serde_json::json!({
                "sources": {
                    REFERENCE_CHAINED_SEARCH: search_response,
                    REFERENCE_CHAINED_FETCH: fetch_response,
                }
            });
            assert_eq!(
                evaluate_fixture_acquisition(
                    &bundle,
                    &kernel,
                    requirement,
                    case.as_object().expect("case is an object"),
                    selectors,
                    observed_at,
                    &mut FixtureTrace::default(),
                ),
                Ok(Err(KernelError::SourceProtocol))
            );
        }
    }

    const REFERENCE_CHAINED_REQUIREMENT: &str =
        "urn:gov:example:requirement:registered-parent-relationship:v1";
    const REFERENCE_CHAINED_SEARCH: &str = "registered-birth-parents";
    const REFERENCE_CHAINED_FETCH: &str = "registered-birth-parents-fetch";

    #[cfg(unix)]
    fn chained_reference_fixture_bundle() -> (Arc<Bundle>, Value) {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle",
        );
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let mut bundle = Bundle::load(directory.path()).expect("reference bundle loads");
        let fixture = serde_json::to_value(
            bundle
                .fixtures
                .get("fixtures/registered-parent-relationship-cases.yaml")
                .expect("reference fixture is captured"),
        )
        .expect("reference fixture is representable");
        let mut config = serde_json::to_value(&bundle.config).expect("config is representable");
        let fetch = config["sources"][REFERENCE_CHAINED_SEARCH].clone();
        config["sources"]
            .as_object_mut()
            .expect("sources are an object")
            .insert(REFERENCE_CHAINED_FETCH.to_owned(), fetch);
        let requirement = config["requirements"]
            .as_array_mut()
            .expect("requirements are an array")
            .iter_mut()
            .find(|requirement| requirement["id"] == REFERENCE_CHAINED_REQUIREMENT)
            .expect("reference requirement is available");
        requirement["acquisition"] = serde_json::json!({
            "kind": "search-then-fetch",
            "search": REFERENCE_CHAINED_SEARCH,
            "fetch": REFERENCE_CHAINED_FETCH,
        });
        bundle.config = serde_json::from_value(config).expect("chained config parses");
        bundle.config.validate().expect("chained config validates");
        set_tree_mode(directory.path(), 0o755, 0o444);
        (Arc::new(bundle), fixture)
    }

    /// A fixture executes the initial source's statement and replays every
    /// other stage from the case. A statement on a later stage would therefore
    /// be reported as covered without having run, so the requirement is refused
    /// rather than half-proven.
    #[test]
    fn a_replayed_statement_stage_has_no_reference_fixture_form() {
        let statement = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle/evidence.yaml"
        ))
        .expect("the statement project config validates");
        let single = &statement
            .requirements
            .iter()
            .find(|requirement| requirement.id == STATEMENT_REQUIREMENT)
            .expect("the statement requirement is declared")
            .acquisition;
        assert_eq!(refuse_replayed_statement_stages(&statement, single), Ok(()));

        let mut chained =
            serde_json::to_value(&statement).expect("the statement config is representable");
        let fetch = chained["sources"][STATEMENT_SOURCE].clone();
        chained["sources"]
            .as_object_mut()
            .expect("sources are an object")
            .insert(format!("{STATEMENT_SOURCE}-fetch"), fetch);
        let chained: EvidenceConfig =
            serde_json::from_value(chained).expect("the duplicated config parses");
        assert_eq!(
            refuse_replayed_statement_stages(
                &chained,
                &AcquisitionConfig::SearchThenFetch {
                    search: STATEMENT_SOURCE.to_owned(),
                    fetch: format!("{STATEMENT_SOURCE}-fetch"),
                },
            ),
            Err(CliError(
                "a replayed statement stage has no reference fixture form"
            ))
        );

        // The refusal is about what a replayed stage would hide, so a chained
        // requirement whose stages both answer over a network keeps its form.
        let recorded = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle/evidence.yaml"
        ))
        .expect("the recorded project config validates");
        assert_eq!(
            refuse_replayed_statement_stages(
                &recorded,
                &AcquisitionConfig::SearchThenFetch {
                    search: "registered-birth-date".to_owned(),
                    fetch: "registered-birth-parents".to_owned(),
                },
            ),
            Ok(())
        );
    }

    /// The refusal is asked before the fixture is, so an author sees the stage
    /// they cannot prove rather than a missing key in a case shape that could
    /// never have carried it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_replayed_statement_stage_is_refused_before_the_fixture_is_read() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle",
        );
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let mut bundle = Bundle::load(directory.path()).expect("the statement bundle loads");
        let fixture = serde_json::to_value(
            bundle
                .fixtures
                .get("fixtures/professional-licence-cases.yaml")
                .expect("the statement fixture is captured"),
        )
        .expect("the fixture is representable");
        let mut config = serde_json::to_value(&bundle.config).expect("config is representable");
        let fetch = config["sources"][STATEMENT_SOURCE].clone();
        config["sources"]
            .as_object_mut()
            .expect("sources are an object")
            .insert(format!("{STATEMENT_SOURCE}-fetch"), fetch);
        let requirement = config["requirements"]
            .as_array_mut()
            .expect("requirements are an array")
            .iter_mut()
            .find(|requirement| requirement["id"] == STATEMENT_REQUIREMENT)
            .expect("the statement requirement is available");
        requirement["acquisition"] = serde_json::json!({
            "kind": "search-then-fetch",
            "search": STATEMENT_SOURCE,
            "fetch": format!("{STATEMENT_SOURCE}-fetch"),
        });
        bundle.config = serde_json::from_value(config).expect("the chained config parses");
        bundle
            .config
            .validate()
            .expect("the chained config validates");
        set_tree_mode(directory.path(), 0o755, 0o444);

        let bundle = Arc::new(bundle);
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == STATEMENT_REQUIREMENT)
            .expect("the chained requirement is captured");
        assert_eq!(
            evaluate_reference_fixture(
                &bundle,
                &kernel,
                &BTreeMap::new(),
                None,
                requirement,
                (fixture.as_object().expect("the fixture is an object"), None),
                &mut FixtureTrace::default(),
            )
            .await
            .err(),
            Some(CliError(
                "a replayed statement stage has no reference fixture form"
            ))
        );
    }

    const STATEMENT_REQUIREMENT: &str = "urn:gov:example:requirement:licence-register-status:v1";
    const STATEMENT_SOURCE: &str = "licence-register";

    #[test]
    fn statement_fixture_vocabulary_excludes_startup_only_failures() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle/evidence.yaml"
        ))
        .expect("the reference configuration parses");
        let source = config
            .sources
            .get(STATEMENT_SOURCE)
            .expect("the statement source exists");

        for symbol in ["extract-unavailable", "statement-refused"] {
            assert_eq!(
                reference_source_failure_error(source, symbol),
                Err(CliError("reference source-failure name is invalid"))
            );
        }
    }

    #[test]
    fn privacy_expectations_check_exact_projected_strings() {
        let expectation = serde_json::json!({
            "evidence_contains": ["urn:example:concept", "subject"],
            "evidence_excludes": ["raw-source-value"],
            "diagnostics_exclude": ["selector-value"]
        });
        let projection = serde_json::json!({
            "subjectRoles": ["subject"],
            "successfulValues": [{"providesValueFor": "urn:example:concept", "value": true}]
        });
        assert_eq!(
            validate_privacy_projection(
                expectation.as_object().expect("expectation object"),
                &projection,
                &[],
            ),
            Ok(())
        );

        let leaking = serde_json::json!({"value": "raw-source-value"});
        assert!(validate_privacy_projection(
            expectation.as_object().expect("expectation object"),
            &leaking,
            &[],
        )
        .is_err());

        let leaking_key = serde_json::json!({"raw-source-value": false});
        assert!(validate_privacy_projection(
            expectation.as_object().expect("expectation object"),
            &leaking_key,
            &[],
        )
        .is_err());
    }

    #[test]
    fn privacy_expectations_check_the_explained_trace_the_run_would_print() {
        let expectation = serde_json::json!({
            "evidence_contains": [],
            "evidence_excludes": [],
            "diagnostics_exclude": ["selector-value"]
        });
        let expectation = expectation.as_object().expect("expectation object");
        let projection = serde_json::json!({});

        let mut safe = FixtureTrace::default();
        safe.begin_case("positive");
        safe.record(
            Stage::Extract,
            StageStatus::Ok,
            "fact keys [\"date_of_birth\"]",
        );
        safe.pass_case();
        assert_eq!(
            validate_privacy_projection(
                expectation,
                &projection,
                &explain_surfaces(&safe).expect("the trace renders"),
            ),
            Ok(())
        );

        // A stage note that interpolated a protected value rather than its
        // shape is what this canary exists to catch.
        let mut leaking = FixtureTrace::default();
        leaking.begin_case("positive");
        leaking.record(
            Stage::Extract,
            StageStatus::Ok,
            "matched the record for selector-value",
        );
        leaking.pass_case();
        assert_eq!(
            validate_privacy_projection(
                expectation,
                &projection,
                &explain_surfaces(&leaking).expect("the trace renders"),
            ),
            Err(CliError("fixture prohibited diagnostic is present"))
        );

        // The same holds for a value that reaches a detail line, a case
        // identifier, or the failure attributed to a case.
        for leaking in [
            {
                let mut trace = FixtureTrace::default();
                trace.begin_case("positive");
                trace.record_with(
                    Stage::Extract,
                    StageStatus::NoMatch,
                    "no match",
                    vec!["searched for selector-value".to_owned()],
                );
                trace.pass_case();
                trace
            },
            {
                let mut trace = FixtureTrace::default();
                trace.begin_case("selector-value");
                trace.pass_case();
                trace
            },
        ] {
            assert_eq!(
                validate_privacy_projection(
                    expectation,
                    &projection,
                    &explain_surfaces(&leaking).expect("the trace renders"),
                ),
                Err(CliError("fixture prohibited diagnostic is present"))
            );
        }
    }

    #[test]
    fn check_compiles_source_plans_without_resolving_secrets() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let valid_config = EvidenceConfig::parse_yaml(valid.as_bytes()).expect("config validates");
        let outbound_tls = OutboundTlsConfig {
            system_roots: true,
            trust_profiles: Default::default(),
        };
        assert_eq!(
            compile_source_plans_with_runtime(
                &valid_config,
                &BTreeMap::new(),
                "/run/secrets/evidence",
                &outbound_tls,
                &Default::default(),
            )
            .map(|plans| plans.len()),
            Ok(valid_config.sources.len())
        );

        let invalid = valid.replacen("timeoutMilliseconds: 3000", "timeoutMilliseconds: 0", 1);
        assert_ne!(invalid, valid, "fixture mutation must remain effective");
        let invalid_config: EvidenceConfig =
            serde_norway::from_str(&invalid).expect("closed typed shape deserializes");
        assert_eq!(
            compile_source_plans_with_runtime(
                &invalid_config,
                &BTreeMap::new(),
                "/run/secrets/evidence",
                &outbound_tls,
                &Default::default(),
            )
            .map(|_| ()),
            Err(CliError("source plan compilation failed").into())
        );
    }

    fn test_audit_secret() -> AuditHashSecret {
        derived_audit_chain_secret(b"0123456789abcdef0123456789abcdef")
            .expect("audit chain secret derives")
    }

    fn test_audit_event(log: &EvidenceAuditLog) -> EvidenceAuditEvent {
        EvidenceAuditEvent::new(
            AssuranceProfile::EvidenceGrade,
            "01K1EXAMPLE0000000000000000".to_owned(),
            AuditPhase::AccessAttempt,
            "urn:example:requirement:v1".to_owned(),
            format!("sha256:{}", "0".repeat(64)),
            "casework".to_owned(),
            log.pseudonym("requester-v1", "urn:example:trust", b"principal-canary")
                .expect("pseudonym builds"),
            AuditAuthority {
                kind: AuthorityKind::Statutory,
                grant_pseudonym: None,
            },
            vec![AuditSubject {
                role: "subject".to_owned(),
                selector_profile: "person-v1".to_owned(),
                selector_bundle_pseudonym: Some(
                    log.pseudonym("subject-v1", "casework", b"selector-canary")
                        .expect("pseudonym builds"),
                ),
            }],
            ResponseProtection::Signed,
            AuditDecision::Authorized,
            5,
        )
    }

    /// Change one byte of a record without changing its length, so the
    /// record no longer matches the hash the chain recorded for it.
    fn corrupt_audit_line(line: &str) -> String {
        let mut bytes = line.as_bytes().to_vec();
        for byte in bytes.iter_mut() {
            if byte.is_ascii_lowercase() {
                *byte = if *byte == b'z' { b'y' } else { *byte + 1 };
                break;
            }
        }
        String::from_utf8(bytes).expect("a corrupted record stays UTF-8")
    }

    #[tokio::test]
    async fn verify_audit_reports_a_clean_multi_segment_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                2048,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..48 {
                log.append(test_audit_event(&log))
                    .await
                    .expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() >= 4,
            "the fixture needs several sealed segments plus the active one"
        );

        let secret = test_audit_secret();
        let summary =
            verify_audit_chain(&path, &secret).expect("a clean multi-segment chain verifies");
        assert_eq!(summary.records, 48);
        assert_eq!(summary.segments, segments.len());
        assert!(summary.active_verified);
        assert_eq!(summary.first_sequence, Some(1));

        assert!(verify_audit_with_secret(&path, &secret).is_ok());
    }

    /// Startup verification only replays the active segment; this pins the
    /// counterpart it exists for: corruption planted in an already sealed
    /// segment passes startup and is only caught by the out-of-band verifier.
    #[tokio::test]
    async fn verify_audit_fails_on_sealed_segment_corruption() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                4096,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..24 {
                log.append(test_audit_event(&log))
                    .await
                    .expect("event appends");
            }
        }

        let segments = audit_segment_paths(&path).expect("segments enumerate");
        let oldest_sealed = segments[0].clone();
        let contents = fs::read_to_string(&oldest_sealed).expect("sealed segment reads");
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        assert!(
            lines.len() > 1,
            "the corrupted record must not be the sealed tail"
        );
        lines[0] = corrupt_audit_line(&lines[0]);
        let mut rewritten = lines.join("\n");
        rewritten.push('\n');
        fs::write(&oldest_sealed, rewritten).expect("segment rewrites");

        let restarted = EvidenceAuditLog::initialize(
            &path,
            4096,
            b"0123456789abcdef0123456789abcdef".to_vec(),
            1,
        )
        .await
        .expect("startup does not replay sealed history");
        assert!(restarted.ready().await);
        drop(restarted);

        assert!(
            verify_audit_with_secret(&path, &test_audit_secret()).is_err(),
            "the out-of-band verifier must catch sealed-segment corruption"
        );
    }

    /// A gap in sealed history is an operator archiving a segment, not
    /// tampering, so it must be reported by sequence rather than folded into
    /// the generic corruption message.
    #[tokio::test]
    async fn verify_audit_reports_an_archived_segment_as_missing_not_corrupt() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        {
            let log = EvidenceAuditLog::initialize(
                &path,
                2048,
                b"0123456789abcdef0123456789abcdef".to_vec(),
                1,
            )
            .await
            .expect("audit initializes");
            for _ in 0..48 {
                log.append(test_audit_event(&log))
                    .await
                    .expect("event appends");
            }
        }
        let segments = audit_segment_paths(&path).expect("segments enumerate");
        assert!(
            segments.len() >= 4,
            "the fixture needs a sealed segment that is neither first nor last"
        );
        fs::remove_file(&segments[1]).expect("a middle segment is archived away");

        let error = verify_audit_chain(&path, &test_audit_secret())
            .expect_err("a gap in sealed history must fail verification");
        let sequence = match &error {
            EvidenceAuditError::SegmentMissing { sequence } => *sequence,
            other => panic!("expected a missing-segment error, got {other:?}"),
        };
        assert_eq!(sequence, 2);

        let (detail, _) = audit_verification_failure(error);
        assert!(
            detail.contains(&format!("segment {sequence}"))
                && detail.contains("archived or missing"),
            "the report must name the sequence and describe archival: {detail}"
        );
        assert!(
            detail.contains("not corruption"),
            "the report must state plainly that this is not corruption: {detail}"
        );

        assert!(verify_audit_with_secret(&path, &test_audit_secret()).is_err());
    }

    /// The offline harness must serve the fetch-set form as completely as it
    /// serves the two frozen ones: every mandatory coverage category, evaluated
    /// through the same entry point, on a bundle an adopter can copy.
    ///
    /// This bundle is a profile bundle rather than a fifth coequal acceptance
    /// definition, so it is exercised on its own instead of being added to the
    /// list above. Adding it there would claim a status it does not have.
    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_the_fetch_set_acceptance_fixture() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/surviving-spouse-status");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            &source_statements(&bundle, None).expect("statement sources bind"),
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        let fixture = Path::new(
            bundle.config.requirements[0]
                .fixtures
                .as_ref()
                .expect("acceptance fixture is declared")
                .as_str(),
        );
        let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
            .get("cases")
            .and_then(serde_norway::Value::as_sequence)
            .expect("cases")
            .len();
        assert_eq!(
            evaluate_fixture(
                &bundle,
                &kernel,
                &source_plans,
                fixture,
                None,
                true,
                &mut FixtureTrace::default(),
            )
            .await,
            Ok(FixtureSummary {
                evaluated_cases: expected_cases,
            })
        );

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    /// The stage keys a fetch-set fixture case must carry are the planned
    /// stages, exactly: no missing stage, no extra one, and not the scalar
    /// `source` key the single form uses. An adopter who omits a member would
    /// otherwise get a case that silently exercised a shorter acquisition than
    /// the one the bundle declares.
    #[cfg(unix)]
    #[test]
    fn fetch_set_fixture_sources_must_name_every_planned_stage() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/surviving-spouse-status");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let requirement = &bundle.config.requirements[0];
        let plan = requirement.acquisition.plan();
        assert!(
            plan.stages.len() >= 3,
            "the fetch-set acceptance bundle needs a search and at least two members"
        );
        let fixture = bundle.fixtures[requirement
            .fixtures
            .as_ref()
            .expect("acceptance fixture is declared")
            .as_str()]
        .clone();
        let fixture = serde_json::to_value(fixture).expect("fixture is representable");
        let positive = fixture["cases"]
            .as_array()
            .expect("cases are an array")
            .iter()
            .find(|case| case["id"] == "positive")
            .and_then(|case| case.get("sources"))
            .and_then(Value::as_object)
            .expect("the positive case carries a source response per stage")
            .clone();
        let observed_at = DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
            .expect("fixed time parses")
            .with_timezone(&Utc);
        let selectors = Value::Object(JsonMap::new());
        // A fresh trace per call. This test reads the refusal, and a shared
        // trace would carry the stages of every earlier case into the next one.
        let evaluate = |case: Value| {
            evaluate_fixture_acquisition(
                &bundle,
                &kernel,
                requirement,
                case.as_object().expect("case is an object"),
                &selectors,
                observed_at,
                &mut FixtureTrace::default(),
            )
        };

        let mut short = positive.clone();
        short.remove(&plan.stages[plan.stages.len() - 1].source);
        assert_eq!(
            evaluate(Value::Object(JsonMap::from_iter([(
                "sources".to_owned(),
                Value::Object(short)
            )]))),
            Err(CliError("chained fixture sources are not exact"))
        );

        let mut extra = positive.clone();
        extra.insert("unplanned-source".to_owned(), Value::Null);
        assert_eq!(
            evaluate(Value::Object(JsonMap::from_iter([(
                "sources".to_owned(),
                Value::Object(extra)
            )]))),
            Err(CliError("chained fixture sources are not exact"))
        );

        assert_eq!(
            evaluate(serde_json::json!({"source": Value::Object(positive)})),
            Err(CliError("search-then-fetch-set fixture must use sources"))
        );

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_every_coequal_acceptance_fixture() {
        for definition in [
            "adult-status",
            "residence-region",
            "professional-licence",
            "legal-parent-relationship",
        ] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/fixtures/acceptance")
                .join(definition);
            copy_tree(&source, directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let source_plans = compile_source_plans_with_runtime(
                &bundle.config,
                &source_statements(&bundle, None).expect("statement sources bind"),
                "/run/secrets/evidence",
                &OutboundTlsConfig {
                    system_roots: true,
                    trust_profiles: Default::default(),
                },
                &Default::default(),
            )
            .expect("source plans compile");
            let fixture = Path::new(
                bundle.config.requirements[0]
                    .fixtures
                    .as_ref()
                    .expect("acceptance fixture is declared")
                    .as_str(),
            );
            let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
                .get("cases")
                .and_then(serde_norway::Value::as_sequence)
                .expect("cases")
                .len();
            assert_eq!(
                evaluate_fixture(
                    &bundle,
                    &kernel,
                    &source_plans,
                    fixture,
                    None,
                    true,
                    &mut FixtureTrace::default()
                )
                .await,
                Ok(FixtureSummary {
                    evaluated_cases: expected_cases,
                }),
                "{definition}"
            );

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn coequal_fixture_selection_evaluates_one_exact_case_value_free() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            &source_statements(&bundle, None).expect("statement sources bind"),
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        let fixture = Path::new(
            bundle.config.requirements[0]
                .fixtures
                .as_ref()
                .expect("acceptance fixture is declared")
                .as_str(),
        );

        let mut trace = FixtureTrace::default();
        assert_eq!(
            evaluate_fixture(
                &bundle,
                &kernel,
                &source_plans,
                fixture,
                Some("positive"),
                true,
                &mut trace,
            )
            .await,
            Ok(FixtureSummary { evaluated_cases: 1 })
        );
        let rendered = trace.render();
        assert!(
            rendered.contains("positive"),
            "selected case is absent: {rendered}"
        );
        assert!(
            !rendered.contains("negative-false-is-success"),
            "another case ran: {rendered}"
        );

        let unknown = "private-case-selector-canary";
        let error = evaluate_fixture(
            &bundle,
            &kernel,
            &source_plans,
            fixture,
            Some(unknown),
            true,
            &mut FixtureTrace::default(),
        )
        .await
        .expect_err("unknown case must be refused");
        assert_eq!(error, CliError("selected fixture case is unavailable"));
        assert!(
            !error.0.contains(unknown),
            "case selector leaked: {}",
            error.0
        );

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_the_combined_acceptance_bundle() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/all-definitions");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            &source_statements(&bundle, None).expect("statement sources bind"),
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        for requirement in &bundle.config.requirements {
            let fixture = Path::new(
                requirement
                    .fixtures
                    .as_ref()
                    .expect("acceptance fixture is declared")
                    .as_str(),
            );
            assert!(
                evaluate_fixture(
                    &bundle,
                    &kernel,
                    &source_plans,
                    fixture,
                    None,
                    true,
                    &mut FixtureTrace::default()
                )
                .await
                .is_ok(),
                "combined acceptance fixture failed"
            );
        }

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_the_holder_bound_acceptance_bundle() {
        // The holder-bound twin runs the same four coequal definitions over the
        // same case fixtures, read-only and with no network. Acceptance
        // evaluation is about what each definition derives from its source, and
        // that is what the mode must leave alone: a definition that stopped
        // deciding its cases once its subjects bound to a holder key would mean
        // the mode had reached into evaluation.
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/holder-bound");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            &source_statements(&bundle, None).expect("statement sources bind"),
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        assert_eq!(bundle.config.requirements.len(), 4);
        for requirement in &bundle.config.requirements {
            assert_eq!(
                requirement.subject_binding,
                Some(SubjectBindingMode::HolderBound),
                "{} is not declared holder-bound",
                requirement.id
            );
            let fixture = Path::new(
                requirement
                    .fixtures
                    .as_ref()
                    .expect("acceptance fixture is declared")
                    .as_str(),
            );
            let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
                .get("cases")
                .and_then(serde_norway::Value::as_sequence)
                .expect("cases")
                .len();
            assert_eq!(
                evaluate_fixture(
                    &bundle,
                    &kernel,
                    &source_plans,
                    fixture,
                    None,
                    true,
                    &mut FixtureTrace::default()
                )
                .await,
                Ok(FixtureSummary {
                    evaluated_cases: expected_cases,
                }),
                "{}",
                requirement.id
            );
        }

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_every_reference_deployment_fixture() {
        for project in [
            "dhis2-tracker-evidence",
            "opencrvs-family-evidence",
            "protected-read-evidence",
        ] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/reference/request-adapter/deployment-projects")
                .join(project)
                .join("bundle");
            copy_tree(&source, directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = Arc::new(Bundle::load(directory.path()).expect("reference bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let outbound_tls: OutboundTlsConfig = if project == "dhis2-tracker-evidence" {
                serde_norway::from_str(
                    "systemRoots: true\ntrustProfiles:\n  government-internal-pki:\n    caBundleFile: /etc/registry-evidence/ca/government-internal.pem\n",
                )
                .expect("private TLS profile parses")
            } else {
                OutboundTlsConfig {
                    system_roots: true,
                    trust_profiles: Default::default(),
                }
            };
            let ca_bundles = if project == "dhis2-tracker-evidence" {
                let certificate =
                    rcgen::generate_simple_self_signed(
                        vec!["tracker.dhis2.gov.example".to_owned()],
                    )
                    .expect("generate private TLS root");
                let certificate = test_certificate_pem(certificate.cert.der().as_ref());
                BTreeMap::from([("government-internal-pki".to_owned(), certificate)])
            } else {
                BTreeMap::new()
            };
            let source_plans = compile_source_plans_with_runtime(
                &bundle.config,
                &source_statements(&bundle, None).expect("statement sources bind"),
                "/run/secrets/evidence",
                &outbound_tls,
                &ca_bundles,
            )
            .expect("source plans compile");
            for requirement in &bundle.config.requirements {
                let fixture_path = requirement
                    .fixtures
                    .as_ref()
                    .expect("reference fixture is declared");
                let fixture = Path::new(fixture_path.as_str());
                let expected_cases = bundle.fixtures[fixture_path.as_str()]
                    .get("cases")
                    .and_then(serde_norway::Value::as_sequence)
                    .expect("cases")
                    .len();
                assert_eq!(
                    evaluate_fixture(
                        &bundle,
                        &kernel,
                        &source_plans,
                        fixture,
                        None,
                        true,
                        &mut FixtureTrace::default()
                    )
                    .await,
                    Ok(FixtureSummary {
                        evaluated_cases: expected_cases,
                    }),
                    "{project}/{}",
                    requirement.id
                );
            }

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create destination");
        for entry in fs::read_dir(source).expect("read source tree") {
            let entry = entry.expect("source entry");
            let target = destination.join(entry.file_name());
            if entry.file_type().expect("source type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("copy artifact");
            }
        }
    }

    #[cfg(unix)]
    fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::symlink_metadata(path).expect("tree metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("read tree") {
                set_tree_mode(
                    &entry.expect("tree entry").path(),
                    directory_mode,
                    file_mode,
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
                .expect("set directory mode");
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
                .expect("set file mode");
        }
    }

    #[cfg(unix)]
    fn test_certificate_pem(der: &[u8]) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is UTF-8"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem.into_bytes()
    }
}
