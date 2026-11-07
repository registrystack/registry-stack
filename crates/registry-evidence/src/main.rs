//! Evidence Version 1 operator CLI and serving process.

use std::{
    collections::{BTreeMap, BTreeSet},
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
use p256::{ecdsa::SigningKey, elliptic_curve::Generate as _};
use registry_evidence::cli::{Cli, Command, ExplainFormat, OutputFormat};
use registry_evidence::{
    audit::{last_local_audit_operation, EvidenceAuditError},
    bundle::{ArtifactFault, Bundle, BundleError, DeploymentInputs, RuntimeDocument},
    check::{check_runtime_file, OfflineCheck},
    config::{
        AssuranceProfile, BurstShortfall, ConceptForm, ConfigError, EvidenceConfig,
        RequirementConfig, SelectorInput,
    },
    fixture_source::{
        compile_sources, fixture_acquisition, FixtureAcquisition, FixtureRun, OfflineSourceProgram,
    },
    kernel::{
        EvidenceConstruction, EvidenceScope, KernelError, KernelOutcome, OfflineKernel,
        ValidatedValues, ValueProjection,
    },
    local_verification::{prepare_local_relying_procedure, LocalRelyingProcedureInput},
    model::{
        AssertionChannel, JwksDocument, LookupResult, PublicValue, ScalarOrEntityReference,
        SubjectBinding, EVIDENCE_REQUEST_BATCH_MAX_ITEMS,
    },
    pack_source::{PackSourceError, PackSourceExecutor, SourceBindingError},
    problem::ProblemCode,
    rhai_runtime::{DerivedConceptValue, DerivedValue},
    runtime::{
        pack_source_failure, validate_secret_material, AuditInitializationFault, EvidenceRuntime,
        RuntimeInitializationError, SigningInitializationFault,
    },
    selector::{
        resolve_offline_fixture_authorization, resolve_offline_fixture_subjects,
        OfflineFixtureError, ResolvedAuthorization,
    },
    server,
    signing::{jwks_document, EvidenceSigner},
    trace::{
        json_type, name_list, object_keys, CategoryClass, FindingCode, FixtureReport, FixtureTrace,
        ReasonCode, ResultClass, ResultClassification, Stage, StageStatus, ValueClass,
    },
    verification_policy::{
        check_policy, read_holder_bound_policy, read_verification_policy, PolicyKind,
    },
    verifier::{
        verify_flattened_jws, verify_flattened_jws_report, verify_sd_jwt_vc_presentation_report,
        verify_sd_jwt_vc_report, EvidenceVerificationPolicy, VerificationError,
    },
};
use registry_platform_audit::{require_audit_under, AuditError, PersistentRootFault};
use registry_platform_crypto::{
    canonicalize_json, parse_json_strict, LocalJwkSigner, PrivateJwk, TransitInitializationError,
};
use registry_platform_yaml::{Report, Severity};
use serde_json::{Map as JsonMap, Value};
use zeroize::Zeroizing;

const OFFLINE_AUDIENCE: &str = "urn:registry-evidence:offline-evaluation";
const OFFLINE_BINDING_KEY: [u8; 32] = [0x45; 32];
const ANTI_RECONSTRUCTION_FIXTURE: &[u8] =
    include_bytes!("../../../products/evidence/fixtures/conformance/anti-reconstruction.yaml");

/// The companion audit role `evidence authority activate` writes under: a
/// file destination's `audit.jsonl` becomes `audit.activation.jsonl`, and a
/// `stdout` destination becomes `stderr`.
const ACTIVATION_AUDIT_PROCESS: &str = "activation";
const ACTIVATION_AUDIT_FAILED: &str = "activation audit initialization failed";
const ACTIVATION_AUDIT_REFUSED: &str =
    "activation audit refused the request entry, so nothing was activated";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError(&'static str);

/// A fixture case `source` that holds a provider response, as the retired
/// Source form wrote it, rather than a pack acquisition transcript.
const FIXTURE_SOURCE_RETIRED: &str = "fixture case `source` holds a provider response, the retired Source form; record the pack's exact `intercepts` and `exchanges` instead (products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project)";

/// A fixture case `source` that is a malformed pack acquisition transcript.
const FIXTURE_SOURCE_INVALID: &str = "fixture case `source` must contain only the pack's exact `intercepts` and `exchanges`; the transcript form is in step 5 of products/evidence/reference/authoring-projects/CONFIG.md#migrate-a-retired-source-project";

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
    Package(registry_platform_config::PackageError),
    /// One or more governed extract sources cannot answer at check time.
    ///
    /// Source identifiers come from the reviewed bundle. Publisher metadata
    /// and filesystem paths stay out of the diagnostic.
    StaleExtracts(Vec<String>),
    /// The audit boundary refused, with the value-free cause it reported.
    ///
    /// It separates its causes because an out-of-range destination, a
    /// permission bit, and a second writer holding the destination lock have
    /// nothing in common but the moment they fail.
    Audit(&'static str, AuditInitializationFault),
    /// The signing boundary refused, with the value-free cause it reported.
    ///
    /// A missing Transit socket, a retired key version, and a key that is not
    /// the governed one each need a different fix, so each names itself.
    Signing(SigningInitializationFault),
    /// The configured audit destination was not proven persistent.
    ///
    /// The fault names the side that failed and nothing else. Neither the
    /// configured destination nor the declared root appears, which keeps the
    /// diagnostic to the same value-free shape as the rest of `check`.
    AuditRoot(PersistentRootFault),
    Service(String),
    /// A pack source did not compile against its reviewed connection and
    /// runtime binding. It names the source and endpoint ids and the
    /// value-free rule broken, never an origin, secret reference or trust bytes.
    SourceBinding(SourceBindingError),
    /// The shared configuration reader refused a configuration file. Its
    /// diagnostics are printed unchanged after one sentence naming the step.
    Refused(Box<Report>),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => fmt::Display::fmt(error, formatter),
            Self::Deployment(message, fault) => write!(formatter, "{message}: {fault}"),
            Self::Package(error) => fmt::Display::fmt(error, formatter),
            Self::StaleExtracts(sources) => write!(
                formatter,
                "bound extract is stale for source{} {}",
                if sources.len() == 1 { "" } else { "s" },
                sources.join(", ")
            ),
            Self::Audit(message, fault) => write!(formatter, "{message}: {fault}"),
            Self::Signing(fault) => {
                write!(formatter, "runtime signing initialization failed: {fault}")
            }
            Self::AuditRoot(fault) => write!(formatter, "audit destination check failed: {fault}"),
            Self::Service(reason) => write!(formatter, "service failed: {reason}"),
            Self::SourceBinding(error) => write!(
                formatter,
                "source pack or connection binding failed compilation: {error}"
            ),
            Self::Refused(report) => write!(
                formatter,
                "the configuration reader refused the configuration\n{}",
                report.render_human().trim_end()
            ),
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

const FIXTURE_FACT_RECORD_API_VERSION: &str =
    "id.registrystack.org/internal/evidence/fixture-fact-record/v1alpha1";
const FIXTURE_FACT_RECORD_KIND: &str = "EvidenceFixtureFactRecord";

/// Private output for Evidencectl's explicit fixture mutation command.
///
/// The map is emitted only by the hidden child-process seam. It is never a
/// diagnostic or explain surface, and Evidencectl captures it privately.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureFactRecord {
    api_version: &'static str,
    kind: &'static str,
    evaluated_cases: usize,
    matched_facts: BTreeMap<String, JsonMap<String, Value>>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let runtime_environment_set =
        std::env::var_os(registry_evidence::cli::REMOVED_RUNTIME_ENVIRONMENT_VARIABLE).is_some();
    if let Some(refusal) = registry_evidence::cli::removed_runtime_input(
        std::env::args_os().skip(1),
        runtime_environment_set,
    ) {
        // A removed flag or environment variable is a usage error, the exit
        // a flag clap does not know gets.
        eprintln!("evidence: {refusal}");
        return ExitCode::from(2);
    }
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("evidence: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CommandError> {
    match cli.command {
        Command::Authority { command } => {
            use registry_evidence::{authority, cli::AuthorityCommand};
            let (runtime_path, document, operator_reference) = match command {
                AuthorityCommand::Activate {
                    runtime_config,
                    document,
                    operator_reference,
                } => (runtime_config, Some(document), operator_reference),
                AuthorityCommand::History { runtime_config } => (runtime_config, None, None),
            };
            // Operator inspection and authority activation need the closed
            // configuration, not source extracts, credentials or a signer.
            let mut bytes = Vec::new();
            File::open(&runtime_path)
                .and_then(|file| {
                    file.take((registry_evidence::config::MAX_CONFIG_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                })
                .map_err(|_| CommandError::Cli(CliError("runtime configuration is unavailable")))?;
            let runtime =
                registry_evidence::config::RuntimeConfig::parse_yaml_with(&bytes, |name| {
                    std::env::var(name).ok()
                })
                .map_err(
                    |error| match error.in_file(&runtime_path.display().to_string()) {
                        ConfigError::Refused(report) => CommandError::Refused(report),
                        error => CommandError::Deployment(
                            "runtime authority binding is invalid",
                            ArtifactFault::new(runtime_path.display().to_string(), error.fault()),
                        ),
                    },
                )?
                .config;
            let binding = runtime
                .authority
                .as_ref()
                .ok_or(CommandError::Cli(CliError(
                    "runtime authority binding is required",
                )))?;
            let result = if let Some(document) = document {
                let mut bytes = Vec::new();
                File::open(&document)
                    .and_then(|file| {
                        file.take((registry_evidence::config::MAX_CONFIG_BYTES + 1) as u64)
                            .read_to_end(&mut bytes)
                    })
                    .map_err(|_| {
                        CommandError::Cli(CliError("target authority document is unavailable"))
                    })?;
                match authority::AuthorityDocument::parse(&document.display().to_string(), &bytes) {
                    Ok(document) => {
                        let bundle =
                            Bundle::load_pinned(&runtime.package).map_err(deployment_load_error)?;
                        let secrets = runtime.secret_providers.resolver().map_err(|_| {
                            CommandError::Cli(CliError("activation audit secrets are unavailable"))
                        })?;
                        let secret = secrets
                            .resolve(bundle.config.audit.key.hash_key_ref.as_str())
                            .map_err(|_| {
                                CommandError::Cli(CliError("activation audit key is unavailable"))
                            })?;
                        // Activation runs while `evidence serve` holds the
                        // configured destination, so it writes that
                        // destination's companion under its own lock.
                        let destination = runtime
                            .audit
                            .destination()
                            .map_err(|_| {
                                CommandError::Audit(
                                    ACTIVATION_AUDIT_FAILED,
                                    AuditInitializationFault::Configuration,
                                )
                            })?
                            .for_process(ACTIVATION_AUDIT_PROCESS)
                            .map_err(|error| {
                                CommandError::Audit(
                                    ACTIVATION_AUDIT_FAILED,
                                    AuditInitializationFault::File(error.to_string()),
                                )
                            })?;
                        let audit = registry_evidence::audit::EvidenceAuditLog::initialize(
                            destination,
                            secret.expose_secret().to_vec(),
                            bundle.config.audit.hash_key_version.get(),
                        )
                        .await
                        .map_err(|error| {
                            CommandError::Audit(
                                ACTIVATION_AUDIT_FAILED,
                                AuditInitializationFault::from(&error),
                            )
                        })?;
                        match bundle
                            .activate_target_authority(
                                &binding.root,
                                &binding.target,
                                &document,
                                operator_reference.as_deref(),
                                &audit,
                            )
                            .await
                        {
                            Ok(snapshot) => {
                                println!(
                                    "ACTIVATED {} {} sequence={}",
                                    snapshot.revision(),
                                    snapshot.digest(),
                                    snapshot.sequence()
                                );
                                Ok(())
                            }
                            Err(authority::ActivationError::RequestUnaudited(error)) => {
                                return Err(CommandError::Audit(
                                    ACTIVATION_AUDIT_REFUSED,
                                    AuditInitializationFault::from(&error),
                                ));
                            }
                            Err(authority::ActivationError::Authority(error)) => Err(error),
                            Err(error) => {
                                eprintln!("evidence: {error}");
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                    }
                    Err(error) => Err(error),
                }
            } else {
                authority::history(&binding.root).map(|entries| {
                    for entry in entries {
                        println!(
                            "{} {} {} {}",
                            entry.sequence,
                            entry.authority_revision,
                            entry.authority_digest,
                            entry.package_digest
                        );
                    }
                })
            };
            match result {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => {
                    eprintln!("evidence: {error}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Check {
            runtime_config,
            format,
            deny_warnings,
            environment,
            require_runtime_dependencies,
            require_audit_under: audit_root,
            without_audit_lock,
        } => Ok(run_check(CheckRequest {
            runtime_config,
            format,
            deny_warnings,
            environment,
            dependencies: require_runtime_dependencies.then_some(DependencyProof {
                audit_root,
                without_audit_lock,
            }),
        })
        .await),
        Command::Evaluate {
            runtime_config,
            fixture,
            case,
            explain,
            explain_format,
        } => {
            let deployment =
                DeploymentInputs::load(&runtime_config).map_err(deployment_load_error)?;
            let (bundle, _runtime) = deployment.into_parts();
            let bundle = Arc::new(bundle);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).map_err(|error| {
                kernel_compile_error("fixture bundle compilation failed", error)
            })?;
            let source_plans = compile_bundle_source_plans(&bundle)?;
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
            // is what joins the two without changing either, and the structured
            // stderr line below reads that attribution back for every failing
            // run, explained or not: the case, the fixed cause, and the value
            // classes each side of its comparison had reached, never a value.
            if let Err(error) = &summary {
                print_fixture_failures(&mut trace, error);
            }
            if explain {
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
        Command::BundleCheck {
            bundle,
            runtime_config,
            authority_document,
            json,
        } => {
            let bundle_path = bundle;
            let bundle = match Bundle::load(&bundle_path).map_err(deployment_load_error) {
                Ok(bundle) => Arc::new(bundle),
                Err(CommandError::Refused(report)) if json => {
                    let document = CheckReport {
                        ok: false,
                        command: "bundle-check",
                        status: "domain-refusal",
                        api_version: CHECK_REPORT_API_VERSION,
                        kind: CHECK_REPORT_KIND,
                        package_digest: None,
                        requirements: None,
                        files_checked: report.files_checked().unwrap_or(1),
                        diagnostics: report.to_json_value(),
                    };
                    println!(
                        "{}",
                        serde_json::to_string(&document)
                            .map_err(|_| CliError("bundle check report could not be written"))?
                    );
                    return Ok(ExitCode::FAILURE);
                }
                Err(CommandError::Deployment(message, fault))
                    if message == DEPLOYMENT_NOT_IMMUTABLE =>
                {
                    let path = bundle_path.display().to_string();
                    let mut check = OfflineCheck::new(path.clone());
                    check.push_artifact_fault(
                        "evidence.bundle.not-immutable",
                        &fault,
                        &format!(
                            "Make the bundle read-only for every user, for example `chmod -R a-w '{path}'`, or mount it read-only, then rerun bundle-check."
                        ),
                    );
                    let report = check.report();
                    if json {
                        let document = CheckReport {
                            ok: false,
                            command: "bundle-check",
                            status: "domain-refusal",
                            api_version: CHECK_REPORT_API_VERSION,
                            kind: CHECK_REPORT_KIND,
                            package_digest: None,
                            requirements: None,
                            files_checked: report.files_checked().unwrap_or(1),
                            diagnostics: report.to_json_value(),
                        };
                        println!(
                            "{}",
                            serde_json::to_string(&document).map_err(|_| CliError(
                                "bundle check report could not be written"
                            ))?
                        );
                    } else {
                        eprint!("{}", report.render_human());
                    }
                    return Ok(ExitCode::FAILURE);
                }
                Err(error) => return Err(error),
            };
            if let Some(path) = authority_document {
                read_bundle_authority(&path, bundle.as_ref())?;
            }
            if let Some(path) = runtime_config {
                let checked = registry_evidence::check::check_runtime_bindings_file(&path, &bundle);
                if checked.has_errors() {
                    let report = checked.report();
                    if json {
                        let document = CheckReport {
                            ok: false,
                            command: "bundle-check",
                            status: "domain-refusal",
                            api_version: CHECK_REPORT_API_VERSION,
                            kind: CHECK_REPORT_KIND,
                            package_digest: None,
                            requirements: None,
                            files_checked: report.files_checked().unwrap_or(1),
                            diagnostics: report.to_json_value(),
                        };
                        println!(
                            "{}",
                            serde_json::to_string(&document).map_err(|_| {
                                CliError("bundle check report could not be written")
                            })?
                        );
                    } else {
                        eprint!("{}", report.render_human());
                    }
                    return Ok(ExitCode::FAILURE);
                }
            }
            OfflineKernel::compile(Arc::clone(&bundle))
                .map_err(|error| kernel_compile_error("bundle compilation failed", error))?;
            let _source_plans = compile_bundle_source_plans(&bundle)?;
            if json {
                println!("{}", package_digest_report(&bundle)?);
            } else {
                println!(
                    "Evidence package {} passed check ({} requirements)",
                    bundle.package_digest(),
                    bundle.config.requirements.len()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::BundleEvaluate {
            bundle,
            authority_document,
            fixture,
            case,
            explain,
            explain_format,
        } => {
            let mut bundle = Bundle::load(&bundle).map_err(deployment_load_error)?;
            if let Some(path) = authority_document {
                let document = read_bundle_authority(&path, &bundle)?;
                // This copy can reach only the offline fixture kernel, never
                // DeploymentInputs or serving initialization. No authority
                // store, credential, source or operator signer is accessed.
                document.apply_to(&mut bundle.config);
            } else if bundle.config.project.is_some() {
                return Err(CliError("normalized fixtures require --authority-document with the compiled target grants").into());
            }
            let bundle = Arc::new(bundle);
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
                true,
                &mut trace,
            )
            .await;
            validate_trace_canaries(&trace)?;
            // The same attribution and structured failure line the deployment
            // evaluation prints, read by the fixture driver that owns this
            // seam: it parses the line rather than the trace.
            if let Err(error) = &summary {
                print_fixture_failures(&mut trace, error);
            }
            if explain {
                match explain_format.unwrap_or_default() {
                    ExplainFormat::Text => print!("{}", trace.render()),
                    ExplainFormat::Json => {
                        println!("{}", fixture_report_json(&trace, summary.as_ref())?);
                        summary?;
                        return Ok(ExitCode::SUCCESS);
                    }
                }
            }
            let summary = summary?;
            println!(
                "Evidence fixture passed ({} evaluated cases)",
                summary.evaluated_cases
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::BundleRecordFixtureFacts {
            bundle,
            authority_document,
            fixture,
        } => {
            let mut bundle = Bundle::load(&bundle).map_err(deployment_load_error)?;
            if let Some(path) = authority_document {
                let document = read_bundle_authority(&path, &bundle)?;
                document.apply_to(&mut bundle.config);
            } else if bundle.config.project.is_some() {
                return Err(CliError("normalized fixtures require --authority-document with the compiled target grants").into());
            }
            let bundle = Arc::new(bundle);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).map_err(|error| {
                kernel_compile_error("fixture bundle compilation failed", error)
            })?;
            let source_plans = compile_bundle_source_plans(&bundle)?;
            let record =
                record_fixture_facts(&bundle, &kernel, &source_plans, &fixture, None).await?;
            println!(
                "{}",
                serde_json::to_string(&record)
                    .map_err(|_| CliError("fixture fact record could not be written"))?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::RenderDiscoveryDescription { config } => {
            let bytes = fs::read(&config).map_err(|_| DISCOVERY_CONFIG_UNREADABLE)?;
            let config = EvidenceConfig::parse_yaml(&bytes).map_err(|error| {
                discovery_config_invalid(error.in_file(&config.display().to_string()))
            })?;
            // Configuration validation projects the publication before it
            // accepts the document, so every projection refusal is already
            // reported as an invalid configuration and this call cannot fail
            // for a document that parsed. The refusal is still classified
            // rather than unwrapped, and it is classified as the same invalid
            // configuration `validate` would have reported.
            if let Some(rendered) = registry_evidence::discovery::render(&config)
                .map_err(|_| DISCOVERY_CONFIG_INVALID)?
            {
                std::io::stdout()
                    .write_all(&rendered)
                    .map_err(|_| DISCOVERY_OUTPUT_UNWRITABLE)?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Serve { runtime_config } => {
            install_operational_logging();
            // Installed before anything is loaded or served, so a failure to
            // install a handler refuses startup.
            let shutdown = stop_signal(registry_platform_httpsec::shutdown_signal)?;
            // The inputs are loaded here rather than inside the runtime so a
            // refused configuration reports its diagnostics, not only a class.
            let deployment =
                DeploymentInputs::load(&runtime_config).map_err(deployment_load_error)?;
            let runtime = Arc::new(
                EvidenceRuntime::initialize_from(deployment)
                    .await
                    .map_err(runtime_initialization_error)?,
            );
            // The startup announcement belongs to the server, which makes it
            // after both listeners are held. Nothing is reported here, because
            // a start reported before the bind describes a service that may
            // never have got its port.
            server::serve(runtime, shutdown)
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
        Command::CheckPolicy {
            verification_policy,
            holder_bound_policy,
            format,
            deny_warnings,
        } => {
            let (path, kind) = match (verification_policy, holder_bound_policy) {
                (Some(path), None) => (path, PolicyKind::Verification),
                (None, Some(path)) => (path, PolicyKind::HolderBound),
                _ => {
                    return Err(CommandError::Cli(CliError(
                        "check-policy requires exactly one policy file",
                    )));
                }
            };
            Ok(run_check_policy(&path, kind, format, deny_warnings))
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
        Command::PrepareLocalRelyingProcedure {
            runtime_config,
            input,
        } => prepare_local_relying_procedure_command(&runtime_config, &input).await,
        Command::LocalAuditLastOperation { runtime_config } => {
            local_audit_last_operation_command(&runtime_config)
        }
    }
}

/// The three ways provider-publication compilation refuses.
///
/// Each stage of the compilation reports its own class, so an adopter learns
/// whether the configuration was unreadable, refused as Evidence
/// configuration, or never reached standard output. Every class is fixed
/// text: the configured path and the document's own keys and scalars stay out
/// of it, exactly as they stay out of `check`.
///
/// A parse refusal appends the parser's closed, value-free cause — the
/// contract clause or bound that refused, plus the schema path and text
/// location when the decoder knew them — so an operator learns which field
/// failed without any configured value reaching the message.
///
/// The projection has no class of its own because it has no refusal of its
/// own. `EvidenceConfig::validate` renders the publication before it accepts
/// the document and refuses the document when the render refuses, and the
/// render is a no-op when no publication is configured, so every projection
/// refusal is an invalid configuration before this command sees it.
const DISCOVERY_CONFIG_UNREADABLE: CliError =
    CliError("discovery description configuration could not be read");
const DISCOVERY_CONFIG_INVALID: CliError =
    CliError("discovery description configuration is not valid Evidence configuration");
const DISCOVERY_OUTPUT_UNWRITABLE: CliError =
    CliError("discovery description output could not be written");

/// Validate one compiled authority through the runtime's owning contract.
/// This offline check neither activates grants nor initializes dependencies.
fn read_bundle_authority(
    path: &Path,
    bundle: &Bundle,
) -> Result<registry_evidence::authority::AuthorityDocument, CommandError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take((registry_evidence::config::MAX_CONFIG_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| CliError("compiled target authority is unavailable"))?;
    let document =
        registry_evidence::authority::AuthorityDocument::parse(&path.display().to_string(), &bytes)
            .map_err(|_| CliError("compiled target authority document is invalid"))?;
    document
        .validate_for(&document.target, &bundle.config)
        .map_err(|_| CliError("compiled target authority exceeds the package ceilings"))?;
    bundle
        .validate_target_authority(&document.target, &document)
        .map_err(deployment_load_error)?;
    Ok(document)
}

/// Report a refused discovery configuration with the cause the parser carried.
///
/// The class is the same fixed text as every other invalid configuration; the
/// appended cause is the parser's own value-free diagnostic, which names the
/// contract clause and, for a bound violation, the closed field label it
/// applies to.
fn discovery_config_invalid(error: ConfigError) -> CommandError {
    if let ConfigError::Refused(report) = error {
        return CommandError::Refused(report);
    }
    CommandError::Deployment(
        "discovery description configuration is not valid Evidence configuration",
        ArtifactFault::new("evidence.yaml", error.fault()),
    )
}

/// One `evidence check` invocation.
struct CheckRequest {
    runtime_config: PathBuf,
    format: OutputFormat,
    deny_warnings: bool,
    environment: bool,
    /// The target-host proof `--require-runtime-dependencies` asks for.
    dependencies: Option<DependencyProof>,
}

struct DependencyProof {
    audit_root: Option<PathBuf>,
    without_audit_lock: bool,
}

/// The `apiVersion` and `kind` of the `evidence/ctl-report` format, which
/// `evidencectl` reports carry too. The runtime cannot depend on
/// `registry-evidencectl`, so `evidencectl` holds the same two strings and a
/// test there keeps them equal.
const CHECK_REPORT_API_VERSION: &str = "id.registrystack.org/formats/evidence/ctl-report/v1alpha1";
const CHECK_REPORT_KIND: &str = "EvidenceCtlReport";

/// The `evidence check --format json` document: the ctl report envelope
/// around the CFG-DIAG-1 diagnostics.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckReport<'a> {
    ok: bool,
    command: &'static str,
    status: &'static str,
    api_version: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requirements: Option<usize>,
    files_checked: usize,
    diagnostics: Value,
}

/// Run the offline check, then the target-host proof when it was asked for
/// and the offline check found no error, and report everything found.
///
/// Exit 0 when no error was reported, 1 when the configuration was refused
/// (or a warning was reported under `--deny-warnings`), and 3 when something
/// the check depends on could not be read or reached.
async fn run_check(request: CheckRequest) -> ExitCode {
    let mut check = check_runtime_file(&request.runtime_config, request.environment);
    let mut accepted = None;
    if let Some(bundle) = check.bundle().cloned() {
        let bundle = Arc::new(bundle);
        let mut compiled = true;
        if let Err(error) = OfflineKernel::compile(Arc::clone(&bundle)) {
            push_command_error(
                &mut check,
                "evidence.bundle.compile-refused",
                kernel_compile_error("bundle compilation failed", error),
            );
            compiled = false;
        }
        if let Err(error) = compile_bundle_source_plans(&bundle) {
            push_command_error(&mut check, "evidence.source.plan-refused", error);
            compiled = false;
        }
        // A warning, not a refusal: a burst below the largest batch is a
        // deliberate cap on some deployments. It names the ceiling and the
        // key to change, never a configured value.
        if let Some(shortfall) = bundle.config.burst_shortfall() {
            let ceiling = match shortfall {
                BurstShortfall::RequestBatch => {
                    format!("{EVIDENCE_REQUEST_BATCH_MAX_ITEMS}, the request batch item ceiling")
                }
                BurstShortfall::HolderBoundBatch => "maximumHolderBoundBatchSize".to_owned(),
            };
            check.push_bundle_member(
                Severity::Warning,
                "evidence.bundle.burst-below-largest-request",
                "/rateLimits/burstPerPrincipal",
                format!(
                    "the burst is below {ceiling}, the largest request cost this bundle admits: \
                     a request batch or holder-bound release that costs more than the burst is \
                     always refused as evidence.invalid-request"
                ),
                format!(
                    "Raise rateLimits.burstPerPrincipal to at least {ceiling}, unless capping \
                     those requests is intended."
                ),
            );
        }
        if compiled {
            accepted = Some(bundle);
        }
    }
    if let Some(proof) = &request.dependencies {
        if !check.has_errors() && !check.is_unavailable() {
            if let Err(error) = prove_runtime_dependencies(&request.runtime_config, proof).await {
                push_dependency_error(&mut check, error);
            }
        }
    }

    let report = check.report();
    let refused = check.has_errors() || (request.deny_warnings && report.warning_count() > 0);
    let (status, exit) = if check.is_unavailable() {
        ("operational-failure", ExitCode::from(3))
    } else if refused {
        ("domain-refusal", ExitCode::FAILURE)
    } else {
        ("complete", ExitCode::SUCCESS)
    };
    // The package is reported as passing only when the check as a whole
    // passed, so `--deny-warnings` never prints a success line.
    let accepted = accepted.filter(|_| status == "complete");
    match request.format {
        OutputFormat::Json => {
            let document = CheckReport {
                ok: status == "complete",
                command: "check",
                status,
                api_version: CHECK_REPORT_API_VERSION,
                kind: CHECK_REPORT_KIND,
                package_digest: accepted.as_deref().map(Bundle::package_digest),
                requirements: accepted
                    .as_deref()
                    .map(|bundle| bundle.config.requirements.len()),
                files_checked: report.files_checked().unwrap_or(1),
                diagnostics: report.to_json_value(),
            };
            match serde_json::to_string(&document) {
                Ok(text) => println!("{text}"),
                Err(_) => {
                    eprintln!("evidence: the check report could not be written");
                    return ExitCode::from(3);
                }
            }
        }
        OutputFormat::Human => {
            if let Some(bundle) = &accepted {
                println!(
                    "Evidence package {} passed check ({} requirements)",
                    bundle.package_digest(),
                    bundle.config.requirements.len()
                );
            }
            eprint!("{}", report.render_human());
        }
    }
    exit
}

/// Check one verification policy offline and report every problem found.
///
/// Exit 0 when the policy reads as its verify command reads it, 1 when it
/// was refused (or, with `deny_warnings`, warned about), and 3 when the file
/// could not be read.
fn run_check_policy(
    path: &Path,
    kind: PolicyKind,
    format: OutputFormat,
    deny_warnings: bool,
) -> ExitCode {
    let check = check_policy(path, kind);
    let report = &check.report;
    let (status, exit) = if check.unavailable {
        ("operational-failure", ExitCode::from(3))
    } else if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        ("domain-refusal", ExitCode::FAILURE)
    } else {
        ("complete", ExitCode::SUCCESS)
    };
    match format {
        OutputFormat::Json => {
            let document = CheckReport {
                ok: status == "complete",
                command: "check-policy",
                status,
                api_version: CHECK_REPORT_API_VERSION,
                kind: CHECK_REPORT_KIND,
                package_digest: None,
                requirements: None,
                files_checked: report.files_checked().unwrap_or(1),
                diagnostics: report.to_json_value(),
            };
            match serde_json::to_string(&document) {
                Ok(text) => println!("{text}"),
                Err(_) => {
                    eprintln!("evidence: the check report could not be written");
                    return ExitCode::from(3);
                }
            }
        }
        OutputFormat::Human => {
            if status == "complete" {
                let label = match kind {
                    PolicyKind::Verification => "verification policy",
                    PolicyKind::HolderBound => "holder-bound verification policy",
                };
                println!("Evidence {label} passed check");
            }
            eprint!("{}", report.render_human());
        }
    }
    exit
}

/// Prove what startup proves on the target host, from a fresh capture of the
/// deployment inputs.
async fn prove_runtime_dependencies(
    runtime_config: &Path,
    proof: &DependencyProof,
) -> Result<(), CommandError> {
    // The inputs are captured once. Every proof below, and the runtime the
    // dependency check initializes, reads this capture rather than the
    // pathname again, so what passed is what gets opened.
    let deployment = DeploymentInputs::load(runtime_config).map_err(deployment_load_error)?;
    let runtime = deployment.runtime().clone();
    let bundle = Arc::new(deployment.bundle().clone());
    let source_plans = compile_source_plans(&bundle, &runtime)?;
    let now = Utc::now();
    let mut stale_sources = Vec::new();
    for (source_id, source) in &source_plans {
        if let Err(failure) = source.diagnose_extract_freshness(now) {
            if failure.category() == PackSourceError::ExtractStale {
                stale_sources.push(source_id.clone());
                continue;
            }
            if let Some(fault) = failure.artifact_fault() {
                return Err(CommandError::Deployment(
                    "the governed extract source is unavailable",
                    fault.clone(),
                ));
            }
            return Err(CliError(DEPENDENCY_UNAVAILABLE).into());
        }
    }
    if !stale_sources.is_empty() {
        return Err(CommandError::StaleExtracts(stale_sources));
    }
    // Deployment secret material is validated exactly as startup validates
    // it, before the audit destination is opened.
    // Source credentials stay unresolved here: readiness owns them.
    let secrets = runtime
        .config
        .secret_providers
        .resolver()
        .map_err(|_| runtime_initialization_error(RuntimeInitializationError::Secrets))?;
    validate_secret_material(&bundle, &runtime.config, &secrets)
        .await
        .map_err(runtime_initialization_error)?;
    // The deployment owns storage persistence and declares the root it
    // mounts; Evidence owns where the audit file resolves. Proving
    // containment before the writer opens keeps the two boundaries separate
    // and never relaxes the writability proof below. A stdout destination has
    // no file to contain, so the flag is refused rather than silently
    // satisfied.
    if let Some(root) = proof.audit_root.as_deref() {
        let audit_path = runtime
            .config
            .audit
            .path
            .as_deref()
            .ok_or(AUDIT_ROOT_WITHOUT_FILE)?;
        require_audit_under(Path::new(audit_path), root).map_err(CommandError::AuditRoot)?;
    }
    let available = if proof.without_audit_lock {
        // The candidate shares the running writer's audit path, so the lock is
        // that writer's. Everything else is proved.
        EvidenceRuntime::check_dependencies_without_audit_lock(deployment)
            .await
            .map_err(runtime_initialization_error)?
    } else {
        let serving = EvidenceRuntime::initialize_from(deployment)
            .await
            .map_err(runtime_initialization_error)?;
        serving.key_source_ready().await && serving.ready().await
    };
    if !available {
        return Err(CliError(DEPENDENCY_UNAVAILABLE).into());
    }
    Ok(())
}

const AUDIT_ROOT_WITHOUT_FILE: CliError = CliError(
    "--require-audit-under needs a file audit destination; this runtime writes audit to stdout",
);
const DEPENDENCY_UNAVAILABLE: &str = "a required runtime dependency is unavailable";
const DEPLOYMENT_UNAVAILABLE: &str = "deployment input is unavailable";
const DEPLOYMENT_NOT_IMMUTABLE: &str = "deployment input is not immutable";
const SECRETS_UNAVAILABLE: &str = "runtime secret initialization failed";
const SOURCES_UNAVAILABLE: &str = "runtime source initialization failed";
const RATE_LIMIT_UNAVAILABLE: &str = "runtime rate-limit initialization failed";

/// Report a failure of the offline check's compilation step as one
/// diagnostic under `code`.
fn push_command_error(check: &mut OfflineCheck, code: &str, error: CommandError) {
    const ACTION: &str = "Correct the artifact the message names and rebuild the package with `evidencectl package`.";
    match error {
        CommandError::Deployment(_, fault) => check.push_artifact_fault(code, &fault, ACTION),
        CommandError::Refused(report) => check.extend(*report),
        other => check.push_deployment(Severity::Error, code, other.to_string(), ACTION),
    }
}

/// Report a failure of the target-host proof as one diagnostic about the
/// deployment. A dependency that could not be read or reached makes the check
/// exit 3; a deployment input the runtime refuses makes it exit 1.
fn push_dependency_error(check: &mut OfflineCheck, error: CommandError) {
    let unavailable = |check: &mut OfflineCheck, code: &str, message: String, action: &str| {
        check.mark_unavailable();
        check.push_deployment(Severity::Error, code, message, action);
    };
    match error {
        CommandError::Deployment(message, fault) if message == DEPLOYMENT_NOT_IMMUTABLE => check
            .push_artifact_fault(
                "evidence.deployment.not-immutable",
                &fault,
                "Make the file read-only for every user, or mount it on a read-only filesystem.",
            ),
        CommandError::Deployment(_, fault) => check.push_artifact_fault(
            "evidence.deployment.invalid-input",
            &fault,
            "Correct the deployment input the message names, then run the check again.",
        ),
        CommandError::Refused(report) => check.extend(*report),
        CommandError::Package(error) => check.push_deployment(
            Severity::Error,
            "evidence.deployment.package-refused",
            error.naming_root_as("package.root").to_string(),
            "Deploy the whole package directory `evidencectl package` built, unchanged.",
        ),
        CommandError::StaleExtracts(sources) => unavailable(
            check,
            "evidence.deployment.stale-extract",
            CommandError::StaleExtracts(sources).to_string(),
            "Publish a current extract for each named source, or bind one in sourceExtracts.",
        ),
        CommandError::Audit(message, fault) => {
            let action = match &fault {
                AuditInitializationFault::Configuration => {
                    "Correct the audit block in the runtime file."
                }
                AuditInitializationFault::Secret => {
                    "Provision the audit hash key the audit block references, and make it readable by this user."
                }
                AuditInitializationFault::Storage | AuditInitializationFault::File(_) => {
                    "Make the audit destination writable by this user and free of another writer, as the message says."
                }
            };
            // An out-of-range audit block is refused input; a key, a file,
            // or storage this host could not use is an unavailable
            // dependency.
            if fault == AuditInitializationFault::Configuration {
                check.push_deployment(
                    Severity::Error,
                    "evidence.deployment.audit-refused",
                    format!("{message}: {fault}"),
                    action,
                );
            } else {
                unavailable(
                    check,
                    "evidence.deployment.audit-unavailable",
                    format!("{message}: {fault}"),
                    action,
                );
            }
        }
        // A signing key this host could not read, or a provider that did not
        // serve it, is an unavailable dependency. A key that is served but is
        // not the one the bundle governs is refused input.
        CommandError::Signing(fault) => {
            let message = CommandError::Signing(fault).to_string();
            let action = "Provision the signing key the signer block names, as the message says.";
            if signing_dependency_unavailable(fault) {
                unavailable(check, "evidence.deployment.signing-unavailable", message, action);
            } else {
                check.push_deployment(
                    Severity::Error,
                    "evidence.deployment.signing-refused",
                    message,
                    action,
                );
            }
        }
        CommandError::AuditRoot(fault) => check.push_deployment(
            Severity::Error,
            "evidence.deployment.audit-outside-root",
            CommandError::AuditRoot(fault).to_string(),
            "Point audit.path at a file under the directory --require-audit-under names, or mount persistent storage there.",
        ),
        CommandError::Cli(error) if error == AUDIT_ROOT_WITHOUT_FILE => check.push_deployment(
            Severity::Error,
            "evidence.deployment.audit-not-a-file",
            error.to_string(),
            "Set audit.path to a file, or leave out --require-audit-under.",
        ),
        CommandError::Cli(error) => {
            let message = error.to_string();
            match error.0 {
                DEPLOYMENT_UNAVAILABLE => unavailable(
                    check,
                    "evidence.deployment.unavailable",
                    message,
                    "Make the runtime file, the package, and the files they name readable by this user.",
                ),
                SECRETS_UNAVAILABLE => unavailable(
                    check,
                    "evidence.deployment.secret-unavailable",
                    message,
                    "Provision every secret the runtime file references, readable by this user and by no other.",
                ),
                SOURCES_UNAVAILABLE => unavailable(
                    check,
                    "evidence.deployment.source-unavailable",
                    message,
                    "Provision the source credentials and trust the sources need, then run the check again.",
                ),
                RATE_LIMIT_UNAVAILABLE => unavailable(
                    check,
                    "evidence.deployment.rate-limit-unavailable",
                    message,
                    "Correct the rateLimits block, then run the check again.",
                ),
                DEPENDENCY_UNAVAILABLE => unavailable(
                    check,
                    "evidence.deployment.dependency-unavailable",
                    message,
                    "Make the signer and every source and token issuer reachable from this host, then run the check again.",
                ),
                _ => check.push_deployment(
                    Severity::Error,
                    "evidence.deployment.refused",
                    message,
                    "Correct the deployment the message names, then run the check again.",
                ),
            }
        }
        CommandError::Service(reason) => unavailable(
            check,
            "evidence.deployment.unavailable",
            reason,
            "Run the check again on the target host.",
        ),
        CommandError::SourceBinding(error) => check.push_deployment(
            Severity::Error,
            "evidence.deployment.refused",
            CommandError::SourceBinding(error).to_string(),
            "Correct the named endpoint's sourceConnections entry in the runtime file, or its reviewed policy in the bundle and rebuild with `evidencectl package`, then run the check again.",
        ),
    }
}

/// Whether a signing fault means the key or its provider could not be reached
/// or read from this host, rather than that what it served is refused.
fn signing_dependency_unavailable(fault: SigningInitializationFault) -> bool {
    matches!(
        fault,
        SigningInitializationFault::LocalKey
            | SigningInitializationFault::Transit(
                TransitInitializationError::Unavailable
                    | TransitInitializationError::Refused
                    | TransitInitializationError::ProviderFailed
                    | TransitInitializationError::InvalidResponse
            )
    )
}

/// Report a startup failure with the artifact diagnostic it carries.
///
/// The failure class stays a fixed operator message. When the loader knew
/// which artifact failed, the value-free diagnostic is appended so that
/// `evidence check` names a file, a schema path, and a text location instead
/// of only a class. Public HTTP problems are unaffected and stay generic.
fn deployment_load_error(error: BundleError) -> CommandError {
    let error = match error {
        BundleError::Package(error) => return CommandError::Package(error),
        BundleError::Refused(report) => return CommandError::Refused(report),
        other => other,
    };
    let message = match &error {
        BundleError::Unavailable => DEPLOYMENT_UNAVAILABLE,
        BundleError::NotImmutable(_) => DEPLOYMENT_NOT_IMMUTABLE,
        BundleError::UnsupportedEntry => "deployment contains an unsupported entry",
        BundleError::InvalidPath => "deployment contains an invalid path binding",
        BundleError::UnknownFile(_) => "deployment artifact closure is invalid",
        BundleError::TooLarge => "deployment exceeds a Version 1 size bound",
        BundleError::Config(_) => "deployment configuration is invalid",
        BundleError::InvalidArtifact(_) => "deployment artifact is invalid",
        BundleError::InvalidScript(_) => "deployment script is invalid",
        BundleError::Package(_) | BundleError::Refused(_) => {
            unreachable!("package errors and reader refusals returned above")
        }
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
        RuntimeInitializationError::Secrets => CliError(SECRETS_UNAVAILABLE).into(),
        RuntimeInitializationError::Audit(fault) => {
            CommandError::Audit("runtime audit initialization failed", fault)
        }
        RuntimeInitializationError::Signing(fault) => CommandError::Signing(fault),
        RuntimeInitializationError::Source(error) => CommandError::SourceBinding(error),
        RuntimeInitializationError::ChannelSource { pointer, cause } => {
            tracing::error!(%pointer, cause, "an Evidence source is on the wrong acquisition channel");
            CliError(SOURCES_UNAVAILABLE).into()
        }
        RuntimeInitializationError::RateLimit => CliError(RATE_LIMIT_UNAVAILABLE).into(),
        RuntimeInitializationError::IssuerTrust => CliError(
            "runtime authentication initialization failed: the access-token issuer TLS trust profile does not resolve to a bound certificate bundle trusted beside the system roots",
        )
        .into(),
    }
}

/// Compile live sources against the process-captured runtime authority.
fn compile_source_plans(
    bundle: &Bundle,
    runtime: &RuntimeDocument,
) -> Result<BTreeMap<String, PackSourceExecutor>, CommandError> {
    let secrets = Arc::new(
        runtime
            .config
            .secret_providers
            .resolver()
            .map_err(|_| CliError("source secret provider is invalid"))?,
    );
    registry_evidence::pack_source::build_sources(bundle, runtime, &secrets)
        .map_err(CommandError::SourceBinding)
}

fn package_digest_report(bundle: &Bundle) -> Result<Value, CliError> {
    let requirements = bundle
        .config
        .requirements
        .iter()
        .map(|requirement| {
            let revision = bundle
                .configuration_revision(&requirement.id)
                .ok_or(CliError(
                    "validated requirement has no configuration revision",
                ))?;
            Ok(serde_json::json!({"id": requirement.id, "configurationRevision": revision}))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(serde_json::json!({"packageDigest": bundle.package_digest(), "requirements": requirements}))
}

fn compile_bundle_source_plans(
    bundle: &Bundle,
) -> Result<BTreeMap<String, OfflineSourceProgram>, CommandError> {
    compile_sources(bundle)
        .map_err(|error| kernel_compile_error("source pack compilation failed", error))
}

/// Install the operational log subscriber for the serving process.
///
/// Records are line-delimited JSON on stderr so a collector can read them
/// without a parsing convention of its own, and so a `stdout` audit
/// destination carries audit entries alone, whatever the destination is.
/// `EVIDENCE_LOG` selects verbosity and defaults to `info`, which is the level
/// the request boundary emits at. Offline commands print their own result and
/// install nothing, so no command gains log output it did not have.
fn install_operational_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("EVIDENCE_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .init();
}

/// Install the operator stop signal handlers, or refuse startup.
///
/// A service manager and a container runtime both stop a process with
/// SIGTERM, and an interactive operator uses Ctrl-C. Both resolve the returned
/// future, so the same drain runs either way: the server stops accepting,
/// finishes its in-flight evaluations, and flushes the audit destination
/// before the process exits. A handler that cannot be installed is a startup
/// error, so a service that no signal can drain is never left running.
/// `install` is [`registry_platform_httpsec::shutdown_signal`] in production.
fn stop_signal<S>(install: impl FnOnce() -> std::io::Result<S>) -> Result<S, CommandError> {
    install().map_err(|error| {
        CommandError::Service(format!(
            "the stop signal handlers could not be installed, so Evidence did not start: {error}"
        ))
    })
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
/// The closed failure classes of local audit inspection that name their
/// cause. Each is fixed text, so `evidencectl` can tell them apart without
/// ever echoing what the process wrote.
const LOCAL_AUDIT_INVALID_ENTRY: CliError =
    CliError("local audit inspection failed: an entry is not well formed");
const LOCAL_AUDIT_WRITER_RUNNING: CliError =
    CliError("local audit inspection failed: a writer still holds the audit file");
const LOCAL_AUDIT_REQUEST_BATCH: CliError =
    CliError("local audit inspection failed: the last operation is a request batch");
/// Exit status, with nothing written, for a stopped local chain that verified
/// and retains no operation. It is a verified answer, not a failure, so it
/// stays apart from the one collapsed failure class.
const LOCAL_AUDIT_NO_OPERATION_EXIT_CODE: u8 = 3;

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
/// The reader takes the audit destination lock, so it refuses while a server
/// still writes. Every failure is reported as one of a few fixed, value-free
/// classes. Retained files that read and hold no operation exit with their own
/// status. The view is written only after every retained file and its native
/// entries have parsed, so stdout can never contain a partial operation.
/// A `stdout` destination retains nothing locally and is refused.
fn local_audit_last_operation_command(runtime_path: &Path) -> Result<ExitCode, CommandError> {
    let deployment = DeploymentInputs::load(runtime_path).map_err(|_| LOCAL_AUDIT_FAILED)?;
    if deployment.bundle().config.assurance_profile != AssuranceProfile::Local {
        return Err(LOCAL_AUDIT_FAILED.into());
    }
    let audit_path = deployment
        .runtime()
        .config
        .audit
        .path
        .as_deref()
        .ok_or(LOCAL_AUDIT_FAILED)?;
    let view = match last_local_audit_operation(Path::new(audit_path)) {
        Ok(view) => view,
        Err(EvidenceAuditError::NoOperation) => {
            return Ok(ExitCode::from(LOCAL_AUDIT_NO_OPERATION_EXIT_CODE));
        }
        Err(error) => return Err(local_audit_failure(&error).into()),
    };
    write_canonical_json_line(&view, LOCAL_AUDIT_FAILED)?;
    Ok(ExitCode::SUCCESS)
}

/// The closed class a local audit inspection failure reports. Only causes an
/// operator can act on differently are named; everything else is the one
/// collapsed class.
fn local_audit_failure(error: &EvidenceAuditError) -> CliError {
    match error {
        EvidenceAuditError::RequestBatchOperation => LOCAL_AUDIT_REQUEST_BATCH,
        EvidenceAuditError::InvalidEvent => LOCAL_AUDIT_INVALID_ENTRY,
        EvidenceAuditError::Audit(AuditError::Io(io))
            if io.kind() == std::io::ErrorKind::InvalidData =>
        {
            LOCAL_AUDIT_INVALID_ENTRY
        }
        EvidenceAuditError::Audit(AuditError::SinkLocked { .. }) => LOCAL_AUDIT_WRITER_RUNNING,
        _ => LOCAL_AUDIT_FAILED,
    }
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
    // The command reports only the closed class; `evidence check-policy`
    // reports where the policy is wrong.
    let document = read_verification_policy(
        &policy_path.display().to_string(),
        &read_verification_input(policy_path)?,
    )
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
const POSSESSION_STATEMENT: &str = "proven when the key-binding JWT was signed; not proof that the presentation is fresh, single-use, or unreplayed";

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
    let document = read_holder_bound_policy(
        &policy_path.display().to_string(),
        &read_verification_input(policy_path)?,
    )
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

/// Render one fixture run as the single JSON document the JSON form prints.
///
/// The verdict comes from the run's own result rather than from the trace, so a
/// document can never report a pass the command did not report. The failing
/// case is the one the run's message was attributed to after the canaries were
/// checked, so a failed document names it and a passed one carries nothing.
/// Attribute a failed run's message and print one structured line per failing
/// case, each followed by the indented detail lines of the stages it failed.
///
/// A coequal fixture run attributes each failing case as it settles it, so
/// only a failure that no case owns still needs attributing here.
fn print_fixture_failures(trace: &mut FixtureTrace, error: &CliError) {
    if trace.case_failures().is_empty() {
        trace.fail(error.0);
    }
    for failure in trace.case_failures() {
        eprintln!("{}", failure.render_line());
        for detail in &failure.details {
            eprintln!("  {detail}");
        }
    }
}

fn fixture_report_json(
    trace: &FixtureTrace,
    summary: Result<&FixtureSummary, &CliError>,
) -> Result<String, CliError> {
    let report = FixtureReport {
        passed: summary.is_ok(),
        evaluated_cases: summary
            .ok()
            .map(|summary| summary.evaluated_cases)
            .or_else(|| (trace.case_count() > 0).then(|| trace.case_count())),
        failing_case: (summary.is_err())
            .then(|| trace.case_failures())
            .and_then(|failures| failures.first().cloned()),
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

async fn evaluate_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, OfflineSourceProgram>,
    fixture_path: &Path,
    selected_case: Option<&str>,
    exercise_signing: bool,
    trace: &mut FixtureTrace,
) -> Result<FixtureSummary, CliError> {
    evaluate_fixture_with_fact_record(
        bundle,
        kernel,
        source_plans,
        fixture_path,
        selected_case,
        exercise_signing,
        trace,
        None,
    )
    .await
}

/// Evaluate one coequal fixture while privately retaining only the final
/// facts of actual pack matches. A successful return means every ordinary
/// semantic assertion other than the old `expectedFacts` value passed.
async fn record_fixture_facts(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, OfflineSourceProgram>,
    fixture_path: &Path,
    selected_case: Option<&str>,
) -> Result<FixtureFactRecord, CliError> {
    let mut matched_facts = BTreeMap::new();
    let mut trace = FixtureTrace::default();
    let summary = evaluate_fixture_with_fact_record(
        bundle,
        kernel,
        source_plans,
        fixture_path,
        selected_case,
        true,
        &mut trace,
        Some(&mut matched_facts),
    )
    .await?;
    validate_trace_canaries(&trace)?;
    Ok(FixtureFactRecord {
        api_version: FIXTURE_FACT_RECORD_API_VERSION,
        kind: FIXTURE_FACT_RECORD_KIND,
        evaluated_cases: summary.evaluated_cases,
        matched_facts,
    })
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_fixture_with_fact_record(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, OfflineSourceProgram>,
    fixture_path: &Path,
    selected_case: Option<&str>,
    exercise_signing: bool,
    trace: &mut FixtureTrace,
    mut matched_facts: Option<&mut BTreeMap<String, JsonMap<String, Value>>>,
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
    let object = fixture
        .as_object()
        .ok_or(CliError("fixture contract must be an object"))?;
    if object.get("syntheticOnly") != Some(&Value::Bool(true)) {
        return Err(CliError("fixture is not an approved synthetic definition"));
    }
    // A fixture that declares itself a coequal acceptance definition is run
    // as one; every other fixture is a reference fixture.
    if object.get("coequalAcceptanceDefinition") != Some(&Value::Bool(true)) {
        if matched_facts.is_some() {
            return Err(CliError(
                "fixture fact recording requires a coequal acceptance definition",
            ));
        }
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
    trace.declare_canaries(declared_canaries(
        object,
        "privacyExpectation",
        "diagnosticsExclude",
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
    let mut first_failure = None;
    for case in cases {
        let case = case
            .as_object()
            .ok_or(CliError("fixture case is not an object"))?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CliError("fixture case identifier is invalid"))?;
        if selected_case.is_some_and(|selected| selected != id) {
            continue;
        }
        trace.begin_case(id);
        // Each case settles on its own, so one failing case does not hide the
        // next: the run reports every failing case and fails with the first.
        let settled: Result<(), CliError> = async {
            if matched_facts.is_none()
                && case.contains_key("expectedFacts")
                && (case.contains_key("subjects") || !case.contains_key("source"))
            {
                return Err(CliError(
                    "fixture expected facts require an actual pack route match",
                ));
            }

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
                    Err(OfflineFixtureError::Audience) => {
                        return Err(CliError(FIXTURE_AUDIENCE_FAILURE));
                    }
                    Err(OfflineFixtureError::Authorization(_)) => {}
                }
                trace.record(
                    Stage::Prepare,
                    StageStatus::Ok,
                    "the selector was refused before any source, as the case states",
                );
                trace.diagnose(
                    ResultClassification::new(ResultClass::SelectorRefused, Vec::new()),
                    ResultClassification::new(ResultClass::SelectorRefused, Vec::new()),
                    ReasonCode::SelectorRefused,
                    None,
                );
                summary.evaluated_cases += 1;
                trace.pass_case();
                return Ok(());
            }
            if let Some(expected_roles) = case.get("expectedSubjectRoles") {
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
                let (outcome, recorded_match) = if matched_facts.is_some() {
                    evaluate_fixture_acquisition_recording(
                        bundle,
                        kernel,
                        requirement,
                        case,
                        FixtureSelectors {
                            resolved: &resolved,
                            derivation: &derivation_selectors,
                        },
                        observed_at,
                        trace,
                    )
                    .await?
                } else {
                    (
                        evaluate_fixture_acquisition(
                            bundle,
                            kernel,
                            requirement,
                            case,
                            FixtureSelectors {
                                resolved: &resolved,
                                derivation: &derivation_selectors,
                            },
                            observed_at,
                            trace,
                        )
                        .await?,
                        None,
                    )
                };
                let categories = category_diagnostic_catalog(bundle, requirement);
                if let Some(values) = validate_case_outcome(case, outcome, trace, &categories)? {
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
                if let (Some(records), Some(facts)) = (matched_facts.as_deref_mut(), recorded_match)
                {
                    records.insert(id.to_owned(), facts);
                }
                summary.evaluated_cases += 1;
                trace.pass_case();
                return Ok(());
            }

            if let Some(injected) = case.get("injectedDerivation") {
                validate_injected_rejection(kernel, requirement, injected, trace)?;
                require_expected(case, "output-gate-rejection")?;
                trace.diagnose(
                    ResultClassification::new(ResultClass::ServiceUnavailable, Vec::new()),
                    ResultClassification::new(ResultClass::ServiceUnavailable, Vec::new()),
                    ReasonCode::OutputRefused,
                    None,
                );
                summary.evaluated_cases += 1;
                trace.pass_case();
                return Ok(());
            }

            if let Some(source_failure) = case.get("sourceFailure") {
                validate_source_failure(case, source_failure)?;
                trace.record(
                    Stage::Acquire,
                    StageStatus::Failed,
                    format!(
                        "the source failed as {}, which the case states",
                        source_failure.as_str().unwrap_or("an unnamed category")
                    ),
                );
                trace.diagnose(
                    ResultClassification::new(ResultClass::SourceUnavailable, Vec::new()),
                    ResultClassification::new(ResultClass::SourceUnavailable, Vec::new()),
                    ReasonCode::SourceFailureFixture,
                    None,
                );
                summary.evaluated_cases += 1;
                trace.pass_case();
                return Ok(());
            }

            if let Some(companion) = case.get("companionBundle") {
                validate_companion_rejection(bundle, requirement, case, companion)?;
                trace.record(
                    Stage::Prepare,
                    StageStatus::Ok,
                    format!(
                        "the companion bundle {:?} was refused, as the case states",
                        companion.as_str().unwrap_or_default()
                    ),
                );
                trace.diagnose(
                    ResultClassification::new(ResultClass::BundleRefused, Vec::new()),
                    ResultClassification::new(ResultClass::BundleRefused, Vec::new()),
                    ReasonCode::CompanionBundleRefused,
                    None,
                );
                summary.evaluated_cases += 1;
                trace.pass_case();
                return Ok(());
            }

            Err(CliError(
                "fixture case has no closed Version 1 evaluation form",
            ))
        }
        .await;
        if let Err(error) = settled {
            trace.fail(error.0);
            first_failure.get_or_insert(error);
        }
    }
    if let Some(error) = first_failure {
        return Err(error);
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
struct FixtureSelectors<'a> {
    resolved: &'a ResolvedAuthorization,
    derivation: &'a Value,
}

async fn evaluate_fixture_acquisition(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    requirement: &RequirementConfig,
    case: &JsonMap<String, Value>,
    selectors: FixtureSelectors<'_>,
    observed_at: DateTime<Utc>,
    trace: &mut FixtureTrace,
) -> Result<Result<KernelOutcome, KernelError>, CliError> {
    evaluate_fixture_acquisition_inner(
        bundle,
        kernel,
        requirement,
        case,
        selectors,
        observed_at,
        trace,
        true,
    )
    .await
    .map(|(outcome, _)| outcome)
}

async fn evaluate_fixture_acquisition_recording(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    requirement: &RequirementConfig,
    case: &JsonMap<String, Value>,
    selectors: FixtureSelectors<'_>,
    observed_at: DateTime<Utc>,
    trace: &mut FixtureTrace,
) -> Result<
    (
        Result<KernelOutcome, KernelError>,
        Option<JsonMap<String, Value>>,
    ),
    CliError,
> {
    evaluate_fixture_acquisition_inner(
        bundle,
        kernel,
        requirement,
        case,
        selectors,
        observed_at,
        trace,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_fixture_acquisition_inner(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    requirement: &RequirementConfig,
    case: &JsonMap<String, Value>,
    selectors: FixtureSelectors<'_>,
    observed_at: DateTime<Utc>,
    trace: &mut FixtureTrace,
    verify_expected_facts: bool,
) -> Result<
    (
        Result<KernelOutcome, KernelError>,
        Option<JsonMap<String, Value>>,
    ),
    CliError,
> {
    if case.contains_key("sources") {
        return Err(CliError(
            "a fixture records one complete pack acquisition in source",
        ));
    }
    let recorded = case
        .get("source")
        .ok_or(CliError("fixture acquisition is unavailable"))?;
    let plans =
        compile_sources(bundle).map_err(|_| CliError("fixture source pack cannot compile"))?;
    let plan = plans
        .get(requirement.initial_source())
        .ok_or(CliError("fixture source pack is unavailable"))?;
    let expected_facts = verify_expected_facts
        .then(|| case.get("expectedFacts"))
        .flatten();
    if let Some(expected) = expected_facts {
        if !expected.is_object()
            || kernel
                .validate_lookup(
                    requirement.initial_source(),
                    &serde_json::json!({"lookup": "matched", "facts": expected}),
                )
                .is_err()
        {
            const MESSAGE: &str = "fixture expected facts do not match the source schema";
            let schema = bundle
                .config
                .sources
                .get(requirement.initial_source())
                .and_then(|source| bundle.fact_schema(source.fact_schema()));
            trace.record_with(
                Stage::Expect,
                StageStatus::Failed,
                MESSAGE,
                expected_facts_schema_details(schema, expected),
            );
            return Err(CliError(MESSAGE));
        }
    }
    let acquisition = fixture_case_acquisition(recorded)?;
    let run = plan
        .execute_observed(selectors.resolved, acquisition, None, observed_at)
        .await;
    record_fixture_source_run(trace, bundle, requirement, &run)?;
    if let Some(expected) = expected_facts {
        match &run.outcome {
            Ok(LookupResult::Match(facts)) => {
                let actual = facts.clone().into_iter().collect::<JsonMap<_, _>>();
                if &Value::Object(actual.clone()) != expected {
                    const MESSAGE: &str = "fixture expected facts did not match actual pack facts";
                    trace.record_with(
                        Stage::Expect,
                        StageStatus::Failed,
                        MESSAGE,
                        expected_facts_mismatch_details(expected, &actual),
                    );
                    return Err(CliError(MESSAGE));
                }
            }
            unmatched => {
                const MESSAGE: &str = "fixture expected facts require the pack route to match";
                // The kernel error messages are fixed and value-free, so the
                // failure category is safe to name beside the lookup answers.
                let answered = match unmatched {
                    Ok(LookupResult::NoMatch) => "the pack route answered no-match".to_owned(),
                    Ok(LookupResult::Ambiguous) => "the pack route answered ambiguous".to_owned(),
                    Ok(LookupResult::Unresolved) => "the pack route answered unresolved".to_owned(),
                    Ok(LookupResult::Match(_)) => "the pack route answered a match".to_owned(),
                    Err(error) => {
                        format!("the pack acquisition failed: {error}; see the acquire stage")
                    }
                };
                trace.record_with(Stage::Expect, StageStatus::Failed, MESSAGE, vec![answered]);
                return Err(CliError(MESSAGE));
            }
        }
    }
    let matched_facts = match &run.outcome {
        Ok(LookupResult::Match(facts)) => Some(facts.clone().into_iter().collect()),
        Ok(LookupResult::NoMatch | LookupResult::Ambiguous | LookupResult::Unresolved) | Err(_) => {
            None
        }
    };
    let lookup = match run.outcome {
        Ok(lookup) => lookup,
        Err(error) => return Ok((Err(error), None)),
    };
    let facts = match record_lookup(trace, Ok(lookup), &Value::Null) {
        Ok(facts) => facts,
        Err(outcome) => return Ok((outcome, None)),
    };
    Ok((
        record_derivation(
            trace,
            kernel.derive_and_validate_with_selectors(
                &requirement.id,
                &facts,
                selectors.derivation,
                observed_at,
                ValueProjection {
                    scope: EvidenceScope::AudienceScoped {
                        audience: selectors
                            .resolved
                            .subject_scope
                            .audience()
                            .unwrap_or(OFFLINE_AUDIENCE),
                        request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                    },
                    binding_key: &OFFLINE_BINDING_KEY,
                    binding_key_version: 1,
                },
            ),
            requirement,
        ),
        matched_facts,
    ))
}

/// Name, without values, why a case's `expectedFacts` failed the source schema:
/// the keys the schema does not declare, the required keys the case omits, and
/// the keys whose JSON type the schema does not allow.
fn expected_facts_schema_details(schema: Option<&Value>, expected: &Value) -> Vec<String> {
    let Some(expected) = expected.as_object() else {
        return vec![format!(
            "expectedFacts must be an object of facts, not a {}",
            json_type(expected)
        )];
    };
    let Some(schema) = schema.and_then(Value::as_object) else {
        return Vec::new();
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    let undeclared = expected
        .keys()
        .filter(|key| properties.is_none_or(|properties| !properties.contains_key(*key)))
        .cloned()
        .collect::<BTreeSet<_>>();
    let omitted = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|key| !expected.contains_key(*key))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let mistyped = expected
        .iter()
        .filter(|(key, value)| {
            let declared = properties
                .and_then(|properties| properties.get(*key))
                .and_then(|property| property.get("type"));
            let allowed = |name: &str| {
                name == json_type(value)
                    || (name == "integer" && (value.is_i64() || value.is_u64()))
            };
            match declared {
                Some(Value::String(name)) => !allowed(name),
                Some(Value::Array(names)) => !names.iter().filter_map(Value::as_str).any(allowed),
                _ => false,
            }
        })
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let mut details = Vec::new();
    for (label, names) in [
        ("facts the source schema does not declare", undeclared),
        (
            "facts the source schema requires but the case omits",
            omitted,
        ),
        (
            "facts whose type the source schema does not allow",
            mistyped,
        ),
    ] {
        if !names.is_empty() {
            let names = names.into_iter().collect::<Vec<_>>();
            details.push(format!("{label}: {}", name_list(&names)));
        }
    }
    if details.is_empty() {
        details.push(
            "every stated fact is declared and typed; check each value against its declared format, \
             pattern, or enumeration"
                .to_owned(),
        );
    }
    details
}

/// Name, without values, how a case's `expectedFacts` differ from the facts
/// the pack route produced.
fn expected_facts_mismatch_details(
    expected: &Value,
    actual: &JsonMap<String, Value>,
) -> Vec<String> {
    let Some(expected) = expected.as_object() else {
        return Vec::new();
    };
    let differ = expected
        .iter()
        .filter(|(key, value)| actual.get(*key).is_some_and(|actual| actual != *value))
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let missing = expected
        .keys()
        .filter(|key| !actual.contains_key(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    let unexpected = actual
        .keys()
        .filter(|key| !expected.contains_key(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut details = Vec::new();
    for (label, names) in [
        ("facts that differ", differ),
        (
            "facts the case expects but the pack did not produce",
            missing,
        ),
        (
            "facts the pack produced but the case does not expect",
            unexpected,
        ),
    ] {
        if !names.is_empty() {
            let names = names.into_iter().collect::<Vec<_>>();
            details.push(format!("{label}: {}", name_list(&names)));
        }
    }
    details
}

/// Read a case's `source` as an exact pack acquisition transcript.
fn fixture_case_acquisition(recorded: &Value) -> Result<FixtureAcquisition, CliError> {
    fixture_acquisition(recorded).map_err(|_| {
        let transcript = recorded
            .as_object()
            .is_some_and(|map| map.contains_key("intercepts") || map.contains_key("exchanges"));
        CliError(if transcript {
            FIXTURE_SOURCE_INVALID
        } else {
            FIXTURE_SOURCE_RETIRED
        })
    })
}

/// Record the actual progress of one complete pack acquisition.
///
/// Input names, Source identity and pack identity are governed configuration.
/// Selector values, credentials and provider data never enter the trace. A data
/// operation is counted when the host admits its attempt, before credentials;
/// the count therefore does not claim a completed wire request.
fn record_fixture_source_run(
    trace: &mut FixtureTrace,
    bundle: &Bundle,
    requirement: &RequirementConfig,
    run: &FixtureRun,
) -> Result<(), CliError> {
    let source_id = requirement.initial_source();
    let source = bundle
        .config
        .sources
        .get(source_id)
        .ok_or(CliError("fixture Source binding is unavailable"))?;
    match &run.prepared_inputs {
        Some(inputs) => trace.record_with(
            Stage::Prepare,
            StageStatus::Ok,
            format!("authorized minimized Source inputs {}", name_list(inputs)),
            vec![format!(
                "source {source_id}, pack {}, route {}",
                source.pack.id.as_str(),
                source.route.as_str()
            )],
        ),
        None => trace.record(
            Stage::Prepare,
            StageStatus::Failed,
            "authorized minimized Source input preparation failed before acquisition",
        ),
    }
    if run.acquisition_started {
        let failed = run.outcome.is_err();
        trace.record_with(
            Stage::Acquire,
            if failed {
                StageStatus::Failed
            } else {
                StageStatus::Ok
            },
            if failed {
                format!(
                    "the complete pack acquisition stopped after admitting {} data-operation attempt(s)",
                    run.data_operations
                )
            } else {
                format!(
                    "the complete pack acquisition admitted {} data-operation attempt(s)",
                    run.data_operations
                )
            },
            run.http_cause
                .iter()
                .map(|(endpoint, cause)| http_cause_note(endpoint, *cause))
                .collect(),
        );
    }
    Ok(())
}

/// Say which endpoint answered which status, in the words the runtime uses
/// for its operator signal, and what an author changes next.
fn http_cause_note(
    endpoint: &str,
    cause: registry_adapter_engine::route::EvidenceHttpDiagnostic,
) -> String {
    use registry_adapter_engine::route::EvidenceHttpDiagnostic;
    let answer = match cause {
        EvidenceHttpDiagnostic::Unauthorized => {
            "answered 401; the source refused the credential"
        }
        EvidenceHttpDiagnostic::Forbidden => "answered 403; the source refused this access",
        EvidenceHttpDiagnostic::RateLimited => "answered 429; the source limited the request rate",
        EvidenceHttpDiagnostic::ServerError => "answered a 5xx server error",
        EvidenceHttpDiagnostic::Verification => {
            "answered a response its host protocol could not verify"
        }
        EvidenceHttpDiagnostic::UndeclaredNotFound => {
            "answered 404 with an undeclared shape; declare the not-found answer in the pack, or correct the recorded response"
        }
        EvidenceHttpDiagnostic::DeclaredNotFoundMismatch => {
            "answered 404 that is not the declared `unresolvedProblem`; record that exact Problem, or correct the declaration"
        }
        EvidenceHttpDiagnostic::OtherClientStatus => "answered a 4xx client error",
    };
    format!("endpoint `{endpoint}` {answer}")
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
        Ok(LookupResult::Unresolved) => {
            trace.record(
                Stage::Extract,
                StageStatus::Unresolved,
                "the pack declared the lookup unresolved",
            );
            Err(Ok(KernelOutcome::Unresolved))
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
        Err(KernelError::UndeclaredOutputProperty(property)) => {
            trace.record(
                Stage::Derive,
                StageStatus::Ok,
                "the derivation script ran and returned values",
            );
            trace.record_with(
                Stage::Validate,
                StageStatus::Failed,
                format!("the output gate rejected an undeclared structured key {property:?}"),
                declared_concept_lines(requirement),
            );
            Err(KernelError::UndeclaredOutputProperty(property))
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
async fn evaluate_reference_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, OfflineSourceProgram>,
    signer: Option<&EvidenceSigner>,
    requirement: &RequirementConfig,
    fixture_selection: (&JsonMap<String, Value>, Option<&str>),
    trace: &mut FixtureTrace,
) -> Result<FixtureSummary, CliError> {
    let (fixture, selected_case) = fixture_selection;
    trace.declare_canaries(declared_canaries(
        fixture,
        "privacyExpectation",
        "diagnosticsExclude",
    )?);
    let common = fixture
        .get("common")
        .and_then(Value::as_object)
        .ok_or(CliError("reference fixture common block is invalid"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .filter(|cases| !cases.is_empty() && cases.len() <= 256)
        .ok_or(CliError("reference fixture case count is invalid"))?;
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
            .ok_or(CliError("reference fixture case is not an object"))?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CliError("reference fixture case identifier is invalid"))?;
        if selected_case.is_some_and(|selected| selected != id) {
            continue;
        }
        trace.begin_case(id);
        let expected = case
            .get("expected")
            .and_then(Value::as_object)
            .ok_or(CliError("reference fixture expectation is invalid"))?;
        if expected.contains_key("value") && expected.contains_key("values") {
            return Err(CliError("reference fixture states two value expectations"));
        }
        let forms = [
            "acquisition",
            "sourceFailure",
            "statementMutation",
            "bundleMutation",
            "requestMutation",
            "derivationMutation",
            "derivationParameterMutation",
        ];
        let selected_forms = forms
            .into_iter()
            .filter(|form| case.contains_key(*form))
            .collect::<Vec<_>>();
        if selected_forms.len() != 1 {
            return Err(CliError("reference fixture case form is not closed"));
        }
        validate_reference_expectation_keys(selected_forms[0], expected)?;
        if let Some(mutation) = case.get("bundleMutation").and_then(Value::as_str) {
            if mutation != "duplicate-disclosure-family"
                || expected.get("bundle").and_then(Value::as_str) != Some("rejected")
            {
                return Err(CliError("reference bundle mutation is invalid"));
            }
            validate_reference_bundle_mutation(bundle, requirement)?;
            diagnose_reference_fixed(
                trace,
                expected,
                bundle,
                requirement,
                ResultClass::BundleRefused,
                ReasonCode::BundleRefused,
            )?;
        } else if let Some(mutation) = case.get("statementMutation").and_then(Value::as_str) {
            validate_reference_statement_mutation(bundle, requirement, mutation, expected)?;
            diagnose_reference_fixed(
                trace,
                expected,
                bundle,
                requirement,
                ResultClass::BundleRefused,
                ReasonCode::BundleRefused,
            )?;
        } else if let Some(symbol) = case.get("sourceFailure").and_then(Value::as_str) {
            let closure = bundle
                .source_pack(requirement.initial_source())
                .ok_or(CliError("reference source pack is unavailable"))?;
            validate_reference_source_failure(closure, symbol, expected)?;
            diagnose_reference_fixed(
                trace,
                expected,
                bundle,
                requirement,
                ResultClass::SourceUnavailable,
                ReasonCode::SourceFailureFixture,
            )?;
        } else if let Some(mutation) = case.get("requestMutation").and_then(Value::as_str) {
            validate_reference_request_mutation(
                bundle,
                requirement,
                common,
                case,
                expected,
                mutation,
            )?;
            diagnose_reference_fixed(
                trace,
                expected,
                bundle,
                requirement,
                ResultClass::SelectorRefused,
                ReasonCode::SelectorRefused,
            )?;
        } else if let Some(mutation) = case.get("derivationMutation").and_then(Value::as_str) {
            validate_reference_derivation_mutation(kernel, requirement, expected, mutation)?;
            diagnose_reference_fixed(
                trace,
                expected,
                bundle,
                requirement,
                ResultClass::ServiceUnavailable,
                ReasonCode::OutputRefused,
            )?;
        } else if let Some(mutation) = case
            .get("derivationParameterMutation")
            .and_then(Value::as_object)
        {
            let resolved = resolve_offline_fixture_authorization(
                bundle,
                requirement,
                Some(common),
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| {
                fixture_failure(error, "reference fixture subjects did not resolve")
            })?;
            let selectors =
                fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
            let observed_at = fixture_observed_at(
                case,
                Some(common),
                requirement.observation_timezone.as_deref(),
            )?;
            let error = validate_reference_parameter_mutation(
                bundle,
                requirement,
                cases,
                mutation,
                FixtureSelectors {
                    resolved: &resolved,
                    derivation: &selectors,
                },
                observed_at,
                expected,
            )
            .await?;
            diagnose_reference_kernel_error(trace, expected, bundle, requirement, error)?;
        } else {
            let resolved = resolve_offline_fixture_authorization(
                bundle,
                requirement,
                Some(common),
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| {
                fixture_failure(error, "reference fixture subjects did not resolve")
            })?;
            let selectors =
                fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
            let observed_at = fixture_observed_at(
                case,
                Some(common),
                requirement.observation_timezone.as_deref(),
            )?;
            let recorded = case.get("acquisition").ok_or(CliError(
                "reference fixture requires a complete recorded acquisition",
            ))?;
            let acquisition = fixture_acquisition(recorded)
                .map_err(|_| CliError("reference acquisition transcript is invalid"))?;
            let plan = source_plans
                .get(requirement.initial_source())
                .ok_or(CliError("reference source pack is unavailable"))?;
            let assets = common
                .get("extract")
                .map(|seed| {
                    let seed = seed
                        .as_str()
                        .ok_or(CliError("reference extract fixture is invalid"))?;
                    plan.materialize_single_extract_in(&std::env::temp_dir(), seed)
                        .map_err(|_| {
                            CliError("reference extract fixture could not be materialized")
                        })
                })
                .transpose()?;
            let run = plan
                .execute_observed(&resolved, acquisition, assets.as_ref(), observed_at)
                .await;
            record_fixture_source_run(trace, bundle, requirement, &run)?;
            let request_count = run.data_operations;
            let context = ReferenceResponseContext {
                bundle,
                kernel,
                signer,
                requirement,
                resolved: &resolved,
            };
            let values = match run.outcome {
                Ok(lookup) => {
                    validate_reference_lookup(
                        &context,
                        Ok(lookup),
                        &Value::Null,
                        &selectors,
                        observed_at,
                        expected,
                        trace,
                    )
                    .await?
                }
                Err(error) => {
                    diagnose_reference_kernel_error(
                        trace,
                        expected,
                        bundle,
                        requirement,
                        error.clone(),
                    )?;
                    validate_reference_error(expected, error, false)?;
                    None
                }
            };
            if let Some(values) = values {
                successful_values.push(values);
            }
            require_reference_request_count(expected, request_count)?;
        }
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
            diagnose_reference_fixed(
                trace,
                expected,
                context.bundle,
                context.requirement,
                ResultClass::NoMatch,
                ReasonCode::NoMatch,
            )?;
            validate_reference_unresolved(expected, "no_match")?;
            return Ok(None);
        }
        Err(Ok(KernelOutcome::Unresolved)) => {
            diagnose_reference_fixed(
                trace,
                expected,
                context.bundle,
                context.requirement,
                ResultClass::EvidenceUnavailable,
                ReasonCode::DeclaredUnresolved,
            )?;
            validate_reference_unresolved(expected, "unresolved")?;
            return Ok(None);
        }
        Err(Ok(KernelOutcome::Ambiguous)) => {
            diagnose_reference_fixed(
                trace,
                expected,
                context.bundle,
                context.requirement,
                ResultClass::Ambiguous,
                ReasonCode::Ambiguous,
            )?;
            validate_reference_unresolved(expected, "ambiguous")?;
            return Ok(None);
        }
        Err(Ok(KernelOutcome::Match(_))) => {
            return Err(CliError(
                "reference lookup settled on an unreachable outcome",
            ));
        }
        Err(Err(error)) => {
            diagnose_reference_kernel_error(
                trace,
                expected,
                context.bundle,
                context.requirement,
                error.clone(),
            )?;
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
            diagnose_reference_kernel_error(
                trace,
                expected,
                context.bundle,
                context.requirement,
                error.clone(),
            )?;
            validate_reference_error(expected, error, true)?;
            return Ok(None);
        }
    };
    diagnose_reference_match(
        trace,
        expected,
        context.bundle,
        context.requirement,
        &values,
        None,
    )?;
    if expected.get("derivationRuns").and_then(Value::as_bool) != Some(true) {
        return Err(CliError("reference derivation execution did not match"));
    }
    if let Some(exact) = expected.get("value") {
        if values.as_slice().len() != 1 || public_json(&values.as_slice()[0].value)? != *exact {
            diagnose_reference_match(
                trace,
                expected,
                context.bundle,
                context.requirement,
                &values,
                Some(FindingCode::ResultValueMismatch),
            )?;
            return Err(CliError("reference scalar value did not match"));
        }
    }
    if let Some(exact) = expected.get("values") {
        let exact = exact
            .as_object()
            .ok_or(CliError("reference concept map is invalid"))?;
        if values.as_slice().len() != exact.len() {
            diagnose_reference_match(
                trace,
                expected,
                context.bundle,
                context.requirement,
                &values,
                Some(FindingCode::ResultShapeMismatch),
            )?;
            return Err(CliError("reference concept value did not match"));
        }
        for (concept, expected_value) in exact {
            let disclosed = values
                .as_slice()
                .iter()
                .find(|value| value.provides_value_for == *concept)
                .ok_or(CliError("reference concept value did not match"))?;
            if public_json(&disclosed.value)? != *expected_value {
                diagnose_reference_match(
                    trace,
                    expected,
                    context.bundle,
                    context.requirement,
                    &values,
                    Some(FindingCode::ResultValueMismatch),
                )?;
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
    let audience = resolved
        .subject_scope
        .audience()
        .unwrap_or(OFFLINE_AUDIENCE);
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
                        registry_evidence::binding::SubjectBindingScope::Audience(audience),
                        &resolved.purpose,
                    )
                    .map_err(|_| CliError("fixture subject binding failed"))?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let issued_at = observed_at + chrono::Duration::seconds(1);
    let evidence_id = format!("urn:ulid:{}", ulid::Ulid::generate());
    let evidence = kernel
        .construct_evidence(
            &requirement.id,
            values,
            EvidenceConstruction {
                evidence_id: &evidence_id,
                purpose: &resolved.purpose,
                scope: EvidenceScope::AudienceScoped {
                    audience,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                issued_at,
                observed_at,
                source_valid_until: None,
                channel: AssertionChannel::Source,
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
    policy.audience = audience.to_owned();
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

    let signing_key = SigningKey::generate();
    let private_bytes = Zeroizing::new(signing_key.to_bytes());
    let public = signing_key.verifying_key().to_sec1_point(false);
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
        "acquisition" | "response" | "responses" | "selectors" => &[
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

fn reference_source_failure_error(
    source: &registry_evidence::bundle::SourcePack,
    failure: &str,
) -> Result<registry_evidence::pack_source::PackSourceError, CliError> {
    use registry_evidence::pack_source::PackSourceError;
    let sqlite =
        source.pack().endpoints.iter().any(|endpoint| {
            endpoint.component == registry_adapter_core::ComponentKind::SqliteExtract
        });
    Ok(match (failure, sqlite) {
        ("timeout", _) => PackSourceError::Timeout,
        ("oversized", _) => PackSourceError::ResponseTooLarge,
        ("connection-refused", false) => PackSourceError::Dependency,
        ("invalid-media-type" | "malformed-json", false) => PackSourceError::Protocol,
        ("extract-too-old", true) => PackSourceError::ExtractStale,
        ("statement-parameter", true) => PackSourceError::StatementParameter,
        ("statement-budget", true) => PackSourceError::StatementBudget,
        ("statement-result", true) => PackSourceError::StatementResult,
        ("statement-unavailable", true) => PackSourceError::StatementUnavailable,
        _ => return Err(CliError("reference source-failure name is invalid")),
    })
}

/// Symbolic cases check the public failure mapping only. Actual transport and
/// SQLite failure behavior is exercised through their host integration tests.
fn validate_reference_source_failure(
    source: &registry_evidence::bundle::SourcePack,
    failure: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let error = reference_source_failure_error(source, failure)?;
    if pack_source_failure(error).problem() != ProblemCode::DependencyUnavailable
        || expected.get("publicProblem").and_then(Value::as_str) != Some("source.unavailable")
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
        || expected
            .get("derivationRuns")
            .is_some_and(|runs| runs.as_bool() != Some(false))
    {
        return Err(CliError("reference source-failure mapping is invalid"));
    }
    require_reference_request_count(expected, 1)
}

/// Refuse a statement the authorizer must never accept.
///
/// A refused statement is a bundle fault, not a request-time one: it is settled
/// while the source is compiled, before a listener binds and before any fixture
/// case runs. The mutation is applied to a disposable copy of the reviewed
/// statement, so the project's own artifact is untouched.
fn validate_reference_statement_mutation(
    bundle: &Bundle,
    requirement: &RequirementConfig,
    mutation: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    use registry_adapter_engine::{
        artifacts::PackArtifactBytes, component::sqlite_extract::SqliteExtractPlan,
    };
    if mutation != "attach-external-database"
        || expected.get("bundle").and_then(Value::as_str) != Some("rejected")
    {
        return Err(CliError("reference statement mutation is invalid"));
    }
    let source = bundle
        .config
        .sources
        .get(requirement.initial_source())
        .ok_or(CliError("reference statement source is unavailable"))?;
    let pack = bundle
        .source_pack(requirement.initial_source())
        .ok_or(CliError("reference source pack is unavailable"))?
        .pack();
    let mut endpoints = pack.endpoints.iter().filter(|endpoint| {
        endpoint.component == registry_adapter_core::ComponentKind::SqliteExtract
    });
    let original = endpoints
        .next()
        .ok_or(CliError("reference statement source is unavailable"))?;
    if endpoints.next().is_some() {
        return Err(CliError(
            "reference statement mutation requires one reviewed statement",
        ));
    }
    let declaration = original
        .sqlite_extract
        .as_ref()
        .ok_or(CliError("reference statement declaration is unavailable"))?;
    let path = &declaration.statement.path;
    let sql = bundle
        .artifact(&format!("{}/{path}", source.pack.artifact_prefix.as_str()))
        .ok_or(CliError("reference statement artifact is unavailable"))?;
    SqliteExtractPlan::compile(
        original,
        &PackArtifactBytes::new([(path.clone(), sql.to_vec())]),
    )
    .map_err(|_| CliError("reference reviewed statement cannot compile"))?;
    let replacement = b"ATTACH DATABASE ':memory:' AS outside;".to_vec();
    let mut endpoint = original.clone();
    endpoint
        .sqlite_extract
        .as_mut()
        .expect("the cloned declaration exists")
        .statement
        .digest = serde_json::from_value(Value::String(registry_platform_config::sha256_uri(
        &replacement,
    )))
    .map_err(|_| CliError("reference statement digest is invalid"))?;
    if SqliteExtractPlan::compile(
        &endpoint,
        &PackArtifactBytes::new([(path.clone(), replacement)]),
    )
    .is_ok()
    {
        return Err(CliError("reference unsafe statement was not refused"));
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
        Err(OfflineFixtureError::Audience) => return Err(CliError(FIXTURE_AUDIENCE_FAILURE)),
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

async fn validate_reference_parameter_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    cases: &[Value],
    mutation: &JsonMap<String, Value>,
    selectors: FixtureSelectors<'_>,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
) -> Result<KernelError, CliError> {
    let mut disposable = bundle.clone();
    let mut config = serde_json::to_value(&disposable.config)
        .map_err(|_| CliError("reference configuration is not representable"))?;
    let target = config["requirements"]
        .as_array_mut()
        .and_then(|requirements| {
            requirements
                .iter_mut()
                .find(|candidate| candidate["uri"].as_str() == Some(&requirement.id))
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
    disposable.config = registry_evidence::config::EvidenceConfig::parse_projection(&config)
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
    let response = positive
        .get("acquisition")
        .ok_or(CliError("reference positive acquisition is unavailable"))?;
    let acquisition_case = JsonMap::from_iter([("source".to_owned(), response.clone())]);

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
    )
    .await?;
    match outcome {
        Err(error) => {
            validate_reference_error(expected, error.clone(), true)?;
            Ok(error)
        }
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
    validate_privacy_projection(source, &projection, diagnostics)
}

const FIXTURE_AUDIENCE_FAILURE: &str =
    "fixture must name one audience inside the definition ceiling when more than one is declared";
const FIXTURE_PURPOSE_FAILURE: &str = "fixture does not select one of the requirement's purposes";

/// Report an unselected fixture purpose as its own failure so a harness
/// omission is never presented as a rejected request.
fn fixture_failure(error: OfflineFixtureError, authorization: &'static str) -> CliError {
    match error {
        OfflineFixtureError::Purpose => CliError(FIXTURE_PURPOSE_FAILURE),
        OfflineFixtureError::Audience => CliError(FIXTURE_AUDIENCE_FAILURE),
        OfflineFixtureError::Authorization(_) => CliError(authorization),
    }
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
    categories: &[CategoryDiagnosticEntry],
) -> Result<Option<ValidatedValues>, CliError> {
    let expected = classify_expected_result(case, categories)?;
    let (observed, reason) = classify_observed_result(&outcome, categories);
    // What the case says it expects, beside what the pipeline just did. The
    // pipeline half of it is already recorded above this line.
    let declared = format!(
        "the case expects lookup {}, public problem {:?}, derivation run {}, signed success {}",
        optional_string(case, "expectedLookup")?.map_or_else(
            || "\"match\" (unstated default)".to_owned(),
            |lookup| format!("{lookup:?}")
        ),
        optional_string(case, "expectedPublicProblem")?.unwrap_or("none"),
        stated_flag(optional_boolean(case, "derivationRuns")?),
        stated_flag(optional_boolean(case, "signedSuccess")?)
    );
    let compared = compare_case_outcome(case, outcome);
    trace.diagnose(
        expected,
        observed,
        reason,
        compared.as_ref().err().map(expectation_finding_code),
    );
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

/// Reduce one authored expectation to the same closed vocabulary used for an
/// observed result. Values become only bounded shape classes. In particular,
/// strings, integers, entity references, and structured values never reach the
/// trace as authored material.
fn classify_expected_result(
    case: &serde_json::Map<String, Value>,
    categories: &[CategoryDiagnosticEntry],
) -> Result<ResultClassification, CliError> {
    let expected_lookup = optional_string(case, "expectedLookup")?;
    let expected_problem = optional_string(case, "expectedPublicProblem")?;
    let class = match expected_lookup {
        Some("no_match") => ResultClass::NoMatch,
        Some("ambiguous") => ResultClass::Ambiguous,
        Some("unresolved") => ResultClass::EvidenceUnavailable,
        Some("match") | None => match expected_problem {
            Some("evidence.unavailable") => ResultClass::EvidenceUnavailable,
            Some("source.unavailable") => ResultClass::SourceUnavailable,
            Some("service.unavailable") => ResultClass::ServiceUnavailable,
            Some(_) => return Err(CliError("fixture public problem expectation is invalid")),
            None => ResultClass::Match,
        },
        Some(_) => return Err(CliError("fixture lookup expectation is invalid")),
    };
    let mut values = Vec::new();
    let mut category_classes = Vec::new();
    if class == ResultClass::Match {
        if let Some(value) = case.get("expectedValue") {
            values.push(classify_json_value(value));
            if categories.len() == 1 {
                if let Some(category) = classify_expected_category(&categories[0], value) {
                    category_classes.push(category);
                }
            }
        }
        if let Some(map) = case.get("expectedValues").and_then(Value::as_object) {
            values.extend(map.values().map(classify_json_value));
            category_classes.extend(categories.iter().filter_map(|category| {
                map.get(&category.concept_id)
                    .and_then(|value| classify_expected_category(category, value))
            }));
        }
    }
    Ok(ResultClassification::new(class, values).with_category_classes(category_classes))
}

/// Reduce the current reference-fixture `expected` object to the same closed
/// vocabulary used for legacy coequal fixtures. The two fixture dialects are
/// authoring surfaces only; they share one authoritative result taxonomy.
fn classify_reference_expected_result(
    expected: &JsonMap<String, Value>,
    categories: &[CategoryDiagnosticEntry],
) -> Result<ResultClassification, CliError> {
    let lookup = expected.get("lookup").and_then(Value::as_str);
    let public_problem = expected.get("publicProblem").and_then(Value::as_str);
    let class = match lookup {
        Some("no_match") => ResultClass::NoMatch,
        Some("ambiguous") => ResultClass::Ambiguous,
        Some("unresolved") => ResultClass::EvidenceUnavailable,
        Some("match") | None => match public_problem {
            Some("evidence.unavailable") => ResultClass::EvidenceUnavailable,
            Some("source.unavailable") => ResultClass::SourceUnavailable,
            Some("service.unavailable") => ResultClass::ServiceUnavailable,
            Some(_) => return Err(CliError("reference public problem expectation is invalid")),
            None if expected.get("bundle").and_then(Value::as_str) == Some("rejected") => {
                ResultClass::BundleRefused
            }
            None if expected.contains_key("rejectedBefore") => ResultClass::SelectorRefused,
            None if expected.get("error").and_then(Value::as_str)
                == Some("source_protocol_error") =>
            {
                ResultClass::SourceUnavailable
            }
            None if expected.get("error").and_then(Value::as_str)
                == Some("derivation_input_error") =>
            {
                ResultClass::EvidenceUnavailable
            }
            None if expected.contains_key("outputGate") || expected.contains_key("error") => {
                ResultClass::ServiceUnavailable
            }
            None => ResultClass::Match,
        },
        Some(_) => return Err(CliError("reference lookup expectation is invalid")),
    };
    let mut values = Vec::new();
    let mut category_classes = Vec::new();
    if class == ResultClass::Match {
        if let Some(value) = expected.get("value") {
            values.push(classify_json_value(value));
            if categories.len() == 1 {
                if let Some(category) = classify_expected_category(&categories[0], value) {
                    category_classes.push(category);
                }
            }
        }
        if let Some(map) = expected.get("values").and_then(Value::as_object) {
            values.extend(map.values().map(classify_json_value));
            category_classes.extend(categories.iter().filter_map(|category| {
                map.get(&category.concept_id)
                    .and_then(|value| classify_expected_category(category, value))
            }));
        }
        if expected.contains_key("entityReferenceCount") {
            values.push(ValueClass::List);
        }
    }
    Ok(ResultClassification::new(class, values).with_category_classes(category_classes))
}

fn reference_diagnostic_finding(
    expected: &ResultClassification,
    observed: &ResultClassification,
) -> Option<FindingCode> {
    if expected == observed {
        return None;
    }
    if expected.class != observed.class {
        return Some(
            if matches!(
                expected.class,
                ResultClass::NoMatch | ResultClass::Ambiguous
            ) || matches!(
                observed.class,
                ResultClass::NoMatch | ResultClass::Ambiguous
            ) {
                FindingCode::LookupOutcomeMismatch
            } else {
                FindingCode::PublicProblemMismatch
            },
        );
    }
    Some(if expected.value_classes != observed.value_classes {
        FindingCode::ResultShapeMismatch
    } else {
        FindingCode::ResultValueMismatch
    })
}

fn diagnose_reference_fixed(
    trace: &mut FixtureTrace,
    expected: &JsonMap<String, Value>,
    bundle: &Bundle,
    requirement: &RequirementConfig,
    observed_class: ResultClass,
    reason: ReasonCode,
) -> Result<(), CliError> {
    let categories = category_diagnostic_catalog(bundle, requirement);
    let expected = classify_reference_expected_result(expected, &categories)?;
    let observed = ResultClassification::new(observed_class, Vec::new());
    let finding = reference_diagnostic_finding(&expected, &observed);
    trace.diagnose(expected, observed, reason, finding);
    Ok(())
}

fn diagnose_reference_kernel_error(
    trace: &mut FixtureTrace,
    expected: &JsonMap<String, Value>,
    bundle: &Bundle,
    requirement: &RequirementConfig,
    error: KernelError,
) -> Result<(), CliError> {
    let categories = category_diagnostic_catalog(bundle, requirement);
    let expected = classify_reference_expected_result(expected, &categories)?;
    let (observed, reason) = classify_observed_result(&Err(error), &categories);
    let finding = reference_diagnostic_finding(&expected, &observed);
    trace.diagnose(expected, observed, reason, finding);
    Ok(())
}

fn diagnose_reference_match(
    trace: &mut FixtureTrace,
    expected: &JsonMap<String, Value>,
    bundle: &Bundle,
    requirement: &RequirementConfig,
    values: &ValidatedValues,
    finding_override: Option<FindingCode>,
) -> Result<(), CliError> {
    let categories = category_diagnostic_catalog(bundle, requirement);
    let expected = classify_reference_expected_result(expected, &categories)?;
    let (observed, reason) =
        classify_observed_result(&Ok(KernelOutcome::Match(values.clone())), &categories);
    let finding = finding_override.or_else(|| reference_diagnostic_finding(&expected, &observed));
    trace.diagnose(expected, observed, reason, finding);
    Ok(())
}

fn classify_observed_result(
    outcome: &Result<KernelOutcome, registry_evidence::kernel::KernelError>,
    categories: &[CategoryDiagnosticEntry],
) -> (ResultClassification, ReasonCode) {
    match outcome {
        Ok(KernelOutcome::Match(values)) => (
            ResultClassification::new(
                ResultClass::Match,
                values
                    .as_slice()
                    .iter()
                    .map(|value| classify_public_value(&value.value))
                    .collect(),
            )
            .with_category_classes(
                values
                    .as_slice()
                    .iter()
                    .filter_map(|value| {
                        categories
                            .iter()
                            .find(|category| category.concept_id == value.provides_value_for)
                            .and_then(|category| classify_observed_category(category, &value.value))
                    })
                    .collect(),
            ),
            ReasonCode::UniqueMatch,
        ),
        Ok(KernelOutcome::NoMatch) => (
            ResultClassification::new(ResultClass::NoMatch, Vec::new()),
            ReasonCode::NoMatch,
        ),
        Ok(KernelOutcome::Unresolved) => (
            ResultClassification::new(ResultClass::EvidenceUnavailable, Vec::new()),
            ReasonCode::DeclaredUnresolved,
        ),
        Ok(KernelOutcome::Ambiguous) => (
            ResultClassification::new(ResultClass::Ambiguous, Vec::new()),
            ReasonCode::Ambiguous,
        ),
        Err(error) => {
            let (class, reason) = match error {
                KernelError::Extraction => (
                    ResultClass::EvidenceUnavailable,
                    ReasonCode::ExtractionRefused,
                ),
                KernelError::DerivationInput => (
                    ResultClass::EvidenceUnavailable,
                    ReasonCode::DerivationInputRefused,
                ),
                KernelError::SourceProtocol => (
                    ResultClass::SourceUnavailable,
                    ReasonCode::SourceProtocolRefused,
                ),
                KernelError::Script | KernelError::FactsBound => {
                    (ResultClass::ServiceUnavailable, ReasonCode::ScriptRefused)
                }
                KernelError::Output | KernelError::UndeclaredOutputProperty(_) => {
                    (ResultClass::ServiceUnavailable, ReasonCode::OutputRefused)
                }
                KernelError::Bundle | KernelError::Artifact(_) => {
                    (ResultClass::ServiceUnavailable, ReasonCode::BundleRefused)
                }
                KernelError::Requirement => (
                    ResultClass::ServiceUnavailable,
                    ReasonCode::RequirementRefused,
                ),
                KernelError::Evidence => (
                    ResultClass::ServiceUnavailable,
                    ReasonCode::EvidenceConstructionRefused,
                ),
                KernelError::Preparation => {
                    (ResultClass::ServiceUnavailable, ReasonCode::ScriptRefused)
                }
            };
            (ResultClassification::new(class, Vec::new()), reason)
        }
    }
}

struct CategoryDiagnosticEntry {
    concept_id: String,
    concept_ordinal: usize,
    allowed_outputs: Vec<String>,
}

fn category_diagnostic_catalog(
    bundle: &Bundle,
    requirement: &RequirementConfig,
) -> Vec<CategoryDiagnosticEntry> {
    requirement
        .concepts
        .iter()
        .enumerate()
        .filter(|(_, concept)| concept.form == ConceptForm::ControlledCategory)
        .filter_map(|(concept_ordinal, concept)| {
            let path = concept
                .constraints
                .get("codelist")
                .and_then(serde_norway::Value::as_str)?;
            let codelist = bundle.codelists.get(path)?;
            let allowed_outputs = match codelist {
                registry_evidence::bundle::Codelist::Codes { codes, .. } => codes.clone(),
                registry_evidence::bundle::Codelist::Mapping {
                    allowed_outputs, ..
                } => allowed_outputs.clone(),
            };
            Some(CategoryDiagnosticEntry {
                concept_id: concept.id.clone(),
                concept_ordinal,
                allowed_outputs,
            })
        })
        .collect()
}

fn classify_expected_category(
    category: &CategoryDiagnosticEntry,
    value: &Value,
) -> Option<CategoryClass> {
    let value = value.as_str()?;
    category
        .allowed_outputs
        .iter()
        .position(|allowed| allowed == value)
        .map(|value_ordinal| CategoryClass {
            concept_ordinal: category.concept_ordinal,
            value_ordinal,
        })
}

fn classify_observed_category(
    category: &CategoryDiagnosticEntry,
    value: &PublicValue,
) -> Option<CategoryClass> {
    let PublicValue::String(value) = value else {
        return None;
    };
    category
        .allowed_outputs
        .iter()
        .position(|allowed| allowed == value)
        .map(|value_ordinal| CategoryClass {
            concept_ordinal: category.concept_ordinal,
            value_ordinal,
        })
}

fn classify_json_value(value: &Value) -> ValueClass {
    match value {
        Value::Bool(false) => ValueClass::BooleanFalse,
        Value::Bool(true) => ValueClass::BooleanTrue,
        Value::Number(_) => ValueClass::Integer,
        Value::String(_) => ValueClass::String,
        Value::Array(_) => ValueClass::List,
        Value::Object(object) => match object.get("form").and_then(Value::as_str) {
            Some("date-bucket" | "time-bucket") => ValueClass::Bucket,
            Some("audience-scoped-entity-reference") => ValueClass::EntityReference,
            _ => ValueClass::Structured,
        },
        Value::Null => ValueClass::Structured,
    }
}

fn classify_public_value(value: &PublicValue) -> ValueClass {
    match value {
        PublicValue::Boolean(false) => ValueClass::BooleanFalse,
        PublicValue::Boolean(true) => ValueClass::BooleanTrue,
        PublicValue::Integer(_) => ValueClass::Integer,
        PublicValue::String(_) => ValueClass::String,
        PublicValue::Bucket(_) => ValueClass::Bucket,
        PublicValue::EntityReference(_) => ValueClass::EntityReference,
        PublicValue::Structured(_) => ValueClass::Structured,
        PublicValue::List(_) => ValueClass::List,
    }
}

/// Convert the fixed comparison error vocabulary into one closed repair code.
/// The returned code, unlike the operator sentence, is a stable machine input.
fn expectation_finding_code(error: &CliError) -> FindingCode {
    match error.0 {
        "fixture lookup outcome did not match its contract" | "fixture expected a unique match" => {
            FindingCode::LookupOutcomeMismatch
        }
        "fixture kernel failure did not match its public problem"
        | "unresolved fixture public problem is not exact"
        | "fixture evaluation failed unexpectedly" => FindingCode::PublicProblemMismatch,
        "unresolved fixture must deny derivation and signed success"
        | "failing fixture execution expectations did not match"
        | "matched fixture cannot deny derivation execution"
        | "matched fixture must require derivation and signed success" => {
            FindingCode::DerivationExpectationMismatch
        }
        "matched fixture cannot deny signed-success eligibility" => {
            FindingCode::SigningExpectationMismatch
        }
        "fixture value did not match its contract" => FindingCode::ResultValueMismatch,
        "fixture value set did not match its contract" => FindingCode::ResultShapeMismatch,
        "fixture lookup expectation is invalid"
        | "matched fixture must require an exact match"
        | "matched fixture must declare exactly one value expectation"
        | "fixture value-set expectation is invalid" => FindingCode::InvalidExpectation,
        _ => FindingCode::UnexpectedToolOutcome,
    }
}

/// Decide whether the outcome one case declared is the outcome it got.
fn compare_case_outcome(
    case: &serde_json::Map<String, Value>,
    outcome: Result<KernelOutcome, registry_evidence::kernel::KernelError>,
) -> Result<Option<ValidatedValues>, CliError> {
    let derivation_runs = optional_boolean(case, "derivationRuns")?;
    let signed_success = optional_boolean(case, "signedSuccess")?;
    let expected_problem = optional_string(case, "expectedPublicProblem")?;

    if let Some(expected_lookup @ ("no_match" | "ambiguous" | "unresolved")) =
        optional_string(case, "expectedLookup")?
    {
        let matches = matches!(
            (expected_lookup, &outcome),
            ("no_match", Ok(KernelOutcome::NoMatch))
                | ("ambiguous", Ok(KernelOutcome::Ambiguous))
                | ("unresolved", Ok(KernelOutcome::Unresolved))
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
    if optional_string(case, "expectedLookup")?.is_some_and(|lookup| lookup != "match") {
        return Err(CliError("fixture lookup expectation is invalid"));
    }

    if let Some(problem) = expected_problem {
        let exact = matches!(
            (problem, &outcome),
            ("evidence.unavailable", Ok(KernelOutcome::Unresolved))
                | (
                    "evidence.unavailable",
                    Err(registry_evidence::kernel::KernelError::Extraction
                        | registry_evidence::kernel::KernelError::DerivationInput)
                )
                | (
                    "source.unavailable",
                    Err(registry_evidence::kernel::KernelError::SourceProtocol)
                )
                | (
                    "service.unavailable",
                    Err(registry_evidence::kernel::KernelError::Script
                        | registry_evidence::kernel::KernelError::Output
                        | registry_evidence::kernel::KernelError::UndeclaredOutputProperty(_)
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
            Ok(KernelOutcome::Unresolved)
                | Err(registry_evidence::kernel::KernelError::Extraction
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
    if optional_string(case, "expectedLookup")? != Some("match") {
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

    let expected_value = case.get("expectedValue");
    let expected_values = case.get("expectedValues");
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
    use registry_evidence::pack_source::PackSourceError;
    let failure = match source_failure.as_str() {
        Some("timeout") => PackSourceError::Timeout,
        Some("redirect" | "wrong-media-type") => PackSourceError::Protocol,
        Some("http-503") => PackSourceError::Dependency,
        _ => return Err(CliError("fixture source-failure category is invalid")),
    };
    if optional_string(case, "expectedPublicProblem")? != Some("source.unavailable")
        || optional_boolean(case, "signedSuccess")? != Some(false)
        || pack_source_failure(failure).problem() != ProblemCode::DependencyUnavailable
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
    let matrix: Value = registry_platform_yaml::Reader::new("anti-reconstruction.yaml")
        .scan(ANTI_RECONSTRUCTION_FIXTURE)
        .ok()
        .flatten()
        .map(|root| root.to_json_value())
        .ok_or(CliError("anti-reconstruction fixture is invalid"))?;
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
    original.disclosure_guard.families =
        registry_platform_yaml::UniqueList::new(vec![shared_family.to_owned()])
            .expect("a single family is distinct");
    for index in 1..definitions.len() {
        let suffix = format!(":fixture-companion-{index}");
        let handle_suffix = format!("-fixture-companion-{index}");
        let mut companion = requirement.clone();
        companion.handle.push_str(&handle_suffix);
        companion.id.push_str(&suffix);
        companion.evidence_type.push_str(&suffix);
        companion.disclosure_guard.families =
            registry_platform_yaml::UniqueList::new(vec![shared_family.to_owned()])
                .expect("a single family is distinct");
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
        .get("privacyExpectation")
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

    for expected in expectation_strings(expectation, "evidenceContains")? {
        if !disclosed_strings.contains(&expected) {
            return Err(CliError("fixture required disclosure is absent"));
        }
    }
    for prohibited in expectation_strings(expectation, "evidenceExcludes")? {
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
    for prohibited in expectation_strings(expectation, "diagnosticsExclude")? {
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
    if let Some(observed) = case.get("observedAt").and_then(Value::as_str) {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = case.get("legalLocalDate").and_then(Value::as_str) {
        return local_date_at_noon(local_date, timezone);
    }

    if let Some(observed) = common
        .and_then(|value| value.get("observedAt"))
        .and_then(Value::as_str)
    {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = common
        .and_then(|value| value.get("legalLocalDate"))
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
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;
    use clap::CommandFactory as _;
    use registry_evidence::config::SubjectBindingMode;
    use registry_evidence::verifier::{ExpectedListItemForm, ExpectedValueForm};
    use std::fs;

    /// A stop signal handler that cannot be installed refuses startup with
    /// the operating system's cause, rather than a service no signal can stop.
    #[test]
    fn a_stop_signal_that_cannot_be_installed_refuses_startup() {
        let refusal = stop_signal(|| {
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "install refused",
            ))
        })
        .expect_err("an install failure is a startup error");
        let CommandError::Service(message) = refusal else {
            panic!("a stop signal refusal is a service error");
        };
        assert_eq!(
            message,
            "the stop signal handlers could not be installed, so Evidence did not start: install refused"
        );
    }

    #[test]
    fn an_installed_stop_signal_is_handed_to_the_server() {
        assert_eq!(stop_signal(|| Ok(7_u8)).expect("the install succeeds"), 7);
    }

    /// The issuer trust refusal covers every way a named profile fails to
    /// resolve, not only a file that holds no certificate.
    #[test]
    fn an_issuer_trust_refusal_names_a_profile_that_does_not_resolve() {
        let CommandError::Cli(CliError(message)) =
            runtime_initialization_error(RuntimeInitializationError::IssuerTrust)
        else {
            panic!("an issuer trust refusal is a plain CLI error");
        };
        assert_eq!(
            message,
            "runtime authentication initialization failed: the access-token issuer TLS trust \
             profile does not resolve to a bound certificate bundle trusted beside the system roots"
        );
    }

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

    fn render_discovery_description_cli(config: &Path) -> Cli {
        Cli {
            command: Command::RenderDiscoveryDescription {
                config: config.to_path_buf(),
            },
        }
    }

    /// Provider-publication compilation refuses in three stages, and each one
    /// reports its own class, so a rejected compilation says which stage
    /// refused.
    #[test]
    fn discovery_description_failure_classes_are_distinct() {
        let classes = [
            DISCOVERY_CONFIG_UNREADABLE,
            DISCOVERY_CONFIG_INVALID,
            DISCOVERY_OUTPUT_UNWRITABLE,
        ];

        let distinct = classes
            .iter()
            .map(|class| class.0)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(distinct.len(), classes.len(), "{classes:?}");
    }

    /// A configuration that cannot be read is its own class, and the path the
    /// operator named stays out of the message.
    #[tokio::test]
    async fn render_discovery_description_reports_an_unreadable_configuration() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("absent-publication.yaml");

        let error = run(render_discovery_description_cli(&missing))
            .await
            .expect_err("a configuration that is not there cannot be read");

        assert_eq!(error, CommandError::Cli(DISCOVERY_CONFIG_UNREADABLE));
        let rendered = error.to_string();
        assert!(!rendered.contains("absent-publication"), "{rendered}");
        assert!(
            !rendered.contains(&missing.display().to_string()),
            "{rendered}"
        );
    }

    /// A document the runtime refuses as configuration is a second class, and
    /// neither the file it came from nor a scalar it carries reaches the
    /// operator message.
    #[tokio::test]
    async fn render_discovery_description_reports_an_invalid_configuration() {
        let directory = tempfile::tempdir().expect("temporary directory");
        for (name, document, expected_code, expected_line) in [
            (
                "unparsable-publication.yaml",
                "kind: EvidenceBundle\nservice: [parcel-owner-lookup\n",
                "yaml.unexpected-end",
                3,
            ),
            (
                "foreign-publication.yaml",
                "apiVersion: id.registrystack.org/formats/evidence/bundle/v1\nkind: EvidenceBundle\nunknownSetting: parcel-owner-lookup\n",
                "config.unknown-key",
                3,
            ),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, document).expect("configuration is written");

            let error = run(render_discovery_description_cli(&path))
                .await
                .expect_err("a document that is not Evidence configuration is refused");

            let CommandError::Refused(report) = &error else {
                panic!("an invalid configuration reports the reader's diagnostics: {error}");
            };
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == expected_code)
                .unwrap_or_else(|| panic!("{name}: no {expected_code}"));
            let source = diagnostic.source.as_ref().expect("a position");
            assert_eq!(source.file, path.display().to_string());
            assert_eq!(source.line, Some(expected_line), "{name}");
            let rendered = error.to_string();
            assert!(!rendered.contains("parcel-owner-lookup"), "{rendered}");
        }
    }

    /// A refused configuration carries the parser's closed, value-free cause,
    /// so the operator learns which bound or field refused the document
    /// without any configured value reaching the message.
    #[test]
    fn a_refused_discovery_configuration_carries_the_field_named_cause() {
        let error = discovery_config_invalid(ConfigError::InvalidField(
            "collection cardinality is outside Version 1 bounds",
            "publication jurisdictions",
        ));
        assert_eq!(
            error.to_string(),
            "discovery description configuration is not valid Evidence configuration: \
             artifact evidence.yaml: collection cardinality is outside Version 1 bounds \
             (publication jurisdictions)"
        );
    }

    /// Configuration validation refuses every scalar the shared public profile
    /// refuses, so a document that could not be projected is reported as an
    /// invalid configuration and never reaches the projection stage.
    #[tokio::test]
    async fn render_discovery_description_refuses_an_unprojectable_publication() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        // The issuer id becomes a role identifier in the projection. A
        // no-break space is whitespace no URI carries, and `validate_uri`
        // reads that rule from the same shared profile the projection reads,
        // so the document is refused while its fields are checked.
        let mut document: Value =
            serde_norway::from_str(ACCEPTANCE).expect("the fixture document parses");
        document["issuer"]["uri"] = serde_json::json!("urn:example:fixture:issuer\u{a0}authority");
        let document =
            serde_norway::to_string(&document).expect("the invalid issuer fixture serializes");
        EvidenceConfig::parse_yaml(ACCEPTANCE.as_bytes())
            .expect("the acceptance configuration is accepted as written");
        let refusal = EvidenceConfig::parse_yaml(document.as_bytes())
            .expect_err("an unprojectable publication is not accepted as configuration");
        let ConfigError::Refused(report) = &refusal else {
            panic!("the reader did not refuse the publication: {refusal}");
        };
        assert_eq!(
            report.diagnostics()[0].code,
            "evidence.bundle.invalid-issuer"
        );
        assert_eq!(report.diagnostics()[0].path, "/issuer/uri");

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("unprojectable-publication.yaml");
        fs::write(&path, &document).expect("configuration is written");

        let error = run(render_discovery_description_cli(&path))
            .await
            .expect_err("a publication the shared profile refuses is not compiled");

        let CommandError::Refused(report) = &error else {
            panic!("an unprojectable publication reports the reader's diagnostics: {error}");
        };
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "evidence.bundle.invalid-issuer");
        assert_eq!(diagnostic.path, "/issuer/uri");
        let source = diagnostic.source.as_ref().expect("a position");
        assert_eq!(source.file, path.display().to_string());
        let issuer_line = document
            .lines()
            .position(|line| line.contains('\u{a0}'))
            .expect("the invalid issuer is present")
            + 1;
        assert_eq!(source.line, Some(issuer_line));
    }

    #[test]
    fn local_audit_failures_report_closed_classes_without_values() {
        assert_eq!(
            local_audit_failure(&EvidenceAuditError::RequestBatchOperation).0,
            "local audit inspection failed: the last operation is a request batch"
        );
        assert_eq!(
            local_audit_failure(&EvidenceAuditError::InvalidEvent).0,
            "local audit inspection failed: an entry is not well formed"
        );
        assert_eq!(
            local_audit_failure(&EvidenceAuditError::Audit(AuditError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "person-123 canary"),
            )))
            .0,
            "local audit inspection failed: an entry is not well formed"
        );
        assert_eq!(
            local_audit_failure(&EvidenceAuditError::Audit(AuditError::SinkLocked {
                path: "/private/audit.jsonl.lock".to_owned(),
                role: None,
            }))
            .0,
            "local audit inspection failed: a writer still holds the audit file"
        );
        assert_eq!(
            local_audit_failure(&EvidenceAuditError::Audit(AuditError::Io(
                std::io::Error::other("person-123 canary"),
            )))
            .0,
            "local audit inspection failed"
        );
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

    #[cfg(unix)]
    #[test]
    fn bundle_check_json_uses_the_package_digest_and_exact_requirement_revisions() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/all-definitions");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("fixture bundle loads");
        let report = package_digest_report(&bundle).expect("package report");
        assert_eq!(report["packageDigest"], bundle.package_digest());
        let requirements = report["requirements"].as_array().unwrap();
        assert_eq!(requirements.len(), bundle.config.requirements.len());
        for (entry, requirement) in requirements.iter().zip(&bundle.config.requirements) {
            assert_eq!(entry["id"], requirement.id);
            assert_eq!(
                entry["configurationRevision"],
                bundle.configuration_revision(&requirement.id).unwrap()
            );
            assert_eq!(entry.as_object().unwrap().len(), 2);
        }
        assert_eq!(report.as_object().unwrap().len(), 2);
        assert!(Cli::try_parse_from([
            "evidence",
            "bundle-check",
            "--bundle",
            "/tmp/bundle",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--json"
        ])
        .is_ok());
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
    /// way that schema writes it. A form is a mapping named by `type`, not a
    /// YAML tag; the list form writes its members beside `type`, and it is the
    /// only form a list-valued concept can state.
    #[test]
    fn policy_documents_parse_every_expected_form_as_the_contract_writes_it() {
        for (written, expected) in [
            ("{type: boolean}", ExpectedValueForm::Boolean),
            ("{type: integer}", ExpectedValueForm::Integer),
            ("{type: string}", ExpectedValueForm::String),
            ("{type: date-bucket}", ExpectedValueForm::DateBucket),
            ("{type: time-bucket}", ExpectedValueForm::TimeBucket),
            (
                "{type: entity-reference}",
                ExpectedValueForm::EntityReference,
            ),
            ("{type: structured}", ExpectedValueForm::Structured),
            (
                "{type: list, items: string, minimumItems: 1, maximumItems: 2, unique: true}",
                ExpectedValueForm::List {
                    item_form: ExpectedListItemForm::String,
                    minimum_items: 1,
                    maximum_items: 2,
                    unique: true,
                },
            ),
        ] {
            let document = verification_policy_document(&format!("form: {written}"));
            let policy = read_verification_policy("policy.yaml", document.as_bytes())
                .unwrap_or_else(|report| {
                    panic!("`{written}` is a policy form: {}", report.render_human())
                });
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
            "boolean",
            "{list: {items: string, minimumItems: 1, maximumItems: 2, unique: true}}",
            "{type: list}",
            "{type: list, minimumItems: 1}",
            "{type: list, minimumItems: 1, maximumItems: 2, extra: 3}",
            "{type: set, minimumItems: 1, maximumItems: 2}",
            "{type: date_bucket}",
            "{type: boolean, unique: true}",
            "{items: string, minimumItems: 1, maximumItems: 2, unique: true}",
        ] {
            let document = verification_policy_document(&format!("form: {written}"));
            assert!(
                read_verification_policy("policy.yaml", document.as_bytes()).is_err(),
                "`{written}` is not a policy form but parsed as one"
            );
        }
    }

    /// One complete policy document whose single expected output states `form`.
    fn verification_policy_document(form: &str) -> String {
        format!(
            "apiVersion: id.registrystack.org/formats/evidence/verification-policy/v1\n\
             kind: EvidenceVerificationPolicy\n\
             expectedAssuranceProfile: evidence-grade\n\
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
        let case = serde_json::json!({"legalLocalDate": "2026-08-03"});
        let observed = fixture_observed_at(case.as_object().expect("object"), None, None)
            .expect("date converts");
        assert_eq!(observed.to_rfc3339(), "2026-08-03T12:00:00+00:00");
    }

    #[test]
    fn case_local_date_overrides_common_observation_time() {
        let case = serde_json::json!({"legalLocalDate": "2026-08-01"});
        let common = serde_json::json!({"observedAt": "2026-08-02T00:00:00Z"});
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
                "sourceFailure": category,
                "expectedPublicProblem": "source.unavailable",
                "signedSuccess": false
            });
            let object = case.as_object().expect("object");
            assert_eq!(
                validate_source_failure(object, &object["sourceFailure"]),
                Ok(())
            );
        }
    }

    #[test]
    fn arbitrary_strings_never_become_category_diagnostic_identity() {
        let category = CategoryDiagnosticEntry {
            concept_id: "urn:example:concept:category".to_owned(),
            concept_ordinal: 0,
            allowed_outputs: vec!["allowed".to_owned()],
        };
        assert_eq!(
            classify_expected_category(&category, &Value::String("arbitrary".to_owned())),
            None
        );
        assert_eq!(
            classify_observed_category(&category, &PublicValue::String("arbitrary".to_owned())),
            None
        );
        let case = serde_json::json!({"expectedValue": "arbitrary"});
        let classified = classify_expected_result(case.as_object().expect("object"), &[])
            .expect("a generic string remains classifiable");
        assert_eq!(classified.value_classes, vec![ValueClass::String]);
        assert!(classified.category_classes.is_empty());
    }

    #[test]
    fn reference_error_only_expectations_keep_their_closed_failure_class() {
        for (signal, class) in [
            ("source_protocol_error", ResultClass::SourceUnavailable),
            ("derivation_input_error", ResultClass::EvidenceUnavailable),
            ("adapter_input_error", ResultClass::ServiceUnavailable),
        ] {
            let expected = serde_json::json!({"error": signal, "signed": false});
            let actual =
                classify_reference_expected_result(expected.as_object().expect("object"), &[])
                    .expect("a closed error expectation is classifiable");
            assert_eq!(actual.class, class, "{signal}");
            assert!(actual.value_classes.is_empty());
        }
        let expected = serde_json::json!({"error":"derivation_input_error", "publicProblem":"service.unavailable"});
        assert_eq!(
            classify_reference_expected_result(expected.as_object().expect("object"), &[])
                .expect("an explicit public outcome is classifiable")
                .class,
            ResultClass::ServiceUnavailable
        );
    }

    #[test]
    fn nested_reference_expectations_use_governed_category_ordinals() {
        let category = CategoryDiagnosticEntry {
            concept_id: "urn:example:concept:category".to_owned(),
            concept_ordinal: 2,
            allowed_outputs: vec!["approved".to_owned(), "pending".to_owned()],
        };
        let expected = serde_json::json!({
            "lookup": "match",
            "value": "pending",
            "derivationRuns": true,
            "signed": true
        });
        let classified =
            classify_reference_expected_result(expected.as_object().expect("object"), &[category])
                .expect("the nested reference expectation is classifiable");
        assert_eq!(classified.class, ResultClass::Match);
        assert_eq!(classified.value_classes, vec![ValueClass::String]);
        assert_eq!(
            classified.category_classes,
            vec![CategoryClass {
                concept_ordinal: 2,
                value_ordinal: 1,
            }]
        );
        let serialized = serde_json::to_string(&classified).expect("classification serializes");
        assert!(!serialized.contains("approved"));
        assert!(!serialized.contains("pending"));
        assert!(!serialized.contains("urn:example:concept:category"));
    }

    #[test]
    fn public_unavailability_requires_an_extraction_failure() {
        let case = serde_json::json!({
            "expectedPublicProblem": "evidence.unavailable",
            "derivationRuns": false,
            "signedSuccess": false
        });
        let case = case.as_object().expect("object");
        assert!(validate_case_outcome(
            case,
            Ok(KernelOutcome::NoMatch),
            &mut FixtureTrace::default(),
            &[],
        )
        .is_err());
        assert!(validate_case_outcome(
            case,
            Err(registry_evidence::kernel::KernelError::Script),
            &mut FixtureTrace::default(),
            &[],
        )
        .is_err());
        assert_eq!(
            validate_case_outcome(
                case,
                Err(registry_evidence::kernel::KernelError::Extraction),
                &mut FixtureTrace::default(),
                &[],
            ),
            Ok(None)
        );
    }

    #[test]
    fn the_expect_note_marks_an_unstated_lookup_as_the_default() {
        let notes = |case: Value| {
            let mut trace = FixtureTrace::default();
            let _ = validate_case_outcome(
                case.as_object().expect("object"),
                Ok(KernelOutcome::NoMatch),
                &mut trace,
                &[],
            );
            trace.cases[0]
                .stages
                .last()
                .expect("expect stage")
                .note
                .clone()
        };
        assert!(notes(serde_json::json!({}))
            .starts_with("the case expects lookup \"match\" (unstated default),"));
        assert!(notes(serde_json::json!({"expectedLookup": "no_match"}))
            .starts_with("the case expects lookup \"no_match\","));
    }

    #[test]
    fn service_unavailability_requires_an_internal_kernel_failure() {
        let case = serde_json::json!({
            "expectedPublicProblem": "service.unavailable",
            "derivationRuns": true,
            "signedSuccess": false
        });
        let case = case.as_object().expect("object");
        assert_eq!(
            validate_case_outcome(
                case,
                Err(registry_evidence::kernel::KernelError::Script),
                &mut FixtureTrace::default(),
                &[],
            ),
            Ok(None)
        );
        assert!(validate_case_outcome(
            case,
            Err(registry_evidence::kernel::KernelError::Extraction),
            &mut FixtureTrace::default(),
            &[],
        )
        .is_err());
    }

    #[test]
    fn unresolved_lookup_rejects_derivation_or_signed_success_claims() {
        for declaration in [
            serde_json::json!({
                "expectedLookup": "no_match",
                "expectedPublicProblem": "evidence.unavailable",
                "derivationRuns": true
            }),
            serde_json::json!({
                "expectedLookup": "no_match",
                "expectedPublicProblem": "evidence.unavailable",
                "signedSuccess": true
            }),
        ] {
            assert!(validate_case_outcome(
                declaration.as_object().expect("object"),
                Ok(KernelOutcome::NoMatch),
                &mut FixtureTrace::default(),
                &[],
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

    fn checked_offline_bundle(relative: &str) -> Arc<Bundle> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        let verified = registry_platform_config::verify_package(
            &root,
            &registry_evidence::bundle::evidence_package_limits(),
            "evidencectl package",
        )
        .expect("exact package checksum closure");
        Arc::new(Bundle::load_as_found(&root, &verified).expect("current pack bundle"))
    }

    #[test]
    fn declared_unresolved_lookup_is_data_free_and_source_bound() {
        let bundle = checked_offline_bundle("products/evidence/fixtures/acceptance/adult-status");
        let kernel = OfflineKernel::compile(bundle).unwrap();
        assert!(matches!(
            kernel.validate_lookup("source-a", &serde_json::json!({"lookup":"unresolved"})),
            Ok(LookupResult::Unresolved)
        ));
        assert!(kernel
            .validate_lookup(
                "unknown-source",
                &serde_json::json!({"lookup":"unresolved"})
            )
            .is_err());
        for invalid in [
            serde_json::json!({"lookup":"unresolved","facts":{"private":"canary"}}),
            serde_json::json!({"lookup":"unresolved","type":"https://example.invalid/problem","code":"private.canary"}),
            serde_json::json!({"lookup":"no-match","facts":{}}),
        ] {
            assert!(kernel.validate_lookup("source-a", &invalid).is_err());
        }
    }

    /// The real pack declares an unresolved answer without returning its raw
    /// problem-like members as facts or diagnostic output.
    #[tokio::test]
    async fn reference_fixture_evaluates_declared_unresolved_without_problem_data() {
        let bundle = checked_offline_bundle("products/evidence/fixtures/acceptance/adult-status");
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
        let source_plans = compile_bundle_source_plans(&bundle).unwrap();
        let source_fixture = serde_json::to_value(&bundle.fixtures["fixtures/cases.yaml"]).unwrap();
        let mut acquisition = source_fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "missing-fact")
            .unwrap()["source"]
            .clone();
        acquisition["exchanges"][0]["response"]["body"]["type"] =
            Value::String("https://example.invalid/fixture-canary".to_owned());
        acquisition["exchanges"][0]["response"]["body"]["code"] =
            Value::String("fixture.canary".to_owned());
        let fixture = serde_json::json!({
            "syntheticOnly":true,"common":source_fixture["common"],
            "cases":[{"id":"unresolved","acquisition":acquisition,"expected":{
                "lookup":"unresolved","publicProblem":"evidence.unavailable",
                "derivationRuns":false,"signed":false,"sourceRequestCount":1
            }}],
            "privacyExpectation":{"evidenceContains":[],"evidenceExcludes":[],"diagnosticsExclude":["fixture-canary","fixture.canary"]}
        });
        let signer = offline_fixture_signer().await.unwrap();
        let requirement = &bundle.config.requirements[0];
        let mut trace = FixtureTrace::default();
        assert_eq!(
            evaluate_reference_fixture(
                &bundle,
                &kernel,
                &source_plans,
                Some(&signer),
                requirement,
                (fixture.as_object().unwrap(), None),
                &mut trace,
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
                (fixture.as_object().unwrap(), Some("unresolved")),
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
                (fixture.as_object().unwrap(), Some("private-case-canary")),
                &mut FixtureTrace::default(),
            )
            .await,
            Err(CliError("selected fixture case is unavailable"))
        );
        let rendered = serde_json::to_string(&trace).unwrap();
        assert!(rendered.contains("unresolved"));
        for prohibited in ["fixture-canary", "fixture.canary", "private-case-canary"] {
            assert!(!rendered.contains(prohibited));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn chained_reference_parameter_mutation_uses_final_fetch_facts() {
        let (bundle, fixture) = chained_reference_fixture_bundle();
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == REFERENCE_CHAINED_REQUIREMENT)
            .unwrap();
        let fixture = fixture.as_object().unwrap();
        let common = fixture["common"].as_object().unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            Some(common),
            &JsonMap::new(),
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let selectors =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs).unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        let positive = cases.iter().find(|case| case["id"] == "positive").unwrap();
        let mut acquisition = positive["acquisition"].clone();
        acquisition["exchanges"][2]["response"]["body"]["results"][0]["declaration"]
            ["mother.personReference"] = Value::String("PERSON-SYNTHETIC-C".to_owned());
        let source_case = serde_json::json!({"source":acquisition});
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
        let outcome = evaluate_fixture_acquisition(
            &bundle,
            &kernel,
            requirement,
            source_case.as_object().unwrap(),
            FixtureSelectors {
                resolved: &resolved,
                derivation: &selectors,
            },
            fixture_observed_at(&JsonMap::new(), Some(common), None).unwrap(),
            &mut FixtureTrace::default(),
        )
        .await
        .unwrap()
        .unwrap();
        let KernelOutcome::Match(values) = outcome else {
            panic!("the final record resolved uniquely");
        };
        assert_eq!(
            public_json(&values.as_slice()[0].value).unwrap(),
            Value::Bool(false)
        );
        let mutation = cases
            .iter()
            .find(|case| case["id"] == "namespace-mismatch")
            .unwrap();
        assert_eq!(
            validate_reference_parameter_mutation(
                &bundle,
                requirement,
                cases,
                mutation["derivationParameterMutation"].as_object().unwrap(),
                FixtureSelectors {
                    resolved: &resolved,
                    derivation: &selectors
                },
                fixture_observed_at(&JsonMap::new(), Some(common), None).unwrap(),
                mutation["expected"].as_object().unwrap(),
            )
            .await,
            Ok(KernelError::DerivationInput)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn chained_fixture_projection_failures_are_source_protocol_outcomes() {
        let (bundle, fixture) = chained_reference_fixture_bundle();
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == REFERENCE_CHAINED_REQUIREMENT)
            .unwrap();
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
        let common = fixture["common"].as_object().unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            Some(common),
            &JsonMap::new(),
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let selectors =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs).unwrap();
        let positive = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "positive")
            .unwrap();
        for index in [1, 2] {
            let mut acquisition = positive["acquisition"].clone();
            acquisition["exchanges"][index]["response"]["body"] = serde_json::json!({"errors":[]});
            let case = serde_json::json!({"source":acquisition});
            assert_eq!(
                evaluate_fixture_acquisition(
                    &bundle,
                    &kernel,
                    requirement,
                    case.as_object().unwrap(),
                    FixtureSelectors {
                        resolved: &resolved,
                        derivation: &selectors
                    },
                    fixture_observed_at(&JsonMap::new(), Some(common), None).unwrap(),
                    &mut FixtureTrace::default(),
                )
                .await,
                Ok(Err(KernelError::SourceProtocol))
            );
        }
    }

    const REFERENCE_CHAINED_REQUIREMENT: &str =
        "urn:gov:example:requirement:registered-parent-relationship:v1";

    /// Two reviewed provider reads run inside one pack acquisition. Each send
    /// must consume its own recorded exchange; the final facts come from the
    /// second uniquely matched record.
    #[cfg(unix)]
    fn chained_reference_fixture_bundle() -> (Arc<Bundle>, Value) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/reference/request-adapter/deployment-projects/opencrvs-family-evidence/bundle");
        copy_tree(&source, &root);
        let mut config: Value =
            serde_norway::from_slice(&fs::read(root.join("evidence.yaml")).unwrap()).unwrap();
        let prefix = config["sources"]["registered-birth-parents"]["pack"]["artifactPrefix"]
            .as_str()
            .unwrap()
            .to_owned();
        let old = root.join(&prefix);
        let mut pack: Value =
            serde_norway::from_slice(&fs::read(old.join("pack.yaml")).unwrap()).unwrap();
        let predicate = b"fn is_matched(exchange) { exchange.body.lookup == \"matched\" }\nfn next_inputs(exchange) { #{trackingId: exchange.body.facts.record_tracking_id} }\n";
        pack["scripts"].as_array_mut().unwrap().push(serde_json::json!({
            "path":"scripts/test-chain.rhai","digest":registry_platform_config::sha256_uri(predicate)
        }));
        let route = pack["sourceRoutes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|route| route["id"] == "evidence-birth-parents")
            .unwrap();
        let mut fetch = route["steps"].as_array().unwrap().clone();
        // The route's send reads the minimized `trackingId` input from the
        // body, so the chained read rewrites the body from the first facts.
        fetch.insert(
            0,
            serde_json::json!({"setBody":{"rhai":
                {"file":"scripts/test-chain.rhai","entrypoint":"next_inputs"}}}),
        );
        let matched =
            serde_json::json!({"file":"scripts/test-chain.rhai","entrypoint":"is_matched"});
        fetch.push(serde_json::json!({"choice":{
            "when":[{"rhai":matched,"steps":[]}],
            "otherwise":{"steps":[{"throwException":{"exceptionType":"upstream.malformed","message":"The referenced record did not resolve uniquely."}}]}
        }}));
        route["steps"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"choice":{
                "when":[{"rhai":matched,"steps":fetch}]
            }}));
        let pack_bytes = serde_json::to_vec_pretty(&pack).unwrap();
        let digest = registry_platform_config::sha256_uri(&pack_bytes);
        let prefix = format!(
            "adapter-packs/opencrvs-events/{}",
            digest.strip_prefix("sha256:").unwrap()
        );
        let replacement = root.join(&prefix);
        copy_tree(&old, &replacement);
        fs::write(replacement.join("pack.yaml"), pack_bytes).unwrap();
        fs::write(replacement.join("scripts/test-chain.rhai"), predicate).unwrap();
        fs::rename(&old, directory.path().join("displaced-pack")).unwrap();
        for source in config["sources"].as_object_mut().unwrap().values_mut() {
            source["pack"]["digest"] = Value::String(digest.clone());
            source["pack"]["artifactPrefix"] = Value::String(prefix.clone());
        }
        fs::write(
            root.join("evidence.yaml"),
            serde_norway::to_string(&config).unwrap(),
        )
        .unwrap();
        fs::remove_file(root.join("SHA256SUMS")).unwrap();
        registry_platform_config::write_sum_file(
            &root,
            None,
            &registry_evidence::bundle::evidence_package_limits(),
            "evidencectl package",
        )
        .unwrap();
        set_tree_mode(&root, 0o555, 0o444);
        let bundle = Arc::new(Bundle::load(&root).unwrap());
        let mut fixture = serde_json::to_value(
            &bundle.fixtures["fixtures/registered-parent-relationship-cases.yaml"],
        )
        .unwrap();
        let positive = fixture["cases"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|case| case["id"] == "positive")
            .unwrap();
        let data = positive["acquisition"]["exchanges"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        positive["acquisition"]["exchanges"]
            .as_array_mut()
            .unwrap()
            .push(data);
        set_tree_mode(&root, 0o755, 0o644);
        (bundle, fixture)
    }

    /// A case `source` written for the retired Source form holds the provider
    /// response itself; the refusal names that form and the migration, apart
    /// from a transcript that is merely malformed.
    #[test]
    fn a_retired_fixture_source_names_the_transcript_and_the_migration() {
        let retired = fixture_case_acquisition(&serde_json::json!({
            "total": 1,
            "date_of_birth": "2000-01-01"
        }))
        .err()
        .expect("a provider response is not a transcript");
        assert_eq!(retired, CliError(FIXTURE_SOURCE_RETIRED));
        for needle in [
            "`source`",
            "`intercepts`",
            "`exchanges`",
            "retired Source form",
            "CONFIG.md#migrate-a-retired-source-project",
        ] {
            assert!(retired.0.contains(needle), "{needle}: {}", retired.0);
        }
        assert!(!retired.0.contains("2000-01-01"));

        let malformed = fixture_case_acquisition(&serde_json::json!({
            "intercepts": [],
            "exchanges": [{"request": {}}]
        }))
        .err()
        .expect("a malformed transcript is refused");
        assert_eq!(malformed, CliError(FIXTURE_SOURCE_INVALID));
        assert!(malformed.0.contains("`intercepts`") && malformed.0.contains("`exchanges`"));

        assert!(
            fixture_case_acquisition(&serde_json::json!({"intercepts": [], "exchanges": []}))
                .is_ok()
        );
    }

    /// Recorded rows cannot stand in for execution against a captured extract.
    #[test]
    fn statement_fixtures_refuse_an_unexecuted_rows_form() {
        assert!(
            fixture_acquisition(&serde_json::json!({"rows":[{"active_licence_count":1}]})).is_err()
        );
        assert!(validate_reference_expectation_keys("statementResponse", &JsonMap::new()).is_err());
    }

    #[tokio::test]
    async fn statement_program_requires_captured_extract_assets() {
        let bundle = checked_offline_bundle("products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle");
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| {
                requirement.id == "urn:gov:example:requirement:licence-register-status:v1"
            })
            .unwrap();
        let fixture =
            serde_json::to_value(&bundle.fixtures[requirement.fixtures.as_ref().unwrap().as_str()])
                .unwrap();
        let case = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "positive")
            .unwrap()
            .as_object()
            .unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            fixture["common"].as_object(),
            case,
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let programs = compile_bundle_source_plans(&bundle).unwrap();
        let recorded =
            fixture_acquisition(&serde_json::json!({"intercepts":[],"exchanges":[]})).unwrap();
        assert!(programs[requirement.initial_source()]
            .execute(
                &resolved,
                recorded,
                DateTime::parse_from_rfc3339("2026-08-02T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .await
            .is_err());
    }

    #[test]
    fn statement_fixture_vocabulary_excludes_startup_only_failures() {
        let bundle = checked_offline_bundle("products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle");
        let source = bundle.source_pack("licence-register").unwrap();
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
            "evidenceContains": ["urn:example:concept", "subject"],
            "evidenceExcludes": ["raw-source-value"],
            "diagnosticsExclude": ["selector-value"]
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
            "evidenceContains": [],
            "evidenceExcludes": [],
            "diagnosticsExclude": ["selector-value"]
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
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/adult-status");
        let verified = registry_platform_config::verify_package(
            &root,
            &registry_evidence::bundle::evidence_package_limits(),
            "evidencectl package",
        )
        .expect("exact package closure");
        let mut bundle = Bundle::load_as_found(&root, &verified).expect("bundle loads");
        assert_eq!(
            compile_bundle_source_plans(&bundle).unwrap().len(),
            bundle.config.sources.len()
        );
        let mut config = serde_json::to_value(&bundle.config).unwrap();
        config["sources"]["source-a"]["route"] = Value::String("undeclared-route".to_owned());
        bundle.config = EvidenceConfig::parse_projection(&config).unwrap();
        assert!(compile_bundle_source_plans(&bundle).is_err());
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
        let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
        let fixture = Path::new(
            bundle.config.requirements[0]
                .fixtures
                .as_ref()
                .expect("acceptance fixture is declared")
                .as_str(),
        );
        let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
            .get("cases")
            .and_then(Value::as_array)
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
    #[tokio::test]
    async fn complete_pack_fixture_requires_every_recorded_send_and_no_extras() {
        let (bundle, fixture) = chained_reference_fixture_bundle();
        let requirement = bundle
            .config
            .requirements
            .iter()
            .find(|requirement| requirement.id == REFERENCE_CHAINED_REQUIREMENT)
            .unwrap();
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
        let common = fixture["common"].as_object().unwrap();
        let positive = fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == "positive")
            .unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            Some(common),
            positive.as_object().unwrap(),
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let selectors =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs).unwrap();
        let observed_at =
            fixture_observed_at(positive.as_object().unwrap(), Some(common), None).unwrap();
        let mut short = positive["acquisition"].clone();
        short["exchanges"].as_array_mut().unwrap().pop();
        let mut extra = positive["acquisition"].clone();
        let last = extra["exchanges"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        extra["exchanges"].as_array_mut().unwrap().push(last);
        for acquisition in [short, extra] {
            let case = serde_json::json!({"source":acquisition});
            assert_eq!(
                evaluate_fixture_acquisition(
                    &bundle,
                    &kernel,
                    requirement,
                    case.as_object().unwrap(),
                    FixtureSelectors {
                        resolved: &resolved,
                        derivation: &selectors
                    },
                    observed_at,
                    &mut FixtureTrace::default(),
                )
                .await,
                Ok(Err(KernelError::SourceProtocol))
            );
        }
        let old_form = serde_json::json!({"sources":{}});
        assert_eq!(
            evaluate_fixture_acquisition(
                &bundle,
                &kernel,
                requirement,
                old_form.as_object().unwrap(),
                FixtureSelectors {
                    resolved: &resolved,
                    derivation: &selectors
                },
                observed_at,
                &mut FixtureTrace::default(),
            )
            .await,
            Err(CliError(
                "a fixture records one complete pack acquisition in source"
            ))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn coequal_expected_facts_check_actual_pack_facts_before_derivation_value_free() {
        const MISMATCHED_FACT_VALUE: &str = "1999-09-09";
        const INVALID_FACT_CANARY: &str = "INVALID-FACT-CANARY-7b21";

        let bundle = checked_offline_bundle("products/evidence/fixtures/acceptance/adult-status");
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
        let requirement = &bundle.config.requirements[0];
        let fixture = serde_json::to_value(&bundle.fixtures["fixtures/cases.yaml"]).unwrap();
        let common = fixture["common"].as_object().unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        let positive = cases
            .iter()
            .find(|case| case["id"] == "positive")
            .unwrap()
            .as_object()
            .unwrap();
        let resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            Some(common),
            positive,
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let derivation =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs).unwrap();
        let observed_at = fixture_observed_at(positive, Some(common), None).unwrap();
        let programs = compile_sources(&bundle).unwrap();
        let program = &programs[requirement.initial_source()];
        let actual_facts = match program
            .execute(
                &resolved,
                fixture_acquisition(&positive["source"]).unwrap(),
                observed_at,
            )
            .await
            .unwrap()
        {
            LookupResult::Match(facts) => Value::Object(facts.into_iter().collect()),
            other => panic!("positive fixture did not produce final facts: {other:?}"),
        };

        let exact = serde_json::json!({
            "source": positive["source"],
            "expectedFacts": actual_facts.clone(),
        });
        assert!(evaluate_fixture_acquisition(
            &bundle,
            &kernel,
            requirement,
            exact.as_object().unwrap(),
            FixtureSelectors {
                resolved: &resolved,
                derivation: &derivation,
            },
            observed_at,
            &mut FixtureTrace::default(),
        )
        .await
        .unwrap()
        .is_ok());

        let mismatched = serde_json::json!({
            "source": positive["source"],
            "expectedFacts": {"date_of_birth": MISMATCHED_FACT_VALUE},
        });
        let mut mismatch_trace = FixtureTrace::default();
        let mismatch = evaluate_fixture_acquisition(
            &bundle,
            &kernel,
            requirement,
            mismatched.as_object().unwrap(),
            FixtureSelectors {
                resolved: &resolved,
                derivation: &derivation,
            },
            observed_at,
            &mut mismatch_trace,
        )
        .await;
        assert_eq!(
            mismatch,
            Err(CliError(
                "fixture expected facts did not match actual pack facts"
            ))
        );
        let mismatch_diagnostic = format!("{mismatch:?} {mismatch_trace:?}");
        for canary in [MISMATCHED_FACT_VALUE, "2000-01-01"] {
            assert!(
                !mismatch_diagnostic.contains(canary),
                "{mismatch_diagnostic}"
            );
        }

        let schema_invalid = serde_json::json!({
            "source": positive["source"],
            "expectedFacts": {"undeclared_fact": INVALID_FACT_CANARY},
        });
        let invalid = evaluate_fixture_acquisition(
            &bundle,
            &kernel,
            requirement,
            schema_invalid.as_object().unwrap(),
            FixtureSelectors {
                resolved: &resolved,
                derivation: &derivation,
            },
            observed_at,
            &mut FixtureTrace::default(),
        )
        .await;
        assert_eq!(
            invalid,
            Err(CliError(
                "fixture expected facts do not match the source schema"
            ))
        );
        assert!(!format!("{invalid:?}").contains(INVALID_FACT_CANARY));

        let mut failed_source = positive["source"].clone();
        failed_source["exchanges"][0]["response"]["body"]["date_of_birth"] =
            Value::String(INVALID_FACT_CANARY.to_owned());
        let failed_source_case = serde_json::json!({
            "source": failed_source,
            "expectedFacts": actual_facts.clone(),
        });
        let mut failed_source_trace = FixtureTrace::default();
        let failed_source = evaluate_fixture_acquisition(
            &bundle,
            &kernel,
            requirement,
            failed_source_case.as_object().unwrap(),
            FixtureSelectors {
                resolved: &resolved,
                derivation: &derivation,
            },
            observed_at,
            &mut failed_source_trace,
        )
        .await;
        assert_eq!(
            failed_source,
            Err(CliError(
                "fixture expected facts require the pack route to match"
            ))
        );
        assert!(!format!("{failed_source:?} {failed_source_trace:?}").contains(INVALID_FACT_CANARY));

        let no_match = cases
            .iter()
            .find(|case| case["id"] == "no-match")
            .unwrap()
            .as_object()
            .unwrap();
        let no_match_resolved = resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            Some(common),
            no_match,
            OFFLINE_AUDIENCE,
        )
        .unwrap();
        let no_match_derivation =
            fixture_selector_value(&no_match_resolved, &requirement.derivation.selector_inputs)
                .unwrap();
        let no_match_case = serde_json::json!({
            "source": no_match["source"],
            "expectedFacts": actual_facts,
        });
        assert_eq!(
            evaluate_fixture_acquisition(
                &bundle,
                &kernel,
                requirement,
                no_match_case.as_object().unwrap(),
                FixtureSelectors {
                    resolved: &no_match_resolved,
                    derivation: &no_match_derivation,
                },
                fixture_observed_at(no_match, Some(common), None).unwrap(),
                &mut FixtureTrace::default(),
            )
            .await,
            Err(CliError(
                "fixture expected facts require the pack route to match"
            ))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn coequal_fact_record_comes_from_the_final_pack_match_and_omits_nonmatches() {
        const STALE_EXPECTATION: &str = "STALE-FACT-EXPECTATION-CANARY-184d";

        let mut bundle =
            (*checked_offline_bundle("products/evidence/fixtures/acceptance/adult-status")).clone();
        let fixture_name = bundle.config.requirements[0]
            .fixtures
            .as_ref()
            .expect("fixture path")
            .as_str()
            .to_owned();
        let fixture = bundle
            .fixtures
            .get_mut(&fixture_name)
            .expect("captured fixture");
        let case_count = fixture["cases"].as_array().expect("cases").len();
        let positive = fixture["cases"]
            .as_array_mut()
            .expect("cases")
            .iter_mut()
            .find(|case| case["id"] == "positive")
            .expect("positive case");
        positive["expectedFacts"] = serde_json::json!({
            "date_of_birth": STALE_EXPECTATION,
        });

        let bundle = Arc::new(bundle);
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
        let positive = record_fixture_facts(
            &bundle,
            &kernel,
            &source_plans,
            Path::new(&fixture_name),
            None,
        )
        .await
        .expect("stale fact assertion is repairable");
        assert_eq!(positive.evaluated_cases, case_count);
        assert_eq!(
            positive.matched_facts["positive"],
            *serde_json::json!({"date_of_birth": "2000-01-01"})
                .as_object()
                .expect("fact object")
        );
        assert!(!positive.matched_facts.contains_key("no-match"));
        assert!(
            !serde_json::to_string(&positive)
                .expect("record serializes")
                .contains(STALE_EXPECTATION),
            "the stale authored value must not enter the record"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn coequal_expected_facts_refuse_paths_that_cannot_observe_pack_facts() {
        async fn evaluate_selected(
            relative: &str,
            case_ids: &[&str],
        ) -> Vec<Result<FixtureSummary, CliError>> {
            let mut bundle = (*checked_offline_bundle(relative)).clone();
            let fixture_name = bundle.config.requirements[0]
                .fixtures
                .as_ref()
                .unwrap()
                .as_str()
                .to_owned();
            let fixture = bundle.fixtures.get_mut(&fixture_name).unwrap();
            for case_id in case_ids {
                let case = fixture["cases"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|case| case["id"] == **case_id)
                    .unwrap();
                case["expectedFacts"] = serde_json::json!({});
            }
            let bundle = Arc::new(bundle);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).unwrap();
            let source_plans = compile_bundle_source_plans(&bundle).unwrap();
            let mut results = Vec::new();
            for case_id in case_ids {
                results.push(
                    evaluate_fixture(
                        &bundle,
                        &kernel,
                        &source_plans,
                        Path::new(&fixture_name),
                        Some(case_id),
                        false,
                        &mut FixtureTrace::default(),
                    )
                    .await,
                );
            }
            results
        }

        let adult_results = evaluate_selected(
            "products/evidence/fixtures/acceptance/adult-status",
            &[
                "source-failure",
                "negative-wrong-derived-type",
                "anti-reconstruction",
            ],
        )
        .await;
        for result in adult_results {
            assert_eq!(
                result,
                Err(CliError(
                    "fixture expected facts require an actual pack route match"
                ))
            );
        }

        let authorization_results = evaluate_selected(
            "products/evidence/fixtures/acceptance/legal-parent-relationship",
            &["negative-swapped-roles"],
        )
        .await;
        assert_eq!(
            authorization_results,
            vec![Err(CliError(
                "fixture expected facts require an actual pack route match"
            ))]
        );
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
            let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
            let fixture = Path::new(
                bundle.config.requirements[0]
                    .fixtures
                    .as_ref()
                    .expect("acceptance fixture is declared")
                    .as_str(),
            );
            let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
                .get("cases")
                .and_then(Value::as_array)
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
        let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
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
        let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
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
        let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
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
                .and_then(Value::as_array)
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
            let source_plans = compile_bundle_source_plans(&bundle).expect("source plans compile");
            for requirement in &bundle.config.requirements {
                let fixture_path = requirement
                    .fixtures
                    .as_ref()
                    .expect("reference fixture is declared");
                let fixture = Path::new(fixture_path.as_str());
                let expected_cases = bundle.fixtures[fixture_path.as_str()]
                    .get("cases")
                    .and_then(Value::as_array)
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
}
