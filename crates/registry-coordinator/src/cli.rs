// SPDX-License-Identifier: Apache-2.0
//! Coordinator authoring, activation and authenticated operation.
use crate::{
    definition::Definition, deployment, http, problem::ProblemCode, project,
    runtime::RuntimeConfig, scenarios, CoordinatorError, Result,
};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
pub const CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/coordinator/ctl-report/v1alpha1";
pub const CTL_REPORT_KIND: &str = "CoordinatorCtlReport";
#[derive(Parser)]
#[command(
    name = "coordinatorctl",
    about = "Author, package, activate and operate Registry Coordinator",
    version
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    /// Output format for local reports and authenticated API responses: readable text, or one JSON report.
    format: Format,
    #[arg(long, global = true, value_name = "FILE")]
    /// Runtime configuration file.
    runtime_config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
/// The authenticated service a command calls; offline commands take neither.
#[derive(Args)]
struct Service {
    /// Authenticated Coordinator service origin, HTTPS or explicit loopback HTTP.
    #[arg(long)]
    url: Option<url::Url>,
    /// File containing a current access token; a relative path is read from the current directory. Token values are never printed.
    #[arg(long, value_name = "FILE")]
    token_file: Option<PathBuf>,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
}
#[derive(Clone, Copy, ValueEnum)]
enum SdkLanguage {
    Typescript,
    Python,
}
#[derive(Clone, Copy, ValueEnum)]
enum ListState {
    Running,
    Finished,
    Failed,
    Cancelled,
    CancelledAfterEffect,
    Expired,
    Attention,
    CancelRequested,
}
impl ListState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Finished => "finished",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::CancelledAfterEffect => "cancelled-after-effect",
            Self::Expired => "expired",
            Self::Attention => "attention",
            Self::CancelRequested => "cancel-requested",
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Create a reviewed four-file starter and its .gitignore in a new or empty directory.
    Init {
        #[arg(long)]
        /// New or empty project directory; a directory with content is refused.
        directory: PathBuf,
        #[arg(long)]
        /// Project id written into workflow.yaml; defaults to the directory name.
        id: Option<String>,
    },
    /// Validate the workflow, functions and root YAML companions offline.
    Check {
        #[arg(long)]
        /// Directory containing workflow.yaml and its declared code and contract assets.
        project: Option<PathBuf>,
        #[arg(long, requires = "project")]
        /// Include reviewed call semantics, recovery and execution bounds.
        explain: bool,
        #[arg(long)]
        /// Refuse warnings, including checks deferred until environment values are supplied.
        deny_warnings: bool,
        #[arg(long)]
        /// Substitute runtime environment expressions; secret values are never resolved.
        environment: bool,
    },
    /// Explain a checked graph, mappings and execution bounds offline.
    Explain {
        #[arg(long)]
        /// Directory containing workflow.yaml and its declared code and contract assets.
        project: PathBuf,
    },
    /// Export revision-pinned typed clients from the compiled workflow contract.
    Types {
        #[arg(long)]
        project: PathBuf,
        #[arg(long, value_enum)]
        language: SdkLanguage,
        #[arg(long)]
        output: PathBuf,
    },
    /// Discover a permitted workflow's active revision and input/outcome contract.
    Workflow {
        #[arg(long)]
        workflow: String,
        #[command(flatten)]
        service: Service,
    },
    /// Run deterministic scenarios with a virtual clock and fake products offline.
    Test {
        #[arg(long)]
        /// Directory containing workflow.yaml and its declared code and contract assets.
        project: PathBuf,
        #[arg(long)]
        /// Scenario YAML file; defaults to scenarios.yaml in the project.
        scenarios: Option<PathBuf>,
    },
    /// Build a new immutable package; existing output is never overwritten.
    Package {
        #[arg(long)]
        /// Directory containing workflow.yaml and its declared code and contract assets.
        project: PathBuf,
        #[arg(long)]
        /// New package directory; existing content is refused.
        output: PathBuf,
    },
    /// Inspect activation, schema and each workflow's package change using runtime credentials, without migrating.
    Plan {
        #[arg(long = "remove-workflow", value_name = "WORKFLOW")]
        /// Active workflow to retire because its package is no longer listed; repeat for each workflow.
        remove_workflow: Vec<String>,
    },
    /// Apply every listed workflow's package and least-privileged runtime grants using migration credentials.
    Apply {
        #[arg(long = "remove-workflow", value_name = "WORKFLOW")]
        /// Active workflow to retire because its package is no longer listed; refused while it has runs that are not terminal.
        remove_workflow: Vec<String>,
    },
    /// Inspect deployed workflow packages and schema using runtime credentials.
    DeploymentStatus,
    /// Generate the authenticated service OpenAPI document offline.
    Openapi,
    /// Start one allowed workflow with caller ownership and an idempotency key.
    Start {
        #[arg(long)]
        /// Allowed workflow identifier from the activated workflow package.
        workflow: String,
        #[arg(long)]
        /// Computed revision obtained from types export or workflow discovery.
        workflow_revision: String,
        #[arg(long)]
        /// JSON input file validated against the workflow input schema.
        input: PathBuf,
        #[arg(long)]
        /// UTF-8 file containing the idempotency key for this logical operation.
        key_file: PathBuf,
        #[command(flatten)]
        service: Service,
    },
    /// Read caller-owned or explicitly operator-authorized run progress.
    Status {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[command(flatten)]
        service: Service,
    },
    /// List the runs the current caller policy permits, newest admission first.
    List {
        #[arg(long,default_value_t=20,value_parser=clap::value_parser!(u32).range(1..=100))]
        /// Number of most recent runs to return, from 1 through 100.
        limit: u32,
        #[arg(long, value_parser = bounded_list_cursor)]
        /// Opaque continuation returned as nextCursor by the preceding page.
        cursor: Option<String>,
        #[arg(long, value_enum)]
        /// Return only runs in this effective state.
        state: Option<ListState>,
        #[arg(long)]
        /// True returns attention or failed runs; false excludes both.
        attention: Option<bool>,
        #[command(flatten)]
        service: Service,
    },
    /// Inspect bounded durable step metadata without input or command payloads.
    Inspect {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[command(flatten)]
        service: Service,
    },
    /// Retry only the original stored command identity under its recovery contract.
    RetrySame {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
        #[command(flatten)]
        service: Service,
    },
    /// Prevent future dispatch where possible and preserve unresolved effects.
    Cancel {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
        #[command(flatten)]
        service: Service,
    },
    /// Observe the receiving product using the original command key and owner.
    Reconcile {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
        #[command(flatten)]
        service: Service,
    },
    /// Bounded operator diagnostics through authenticated HTTP.
    Doctor {
        #[command(flatten)]
        service: Service,
    },
    /// Stop dispatch before a restore or recovery investigation.
    RestoreHold {
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
        #[command(flatten)]
        service: Service,
    },
    /// Release hold only after external fencing and authoritative reconciliation.
    ReleaseRestoreHold {
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
        #[command(flatten)]
        service: Service,
    },
    /// Release restored ingress only with complete retained admission evidence and fencing.
    ReleaseAdmissionHold {
        #[arg(long)]
        /// Bounded reference to retained recovery evidence without personal data.
        recovery_reference: String,
        #[arg(long)]
        /// Attest complete authoritative spent-admission history.
        admission_history_complete: bool,
        #[arg(long)]
        /// Attest that every prior service and worker has been externally fenced.
        prior_deployment_fenced: bool,
        #[command(flatten)]
        service: Service,
    },
    /// Attest complete execution history and external fencing while recovery hold remains.
    CompleteExecutionRecovery {
        #[arg(long)]
        /// Bounded reference to retained recovery evidence without personal data.
        recovery_reference: String,
        #[arg(long)]
        /// Attest complete authoritative execution history for restored work.
        execution_history_complete: bool,
        #[arg(long)]
        /// Attest that every prior service and worker has been externally fenced.
        prior_deployment_fenced: bool,
        #[command(flatten)]
        service: Service,
    },
    /// Erase eligible terminal payloads and preserve spent-key tombstones.
    Retain {
        #[arg(long)]
        /// Erase only eligible terminal payloads older than this RFC 3339 timestamp.
        before: chrono::DateTime<chrono::Utc>,
        #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u32).range(1..=100))]
        /// Maximum number of records, from 1 through 100.
        limit: u32,
        #[command(flatten)]
        service: Service,
    },
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Check { .. } => "check",
            Self::Explain { .. } => "explain",
            Self::Types { .. } => "types",
            Self::Workflow { .. } => "workflow",
            Self::Test { .. } => "test",
            Self::Package { .. } => "package",
            Self::Plan { .. } => "plan",
            Self::Apply { .. } => "apply",
            Self::DeploymentStatus => "deployment-status",
            Self::Openapi => "openapi",
            Self::Start { .. } => "start",
            Self::Status { .. } => "status",
            Self::List { .. } => "list",
            Self::Inspect { .. } => "inspect",
            Self::RetrySame { .. } => "retry-same",
            Self::Cancel { .. } => "cancel",
            Self::Reconcile { .. } => "reconcile",
            Self::Doctor { .. } => "doctor",
            Self::RestoreHold { .. } => "restore-hold",
            Self::ReleaseRestoreHold { .. } => "release-restore-hold",
            Self::ReleaseAdmissionHold { .. } => "release-admission-hold",
            Self::CompleteExecutionRecovery { .. } => "complete-execution-recovery",
            Self::Retain { .. } => "retain",
        }
    }
}

fn check(
    project: Option<&Path>,
    runtime: Option<&Path>,
    explain: bool,
    deny_warnings: bool,
    environment: bool,
) -> Result<Value> {
    use registry_platform_yaml::{Report, Severity};
    if project.is_none() && runtime.is_none() {
        return Err(CoordinatorError::new(
            "coordinator.command.usage",
            "check requires a project or runtime configuration",
        )
        .suggest("Supply --project DIRECTORY, --runtime-config FILE, or both.")
        .with_exit(2));
    }
    let mut report = Report::default();
    let mut exit_code = 1;
    let loaded = project.and_then(|path| match Definition::load_project(path) {
        Ok(loaded) => Some(loaded),
        Err(error) => {
            exit_code = exit_code.max(error.exit_code);
            report.extend(error.report());
            None
        }
    });
    if let Some(path) = runtime {
        let (findings, runtime_exit) = crate::project_check::check_runtime(
            path,
            loaded.as_ref().map(|(definition, _)| definition),
            environment,
        );
        report.extend(findings);
        exit_code = exit_code.max(runtime_exit);
    }
    if let Some(path) = project {
        let (findings, project_exit) = crate::project_check::check_directory(
            path,
            loaded
                .as_ref()
                .map(|(definition, workflow)| (definition, workflow)),
            runtime,
            environment,
        );
        report.extend(findings);
        exit_code = exit_code.max(project_exit);
    }
    if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        return Err(CoordinatorError::from_report(report).with_exit(exit_code));
    }
    let mut result = match loaded.map(|(definition, _)| definition) {
        Some(definition) if explain => definition.explain()?,
        Some(definition) => {
            json!({"status":"valid","workflow":definition.workflow.id,"version":definition.workflow.version,"workflowRevision":definition.digest,"steps":definition.workflow.steps.len()})
        }
        None => json!({"status":"valid"}),
    };
    result["diagnostics"] = report.to_json_value();
    if report
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Warning)
    {
        result["status"] = json!("valid-with-warnings");
    }
    Ok(result)
}
/// Run every scenario case offline. Each case reports `passed` or `failed`,
/// and the findings are those `check` reports for the same cases.
fn test(project: &Path, scenarios: Option<&Path>) -> Result<Value> {
    let (definition, workflow) = Definition::load_project(project)?;
    let path = match scenarios {
        Some(path) => path.to_path_buf(),
        None => project
            .canonicalize()
            .unwrap_or_else(|_| project.to_path_buf())
            .join("scenarios.yaml"),
    };
    let (scenarios, document) = scenarios::load_with_document(&path)?;
    let (cases, diagnostics) =
        scenarios::run_project(&definition, &workflow, &document, &scenarios);
    let failed = cases
        .iter()
        .filter(|case| case["status"] == "failed")
        .count();
    Ok(json!({
        "status": if failed == 0 && diagnostics.is_empty() { "passed" } else { "failed" },
        "passed": cases.len() - failed,
        "failed": failed,
        "scenarios": cases,
        "diagnostics": registry_platform_yaml::Report::new(diagnostics).to_json_value(),
    }))
}
/// Read the file `argument` names, up to `maximum` bytes.
fn read(path: &Path, maximum: usize, argument: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| {
            CoordinatorError::new("input-invalid", format!("cannot read the {argument} file"))
                .suggest(format!("Name a readable regular file with {argument}."))
        })?;
    if bytes.len() > maximum {
        return Err(CoordinatorError::new(
            "input-invalid",
            format!("the {argument} file exceeds {maximum} bytes"),
        )
        .suggest(format!("Keep the {argument} file within {maximum} bytes.")));
    }
    Ok(bytes)
}
fn text_file(path: &Path, maximum: usize, argument: &str) -> Result<String> {
    String::from_utf8(read(path, maximum, argument)?)
        .map(|s| s.trim_end_matches(['\r', '\n']).into())
        .map_err(|_| {
            CoordinatorError::new(
                "input-invalid",
                format!("the {argument} file is not UTF-8 text"),
            )
            .suggest(format!("Write the {argument} file as UTF-8 text."))
        })
}
fn runtime(cli: &Cli) -> Result<RuntimeConfig> {
    RuntimeConfig::load(&runtime_config(cli)?.ok_or_else(|| {
        CoordinatorError::new("runtime-config-required", "supply --runtime-config FILE")
            .suggest("Add --runtime-config with the deployment's runtime.yaml.")
    })?)
}
/// `--runtime-config` made absolute against the working directory, with `.`
/// and `..` resolved by name, as the runtime loader requires.
fn runtime_config(cli: &Cli) -> Result<Option<PathBuf>> {
    let Some(path) = cli.runtime_config.as_deref() else {
        return Ok(None);
    };
    let absolute = std::path::absolute(path).map_err(|_| {
        CoordinatorError::new(
            "runtime-config-unresolved",
            "the --runtime-config path could not be resolved against the working directory",
        )
        .suggest("Pass --runtime-config as an absolute path.")
    })?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Ok(Some(normal))
}
async fn remote(
    service: &Service,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
    key: Option<&str>,
) -> Result<Value> {
    let mut url = service.url.clone().ok_or_else(|| {
        CoordinatorError::new(
            "service-required",
            "supply --url with the authenticated Coordinator origin",
        )
        .suggest("Add --url with the Coordinator service origin, such as --url https://coordinator.example.org.")
    })?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(CoordinatorError::new(
            "service-invalid",
            "use an HTTPS origin or explicit loopback HTTP origin",
        )
        .suggest("Pass only the origin to --url: https://HOST[:PORT], or http://127.0.0.1:PORT for a local service, without a path, query, fragment or credentials."));
    }
    let token_path = service.token_file.as_deref().ok_or_else(|| {
        CoordinatorError::new(
            "token-file-required",
            "supply --token-file with a current access token",
        )
        .suggest("Add --token-file with the path of a file that holds a current access token.")
    })?;
    let token = zeroize::Zeroizing::new(text_file(token_path, 16_384, "--token-file")?);
    registry_platform_authcommon::validate_compact_access_token(&token).map_err(|_| {
        CoordinatorError::new(
            "token-invalid",
            "the token file must contain one compact access token",
        )
        .suggest("Write one current compact access token, three dot-separated parts, into the --token-file file.")
    })?;
    url.set_path(path.split('?').next().unwrap_or(path));
    url.set_query(path.split_once('?').map(|(_, q)| q));
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| {
            CoordinatorError::new("service-unavailable", "cannot initialize the HTTP client")
        })?;
    let mut request = client.request(method, url).bearer_auth(token.as_str());
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = request.send().await.map_err(|_| {
        CoordinatorError::new(
            "service-unavailable",
            "the service could not answer; inspect the original run before retrying",
        )
        .suggest("Check that --url reaches the running Coordinator service, then inspect the original run before repeating the command.")
    })?;
    let status = response.status();
    let bytes = registry_platform_httputil::read_bounded(response, 1_048_576)
        .await
        .map_err(|_| {
            CoordinatorError::new(
                "service-unavailable",
                "the service response exceeded its bound",
            )
            .suggest("Check that --url names the Coordinator service origin, not another service.")
        })?;
    let value = registry_platform_canonical_json::parse_json_strict(&bytes).map_err(|_| {
        CoordinatorError::new(
            "service-unavailable",
            "the service response was not bounded JSON",
        )
        .suggest("Check that --url names the Coordinator service origin, not another service.")
    })?;
    if !status.is_success() {
        let (code, message, action) = if status.is_server_error() {
            (
                "service-unavailable",
                "the service could not complete the operation",
                "restore service availability and inspect the original run before attempting same-command recovery",
            )
        } else {
            (
                "service-refused",
                "the authenticated service refused the operation",
                "inspect caller policy and current run status before repeating the operation",
            )
        };
        let problem = value["code"].as_str().and_then(ProblemCode::from_code);
        let detail = value["detail"]
            .as_str()
            .map(escape_controls)
            .filter(|text| text.len() <= 256)
            .unwrap_or_else(|| message.to_owned());
        return Err(CoordinatorError::new(
            code,
            with_reference(detail, problem, value["traceId"].as_str()),
        )
        .suggest(problem.and_then(refusal_advice).unwrap_or(action)));
    }
    Ok(value)
}
/// Name the problem code and trace identifier a refusal carries, so an
/// operator can look the code up and find the request in the service's logs.
/// Only a code from the closed vocabulary and a well-formed W3C trace
/// identifier are echoed.
fn with_reference(detail: String, problem: Option<ProblemCode>, trace: Option<&str>) -> String {
    let trace = trace.and_then(|trace| registry_platform_httpsec::TraceId::parse(trace).ok());
    match (problem, trace) {
        (Some(problem), Some(trace)) => {
            format!("{detail} (problem {}, trace {trace})", problem.code())
        }
        (Some(problem), None) => format!("{detail} (problem {})", problem.code()),
        (None, Some(trace)) => format!("{detail} (trace {trace})"),
        (None, None) => detail,
    }
}
/// Escape every C0, DEL and C1 control character in service-supplied text.
/// JSON output leaves DEL and C1 raw, so a refusal message could otherwise
/// drive the terminal that shows the report.
fn escape_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
/// The fix for a problem code the service returns, in this command line's
/// terms. Only the code is read from a problem document: the service's own
/// text is shown as the message, never as the suggested action.
fn refusal_advice(problem: ProblemCode) -> Option<&'static str> {
    Some(match problem {
        ProblemCode::AuthenticationRefused => "Write a current access token, issued by the deployment's configured issuer to an admitted client, into the --token-file file.",
        ProblemCode::OperationNotAuthorized => "Use a token whose client and scopes match a caller policy that lists this action and, for a run action, this workflow; deployment-wide actions need a policy with operator: true.",
        ProblemCode::WorkflowNotServed => "Name a workflow this deployment serves; its operator lists them with coordinatorctl deployment-status.",
        ProblemCode::RunNotVisible => "Check --run; without operator authority a caller reaches only the runs it started, and only in workflows its policy lists.",
        ProblemCode::InputInvalid => "Correct the --input file to satisfy the workflow's declared input schema and value bounds.",
        ProblemCode::IdempotencyKeyInvalid => "Write an idempotency key of 1 to 256 bytes into the --key-file file.",
        ProblemCode::IdempotencyKeyReused => "This idempotency key already started a run with different input; resend the original input to reach that run, or use another key for a different operation.",
        ProblemCode::WorkflowRevisionMismatch => "Discover the active workflow revision before starting new work. To recover an earlier admission, retain its original workflow revision, caller identity, key and input.",
        ProblemCode::AdmissionRecoveryOnly => "This instance runs in recovery-only mode and admits no runs; send starts to the ordinary service.",
        ProblemCode::AdmissionHeld => "Starts stay held after a restore; once execution hold is released, admission history is complete and the prior deployment is fenced, an operator runs coordinatorctl release-admission-hold --recovery-reference REFERENCE --admission-history-complete --prior-deployment-fenced.",
        ProblemCode::ExecutionHeld => "Execution is under restore hold; once fencing and reconciliation evidence is recorded, an operator runs coordinatorctl release-restore-hold --reason REFERENCE.",
        ProblemCode::RestoreHoldRequired => "Run coordinatorctl restore-hold first, then complete-execution-recovery while that hold remains.",
        ProblemCode::RestoreUnresolved => "Find held work with coordinatorctl doctor and inspect, reconcile uncertain mutations and complete execution recovery where the history allows, then release the hold again.",
        ProblemCode::RestoreLeaseIncompatible => "Held work no longer matches its protected definition or prepared command; restore the run snapshots and prepared commands exactly as backed up, with the state keys and Coordinator version that wrote them, then run complete-execution-recovery again while execution hold remains.",
        ProblemCode::RestoreReviewRequired => "Pass --execution-history-complete and --prior-deployment-fenced only once both are established and recorded.",
        ProblemCode::RetryRefused => "Inspect the run: retry-same applies only to held work before its original deadline; cancel the run when no further execution is appropriate.",
        ProblemCode::RunDefinitionIncompatible => "This service's Coordinator version cannot interpret the run's pinned definition; send retry-same to a service running a version that can, such as the one that admitted the run, or cancel the run when no further execution is appropriate.",
        ProblemCode::ReceiptExpired => "Consult the receiving product's own records for the original command rather than inferring it was not sent, and cancel the run when no further execution is appropriate.",
        ProblemCode::EvaluationUncertain => "Inspect the run and cancel it when no further execution is appropriate; retry-same never reevaluates an evaluation that may have completed.",
        ProblemCode::RunPayloadErased => "Retention erased this run's payloads; inspect it, but it can no longer be retried or reconciled.",
        ProblemCode::BindingConflict => "Restore the run's original connection settings in the runtime file and restart the service before retrying.",
        ProblemCode::BindingLiveConflict => "Restore the original connection settings live runs use, or start the service with --recovery-only to investigate.",
        ProblemCode::ReconcileRefused => "Inspect the run: reconcile applies to a held mutation with a prepared command, its original binding and no active lease; use retry-same for a read.",
        ProblemCode::ReconcileUnsupported => "This operation has no original-result lookup; consult the receiving product's records and cancel the held run when no further execution is appropriate.",
        ProblemCode::ReconcileRaced => "Inspect the run again; its progress changed during reconciliation.",
        ProblemCode::DeploymentActivationChanged => "An apply changed the active packages; restart the service with the runtime file that apply used.",
        ProblemCode::DeploymentRefused => "Run coordinatorctl deployment-status with the service's runtime file; it names the failing check and its fix.",
        ProblemCode::ServiceUnavailable => "Restore the service's database connectivity, durable audit stream and access to its configured token issuer, then inspect the original run before repeating the same command.",
        ProblemCode::AuditResponseUnavailable => "The operation may have completed; inspect the run, or run doctor for a deployment-wide action, before repeating it.",
        ProblemCode::RequestReasonInvalid => "Pass a bounded --reason or --recovery-reference, such as incident-2026-10-09, without personal data or control characters.",
        ProblemCode::RequestRetentionInvalid => "Choose a --before cutoff in the past.",
        ProblemCode::DefinitionRefused
        | ProblemCode::RequestBodyTooLarge
        | ProblemCode::RequestInvalid
        | ProblemCode::RequestLimitOutOfRange
        | ProblemCode::RequestMethodNotAllowed
        | ProblemCode::RequestNotFound
        | ProblemCode::RequestUnprocessable
        | ProblemCode::RequestUnsupportedMediaType
        | ProblemCode::RuntimeFailure => return None,
    })
}
async fn execute(cli: &Cli) -> Result<Value> {
    match &cli.command {
        Command::Init { directory, id } => {
            let created = project::init(directory, id.as_deref())?;
            Ok(json!({"status":"initialized","project":directory,"created":created}))
        }
        Command::Check { project, explain, deny_warnings, environment } => check(project.as_deref(), runtime_config(cli)?.as_deref(), *explain, *deny_warnings, *environment),
        Command::Explain { project } => check(Some(project), runtime_config(cli)?.as_deref(), true, false, false),
        Command::Test { project, scenarios } => test(project, scenarios.as_deref()),
        Command::Package { project, output } => {
            Ok(json!({"packageDigest":deployment::package(project,output)?,"root":output}))
        }
        Command::Plan { remove_workflow } | Command::Apply { remove_workflow } => {
            let apply = matches!(cli.command, Command::Apply { .. });
            let r = runtime(cli)?;
            let workflows = deployment::load_workflows(deployment::config(&r)?)?;
            let store = deployment::open_ctl(&r, apply).await?;
            if apply {
                serde_json::to_value(deployment::apply(&store, &r, &workflows, remove_workflow).await?)
                    .map_err(|_| CoordinatorError::new("output-unavailable", "cannot encode activation"))
            } else {
                deployment::plan(&store, &r, &workflows, remove_workflow).await
            }
        }
        Command::DeploymentStatus => {
            let r = runtime(cli)?;
            let workflows = deployment::load_workflows(deployment::config(&r)?)?;
            workflows.validate(&r)?;
            let store = deployment::open_ctl(&r, false).await?;
            let active = deployment::check_serving(&store, &r, workflows.digest()).await?;
            let d = deployment::config(&r)?;
            Ok(json!({"status":"checked","databaseId":d.database_id,"workflowsDigest":workflows.digest(),"workflows":workflows.package_digests(),"schemaVersion":crate::store::SCHEMA_VERSION,"runtimeRole":d.runtime_role,"active":active}))
        }
        Command::Openapi => Ok(http::openapi()),
        Command::Types { project, language, output } => {
            let definition = Definition::load(project)?;
            let language = match language { SdkLanguage::Typescript => crate::sdk::Language::Typescript, SdkLanguage::Python => crate::sdk::Language::Python };
            let source = crate::sdk::generate(&definition, language)?;
            std::fs::write(output, source).map_err(|_| CoordinatorError::new("output-unavailable", "cannot write the typed workflow client").suggest("Name a writable output file."))?;
            Ok(json!({"status":"exported","output":output,"workflow":definition.workflow.id,"workflowRevision":definition.digest}))
        }
        Command::Workflow { workflow, service } => {
            if !crate::definition::valid_name(workflow) { return Err(CoordinatorError::new("input-invalid", "supply a bounded workflow identifier")); }
            remote(service, reqwest::Method::GET, &format!("/v1/workflows/{workflow}"), None, None).await
        }
        Command::Start {
            workflow,
            workflow_revision,
            input,
            key_file,
            service,
        } => {
            let input = registry_platform_canonical_json::parse_json_strict(&read(input, 65_536, "--input")?)
                .map_err(|_| CoordinatorError::new("input-invalid", "input must be unambiguous JSON").suggest("Write the --input file as one JSON value without duplicate member names."))?;
            let key = text_file(key_file, 256, "--key-file")?;
            remote(
                service,
                reqwest::Method::POST,
                "/v1/runs",
                Some(json!({"workflow":workflow,"workflowRevision":workflow_revision,"input":input})),
                Some(&key),
            )
            .await
        }
        Command::Status { run, service } => {
            remote(
                service,
                reqwest::Method::GET,
                &format!("/v1/runs/{run}"),
                None,
                None,
            )
            .await
        }
        Command::List {
            limit,
            cursor,
            state,
            attention,
            service,
        } => {
            let mut query = format!("/v1/runs?limit={limit}");
            if let Some(cursor) = cursor {
                query.push_str("&cursor=");
                query.push_str(cursor);
            }
            if let Some(state) = state {
                query.push_str("&state=");
                query.push_str(state.as_str());
            }
            if let Some(attention) = attention {
                query.push_str("&attention=");
                query.push_str(if *attention { "true" } else { "false" });
            }
            remote(
                service,
                reqwest::Method::GET,
                &query,
                None,
                None,
            )
            .await
        }
        Command::Inspect { run, service } => {
            remote(
                service,
                reqwest::Method::GET,
                &format!("/v1/runs/{run}/inspect"),
                None,
                None,
            )
            .await
        }
        Command::RetrySame { run, reason, service }
        | Command::Cancel { run, reason, service }
        | Command::Reconcile { run, reason, service } => {
            let action = match cli.command {
                Command::RetrySame { .. } => "retry-same",
                Command::Cancel { .. } => "cancel",
                _ => "reconcile",
            };
            remote(
                service,
                reqwest::Method::POST,
                &format!("/v1/runs/{run}/{action}"),
                Some(json!({"reason":reason})),
                None,
            )
            .await
        }
        Command::Doctor { service } => remote(service, reqwest::Method::GET, "/v1/doctor", None, None).await,
        Command::RestoreHold { reason, service } | Command::ReleaseRestoreHold { reason, service } => {
            remote(
                service,
                reqwest::Method::POST,
                if matches!(cli.command, Command::RestoreHold { .. }) {
                    "/v1/restore-hold"
                } else {
                    "/v1/release-restore-hold"
                },
                Some(json!({"reason":reason})),
                None,
            )
            .await
        }
        Command::ReleaseAdmissionHold { recovery_reference, admission_history_complete, prior_deployment_fenced, service } => remote(service,reqwest::Method::POST,"/v1/release-admission-hold",Some(json!({"recoveryReference":recovery_reference,"admissionHistoryComplete":admission_history_complete,"priorDeploymentFenced":prior_deployment_fenced})),None).await,
        Command::CompleteExecutionRecovery { recovery_reference, execution_history_complete, prior_deployment_fenced, service } => remote(service,reqwest::Method::POST,"/v1/complete-execution-recovery",Some(json!({"recoveryReference":recovery_reference,"executionHistoryComplete":execution_history_complete,"priorDeploymentFenced":prior_deployment_fenced})),None).await,
        Command::Retain { before, limit, service } => {
            remote(
                service,
                reqwest::Method::POST,
                "/v1/retention",
                Some(json!({"before":before,"limit":limit})),
                None,
            )
            .await
        }
    }
}

fn bounded_list_cursor(value: &str) -> std::result::Result<String, String> {
    if value.is_empty()
        || value.len() > 4096
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("cursor must be the bounded opaque value returned by the service".into());
    }
    Ok(value.to_owned())
}
/// The arguments only the commands that call the service take.
const SERVICE_ARGUMENTS: [&str; 2] = ["--url", "--token-file"];
/// Describe a command line clap refused by the argument it names, never by a
/// value the operator typed, and say what fixes that mistake.
fn usage(error: &clap::Error, arguments: &[String]) -> CoordinatorError {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let cli = Cli::command();
    let command = arguments
        .iter()
        .skip(1)
        .find_map(|argument| cli.find_subcommand(argument));
    let help = match command {
        Some(command) => format!("`coordinatorctl {} --help`", command.get_name()),
        None => "`coordinatorctl --help`".to_owned(),
    };
    let named = refused_arguments(error);
    let all = named.join(", ");
    let (message, action) = match (error.kind(), named.first()) {
        (ErrorKind::UnknownArgument, Some(name)) => match command {
            Some(command)
                if command
                    .get_arguments()
                    .any(|known| known.get_long() == name.strip_prefix("--")) =>
            {
                (
                    format!("{name} is written before the command"),
                    format!(
                        "Write {name} after {}, as {help} shows.",
                        command.get_name()
                    ),
                )
            }
            Some(command) if SERVICE_ARGUMENTS.contains(&name.as_str()) => (
                format!("{} does not take {name}", command.get_name()),
                format!("Remove {name}: {} calls no service.", command.get_name()),
            ),
            _ => (
                format!("unexpected argument {name}"),
                format!("Remove {name}; {help} lists the accepted arguments."),
            ),
        },
        (ErrorKind::MissingRequiredArgument, Some(_)) => (
            format!("missing required argument {all}"),
            format!("Add {all}; {help} describes it."),
        ),
        (ErrorKind::InvalidValue | ErrorKind::ValueValidation, Some(name)) => (
            format!("invalid value for {name}"),
            match error.get(ContextKind::ValidValue) {
                Some(ContextValue::Strings(values)) if !values.is_empty() => {
                    format!("Use one of {} for {name}.", values.join(", "))
                }
                _ => format!("Correct the value of {name}; {help} describes it."),
            },
        ),
        (ErrorKind::ArgumentConflict, Some(_)) => (
            format!("conflicting use of {all}"),
            format!("Keep only one of the conflicting arguments; {help} describes them."),
        ),
        (ErrorKind::InvalidSubcommand, _) => (
            "unrecognized command".to_owned(),
            match error.get(ContextKind::SuggestedSubcommand) {
                Some(ContextValue::Strings(names)) if !names.is_empty() => format!(
                    "Use `coordinatorctl {}`, or a command `coordinatorctl --help` lists.",
                    names[0]
                ),
                _ => "Use a command `coordinatorctl --help` lists.".to_owned(),
            },
        ),
        (ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand, _) => {
            (
                "missing command".to_owned(),
                "Name a command; `coordinatorctl --help` lists them.".to_owned(),
            )
        }
        _ => (
            "the command line is incomplete or contains an unsupported argument".to_owned(),
            format!("Run {help} for the accepted arguments."),
        ),
    };
    CoordinatorError::new("coordinator.cli.usage", message).suggest(action)
}
/// The argument names clap refused, without any value. An unknown argument
/// is the operator's own token, so it is named only when it has the shape of
/// a long option, and only up to any `=`.
fn refused_arguments(error: &clap::Error) -> Vec<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let names = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(name)) => vec![name.as_str()],
        Some(ContextValue::Strings(names)) => names.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    names
        .into_iter()
        .filter_map(|name| {
            if error.kind() == ErrorKind::UnknownArgument {
                let option = name.split('=').next()?;
                let flag = option.strip_prefix("--")?;
                let shaped = !flag.is_empty()
                    && flag.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    });
                shaped.then(|| option.to_owned())
            } else {
                name.split_whitespace().next().map(str::to_owned)
            }
        })
        .collect()
}
pub async fn run() -> std::process::ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return std::process::ExitCode::SUCCESS;
        }
        Err(error) => {
            let arguments = std::env::args().collect::<Vec<_>>();
            let error = usage(&error, &arguments);
            let json = arguments
                .windows(2)
                .any(|pair| pair == ["--format", "json"])
                || arguments.iter().any(|argument| argument == "--format=json");
            if json {
                write_report(false, "usage", failure_value(&error, 2));
            } else {
                eprint!("{}", error.report().render_human());
            }
            return std::process::ExitCode::from(2);
        }
    };
    match execute(&cli).await {
        Ok(value) => {
            let tested = matches!(cli.command, Command::Test { .. });
            let ok = !(tested && value["status"] == "failed");
            match cli.format {
                Format::Json if matches!(cli.command, Command::Openapi) => println!("{value}"),
                Format::Json => write_report(ok, cli.command.name(), value),
                Format::Human => {
                    if let Some(diagnostics) = value["diagnostics"].as_array() {
                        if !diagnostics.is_empty() {
                            if let Ok(diagnostics) =
                                serde_json::from_value(Value::Array(diagnostics.clone()))
                            {
                                eprint!(
                                    "{}",
                                    registry_platform_yaml::Report::new(diagnostics).render_human()
                                );
                            }
                        }
                    }
                    print!("{}", render_human(&cli, &value));
                }
            }
            if ok {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::from(1)
            }
        }
        Err(e) => {
            match cli.format {
                Format::Human => eprint!("{}", e.report().render_human()),
                Format::Json => {
                    write_report(false, cli.command.name(), failure_value(&e, e.exit_code))
                }
            }
            std::process::ExitCode::from(e.exit_code)
        }
    }
}

/// The default output: a few lines a person reads. `--format json` keeps
/// the full report, and the OpenAPI document stays JSON in both formats.
fn render_human(cli: &Cli, value: &Value) -> String {
    match &cli.command {
        Command::Init { .. } => {
            let project = text(&value["project"]);
            let mut out = format!("created: {project}\n");
            for file in value["created"].as_array().into_iter().flatten() {
                out.push_str(&format!("  {}\n", text(file)));
            }
            out.push_str(&format!("next: coordinatorctl test --project {project}\n"));
            out
        }
        Command::Check { .. } | Command::Explain { .. } if value["steps"].is_array() => {
            render_explain(value)
        }
        Command::Check { .. } => {
            let mut out = String::new();
            if let Some(workflow) = value["workflow"].as_str() {
                out.push_str(&format!(
                    "Valid workflow {workflow} version {}\nDefinition: {}\n",
                    text(&value["version"]),
                    text(&value["workflowRevision"])
                ));
            }
            if cli.runtime_config.is_some() {
                out.push_str("Valid runtime configuration\n");
            }
            out
        }
        Command::Test { .. } => {
            let mut out = String::new();
            for case in value["scenarios"].as_array().into_iter().flatten() {
                let verdict = if case["status"] == "passed" {
                    "PASS"
                } else {
                    "FAIL"
                };
                out.push_str(&format!("{verdict} {}\n", text(&case["name"])));
            }
            out.push_str(&format!(
                "{} passed, {} failed\n",
                value["passed"], value["failed"]
            ));
            out
        }
        Command::Package { .. } => format!(
            "created: {}\npackage digest: {}\n",
            text(&value["root"]),
            text(&value["packageDigest"])
        ),
        Command::Openapi => format!(
            "{}\n",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
        ),
        _ => serde_norway::to_string(value).unwrap_or_else(|_| format!("{value}\n")),
    }
}

/// One line per step in graph order from start, then the execution bounds.
fn render_explain(value: &Value) -> String {
    let listed = |values: &Value| {
        values
            .as_array()
            .into_iter()
            .flatten()
            .map(text)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = format!(
        "Workflow {} version {}\nDefinition: {}\nDeadline: {} seconds; outcomes: {}\nSteps from start:\n",
        text(&value["workflow"]),
        text(&value["version"]),
        text(&value["workflowRevision"]),
        value["deadlineSeconds"],
        listed(&value["outcomes"])
    );
    for step in value["steps"].as_array().into_iter().flatten() {
        let next = listed(&step["next"]);
        let line = match step["kind"].as_str().unwrap_or_default() {
            "wait-until" => format!("wait until {}, then {next}", mapping(&step["mapping"])),
            "wait-for" => format!(
                "wait for the {} of {}, at most {} seconds, then {}; on timeout {}; on cancel {}",
                text(&step["completion"]["name"]),
                text(&step["completion"]["step"]),
                step["timeoutSeconds"],
                text(&step["next"][0]),
                match step["onTimeout"].as_str() {
                    Some(target) => target.to_owned(),
                    None => "the run fails with wait-timed-out".to_owned(),
                },
                match step["onCancel"].as_str() {
                    Some(target) => target.to_owned(),
                    None => "the run stops with ordinary cancellation".to_owned(),
                },
            ),
            "call" => format!(
                "call {} {} ({} {}, recovery {}) with {}, then {next}",
                text(&step["connection"]),
                text(&step["operation"]),
                text(&step["product"]),
                text(&step["effect"]),
                text(&step["recovery"]),
                mapping(&step["mapping"])
            ),
            "choose" => format!(
                "choose by {}: {}",
                mapping(&step["mapping"]),
                step["cases"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(case, target)| format!("{case} -> {}", text(target)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ if step["mapping"].is_object() => format!(
                "finish {} with {}",
                text(&step["outcome"]),
                mapping(&step["mapping"])
            ),
            _ => format!("finish {}", text(&step["outcome"])),
        };
        out.push_str(&format!("  {}: {line}\n", text(&step["id"])));
    }
    let limits = value["limits"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(limit, bound)| format!("{limit} {bound}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("Function limits: {limits}\n"));
    out.push_str(&format!("Recovery: {}\n", text(&value["recovery"])));
    out
}

/// A step mapping as one phrase: `f(input, step a /b)`, `{m: input /n}` or
/// one reference.
fn mapping(value: &Value) -> String {
    if let Some(function) = value["function"].as_str() {
        let arguments = value["arguments"]
            .as_array()
            .into_iter()
            .flatten()
            .map(reference)
            .collect::<Vec<_>>();
        return format!("{function}({})", arguments.join(", "));
    }
    if let Some(fields) = value["fields"].as_object() {
        let members = fields
            .iter()
            .map(|(member, source)| format!("{member}: {}", reference(source)))
            .collect::<Vec<_>>();
        return format!("{{{}}}", members.join(", "));
    }
    reference(value)
}

fn reference(value: &Value) -> String {
    let path = value["path"]
        .as_str()
        .map(|path| format!(" {path}"))
        .unwrap_or_default();
    match value["type"].as_str() {
        Some("input") => format!("input{path}"),
        Some("step") => format!("step {}{path}", text(&value["step"])),
        _ => value["value"].to_string(),
    }
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn failure_value(error: &CoordinatorError, exit: u8) -> Value {
    json!({"status": match exit { 2 => "usage-error", 3 => "operational-failure", _ => "domain-refusal" }, "diagnostics":error.report().to_json_value()})
}

/// One report envelope for local commands and authenticated operation results.
pub fn write_report(ok: bool, command: &str, mut value: Value) {
    if !value.is_object() {
        value = json!({"result":value});
    }
    if value.get("diagnostics").is_none() {
        value["diagnostics"] = json!([]);
    }
    value["ok"] = json!(ok);
    value["command"] = json!(command);
    value["apiVersion"] = json!(CTL_REPORT_API_VERSION);
    value["kind"] = json!(CTL_REPORT_KIND);
    if value.get("status").is_none() {
        value["status"] = json!("completed");
    }
    println!("{value}");
}

/// Public command tree used by the supported CLI reference generator.
pub fn command() -> clap::Command {
    Cli::command()
}
