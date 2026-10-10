// SPDX-License-Identifier: Apache-2.0
//! Coordinator authoring, activation and authenticated operation.
use crate::{
    definition::Definition, deployment, http, project, runtime::RuntimeConfig, scenarios, PocError,
    Result,
};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
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
    #[arg(long, global = true, value_enum, default_value = "text")]
    /// Output format for local reports and authenticated API responses.
    format: Format,
    #[arg(long, global = true, value_name = "FILE")]
    /// Absolute runtime configuration file for binding checks and deployment commands.
    runtime_config: Option<PathBuf>,
    /// Authenticated Coordinator service origin, HTTPS or explicit loopback HTTP.
    #[arg(long, global = true)]
    url: Option<url::Url>,
    /// Absolute file containing a current access token. Token values are never printed.
    #[arg(long, global = true, value_name = "FILE")]
    token_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}
#[derive(Subcommand)]
enum Command {
    /// Create a reviewed three-file starter in a new directory.
    Init {
        #[arg(long)]
        /// New project directory; existing content is refused.
        directory: PathBuf,
    },
    /// Validate the workflow, functions and root YAML companions offline.
    Check {
        #[arg(long)]
        /// Directory containing workflow.yaml and functions.rhai.
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
        /// Directory containing workflow.yaml and functions.rhai.
        project: PathBuf,
    },
    /// Run deterministic scenarios with a virtual clock and fake products offline.
    Test {
        #[arg(long)]
        /// Directory containing workflow.yaml and functions.rhai.
        project: PathBuf,
        #[arg(long)]
        /// Scenario YAML file; defaults to scenarios.yaml in the project.
        scenarios: Option<PathBuf>,
    },
    /// Build a new immutable package; existing output is never overwritten.
    Package {
        #[arg(long)]
        /// Directory containing workflow.yaml and functions.rhai.
        project: PathBuf,
        #[arg(long)]
        /// New package directory; existing content is refused.
        output: PathBuf,
    },
    /// Inspect activation and schema using runtime credentials, without migrating.
    Plan,
    /// Apply the package and least-privileged runtime grants using migration credentials.
    Apply,
    /// Inspect deployed package identity and schema using runtime credentials.
    DeploymentStatus,
    /// Generate the authenticated service OpenAPI document offline.
    Openapi,
    /// Start one allowed flow with caller ownership and a stable admission key.
    Start {
        #[arg(long)]
        /// Allowed flow identifier from the activated workflow package.
        flow: String,
        #[arg(long)]
        /// JSON input file validated against the workflow input schema.
        input: PathBuf,
        #[arg(long)]
        /// UTF-8 file containing the stable admission key for this logical operation.
        key_file: PathBuf,
    },
    /// Read caller-owned or explicitly operator-authorized run progress.
    Status {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
    },
    /// List bounded run progress permitted by the current caller policy.
    List {
        #[arg(long,default_value_t=20,value_parser=clap::value_parser!(u32).range(1..=100))]
        /// Maximum number of records, from 1 through 100.
        limit: u32,
    },
    /// Inspect bounded durable step metadata without input or command payloads.
    Inspect {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
    },
    /// Retry only the original stored command identity under its recovery contract.
    RetrySame {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
    },
    /// Prevent future dispatch where possible and preserve unresolved effects.
    Cancel {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
    },
    /// Observe the receiving product using the original command key and owner.
    Reconcile {
        #[arg(long)]
        /// Durable run UUID returned by admission.
        run: Uuid,
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
    },
    /// Bounded operator diagnostics through authenticated HTTP.
    Doctor,
    /// Stop dispatch before a restore or recovery investigation.
    RestoreHold {
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
    },
    /// Release hold only after external fencing and authoritative reconciliation.
    ReleaseRestoreHold {
        #[arg(long)]
        /// Bounded investigation identifier without personal data.
        reason: String,
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
    },
    /// Erase eligible terminal payloads and preserve spent-key tombstones.
    Retain {
        #[arg(long)]
        /// Erase only eligible terminal payloads older than this RFC 3339 timestamp.
        before: chrono::DateTime<chrono::Utc>,
        #[arg(long,default_value_t=100,value_parser=clap::value_parser!(u32).range(1..=100))]
        /// Maximum number of records, from 1 through 100.
        limit: u32,
    },
}
impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Check { .. } => "check",
            Self::Explain { .. } => "explain",
            Self::Test { .. } => "test",
            Self::Package { .. } => "package",
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::DeploymentStatus => "deployment-status",
            Self::Openapi => "openapi",
            Self::Start { .. } => "start",
            Self::Status { .. } => "status",
            Self::List { .. } => "list",
            Self::Inspect { .. } => "inspect",
            Self::RetrySame { .. } => "retry-same",
            Self::Cancel { .. } => "cancel",
            Self::Reconcile { .. } => "reconcile",
            Self::Doctor => "doctor",
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
        return Err(PocError::new(
            "coordinator.command.usage",
            "check requires a project or runtime configuration",
        )
        .suggest("Supply --project DIRECTORY, --runtime-config FILE, or both.")
        .with_exit(2));
    }
    let mut report = Report::default();
    let mut exit_code = 1;
    let definition = project.and_then(|path| match Definition::load(path) {
        Ok(definition) => Some(definition),
        Err(error) => {
            exit_code = exit_code.max(error.exit_code);
            report.extend(error.report());
            None
        }
    });
    if let Some(path) = runtime {
        let (findings, runtime_exit) =
            crate::project_check::check_runtime(path, definition.as_ref(), environment);
        report.extend(findings);
        exit_code = exit_code.max(runtime_exit);
    }
    if let Some(path) = project {
        let (findings, project_exit) =
            crate::project_check::check_directory(path, definition.as_ref(), runtime, environment);
        report.extend(findings);
        exit_code = exit_code.max(project_exit);
    }
    if report.has_errors() || (deny_warnings && report.warning_count() > 0) {
        return Err(PocError::from_report(report).with_exit(exit_code));
    }
    let mut result = match definition {
        Some(definition) if explain => definition.explain()?,
        Some(definition) => {
            json!({"status":"valid","workflow":definition.workflow.id,"version":definition.workflow.version,"definitionDigest":definition.digest,"steps":definition.workflow.steps.len()})
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
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(maximum as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| {
            PocError::new(
                "coordinator.command.input-invalid",
                "cannot read bounded local input",
            )
        })?;
    if bytes.len() > maximum {
        return Err(PocError::new(
            "coordinator.command.input-invalid",
            "local input exceeds its bound",
        ));
    }
    Ok(bytes)
}
fn text_file(path: &Path, maximum: usize) -> Result<String> {
    String::from_utf8(read(path, maximum)?)
        .map(|s| s.trim_end_matches(['\r', '\n']).into())
        .map_err(|_| {
            PocError::new(
                "coordinator.command.input-invalid",
                "supply bounded UTF-8 text",
            )
        })
}
fn runtime(cli: &Cli) -> Result<RuntimeConfig> {
    RuntimeConfig::load(cli.runtime_config.as_deref().ok_or_else(|| {
        PocError::new(
            "coordinator.command.runtime-config-required",
            "supply --runtime-config FILE",
        )
    })?)
}
async fn remote(
    cli: &Cli,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
    key: Option<&str>,
) -> Result<Value> {
    let mut url = cli.url.clone().ok_or_else(|| {
        PocError::new(
            "coordinator.command.service-required",
            "supply --url with the authenticated Coordinator origin",
        )
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
        return Err(PocError::new(
            "coordinator.command.service-invalid",
            "use an HTTPS origin or explicit loopback HTTP origin",
        ));
    }
    let token_path = cli
        .token_file
        .as_deref()
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            PocError::new(
                "coordinator.command.token-file-required",
                "supply an absolute --token-file with a current access token",
            )
        })?;
    let token = zeroize::Zeroizing::new(text_file(token_path, 16_384)?);
    registry_platform_authcommon::validate_compact_access_token(&token).map_err(|_| {
        PocError::new(
            "coordinator.command.token-invalid",
            "the token file must contain one compact access token",
        )
    })?;
    url.set_path(path.split('?').next().unwrap_or(path));
    url.set_query(path.split_once('?').map(|(_, q)| q));
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| {
            PocError::new(
                "coordinator.command.service-unavailable",
                "cannot initialize the HTTP client",
            )
        })?;
    let mut request = client.request(method, url).bearer_auth(token.as_str());
    if let Some(body) = body {
        request = request.json(&body);
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = request.send().await.map_err(|_| {
        PocError::new(
            "coordinator.command.service-unavailable",
            "the service could not answer; inspect the original run before retrying",
        )
    })?;
    let status = response.status();
    let bytes = registry_platform_httputil::read_bounded(response, 1_048_576)
        .await
        .map_err(|_| {
            PocError::new(
                "coordinator.command.service-unavailable",
                "the service response exceeded its bound",
            )
        })?;
    let value = registry_platform_canonical_json::parse_json_strict(&bytes).map_err(|_| {
        PocError::new(
            "coordinator.command.service-unavailable",
            "the service response was not bounded JSON",
        )
    })?;
    if !status.is_success() {
        let (code, message, action) = if status.is_server_error() {
            (
                "coordinator.command.service-unavailable",
                "the service could not complete the operation",
                "restore service availability and inspect the original run before attempting same-command recovery",
            )
        } else {
            (
                "coordinator.command.service-refused",
                "the authenticated service refused the operation",
                "inspect caller policy and current run status before repeating the operation",
            )
        };
        return Err(PocError::new(
            code,
            value["message"]
                .as_str()
                .filter(|text| text.len() <= 256)
                .unwrap_or(message),
        )
        .suggest(value["suggestedAction"].as_str().unwrap_or(action)));
    }
    Ok(value)
}
async fn execute(cli: &Cli) -> Result<Value> {
    match &cli.command {
        Command::Init { directory } => {
            project::init(directory)?;
            Ok(json!({"status":"initialized","project":directory}))
        }
        Command::Check { project, explain, deny_warnings, environment } => check(project.as_deref(), cli.runtime_config.as_deref(), *explain, *deny_warnings, *environment),
        Command::Explain { project } => check(Some(project), cli.runtime_config.as_deref(), true, false, false),
        Command::Test {
            project,
            scenarios: path,
        } => {
            let d = Definition::load(project)?;
            let path = path
                .clone()
                .unwrap_or_else(|| project.join("scenarios.yaml"));
            let document = scenarios::load(&path)?;
            Ok(json!({"scenarios":scenarios::check(&d,&document)?}))
        }
        Command::Package { project, output } => {
            Ok(json!({"packageDigest":deployment::package(project,output)?,"root":output}))
        }
        Command::Plan | Command::Apply => {
            let r = runtime(cli)?;
            let p = deployment::load_package(deployment::config(&r)?)?;
            let store = deployment::open_ctl(&r, matches!(cli.command, Command::Apply)).await?;
            if matches!(cli.command, Command::Apply) {
                serde_json::to_value(deployment::apply(&store, &r, &p).await?)
                    .map_err(|_| PocError::new("coordinator.command.output-unavailable", "cannot encode activation"))
            } else {
                deployment::plan(&store, &r, &p.digest).await
            }
        }
        Command::DeploymentStatus => {
            let r = runtime(cli)?;
            let p = deployment::load_package(deployment::config(&r)?)?;
            r.validate_workflow(&p.definition.workflow)?;
            let store = deployment::open_ctl(&r, false).await?;
            let active = deployment::check_serving(&store, &r, &p.digest).await?;
            let d = deployment::config(&r)?;
            Ok(json!({"status":"checked","databaseId":d.database_id,"packageDigest":p.digest,"schemaVersion":crate::store::SCHEMA_VERSION,"runtimeRole":d.runtime_role,"active":active}))
        }
        Command::Openapi => Ok(http::openapi()),
        Command::Start {
            flow,
            input,
            key_file,
        } => {
            let input = registry_platform_canonical_json::parse_json_strict(&read(input, 65_536)?)
                .map_err(|_| PocError::new("coordinator.command.input-invalid", "input must be unambiguous JSON"))?;
            let key = text_file(key_file, 256)?;
            remote(
                cli,
                reqwest::Method::POST,
                "/v1/runs",
                Some(json!({"flow":flow,"input":input})),
                Some(&key),
            )
            .await
        }
        Command::Status { run } => {
            remote(
                cli,
                reqwest::Method::GET,
                &format!("/v1/runs/{run}"),
                None,
                None,
            )
            .await
        }
        Command::List { limit } => {
            remote(
                cli,
                reqwest::Method::GET,
                &format!("/v1/runs?limit={limit}"),
                None,
                None,
            )
            .await
        }
        Command::Inspect { run } => {
            remote(
                cli,
                reqwest::Method::GET,
                &format!("/v1/runs/{run}/inspect"),
                None,
                None,
            )
            .await
        }
        Command::RetrySame { run, reason }
        | Command::Cancel { run, reason }
        | Command::Reconcile { run, reason } => {
            let action = match cli.command {
                Command::RetrySame { .. } => "retry-same",
                Command::Cancel { .. } => "cancel",
                _ => "reconcile",
            };
            remote(
                cli,
                reqwest::Method::POST,
                &format!("/v1/runs/{run}/{action}"),
                Some(json!({"reason":reason})),
                None,
            )
            .await
        }
        Command::Doctor => remote(cli, reqwest::Method::GET, "/v1/doctor", None, None).await,
        Command::RestoreHold { reason } | Command::ReleaseRestoreHold { reason } => {
            remote(
                cli,
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
        Command::ReleaseAdmissionHold { recovery_reference, admission_history_complete, prior_deployment_fenced } => remote(cli,reqwest::Method::POST,"/v1/release-admission-hold",Some(json!({"recoveryReference":recovery_reference,"admissionHistoryComplete":admission_history_complete,"priorDeploymentFenced":prior_deployment_fenced})),None).await,
        Command::CompleteExecutionRecovery { recovery_reference, execution_history_complete, prior_deployment_fenced } => remote(cli,reqwest::Method::POST,"/v1/complete-execution-recovery",Some(json!({"recoveryReference":recovery_reference,"executionHistoryComplete":execution_history_complete,"priorDeploymentFenced":prior_deployment_fenced})),None).await,
        Command::Retain { before, limit } => {
            remote(
                cli,
                reqwest::Method::POST,
                "/v1/retention",
                Some(json!({"before":before,"limit":limit})),
                None,
            )
            .await
        }
    }
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
        Err(_) => {
            let error = PocError::new("coordinator.cli.usage", "the command line is incomplete or contains an unsupported argument")
                .suggest("Run coordinatorctl --help or coordinatorctl COMMAND --help for accepted arguments.");
            let arguments = std::env::args().collect::<Vec<_>>();
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
            match cli.format {
                Format::Json if matches!(cli.command, Command::Openapi) => println!("{value}"),
                Format::Json => write_report(true, cli.command.name(), value),
                Format::Text => {
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
                    if value["status"] == "valid" && value["workflow"].is_string() {
                        println!(
                            "Valid workflow {} version {}\nDefinition: {}",
                            value["workflow"].as_str().unwrap_or_default(),
                            value["version"].as_str().unwrap_or_default(),
                            value["definitionDigest"].as_str().unwrap_or_default()
                        );
                    } else {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&value).unwrap_or_default()
                        );
                    }
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            match cli.format {
                Format::Text => eprint!("{}", e.report().render_human()),
                Format::Json => {
                    write_report(false, cli.command.name(), failure_value(&e, e.exit_code))
                }
            }
            std::process::ExitCode::from(e.exit_code)
        }
    }
}

fn failure_value(error: &PocError, exit: u8) -> Value {
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
