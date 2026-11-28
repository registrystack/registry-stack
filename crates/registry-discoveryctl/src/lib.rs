// SPDX-License-Identifier: Apache-2.0
//! Finite Registry Discovery authoring and immutable index packages.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitCode};

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_platform_config::{declared_from, PostureReport, POSTURE_ENV};
pub use registry_platform_config::{DeclaredPosture, Posture, PostureSource};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};

mod build;
mod index;
mod project;
mod report;
#[cfg(feature = "schema")]
pub mod schema;
mod selected_binary;

/// Build identity for the independently versioned Discovery product.
pub mod build_info {
    include!(concat!(env!("OUT_DIR"), "/product_build_info.rs"));
}

pub use build::{package_project, package_project_at, BuildError, PackagedDiscovery};
pub use index::{inspect_index_file, IndexReport};
pub use project::{
    check_project, inspect_project, inspect_runtime_file, ApprovedOrigin, AuthoredEvidenceMapping,
    AuthoredEvidenceTypeAlternative, CheckedProject, OriginProfile, OriginsFile, ProjectError,
    ProjectOptions, ProjectReport, MAPPINGS_DIRECTORY, MAPPING_API_VERSION, MAPPING_KIND,
    ORIGINS_API_VERSION, ORIGINS_FILE, ORIGINS_KIND,
};

/// The `apiVersion` every `--format json` report carries.
pub const CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/discovery/ctl-report/v1alpha1";
/// The `kind` every `--format json` report carries.
pub const CTL_REPORT_KIND: &str = "DiscoveryCtlReport";

#[derive(Debug, Parser)]
#[command(
    name = "discoveryctl",
    about = "Check and package one immutable Registry Discovery index",
    version = build_info::DISPLAY_VERSION
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

/// The clap command tree, for the generated CLI reference.
#[must_use]
pub fn command() -> clap::Command {
    Arguments::command()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    /// Diagnostics with their position first, then a summary line.
    #[default]
    Human,
    /// One JSON report on standard output.
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write a local Discovery starter and its development plan.
    Init {
        /// New directory to create.
        directory: PathBuf,
    },
    #[command(name = registry_rstack_dev::COMMAND, hide = true)]
    RstackDev(registry_rstack_dev::Args),
    /// Send one raw HTTP request to a Discovery endpoint.
    Api(Box<registry_cli_api::ApiArgs>),
    /// Manage named Discovery API connections.
    Connection {
        /// Write human-readable diagnostics or one JSON report for connection check.
        #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        #[command(subcommand)]
        command: registry_cli_api::ConnectionCommand,
    },
    /// Run the Discovery service with the selected runtime configuration.
    Serve(ServeArgs),
    /// Check an authoring project, a runtime file, or an index without
    /// network I/O.
    #[command(group(
        ArgGroup::new("input")
            .required(true)
            .multiple(true)
            .args(["project", "runtime_config", "index"])
    ))]
    Check {
        /// The authoring project directory: origins.yaml, the mappings
        /// directory, and every runtime file beside them.
        #[arg(long, value_name = "DIRECTORY")]
        project: Option<PathBuf>,
        /// Runtime configuration file, checked on its own.
        #[arg(long, value_name = "FILE")]
        runtime_config: Option<PathBuf>,
        /// One index file, as `discoveryctl package` wrote it, checked on
        /// its own exactly as `discovery --runtime-config` parses it at startup.
        #[arg(long, value_name = "FILE")]
        index: Option<PathBuf>,
        /// Declared posture: development or production. Unset means production.
        #[arg(long = "posture", value_name = "POSTURE")]
        posture: Option<String>,
        /// Check under the production posture.
        #[arg(long)]
        production: bool,
        /// Fill the runtime file's ${NAME} expressions from this process's
        /// environment and check the values they produce.
        #[arg(long)]
        environment: bool,
        /// Write human-readable diagnostics or one JSON report.
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
        /// Exit 1 when the check reports a warning.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Fetch every enabled approved origin once and write one immutable package.
    Package {
        /// The authoring project directory: origins.yaml, the mappings
        /// directory, and every runtime file beside them.
        #[arg(long, value_name = "DIRECTORY")]
        project: PathBuf,
        /// The new directory the package is written to.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
        /// Declared posture: development or production. Unset means production.
        #[arg(long = "posture", value_name = "POSTURE")]
        posture: Option<String>,
        /// Optional operator revision recorded in the package envelope.
        #[arg(long)]
        revision: Option<String>,
    },
    /// Removed. Use `discoveryctl package`.
    #[command(hide = true, trailing_var_arg = true)]
    Build {
        #[arg(allow_hyphen_values = true)]
        _legacy_arguments: Vec<OsString>,
    },
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Runtime configuration file passed unchanged to the Discovery runtime.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Declared posture: development or production. Unset means production.
    #[arg(long = "posture", value_name = "POSTURE")]
    posture: Option<String>,

    /// Discovery runtime executable for an unmanaged installation.
    #[arg(long, hide = true, env = "DISCOVERY_BIN", value_name = "BINARY")]
    discovery_bin: Option<PathBuf>,
}

const RETIRED_BUILD_ERROR: &str =
    "discoveryctl build was removed; use discoveryctl package with a new output directory";
const DOMAIN_REFUSAL_EXIT: u8 = 1;
const USAGE_CODE: &str = "discovery.usage.invalid-arguments";
/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run discoveryctl --help, or the command with --help, and retry with the documented arguments.";

#[must_use]
pub fn main_entry() -> ExitCode {
    registry_cli_report::install_panic_hook(
        registry_cli_report::Identity {
            binary: "discoveryctl",
            api_version: CTL_REPORT_API_VERSION,
            kind: CTL_REPORT_KIND,
            version: build_info::DISPLAY_VERSION,
        },
        registry_cli_report::json_requested(std::env::args_os()),
    );
    main_entry_from(
        std::env::args_os(),
        std::env::var_os(POSTURE_ENV).as_deref(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

fn main_entry_from<I, T>(
    args: I,
    posture_environment: Option<&OsStr>,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let machine = args
        .windows(2)
        .any(|pair| pair[0] == OsStr::new("--format") && pair[1] == OsStr::new("json"))
        || args.iter().any(|arg| arg == OsStr::new("--format=json"));
    let arguments = match Arguments::try_parse_from(args) {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = write!(stdout, "{error}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            let usage =
                Diagnostic::error(USAGE_CODE, "", report::usage_message(&error), USAGE_ACTION);
            if machine {
                let _ = report::write(
                    &envelope("usage", report::USAGE_EXIT, json!({"diagnostics": [usage]})),
                    None,
                    stdout,
                );
            } else {
                let _ = write!(stderr, "{}", usage.render_human());
            }
            return ExitCode::from(report::USAGE_EXIT);
        }
    };
    let posture = match &arguments.command {
        Command::Check {
            posture,
            production,
            ..
        } => {
            if *production && posture.as_deref() == Some("development") {
                return posture_usage(
                    "platform.posture.conflict",
                    "--production and --posture development contradict each other",
                    "Use one of them.",
                    machine,
                    stdout,
                    stderr,
                );
            }
            Some(declared_from(
                posture.as_deref().or(production.then_some("production")),
                posture_environment,
            ))
        }
        Command::Package { posture, .. } | Command::Serve(ServeArgs { posture, .. }) => {
            Some(declared_from(posture.as_deref(), posture_environment))
        }
        _ => None,
    };
    let posture = match posture.transpose() {
        Ok(posture) => posture,
        Err(error) => {
            return posture_usage(
                error.code(),
                error.message(),
                error.suggested_action(),
                machine,
                stdout,
                stderr,
            )
        }
    };
    match arguments.command {
        Command::Api(args) => api_command(registry_cli_api::run_api("discovery", *args), stderr),
        Command::Connection { command, format } => {
            if let registry_cli_api::ConnectionCommand::Check(args) = &command {
                return match registry_cli_api::run_connection_check(
                    &args.file,
                    matches!(format, OutputFormat::Json),
                    args.deny_warnings,
                ) {
                    Ok(code) => ExitCode::from(code),
                    Err(error) => {
                        let _ = writeln!(stderr, "error: {error}");
                        ExitCode::from(error.exit_code())
                    }
                };
            }
            if matches!(format, OutputFormat::Json) {
                let _ = writeln!(
                    stderr,
                    "error: --format json is supported only by connection check"
                );
                return ExitCode::from(report::USAGE_EXIT);
            }
            api_command(
                registry_cli_api::run_connection("discovery", command),
                stderr,
            )
        }
        Command::RstackDev(args) => registry_rstack_dev::run(args, stdout, stderr),
        Command::Serve(args) => serve(args, stderr),
        Command::Check {
            project,
            runtime_config,
            index,
            environment,
            format,
            deny_warnings,
            ..
        } => check(
            &CheckRequest {
                project,
                runtime_config,
                index,
                options: ProjectOptions {
                    declared: posture.expect("check resolves posture"),
                    environment,
                },
                format,
                deny_warnings,
            },
            stdout,
            stderr,
        ),
        command => match run(command, posture) {
            Ok((line, diagnostics)) => {
                let _ = writeln!(stdout, "{line}");
                for diagnostic in diagnostics {
                    let _ = write!(stdout, "{}", diagnostic.render_human());
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                let _ = writeln!(stderr, "{error}");
                ExitCode::from(DOMAIN_REFUSAL_EXIT)
            }
        },
    }
}

fn posture_usage(
    code: &str,
    message: &str,
    action: &str,
    machine: bool,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let usage = Diagnostic::error(code, "", message, action);
    if machine {
        let _ = report::write(
            &envelope("usage", report::USAGE_EXIT, json!({"diagnostics": [usage]})),
            None,
            stdout,
        );
    } else {
        let _ = write!(stderr, "{}", usage.render_human());
    }
    ExitCode::from(report::USAGE_EXIT)
}

fn api_command(
    result: Result<(), registry_cli_api::ApiError>,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(stderr, "error: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

struct CheckRequest {
    project: Option<PathBuf>,
    runtime_config: Option<PathBuf>,
    index: Option<PathBuf>,
    options: ProjectOptions,
    format: OutputFormat,
    deny_warnings: bool,
}

/// Run `discoveryctl check` and report every finding (CFG-CHECK-1,
/// CFG-DIAG-4): exit 0 when nothing was refused, 1 when something was or a
/// warning was reported under `--deny-warnings`, and 3 when an input could
/// not be read.
fn check(
    request: &CheckRequest,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    let mut diagnostics = Vec::new();
    let mut files = 0;
    let mut unavailable = false;
    let mut counts = None;
    if let Some(root) = &request.project {
        let inspected = inspect_project(root, request.options);
        unavailable |= inspected.unavailable;
        files += inspected.report.files_checked().unwrap_or(0);
        counts = inspected
            .project
            .as_ref()
            .map(|project| (project.origins.len(), project.mappings.len()));
        diagnostics.extend(inspected.report.into_diagnostics());
    }
    if let Some(path) = &request.runtime_config {
        let (checked, missing) =
            inspect_runtime_file(path, request.options.environment, request.options.declared);
        unavailable |= missing;
        files += checked.files_checked().unwrap_or(0);
        diagnostics.extend(checked.into_diagnostics());
    }
    let mut index = None;
    if let Some(path) = &request.index {
        let checked = inspect_index_file(path);
        unavailable |= checked.unavailable;
        files += checked.report.files_checked().unwrap_or(0);
        index = checked.index;
        if let Some(index) = &index {
            let mut posture = PostureReport::new(request.options.declared);
            registry_discovery::record_index_posture(index, &mut posture, |host| {
                registry_platform_httputil::loopback::loopback_host(host).is_some()
            });
            diagnostics.extend(posture.diagnostics(path));
        }
        diagnostics.extend(checked.report.into_diagnostics());
    }
    let mut report = Report::new(diagnostics);
    report.set_files_checked(files);
    if let Some(root) = &request.project {
        registry_platform_config::apply_check_acceptances(root, &mut report);
        files = report.files_checked().unwrap_or(files);
    }
    let exit = if unavailable {
        report::OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors() || (request.deny_warnings && report.warning_count() > 0) {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    };

    if request.format == OutputFormat::Json {
        let mut body = json!({
            "filesChecked": files,
            "errors": report.error_count(),
            "warnings": report.warning_count(),
            "diagnostics": report.to_json_value(),
        });
        if let Some((origins, mappings)) = counts {
            body["origins"] = json!(origins);
            body["mappings"] = json!(mappings);
        }
        if let Some(index) = &index {
            body["index"] = json!({
                "origins": index.origins.len(),
                "services": index.services.len(),
                "mappings": index.mappings.len(),
                "catalogRevision": index.catalog_revision,
                "mappingRevision": index.mapping_revision,
            });
        }
        let _ = report::write(
            &envelope("check", exit, body),
            Some(request.options.declared),
            stdout,
        );
    } else if exit == 0 {
        if let Some((origins, mappings)) = counts {
            let _ = writeln!(stdout, "valid origins={origins} mappings={mappings}");
        }
        if let Some(index) = &index {
            let _ = writeln!(
                stdout,
                "valid index origins={} services={} mappings={} catalogRevision={} \
                 mappingRevision={}",
                index.origins.len(),
                index.services.len(),
                index.mappings.len(),
                index.catalog_revision,
                index.mapping_revision
            );
        }
        let _ = write!(stdout, "{}", report.render_human());
    } else {
        let sentence = if exit == report::OPERATIONAL_FAILURE_EXIT {
            "discoveryctl check could not read all of its input."
        } else {
            "discoveryctl check refused the input."
        };
        let _ = write!(stderr, "{sentence}\n{}", report.render_human());
    }
    ExitCode::from(exit)
}

/// Complete a command's report into the shared ctl envelope: `ok` agrees
/// with the exit code, `command` names the command, and `status` names what
/// happened.
fn envelope(command: &str, exit: u8, mut body: Value) -> Value {
    body["ok"] = json!(exit == 0);
    body["command"] = json!(command);
    body["status"] = json!(if exit == 0 {
        "complete"
    } else {
        report::failure_status(exit)
    });
    body["apiVersion"] = json!(CTL_REPORT_API_VERSION);
    body["kind"] = json!(CTL_REPORT_KIND);
    body
}

fn run(
    command: Command,
    declared: Option<DeclaredPosture>,
) -> Result<(String, Vec<Diagnostic>), String> {
    match command {
        Command::Init { directory } => {
            registry_rstack_dev::write_starter(&directory, &[
                ("origins.yaml", include_bytes!("../../../products/discovery/examples/starter/origins.yaml")),
                ("mappings/adult-status.yaml", include_bytes!("../../../products/discovery/examples/starter/mappings/adult-status.yaml")),
                ("dev.yaml", include_bytes!("../../../products/discovery/examples/starter/dev.yaml")),
                ("dev-scenarios.yaml", include_bytes!("../../../products/discovery/examples/starter/dev-scenarios.yaml")),
            ]).map_err(|error| format!("discoveryctl init: {error:#}"))?;
            Ok((
                format!("Next: rstack dev start {}", directory.display()),
                vec![],
            ))
        }
        Command::Api(_) | Command::Connection { .. } => {
            unreachable!("API commands handle their output before report dispatch")
        }
        Command::RstackDev(_) => unreachable!("development runner handles its own output"),
        Command::Serve(_) => unreachable!("serve replaces the ctl process before report dispatch"),
        Command::Check { .. } => unreachable!("check reports through its own path"),
        Command::Package {
            project,
            output,
            revision,
            ..
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "the Discovery package runtime could not start".to_owned())
            .and_then(|runtime| {
                runtime
                    .block_on(package_project(
                        &project,
                        &output,
                        declared.expect("package resolves posture"),
                        revision.as_deref(),
                    ))
                    .map(|package| {
                        let line = format!(
                            "packaged packageDigest={} catalogRevision={} mappingRevision={}",
                            package.package_digest,
                            package.index.catalog_revision,
                            package.index.mapping_revision
                        );
                        (line, package.posture_diagnostics)
                    })
                    .map_err(|error| error.to_string())
            }),
        Command::Build { .. } => Err(RETIRED_BUILD_ERROR.to_owned()),
    }
}

fn serve(args: ServeArgs, stderr: &mut dyn io::Write) -> ExitCode {
    let binary = match selected_binary::resolve_managed(
        selected_binary::DISCOVERY,
        args.discovery_bin.as_deref(),
    ) {
        Ok(Some(binary)) => binary,
        Ok(None) => args
            .discovery_bin
            .unwrap_or_else(|| PathBuf::from("discovery")),
        Err(error) => {
            let _ = writeln!(
                stderr,
                "discoveryctl serve could not select discovery: {error}"
            );
            return ExitCode::from(report::OPERATIONAL_FAILURE_EXIT);
        }
    };
    let mut command = ProcessCommand::new(binary);
    command.arg("--runtime-config").arg(args.runtime_config);
    if let Some(posture) = args.posture {
        command.args(["--posture", &posture]);
    }
    replace_with_service(command, "discovery", stderr)
}

#[cfg(unix)]
fn replace_with_service(
    mut command: ProcessCommand,
    name: &str,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    use std::os::unix::process::CommandExt as _;

    let error = command.exec();
    let _ = writeln!(stderr, "discoveryctl serve could not start {name}: {error}");
    ExitCode::from(report::OPERATIONAL_FAILURE_EXIT)
}

#[cfg(not(unix))]
fn replace_with_service(
    mut command: ProcessCommand,
    name: &str,
    stderr: &mut dyn io::Write,
) -> ExitCode {
    match command.status() {
        Ok(status) => ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(report::OPERATIONAL_FAILURE_EXIT),
        ),
        Err(error) => {
            let _ = writeln!(stderr, "discoveryctl serve could not start {name}: {error}");
            ExitCode::from(report::OPERATIONAL_FAILURE_EXIT)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/discovery/fixtures/project"
    );

    /// Run discoveryctl with `args` and return its exit code, standard
    /// output, and standard error.
    fn run_cli(args: &[&str]) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = main_entry_from(
            std::iter::once("discoveryctl").chain(args.iter().copied()),
            None,
            &mut stdout,
            &mut stderr,
        );
        (
            exit,
            String::from_utf8(stdout).expect("utf-8 output"),
            String::from_utf8(stderr).expect("utf-8 errors"),
        )
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("one JSON report")
    }

    /// A temporary directory named by its resolved path: the runtime loader
    /// refuses a path through a symbolic link, and macOS reaches its
    /// temporary directory through one.
    fn temporary() -> TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(base)
                .expect("temporary directory")
        }
        #[cfg(not(unix))]
        {
            TempDir::new_in(base).expect("temporary directory")
        }
    }

    /// A copy of the shipped fixture project with `edit` applied.
    fn fixture_copy(edit: impl FnOnce(&Path)) -> TempDir {
        let root = temporary();
        fs::copy(
            Path::new(FIXTURE).join("origins.yaml"),
            root.path().join("origins.yaml"),
        )
        .expect("origins");
        fs::create_dir(root.path().join("mappings")).expect("mappings");
        fs::copy(
            Path::new(FIXTURE).join("mappings/adult-status.yaml"),
            root.path().join("mappings/adult-status.yaml"),
        )
        .expect("mapping");
        edit(root.path());
        root
    }

    fn copy_runtime(root: &Path) {
        fs::copy(
            Path::new(FIXTURE).join("runtime.yaml"),
            root.join("runtime.yaml"),
        )
        .expect("runtime");
    }

    #[test]
    fn cfg_diag_1_a_clean_check_reports_json_in_the_ctl_envelope() {
        let fixture = fixture_copy(copy_runtime);
        let root = fixture.path().to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--project", root, "--format", "json"]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        assert!(stderr.is_empty(), "{stderr}");
        assert!(
            stdout.starts_with(
                "{\n  \"ok\": true,\n  \"command\": \"check\",\n  \"status\": \"complete\""
            ),
            "{stdout}"
        );
        let report = json(&stdout);
        assert_eq!(report["apiVersion"], CTL_REPORT_API_VERSION);
        assert_eq!(report["kind"], CTL_REPORT_KIND);
        assert_eq!(report["filesChecked"], 3);
        assert_eq!(report["errors"], 0);
        assert_eq!(report["warnings"], 0);
        assert_eq!(report["origins"], 1);
        assert_eq!(report["mappings"], 1);
        assert_eq!(report["diagnostics"], json!([]));
    }

    /// The registered example of the report format (CFG-SCHEMA-1) is this
    /// command's own output.
    #[test]
    fn cfg_schema_1_the_report_example_is_the_check_output() {
        let fixture = fixture_copy(copy_runtime);
        let root = fixture.path().to_str().unwrap();
        let example = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/discovery/fixtures/ctl-report/check.json"
        );
        let (exit, stdout, _) = run_cli(&["check", "--project", root, "--format", "json"]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}");
        let committed = fs::read_to_string(example).expect("the report example");
        let sample: Value = serde_json::from_str(&committed).expect("the report example parses");
        let sample_version = sample["version"]
            .as_str()
            .filter(|version| !version.is_empty())
            .expect("the report example carries a displayed binary version");
        let actual_version = format!(
            "  \"version\": {},\n",
            serde_json::to_string(build_info::DISPLAY_VERSION).unwrap()
        );
        assert_eq!(stdout.matches(&actual_version).count(), 1, "{stdout}");
        let sample_version = format!(
            "  \"version\": {},\n",
            serde_json::to_string(sample_version).unwrap()
        );
        let normalized = stdout.replacen(&actual_version, &sample_version, 1);
        assert_eq!(
            committed, normalized,
            "regenerate it with `discoveryctl check --project \
             products/discovery/fixtures/project --format json`"
        );
    }

    #[test]
    fn cfg_diag_2_a_clean_check_prints_the_counts_and_the_summary() {
        let fixture = fixture_copy(copy_runtime);
        let root = fixture.path().to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--project", root]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        assert_eq!(
            stdout,
            "valid origins=1 mappings=1\n0 errors, 0 warnings in 3 files\n"
        );
        assert!(stderr.is_empty(), "{stderr}");
    }

    #[test]
    fn cfg_diag_2_a_refusal_prints_the_reader_diagnostics_unchanged_after_one_sentence() {
        let root = fixture_copy(|root| {
            fs::write(
                root.join("mappings/adult-status.yaml"),
                "apiVersion: id.registrystack.org/formats/discovery/evidence-mapping/v1alpha1\nkind: DiscoveryEvidenceMapping\nsurprise: true\n",
            )
            .unwrap();
        });
        let project = root.path().to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--project", project]);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty(), "{stdout}");
        let inspected = inspect_project(root.path(), ProjectOptions::default());
        assert_eq!(
            stderr,
            format!(
                "discoveryctl check refused the input.\n{}",
                inspected.report.render_human()
            )
        );
        let mapping = root.path().join("mappings/adult-status.yaml");
        assert!(
            stderr.contains(&format!(
                "error[config.unknown-key] {}:3:1 /surprise",
                mapping.display()
            )),
            "{stderr}"
        );

        let (exit, stdout, _) = run_cli(&["check", "--project", project, "--format", "json"]);
        assert_eq!(exit, ExitCode::from(1));
        let report = json(&stdout);
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["diagnostics"], inspected.report.to_json_value());
        let unknown = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["code"] == "config.unknown-key")
            .expect("the unknown key is reported");
        assert_eq!(unknown["path"], "/surprise");
        assert_eq!(unknown["source"]["line"], 3);
        assert_eq!(unknown["source"]["column"], 1);
        assert!(unknown["suggestedAction"].is_string());
    }

    #[test]
    fn project_check_acceptance_keeps_the_warning_and_allows_the_warning_gate() {
        let root = fixture_copy(|root| {
            fs::write(root.join("notes.yaml"), "title: Project notes\n").unwrap();
        });
        let args = [
            "check",
            "--project",
            root.path().to_str().unwrap(),
            "--format",
            "json",
            "--deny-warnings",
        ];
        let (exit, stdout, _) = run_cli(&args);
        assert_eq!(exit, ExitCode::from(1));
        let before = json(&stdout);
        let files_before_acceptance = before["filesChecked"].as_u64().unwrap();
        let warning = &before["diagnostics"][0];
        let acceptance = serde_json::json!({
            "apiVersion": registry_platform_yaml::CHECK_ACCEPTANCES_API_VERSION,
            "kind": registry_platform_yaml::CHECK_ACCEPTANCES_KIND,
            "acceptances": [{"code":warning["code"], "scope":warning["scope"], "reason":"Project notes are intentionally kept beside the origins."}]
        });
        fs::write(
            root.path().join("check-acceptances.yaml"),
            serde_json::to_vec(&acceptance).unwrap(),
        )
        .unwrap();
        let (exit, stdout, stderr) = run_cli(&args);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        let after = json(&stdout);
        assert_eq!(
            after["filesChecked"],
            serde_json::json!(files_before_acceptance + 1)
        );
        assert_eq!(after["warnings"], 0);
        assert_eq!(after["diagnostics"].as_array().unwrap().len(), 1);
        assert_eq!(after["diagnostics"][0]["severity"], "warning");
        assert_eq!(
            after["diagnostics"][0]["acceptedReason"],
            "Project notes are intentionally kept beside the origins."
        );
    }

    #[test]
    fn project_acceptance_is_retained_when_an_explicit_runtime_refuses() {
        let root = fixture_copy(|root| {
            fs::write(root.join("notes.yaml"), "title: Project notes\n").unwrap();
        });
        let deployment = root.path().join("deployment");
        fs::create_dir(&deployment).unwrap();
        let runtime = deployment.join("runtime.yaml");
        let source = fs::read_to_string(Path::new(FIXTURE).join("runtime.yaml")).unwrap();
        let source = format!("{source}unknownMember: true\n");
        fs::write(&runtime, source).unwrap();
        fs::write(
            root.path().join("check-acceptances.yaml"),
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": registry_platform_yaml::CHECK_ACCEPTANCES_API_VERSION,
                "kind": registry_platform_yaml::CHECK_ACCEPTANCES_KIND,
                "acceptances": [{
                    "code": "discovery.project.unread-file",
                    "scope": {"file": "notes.yaml", "path": ""},
                    "reason": "Project notes are intentionally kept beside the origins."
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let (exit, stdout, stderr) = run_cli(&[
            "check",
            "--project",
            root.path().to_str().unwrap(),
            "--runtime-config",
            runtime.to_str().unwrap(),
            "--format",
            "json",
            "--deny-warnings",
        ]);
        assert_eq!(exit, ExitCode::from(1), "{stdout}{stderr}");
        let report = json(&stdout);
        assert_eq!(report["errors"], 1);
        assert_eq!(report["warnings"], 0);
        assert_eq!(report["diagnostics"].as_array().unwrap().len(), 2);
        let accepted = report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|diagnostic| diagnostic["code"] == "discovery.project.unread-file")
            .expect("the accepted project warning remains beside the runtime error");
        assert_eq!(
            accepted["acceptedReason"],
            "Project notes are intentionally kept beside the origins."
        );
    }

    #[test]
    fn cfg_diag_4_deny_warnings_turns_a_warning_into_exit_one() {
        let root = fixture_copy(|root| {
            fs::write(root.join("notes.yaml"), "title: notes\n").unwrap();
        });
        let project = root.path().to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--project", project]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(
            stdout.contains("warning[discovery.project.unread-file]"),
            "{stdout}"
        );
        assert!(
            stdout.ends_with("0 errors, 1 warning in 3 files\n"),
            "{stdout}"
        );

        let (exit, _, stderr) = run_cli(&["check", "--project", project, "--deny-warnings"]);
        assert_eq!(exit, ExitCode::from(1));
        assert!(
            stderr.starts_with("discoveryctl check refused the input.\nwarning["),
            "{stderr}"
        );
    }

    #[test]
    fn cfg_diag_4_an_unreadable_input_exits_three() {
        let root = temporary();
        let absent = root.path().join("absent");
        let absent = absent.to_str().unwrap();
        let (exit, stdout, _) = run_cli(&["check", "--project", absent, "--format", "json"]);
        assert_eq!(exit, ExitCode::from(3));
        let report = json(&stdout);
        assert_eq!(report["ok"], false);
        assert_eq!(report["status"], "operational-failure");

        let (exit, _, stderr) = run_cli(&["check", "--runtime-config", absent]);
        assert_eq!(exit, ExitCode::from(3));
        assert!(
            stderr.starts_with("discoveryctl check could not read all of its input.\n"),
            "{stderr}"
        );
    }

    #[test]
    fn cfg_diag_4_a_usage_error_exits_two_in_both_formats() {
        let (exit, stdout, stderr) = run_cli(&["check"]);
        assert_eq!(exit, ExitCode::from(2));
        assert!(stdout.is_empty(), "{stdout}");
        assert!(
            stderr.starts_with(&format!("error[{USAGE_CODE}]")),
            "{stderr}"
        );
        assert!(stderr.contains(USAGE_ACTION), "{stderr}");

        let (exit, stdout, stderr) = run_cli(&["check", "--format", "json"]);
        assert_eq!(exit, ExitCode::from(2));
        assert!(stderr.is_empty(), "{stderr}");
        let report = json(&stdout);
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "usage");
        assert_eq!(report["status"], "usage-error");
        assert_eq!(report["diagnostics"][0]["code"], USAGE_CODE);

        let (exit, stdout, _) = run_cli(&["--help"]);
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(stdout.contains("check"), "{stdout}");
    }

    #[test]
    fn check_help_names_the_discovery_invocation_that_exists() {
        // The `discovery` binary has no subcommands: it serves one index
        // from the file named by `--runtime-config`.
        let (exit, stdout, stderr) = run_cli(&["check", "--help"]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(!stdout.contains("discovery serve"), "{stdout}");
        assert!(
            stdout.contains("exactly as `discovery --runtime-config` parses it at startup"),
            "{stdout}"
        );
    }

    #[test]
    fn cfg_check_1_the_runtime_file_checks_on_its_own_and_with_the_project() {
        let fixture = fixture_copy(copy_runtime);
        let root = fixture.path().to_str().unwrap();
        let runtime = fixture.path().join("runtime.yaml");
        let runtime = runtime.to_str().unwrap();
        let (exit, stdout, stderr) =
            run_cli(&["check", "--runtime-config", runtime, "--format", "json"]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        let report = json(&stdout);
        assert_eq!(report["filesChecked"], 1);
        assert!(report.get("origins").is_none());

        let (exit, stdout, stderr) = run_cli(&[
            "check",
            "--project",
            root,
            "--runtime-config",
            runtime,
            "--format",
            "json",
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        assert_eq!(json(&stdout)["filesChecked"], 4);
    }

    #[test]
    fn cfg_diag_2_a_refused_runtime_file_prints_its_diagnostic_and_exits_one() {
        let fixture = fixture_copy(copy_runtime);
        let runtime = fixture.path().join("runtime.yaml");
        let runtime = runtime.to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--runtime-config", runtime]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(
            stdout.ends_with("0 errors, 0 warnings in 1 file\n"),
            "{stdout}"
        );

        let directory = temporary();
        let path = directory.path().join("runtime.yaml");
        fs::write(&path, b"unknownMember: true\n").unwrap();
        let path = path.to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--runtime-config", path]);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty(), "{stdout}");
        assert!(stderr.contains(path), "{stderr}");
        assert!(stderr.contains("next:"), "{stderr}");

        let (exit, stdout, _) = run_cli(&["check", "--runtime-config", path, "--format", "json"]);
        assert_eq!(exit, ExitCode::from(1));
        let report = json(&stdout);
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["ok"], false);
        assert!(!report["diagnostics"].as_array().unwrap().is_empty());
    }

    #[test]
    fn runtime_config_check_reports_package_posture() {
        use registry_discovery::{
            canonical_index_bytes, catalog_revision, package_limits, INDEX_FILE, PACKAGE_COMMAND,
        };

        let root = fixture_copy(copy_runtime);
        let runtime = root.path().join("runtime.yaml");
        let package = root.path().join("package");
        let text = fs::read_to_string(&runtime)
            .unwrap()
            .replace("/srv/registry-discovery/package", package.to_str().unwrap());
        fs::write(&runtime, text).unwrap();

        let mut index =
            registry_discovery::load_index(&Path::new(FIXTURE).join(INDEX_FILE)).unwrap();
        index.origins[0].catalog_url = "http://127.0.0.1/catalog.jsonld".into();
        index.services[0].origin_url = index.origins[0].catalog_url.clone();
        index.catalog_revision = catalog_revision(&index.services).unwrap();
        let files = std::collections::BTreeMap::from([(
            INDEX_FILE.to_owned(),
            canonical_index_bytes(&index).unwrap(),
        )]);
        registry_platform_config::write_package(
            &package,
            &files,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();

        let production = registry_platform_config::declared(Some("production")).unwrap();
        let result = registry_discovery::check_runtime_with_package(&runtime, false, production);
        assert_eq!(result.diagnostics.len(), 2, "{:?}", result.diagnostics);

        for (posture, code) in [("production", 1), ("development", 0)] {
            let (exit, stdout, stderr) = run_cli(&[
                "check",
                "--runtime-config",
                runtime.to_str().unwrap(),
                "--posture",
                posture,
                "--format",
                "json",
            ]);
            assert_eq!(exit, ExitCode::from(code), "{stdout}{stderr}");
            let report = json(&stdout);
            let diagnostics = report["diagnostics"].as_array().unwrap();
            assert_eq!(diagnostics.len(), 2, "{report}");
            let severity = if posture == "production" {
                "error"
            } else {
                "warning"
            };
            for (finding, pointer) in diagnostics
                .iter()
                .zip(["/origins/0/catalogUrl", "/services/0/originUrl"])
            {
                assert_eq!(finding["code"], "discovery.posture.loopback-catalog-url");
                assert_eq!(finding["path"], pointer);
                assert_eq!(finding["severity"], severity);
            }
        }

        let (exit, stdout, stderr) = run_cli(&[
            "check",
            "--runtime-config",
            runtime.to_str().unwrap(),
            "--posture",
            "development",
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        let index = package.join(INDEX_FILE);
        let warning = |pointer: &str| {
            format!(
                "warning[discovery.posture.loopback-catalog-url] {} {pointer}\n  \
                 the index advertises an address on the reader's own machine; production refuses it\n  \
                 next: Publish HTTPS URLs on non-loopback hosts.\n",
                index.display()
            )
        };
        assert!(
            stdout.contains(&warning("/origins/0/catalogUrl"))
                && stdout.contains(&warning("/services/0/originUrl"))
                && stdout.ends_with("0 errors, 2 warnings in 1 file\n"),
            "{stdout}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_config_check_reports_an_unreadable_package_as_unavailable() {
        let root = fixture_copy(copy_runtime);
        let runtime = root.path().join("runtime.yaml");
        let mut package = root.path().join("package");
        // Linux accepts this directory path but returns ENAMETOOLONG when
        // the verifier appends SHA256SUMS, even for a privileged process.
        const ROOT_LENGTH: usize = 4090;
        while package.as_os_str().len() < ROOT_LENGTH {
            let remaining = ROOT_LENGTH - package.as_os_str().len() - 1;
            package.push("x".repeat(remaining.min(200)));
        }
        fs::create_dir_all(&package).unwrap();
        assert!(package.is_dir());
        assert_ne!(
            fs::symlink_metadata(package.join("SHA256SUMS"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        let text = fs::read_to_string(&runtime)
            .unwrap()
            .replace("/srv/registry-discovery/package", package.to_str().unwrap());
        fs::write(&runtime, text).unwrap();

        let (exit, stdout, stderr) = run_cli(&[
            "check",
            "--runtime-config",
            runtime.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(
            exit,
            ExitCode::from(report::OPERATIONAL_FAILURE_EXIT),
            "{stdout}{stderr}"
        );
        let report = json(&stdout);
        assert_eq!(report["status"], "operational-failure");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "discovery.runtime.package-refused"
        );
    }

    #[test]
    fn cfg_check_1_the_index_checks_on_its_own_in_both_formats() {
        let index = Path::new(FIXTURE).join("discovery-index.json");
        let index = index.to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--index", index, "--format", "json"]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        let report = json(&stdout);
        assert_eq!(report["filesChecked"], 1);
        assert_eq!(report["index"]["services"], 1);
        assert_eq!(report["index"]["mappings"], 1);

        let (exit, stdout, stderr) = run_cli(&["check", "--index", index]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stderr}");
        assert!(
            stdout
                .starts_with("valid index origins=1 services=1 mappings=1 catalogRevision=sha256:"),
            "{stdout}"
        );
        assert!(
            stdout.ends_with("0 errors, 0 warnings in 1 file\n"),
            "{stdout}"
        );
    }

    #[test]
    fn cfg_diag_2_a_refused_index_prints_its_diagnostic_and_exits_one() {
        let directory = temporary();
        let path = directory.path().join("discovery-index.json");
        fs::write(&path, b"{}").unwrap();
        let path = path.to_str().unwrap();
        let (exit, stdout, stderr) = run_cli(&["check", "--index", path]);
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty(), "{stdout}");
        assert!(
            stderr.starts_with(&format!(
                "discoveryctl check refused the input.\nerror[discovery.index.invalid] {path}"
            )),
            "{stderr}"
        );
        assert!(
            stderr.contains("next: Rebuild the index with `discoveryctl package`"),
            "{stderr}"
        );

        let (exit, stdout, _) = run_cli(&["check", "--index", path, "--format", "json"]);
        assert_eq!(exit, ExitCode::from(1));
        let report = json(&stdout);
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(report["diagnostics"][0]["code"], "discovery.index.invalid");
        assert!(report.get("index").is_none());
    }

    #[test]
    fn retired_build_refusal_names_discoveryctl_package() {
        let arguments = Arguments::try_parse_from([
            "discoveryctl",
            "build",
            "--project",
            "project",
            "--output",
            "discovery-index.json",
        ])
        .expect("the retired command reaches its migration refusal");
        let message = run(arguments.command, None).unwrap_err();
        assert!(message.contains("discoveryctl package"), "{message}");

        assert!(Arguments::try_parse_from([
            "discoveryctl",
            "package",
            "--project",
            "project",
            "--output",
            "package",
        ])
        .is_ok());
    }
}
