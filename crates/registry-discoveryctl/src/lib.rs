// SPDX-License-Identifier: Apache-2.0
//! Finite Registry Discovery authoring and immutable index packages.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};

mod build;
mod index;
mod project;
mod report;
#[cfg(feature = "schema")]
pub mod schema;

pub use build::{package_project, package_project_at, BuildError, PackagedDiscovery};
pub use index::{inspect_index_file, IndexReport};
pub use project::{
    check_project, inspect_project, inspect_runtime_file, ApprovedOrigin, AuthoredEvidenceMapping,
    AuthoredEvidenceTypeAlternative, CheckedProject, MappingSchemaVersion, OriginProfile,
    OriginsFile, OriginsSchemaVersion, ProjectError, ProjectOptions, ProjectReport,
    MAPPINGS_DIRECTORY, MAPPING_KIND, MAPPING_SCHEMA, ORIGINS_FILE, ORIGINS_KIND, ORIGINS_SCHEMA,
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
    version = registry_platform_buildinfo::DISPLAY_VERSION
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
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
        /// One runtime file, checked on its own.
        #[arg(long, value_name = "FILE")]
        runtime_config: Option<PathBuf>,
        /// One index file, as `discoveryctl package` wrote it, checked on
        /// its own exactly as `discovery serve` parses it.
        #[arg(long, value_name = "FILE")]
        index: Option<PathBuf>,
        /// Accept an http loopback catalog URL, for development.
        #[arg(long)]
        allow_loopback: bool,
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
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        allow_loopback: bool,
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

const RETIRED_BUILD_ERROR: &str =
    "discoveryctl build was removed; use discoveryctl package with a new output directory";
const DOMAIN_REFUSAL_EXIT: u8 = 1;
const USAGE_CODE: &str = "discovery.usage.invalid-arguments";
/// The next step for a command line clap refused.
const USAGE_ACTION: &str =
    "Run discoveryctl --help, or the command with --help, and retry with the documented arguments.";

#[must_use]
pub fn main_entry() -> ExitCode {
    main_entry_from(
        std::env::args_os(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )
}

fn main_entry_from<I, T>(
    args: I,
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
                    stdout,
                );
            } else {
                let _ = write!(stderr, "{}", usage.render_human());
            }
            return ExitCode::from(report::USAGE_EXIT);
        }
    };
    match arguments.command {
        Command::Check {
            project,
            runtime_config,
            index,
            allow_loopback,
            environment,
            format,
            deny_warnings,
        } => check(
            &CheckRequest {
                project,
                runtime_config,
                index,
                options: ProjectOptions {
                    allow_loopback,
                    environment,
                },
                format,
                deny_warnings,
            },
            stdout,
            stderr,
        ),
        command => match run(command) {
            Ok(line) => {
                let _ = writeln!(stdout, "{line}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                let _ = writeln!(stderr, "{error}");
                ExitCode::from(DOMAIN_REFUSAL_EXIT)
            }
        },
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
        let (checked, missing) = inspect_runtime_file(path, request.options.environment);
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
        diagnostics.extend(checked.report.into_diagnostics());
    }
    let mut report = Report::new(diagnostics);
    report.set_files_checked(files);
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
        let _ = report::write(&envelope("check", exit, body), stdout);
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

fn run(command: Command) -> Result<String, String> {
    match command {
        Command::Check { .. } => unreachable!("check reports through its own path"),
        Command::Package {
            project,
            output,
            allow_loopback,
            revision,
        } => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "the Discovery package runtime could not start".to_owned())
            .and_then(|runtime| {
                runtime
                    .block_on(package_project(
                        &project,
                        &output,
                        allow_loopback,
                        revision.as_deref(),
                    ))
                    .map(|package| {
                        format!(
                            "packaged packageDigest={} catalogRevision={} mappingRevision={}",
                            package.package_digest,
                            package.index.catalog_revision,
                            package.index.mapping_revision
                        )
                    })
                    .map_err(|error| error.to_string())
            }),
        Command::Build { .. } => Err(RETIRED_BUILD_ERROR.to_owned()),
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
        TempDir::new_in(base).expect("temporary directory")
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

    #[test]
    fn cfg_diag_1_a_clean_check_reports_json_in_the_ctl_envelope() {
        let (exit, stdout, stderr) = run_cli(&["check", "--project", FIXTURE, "--format", "json"]);
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

    #[test]
    fn cfg_diag_2_a_clean_check_prints_the_counts_and_the_summary() {
        let (exit, stdout, stderr) = run_cli(&["check", "--project", FIXTURE]);
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
                "schemaVersion: registry-discovery/evidence-mapping/v1alpha1\nsurprise: true\n",
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
                "error[config.unknown-key] {}:2:1 /surprise",
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
        assert_eq!(unknown["source"]["line"], 2);
        assert_eq!(unknown["source"]["column"], 1);
        assert!(unknown["suggestedAction"].is_string());
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
    fn cfg_check_1_the_runtime_file_checks_on_its_own_and_with_the_project() {
        let runtime = Path::new(FIXTURE).join("runtime.yaml");
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
            FIXTURE,
            "--runtime-config",
            runtime,
            "--format",
            "json",
        ]);
        assert_eq!(exit, ExitCode::SUCCESS, "{stdout}{stderr}");
        assert_eq!(json(&stdout)["filesChecked"], 4);
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
        let message = run(arguments.command).unwrap_err();
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
