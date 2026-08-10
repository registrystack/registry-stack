// SPDX-License-Identifier: Apache-2.0
//! Thin adopter-facing command line for Relay V2.
//!
//! This crate owns argument parsing and report presentation. Contract parsing,
//! SQLite schema inspection, compilation, generation, fixture evaluation,
//! change classification, and packaging remain in `registry-relay-v2`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use registry_relay_v2::identification::render_operation_explanation_text;
use registry_relay_v2::tooling::{ToolingDetails, ToolingReport};
use serde::Serialize;

mod shared;

const DOMAIN_REFUSAL_EXIT: u8 = 1;
const USAGE_EXIT: u8 = 2;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

#[derive(Debug, Parser)]
#[command(
    name = "relayctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Relay V2 project authoring, validation, and packaging"
)]
pub struct Cli {
    /// Emit the shared report as best-effort JSON for local automation.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a complete authoring project with unreviewed starters.
    Init(ProjectArg),
    /// Inspect SQLite structure without reading row values.
    Inspect(InspectArgs),
    /// Compile and validate an authoring project.
    Check(CheckArgs),
    /// Generate deterministic artifacts from the compiled project.
    Generate(OutputArgs),
    /// Run the project's offline fixture cases through the shared kernel.
    Test(TestArgs),
    /// Classify meaning, disclosure, and security changes between projects.
    Diff(DiffArgs),
    /// Build a deterministic sealed deployment package.
    Package(PackageArgs),
}

#[derive(Debug, Args)]
struct ProjectArg {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct InspectArgs {
    /// SQLite database to inspect structurally.
    #[arg(value_name = "DATABASE")]
    database: std::path::PathBuf,

    /// Write compiler-derived, visibly unreviewed starters to this directory.
    #[arg(long, value_name = "DIRECTORY")]
    starters: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,

    /// Require all generated suggestions to have been reviewed.
    #[arg(long)]
    production: bool,

    /// Explain compiled operations, access, disclosure, and wire formats.
    #[arg(long)]
    explain: bool,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,

    /// Destination for generated artifacts.
    #[arg(long, value_name = "DIRECTORY")]
    output: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
struct TestArgs {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,

    /// Run one selected fixture and its declared prerequisites.
    #[arg(long, value_name = "IDENTIFIER")]
    fixture: Option<String>,
}

#[derive(Debug, Args)]
struct DiffArgs {
    /// Previously reviewed project directory.
    #[arg(value_name = "PREVIOUS")]
    previous: std::path::PathBuf,

    /// Candidate project directory.
    #[arg(value_name = "CURRENT")]
    current: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct PackageArgs {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,

    /// New sealed package directory.
    #[arg(long, required = true, value_name = "DIRECTORY")]
    output: std::path::PathBuf,
}

/// Parse process arguments, run one shared-library operation, and return the
/// process exit status without exposing source values in errors.
pub fn main_entry() -> ExitCode {
    run_from(std::env::args_os(), &mut io::stdout(), &mut io::stderr())
}

/// Testable command entry point. The operation itself is always delegated to
/// the shared Relay V2 tooling facade.
pub fn run_from<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() {
                ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(USAGE_EXIT))
            } else {
                ExitCode::SUCCESS
            };
            if error.use_stderr() {
                let _ = write!(stderr, "{error}");
            } else {
                let _ = write!(stdout, "{error}");
            }
            return code;
        }
    };

    let command_name = cli.command.name();
    let report = match shared::execute(cli.command) {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "relayctl: {}", error.safe_message());
            return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
        }
    };

    if render_tooling_report(command_name, &report, cli.json, stdout).is_err() {
        let _ = writeln!(stderr, "relayctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }

    if report.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(DOMAIN_REFUSAL_EXIT)
    }
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::Inspect(_) => "inspect",
            Self::Check(_) => "check",
            Self::Generate(_) => "generate",
            Self::Test(_) => "test",
            Self::Diff(_) => "diff",
            Self::Package(_) => "package",
        }
    }
}

fn render_tooling_report(
    command: &str,
    report: &ToolingReport,
    json: bool,
    output: &mut dyn Write,
) -> io::Result<()> {
    if json {
        return render_json(report, output);
    }

    writeln!(output, "relayctl {command}")?;
    if let ToolingDetails::Check {
        operation_explanation: Some(explanation),
        ..
    } = &report.details
    {
        return output.write_all(render_operation_explanation_text(explanation).as_bytes());
    }

    // The shared report is the sole source of command details. Rendering it
    // here does not reinterpret compiler outcomes or change classes.
    render_json(report, output)
}

fn render_json<T: Serialize>(report: &T, output: &mut dyn Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *output, report).map_err(io::Error::other)?;
    writeln!(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(std::path::PathBuf);

    impl TemporaryDirectory {
        fn create() -> Self {
            let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock follows the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "registry-relayctl-unit-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("temporary project root creates");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn generic_project() -> (TemporaryDirectory, std::path::PathBuf) {
        let temporary = TemporaryDirectory::create();
        let project = temporary.path().join("project");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run_from(
            [
                OsString::from("relayctl"),
                OsString::from("init"),
                project.clone().into_os_string(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(
            status,
            ExitCode::SUCCESS,
            "{}",
            String::from_utf8_lossy(&stderr)
        );
        std::fs::remove_file(project.join("runtime.yaml"))
            .expect("runtime is optional for an authoring check");
        std::fs::write(
            project.join("fixture.sql"),
            "-- ROW-VALUE-CANARY REQUEST-VALUE-CANARY PRINCIPAL-VALUE-CANARY\n",
        )
        .expect("generic value canaries write");
        (temporary, project)
    }

    #[test]
    fn every_approved_command_is_present() {
        for command in [
            "init", "inspect", "check", "generate", "test", "diff", "package",
        ] {
            let error = Cli::try_parse_from(["relayctl", command, "--help"])
                .expect_err("help stops parsing");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        }
    }

    #[test]
    fn inspect_has_no_value_sampling_option() {
        let help = Cli::try_parse_from(["relayctl", "inspect", "--help"])
            .expect_err("help stops parsing")
            .to_string();

        assert!(help.contains("without reading row values"));
        for forbidden in ["--sample", "--rows", "--values", "--limit"] {
            assert!(!help.contains(forbidden), "unexpected option {forbidden}");
        }
    }

    #[test]
    fn package_requires_an_explicit_destination() {
        let error = Cli::try_parse_from(["relayctl", "package", "project"])
            .expect_err("package destination is mandatory");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn json_is_a_global_flag_before_or_after_the_subcommand() {
        for arguments in [
            ["relayctl", "--json", "check", "project"],
            ["relayctl", "check", "project", "--json"],
        ] {
            let cli = Cli::try_parse_from(arguments).expect("global JSON flag parses");
            assert!(cli.json);
        }
    }

    #[test]
    fn command_line_usage_errors_do_not_enter_the_tooling_facade() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let status = run_from(
            ["relayctl", "package", "authoring-project"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(status, ExitCode::from(USAGE_EXIT));
        assert!(stdout.is_empty());
        let error = String::from_utf8(stderr).expect("clap error is UTF-8");
        assert!(error.contains("--output"));
        assert!(!error.contains("selector"));
        assert!(!error.contains("record"));
    }

    #[test]
    fn json_reports_are_one_valid_document() {
        #[derive(Serialize)]
        struct Report<'a> {
            status: &'a str,
            summary: &'a str,
        }

        let mut output = Vec::new();
        render_json(
            &Report {
                status: "accepted",
                summary: "schema structure inspected",
            },
            &mut output,
        )
        .expect("report renders");

        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(value["status"], "accepted");
    }

    #[test]
    fn production_review_is_an_explicit_check_mode() {
        let cli = Cli::try_parse_from(["relayctl", "check", "project", "--production"])
            .expect("production check parses");
        let Command::Check(args) = cli.command else {
            panic!("check command is retained");
        };
        assert!(args.production);
    }

    #[test]
    fn operation_explanation_is_an_explicit_check_mode() {
        let cli =
            Cli::try_parse_from(["relayctl", "check", "project", "--explain", "--production"])
                .expect("explanation check parses");
        let Command::Check(args) = cli.command else {
            panic!("check command is retained");
        };
        assert!(args.explain);
        assert!(args.production);
    }

    #[test]
    fn operation_explanation_is_not_a_mode_of_write_commands() {
        let error = Cli::try_parse_from(["relayctl", "generate", "project", "--explain"])
            .expect_err("explanation is confined to check");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn json_rendering_is_deterministic_and_has_one_trailing_newline() {
        #[derive(Serialize)]
        struct Report<'a> {
            status: &'a str,
            summary: &'a str,
        }

        let mut first = Vec::new();
        let mut second = Vec::new();
        let report = Report {
            status: "accepted",
            summary: "schema structure inspected",
        };
        render_json(&report, &mut first).expect("report renders");
        render_json(&report, &mut second).expect("report repeats");

        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        assert!(!first.ends_with(b"\n\n"));
    }

    #[test]
    fn human_explanation_is_grouped_and_does_not_dump_key_paths() {
        let (_temporary, project) = generic_project();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let status = run_from(
            [
                OsString::from("relayctl"),
                OsString::from("check"),
                project.into_os_string(),
                OsString::from("--explain"),
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(
            status,
            ExitCode::SUCCESS,
            "{}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stderr.is_empty());
        let rendered = String::from_utf8(stdout).expect("human output is UTF-8");
        for heading in [
            "Resource: ",
            "consultation/",
            "query capabilities:",
            "access profile:",
            "processing:",
            "disclosure:",
            "wire formats:",
        ] {
            assert!(rendered.contains(heading), "missing heading {heading}");
        }
        assert!(!rendered.contains("configurationKeyPaths"));
        for canary in [
            "ROW-VALUE-CANARY",
            "REQUEST-VALUE-CANARY",
            "PRINCIPAL-VALUE-CANARY",
        ] {
            assert!(!rendered.contains(canary));
        }
        assert!(rendered.ends_with('\n'));
        assert!(!rendered.ends_with("\n\n"));
    }
}
