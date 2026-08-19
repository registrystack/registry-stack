// SPDX-License-Identifier: Apache-2.0
//! Thin adopter-facing command line for Relay V2.
//!
//! This crate owns argument parsing and report presentation. Contract parsing,
//! SQLite schema inspection, compilation, generation, fixture evaluation,
//! change classification, and packaging remain in `registry-relay-v2`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod report;
mod shared;
mod tooling_editor;

use crate::shared::ToolingReport;

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
    /// Emit the selected command's report as best-effort JSON when it has one.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

/// Return the complete public command tree for documentation and completion
/// generators without running a Relay operation.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
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
    /// Advanced editor and language-server integration surfaces.
    #[command(subcommand)]
    Tooling(ToolingCommand),
}

#[derive(Debug, Subcommand)]
enum ToolingCommand {
    /// Write project-local schema mappings for VS Code and Zed.
    Editor(tooling_editor::EditorArgs),
    /// Run Relay V2 authoring support over the Language Server Protocol.
    LanguageServer,
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

    /// Source posture to use while opening the database read-only.
    #[arg(long, value_enum, default_value_t)]
    profile: InspectionProfileArg,

    /// Write compiler-derived, visibly unreviewed starters to this directory.
    #[arg(long, value_name = "DIRECTORY")]
    starters: Option<std::path::PathBuf>,

    /// Generate a format-neutral statistical component starter for this view.
    #[arg(
        long,
        value_name = "VIEW",
        requires = "starters",
        requires_all = ["time_column", "measure_column"]
    )]
    statistical_view: Option<String>,

    /// Exact source column for the required time-period dimension.
    #[arg(long, value_name = "COLUMN", requires = "statistical_view")]
    time_column: Option<String>,

    /// Exact source column for the required observation measure.
    #[arg(long, value_name = "COLUMN", requires = "statistical_view")]
    measure_column: Option<String>,

    /// Exact source column to treat as an observation attribute instead of a dimension.
    #[arg(long, value_name = "COLUMN", requires = "statistical_view")]
    attribute_column: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum InspectionProfileArg {
    Snapshot,
    #[default]
    LiveReadOnly,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: std::path::PathBuf,

    /// Require all generated suggestions to have been reviewed.
    #[arg(long)]
    production: bool,
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

    /// Run one exact fixture identifier.
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

    let Cli { json, command } = cli;
    let command = match command {
        Command::Tooling(command) => return run_tooling(command, json, stdout, stderr),
        command => command,
    };

    let report = match shared::execute(command) {
        Ok(report) => report,
        Err(error) => {
            let _ = writeln!(stderr, "relayctl: {}", error.safe_message());
            return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
        }
    };

    if render_report(&report, json, stdout).is_err() {
        let _ = writeln!(stderr, "relayctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }

    if report.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(DOMAIN_REFUSAL_EXIT)
    }
}

fn run_tooling(
    command: ToolingCommand,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        ToolingCommand::Editor(args) => match tooling_editor::setup_project_editor(&args.project) {
            Ok(report) => {
                let rendered = if json {
                    serde_json::to_string_pretty(&report).map(|document| format!("{document}\n"))
                } else {
                    Ok(report.render_human())
                };
                match rendered.and_then(|document| {
                    stdout
                        .write_all(document.as_bytes())
                        .map_err(serde_json::Error::io)
                }) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(_) => {
                        let _ = writeln!(stderr, "relayctl: output could not be written");
                        ExitCode::from(OPERATIONAL_FAILURE_EXIT)
                    }
                }
            }
            Err(error) => {
                let _ = writeln!(stderr, "relayctl: {error}");
                ExitCode::from(OPERATIONAL_FAILURE_EXIT)
            }
        },
        ToolingCommand::LanguageServer => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(runtime) => {
                    runtime.block_on(registry_language_server::run_stdio());
                    ExitCode::SUCCESS
                }
                Err(_) => {
                    let _ = writeln!(stderr, "relayctl: language server could not start");
                    ExitCode::from(OPERATIONAL_FAILURE_EXIT)
                }
            }
        }
    }
}

/// Write one shared report: the machine document under `--json`, and the plain
/// adopter rendering otherwise. The shared report is the sole source of command
/// details in both. Rendering it does not reinterpret compiler outcomes or
/// change classes, and the JSON document is the same one either way.
fn render_report(report: &ToolingReport, json: bool, output: &mut dyn Write) -> io::Result<()> {
    if json {
        serde_json::to_writer_pretty(&mut *output, report).map_err(io::Error::other)?;
        writeln!(output)
    } else {
        let rendered = report::render_human(report).map_err(io::Error::other)?;
        output.write_all(rendered.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_CONTENT_CANARY: &str = "source-content-canary";

    fn editor_project() -> tempfile::TempDir {
        let project = tempfile::tempdir().expect("temporary project is created");
        assert!(project.path().is_absolute());
        std::fs::write(
            project.path().join("registry.yaml"),
            format!("kind: RegistryContract\nsummary: {SOURCE_CONTENT_CANARY}\n"),
        )
        .expect("project marker is written");
        project
    }

    fn run_editor(project: &std::path::Path) -> (ExitCode, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run_from(
            [
                std::ffi::OsStr::new("relayctl"),
                std::ffi::OsStr::new("tooling"),
                std::ffi::OsStr::new("editor"),
                project.as_os_str(),
            ],
            &mut stdout,
            &mut stderr,
        );
        (
            status,
            String::from_utf8(stdout).expect("stdout is UTF-8"),
            String::from_utf8(stderr).expect("stderr is UTF-8"),
        )
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
        assert!(help.contains("--profile <PROFILE>"));
        assert!(help.contains("live-read-only"));
        assert!(help.contains("snapshot"));
        assert!(help.contains("--statistical-view"));
        assert!(help.contains("--time-column"));
        assert!(help.contains("--measure-column"));
        assert!(help.contains("--attribute-column"));
        assert!(help.contains("format-neutral statistical component starter"));
    }

    #[test]
    fn statistical_starter_selection_is_explicit_and_complete() {
        let cli = Cli::try_parse_from([
            "relayctl",
            "inspect",
            "registry.sqlite",
            "--starters",
            "generated",
            "--statistical-view",
            "published_rates",
            "--time-column",
            "time_period",
            "--measure-column",
            "obs_value",
            "--attribute-column",
            "unit_measure",
        ])
        .expect("statistical starter request parses");
        let Command::Inspect(args) = cli.command else {
            panic!("inspect command is retained");
        };
        assert_eq!(args.statistical_view.as_deref(), Some("published_rates"));
        assert_eq!(args.time_column.as_deref(), Some("time_period"));
        assert_eq!(args.measure_column.as_deref(), Some("obs_value"));
        assert_eq!(args.attribute_column, ["unit_measure"]);
        assert_eq!(
            args.starters.as_deref(),
            Some(std::path::Path::new("generated"))
        );

        for arguments in [
            vec![
                "relayctl",
                "inspect",
                "registry.sqlite",
                "--starters",
                "generated",
                "--statistical-view",
                "published_rates",
            ],
            vec![
                "relayctl",
                "inspect",
                "registry.sqlite",
                "--statistical-view",
                "published_rates",
                "--time-column",
                "time_period",
                "--measure-column",
                "obs_value",
            ],
        ] {
            let error = Cli::try_parse_from(arguments)
                .expect_err("a partial statistical starter request is refused");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
        }
    }

    #[test]
    fn inspection_defaults_to_the_ordinary_live_read_only_profile() {
        let cli = Cli::try_parse_from(["relayctl", "inspect", "registry.sqlite"])
            .expect("inspection parses");
        let Command::Inspect(args) = cli.command else {
            panic!("inspect command is retained");
        };
        assert!(matches!(args.profile, InspectionProfileArg::LiveReadOnly));
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

    #[cfg(unix)]
    #[test]
    fn editor_symlink_stderr_contains_neither_absolute_project_path_nor_source_content() {
        let project = editor_project();
        let outside = tempfile::tempdir().expect("outside directory is created");
        std::os::unix::fs::symlink(outside.path(), project.path().join(".vscode"))
            .expect("editor ancestor symlink is created");

        let (status, stdout, stderr) = run_editor(project.path());

        assert_eq!(status, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "relayctl: editor setup refused a symbolic link in its managed file set\n"
        );
        assert!(!stderr.contains(project.path().to_string_lossy().as_ref()));
        assert!(!stderr.contains(SOURCE_CONTENT_CANARY));
        assert!(std::fs::read_dir(outside.path())
            .expect("outside directory remains readable")
            .next()
            .is_none());
    }

    #[test]
    fn editor_recovery_stderr_contains_neither_absolute_project_path_nor_source_content() {
        let project = editor_project();
        tooling_editor::change_target_during_publication(
            std::path::PathBuf::from(".zed/settings.json"),
            SOURCE_CONTENT_CANARY.as_bytes().to_vec(),
        );

        let (status, stdout, stderr) = run_editor(project.path());

        assert_eq!(status, ExitCode::from(OPERATIONAL_FAILURE_EXIT));
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "relayctl: editor setup publication failed; recoverable transaction files remain in the project directory\n"
        );
        assert!(!stderr.contains(project.path().to_string_lossy().as_ref()));
        assert!(!stderr.contains(SOURCE_CONTENT_CANARY));
        assert!(std::fs::read_dir(project.path())
            .expect("project remains readable")
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".relay-v2-editor-transaction-")));
    }

    /// One shared report of every kind the tooling facade can return, as the
    /// exact JSON document `--json` has always written.
    const REPORT_DOCUMENTS: [&str; 7] = [
        concat!(
            "{\n",
            "  \"status\": \"success\",\n",
            "  \"diagnostics\": [],\n",
            "  \"details\": {\n",
            "    \"kind\": \"initialized\",\n",
            "    \"files\": [\n",
            "      \"registry.yaml\"\n",
            "    ]\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"success\",\n",
            "  \"diagnostics\": [],\n",
            "  \"details\": {\n",
            "    \"kind\": \"schema-inspection\",\n",
            "    \"fingerprint\": \"sha256:aaaa\",\n",
            "    \"objects\": [\n",
            "      {\n",
            "        \"kind\": \"table\",\n",
            "        \"name\": \"source_records\",\n",
            "        \"tableName\": \"source_records\",\n",
            "        \"columns\": [\n",
            "          {\n",
            "            \"name\": \"record_identifier\",\n",
            "            \"declaredType\": \"TEXT\",\n",
            "            \"nullable\": false,\n",
            "            \"primaryKey\": true\n",
            "          }\n",
            "        ]\n",
            "      }\n",
            "    ],\n",
            "    \"starter_file\": null\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"refused\",\n",
            "  \"diagnostics\": [\n",
            "    {\n",
            "      \"severity\": \"error\",\n",
            "      \"code\": \"runtime.issuer_missing\",\n",
            "      \"location\": \"runtime.yaml.authentication.issuer\",\n",
            "      \"message\": \"a Registry with protected operations requires one configured issuer\"\n",
            "    }\n",
            "  ],\n",
            "  \"details\": {\n",
            "    \"kind\": \"check\",\n",
            "    \"contract_revision\": null,\n",
            "    \"production\": true,\n",
            "    \"configuration_key_paths\": null\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"success\",\n",
            "  \"diagnostics\": [],\n",
            "  \"details\": {\n",
            "    \"kind\": \"generate\",\n",
            "    \"contract_revision\": \"sha256:bbbb\",\n",
            "    \"artifacts\": [\n",
            "      {\n",
            "        \"id\": \"capability-inventory\",\n",
            "        \"path\": \"artifacts/capabilities.json\",\n",
            "        \"sha256\": \"sha256:cccc\"\n",
            "      }\n",
            "    ]\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"success\",\n",
            "  \"diagnostics\": [],\n",
            "  \"details\": {\n",
            "    \"kind\": \"test\",\n",
            "    \"contract_revision\": \"sha256:dddd\",\n",
            "    \"report\": {\n",
            "      \"registryIdentifier\": \"urn:example:registry:records\",\n",
            "      \"selectedFixture\": null,\n",
            "      \"steps\": [\n",
            "        {\n",
            "          \"id\": \"first-page\",\n",
            "          \"operationIdentifier\": \"record.list\",\n",
            "          \"expectedStatus\": 200,\n",
            "          \"actualStatus\": 200,\n",
            "          \"actualCode\": null,\n",
            "          \"passed\": true\n",
            "        }\n",
            "      ],\n",
            "      \"diagnostics\": []\n",
            "    }\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"success\",\n",
            "  \"diagnostics\": [],\n",
            "  \"details\": {\n",
            "    \"kind\": \"diff\",\n",
            "    \"report\": {\n",
            "      \"previousRevision\": \"sha256:eeee\",\n",
            "      \"currentRevision\": \"sha256:ffff\",\n",
            "      \"changes\": [\n",
            "        {\n",
            "          \"class\": \"filter-removed\",\n",
            "          \"impact\": \"breaking\",\n",
            "          \"location\": \"resources[0].operations.list.filters\",\n",
            "          \"description\": \"a request filter was removed\"\n",
            "        }\n",
            "      ]\n",
            "    }\n",
            "  }\n",
            "}"
        ),
        concat!(
            "{\n",
            "  \"status\": \"refused\",\n",
            "  \"diagnostics\": [\n",
            "    {\n",
            "      \"severity\": \"error\",\n",
            "      \"code\": \"classification.unreviewed\",\n",
            "      \"location\": \"resources[0].sourceColumnClassifications\",\n",
            "      \"message\": \"production compilation requires reviewed classification\"\n",
            "    }\n",
            "  ],\n",
            "  \"details\": {\n",
            "    \"kind\": \"package\",\n",
            "    \"manifest\": null\n",
            "  }\n",
            "}"
        ),
    ];

    fn parsed_report(document: &str) -> ToolingReport {
        serde_json::from_str(document).expect("the report document parses")
    }

    fn written(report: &ToolingReport, json: bool) -> String {
        let mut output = Vec::new();
        render_report(report, json, &mut output).expect("report renders");
        String::from_utf8(output).expect("output is UTF-8")
    }

    #[test]
    fn json_reports_are_one_valid_document() {
        let output = written(&parsed_report(REPORT_DOCUMENTS[1]), true);

        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(value["status"], "success");
        assert_eq!(value["details"]["kind"], "schema-inspection");
    }

    #[test]
    fn json_output_stays_byte_identical_to_the_shared_report_document() {
        for document in REPORT_DOCUMENTS {
            let report = parsed_report(document);

            assert_eq!(written(&report, true), format!("{document}\n"));
        }
    }

    #[test]
    fn the_default_output_is_the_plain_rendering_and_never_the_document() {
        for document in REPORT_DOCUMENTS {
            let report = parsed_report(document);

            let output = written(&report, false);

            assert_eq!(output, report::render_human(&report).expect("renders"));
            assert!(!output.starts_with('{'), "default output opened a document");
            assert!(!output.contains("\"status\""), "default output kept JSON");
            assert!(output.ends_with('\n'));
        }
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
    fn json_rendering_is_deterministic_and_has_one_trailing_newline() {
        let report = parsed_report(REPORT_DOCUMENTS[1]);

        let first = written(&report, true);
        let second = written(&report, true);

        assert_eq!(first, second);
        assert!(first.ends_with('\n'));
        assert!(!first.ends_with("\n\n"));
    }
}
