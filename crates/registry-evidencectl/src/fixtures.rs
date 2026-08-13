//! Fixture-run driver. Shells out to the `evidence` binary for every
//! semantic decision and only aggregates results.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_norway::Value as YamlValue;

use crate::authoring::{compile_fixture_project, CompiledFixtureProject};
use crate::evidence_binary;

#[derive(Debug, Subcommand)]
pub enum FixturesCommand {
    /// Run `evidence check` and every bundle fixture through `evidence evaluate`.
    Run(RunArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Deployment project directory containing runtime.yaml and bundle/.
    #[arg(long)]
    pub project: PathBuf,

    /// Path to the evidence binary; defaults to `evidence` on PATH.
    #[arg(long)]
    pub evidence_bin: Option<PathBuf>,

    /// Run only the exact bundle-relative fixture path named here.
    #[arg(long)]
    pub fixture: Option<String>,

    /// Run only the exact case identifier in the selected fixture.
    #[arg(long, requires = "fixture")]
    pub case: Option<String>,

    /// Emit one machine-readable JSON report on standard output.
    #[arg(long)]
    pub json: bool,

    /// Ask `evidence` for each structured value-free evaluation diagnostic and
    /// relay it without interpreting Evidence semantics.
    #[arg(long)]
    pub explain: bool,
}

/// The result of one `evidence` invocation: whether it exited zero, when it
/// failed its captured stderr for the operator to read, and, for a fixture run,
/// how many cases that fixture evaluated.
struct StepOutcome {
    passed: bool,
    stderr: Option<String>,
    evaluated_cases: Option<usize>,
    trace: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
struct CheckReport {
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
}

#[derive(Debug, Serialize)]
struct FixtureReport {
    path: String,
    passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
    /// Absent when the fixture failed, or when `evidence` reported no count.
    #[serde(skip_serializing_if = "Option::is_none")]
    evaluated_cases: Option<usize>,
    /// What `evidence evaluate --explain` printed, verbatim, and only when a
    /// trace was asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
struct RunReport {
    check: CheckReport,
    fixtures: Vec<FixtureReport>,
    passed: bool,
    /// The cases every fixture in this run evaluated, summed.
    ///
    /// The step counts above measure artifacts, which a reader mistakes for
    /// coverage: a project with four fixture files reports the same `5 passed`
    /// whether those files hold four cases or forty.
    evaluated_cases: usize,
}

pub fn run(command: FixturesCommand) -> Result<ExitCode> {
    match command {
        FixturesCommand::Run(args) => run_fixtures(args),
    }
}

fn run_fixtures(args: RunArgs) -> Result<ExitCode> {
    let runtime_path = args.project.join("runtime.yaml");
    let evidence_bin = evidence_binary::resolve(args.evidence_bin.as_deref())?;
    let target = if runtime_path.is_file() {
        let bundle_directory = resolve_bundle_directory(&runtime_path, &args.project)?;
        let bundle_config_path = bundle_directory.join("evidence.yaml");
        FixtureTarget::Deployment {
            runtime_path,
            fixture_paths: discover_fixtures(&bundle_config_path)?,
        }
    } else {
        if !args.project.join("questions").is_dir() || !args.project.join("sources").is_dir() {
            bail!(
                "project at {} is neither a deployment project with runtime.yaml nor an editable project with questions/ and sources/",
                args.project.display()
            );
        }
        let staging = tempfile::Builder::new()
            .prefix("evidencectl-fixtures-")
            .tempdir()
            .context("creating private fixture compilation staging")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
                .context("sealing private fixture compilation staging")?;
        }
        let compilation = compile_fixture_project(&args.project, staging.path(), &evidence_bin)
            .context("compiling editable project for fixture evaluation")?;
        FixtureTarget::Editable {
            compilation,
            _staging: staging,
        }
    };
    let fixture_paths = select_fixture_paths(target.fixture_paths(), args.fixture.as_deref())?;

    let check_outcome = target.check(&evidence_bin);
    let check_passed = check_outcome.passed;

    // A broken bundle makes per-fixture results meaningless, so a failing
    // check short-circuits before any fixture is evaluated.
    let mut fixtures = Vec::new();
    if check_passed {
        for fixture_path in fixture_paths {
            let outcome = target.evaluate(
                &evidence_bin,
                fixture_path,
                args.case.as_deref(),
                args.explain,
            );
            fixtures.push(FixtureReport {
                path: fixture_path.to_owned(),
                passed: outcome.passed,
                stderr: outcome.stderr,
                evaluated_cases: outcome.evaluated_cases,
                trace: outcome.trace,
            });
        }
    }

    let overall_passed = check_passed && fixtures.iter().all(|fixture| fixture.passed);
    let evaluated_cases = fixtures
        .iter()
        .filter_map(|fixture| fixture.evaluated_cases)
        .sum();
    let report = RunReport {
        check: CheckReport {
            passed: check_passed,
            stderr: check_outcome.stderr,
        },
        fixtures,
        passed: overall_passed,
        evaluated_cases,
    };

    if args.json {
        print_diagnostics(&report, true);
        let encoded = serde_json::to_string(&report).context("failed to encode the JSON report")?;
        println!("{encoded}");
    } else {
        print_diagnostics(&report, false);
    }

    Ok(if overall_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Preserve the bundle's declared order for a full run, or select one exact
/// referenced path. The rejected value is deliberately absent from the error:
/// fixture selectors are operator input and diagnostics stay value-free.
fn select_fixture_paths<'a>(
    fixture_paths: &'a [String],
    selected: Option<&str>,
) -> Result<Vec<&'a str>> {
    match selected {
        None => Ok(fixture_paths.iter().map(String::as_str).collect()),
        Some(selected) => fixture_paths
            .iter()
            .find(|fixture| fixture.as_str() == selected)
            .map(|fixture| vec![fixture.as_str()])
            .ok_or_else(|| anyhow!("selected fixture is not referenced by the project")),
    }
}

/// The two project shapes adopters work with. Deployment projects carry a
/// runtime binding; editable projects compile to a private bundle and use the
/// runtime's bundle-only fixture seam.
enum FixtureTarget {
    Deployment {
        runtime_path: PathBuf,
        fixture_paths: Vec<String>,
    },
    Editable {
        // Declared before the temporary directory so its Drop restores bundle
        // permissions before the directory removes the staging tree.
        compilation: CompiledFixtureProject,
        _staging: tempfile::TempDir,
    },
}

impl FixtureTarget {
    fn fixture_paths(&self) -> &[String] {
        match self {
            Self::Deployment { fixture_paths, .. } => fixture_paths,
            Self::Editable { compilation, .. } => &compilation.fixture_paths,
        }
    }

    fn check(&self, evidence_bin: &Path) -> StepOutcome {
        match self {
            Self::Deployment { runtime_path, .. } => {
                run_evidence_step(evidence_bin, &["--runtime"], Some(runtime_path), &["check"])
            }
            Self::Editable { compilation, .. } => run_evidence_step(
                evidence_bin,
                &["bundle-check", "--bundle"],
                Some(&compilation.bundle_path),
                &[],
            ),
        }
    }

    fn evaluate(
        &self,
        evidence_bin: &Path,
        fixture: &str,
        case: Option<&str>,
        explain: bool,
    ) -> StepOutcome {
        match self {
            Self::Deployment { runtime_path, .. } => {
                let mut args = vec!["evaluate", "--fixture", fixture];
                if let Some(case) = case {
                    args.extend(["--case", case]);
                }
                if explain {
                    args.extend(["--explain", "--explain-format", "json"]);
                }
                run_evidence_step(evidence_bin, &["--runtime"], Some(runtime_path), &args)
            }
            Self::Editable { compilation, .. } => {
                let mut args = vec!["--fixture", fixture];
                if let Some(case) = case {
                    args.extend(["--case", case]);
                }
                if explain {
                    args.extend(["--explain", "--explain-format", "json"]);
                }
                run_evidence_step(
                    evidence_bin,
                    &["bundle-evaluate", "--bundle"],
                    Some(&compilation.bundle_path),
                    &args,
                )
            }
        }
    }
}

/// Resolve the bundle directory a project's `runtime.yaml` names. A relative
/// `bundleDirectory` is resolved against the runtime file's own directory, an
/// absolute one is used as-is, and `<project>/bundle` is the default only when
/// the key is absent. This is discovery, not validation: `evidence check` is
/// left to reject a runtime configuration that is otherwise malformed.
fn resolve_bundle_directory(runtime_path: &Path, project: &Path) -> Result<PathBuf> {
    let bytes = fs::read(runtime_path).with_context(|| {
        format!(
            "failed to read runtime configuration at {}",
            runtime_path.display()
        )
    })?;
    let document: YamlValue = serde_norway::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse runtime configuration at {}",
            runtime_path.display()
        )
    })?;
    match document.get("bundleDirectory") {
        Some(value) => {
            let value = value.as_str().ok_or_else(|| {
                anyhow!(
                    "bundleDirectory in {} is not a string",
                    runtime_path.display()
                )
            })?;
            let path = Path::new(value);
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                let base = runtime_path.parent().unwrap_or(project);
                Ok(base.join(path))
            }
        }
        None => Ok(project.join("bundle")),
    }
}

/// Enumerate the bundle-relative fixture paths a project's requirements
/// reference. This is discovery, not validation: unknown fields anywhere in
/// the document are tolerated, and `evidence check` is left to reject a
/// bundle that is otherwise malformed.
fn discover_fixtures(bundle_config_path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(bundle_config_path).with_context(|| {
        format!(
            "failed to read bundle configuration at {}",
            bundle_config_path.display()
        )
    })?;
    let document: YamlValue = serde_norway::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse bundle configuration at {}",
            bundle_config_path.display()
        )
    })?;
    let requirements = document
        .get("requirements")
        .and_then(YamlValue::as_sequence)
        .ok_or_else(|| {
            anyhow!(
                "bundle configuration at {} has no requirements list",
                bundle_config_path.display()
            )
        })?;

    let mut fixture_paths: Vec<String> = Vec::new();
    for requirement in requirements {
        let fixture_path = requirement
            .get("fixtures")
            .and_then(YamlValue::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "a requirement in {} has no fixtures path",
                    bundle_config_path.display()
                )
            })?;
        if !fixture_paths
            .iter()
            .any(|existing| existing == fixture_path)
        {
            fixture_paths.push(fixture_path.to_owned());
        }
    }
    Ok(fixture_paths)
}

/// Run one `evidence --runtime <runtime_path> <args...>` invocation.
///
/// Standard output and standard error are captured rather than inherited so
/// steps never interleave, and any failure to even spawn the process is
/// treated the same as a nonzero exit: the step failed.
fn run_evidence_step(
    evidence_bin: &Path,
    prefix: &[&str],
    path: Option<&Path>,
    args: &[&str],
) -> StepOutcome {
    let mut command = Command::new(evidence_bin);
    command.args(prefix);
    if let Some(path) = path {
        command.arg(path);
    }
    command.args(args);
    match command.output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let trace = structured_trace(&stdout);
            StepOutcome {
                passed: true,
                evaluated_cases: structured_evaluated_cases(trace.as_ref())
                    .or_else(|| evaluated_cases(&stdout)),
                stderr: None,
                trace,
            }
        }
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let trace = structured_trace(&stdout);
            StepOutcome {
                passed: false,
                evaluated_cases: structured_evaluated_cases(trace.as_ref())
                    .or_else(|| evaluated_cases(&stdout)),
                trace,
                stderr: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
            }
        }
        Err(error) => StepOutcome {
            passed: false,
            stderr: Some(format!("failed to run {}: {error}", evidence_bin.display())),
            evaluated_cases: None,
            trace: None,
        },
    }
}

fn structured_evaluated_cases(trace: Option<&JsonValue>) -> Option<usize> {
    trace
        .and_then(|trace| trace.get("evaluatedCases"))
        .and_then(JsonValue::as_u64)
        .and_then(|count| usize::try_from(count).ok())
}

fn structured_trace(stdout: &str) -> Option<JsonValue> {
    serde_json::from_str(stdout.trim())
        .ok()
        .filter(|value: &JsonValue| {
            value.get("passed").is_some_and(JsonValue::is_boolean)
                && value.get("cases").is_some_and(JsonValue::is_array)
        })
}

/// Read the case count out of `Evidence fixture passed (N evaluated cases)`.
///
/// This driver makes no semantic decision, so the count is `evidence`'s own
/// figure or nothing at all. An unrecognized line leaves it absent rather than
/// guessed, which keeps a total that is short honest instead of wrong.
fn evaluated_cases(stdout: &str) -> Option<usize> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Evidence fixture passed (")?
            .strip_suffix(" evaluated cases)")?
            .parse()
            .ok()
    })
}

/// Print one line per step and a summary line.
///
/// In JSON mode this goes to stderr, keeping stdout reserved for the single
/// JSON document; in human mode it is the entire report and goes to stdout.
fn print_diagnostics(report: &RunReport, to_stderr: bool) {
    let mut lines = Vec::new();
    lines.push(step_line("check", report.check.passed));
    if !report.check.passed {
        lines.extend(indented(report.check.stderr.as_deref()));
    }
    for fixture in &report.fixtures {
        let mut line = step_line(&fixture.path, fixture.passed);
        if let Some(cases) = fixture.evaluated_cases {
            line.push_str(&format!(" ({cases} cases)"));
        }
        lines.push(line);
        // The trace comes before the diagnostic, the order `evidence` itself
        // prints them in: how far the run got, then what stopped it.
        if let Some(trace) = &fixture.trace {
            let rendered = serde_json::to_string_pretty(trace).unwrap_or_default();
            lines.extend(indented(Some(&rendered)));
        }
        if !fixture.passed {
            lines.extend(indented(fixture.stderr.as_deref()));
        }
    }
    let passed_count =
        usize::from(report.check.passed) + report.fixtures.iter().filter(|f| f.passed).count();
    let failed_count =
        usize::from(!report.check.passed) + report.fixtures.iter().filter(|f| !f.passed).count();
    // The step counts stay, because they are what the exit code is made of.
    // The case total is beside them because it is the number a reader is
    // actually looking for: how much of the deployment this run exercised.
    lines.push(format!(
        "{passed_count} passed, {failed_count} failed ({} cases evaluated)",
        report.evaluated_cases
    ));

    for line in lines {
        if to_stderr {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    }
}

fn step_line(name: &str, passed: bool) -> String {
    let status = if passed { "PASS" } else { "FAIL" };
    format!("{status}: {name}")
}

fn indented(stderr: Option<&str>) -> Vec<String> {
    let text = stderr.unwrap_or_default();
    if text.trim().is_empty() {
        return vec!["    (no output captured)".to_owned()];
    }
    text.lines().map(|line| format!("    {line}")).collect()
}
