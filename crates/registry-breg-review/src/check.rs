// SPDX-License-Identifier: Apache-2.0

//! `breg-review check`: the offline check of the runtime file (CFG-CHECK-1).
//! It reads the file as `serve` does and reports its findings in the shared
//! diagnostic shape, with no secret material, network call, audit file, or
//! listener. A secret the file names is resolved, and the audit directory
//! opened, only when `serve` starts.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use registry_platform_yaml::{Diagnostic, Report, Source};
use serde::Serialize;

/// The `apiVersion` of the report `check --format json` writes.
pub const CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/breg/review-ctl-report/v1alpha1";
/// The `kind` of the report `check --format json` writes.
pub const CTL_REPORT_KIND: &str = "BRegReviewCtlReport";

/// Something was refused, or a warning was reported under `--deny-warnings`.
const DOMAIN_REFUSAL_EXIT: u8 = 1;
/// The runtime file could not be read at all (CFG-DIAG-4).
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// How `check` writes what it found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Diagnostics in the shared human shape (CFG-DIAG-2).
    #[default]
    Human,
    /// One report object on standard output (CFG-DIAG-1).
    Json,
}

/// What one `breg-review check` run reads and how it reports.
#[derive(Debug)]
pub struct CheckRequest<'a> {
    /// The runtime file, as given on the command line.
    pub runtime: &'a Path,
    /// Substitute `${NAME}` expressions from the process environment and
    /// check every value.
    pub environment: bool,
    pub format: OutputFormat,
    pub deny_warnings: bool,
}

/// The report `check --format json` writes: the envelope members every ctl
/// report opens with, then the counts and every diagnostic.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CtlReport {
    ok: bool,
    command: &'static str,
    status: &'static str,
    api_version: &'static str,
    kind: &'static str,
    files_checked: usize,
    errors: usize,
    warnings: usize,
    diagnostics: serde_json::Value,
}

/// Run `breg-review check` and report every finding (CFG-DIAG-4): exit 0 when
/// nothing was refused, 1 when something was or a warning was reported under
/// `--deny-warnings`, and 3 when the file could not be read.
pub fn run(request: &CheckRequest<'_>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let (diagnostics, unavailable) = check_runtime_file(request.runtime, request.environment);
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    let exit = if unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors() || (request.deny_warnings && report.warning_count() > 0) {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    };
    match request.format {
        OutputFormat::Json => {
            let document = CtlReport {
                ok: exit == 0,
                command: "check",
                status: match exit {
                    0 => "complete",
                    OPERATIONAL_FAILURE_EXIT => "operational-failure",
                    _ => "domain-refusal",
                },
                api_version: CTL_REPORT_API_VERSION,
                kind: CTL_REPORT_KIND,
                files_checked: 1,
                errors: report.error_count(),
                warnings: report.warning_count(),
                diagnostics: report.to_json_value(),
            };
            let written = serde_json::to_writer_pretty(&mut *stdout, &document)
                .map_err(std::io::Error::other)
                .and_then(|()| writeln!(stdout));
            if written.is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human if exit == 0 => {
            if stdout.write_all(report.render_human().as_bytes()).is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human => {
            let sentence = if exit == OPERATIONAL_FAILURE_EXIT {
                "breg-review check could not read all of its input."
            } else {
                "breg-review check refused the input."
            };
            if write!(stderr, "{sentence}\n{}", report.render_human()).is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
    }
    exit
}

/// Check the runtime file at `path` as given: the loader needs an absolute,
/// lexically normal path, and every diagnostic names the file as given.
/// Returns the findings and whether the file could not be read at all.
fn check_runtime_file(path: &Path, environment: bool) -> (Vec<Diagnostic>, bool) {
    let given = path.display().to_string();
    let Some(absolute) = absolute_lexical(path) else {
        let mut diagnostic = Diagnostic::error(
            "breg.review-check.runtime-unreadable",
            "",
            "the runtime file path could not be made absolute",
            "Name the runtime file by an absolute path, then run the check again.",
        );
        diagnostic.source = Some(Source {
            file: given,
            line: None,
            column: None,
        });
        return (vec![diagnostic], true);
    };
    let checked = crate::config::check_runtime(&absolute, environment);
    let absolute = absolute.display().to_string();
    let diagnostics = checked
        .diagnostics
        .into_iter()
        .map(|mut diagnostic| {
            if let Some(source) = &mut diagnostic.source {
                if source.file == absolute {
                    source.file.clone_from(&given);
                }
            }
            for related in &mut diagnostic.related {
                if related.file == absolute {
                    related.file.clone_from(&given);
                }
            }
            diagnostic
        })
        .collect();
    (diagnostics, checked.unavailable)
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires (CFG-ENV-5).
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}
