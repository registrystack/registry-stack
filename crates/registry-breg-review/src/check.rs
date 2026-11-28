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

use crate::config::RuntimeCheck;

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
    pub posture: registry_platform_config::DeclaredPosture,
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
    explicit_production_settings: serde_json::Value,
    posture: serde_json::Value,
}

/// Run `breg-review check` and report every finding (CFG-DIAG-4): exit 0 when
/// nothing was refused, 1 when something was or a warning was reported under
/// `--deny-warnings`, and 3 when the file could not be read.
pub fn run(request: &CheckRequest<'_>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let RuntimeCheck {
        diagnostics,
        unavailable,
        explicit_settings,
    } = check_runtime_file(request.runtime, request.environment, request.posture);
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    let exit = if unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors()
        || (request.deny_warnings
            && registry_platform_config::has_denied_warnings(report.diagnostics()))
    {
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
                explicit_production_settings: serde_json::json!(explicit_settings
                    .iter()
                    .map(|found| registry_cli_report::ExplicitSettingLine {
                        code: found.setting.code.to_owned(),
                        file: request.runtime.to_str().map(ToOwned::to_owned),
                        pointer: found.pointer.clone(),
                        line: found.position.map(|position| position.line),
                        column: found.position.map(|position| position.column),
                        summary: found.setting.summary.to_owned(),
                    })
                    .collect::<Vec<_>>()),
                posture: serde_json::json!({
                    "value": request.posture.posture.as_str(),
                    "source": request.posture.source.as_str(),
                }),
            };
            let written = serde_json::to_writer_pretty(&mut *stdout, &document)
                .map_err(std::io::Error::other)
                .and_then(|()| writeln!(stdout));
            if written.is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human if exit == 0 => {
            if write_explicit_settings(stdout, &explicit_settings)
                .and_then(|()| stdout.write_all(report.render_human().as_bytes()))
                .is_err()
            {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human => {
            let sentence = if exit == OPERATIONAL_FAILURE_EXIT {
                "breg-review check could not read all of its input."
            } else {
                "breg-review check refused the input."
            };
            if write_explicit_settings(stderr, &explicit_settings)
                .and_then(|()| write!(stderr, "{sentence}\n{}", report.render_human()))
                .is_err()
            {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
    }
    exit
}

fn write_explicit_settings(
    output: &mut dyn Write,
    settings: &[registry_platform_config::FoundExplicitSetting],
) -> std::io::Result<()> {
    for found in settings {
        writeln!(
            output,
            "Explicit production setting {} at {}. {}.",
            found.setting.code,
            found.pointer.as_deref().unwrap_or_default(),
            found.setting.summary
        )?;
    }
    Ok(())
}

/// Check the runtime file at `path` as given: the loader needs an absolute,
/// lexically normal path, and every diagnostic names the file as given.
/// Returns the findings and whether the file could not be read at all.
fn check_runtime_file(
    path: &Path,
    environment: bool,
    posture: registry_platform_config::DeclaredPosture,
) -> RuntimeCheck {
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
        return RuntimeCheck {
            diagnostics: vec![diagnostic],
            unavailable: true,
            explicit_settings: vec![],
        };
    };
    let mut checked = crate::config::check_runtime_with_posture(&absolute, environment, posture);
    let absolute = absolute.display().to_string();
    for diagnostic in &mut checked.diagnostics {
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
    }
    checked
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
