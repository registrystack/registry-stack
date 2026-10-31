// SPDX-License-Identifier: Apache-2.0

//! `adapterctl compile`: the deployment's concrete contract, written as an
//! OpenAPI 3.1 document beside the project (`generated/openapi.json`) and
//! held byte-identical by `--check` (`products/adapter/CONCEPT.md` sections
//! 7 and 8.11.1). The command compiles a workspace `adapterctl check`
//! accepts: it reads the project, profile, and pack the same way, verifies
//! the pins, and runs the same core checks over the workspace before any
//! byte is written, so a refused authoring never reaches a contract file.

pub(crate) mod document;

use clap::Args;
use registry_adapter_core::{
    check_project_pins, check_workspace, AdapterPack, AdapterProfile, AdapterProject, Workspace,
};
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::Value;
use std::io;
use std::path::PathBuf;

use crate::check;
use crate::report;

/// The file the compiled contract is written to, relative to the project
/// directory.
pub(crate) const DEFAULT_OUTPUT: &str = "generated/openapi.json";

#[derive(Debug, Args)]
pub struct CompileArgs {
    /// Authored adapter project: its directory (holding `project.yaml`) or
    /// the `project.yaml` file itself. The profile and pack are read beside
    /// the project either way.
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Profile file read instead of the `profile.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Pack file read instead of the `pack.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,

    /// Compare the compiled bytes with the written file and refuse on drift
    /// instead of writing anything. A file that is not there counts as
    /// drift.
    #[arg(long)]
    pub check: bool,

    /// File the compiled contract is written to or compared against,
    /// instead of `generated/openapi.json` beside the project.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// One completed compile: the project as given, the file the contract was
/// written to or checked against, the concrete operations the document
/// carries, and whether the run compared instead of writing.
pub(crate) struct CompileRun {
    pub project: String,
    pub output: String,
    pub operations: usize,
    pub check: bool,
}

/// Why the compile could not run to a written or checked document.
#[derive(Debug)]
pub(crate) enum CompileFailure {
    /// A required file could not be read: the environment is broken, not
    /// the authoring.
    Io { path: String, source: io::Error },
    /// The written contract differs from the compiled bytes, or is not
    /// there to compare against.
    Drift { path: String },
    /// The workspace refused the compile: the reader's, the pin checks', or
    /// the core checks' findings.
    Refused { diagnostics: Vec<Diagnostic> },
}

/// Compile one project's contract: read and check the workspace exactly as
/// `check` does, assemble the document, then write it or compare it.
pub(crate) fn run(args: &CompileArgs) -> Result<CompileRun, CompileFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    // The project may be given as its directory or as its `project.yaml`;
    // the profile and pack are read beside the project or where the flags
    // point, exactly as `check` resolves them.
    let (project_path, directory) = check::resolve_project(&args.project);
    let project = check::read::<AdapterProject>(
        &project_path,
        &check::PROJECT_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io_failure)?;
    let profile_path = check::artifact_path(
        args.profile.as_deref(),
        &directory,
        "profile.yaml",
        "--profile",
    )
    .map_err(io_failure)?;
    let profile = check::read::<AdapterProfile>(
        &profile_path,
        &check::PROFILE_FORMAT,
        &mut report,
        &mut files,
    )
    .map_err(io_failure)?;
    let pack_path = check::artifact_path(args.pack.as_deref(), &directory, "pack.yaml", "--pack")
        .map_err(io_failure)?;
    let pack = check::read::<AdapterPack>(&pack_path, &check::PACK_FORMAT, &mut report, &mut files)
        .map_err(io_failure)?;

    // A document the reader refuses stops the composition: the pure checks
    // need parsed values.
    if report.has_errors() {
        return Err(CompileFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }
    let (project_decoded, _) = project.expect("the project decoded");
    let (profile_decoded, profile_bytes) = profile.expect("the profile decoded");
    let (pack_decoded, pack_bytes) = pack.expect("the pack decoded");
    let project = project_decoded.value;
    let profile = profile_decoded.value;
    let pack = pack_decoded.value;

    for finding in check_project_pins(
        &project,
        &profile.version,
        &check::digest_of(&profile_bytes),
        &pack.version,
        &check::digest_of(&pack_bytes),
    ) {
        report.push(finding);
    }
    for finding in check_workspace(&Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: None,
        fixtures: &[],
    }) {
        report.push(finding);
    }
    if report.has_errors() {
        return Err(CompileFailure::Refused {
            diagnostics: report.into_diagnostics(),
        });
    }

    let compiled =
        document::assemble(&profile, &project).map_err(|findings| CompileFailure::Refused {
            diagnostics: findings,
        })?;
    let operations = compiled["paths"].as_object().map_or(0, |paths| {
        paths
            .values()
            .map(|item| item.as_object().map_or(0, serde_json::Map::len))
            .sum()
    });
    let rendered = document::render(&compiled);
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| directory.join(DEFAULT_OUTPUT));

    if args.check {
        match std::fs::read(&output) {
            Ok(written) => {
                if written != rendered.as_bytes() {
                    return Err(CompileFailure::Drift {
                        path: output.display().to_string(),
                    });
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(CompileFailure::Drift {
                    path: output.display().to_string(),
                });
            }
            Err(source) => {
                return Err(CompileFailure::Io {
                    path: output.display().to_string(),
                    source,
                });
            }
        }
    } else {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(|source| CompileFailure::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        std::fs::write(&output, rendered.as_bytes()).map_err(|source| CompileFailure::Io {
            path: output.display().to_string(),
            source,
        })?;
    }

    Ok(CompileRun {
        project: args.project.display().to_string(),
        output: output.display().to_string(),
        operations,
        check: args.check,
    })
}

/// One unreadable file, in the compile's own failure type.
fn io_failure(failure: check::CheckFailure) -> CompileFailure {
    let check::CheckFailure::Io { path, source } = failure;
    CompileFailure::Io { path, source }
}

/// The exit class and diagnostics of a compile failure, written by the
/// shared failure path in `lib.rs`.
pub(crate) fn failure(failure: &CompileFailure) -> (u8, Vec<Value>) {
    match failure {
        CompileFailure::Io { path, source } => (
            report::OPERATIONAL_FAILURE_EXIT,
            vec![serde_json::json!({
                "severity": "error",
                "code": "adapterctl.io-failure",
                "artifact": "filesystem",
                "path": path,
                "message": format!("the compiled contract could not be read or written: {source}"),
                "suggestedAction": "Correct the path or permissions, then retry.",
            })],
        ),
        CompileFailure::Drift { path } => (
            report::DOMAIN_REFUSAL_EXIT,
            vec![serde_json::json!({
                "severity": "error",
                "code": "adapterctl.compile.drift",
                "artifact": "compiled-contract",
                "path": path,
                "message": "the written contract drifted from the compiled bytes".to_owned(),
                "suggestedAction": "Run `adapterctl compile` again and commit the regenerated file.",
            })],
        ),
        CompileFailure::Refused { diagnostics } => (
            report::DOMAIN_REFUSAL_EXIT,
            diagnostics
                .iter()
                .map(|diagnostic| {
                    serde_json::to_value(diagnostic).expect("a diagnostic serializes")
                })
                .collect(),
        ),
    }
}
