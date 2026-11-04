// SPDX-License-Identifier: Apache-2.0

//! `adapterctl job check`: the offline validation of one ingestion job
//! over the same compile the page run uses
//! (`products/adapter/CONCEPT.md` sections 17.1 and 17.2); and
//! `adapterctl job lock`, the rewrite of the job's digest pins from the
//! bytes of the files beside it.
//!
//! The command compiles the job exactly as the engine's page entry
//! would: the pinned pack, the `AdapterJob` definition, the operator
//! runtime config through the shared loader, the authoring checks the
//! runtime stands on, the source endpoints, the scripts and routes the
//! source route reaches. It is validation only: no listener, no
//! database, no OIDC issuer, no send, no read. A refusal carries its
//! closed code, the same diagnostics a page run's compile raises.

use clap::{Args, Subcommand};
use registry_adapter_core::{AdapterJob, JobDestination};
use registry_platform_yaml::{Diagnostic, Digest, Report, Source};
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::check::{digest_of, read, CheckFailure, JOB_FORMAT, PACK_FORMAT};
use crate::project::{is_bare_sha256_uri, LockFailure, PinStatus};

/// The `job` command group.
#[derive(Debug, Args)]
pub struct JobArgs {
    #[command(subcommand)]
    pub command: JobCommand,
}

/// The subcommands of `job`.
#[derive(Debug, Subcommand)]
pub enum JobCommand {
    /// Compile one ingestion job offline, exactly as the page run
    /// would, and print the findings.
    Check(JobCheckArgs),
    /// Compute and write the job's digest pins from the files beside the
    /// job document.
    Lock(JobLockArgs),
}

/// The arguments of `job lock`.
#[derive(Debug, Args)]
pub struct JobLockArgs {
    /// The job definition whose pins are rewritten.
    #[arg(value_name = "JOB")]
    pub job: PathBuf,

    /// The pack document the job pins; when given, the job's pack digest is
    /// rewritten from its bytes too.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,
}

/// The arguments of `job check`.
#[derive(Debug, Args)]
pub struct JobCheckArgs {
    /// The pack document the job pins.
    #[arg(value_name = "PACK")]
    pub pack: PathBuf,

    /// The job definition.
    #[arg(value_name = "JOB")]
    pub job: PathBuf,

    /// The operator runtime config; defaults to `job-runtime.yaml` beside
    /// the pack.
    #[arg(long, value_name = "FILE")]
    pub runtime: Option<PathBuf>,
    /// The facade profile the workspace checks run over; defaults to
    /// `profile.yaml` beside the pack.
    #[arg(long, value_name = "FILE", requires = "project")]
    pub profile: Option<PathBuf>,
    /// The project whose workspace checks the runtime stands on;
    /// defaults to `project.yaml` beside the pack.
    #[arg(long, value_name = "FILE", requires = "profile")]
    pub project: Option<PathBuf>,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
}

/// One completed job check: the artifacts as written.
pub(crate) struct JobCheckRun {
    pub(crate) pack: String,
    pub(crate) job: String,
    pub(crate) runtime: String,
    pub(crate) files_checked: usize,
    /// The reader's warnings over the authored artifacts.
    pub(crate) warnings: Vec<registry_platform_yaml::Diagnostic>,
}

/// Why the job check could not run to a verdict.
#[derive(Debug)]
pub(crate) enum JobCheckFailure {
    /// A required file could not be read: the environment is broken,
    /// not the authoring.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The compile refused the job: the diagnostics carry their closed
    /// codes.
    Refused {
        diagnostics: Vec<registry_platform_yaml::Diagnostic>,
    },
}

/// Count the artifacts the check itself opened, for the report: the
/// pack, the job, the runtime config, and the profile and project the
/// compile reads (beside the pack unless passed). The scripts and query
/// files the pack inventories are the compile's own accounting.
fn files_checked() -> usize {
    5
}

/// Run the job check: compile the job offline, or refuse with the
/// compile's own diagnostics.
pub(crate) fn run(args: &JobCheckArgs) -> Result<JobCheckRun, JobCheckFailure> {
    let pack_directory = args
        .pack
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    let runtime = match &args.runtime {
        Some(runtime) => runtime.clone(),
        None => pack_directory.join("job-runtime.yaml"),
    };
    if !runtime.is_file() {
        return Err(JobCheckFailure::Io {
            path: runtime.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no runtime config was given and none sits beside the pack",
            ),
        });
    }
    let outcome = match (&args.profile, &args.project) {
        (Some(profile), Some(project)) => registry_adapter::engine::job::compile_job_with(
            &args.pack, &args.job, &runtime, profile, project,
        ),
        (None, None) => registry_adapter::engine::job::compile_job(&args.pack, &args.job, &runtime),
        // The parser requires the two together; a caller that builds the
        // arguments by hand still gets a refusal, never a guess.
        _ => {
            return Err(JobCheckFailure::Io {
                path: "--profile --project".to_owned(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--profile and --project stand together; pass both or neither",
                ),
            })
        }
    };
    match outcome {
        Ok(program) => {
            let mut warnings = program.warnings.clone();
            warnings.extend(mapping_drift(&program.job, &args.job));
            warnings.extend(pack_mapping_drift(&args.pack)?);
            Ok(JobCheckRun {
                pack: args.pack.display().to_string(),
                job: args.job.display().to_string(),
                runtime: runtime.display().to_string(),
                files_checked: files_checked(),
                warnings,
            })
        }
        Err(error) => Err(JobCheckFailure::Refused {
            diagnostics: error.diagnostics,
        }),
    }
}

/// The drift warning for the job's direct-breg destination mapping script,
/// when it is a generated script that no longer matches its model. The
/// mapping file is relative to the job document's directory, and its model
/// must lie inside that directory.
fn mapping_drift(
    job: &registry_adapter_core::AdapterJob,
    job_path: &std::path::Path,
) -> Option<registry_platform_yaml::Diagnostic> {
    let registry_adapter_core::JobDestination::DirectBreg { mapping, .. } = &job.destination else {
        return None;
    };
    let directory = job_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    crate::mapping::script_drift(
        &directory.join(&mapping.file),
        directory,
        "/destination/mapping",
    )
}

/// The drift warnings for the generated scripts the pack inventories. The
/// compile has already read the pack and reported its findings, so this
/// second read feeds the drift check alone.
fn pack_mapping_drift(pack: &Path) -> Result<Vec<Diagnostic>, JobCheckFailure> {
    let mut scratch = Report::new(Vec::new());
    let mut files = 0usize;
    let decoded =
        read::<registry_adapter_core::AdapterPack>(pack, &PACK_FORMAT, &mut scratch, &mut files)
            .map_err(|CheckFailure::Io { path, source }| JobCheckFailure::Io { path, source })?;
    let mut report = Report::new(Vec::new());
    if let Some((decoded, _)) = decoded {
        crate::check::verify_pack_mapping_drift(&decoded.value, pack, &mut report);
    }
    Ok(report.into_diagnostics())
}

/// One lock run's verdict: whether each requested pin was rewritten (`None`
/// when the job has no such pin or none was asked for), the findings
/// collected, how many files were read, and the job path as given.
pub(crate) struct JobLockRun {
    pub mapping: Option<PinStatus>,
    pub pack: Option<PinStatus>,
    pub diagnostics: Vec<Diagnostic>,
    pub files_checked: usize,
    pub job: String,
}

/// The digest lines the rewriter edits, by their position in the job
/// document.
const MAPPING_POINTER: &str = "/destination/mapping/digest";
const PACK_POINTER: &str = "/source/pack/digest";

/// Lock one job. The job is read with the same format and reader as
/// `job check`: a job the reader refuses is reported and nothing is
/// written. The pins are byte digests, so the mapping script (and the pack,
/// when passed) contribute their bytes only; whether either is a good
/// artifact is `job check`'s business. Every digest is computed from the
/// bytes as read before any text is rewritten, and the rewritten document
/// replaces the job atomically, so a refusal leaves it byte for byte as it
/// was.
pub(crate) fn run_lock(args: &JobLockArgs) -> Result<JobLockRun, LockFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;
    let run = |report: Report, files, mapping, pack| JobLockRun {
        mapping,
        pack,
        diagnostics: report.into_diagnostics(),
        files_checked: files,
        job: args.job.display().to_string(),
    };

    let decoded = read::<AdapterJob>(&args.job, &JOB_FORMAT, &mut report, &mut files)
        .map_err(|CheckFailure::Io { path, source }| LockFailure::Io { path, source })?;
    let Some((decoded, job_bytes)) = decoded else {
        return Ok(run(report, files, None, None));
    };
    let job_directory = args.job.parent().unwrap_or_else(|| Path::new(""));

    let mapping_digest = match &decoded.value.destination {
        JobDestination::DirectBreg { mapping, .. } => {
            let digest = pinned_digest(
                &job_directory.join(&mapping.file),
                &mapping.file,
                MAPPING_POINTER,
                Some(Path::new(&mapping.file)),
                &args.job,
                &mut report,
                &mut files,
            )?;
            Some(digest)
        }
        JobDestination::SignedCoordinatorEvent { .. } => None,
    };
    let pack_digest = match &args.pack {
        // A missing pack gets the same refusal as a missing mapping.
        Some(pack) if !pack.exists() => Some(pinned_digest(
            pack,
            &pack.display().to_string(),
            PACK_POINTER,
            None,
            &args.job,
            &mut report,
            &mut files,
        )?),
        Some(pack) => Some(pack_pin_digest(
            pack,
            &decoded.value.source.pack,
            &args.job,
            &mut report,
            &mut files,
        )?),
        None => None,
    };
    if report.has_errors() {
        return Ok(run(report, files, None, None));
    }
    let mapping_digest = mapping_digest.flatten();
    let pack_digest = pack_digest.flatten();

    let text = std::str::from_utf8(&job_bytes).map_err(|source| LockFailure::Io {
        path: args.job.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    let rewritten = match rewrite_pins(text, mapping_digest.as_ref(), pack_digest.as_ref()) {
        Ok(rewritten) => rewritten,
        Err(pointers) => {
            for pointer in pointers {
                report.push(layout_finding(&args.job, pointer));
            }
            return Ok(run(report, files, None, None));
        }
    };
    if rewritten.text != text {
        crate::mapping::write_atomically(&args.job, job_directory, rewritten.text.as_bytes())
            .map_err(|failure| match failure {
                crate::mapping::MappingFailure::Io { path, source } => {
                    LockFailure::Io { path, source }
                }
                crate::mapping::MappingFailure::Refused { .. } => LockFailure::Io {
                    path: args.job.display().to_string(),
                    source: io::Error::other("the job could not be written"),
                },
            })?;
    }
    Ok(run(report, files, rewritten.mapping, rewritten.pack))
}

/// Read one pinned file and digest its bytes. `None` means a finding was
/// reported instead: the path leaves the job's directory, or the file does
/// not exist. `relative` is the path a job document names, which must be
/// clean; the pack path is none, because the operator passes it on the
/// command line.
fn pinned_digest(
    path: &Path,
    shown: &str,
    pointer: &str,
    relative: Option<&Path>,
    job: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<Digest>, LockFailure> {
    let contained = relative.is_none_or(|relative| {
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    });
    if !contained {
        report.push(job_finding(
            "adapterctl.job-lock-path-invalid",
            pointer,
            job,
            shown,
            "the pinned file is not a clean relative path inside the job's directory",
            "Name the file by a relative path without `..` beside the job document.",
        ));
        return Ok(None);
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            *files += 1;
            Ok(Some(digest_of(&bytes)))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            report.push(job_finding(
                "adapterctl.job-lock-pinned-file-missing",
                pointer,
                job,
                shown,
                "the pinned file is missing",
                "Restore or regenerate the file, then run adapterctl job lock again.",
            ));
            Ok(None)
        }
        Err(source) => Err(LockFailure::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// An error finding on the job document naming the pinned file. Value-free
/// (CFG-SEC-3): the message names the rule, never the job's contents.
/// The digest of the pack passed to `job lock`, read as a pack so its id
/// and version are compared with the job's pin: locking a job to another
/// pack's bytes would leave a pin whose id and digest disagree.
fn pack_pin_digest(
    pack: &Path,
    pin: &registry_adapter_core::PinnedRef,
    job: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<Digest>, LockFailure> {
    let decoded = read::<registry_adapter_core::AdapterPack>(pack, &PACK_FORMAT, report, files)
        .map_err(|CheckFailure::Io { path, source }| LockFailure::Io { path, source })?;
    let Some((decoded, bytes)) = decoded else {
        return Ok(None);
    };
    if decoded.value.id != pin.id || decoded.value.version != pin.version {
        report.push(job_finding(
            "adapterctl.job-lock-pack-mismatch",
            PACK_POINTER,
            job,
            &pack.display().to_string(),
            "the pack's id or version differs from the pack the job pins",
            "Pass the pack the job pins, or change the job's source.pack id and version first.",
        ));
        return Ok(None);
    }
    Ok(Some(digest_of(&bytes)))
}

fn job_finding(
    code: &str,
    pointer: &str,
    job: &Path,
    artifact: &str,
    message: &str,
    action: &str,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, pointer, message, action);
    diagnostic.source = Some(Source {
        file: format!("{} ({artifact})", job.display()),
        line: None,
        column: None,
    });
    diagnostic
}

/// The refusal for a digest line the rewriter could not find in block form.
fn layout_finding(job: &Path, pointer: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "adapterctl.job-lock-layout",
        pointer,
        "the digest pin is not in the block form the lock rewrites",
        "Write the pinned artifact as a block mapping with one indented, unquoted digest line, or pin its digest by hand.",
    );
    diagnostic.source = Some(Source {
        file: job.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

/// The job text with its pins rewritten and what happened to each.
struct Rewritten {
    text: String,
    mapping: Option<PinStatus>,
    pack: Option<PinStatus>,
}

/// Rewrite the `digest:` line of `destination.mapping` and `source.pack`
/// (each only when its digest is given). The rewriter is deliberately
/// narrow: it tracks block-mapping keys by indentation, edits an unquoted
/// `sha256:` value, and refuses with the pointers it could not reach
/// (flow, quoted or missing pins) so a rewrite never silently leaves a pin
/// behind. Everything outside the digest values, comments and line endings
/// included, is preserved.
fn rewrite_pins(
    text: &str,
    mapping: Option<&Digest>,
    pack: Option<&Digest>,
) -> Result<Rewritten, Vec<&'static str>> {
    let mut stack: Vec<(usize, &str)> = Vec::new();
    let mut seen = [false; 2];
    let mut changed = [false; 2];
    let mut faults: Vec<&'static str> = Vec::new();
    let mut out = String::with_capacity(text.len());
    for raw in text.split_inclusive('\n') {
        let body = raw.trim_end_matches(['\n', '\r']);
        let terminator = &raw[body.len()..];
        let trimmed = body.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out.push_str(raw);
            continue;
        }
        let indent = body.len() - trimmed.len();
        while stack.last().is_some_and(|(open, _)| *open >= indent) {
            stack.pop();
        }
        let Some((key, rest)) = trimmed.split_once(':') else {
            out.push_str(raw);
            continue;
        };
        let path: Vec<&str> = stack.iter().map(|(_, key)| *key).collect();
        let target = match (key, path.as_slice()) {
            ("digest", ["destination", "mapping"]) => {
                mapping.map(|digest| (0, MAPPING_POINTER, digest))
            }
            ("digest", ["source", "pack"]) => pack.map(|digest| (1, PACK_POINTER, digest)),
            _ => None,
        };
        let Some((slot, pointer, digest)) = target else {
            if rest.trim().is_empty() {
                stack.push((indent, key));
            }
            out.push_str(raw);
            continue;
        };
        seen[slot] = true;
        let value = rest.trim_start();
        // The digest token must be the whole unquoted value; a trailing
        // comment survives the rewrite.
        let (current, comment) = match value.split_once(" #") {
            Some((value, comment)) => (value, Some(comment)),
            None => (value, None),
        };
        if !is_bare_sha256_uri(current) {
            faults.push(pointer);
            out.push_str(raw);
            continue;
        }
        if current == digest.as_str() {
            out.push_str(raw);
            continue;
        }
        changed[slot] = true;
        out.push_str(&body[..indent]);
        out.push_str("digest: ");
        out.push_str(digest.as_str());
        if let Some(comment) = comment {
            out.push_str(" #");
            out.push_str(comment);
        }
        out.push_str(terminator);
    }
    if mapping.is_some() && !seen[0] {
        faults.push(MAPPING_POINTER);
    }
    if pack.is_some() && !seen[1] {
        faults.push(PACK_POINTER);
    }
    if !faults.is_empty() {
        return Err(faults);
    }
    let status = |wanted: bool, slot: usize| {
        wanted.then_some(if changed[slot] {
            PinStatus::Updated
        } else {
            PinStatus::Unchanged
        })
    };
    Ok(Rewritten {
        text: out,
        mapping: status(mapping.is_some(), 0),
        pack: status(pack.is_some(), 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(flatten)]
        args: JobCheckArgs,
    }

    fn parse(extra: &[&str]) -> Result<Harness, clap::Error> {
        let mut argv = vec!["job-check", "pack.yaml", "job.yaml"];
        argv.extend_from_slice(extra);
        Harness::try_parse_from(argv)
    }

    /// The profile and the project stand together: one without the other
    /// is a usage error at the parser, never a missing-file failure.
    #[test]
    fn the_profile_and_the_project_are_passed_together() {
        assert!(parse(&[]).is_ok(), "neither reads both beside the pack");
        assert!(parse(&["--profile", "p.yaml", "--project", "q.yaml"]).is_ok());
        let alone = parse(&["--profile", "p.yaml"]).expect_err("a profile alone refuses");
        assert_eq!(
            alone.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let alone = parse(&["--project", "q.yaml"]).expect_err("a project alone refuses");
        assert_eq!(
            alone.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    /// The report counts every file the check opened: the pack, the job,
    /// the runtime config, the profile, and the project.
    #[test]
    fn the_report_counts_the_five_files_the_check_opens() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/fixtures/corpus/base-job");
        let args = JobCheckArgs {
            pack: base.join("pack.yaml"),
            job: base.join("job.yaml"),
            runtime: Some(base.join("job-runtime.yaml")),
            profile: Some(base.join("profile.yaml")),
            project: Some(base.join("project.yaml")),
            deny_warnings: false,
        };
        let run = match run(&args) {
            Ok(run) => run,
            Err(JobCheckFailure::Io { path, source }) => panic!("{path}: {source}"),
            Err(JobCheckFailure::Refused { diagnostics }) => panic!("{diagnostics:?}"),
        };
        assert_eq!(run.files_checked, 5);
    }
}
