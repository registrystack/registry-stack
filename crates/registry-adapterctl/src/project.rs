// SPDX-License-Identifier: Apache-2.0

//! `adapterctl project lock`: rewrite a project's profile and pack digest
//! pins from the bytes of the artifacts beside it (CFG-ID-4), the way
//! `bregctl project lock` recomputes module digests. An adopter authors or
//! refreshes the profile or pack, runs the lock, and commits the project
//! with pins that match the bytes; `adapterctl check` holds every pin
//! against those same bytes.

use clap::{Args, Subcommand};
use registry_adapter_core::AdapterProject;
use registry_platform_yaml::{Diagnostic, Digest, FormatSpec, Report};
use std::io;
use std::path::{Path, PathBuf};

use crate::check::{
    digest_of, read, resolve_project, CheckFailure, PACK_FORMAT, PROFILE_FORMAT, PROJECT_FORMAT,
};

#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Compute and write the profile and pack digest pins in project.yaml
    /// from the artifacts beside it.
    Lock(ProjectLockArgs),
}

#[derive(Debug, Args)]
pub struct ProjectLockArgs {
    /// Authored adapter project: its directory (holding `project.yaml`) or
    /// the `project.yaml` file itself.
    #[arg(value_name = "PROJECT")]
    pub project: PathBuf,

    /// Profile file pinned instead of the `profile.yaml` beside the
    /// project.
    #[arg(long, value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Pack file pinned instead of the `pack.yaml` beside the project.
    #[arg(long, value_name = "FILE")]
    pub pack: Option<PathBuf>,
}

/// Why the lock could not run to a verdict.
pub(crate) enum LockFailure {
    /// A required file could not be read or the rewritten project could
    /// not be written: the environment is broken, not the authoring.
    Io { path: String, source: io::Error },
}

/// Whether a lock run rewrote a pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinStatus {
    Unchanged,
    Updated,
}

impl PinStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PinStatus::Unchanged => "unchanged",
            PinStatus::Updated => "updated",
        }
    }
}

/// One lock run's verdict: whether each pin was rewritten, the findings
/// collected, how many files were read, and the project path as given.
pub(crate) struct LockRun {
    pub profile: PinStatus,
    pub pack: PinStatus,
    pub diagnostics: Vec<Diagnostic>,
    pub files_checked: usize,
    pub project: String,
}

/// The pinned block whose digest line the rewriter could not rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinnedBlock {
    Profile,
    Pack,
}

impl PinnedBlock {
    fn pointer(self) -> &'static str {
        match self {
            PinnedBlock::Profile => "/profile/digest",
            PinnedBlock::Pack => "/pack/digest",
        }
    }
}

/// Lock one project. Reads the project, profile, and pack with the same
/// formats and reader as `check`; a workspace the reader refuses is
/// reported and nothing is written. Both pins are computed from the bytes
/// as read before the project text is rewritten, so a refusal leaves the
/// project byte-for-byte as it was.
pub(crate) fn run_lock(args: &ProjectLockArgs) -> Result<LockRun, LockFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    let (project_path, directory) = resolve_project(&args.project);
    let project = read::<AdapterProject>(&project_path, &PROJECT_FORMAT, &mut report, &mut files)
        .map_err(io_failure)?;
    let profile_path = args
        .profile
        .clone()
        .unwrap_or_else(|| directory.join("profile.yaml"));
    let profile = read_artifact::<registry_adapter_core::AdapterProfile>(
        &profile_path,
        &PROFILE_FORMAT,
        &mut report,
        &mut files,
    )?;
    let pack_path = args
        .pack
        .clone()
        .unwrap_or_else(|| directory.join("pack.yaml"));
    let pack = read_artifact::<registry_adapter_core::AdapterPack>(
        &pack_path,
        &PACK_FORMAT,
        &mut report,
        &mut files,
    )?;
    let (Some((_, profile_bytes)), Some((_, pack_bytes))) = (profile, pack) else {
        return Ok(LockRun {
            diagnostics: report.into_diagnostics(),
            files_checked: files,
            profile: PinStatus::Unchanged,
            pack: PinStatus::Unchanged,
            project: args.project.display().to_string(),
        });
    };
    let Some((_, project_bytes)) = project else {
        return Ok(LockRun {
            diagnostics: report.into_diagnostics(),
            files_checked: files,
            profile: PinStatus::Unchanged,
            pack: PinStatus::Unchanged,
            project: args.project.display().to_string(),
        });
    };

    let profile_digest = digest_of(&profile_bytes);
    let pack_digest = digest_of(&pack_bytes);
    let project_text = std::str::from_utf8(&project_bytes).map_err(|source| LockFailure::Io {
        path: project_path.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    let (rewritten, profile_status, pack_status) =
        match pin_digest_lines(project_text, &profile_digest, &pack_digest) {
            Ok(rewritten) => rewritten,
            Err(block) => {
                report.push(layout_finding(block));
                return Ok(LockRun {
                    diagnostics: report.into_diagnostics(),
                    files_checked: files,
                    profile: PinStatus::Unchanged,
                    pack: PinStatus::Unchanged,
                    project: args.project.display().to_string(),
                });
            }
        };
    if profile_status == PinStatus::Updated || pack_status == PinStatus::Updated {
        std::fs::write(&project_path, rewritten.as_bytes()).map_err(|source| LockFailure::Io {
            path: project_path.display().to_string(),
            source,
        })?;
    }
    Ok(LockRun {
        diagnostics: report.into_diagnostics(),
        files_checked: files,
        profile: profile_status,
        pack: pack_status,
        project: args.project.display().to_string(),
    })
}

/// Read one pinned artifact beside the project. A missing or unreadable
/// file is an environment failure; a refused document folds into the
/// report and leaves nothing to pin.
fn read_artifact<T: serde::de::DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
    report: &mut Report,
    files: &mut usize,
) -> Result<crate::check::DecodedFile<T>, LockFailure> {
    read(path, format, report, files).map_err(io_failure)
}

/// The environment failure of the check command, restated as the lock's.
fn io_failure(failure: CheckFailure) -> LockFailure {
    match failure {
        CheckFailure::Io { path, source } => LockFailure::Io { path, source },
    }
}

/// Rewrite the `digest:` line of the `profile` and `pack` blocks from the
/// artifact bytes. The rewriter is deliberately narrow: it edits the block
/// form (`profile:` or `pack:` at the left margin, one indented
/// `digest: sha256:…` member) and refuses anything else, so a rewrite
/// never silently mangles a project it does not understand. Text outside
/// the two digest values, including every comment, is preserved.
fn pin_digest_lines(
    project_text: &str,
    profile_digest: &Digest,
    pack_digest: &Digest,
) -> Result<(String, PinStatus, PinStatus), PinnedBlock> {
    use PinStatus::{Unchanged, Updated};

    let mut section = None::<PinnedBlock>;
    let mut profile_seen = false;
    let mut pack_seen = false;
    let mut profile_status = Unchanged;
    let mut pack_status = Unchanged;
    let mut lines = Vec::new();
    for line in project_text.lines() {
        let trimmed = line.trim_start();
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank lines and comments keep the open block.
            lines.push(line.to_owned());
            continue;
        }
        if indented {
            // Indented lines outside the two pinned blocks are none of the
            // rewriter's business; the blocks themselves are required, and
            // a missing one is refused after the walk.
            let Some(block) = section else {
                lines.push(line.to_owned());
                continue;
            };
            if let Some(new_line) = pinned_digest_line(line, block, profile_digest, pack_digest)? {
                if block == PinnedBlock::Profile {
                    if profile_status == Updated {
                        return Err(PinnedBlock::Profile);
                    }
                    profile_status = Updated;
                } else {
                    if pack_status == Updated {
                        return Err(PinnedBlock::Pack);
                    }
                    pack_status = Updated;
                }
                lines.push(new_line);
            } else {
                lines.push(line.to_owned());
            }
            continue;
        }
        // A left-margin line closes the open block and may open the next.
        section = None;
        if let Some((key, rest)) = line.split_once(':') {
            let block = match key {
                "profile" => Some(PinnedBlock::Profile),
                "pack" => Some(PinnedBlock::Pack),
                _ => None,
            };
            if let Some(block) = block {
                if rest.trim().is_empty() {
                    section = Some(block);
                    match block {
                        PinnedBlock::Profile => profile_seen = true,
                        PinnedBlock::Pack => pack_seen = true,
                    }
                } else {
                    // Flow or anchored form: the digest line is not where
                    // the rewriter expects it.
                    return Err(block);
                }
            }
        }
        lines.push(line.to_owned());
    }
    if !profile_seen {
        return Err(PinnedBlock::Profile);
    }
    if !pack_seen {
        return Err(PinnedBlock::Pack);
    }
    let newline = if project_text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut rewritten = lines.join(newline);
    if project_text.ends_with('\n') {
        rewritten.push_str(newline);
    }
    Ok((rewritten, profile_status, pack_status))
}

/// The rewritten digest line of one pinned block, or `None` for a line the
/// block carries that is not its digest member.
fn pinned_digest_line(
    line: &str,
    block: PinnedBlock,
    profile_digest: &Digest,
    pack_digest: &Digest,
) -> Result<Option<String>, PinnedBlock> {
    let member = line.trim_start();
    let Some(rest) = member.strip_prefix("digest:") else {
        return Ok(None);
    };
    let indent = &line[..line.len() - member.len()];
    let value = rest.trim_start();
    let pinned = match block {
        PinnedBlock::Profile => profile_digest,
        PinnedBlock::Pack => pack_digest,
    };
    // The digest token must be the whole unquoted value; a trailing
    // comment survives the rewrite.
    let (current, comment) = match value.split_once(" #") {
        Some((value, comment)) => (value, Some(comment)),
        None => (value, None),
    };
    if !is_bare_sha256_uri(current) {
        return Err(block);
    }
    // A pin that already matches the bytes stays as written: a fresh
    // project is rewritten byte-for-byte never.
    if current == pinned.as_str() {
        return Ok(None);
    }
    let mut new_line = format!("{indent}digest: {}", pinned.as_str());
    if let Some(comment) = comment {
        new_line.push_str(" #");
        new_line.push_str(comment);
    }
    Ok(Some(new_line))
}

/// Whether one digest value is exactly the pinned uri form, unquoted and
/// comment-free.
fn is_bare_sha256_uri(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The layout refusal for one pinned block. Value-free (CFG-SEC-3): the
/// message names the rule, never the project's contents.
fn layout_finding(block: PinnedBlock) -> Diagnostic {
    Diagnostic::error(
        "adapterctl.project-lock-layout",
        block.pointer(),
        "the digest pin is not in the block form the lock rewrites",
        "Write the pinned artifact as a block mapping with one indented digest line, or pin its digest by hand.",
    )
}
