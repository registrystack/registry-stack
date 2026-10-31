// SPDX-License-Identifier: Apache-2.0

//! `adapterctl project lock`: rewrite a project's profile and pack digest
//! pins, and the pack's script and query-file digest pins, from the bytes
//! of the artifacts beside them (CFG-ID-4), the way `bregctl project
//! lock` recomputes module digests. An adopter authors or refreshes the
//! profile, the pack, or a pinned script, runs the lock, and commits with
//! pins that match the bytes; `adapterctl check` holds every pin against
//! those same bytes.

use clap::{Args, Subcommand};
use registry_adapter_core::{AdapterPack, AdapterProject};
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::{Diagnostic, Digest, Expect, Reader, Report, Source};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use crate::check::{
    digest_of, pin_finding, read, resolve_project, CheckFailure, PACK_FORMAT, PROJECT_FORMAT,
};

#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Compute and write the profile and pack digest pins in project.yaml,
    /// and the pack's script and query-file digest pins, from the
    /// artifacts beside them.
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
    /// Whether the pack's script and query-file digest lines were
    /// rewritten from the files beside the pack document.
    pub inventory: PinStatus,
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

/// Lock one project. Reads the project with the same format and reader as
/// `check`: a project the reader refuses is reported and nothing is
/// written. The pins are byte digests, so the profile and pack contribute
/// their bytes only; whether either artifact is a good one is `check`'s
/// business. The pack is decoded quietly to learn its inventory, never to
/// judge it: a pack that does not decode cannot name its files, so its
/// inventory pins stay and a warning says so. The inventory pins are
/// rewritten first and the pack digest is computed from the pack bytes as
/// they will sit on disk, so one run leaves every pin matching the bytes.
/// The pins are computed from the bytes as read before any text is
/// rewritten, so a refusal leaves every document byte-for-byte as it was.
pub(crate) fn run_lock(args: &ProjectLockArgs) -> Result<LockRun, LockFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;

    let (project_path, directory) = resolve_project(&args.project);
    let project = read::<AdapterProject>(&project_path, &PROJECT_FORMAT, &mut report, &mut files)
        .map_err(io_failure)?;
    let profile_path = crate::check::artifact_path(
        args.profile.as_deref(),
        &directory,
        "profile.yaml",
        "--profile",
    )
    .map_err(io_failure)?;
    let profile_bytes = read_pinned(&profile_path, &mut files)?;
    let pack_path =
        crate::check::artifact_path(args.pack.as_deref(), &directory, "pack.yaml", "--pack")
            .map_err(io_failure)?;
    let pack_bytes = read_pinned(&pack_path, &mut files)?;
    let Some((_, project_bytes)) = project else {
        return Ok(LockRun {
            diagnostics: report.into_diagnostics(),
            files_checked: files,
            profile: PinStatus::Unchanged,
            pack: PinStatus::Unchanged,
            inventory: PinStatus::Unchanged,
            project: args.project.display().to_string(),
        });
    };

    let decoded_pack = decode_pack_quietly(&pack_bytes, &pack_path, &mut report);
    let (pack_bytes, inventory_status) = match &decoded_pack {
        Some(pack) => {
            match repin_pack_inventory(pack, &pack_path, &pack_bytes, &mut report, &mut files)? {
                InventoryRewrite::Rewritten(bytes) => (bytes, PinStatus::Updated),
                InventoryRewrite::Unchanged(bytes) => (bytes, PinStatus::Unchanged),
                InventoryRewrite::Refused => {
                    return Ok(LockRun {
                        diagnostics: report.into_diagnostics(),
                        files_checked: files,
                        profile: PinStatus::Unchanged,
                        pack: PinStatus::Unchanged,
                        inventory: PinStatus::Unchanged,
                        project: args.project.display().to_string(),
                    });
                }
            }
        }
        None => (pack_bytes, PinStatus::Unchanged),
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
                    inventory: PinStatus::Unchanged,
                    project: args.project.display().to_string(),
                });
            }
        };
    // The pack is written before the project: the project's pack pin
    // digests the pack bytes, so a run stopped between the two writes
    // converges on the next one.
    if inventory_status == PinStatus::Updated {
        std::fs::write(&pack_path, &pack_bytes).map_err(|source| LockFailure::Io {
            path: pack_path.display().to_string(),
            source,
        })?;
    }
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
        inventory: inventory_status,
        project: args.project.display().to_string(),
    })
}

/// Read one pinned artifact's bytes. A missing or unreadable file is an
/// environment failure. The content is never decoded or judged here.
fn read_pinned(path: &Path, files: &mut usize) -> Result<Vec<u8>, LockFailure> {
    let bytes = std::fs::read(path).map_err(|source| LockFailure::Io {
        path: path.display().to_string(),
        source,
    })?;
    *files += 1;
    Ok(bytes)
}

/// The environment failure of the check command, restated as the lock's.
fn io_failure(failure: CheckFailure) -> LockFailure {
    match failure {
        CheckFailure::Io { path, source } => LockFailure::Io { path, source },
    }
}

/// The outcome of the inventory half of a lock run.
enum InventoryRewrite {
    /// The pack text rewritten to the digests the pinned files hash to.
    Rewritten(Vec<u8>),
    /// Every inventory pin already matches the file bytes.
    Unchanged(Vec<u8>),
    /// The inventory could not be rewritten; the findings name why, and
    /// nothing is written.
    Refused,
}

/// Decode the pack bytes the way `check` reads them, without reporting the
/// reader's findings: the lock needs the inventory's shape, not the
/// reader's verdict. `None` means the pack does not decode, so it cannot
/// name the files it pins; the warning says so, and the pins stay with
/// the bytes.
fn decode_pack_quietly(
    pack_bytes: &[u8],
    pack_path: &Path,
    report: &mut Report,
) -> Option<AdapterPack> {
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(pack_path.display().to_string())
        .with_hook(&mut hook)
        .decode::<AdapterPack>(pack_bytes, &Expect::one(&PACK_FORMAT));
    match decoded {
        Ok(decoded) => Some(decoded.value),
        Err(_) => {
            report.push(pack_not_decoded_warning(pack_path));
            None
        }
    }
}

/// Repin the pack's script and query-file digest lines from the files
/// beside the pack document. Every file the inventory names is read even
/// after one is missing, so one pass names everything to fix; a missing
/// file refuses the run, because there is nothing to hash. The rewrite is
/// the same narrow line discipline as the project's pins, and a fault
/// refuses the run with nothing written.
fn repin_pack_inventory(
    pack: &AdapterPack,
    pack_path: &Path,
    pack_bytes: &[u8],
    report: &mut Report,
    files: &mut usize,
) -> Result<InventoryRewrite, LockFailure> {
    let mut resolved = Vec::new();
    let mut counted: BTreeSet<PathBuf> = BTreeSet::new();
    let mut missing = false;
    for (section, entries) in [
        ("scripts", &pack.scripts),
        ("queryFiles", &pack.query_files),
    ] {
        for (index, entry) in entries.iter().enumerate() {
            let path = pack_path
                .parent()
                .map(|directory| directory.join(&entry.path))
                .unwrap_or_else(|| PathBuf::from(&entry.path));
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    let pointer = format!("/{section}/{index}");
                    report.push(pin_finding(
                        pack_path,
                        &pointer,
                        "the pinned file is missing",
                        "Restore the file beside the pack document, or update its sha256 digest pin.",
                        &entry.path,
                    ));
                    missing = true;
                    continue;
                }
                Err(source) => {
                    return Err(LockFailure::Io {
                        path: path.display().to_string(),
                        source,
                    })
                }
            };
            if counted.insert(path) {
                *files += 1;
            }
            resolved.push((section, index, digest_of(&bytes)));
        }
    }
    if missing {
        return Ok(InventoryRewrite::Refused);
    }
    let text = std::str::from_utf8(pack_bytes).map_err(|source| LockFailure::Io {
        path: pack_path.display().to_string(),
        source: io::Error::new(io::ErrorKind::InvalidData, source),
    })?;
    let (rewritten, status) = match rewrite_inventory_lines(text, &resolved) {
        Ok(rewritten) => rewritten,
        Err(faults) => {
            for pointer in faults {
                report.push(inventory_layout_finding(&pointer));
            }
            return Ok(InventoryRewrite::Refused);
        }
    };
    match status {
        PinStatus::Updated => Ok(InventoryRewrite::Rewritten(rewritten.into_bytes())),
        PinStatus::Unchanged => Ok(InventoryRewrite::Unchanged(pack_bytes.to_vec())),
    }
}

/// One inventory pin the walk expects: its section (`scripts` or
/// `queryFiles`), its index there, and the digest its file hashes to.
type InventoryPin<'a> = (&'a str, usize, Digest);

/// Rewrite the inventory digest lines from the digests the pinned files
/// hash to. The rewriter is deliberately narrow, like the project pins:
/// within a `scripts:` or `queryFiles:` section it edits the block form (a
/// `- ` list item, one indented `digest: sha256:…` member) and refuses
/// anything else, including a decoded entry whose digest line the walk
/// never saw, so a rewrite never silently leaves a pin it could not
/// reach. Text outside the digest values, including every comment, is
/// preserved.
fn rewrite_inventory_lines(
    pack_text: &str,
    resolved: &[InventoryPin],
) -> Result<(String, PinStatus), Vec<String>> {
    use PinStatus::{Unchanged, Updated};

    let expected: BTreeMap<(&str, usize), &Digest> = resolved
        .iter()
        .map(|(section, index, digest)| ((*section, *index), digest))
        .collect();
    let mut section = None::<&str>;
    let mut entry = None::<usize>;
    let mut items: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen: BTreeSet<(&str, usize)> = BTreeSet::new();
    let mut faults: Vec<String> = Vec::new();
    let mut updated = false;
    let mut lines = Vec::new();
    for line in pack_text.lines() {
        let trimmed = line.trim_start();
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // Blank lines and comments keep the open section and entry.
            lines.push(line.to_owned());
            continue;
        }
        if !indented {
            // A left-margin line closes the open section and may open the
            // next. A flow or anchored section carries no block digest
            // lines; the completeness walk below refuses it when the
            // inventory is non-empty.
            section = None;
            entry = None;
            if let Some((key, rest)) = line.split_once(':') {
                if matches!(key, "scripts" | "queryFiles") && rest.trim().is_empty() {
                    section = Some(key);
                }
            }
            lines.push(line.to_owned());
            continue;
        }
        let Some(open_section) = section else {
            lines.push(line.to_owned());
            continue;
        };
        if trimmed == "-" || trimmed.starts_with("- ") {
            let next = items.entry(open_section).or_insert(0);
            entry = Some(*next);
            *next += 1;
            lines.push(line.to_owned());
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("digest:") else {
            lines.push(line.to_owned());
            continue;
        };
        let Some(index) = entry else {
            faults.push(format!("/{open_section}/0/digest"));
            lines.push(line.to_owned());
            continue;
        };
        seen.insert((open_section, index));
        let Some(digest) = expected.get(&(open_section, index)) else {
            faults.push(format!("/{open_section}/{index}/digest"));
            lines.push(line.to_owned());
            continue;
        };
        let indent = &line[..line.len() - trimmed.len()];
        let value = rest.trim_start();
        // The digest token must be the whole unquoted value; a trailing
        // comment survives the rewrite.
        let (current, comment) = match value.split_once(" #") {
            Some((value, comment)) => (value, Some(comment)),
            None => (value, None),
        };
        if !is_bare_sha256_uri(current) {
            faults.push(format!("/{open_section}/{index}/digest"));
            lines.push(line.to_owned());
            continue;
        }
        if current == digest.as_str() {
            lines.push(line.to_owned());
            continue;
        }
        let mut new_line = format!("{indent}digest: {}", digest.as_str());
        if let Some(comment) = comment {
            new_line.push_str(" #");
            new_line.push_str(comment);
        }
        updated = true;
        lines.push(new_line);
    }
    let mut unreached: BTreeSet<&str> = BTreeSet::new();
    for (section, index, _) in resolved {
        if !seen.contains(&(*section, *index)) {
            unreached.insert(section);
        }
    }
    for section in unreached {
        faults.push(format!("/{section}"));
    }
    if !faults.is_empty() {
        return Err(faults);
    }
    let newline = if pack_text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut rewritten = lines.join(newline);
    if pack_text.ends_with('\n') {
        rewritten.push_str(newline);
    }
    Ok((rewritten, if updated { Updated } else { Unchanged }))
}

/// The layout refusal for one inventory pin. Value-free (CFG-SEC-3): the
/// message names the rule, never the pack's contents.
fn inventory_layout_finding(pointer: &str) -> Diagnostic {
    Diagnostic::error(
        "adapterctl.project-lock-layout",
        pointer,
        "the digest pin is not in the block form the lock rewrites",
        "Write the pack's inventory entries as block mappings with one indented digest line each, or pin their digests by hand.",
    )
}

/// The warning for a pack that does not decode: the lock cannot learn the
/// inventory it would repin, and says so instead of skipping in silence.
fn pack_not_decoded_warning(pack_path: &Path) -> Diagnostic {
    let mut diagnostic = Diagnostic::warning(
        "adapterctl.pack-not-decoded",
        "",
        "the pack does not decode, so its inventory digest pins were not rewritten",
        "Run adapterctl check for the pack's findings, then run adapterctl project lock again.",
    );
    diagnostic.source = Some(Source {
        file: pack_path.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
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
