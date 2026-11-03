// SPDX-License-Identifier: Apache-2.0

//! The `file` source of the governed-ingestion read step, the bounded
//! read-only port of camel-file
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2).
//!
//! One read considers the candidates of one base directory: the files
//! directly under it (non-recursive; Camel's `recursive` is not
//! ported), matched by the Ant-style `include` glob when declared
//! (camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/AntPathMatcherFileFilter.java
//! over
//! camel-4.23.0:core/camel-util/src/main/java/org/apache/camel/util/AntPathMatcher.java),
//! sorted by name ascending (an addition: Camel ships no default
//! sorter, and the cursor's resume order needs a stable one), hidden
//! files refused (names beginning with a dot, Camel's own default
//! posture,
//! camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileConsumer.java,
//! `isMatchedHiddenFile`, which also keeps `.camelLock` and editor
//! backups out of the data), and, when the source declares
//! `doneFileName`, admitted only while its done file exists
//! (camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/FileConsumer.java,
//! `isMatched`, and
//! camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/GenericFileEndpoint.java,
//! `createDoneFileName` and `isDoneFile`). A done file itself is never
//! a candidate.
//!
//! Ported divergences, each with its reason: `markerFile`, `fileLock`,
//! `rename`, `delete`, `move`, `preMove`, `moveFailed`, and
//! `idempotent-rename` are not ported because each writes, locks, or
//! renames the source, and this read is read-only always; the `changed`
//! read lock keeps camel-4.23.0's FileChangedExclusiveReadLockStrategy
//! semantics (length and last-modified stable across two checks spaced
//! the check interval apart, inside the timeout) but raises a timeout
//! instead of silently skipping the file, because a skipped file reads
//! as a completed scan and nothing is silently skipped here, and it
//! locks a stable empty file instead of keeping Camel's `minLength` 1,
//! because an empty file that never locks would raise on every poll and
//! block the candidates after it; and Camel's `noop` implies `idempotent`, suppressing
//! re-reads of a consumed file, which WE DIVERGE from: the read never
//! suppresses re-reads, the item table owns identity, and a second read
//! of unchanged content returns the same items (raw files use the
//! namespace-plus-digest key; decoded rows use their declared business key).
//!
//! Paging (original work, recorded simplification): one read processes
//! at most one file, the first candidate the cursor has not passed. The
//! cursor carries the processed file's digest, the byte offset after
//! the last emitted row, and that file's name as `resumeAfter`; the
//! next read resumes the named file at its offset while its bytes still
//! carry the pinned digest, passes it for the next candidate once its
//! offset stands at or past its end, reads it again from zero when its
//! content changed (the new digest starts the new bytes from zero, while
//! decoded rows retain their business-key identity), and otherwise starts at the first candidate after the
//! resume name. A cursor past every candidate, or a last candidate
//! finished, ends a finite scan: `next` is absent. An ongoing scan keeps
//! its place at the tail instead: the last file's page and every empty
//! read after it carry a cursor, so the next pass reads only files that
//! sort after it. `maxMessagesPerPoll` is
//! accepted for Camel parity and windows the candidates after the
//! cursor, but because one read emits at most one file and a consumed
//! resume file never spends the window, any cap of one or more reaches
//! the same file: the cap bounds nothing a read does not already bound.
//!
//! Paging cost (recorded bound): every page reads and hashes the whole
//! file to check the cursor's pinned digest, and the CSV decoder walks
//! records from the file's start to keep the header and ordinals exact,
//! so one page costs O(file bytes) and a full scan of one file costs
//! O(pages times file bytes). `maximumFileBytes` bounds each page's
//! work; seeking on resume would not remove the whole-file digest that
//! keeps a replaced file from resuming at a stale offset.
//!
//! Security: the configured base resolves once and is pinned by its
//! directory descriptor; every candidate opens beneath that descriptor
//! with no final symlink traversal. A candidate name carrying a path
//! separator or a dot segment refuses, every candidate symlink the name
//! filters select refuses,
//! and a file over the profile's file bound refuses whole, never a
//! partial read. Discovery, metadata checks, content reads, and
//! decoding run off the async executor so the enclosing poll deadline
//! can fire.

use std::io::Read as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use registry_adapter_core::ReadBounds;
use serde_json::{json, Value};

use crate::decoder::{decode_with_cancellation, DecodeInput, DecodedPage, Decoder, DecoderFault};
#[cfg(test)]
use crate::job_sources::FlatGlob;
use crate::job_sources::{FileSourceConfig, ReadLockKind, SourceReadPage};

/// Why a read refused. The processor carries the closed code beside the
/// class the route failure raises.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FileReadFault {
    /// A candidate name carried a path separator or dot segment.
    Traversal,
    /// A candidate name was not UTF-8, so no glob, done-file form, or
    /// item key could ever carry it.
    NameUnreadable,
    /// A candidate's canonical path left the base directory.
    Escape,
    /// A file stood over the profile's file bound.
    Oversize,
    /// The base directory could not be listed.
    DirectoryUnreadable,
    /// A malformed record the decoder refused; the payload is the
    /// record's 0-based index over every record of the file, header
    /// included, the one value the refusal may name.
    Row(u64),
    /// The declared business-key pointer selected no member of the record.
    KeyMissing(u64),
    /// The selected business key was not a valid bounded opaque string.
    KeyInvalid(u64),
    /// The record repeated an earlier business key in the same file.
    KeyDuplicate(u64),
    /// A record or field over the profile's read bounds.
    RowBound,
    /// The CSV decoder declares a syntax character outside ASCII.
    DecoderSyntax,
    /// The changed read lock did not settle inside its timeout.
    LockTimeout,
    /// The decode was abandoned at the poll deadline.
    DecodeTimeout,
}

/// One candidate: its directory-flat name. It is opened only relative
/// to the pinned directory descriptor after selection.
#[derive(Clone)]
struct Candidate {
    name: String,
}

/// One directory scan pinned to the exact directory descriptor that
/// every selected candidate is later opened beneath.
struct CandidateDirectory {
    directory: std::sync::Arc<std::fs::File>,
    base: Vec<Candidate>,
}

/// Read one page from a file source under the profile's read bounds and
/// the job cursor the entry placed.
pub(crate) async fn read_page(
    config: &FileSourceConfig,
    bounds: &ReadBounds,
    cursor: Option<&Value>,
    decoder: &Decoder,
    ongoing: bool,
) -> Result<SourceReadPage, FileReadFault> {
    let (resume_name, resume_digest, resume_offset) = cursor_parts(cursor);
    let scan_config = config.clone();
    let scan_resume = resume_name.clone();
    let candidates =
        tokio::task::spawn_blocking(move || candidates(&scan_config, scan_resume.as_deref()))
            .await
            .map_err(|_| FileReadFault::DirectoryUnreadable)??;
    let base = &candidates.base;
    let read_lock = config.read_lock();
    // The candidate this read starts at: the resume file while it
    // stands, else the first candidate sorted after it, else the first
    // candidate of the directory.
    let start = resume_name.as_deref().map_or(0, |name| {
        base.partition_point(|candidate| candidate.name.as_str() < name)
    });
    // The per-poll cap is a window over the candidates that stand after
    // the cursor, never over the directory itself: consumed files stay
    // in place, so a cap applied before the cursor would re-read the
    // same head forever and never reach the tail. One read emits at
    // most one file, so the window always reaches it.
    let mut window_end = start
        .saturating_add(config.max_messages_per_poll.get() as usize)
        .min(base.len());
    let mut index = start;
    while index < window_end {
        let Some(candidate) = base.get(index) else {
            break;
        };
        let directory = std::sync::Arc::clone(&candidates.directory);
        let candidate_name = candidate.name.clone();
        let opened = tokio::task::spawn_blocking(move || {
            open_candidate(directory.as_ref(), candidate_name.as_str())
        })
        .await
        .map_err(|_| FileReadFault::DirectoryUnreadable)??;
        if let Ok(ReadLockKind::Changed {
            timeout_milliseconds,
            check_interval_milliseconds,
        }) = &read_lock
        {
            changed_lock(
                &opened,
                Duration::from_millis(*timeout_milliseconds),
                Duration::from_millis(*check_interval_milliseconds),
            )
            .await?;
        }
        let file = read_file(opened, bounds.clone()).await?;
        // The cursor's own file stands while its bytes carry the pinned
        // digest. At or past its end it is consumed, and the read moves
        // to the next candidate; inside it the read resumes at the
        // offset. A replaced file (its digest moved) reads again from
        // zero, under its new digest.
        let named_by_cursor = index == start
            && resume_name.as_deref() == Some(candidate.name.as_str())
            && resume_digest.as_deref() == Some(file.digest.as_str());
        if named_by_cursor && resume_offset.is_some_and(|offset| offset >= file.length) {
            index += 1;
            // The cursor proves this file was already consumed, so it
            // does not spend this poll's candidate allowance. Extend the
            // window to keep the declared number of unread candidates in
            // reach, including when the cap is one.
            window_end = window_end.saturating_add(1).min(base.len());
            continue;
        }
        let resume = if named_by_cursor {
            resume_offset
                .filter(|offset| *offset < file.length)
                .unwrap_or(0)
        } else {
            0
        };
        let page = decode_page(
            decoder.clone(),
            config.namespace.clone(),
            file.digest.clone(),
            candidate.name.clone(),
            file.bytes,
            resume,
            bounds.clone(),
        )
        .await?;
        let body = if page.complete && index + 1 == base.len() && !ongoing {
            // The file is finished and no candidate stands after it: the
            // scan of this directory is complete. An ongoing scan keeps
            // its place instead, so the next pass starts after this file.
            json!({ "items": page.items })
        } else {
            json!({
                "items": page.items,
                "next": {
                    "digest": file.digest,
                    "position": if page.complete { file.length } else { page.position },
                    "resumeAfter": candidate.name,
                },
            })
        };
        return Ok(SourceReadPage {
            body,
            malformed_lines: page.malformed_lines,
        });
    }
    // No candidate stands beyond the cursor: a finite scan is complete.
    // An ongoing scan has caught up and keeps the cursor it was given.
    let body = match cursor {
        Some(cursor) if ongoing => json!({ "items": [], "next": cursor }),
        _ => json!({ "items": [] }),
    };
    Ok(SourceReadPage {
        body,
        malformed_lines: 0,
    })
}

/// Decode one file's page. The decode walks the whole file under the
/// read bounds, so it is CPU work the enclosing poll deadline must be
/// able to interrupt: it runs off the async executor, and dropping the
/// page future asks the blocking parser to stop at its next bounded input
/// boundary.
pub(crate) async fn decode_page(
    decoder: Decoder,
    namespace: String,
    digest: String,
    name: String,
    bytes: Vec<u8>,
    resume: u64,
    bounds: ReadBounds,
) -> Result<DecodedPage, FileReadFault> {
    let cancellation = std::sync::Arc::new(AtomicBool::new(false));
    let blocking_cancellation = std::sync::Arc::clone(&cancellation);
    let mut cancellation_guard = CancelDecodeOnDrop {
        cancellation,
        armed: true,
    };
    let result = tokio::task::spawn_blocking(move || {
        decode_with_cancellation(
            &decoder,
            DecodeInput {
                namespace: &namespace,
                digest: &digest,
                name: &name,
                bytes: &bytes,
            },
            resume,
            &bounds,
            &|| blocking_cancellation.load(Ordering::Relaxed),
        )
    })
    .await
    .map_err(|_| FileReadFault::DirectoryUnreadable)?;
    cancellation_guard.armed = false;
    result.map_err(file_fault)
}

fn file_fault(fault: DecoderFault) -> FileReadFault {
    match fault {
        DecoderFault::Row(index) => FileReadFault::Row(index),
        DecoderFault::KeyMissing(index) => FileReadFault::KeyMissing(index),
        DecoderFault::KeyInvalid(index) => FileReadFault::KeyInvalid(index),
        DecoderFault::KeyDuplicate(index) => FileReadFault::KeyDuplicate(index),
        DecoderFault::Bound => FileReadFault::RowBound,
        DecoderFault::Syntax => FileReadFault::DecoderSyntax,
        DecoderFault::Cancelled => FileReadFault::DecodeTimeout,
    }
}

/// Dropping the async read, including when its poll deadline expires, asks the
/// detached blocking parser to stop at its next bounded input boundary.
struct CancelDecodeOnDrop {
    cancellation: std::sync::Arc<AtomicBool>,
    armed: bool,
}

impl Drop for CancelDecodeOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Relaxed);
        }
    }
}

/// The cursor a previous page returned: the resume name, the file
/// digest it pinned, and the byte offset inside that file.
pub(crate) fn cursor_parts(
    cursor: Option<&Value>,
) -> (Option<String>, Option<String>, Option<u64>) {
    let Some(cursor) = cursor.and_then(Value::as_object) else {
        return (None, None, None);
    };
    (
        cursor
            .get("resumeAfter")
            .and_then(Value::as_str)
            .map(str::to_owned),
        cursor
            .get("digest")
            .and_then(Value::as_str)
            .map(str::to_owned),
        cursor.get("position").and_then(Value::as_u64),
    )
}

/// The candidates of one read: the directory's regular files, flat
/// names only, include-matched, done-file filtered, sorted by name.
fn candidates(
    config: &FileSourceConfig,
    resume_name: Option<&str>,
) -> Result<CandidateDirectory, FileReadFault> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let canonical_base =
        std::fs::canonicalize(&config.directory).map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let directory = rustix::fs::open(
        canonical_base,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map(std::fs::File::from)
    .map(std::sync::Arc::new)
    .map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let entries = rustix::fs::Dir::read_from(directory.as_ref())
        .map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let mut base: Vec<Candidate> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| FileReadFault::DirectoryUnreadable)?;
        // The name filters run on a lossy rendering first, so a name the
        // source would not select stays invisible whatever bytes it
        // carries; only a selected name can refuse the read below.
        let lossy_name = entry.file_name().to_string_lossy();
        let name: &str = &lossy_name;
        if name == "." || name == ".." {
            continue;
        }
        // Hidden files never enter the candidate chain: Camel's default
        // posture skips dot names before any include or done-file
        // filter, keeping lock and editor-backup files out of the data.
        if name.starts_with('.') {
            continue;
        }
        if let Some(include) = &config.include {
            if !include.matches(name) {
                continue;
            }
        }
        if entry.file_name().to_str().is_err() {
            return Err(FileReadFault::NameUnreadable);
        }
        if name.contains('/') || name.contains('\\') {
            return Err(FileReadFault::Traversal);
        }
        if config
            .done_file_name
            .as_ref()
            .is_some_and(|done| done.is_done_file(name))
        {
            continue;
        }
        let metadata = rustix::fs::statat(directory.as_ref(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| FileReadFault::DirectoryUnreadable)?;
        let file_type = FileType::from_raw_mode(metadata.st_mode);
        if file_type == FileType::Symlink {
            return Err(FileReadFault::Escape);
        }
        if file_type != FileType::RegularFile {
            continue;
        }
        if let Some(done) = &config.done_file_name {
            match rustix::fs::statat(directory.as_ref(), done.of(name), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(metadata)
                    if FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile => {}
                _ => continue,
            }
        }
        if resume_name.is_some_and(|resume| name < resume) {
            continue;
        }
        let insertion = base.partition_point(|candidate| candidate.name.as_str() < name);
        base.insert(
            insertion,
            Candidate {
                name: name.to_owned(),
            },
        );
        // One read emits at most one file. Retaining the resume file,
        // its successor, and one lookahead is enough to skip a consumed
        // resume and still decide whether the emitted file ends the scan.
        base.truncate(3);
    }
    Ok(CandidateDirectory { directory, base })
}

/// One candidate read whole under the file bound, never partially, with
/// its digest.
struct ReadFile {
    bytes: Vec<u8>,
    digest: String,
    length: u64,
}

fn open_candidate(directory: &std::fs::File, name: &str) -> Result<std::fs::File, FileReadFault> {
    use rustix::fs::{Mode, OFlags};

    let file = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            FileReadFault::Escape
        } else {
            FileReadFault::DirectoryUnreadable
        }
    })?;
    let file = std::fs::File::from(file);
    if !file
        .metadata()
        .map_err(|_| FileReadFault::DirectoryUnreadable)?
        .is_file()
    {
        return Err(FileReadFault::Escape);
    }
    Ok(file)
}

async fn read_file(file: std::fs::File, bounds: ReadBounds) -> Result<ReadFile, FileReadFault> {
    tokio::task::spawn_blocking(move || read_opened_file(file, &bounds))
        .await
        .map_err(|_| FileReadFault::DirectoryUnreadable)?
}

fn read_opened_file(file: std::fs::File, bounds: &ReadBounds) -> Result<ReadFile, FileReadFault> {
    let mut bytes = Vec::new();
    let reader = std::io::BufReader::new(file);
    reader
        .take(bounds.maximum_file_bytes.get().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FileReadFault::DirectoryUnreadable)?;
    if bytes.len() as u64 > bounds.maximum_file_bytes.get() {
        return Err(FileReadFault::Oversize);
    }
    let digest = registry_platform_config::sha256_uri(&bytes);
    let length = bytes.len() as u64;
    Ok(ReadFile {
        bytes,
        digest,
        length,
    })
}

/// Camel's `changed` read lock
/// (camel-4.23.0:components/camel-file/src/main/java/org/apache/camel/component/file/strategy/FileChangedExclusiveReadLockStrategy.java):
/// the file's length and last-modified time stand still across two
/// checks spaced the check interval apart, inside the timeout.
/// Divergences: a lock that never settles raises instead of skipping
/// the file this poll, and a stable empty file locks too (Camel's
/// `minLength` 1 is not ported), because a raised timeout on every poll
/// would block every candidate sorted after an empty file forever.
async fn changed_lock(
    file: &std::fs::File,
    timeout: Duration,
    check_interval: Duration,
) -> Result<(), FileReadFault> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut previous: Option<(u64, Option<std::time::SystemTime>)> = None;
    loop {
        let metadata_file = file
            .try_clone()
            .map_err(|_| FileReadFault::DirectoryUnreadable)?;
        let metadata = tokio::task::spawn_blocking(move || metadata_file.metadata())
            .await
            .map_err(|_| FileReadFault::DirectoryUnreadable)?
            .map_err(|_| FileReadFault::DirectoryUnreadable)?;
        let current = (metadata.len(), metadata.modified().ok());
        if previous == Some(current) {
            return Ok(());
        }
        previous = Some(current);
        let wake = tokio::time::Instant::now() + check_interval;
        if wake >= deadline {
            return Err(FileReadFault::LockTimeout);
        }
        tokio::time::sleep_until(wake).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(directory: &std::path::Path) -> FileSourceConfig {
        serde_json::from_value(serde_json::json!({
            "directory": directory,
            "namespace": "exports"
        }))
        .expect("the file source")
    }

    fn read_bounds() -> ReadBounds {
        ReadBounds {
            maximum_file_bytes: 1024.try_into().expect("inside its range"),
            maximum_row_bytes: 256.try_into().expect("inside its range"),
            maximum_field_bytes: 128.try_into().expect("inside its range"),
            maximum_rows_per_page: 10.try_into().expect("inside its range"),
        }
    }

    async fn read_raw(directory: &std::path::Path, cursor: Option<&Value>, ongoing: bool) -> Value {
        read_page(
            &source(directory),
            &read_bounds(),
            cursor,
            &Decoder::Raw,
            ongoing,
        )
        .await
        .expect("the read")
        .body
    }

    /// An ongoing scan holds its place at the tail: the last file's page
    /// carries a cursor, so the next pass starts after it instead of at
    /// the first retained file. A finite scan ends there.
    #[tokio::test]
    async fn an_ongoing_scan_keeps_a_cursor_at_the_tail_and_a_finite_scan_ends() {
        let base = tempfile::tempdir().expect("the base directory");
        std::fs::write(base.path().join("a.bin"), "a").expect("the candidate");

        let finite = read_raw(base.path(), None, false).await;
        assert!(finite.get("next").is_none(), "finite ends: {finite}");

        let ongoing = read_raw(base.path(), None, true).await;
        assert_eq!(ongoing["next"]["resumeAfter"], "a.bin", "{ongoing}");
    }

    /// From the tail cursor an ongoing scan reads only files that arrived
    /// after it, and an empty read echoes the cursor so the position is
    /// kept rather than cleared.
    #[tokio::test]
    async fn an_ongoing_scan_resumes_after_the_tail_and_keeps_its_place_when_caught_up() {
        let base = tempfile::tempdir().expect("the base directory");
        std::fs::write(base.path().join("a.bin"), "a").expect("the first file");
        let tail = read_raw(base.path(), None, true).await["next"].clone();

        let caught_up = read_raw(base.path(), Some(&tail), true).await;
        assert_eq!(caught_up["items"], serde_json::json!([]), "{caught_up}");
        assert_eq!(caught_up["next"], tail, "{caught_up}");

        std::fs::write(base.path().join("b.bin"), "b").expect("the new file");
        let fresh = read_raw(base.path(), Some(&tail), true).await;
        assert_eq!(fresh["items"].as_array().map(Vec::len), Some(1), "{fresh}");
        assert_eq!(fresh["next"]["resumeAfter"], "b.bin", "{fresh}");
    }

    /// The flat glob matches Camel's simple Ant patterns over plain
    /// names: stars span, question marks span one, and a mismatched
    /// literal refuses.
    #[test]
    fn the_include_glob_matches_plain_names() {
        let matched = |pattern: &str, name: &str| {
            FlatGlob::compile(pattern)
                .expect("valid flat glob")
                .matches(name)
        };
        assert!(matched("*.csv", "people.csv"));
        assert!(!matched("*.csv", "people.tsv"));
        assert!(matched("export-???.json", "export-042.json"));
        assert!(!matched("export-???.json", "export-42.json"));
        assert!(matched("a*b*c", "aXbYc"));
        assert!(!matched("a*b*c", "aXc"));
        assert!(matched("**", "anything"));
        assert!(matched("plain.txt", "plain.txt"));
        assert!(matched("résumé-?.csv", "résumé-東.csv"));
    }

    /// A done-file pattern never admits its own done files as
    /// candidates.
    #[test]
    fn done_file_patterns_recognize_their_own_done_files() {
        let literal = crate::job_sources::DoneFileName::Literal("done".to_owned());
        assert!(literal.is_done_file("done"));
        assert!(!literal.is_done_file("data.csv"));
        let suffix = crate::job_sources::DoneFileName::Placeholder {
            prefix: String::new(),
            suffix: ".done".to_owned(),
        };
        assert!(suffix.is_done_file("data.csv.done"));
        assert!(!suffix.is_done_file("data.csv"));
        assert_eq!(suffix.of("data.csv"), "data.csv.done");
    }

    /// Candidate selection and opening share one pinned directory
    /// descriptor. Replacing the selected name with a symlink before the
    /// open refuses instead of following the replacement outside the base.
    #[cfg(unix)]
    #[test]
    fn a_candidate_replaced_by_a_symlink_refuses_at_open() {
        let base = tempfile::tempdir().expect("the base directory");
        let outside = tempfile::tempdir().expect("the outside directory");
        std::fs::write(base.path().join("data.bin"), b"inside").expect("the candidate");
        std::fs::write(outside.path().join("outside.bin"), b"outside").expect("the outside file");
        let selected = candidates(&source(base.path()), None).expect("the candidate scan");
        assert_eq!(selected.base.len(), 1);

        std::fs::remove_file(base.path().join("data.bin")).expect("remove the scratch candidate");
        std::os::unix::fs::symlink(
            outside.path().join("outside.bin"),
            base.path().join("data.bin"),
        )
        .expect("replace it with a symlink");

        assert!(matches!(
            open_candidate(selected.directory.as_ref(), &selected.base[0].name),
            Err(FileReadFault::Escape)
        ));
    }

    /// Runtime configuration may resolve the base through a symlink. The
    /// resolved directory is then pinned, while candidate symlinks remain
    /// refused.
    #[cfg(unix)]
    #[test]
    fn a_configured_directory_symlink_resolves_before_pinning() {
        let root = tempfile::tempdir().expect("the scratch root");
        let actual = root.path().join("actual");
        let linked = root.path().join("linked");
        std::fs::create_dir(&actual).expect("the actual directory");
        std::fs::write(actual.join("data.bin"), b"inside").expect("the candidate");
        std::os::unix::fs::symlink(&actual, &linked).expect("the configured directory symlink");

        let selected = candidates(&source(&linked), None).expect("the resolved directory scans");
        assert_eq!(selected.base[0].name, "data.bin");
        assert!(open_candidate(selected.directory.as_ref(), "data.bin").is_ok());
    }

    /// An abandoned decode is a deadline, not a read-lock problem.
    #[test]
    fn a_cancelled_decode_is_not_a_lock_timeout() {
        assert!(matches!(
            file_fault(DecoderFault::Cancelled),
            FileReadFault::DecodeTimeout
        ));
    }

    fn csv_source(directory: &std::path::Path) -> FileSourceConfig {
        serde_json::from_value(serde_json::json!({
            "directory": directory,
            "namespace": "exports",
            "include": "*.csv"
        }))
        .expect("the file source")
    }

    /// A name the include filter does not select never refuses the read,
    /// whatever bytes it carries; a legacy-code-page name on an SMB share
    /// must not block the `*.csv` files beside it.
    #[cfg(unix)]
    #[test]
    fn a_backslash_name_the_include_filter_skips_does_not_block_the_read() {
        let base = tempfile::tempdir().expect("the base directory");
        std::fs::write(base.path().join("data.csv"), b"a").expect("the candidate");
        std::fs::write(base.path().join("old\\notes.txt"), b"x").expect("the stray name");

        let selected = candidates(&csv_source(base.path()), None).expect("the scan");
        assert_eq!(selected.base.len(), 1);
        assert_eq!(selected.base[0].name, "data.csv");
    }

    /// A selected name that leaves the directory still refuses.
    #[cfg(unix)]
    #[test]
    fn a_backslash_name_the_include_filter_selects_still_refuses() {
        let base = tempfile::tempdir().expect("the base directory");
        std::fs::write(base.path().join("a\\b.csv"), b"x").expect("the stray name");

        assert!(matches!(
            candidates(&csv_source(base.path()), None),
            Err(FileReadFault::Traversal)
        ));
    }

    /// A non-UTF-8 name the include filter skips does not block the read;
    /// one the filter selects refuses, since no item key can carry it.
    /// Filesystems that refuse such names (APFS) cannot run this case.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_name_blocks_the_read_only_when_the_include_filter_selects_it() {
        use std::os::unix::ffi::OsStrExt as _;

        let base = tempfile::tempdir().expect("the base directory");
        std::fs::write(base.path().join("data.csv"), b"a").expect("the candidate");
        let skipped = std::ffi::OsStr::from_bytes(b"caf\xe9.txt");
        if std::fs::write(base.path().join(skipped), b"x").is_err() {
            return;
        }
        let selected = candidates(&csv_source(base.path()), None).expect("the scan");
        assert_eq!(selected.base.len(), 1);

        let selected_name = std::ffi::OsStr::from_bytes(b"caf\xe9.csv");
        std::fs::write(base.path().join(selected_name), b"x").expect("the selected stray name");
        assert!(matches!(
            candidates(&csv_source(base.path()), None),
            Err(FileReadFault::NameUnreadable)
        ));
    }

    /// Candidate discovery retains only the resume point, its successor,
    /// and one lookahead, even when the directory is larger.
    #[test]
    fn candidate_discovery_keeps_the_nearest_bounded_window() {
        let base = tempfile::tempdir().expect("the base directory");
        for name in ["a.bin", "b.bin", "c.bin", "d.bin", "e.bin"] {
            std::fs::write(base.path().join(name), name).expect("the candidate");
        }

        let selected = candidates(&source(base.path()), Some("b.bin")).expect("the scan");
        assert_eq!(
            selected
                .base
                .iter()
                .map(|candidate| candidate.name.as_str())
                .collect::<Vec<_>>(),
            ["b.bin", "c.bin", "d.bin"]
        );
    }

    /// A blocking descriptor read runs away from the current-thread async
    /// executor, so the poll's enclosing timer can expire while the read is
    /// stalled.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_read_does_not_block_the_poll_deadline() {
        use std::io::Write as _;

        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().expect("the pipe pair");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = std::thread::spawn(move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            writer.write_all(b"released").expect("release the read");
        });
        let reader = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
        let bounds = ReadBounds {
            maximum_file_bytes: 1024.try_into().expect("inside its range"),
            maximum_row_bytes: 1024.try_into().expect("inside its range"),
            maximum_field_bytes: 1024.try_into().expect("inside its range"),
            maximum_rows_per_page: 1.try_into().expect("inside its range"),
        };

        let result =
            tokio::time::timeout(Duration::from_millis(10), read_file(reader, bounds)).await;
        release_tx.send(()).expect("signal the release thread");
        release.join().expect("the release thread");
        assert!(result.is_err(), "the timer fires while the read is stalled");
    }

    /// Decoding walks the whole file, so it runs away from the
    /// current-thread async executor too: an expired poll deadline fires
    /// instead of waiting for a large file's decode to finish.
    #[tokio::test(flavor = "current_thread")]
    async fn a_long_decode_does_not_block_the_poll_deadline() {
        let mut bytes = b"name,age\n".to_vec();
        for row in 0..200_000 {
            bytes.extend_from_slice(format!("person-{row},{row}\n").as_bytes());
        }
        let bounds = ReadBounds {
            maximum_file_bytes: 1_073_741_824.try_into().expect("inside its range"),
            maximum_row_bytes: 1024.try_into().expect("inside its range"),
            maximum_field_bytes: 1024.try_into().expect("inside its range"),
            maximum_rows_per_page: 1.try_into().expect("inside its range"),
        };

        let result = tokio::time::timeout(
            Duration::ZERO,
            decode_page(
                Decoder::Csv {
                    options: Default::default(),
                    key_pointer: "/name".to_owned(),
                },
                "exports".to_owned(),
                "sha256:aa".to_owned(),
                "people.csv".to_owned(),
                bytes,
                // A resume offset near the end makes the decoder walk
                // every record before it emits.
                u64::MAX - 1,
                bounds,
            ),
        )
        .await;
        assert!(result.is_err(), "the timer fires while the decode runs");
    }
}
