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
//! sorted by name ascending (the `sortBy` default), limited to
//! `maxMessagesPerPoll` candidates, and, when the source declares
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
//! the check interval apart, inside the timeout, minLength 1) but
//! raises a timeout instead of silently skipping the file, because a
//! skipped file reads as a completed scan and nothing is silently
//! skipped here; and Camel's `noop` implies `idempotent`, suppressing
//! re-reads of a consumed file, which WE DIVERGE from: the read never
//! suppresses re-reads, the item table owns identity, and a second read
//! of unchanged content returns the same items (the page is the same;
//! the consumer deduplicates by the namespace-plus-digest key).
//!
//! Paging (original work, recorded simplification): one read processes
//! at most one file, the first candidate the cursor has not passed. The
//! cursor carries the processed file's digest, the byte offset after
//! the last emitted row, and that file's name as `resumeAfter`; the
//! next read resumes the named file at its offset while its bytes still
//! carry the pinned digest, passes it for the next candidate once its
//! offset stands at or past its end, reads it again from zero when its
//! content changed (the new digest gives the new bytes their own
//! identity), and otherwise starts at the first candidate after the
//! resume name. A cursor past every candidate, or a last candidate
//! finished, ends the scan: `next` is absent.
//!
//! Security: a candidate name carrying a path separator or a dot
//! segment refuses, a candidate whose canonical path leaves the
//! canonical base directory refuses (symlink escape), and a file over
//! the profile's file bound refuses whole, never a partial read.

use std::io::Read as _;
use std::time::Duration;

use registry_adapter_core::ReadBounds;
use serde_json::{json, Value};

use crate::engine::decoder::{decode, Decoder, DecoderFault};
use crate::engine::job_sources::{FileSourceConfig, ReadLockKind};

/// One completed read: the item page as the exchange body takes it.
pub(crate) struct FilePage {
    /// The `{items, next}` page value.
    pub(crate) body: Value,
    /// How many malformed JSONL lines the read skipped, for the job
    /// entry's side channel.
    pub(crate) malformed_lines: u32,
}

/// Why a read refused. The processor carries the closed code beside the
/// class the route failure raises.
#[derive(Debug)]
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
    /// A record or field over the profile's read bounds.
    RowBound,
    /// The changed read lock did not settle inside its timeout.
    LockTimeout,
}

/// One candidate: its directory-flat name and its canonical path.
struct Candidate {
    name: String,
    path: std::path::PathBuf,
}

/// Read one page from a file source under the profile's read bounds and
/// the job cursor the entry placed.
pub(crate) async fn read_page(
    config: &FileSourceConfig,
    bounds: &ReadBounds,
    cursor: Option<&Value>,
    decoder: &Decoder,
) -> Result<FilePage, FileReadFault> {
    let base = candidates(config)?;
    let (resume_name, resume_digest, resume_offset) = cursor_parts(cursor);
    let read_lock = config.read_lock();
    // The candidate this read starts at: the resume file while it
    // stands, else the first candidate sorted after it, else the first
    // candidate of the directory.
    let start = resume_name.as_deref().map_or(0, |name| {
        base.partition_point(|candidate| candidate.name.as_str() < name)
    });
    let mut index = start;
    while let Some(candidate) = base.get(index) {
        if let Ok(ReadLockKind::Changed {
            timeout_milliseconds,
            check_interval_milliseconds,
        }) = &read_lock
        {
            changed_lock(
                &candidate.path,
                Duration::from_millis(*timeout_milliseconds),
                Duration::from_millis(*check_interval_milliseconds),
            )
            .await?;
        }
        let file = read_file(candidate, bounds)?;
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
            continue;
        }
        let resume = if named_by_cursor {
            resume_offset
                .filter(|offset| *offset < file.length)
                .unwrap_or(0)
        } else {
            0
        };
        let page = decode(
            decoder,
            &config.namespace,
            &file.digest,
            &candidate.name,
            &file.bytes,
            resume,
            bounds,
        )
        .map_err(|fault| match fault {
            DecoderFault::Row(index) => FileReadFault::Row(index),
            DecoderFault::Bound => FileReadFault::RowBound,
        })?;
        let body = if page.complete && index + 1 == base.len() {
            // The file is finished and no candidate stands after it: the
            // scan of this directory is complete.
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
        return Ok(FilePage {
            body,
            malformed_lines: page.malformed_lines,
        });
    }
    // No candidate stands beyond the cursor: the scan is complete.
    Ok(FilePage {
        body: json!({ "items": [] }),
        malformed_lines: 0,
    })
}

/// The cursor a previous page returned: the resume name, the file
/// digest it pinned, and the byte offset inside that file.
fn cursor_parts(cursor: Option<&Value>) -> (Option<String>, Option<String>, Option<u64>) {
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
fn candidates(config: &FileSourceConfig) -> Result<Vec<Candidate>, FileReadFault> {
    let entries =
        std::fs::read_dir(&config.directory).map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let canonical_base =
        std::fs::canonicalize(&config.directory).map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let mut base = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| FileReadFault::DirectoryUnreadable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(FileReadFault::NameUnreadable);
        };
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(FileReadFault::Traversal);
        }
        let path = entry.path();
        if !std::fs::metadata(&path)
            .map_err(|_| FileReadFault::DirectoryUnreadable)?
            .is_file()
        {
            continue;
        }
        let canonical =
            std::fs::canonicalize(&path).map_err(|_| FileReadFault::DirectoryUnreadable)?;
        if !canonical.starts_with(&canonical_base) {
            return Err(FileReadFault::Escape);
        }
        if let Some(done) = &config.done_file_name {
            if done.is_done_file(name) {
                continue;
            }
            match std::fs::metadata(config.directory.join(done.of(name))) {
                Ok(metadata) if metadata.is_file() => {}
                _ => continue,
            }
        }
        if let Some(include) = &config.include {
            if !match_glob(include, name) {
                continue;
            }
        }
        base.push(Candidate {
            name: name.to_owned(),
            path: canonical,
        });
    }
    base.sort_by(|left, right| left.name.cmp(&right.name));
    base.truncate(config.max_messages_per_poll as usize);
    Ok(base)
}

/// One candidate read whole under the file bound, never partially, with
/// its digest.
struct ReadFile {
    bytes: Vec<u8>,
    digest: String,
    length: u64,
}

fn read_file(candidate: &Candidate, bounds: &ReadBounds) -> Result<ReadFile, FileReadFault> {
    let file =
        std::fs::File::open(&candidate.path).map_err(|_| FileReadFault::DirectoryUnreadable)?;
    let mut bytes = Vec::new();
    let reader = std::io::BufReader::new(file);
    reader
        .take(bounds.maximum_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FileReadFault::DirectoryUnreadable)?;
    if bytes.len() as u64 > bounds.maximum_file_bytes {
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
/// checks spaced the check interval apart, inside the timeout, and a
/// nonempty file locks. Divergence: a lock that never settles raises
/// instead of skipping the file this poll.
async fn changed_lock(
    path: &std::path::Path,
    timeout: Duration,
    check_interval: Duration,
) -> Result<(), FileReadFault> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut previous: Option<(u64, Option<std::time::SystemTime>)> = None;
    loop {
        let metadata = std::fs::metadata(path).map_err(|_| FileReadFault::DirectoryUnreadable)?;
        let current = (metadata.len(), metadata.modified().ok());
        if current.0 >= 1 && previous == Some(current) {
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

/// The Ant-style flat glob match over one file name: `*` spans any run
/// of characters, `?` spans exactly one, and the rest matches itself.
/// Names carry no path separators, so `**` has no recursive meaning
/// here and spans like `*`.
fn match_glob(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    // Classic backtracking glob: a star remembers its position and
    // extends over the name until the pattern's tail matches.
    let (mut p, mut n) = (0_usize, 0_usize);
    let (mut star, mut mark) = (None::<usize>, 0_usize);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            mark = n;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            mark += 1;
            n = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flat glob matches Camel's simple Ant patterns over plain
    /// names: stars span, question marks span one, and a mismatched
    /// literal refuses.
    #[test]
    fn the_include_glob_matches_plain_names() {
        assert!(match_glob("*.csv", "people.csv"));
        assert!(!match_glob("*.csv", "people.tsv"));
        assert!(match_glob("export-???.json", "export-042.json"));
        assert!(!match_glob("export-???.json", "export-42.json"));
        assert!(match_glob("a*b*c", "aXbYc"));
        assert!(!match_glob("a*b*c", "aXc"));
        assert!(match_glob("**", "anything"));
        assert!(match_glob("plain.txt", "plain.txt"));
    }

    /// A done-file pattern never admits its own done files as
    /// candidates.
    #[test]
    fn done_file_patterns_recognize_their_own_done_files() {
        let literal = crate::engine::job_sources::DoneFileName::Literal("done".to_owned());
        assert!(literal.is_done_file("done"));
        assert!(!literal.is_done_file("data.csv"));
        let suffix = crate::engine::job_sources::DoneFileName::Placeholder {
            prefix: String::new(),
            suffix: ".done".to_owned(),
        };
        assert!(suffix.is_done_file("data.csv.done"));
        assert!(!suffix.is_done_file("data.csv"));
        assert_eq!(suffix.of("data.csv"), "data.csv.done");
    }
}
