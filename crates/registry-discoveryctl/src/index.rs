// SPDX-License-Identifier: Apache-2.0

//! The offline check of one Discovery index, as `discoveryctl package` wrote
//! it (CFG-CHECK-1).
//!
//! The index is generated, never authored: it is one canonical JSON document
//! that `discovery serve` parses from its package. The check parses it the
//! same way, so a file this check accepts is an index the runtime accepts,
//! and every refusal names the rebuild that fixes it. Diagnostics never
//! repeat the index's contents.

use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use registry_discovery::{parse_index, DiscoveryIndex, MAXIMUM_INDEX_BYTES};
use registry_platform_yaml::{Diagnostic, Report, Source};

/// Everything one index check found.
#[derive(Debug)]
pub struct IndexReport {
    pub report: Report,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
    /// The index, when it passed every check.
    pub index: Option<DiscoveryIndex>,
}

/// Check the index file at `path` exactly as `discovery serve` parses the
/// index of a verified package, without the package around it.
#[must_use]
pub fn inspect_index_file(path: &Path) -> IndexReport {
    let bytes = match read(path) {
        Ok(bytes) => bytes,
        Err(Unread::NotRegular) => {
            return refused(
                0,
                about(
                    path,
                    "discovery.index.not-a-regular-file",
                    "the index path is not a regular file",
                    "Pass the discovery-index.json file itself, not a link or a directory.",
                ),
            );
        }
        Err(Unread::Unreadable) => {
            let mut checked = refused(
                0,
                about(
                    path,
                    "discovery.index.unreadable",
                    "the file could not be read",
                    "Check that it exists and that this user may read it, then run the check \
                     again.",
                ),
            );
            checked.unavailable = true;
            return checked;
        }
    };
    match parse_index(&bytes) {
        Ok(index) => {
            let mut report = Report::new(Vec::new());
            report.set_files_checked(1);
            IndexReport {
                report,
                unavailable: false,
                index: Some(index),
            }
        }
        Err(refusal) => refused(
            1,
            about(
                path,
                refusal.code(),
                refusal.finding(),
                refusal.suggested_action(),
            ),
        ),
    }
}

enum Unread {
    NotRegular,
    Unreadable,
}

/// The file's bytes, up to one byte past the index bound so the parser
/// refuses an oversized index itself.
fn read(path: &Path) -> Result<Vec<u8>, Unread> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Unread::Unreadable)?;
    if !metadata.file_type().is_file() {
        return Err(Unread::NotRegular);
    }
    let file = fs::File::open(path).map_err(|_| Unread::Unreadable)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_INDEX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_: io::Error| Unread::Unreadable)?;
    Ok(bytes)
}

fn refused(files: usize, diagnostic: Diagnostic) -> IndexReport {
    let mut report = Report::new(vec![diagnostic]);
    report.set_files_checked(files);
    IndexReport {
        report,
        unavailable: false,
        index: None,
    }
}

/// A finding about the index file as a whole: the index is one canonical
/// line, so a position inside it would not help.
fn about(path: &Path, code: &str, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, "", message, action);
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

#[cfg(test)]
mod tests {
    use registry_discovery::canonical_index_bytes;
    use tempfile::TempDir;

    use super::*;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/discovery/fixtures/project/discovery-index.json"
    );

    /// A temporary directory under the canonical temporary base.
    fn temporary() -> TempDir {
        let base = std::env::temp_dir().canonicalize().unwrap();
        TempDir::new_in(base).unwrap()
    }

    fn fixture() -> Vec<u8> {
        let bytes = fs::read(FIXTURE).unwrap();
        bytes
            .strip_suffix(b"\n")
            .map(<[u8]>::to_vec)
            .unwrap_or(bytes)
    }

    fn codes(checked: &IndexReport) -> Vec<String> {
        checked
            .report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    #[test]
    fn cfg_check_1_the_fixture_index_is_accepted() {
        let directory = temporary();
        let path = directory.path().join("discovery-index.json");
        fs::write(&path, fixture()).unwrap();
        let checked = inspect_index_file(&path);
        assert!(checked.index.is_some(), "{:?}", checked.report);
        assert!(!checked.report.has_errors());
        assert_eq!(checked.report.files_checked(), Some(1));
        assert_eq!(
            canonical_index_bytes(checked.index.as_ref().unwrap()).unwrap(),
            fixture()
        );
    }

    #[test]
    fn cfg_change_2_an_index_with_the_retired_header_names_the_rebuild() {
        let mut value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
        let members = value.as_object_mut().unwrap();
        members.remove("apiVersion");
        members.remove("kind");
        members.insert(
            "schemaVersion".into(),
            "registry-discovery/index/v1alpha1".into(),
        );
        let directory = temporary();
        let path = directory.path().join("discovery-index.json");
        fs::write(
            &path,
            registry_platform_canonical_json::canonicalize_json(&value).unwrap(),
        )
        .unwrap();
        let checked = inspect_index_file(&path);
        assert_eq!(codes(&checked), ["discovery.index.retired-header"]);
        let diagnostic = &checked.report.diagnostics()[0];
        assert!(diagnostic.suggested_action.contains("discoveryctl package"));
        assert_eq!(
            diagnostic.source.as_ref().unwrap().file,
            path.display().to_string()
        );
        assert!(!checked.unavailable);
    }

    #[test]
    fn a_reformatted_index_is_refused_as_not_canonical() {
        let value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
        let directory = temporary();
        let path = directory.path().join("discovery-index.json");
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert_eq!(
            codes(&inspect_index_file(&path)),
            ["discovery.index.not-canonical"]
        );
    }

    #[test]
    fn an_index_over_the_bound_is_refused_without_reading_past_it() {
        let directory = temporary();
        let path = directory.path().join("discovery-index.json");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAXIMUM_INDEX_BYTES + 2).unwrap();
        assert_eq!(
            codes(&inspect_index_file(&path)),
            ["discovery.index.bound-exceeded"]
        );
    }

    #[test]
    fn a_missing_index_could_not_be_read() {
        let directory = temporary();
        let checked = inspect_index_file(&directory.path().join("absent.json"));
        assert_eq!(codes(&checked), ["discovery.index.unreadable"]);
        assert!(checked.unavailable);
        assert_eq!(checked.report.files_checked(), Some(0));
    }

    #[test]
    fn a_directory_is_not_an_index() {
        let directory = temporary();
        let checked = inspect_index_file(directory.path());
        assert_eq!(codes(&checked), ["discovery.index.not-a-regular-file"]);
        assert!(!checked.unavailable);
    }

    #[test]
    fn the_retired_relay_fixture_names_its_removal() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/discovery/fixtures/compatibility/pre-retirement-mixed-index.json"
        );
        let directory = temporary();
        let copy = directory.path().join("discovery-index.json");
        let bytes = fs::read(path).unwrap();
        fs::write(&copy, bytes.strip_suffix(b"\n").unwrap_or(&bytes)).unwrap();
        assert_eq!(
            codes(&inspect_index_file(&copy)),
            ["discovery.index.retired-service-kind"]
        );
    }
}
