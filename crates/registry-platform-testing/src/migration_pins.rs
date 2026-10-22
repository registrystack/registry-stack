// SPDX-License-Identifier: Apache-2.0
//! The sha256 pin of every migration file a product ships.
//!
//! A product's migration ledger records versions only, so a database that
//! applied a version never runs that file again. Editing a released file
//! therefore changes fresh installs and leaves every existing database on
//! the old text. Pinning each file's digest makes such an edit fail a test
//! and points at the only safe change: a new, later version.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The rule every pin failure states.
pub const MIGRATION_PIN_RULE: &str =
    "a migration a release has shipped is never edited: add the next version";

/// Compares every regular file in `directory` with `pins`, given as
/// `(file name, lowercase hex sha256)`. Reports each edited, unpinned, or
/// missing file, followed by [`MIGRATION_PIN_RULE`].
pub fn verify_migration_pins(directory: &Path, pins: &[(&str, &str)]) -> Result<(), String> {
    let mut actual = BTreeMap::new();
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("{} cannot be read: {error}", directory.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("{} cannot be read: {error}", directory.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        actual.insert(name, hex(&Sha256::digest(&bytes)));
    }
    let expected: BTreeMap<&str, &str> = pins.iter().copied().collect();
    let mut findings = Vec::new();
    for (name, digest) in &actual {
        match expected.get(name.as_str()) {
            None => findings.push(format!("{name} is unpinned (sha256 {digest})")),
            Some(pinned) if pinned != digest => findings.push(format!(
                "{name} was edited (pinned sha256 {pinned}, now {digest})"
            )),
            Some(_) => {}
        }
    }
    for name in expected.keys() {
        if !actual.contains_key(*name) {
            findings.push(format!("{name} is pinned but missing"));
        }
    }
    if findings.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} in {}: {}; {MIGRATION_PIN_RULE}",
        if findings.len() == 1 {
            "a migration pin failed"
        } else {
            "migration pins failed"
        },
        directory.display(),
        findings.join("; ")
    ))
}

/// Panics with the [`verify_migration_pins`] report when a pin fails.
pub fn assert_migration_pins(directory: &Path, pins: &[(&str, &str)]) {
    if let Err(report) = verify_migration_pins(directory, pins) {
        panic!("{report}");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE: &str = "CREATE TABLE t (id bigint PRIMARY KEY);\n";

    fn directory_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("scratch directory");
        for (name, contents) in files {
            fs::write(directory.path().join(name), contents).expect("migration writes");
        }
        directory
    }

    fn baseline_digest() -> String {
        hex(&Sha256::digest(BASELINE.as_bytes()))
    }

    #[test]
    fn pinned_files_with_their_digests_pass() {
        let directory = directory_with(&[("0100_base.sql", BASELINE)]);
        let digest = baseline_digest();
        verify_migration_pins(directory.path(), &[("0100_base.sql", &digest)])
            .expect("the pinned file passes");
    }

    #[test]
    fn an_edited_file_is_named_with_the_rule() {
        let directory = directory_with(&[("0100_base.sql", "CREATE TABLE t ();\n")]);
        let digest = baseline_digest();
        let report = verify_migration_pins(directory.path(), &[("0100_base.sql", &digest)])
            .expect_err("an edited file fails");
        assert!(report.contains("0100_base.sql"), "{report}");
        assert!(report.contains("edited"), "{report}");
        assert!(report.contains(MIGRATION_PIN_RULE), "{report}");
    }

    #[test]
    fn an_unpinned_file_is_named_with_the_rule() {
        let directory = directory_with(&[("0100_base.sql", BASELINE), ("0101_next.sql", BASELINE)]);
        let digest = baseline_digest();
        let report = verify_migration_pins(directory.path(), &[("0100_base.sql", &digest)])
            .expect_err("an unpinned file fails");
        assert!(report.contains("0101_next.sql"), "{report}");
        assert!(report.contains("unpinned"), "{report}");
        assert!(report.contains(MIGRATION_PIN_RULE), "{report}");
    }

    #[test]
    fn a_pinned_file_that_is_gone_is_named() {
        let directory = directory_with(&[]);
        let digest = baseline_digest();
        let report = verify_migration_pins(directory.path(), &[("0100_base.sql", &digest)])
            .expect_err("a missing pinned file fails");
        assert!(report.contains("0100_base.sql"), "{report}");
        assert!(report.contains("missing"), "{report}");
    }

    #[test]
    #[should_panic(expected = "a migration a release has shipped is never edited")]
    fn the_assertion_panics_with_the_report() {
        let directory = directory_with(&[("0100_base.sql", BASELINE)]);
        assert_migration_pins(directory.path(), &[]);
    }
}
