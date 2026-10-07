// SPDX-License-Identifier: Apache-2.0
//! The committed catalog snapshot is the reviewed form of every public command
//! line. A change to a Clap tree reaches review as a diff of that file.

use registry_cli_docs::{catalog_snapshot, snapshot_path};

const REGENERATE: &str =
    "run `cargo run --locked -p registry-cli-docs -- --write` and review the snapshot diff";

#[test]
fn committed_snapshot_matches_the_public_command_trees() {
    let path = snapshot_path();
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}; {REGENERATE}", path.display()));
    let generated = catalog_snapshot().expect("the catalog serializes");
    if committed != generated {
        panic!(
            "{} {}\n{REGENERATE}",
            path.display(),
            difference(&committed, &generated)
        );
    }
}

/// Names the first difference between two catalogs that are known to differ.
/// `str::lines` drops line endings, so catalogs whose lines all match differ
/// only in how those lines end.
fn difference(committed: &str, generated: &str) -> String {
    let mut committed_lines = committed.lines();
    let mut generated_lines = generated.lines();
    let mut line = 1;
    loop {
        match (committed_lines.next(), generated_lines.next()) {
            (Some(left), Some(right)) if left == right => line += 1,
            (None, None) if committed.contains('\r') => {
                return "uses CRLF line endings; the generator writes LF".to_owned();
            }
            (None, None) => {
                return "differs only in its trailing newline; the generator ends the file with one newline"
                    .to_owned();
            }
            (left, right) => {
                return format!(
                    "is stale at line {line}:\n  committed: {}\n  generated: {}",
                    left.unwrap_or("<end of file>"),
                    right.unwrap_or("<end of file>"),
                );
            }
        }
    }
}

#[test]
fn a_line_ending_difference_is_named_rather_than_shown_as_matching_lines() {
    assert_eq!(
        difference("{\r\n}\r\n", "{\n}\n"),
        "uses CRLF line endings; the generator writes LF"
    );
    assert_eq!(
        difference("{\n}", "{\n}\n"),
        "differs only in its trailing newline; the generator ends the file with one newline"
    );
    assert_eq!(
        difference("{\n  \"a\": 1\n}\n", "{\n  \"a\": 2\n}\n"),
        "is stale at line 2:\n  committed:   \"a\": 1\n  generated:   \"a\": 2"
    );
    assert_eq!(
        difference("{\n", "{\n}\n"),
        "is stale at line 2:\n  committed: <end of file>\n  generated: }"
    );
}

#[test]
fn the_snapshot_omits_the_workspace_version() {
    let snapshot = catalog_snapshot().expect("the catalog serializes");
    let value: serde_json::Value = serde_json::from_str(&snapshot).expect("the snapshot is JSON");
    let keys: Vec<&str> = value
        .as_object()
        .expect("the snapshot is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["binaries", "schema_version"]);
    assert!(snapshot.ends_with("}\n"));
}
