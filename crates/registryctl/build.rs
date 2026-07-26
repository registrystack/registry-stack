// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

const EMBEDDED_PROJECT_TREES: &[&str] = &[
    "assets/project-starters",
    "tests/fixtures/project-authoring/dhis2-tracker",
    "tests/fixtures/project-authoring/fhir-r4-coverage-active",
    "tests/fixtures/project-authoring/opencrvs",
    "tests/fixtures/project-authoring/snapshot-exact",
];

fn main() {
    for tree in EMBEDDED_PROJECT_TREES {
        track_tree(Path::new(tree));
    }
}

fn track_tree(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
        panic!(
            "failed to inspect embedded project path {}: {error}",
            path.display()
        )
    });
    if !metadata.file_type().is_dir() {
        return;
    }

    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| {
            panic!(
                "failed to read embedded project tree {}: {error}",
                path.display()
            )
        })
        .map(|entry| {
            entry.unwrap_or_else(|error| {
                panic!(
                    "failed to inspect embedded project tree {}: {error}",
                    path.display()
                )
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        track_tree(&entry.path());
    }
}
