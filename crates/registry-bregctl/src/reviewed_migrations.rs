// SPDX-License-Identifier: Apache-2.0
//! Capture reviewed migration inputs once, before credentials or database I/O.
//! Package validation remains the authority for SQL, coverage, and evidence.

use std::collections::BTreeMap;
use std::path::Path;

use registry_breg::migration_plan::{
    reviewed_artifact_kind, MigrationRehearsalReceipt, ReviewedArtifactKind, ReviewedMigrationFile,
    ReviewedMigrationSource,
};
use registry_breg::package::{MAX_PACKAGE_BYTES, MAX_PACKAGE_FILES, MAX_PACKAGE_SOURCE_FILE_BYTES};
use registry_breg::Diagnostic;
use registry_platform_canonical_json::parse_json_strict;

#[derive(Debug)]
pub(crate) struct CapturedReview {
    pub sources: Vec<ReviewedMigrationSource>,
    // A hint for prevalidation only. `test` subsequently measures the candidate
    // fingerprint and the package validator requires an exact receipt match.
    pub declared_schema_fingerprint: String,
}

pub(crate) fn capture(root: &Path) -> Result<CapturedReview, Diagnostic> {
    if super::has_parent_component(root) {
        return Err(refusal(
            "migration.review.path",
            "reviewedMigrations",
            "use a directory without parent traversal",
        ));
    }
    super::validate_directory(root, "migration.review.path").map_err(|_| {
        refusal(
            "migration.review.path",
            "reviewedMigrations",
            "use an existing regular directory without symbolic links",
        )
    })?;
    let mut files = BTreeMap::new();
    let mut budget = CaptureBudget::default();
    capture_directory(root, "", &mut files, &mut budget)?;
    if files.is_empty() {
        return Err(refusal(
            "migration.review.empty",
            "reviewedMigrations",
            "provide modules/<module>/migrations/<id>/descriptor.json and its referenced evidence",
        ));
    }
    let mut groups: BTreeMap<String, Vec<ReviewedMigrationFile>> = BTreeMap::new();
    let mut declared_schema_fingerprint = None;
    for (path, bytes) in files {
        // Every file path was accepted by the package's existing path classifier.
        let parts = path.split('/').collect::<Vec<_>>();
        let base = parts[..4].join("/");
        if reviewed_artifact_kind(&path) == Some(ReviewedArtifactKind::RehearsalReceipt) {
            let receipt: MigrationRehearsalReceipt = parse_json_strict(&bytes)
                .ok()
                .and_then(|value| serde_json::from_value(value).ok())
                .ok_or_else(|| refusal("migration.review.receipt", &path, "provide a strict rehearsal receipt using the existing MigrationRehearsalReceipt format"))?;
            if declared_schema_fingerprint
                .as_ref()
                .is_some_and(|expected| expected != &receipt.final_schema_fingerprint)
            {
                return Err(refusal(
                    "migration.review.fingerprint",
                    &path,
                    "all rehearsal receipts must bind the same candidate schema fingerprint",
                ));
            }
            declared_schema_fingerprint = Some(receipt.final_schema_fingerprint);
        }
        groups
            .entry(base)
            .or_default()
            .push(ReviewedMigrationFile { path, bytes });
    }
    let mut sources = Vec::with_capacity(groups.len());
    for (base, mut files) in groups {
        let descriptor_path = format!("{base}/descriptor.json");
        let index = files
            .iter()
            .position(|file| file.path == descriptor_path)
            .ok_or_else(|| {
                refusal(
                    "migration.review.descriptor",
                    &descriptor_path,
                    "each migration directory must contain descriptor.json",
                )
            })?;
        let descriptor = files.remove(index);
        sources.push(ReviewedMigrationSource {
            module_id: base
                .split('/')
                .nth(1)
                .expect("classified module path")
                .to_owned(),
            descriptor,
            files,
        });
    }
    let declared_schema_fingerprint = declared_schema_fingerprint.ok_or_else(||
        refusal("migration.review.receipt", "reviewedMigrations", "provide the referenced rehearsal.json; the CLI does not manufacture migration evidence"))?;
    Ok(CapturedReview {
        sources,
        declared_schema_fingerprint,
    })
}

#[derive(Default)]
struct CaptureBudget {
    entries: usize,
    bytes: u64,
}

fn capture_directory(
    root: &Path,
    relative: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    budget: &mut CaptureBudget,
) -> Result<(), Diagnostic> {
    // The held descriptor is what the listing below reads, so replacing a
    // component of the operator's reviewed-migrations path after this check
    // cannot substitute another directory's inventory.
    let directory = super::validate_directory(&root.join(relative), "migration.review.path")
        .map_err(|_| {
            refusal(
                "migration.review.path",
                "reviewedMigrations",
                "migration directories must not contain symbolic links",
            )
        })?;
    let entries = directory.read_entries().map_err(|_| {
        refusal(
            "migration.review.unavailable",
            "reviewedMigrations",
            "the reviewed migration directory cannot be read",
        )
    })?;
    for entry in entries {
        budget.entries += 1;
        if budget.entries > MAX_PACKAGE_FILES * 2 {
            return Err(refusal(
                "migration.review.bounds",
                "reviewedMigrations",
                "the reviewed artifact inventory exceeds package bounds",
            ));
        }
        let name = entry.name.to_str().ok_or_else(|| {
            refusal(
                "migration.review.path",
                "reviewedMigrations",
                "use UTF-8 package-relative artifact names",
            )
        })?;
        let path = if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        if entry.is_dir {
            // The deepest accepted file is modules/<module>/migrations/<id>/fixtures/<id>.jsonl.
            if path.split('/').count() > 5 {
                return Err(refusal(
                    "migration.review.path",
                    "reviewedMigrations",
                    "use the package's modules/<module>/migrations/<id> layout",
                ));
            }
            capture_directory(root, &path, files, budget)?;
            continue;
        }
        if !entry.is_file || reviewed_artifact_kind(&path).is_none() {
            return Err(refusal("migration.review.path", "reviewedMigrations", "only regular reviewed migration artifacts in the package layout are accepted; remove unrelated files and symbolic links"));
        }
        if files.len() >= MAX_PACKAGE_FILES {
            return Err(refusal(
                "migration.review.bounds",
                "reviewedMigrations",
                "the reviewed artifact inventory exceeds package bounds",
            ));
        }
        let bound = if reviewed_artifact_kind(&path) == Some(ReviewedArtifactKind::Fixture) {
            MAX_PACKAGE_SOURCE_FILE_BYTES
        } else {
            super::AUTHORED_SOURCE_REDERIVATION_MAX_BYTES
        };
        let bytes = super::read_bounded_regular_file(&root.join(&path), "migration.review.unavailable", bound.min(MAX_PACKAGE_BYTES.saturating_sub(budget.bytes)))
            .map_err(|_| refusal("migration.review.file", &path, "the artifact must be readable, regular, unchanged during capture, and within package size bounds"))?;
        budget.bytes += bytes.len() as u64;
        files.insert(path, bytes);
    }
    Ok(())
}

fn refusal(code: &str, path: &str, message: &str) -> Diagnostic {
    super::diagnostic(code, path, message)
}

/// Deterministic ancestor-swap regression for the reviewed-migrations input
/// this module owns. Capture resolves each nested directory and file again from
/// the operator's root, so a swap that lands mid-capture refuses rather than
/// silently inventorying a tree the operator never named.
#[cfg(all(test, any(target_os = "linux", target_vendor = "apple")))]
mod tests {
    use super::*;
    use crate::safe_path::race_fixture::race_tree;

    #[test]
    fn a_capture_after_an_ancestor_swap_never_inventories_outside_the_named_tree() {
        let tree = race_tree();
        std::fs::create_dir_all(tree.named("modules/core/migrations/0001")).unwrap();
        std::fs::write(
            tree.named("modules/core/migrations/0001/up.sql"),
            b"genuine",
        )
        .unwrap();
        std::fs::create_dir_all(tree.outside("modules/core/migrations/0001")).unwrap();
        std::fs::write(
            tree.outside("modules/core/migrations/0001/up.sql"),
            b"decoy",
        )
        .unwrap();

        let guard = tree.arm();
        let refused = capture(&tree.named_directory())
            .expect_err("a resolution that would traverse the swapped ancestor is refused");
        drop(guard);

        assert_eq!(refused.code, "migration.review.path");
    }
}
