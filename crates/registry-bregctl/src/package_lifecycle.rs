// SPDX-License-Identifier: Apache-2.0
//! Deterministic package publication orchestration.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::Read;
use std::path::Path;

use registry_breg::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package, FixtureError,
};
use registry_breg::package::{
    PackageError, PackageFileRole, PreparedPackage, FIXTURE_JOURNEYS_PATH,
};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::Deserialize;

use crate::safe_path::{EntryStat, SafeDir, SafeEntry};

const TEST_RECEIPT_PATH: &str = "schema-test-receipt.json";
const PACKAGE_DIRECTORY: &str = "package";
const MAX_TEST_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackageLifecycleOutcome {
    pub package_digest: String,
    pub registry_revision: String,
    pub package_files: usize,
    pub revision: Option<String>,
}

/// Canonical receipt bytes that have been rederived against one exact
/// in-memory candidate. No unchecked constructor is exposed.
pub(crate) struct ValidatedTestReceipt {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum PackageLifecycleError {
    Package(PackageError),
    Output,
    TestReceiptMissing,
    /// The receipt file itself could not be taken in: path, permissions, size.
    TestReceiptRefused {
        message: String,
    },
    /// The shared reader refused the candidate's fixture journeys.
    Journeys(registry_platform_yaml::Report),
    /// The receipt bytes are not a strict canonical receipt document.
    TestReceiptInvalid {
        message: String,
    },
    /// The receipt was produced for a different target schema fingerprint than
    /// the one supplied on the command line.
    TestReceiptFingerprint {
        receipt: String,
        supplied: String,
    },
    /// The receipt records a different candidate build.
    TestReceiptCandidate {
        field: &'static str,
        receipt: String,
        package: String,
    },
    /// The receipt kept in the build directory is not the receipt being used.
    TestReceiptEvidence {
        message: String,
    },
}

/// The receipt fields this tool reads to explain a refusal and to derive the
/// target schema fingerprint. The runtime remains the authority on the receipt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestReceiptFields {
    registry_revision: String,
    project_source_revision: String,
    #[serde(default)]
    prior_package_digest: Option<String>,
    target_managed_schema_fingerprint: String,
    journey_file_sha256: String,
    migration_plan_sha256: String,
    source_closure_sha256: String,
}

pub(crate) fn run(
    prepared: PreparedPackage,
    test_receipt: ValidatedTestReceipt,
    build_directory: &Path,
    revision: Option<&str>,
) -> Result<PackageLifecycleOutcome, PackageLifecycleError> {
    ensure_reviewer_evidence(build_directory, &test_receipt.bytes)?;

    let shared = prepared
        .publish_to_directory_with_revision(&build_directory.join(PACKAGE_DIRECTORY), revision)
        .map_err(PackageLifecycleError::Package)?;
    Ok(PackageLifecycleOutcome {
        package_digest: shared.digest().to_owned(),
        registry_revision: prepared.registry().revision().to_owned(),
        package_files: shared.files().count() + 1,
        revision: shared.revision().map(str::to_owned),
    })
}

/// Read the target managed schema fingerprint the receipt was produced for, so
/// `package` can use it when the operator does not restate it.
pub(crate) fn receipt_schema_fingerprint(path: &Path) -> Result<String, PackageLifecycleError> {
    let bytes = read_test_receipt(path)?;
    Ok(receipt_fields(&bytes)?.target_managed_schema_fingerprint)
}

pub(crate) fn validate_test_receipt(
    path: &Path,
    prepared: &PreparedPackage,
    supplied_schema_fingerprint: Option<&str>,
) -> Result<ValidatedTestReceipt, PackageLifecycleError> {
    let bytes = read_test_receipt(path)?;
    let fields = receipt_fields(&bytes)?;
    if let Some(supplied) = supplied_schema_fingerprint {
        if supplied != fields.target_managed_schema_fingerprint {
            return Err(PackageLifecycleError::TestReceiptFingerprint {
                receipt: fields.target_managed_schema_fingerprint,
                supplied: supplied.to_owned(),
            });
        }
    }
    let journeys = prepared
        .file_bytes()
        .get(FIXTURE_JOURNEYS_PATH)
        .ok_or_else(|| PackageLifecycleError::TestReceiptRefused {
            message: format!("the candidate carries no {FIXTURE_JOURNEYS_PATH}"),
        })?;
    let suite =
        validate_fixture_journeys(journeys, prepared.registry()).map_err(|error| match error {
            FixtureError::JourneyDocument(report) => PackageLifecycleError::Journeys(report),
            error => PackageLifecycleError::TestReceiptRefused {
                message: format!("the packaged journey suite was refused: {error}"),
            },
        })?;
    if let Err(error) = validate_schema_test_receipt_for_package(&bytes, prepared, &suite) {
        return Err(explain_receipt_binding(fields, prepared, &suite, error));
    }
    Ok(ValidatedTestReceipt { bytes })
}

/// Name the exact disagreement between a well-formed receipt and this
/// candidate. The runtime already refused the pair; this only reports why.
fn explain_receipt_binding(
    fields: TestReceiptFields,
    prepared: &PreparedPackage,
    suite: &registry_breg::fixtures::ValidatedFixtureJourneys,
    error: registry_breg::fixtures::FixtureError,
) -> PackageLifecycleError {
    let manifest = prepared.manifest();
    for (field, receipt, package) in [
        (
            "registryRevision",
            fields.registry_revision,
            prepared.registry().revision().to_owned(),
        ),
        (
            "projectSourceRevision",
            fields.project_source_revision,
            prepared
                .registry()
                .package()
                .map(|identity| identity.source_revision.clone())
                .unwrap_or_default(),
        ),
        (
            "priorPackageDigest",
            fields.prior_package_digest.unwrap_or_default(),
            manifest
                .migration_plan
                .from_package_digest
                .clone()
                .unwrap_or_default(),
        ),
        (
            "journeyFileSha256",
            fields.journey_file_sha256,
            suite.file_sha256().to_owned(),
        ),
        (
            "migrationPlanSha256",
            fields.migration_plan_sha256,
            manifest
                .files
                .iter()
                .find(|file| file.role == PackageFileRole::MigrationPlan)
                .map(|file| file.sha256.clone())
                .unwrap_or_default(),
        ),
        (
            "targetManagedSchemaFingerprint",
            fields.target_managed_schema_fingerprint,
            manifest.schema_fingerprint.clone(),
        ),
        (
            "sourceClosureSha256",
            fields.source_closure_sha256,
            registry_breg::fixtures::schema_test_source_closure_sha256(prepared)
                .unwrap_or_default(),
        ),
    ] {
        if receipt != package {
            return PackageLifecycleError::TestReceiptCandidate {
                field,
                receipt,
                package,
            };
        }
    }
    PackageLifecycleError::TestReceiptRefused {
        message: format!("the receipt does not bind this candidate: {error}"),
    }
}

fn receipt_fields(bytes: &[u8]) -> Result<TestReceiptFields, PackageLifecycleError> {
    let value =
        parse_json_strict(bytes).map_err(|_| PackageLifecycleError::TestReceiptInvalid {
            message: "the schema-test receipt must be strict JSON without duplicate keys"
                .to_owned(),
        })?;
    let canonical =
        canonicalize_json(&value).map_err(|_| PackageLifecycleError::TestReceiptInvalid {
            message: "the schema-test receipt is not canonicalizable JSON".to_owned(),
        })?;
    if canonical != bytes {
        return Err(PackageLifecycleError::TestReceiptInvalid {
            message: "the schema-test receipt bytes must be exactly the canonical document written by test".to_owned(),
        });
    }
    serde_json::from_value(value).map_err(|error| PackageLifecycleError::TestReceiptInvalid {
        message: format!("the schema-test receipt document is incomplete: {error}"),
    })
}

fn ensure_reviewer_evidence(
    build_directory: &Path,
    expected_test_receipt: &[u8],
) -> Result<(), PackageLifecycleError> {
    // Resolving once decides both outcomes: a build directory that is there
    // is compared through the descriptor this opens, and one that is not there
    // is the first run, which writes the evidence below. Anything else about
    // the path, a symbolic link included, is refused rather than retried by
    // name.
    let existing = match SafeDir::resolve(build_directory) {
        Ok(directory) => Some(directory),
        Err(error) if error.is_not_found() => None,
        Err(_) => return Err(PackageLifecycleError::Output),
    };
    if let Some(directory) = existing {
        // The held descriptor is what the evidence reads and the published
        // package check below use, so replacing a component of the build path
        // afterwards can neither substitute the evidence compared here nor hide
        // an already published package.
        let existing_test_receipt = read_bounded_entry(
            &directory,
            OsStr::new(TEST_RECEIPT_PATH),
            MAX_TEST_RECEIPT_BYTES,
        )
        .map_err(|_| PackageLifecycleError::TestReceiptEvidence {
            message: format!(
                "the build directory holds no readable {TEST_RECEIPT_PATH} to compare against"
            ),
        })?;
        if existing_test_receipt != expected_test_receipt {
            return Err(PackageLifecycleError::TestReceiptEvidence {
                message: format!(
                    "the {TEST_RECEIPT_PATH} kept in the build directory is not the receipt supplied to this run"
                ),
            });
        }
        if directory
            .entry_exists(OsStr::new(PACKAGE_DIRECTORY))
            .map_err(|_| PackageLifecycleError::Output)?
        {
            return Err(PackageLifecycleError::Output);
        }
        return Ok(());
    }
    let files = BTreeMap::from([(TEST_RECEIPT_PATH.to_owned(), expected_test_receipt.to_vec())]);
    super::write_source_files(build_directory, &files).map_err(|_| PackageLifecycleError::Output)
}

/// Read a bounded regular file through a held directory descriptor, for callers
/// that must read the tree they resolved rather than the pathname again.
fn read_bounded_entry(
    directory: &SafeDir,
    name: &OsStr,
    bound: u64,
) -> Result<Vec<u8>, PackageLifecycleError> {
    let stat = directory
        .entry_stat(name)
        .map_err(|_| PackageLifecycleError::Output)?;
    if stat.is_symlink() || !stat.is_file() || stat.len() == 0 || stat.len() > bound {
        return Err(PackageLifecycleError::Output);
    }
    // The descriptor is opened through the held directory with `O_NOFOLLOW`, so
    // no ancestor and no symbolic link can redirect the open. The name is still
    // resolved a second time here, so the identity check below is what rejects a
    // name relinked between the stat above and this open.
    let file = directory
        .open_read(name)
        .map_err(|_| PackageLifecycleError::Output)?;
    let opened = file.metadata().map_err(|_| PackageLifecycleError::Output)?;
    ensure_package_input_identity(stat, &opened)?;
    let mut bytes = Vec::new();
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PackageLifecycleError::Output)?;
    if bytes.is_empty() || bytes.len() as u64 > bound {
        return Err(PackageLifecycleError::Output);
    }
    Ok(bytes)
}

/// Refuse a bounded package input whose opened descriptor is not the entry that
/// was stat'ed. See `super::ensure_source_entry_identity` for the window a
/// stat-then-open pair leaves open.
fn ensure_package_input_identity(
    stat: EntryStat,
    opened: &Metadata,
) -> Result<(), PackageLifecycleError> {
    if stat.is_same_file_as(opened) {
        return Ok(());
    }
    Err(PackageLifecycleError::Output)
}

fn read_test_receipt(path: &Path) -> Result<Vec<u8>, PackageLifecycleError> {
    if !path.is_absolute() || super::has_parent_component(path) {
        return Err(receipt_refused(
            "the schema-test receipt path must be absolute and must not contain a parent component",
        ));
    }
    let entry = SafeEntry::resolve(path).map_err(|error| {
        if error.is_not_found() {
            PackageLifecycleError::TestReceiptMissing
        } else {
            receipt_refused("the schema-test receipt path must not traverse a symbolic link")
        }
    })?;
    let stat = match entry.stat() {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackageLifecycleError::TestReceiptMissing)
        }
        Err(_) => return Err(receipt_refused("the schema-test receipt is not readable")),
    };
    if stat.is_symlink()
        || !stat.is_file()
        || stat.len() == 0
        || stat.len() > MAX_TEST_RECEIPT_BYTES
    {
        return Err(receipt_refused(&format!(
            "the schema-test receipt must be a regular file of 1 to {MAX_TEST_RECEIPT_BYTES} bytes"
        )));
    }
    // The descriptor comes from the resolved parent with `O_NOFOLLOW`, so no
    // ancestor and no symbolic link can redirect the open. The final name is
    // still resolved a second time here, so the identity check below is what
    // rejects a name relinked between the stat above and this open.
    let file = entry
        .open_read()
        .map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    let opened = file
        .metadata()
        .map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    ensure_receipt_identity(stat, &opened)?;
    if !opened.is_file() || opened.len() > MAX_TEST_RECEIPT_BYTES {
        return Err(receipt_refused(
            "the schema-test receipt changed while it was being read",
        ));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| receipt_refused("the schema-test receipt is larger than this tool reads"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_TEST_RECEIPT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_TEST_RECEIPT_BYTES {
        return Err(receipt_refused(
            "the schema-test receipt changed while it was being read",
        ));
    }
    Ok(bytes)
}

/// Refuse a schema-test receipt whose opened descriptor is not the entry that
/// was stat'ed. See `super::ensure_source_entry_identity` for the window a
/// stat-then-open pair leaves open.
fn ensure_receipt_identity(
    stat: EntryStat,
    opened: &Metadata,
) -> Result<(), PackageLifecycleError> {
    if stat.is_same_file_as(opened) {
        return Ok(());
    }
    Err(receipt_refused(
        "the schema-test receipt changed while it was being read",
    ))
}

fn receipt_refused(message: &str) -> PackageLifecycleError {
    PackageLifecycleError::TestReceiptRefused {
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic ancestor-swap regression for the schema-test receipt input
    /// this module owns.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod ancestor_swap {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn a_reviewer_evidence_check_after_an_ancestor_swap_still_sees_the_named_package() {
            let tree = race_tree();
            let build = tree.named("build");
            std::fs::create_dir_all(build.join(PACKAGE_DIRECTORY)).unwrap();
            std::fs::write(build.join(TEST_RECEIPT_PATH), b"receipt").unwrap();
            // The tree the operator never named holds the same evidence without
            // a published package directory, which is what a check made by
            // pathname would read instead.
            let decoy = tree.outside("build");
            std::fs::create_dir_all(&decoy).unwrap();
            std::fs::write(decoy.join(TEST_RECEIPT_PATH), b"receipt").unwrap();

            // Swap once the build directory is resolved, so only the held
            // descriptor still names the real tree.
            let guard = tree.arm();
            let refused = ensure_reviewer_evidence(&build, b"receipt")
                .expect_err("an already published package directory is refused");
            drop(guard);

            assert!(matches!(refused, PackageLifecycleError::Output));
        }

        #[test]
        fn reviewer_evidence_after_an_ancestor_swap_compares_the_named_build_directory() {
            let tree = race_tree();
            let build = tree.named("build");
            std::fs::create_dir_all(&build).unwrap();
            std::fs::write(build.join(TEST_RECEIPT_PATH), b"other receipt").unwrap();
            // The tree the operator never named holds evidence that matches
            // this run, which is what a comparison made by pathname would
            // accept instead of the mismatched evidence really on disk. It is
            // moved into place as a real directory, so resolving the pathname
            // again would meet no symbolic link to refuse.
            let decoy = tree.outside("build");
            std::fs::create_dir_all(&decoy).unwrap();
            std::fs::write(decoy.join(TEST_RECEIPT_PATH), b"receipt").unwrap();

            // Swap once the build directory is resolved and before its evidence
            // is read, which is where a racing process would land.
            let guard = tree.arm_directory_swap();
            let refused = ensure_reviewer_evidence(&build, b"receipt")
                .expect_err("evidence from a directory the operator never named is refused");
            drop(guard);

            assert!(matches!(
                refused,
                PackageLifecycleError::TestReceiptEvidence { .. }
            ));
        }

        #[test]
        fn a_receipt_read_after_an_ancestor_swap_reads_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("schema-test-receipt.json");
            std::fs::write(&named, b"genuine").unwrap();
            std::fs::write(tree.outside("schema-test-receipt.json"), b"decoy").unwrap();

            let guard = tree.arm();
            let bytes = read_test_receipt(&named).unwrap();
            drop(guard);

            assert_eq!(bytes, b"genuine");
            // The window is real: the same pathname now reaches the tree the
            // operator never named.
            assert_eq!(std::fs::read(&named).unwrap(), b"decoy");
        }
    }

    /// Coverage for the single resolution the reviewer-evidence check makes.
    /// One `SafeDir::resolve` decides whether this run compares evidence or
    /// writes it, so no branch here reaches the build path by name a second
    /// time.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod build_directory_resolution {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn a_first_run_writes_the_evidence_into_the_named_build_directory() {
            let tree = race_tree();
            let build = tree.named("build");

            ensure_reviewer_evidence(&build, b"receipt")
                .expect("a build directory that is not there yet is the first run");

            assert_eq!(
                std::fs::read(build.join(TEST_RECEIPT_PATH)).unwrap(),
                b"receipt"
            );
        }

        #[cfg(unix)]
        #[test]
        fn a_build_directory_that_is_a_symbolic_link_is_refused_rather_than_followed() {
            use std::os::unix::fs::symlink;

            let tree = race_tree();
            let build = tree.named("build");
            // Matching evidence sits behind the link, so a check that followed
            // it would accept this run instead of refusing the path.
            let decoy = tree.outside("build");
            std::fs::create_dir_all(&decoy).unwrap();
            std::fs::write(decoy.join(TEST_RECEIPT_PATH), b"receipt").unwrap();
            symlink(&decoy, &build).unwrap();

            let refused = ensure_reviewer_evidence(&build, b"receipt")
                .expect_err("a build directory reached through a symbolic link is refused");

            assert!(matches!(refused, PackageLifecycleError::Output));
        }
    }

    /// Coverage for the identity checks the package inputs apply to the
    /// descriptors they open. A relink landing between the stat and the open
    /// cannot be scheduled from a test, so each check is exercised through its
    /// own seam with the two outcomes a reader can meet.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod relinked_entry {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        /// The stat of the file the operator named, paired with the metadata of
        /// the descriptor a reader holds once that name reaches another regular
        /// file.
        fn stat_and_relinked_metadata() -> (EntryStat, Metadata) {
            let tree = race_tree();
            let named = tree.named("input.json");
            std::fs::write(&named, b"genuine").unwrap();
            let relinked = tree.outside("input.json");
            std::fs::write(&relinked, b"decoy").unwrap();
            let stat = SafeEntry::resolve(&named).unwrap().stat().unwrap();
            let opened = std::fs::File::open(&relinked).unwrap().metadata().unwrap();
            (stat, opened)
        }

        /// The stat and the opened metadata of one file, which is what a read
        /// of an untouched input holds.
        fn stat_and_own_metadata() -> (EntryStat, Metadata) {
            let tree = race_tree();
            let named = tree.named("input.json");
            std::fs::write(&named, b"genuine").unwrap();
            let entry = SafeEntry::resolve(&named).unwrap();
            let stat = entry.stat().unwrap();
            let opened = entry.open_read().unwrap().metadata().unwrap();
            (stat, opened)
        }

        #[test]
        fn a_package_input_opened_as_another_file_is_refused() {
            let (stat, opened) = stat_and_relinked_metadata();

            let refused = ensure_package_input_identity(stat, &opened)
                .expect_err("a descriptor that is not the stat'ed entry is refused");

            assert!(matches!(refused, PackageLifecycleError::Output));
        }

        #[test]
        fn a_package_input_opened_as_the_stat_entry_is_read() {
            let (stat, opened) = stat_and_own_metadata();

            ensure_package_input_identity(stat, &opened)
                .expect("the entry that was stat'ed is read");
        }

        #[test]
        fn a_schema_test_receipt_opened_as_another_file_is_refused() {
            let (stat, opened) = stat_and_relinked_metadata();

            let refused = ensure_receipt_identity(stat, &opened)
                .expect_err("a descriptor that is not the stat'ed entry is refused");

            match refused {
                PackageLifecycleError::TestReceiptRefused { message } => assert_eq!(
                    message,
                    "the schema-test receipt changed while it was being read"
                ),
                other => panic!("unexpected refusal: {other:?}"),
            }
        }

        #[test]
        fn a_schema_test_receipt_opened_as_the_stat_entry_is_read() {
            let (stat, opened) = stat_and_own_metadata();

            ensure_receipt_identity(stat, &opened).expect("the entry that was stat'ed is read");
        }
    }
}
