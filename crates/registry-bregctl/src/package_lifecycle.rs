// SPDX-License-Identifier: Apache-2.0
//! Deterministic package signing-input and publication orchestration.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use registry_breg::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package,
};
use registry_breg::package::{
    PackageError, PackageSignature, PreparedPackage, FIXTURE_JOURNEYS_PATH,
};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const SIGNING_INPUT_PATH: &str = "signing-input.json";
const TEST_RECEIPT_PATH: &str = "schema-test-receipt.json";
const PACKAGE_DIRECTORY: &str = "package";
const MAX_SIGNATURE_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_TEST_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackageLifecycleState {
    AwaitingSignatures,
    Published,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackageLifecycleOutcome {
    pub state: PackageLifecycleState,
    pub package_revision: String,
    pub signing_input_sha256: String,
    pub signing_input_bytes: usize,
    pub signature_threshold: u16,
    pub provided_signatures: usize,
    pub package_files: usize,
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
    SignatureDocument,
    TestReceiptMissing,
    /// The receipt file itself could not be taken in: path, permissions, size.
    TestReceiptRefused {
        message: String,
    },
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
    /// The receipt records a different deployment identity than the candidate.
    TestReceiptIdentity {
        field: &'static str,
        receipt: String,
        package: String,
    },
    /// The receipt records the same identity but a different candidate build.
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
    environment: String,
    instance_id: String,
    database_id: String,
    sequence: u64,
    candidate_package_revision: String,
    signing_input_sha256: String,
    target_managed_schema_fingerprint: String,
    journey_file_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignatureDocument {
    signatures: Vec<PackageSignature>,
}

pub(crate) fn run(
    prepared: PreparedPackage,
    test_receipt: ValidatedTestReceipt,
    build_directory: &Path,
    signature_document: Option<&Path>,
) -> Result<PackageLifecycleOutcome, PackageLifecycleError> {
    let signed_bytes = prepared.canonical_signed_bytes();
    ensure_reviewer_evidence(build_directory, signed_bytes, &test_receipt.bytes)?;

    let signatures = signature_document
        .map(read_signatures)
        .transpose()?
        .unwrap_or_default();
    let threshold = prepared.manifest().signature_policy.threshold;
    let requires_external_signatures = prepared.manifest().environment != "local";
    if requires_external_signatures && signature_document.is_none() {
        return Ok(outcome(
            &prepared,
            PackageLifecycleState::AwaitingSignatures,
            0,
        ));
    }

    prepared
        .publish_to_directory(&build_directory.join(PACKAGE_DIRECTORY), signatures.clone())
        .map_err(PackageLifecycleError::Package)?;
    Ok(PackageLifecycleOutcome {
        state: PackageLifecycleState::Published,
        package_revision: prepared.package_revision().to_owned(),
        signing_input_sha256: sha256(signed_bytes),
        signing_input_bytes: signed_bytes.len(),
        signature_threshold: threshold,
        provided_signatures: signatures.len(),
        package_files: prepared.file_bytes().len() + 1,
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
    let suite = validate_fixture_journeys(journeys, prepared.registry()).map_err(|error| {
        PackageLifecycleError::TestReceiptRefused {
            message: format!("the packaged journey suite was refused: {error}"),
        }
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
            "environment",
            fields.environment,
            manifest.environment.clone(),
        ),
        (
            "instanceId",
            fields.instance_id,
            manifest.instance_id.clone(),
        ),
        (
            "databaseId",
            fields.database_id,
            manifest.database_id.clone(),
        ),
        (
            "sequence",
            fields.sequence.to_string(),
            manifest.sequence.to_string(),
        ),
    ] {
        if receipt != package {
            return PackageLifecycleError::TestReceiptIdentity {
                field,
                receipt,
                package,
            };
        }
    }
    for (field, receipt, package) in [
        (
            "candidatePackageRevision",
            fields.candidate_package_revision,
            manifest.package_revision.clone(),
        ),
        (
            "signingInputSha256",
            fields.signing_input_sha256,
            sha256(prepared.canonical_signed_bytes()),
        ),
        (
            "journeyFileSha256",
            fields.journey_file_sha256,
            suite.file_sha256().to_owned(),
        ),
        (
            "targetManagedSchemaFingerprint",
            fields.target_managed_schema_fingerprint,
            manifest.schema_fingerprint.clone(),
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

fn outcome(
    prepared: &registry_breg::package::PreparedPackage,
    state: PackageLifecycleState,
    provided_signatures: usize,
) -> PackageLifecycleOutcome {
    let signed_bytes = prepared.canonical_signed_bytes();
    PackageLifecycleOutcome {
        state,
        package_revision: prepared.package_revision().to_owned(),
        signing_input_sha256: sha256(signed_bytes),
        signing_input_bytes: signed_bytes.len(),
        signature_threshold: prepared.manifest().signature_policy.threshold,
        provided_signatures,
        package_files: prepared.file_bytes().len() + 1,
    }
}

fn ensure_reviewer_evidence(
    build_directory: &Path,
    expected_signing_input: &[u8],
    expected_test_receipt: &[u8],
) -> Result<(), PackageLifecycleError> {
    if build_directory.exists() {
        super::validate_directory_for(
            build_directory,
            "package.output.invalid",
            "output",
            "the package build directory is unavailable",
            "the package build path must be a directory and must not be a symbolic link",
        )
        .map_err(|_| PackageLifecycleError::Output)?;
        let existing_signing_input =
            read_bounded_regular(&build_directory.join(SIGNING_INPUT_PATH))?;
        let existing_test_receipt = read_bounded_regular_with_bound(
            &build_directory.join(TEST_RECEIPT_PATH),
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
        if existing_signing_input != expected_signing_input
            || build_directory.join(PACKAGE_DIRECTORY).exists()
        {
            return Err(PackageLifecycleError::Output);
        }
        return Ok(());
    }
    let files = BTreeMap::from([
        (
            SIGNING_INPUT_PATH.to_owned(),
            expected_signing_input.to_vec(),
        ),
        (TEST_RECEIPT_PATH.to_owned(), expected_test_receipt.to_vec()),
    ]);
    super::write_source_files(build_directory, &files).map_err(|_| PackageLifecycleError::Output)
}

fn read_signatures(path: &Path) -> Result<Vec<PackageSignature>, PackageLifecycleError> {
    let bytes = read_bounded_regular(path)?;
    let value = parse_json_strict(&bytes).map_err(|_| PackageLifecycleError::SignatureDocument)?;
    let document: SignatureDocument =
        serde_json::from_value(value).map_err(|_| PackageLifecycleError::SignatureDocument)?;
    if document.signatures.is_empty() || document.signatures.len() > 128 {
        return Err(PackageLifecycleError::SignatureDocument);
    }
    Ok(document.signatures)
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, PackageLifecycleError> {
    read_bounded_regular_with_bound(path, MAX_SIGNATURE_DOCUMENT_BYTES)
}

fn read_bounded_regular_with_bound(
    path: &Path,
    bound: u64,
) -> Result<Vec<u8>, PackageLifecycleError> {
    if path.as_os_str().is_empty() || super::has_parent_component(path) {
        return Err(PackageLifecycleError::Output);
    }
    super::ensure_no_symlink_components(path, "package.input.invalid", "package")
        .map_err(|_| PackageLifecycleError::Output)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PackageLifecycleError::Output)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > bound
    {
        return Err(PackageLifecycleError::Output);
    }
    fs::read(path).map_err(|_| PackageLifecycleError::Output)
}

fn read_test_receipt(path: &Path) -> Result<Vec<u8>, PackageLifecycleError> {
    if !path.is_absolute() || super::has_parent_component(path) {
        return Err(receipt_refused(
            "the schema-test receipt path must be absolute and must not contain a parent component",
        ));
    }
    super::ensure_no_symlink_components(path, "package.test_receipt.refused", "testReceipt")
        .map_err(|_| {
            receipt_refused("the schema-test receipt path must not traverse a symbolic link")
        })?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackageLifecycleError::TestReceiptMissing)
        }
        Err(_) => return Err(receipt_refused("the schema-test receipt is not readable")),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_TEST_RECEIPT_BYTES
    {
        return Err(receipt_refused(&format!(
            "the schema-test receipt must be a regular file of 1 to {MAX_TEST_RECEIPT_BYTES} bytes"
        )));
    }
    let file =
        File::open(path).map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    let opened = file
        .metadata()
        .map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|_| receipt_refused("the schema-test receipt is not readable"))?;
    if after.file_type().is_symlink()
        || !opened.is_file()
        || !super::same_file_metadata(&metadata, &opened)
        || !super::same_file_metadata(&opened, &after)
        || opened.len() > MAX_TEST_RECEIPT_BYTES
    {
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

fn receipt_refused(message: &str) -> PackageLifecycleError {
    PackageLifecycleError::TestReceiptRefused {
        message: message.to_owned(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_document_is_closed_and_never_accepts_an_empty_approval_set() {
        for refused in [
            br#"{"signatures":[]}"#.as_slice(),
            br#"{"signatures":[],"privateKey":"canary"}"#.as_slice(),
            br#"[{"keyId":"operator","signatureHex":"00"}]"#.as_slice(),
        ] {
            let parsed = serde_json::from_slice::<SignatureDocument>(refused);
            assert!(parsed.is_err() || parsed.is_ok_and(|document| document.signatures.is_empty()));
        }
    }
}
