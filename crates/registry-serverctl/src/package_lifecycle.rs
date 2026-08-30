// SPDX-License-Identifier: Apache-2.0
//! Deterministic package signing-input and publication orchestration.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use registry_platform_canonical_json::parse_json_strict;
use registry_server::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package,
};
use registry_server::package::{
    PackageError, PackageSignature, PreparedPackage, FIXTURE_JOURNEYS_PATH,
};
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
    TestReceiptRefused,
    TestReceiptEvidence,
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

pub(crate) fn validate_test_receipt(
    path: &Path,
    prepared: &PreparedPackage,
) -> Result<ValidatedTestReceipt, PackageLifecycleError> {
    let bytes = read_test_receipt(path)?;
    let journeys = prepared
        .file_bytes()
        .get(FIXTURE_JOURNEYS_PATH)
        .ok_or(PackageLifecycleError::TestReceiptRefused)?;
    let suite = validate_fixture_journeys(journeys, prepared.registry())
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let receipt = validate_schema_test_receipt_for_package(&bytes, prepared, &suite)
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let canonical = receipt
        .canonical_bytes()
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    if canonical != bytes {
        return Err(PackageLifecycleError::TestReceiptRefused);
    }
    Ok(ValidatedTestReceipt { bytes })
}

fn outcome(
    prepared: &registry_server::package::PreparedPackage,
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
        .map_err(|_| PackageLifecycleError::TestReceiptEvidence)?;
        if existing_test_receipt != expected_test_receipt {
            return Err(PackageLifecycleError::TestReceiptEvidence);
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
        return Err(PackageLifecycleError::TestReceiptRefused);
    }
    super::ensure_no_symlink_components(path, "package.test_receipt.refused", "testReceipt")
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackageLifecycleError::TestReceiptMissing)
        }
        Err(_) => return Err(PackageLifecycleError::TestReceiptRefused),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_TEST_RECEIPT_BYTES
    {
        return Err(PackageLifecycleError::TestReceiptRefused);
    }
    let file = File::open(path).map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let opened = file
        .metadata()
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let after =
        fs::symlink_metadata(path).map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    if after.file_type().is_symlink()
        || !opened.is_file()
        || !super::same_file_metadata(&metadata, &opened)
        || !super::same_file_metadata(&opened, &after)
        || opened.len() > MAX_TEST_RECEIPT_BYTES
    {
        return Err(PackageLifecycleError::TestReceiptRefused);
    }
    let capacity =
        usize::try_from(opened.len()).map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_TEST_RECEIPT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| PackageLifecycleError::TestReceiptRefused)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_TEST_RECEIPT_BYTES {
        return Err(PackageLifecycleError::TestReceiptRefused);
    }
    Ok(bytes)
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
