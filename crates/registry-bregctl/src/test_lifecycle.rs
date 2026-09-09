// SPDX-License-Identifier: Apache-2.0
//! Production schema-test orchestration for unsigned package candidates.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use registry_breg::fixtures::{
    execute_schema_test, validate_fixture_journeys, FixtureError, SchemaTestCredentialBinding,
    SchemaTestCredentialBindings, SchemaTestRuntimeSetupError,
};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use registry_breg::startup;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::safe_path::{EntryStat, SafeDir, SafeEntry};
use crate::CapturedPackageCandidate;

const CREDENTIALS_API_VERSION: &str = "registry.registrystack.org/breg-schema-test-credentials/v1";
const CREDENTIALS_KIND: &str = "SchemaTestCredentials";
const MAX_CREDENTIAL_DOCUMENT_BYTES: u64 = 64 * 1024;
const RECEIPT_ARTIFACT_PATH: &str = "schema-test-receipt.json";

static TEST_OUTPUT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct TestLifecycleRequest<'a> {
    pub candidate: CapturedPackageCandidate,
    pub runtime_config: &'a Path,
    pub credentials: &'a Path,
    pub output: OutputTarget,
}

#[derive(Debug)]
pub(crate) struct TestLifecycleOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub signing_input_sha256: String,
    pub successful_journey_ids: Vec<String>,
    pub receipt_sha256: String,
    pub receipt_bytes: usize,
}

/// The receipt destination, held as its resolved parent descriptor plus the
/// final component name. The preflight and the publication act through the same
/// descriptor, so no component of the operator's path is resolved twice.
#[derive(Debug)]
pub(crate) struct OutputTarget {
    destination: SafeEntry,
}

#[derive(Debug)]
pub(crate) enum TestLifecycleError {
    RuntimeConfigPath,
    RuntimeConfig(RuntimeConfigError),
    Candidate,
    CandidateBinding { path: &'static str },
    ReviewFingerprint,
    Journeys { message: String },
    JourneySyntax { path: String, message: &'static str },
    JourneyStep { path: String, message: String },
    Credentials { path: String, message: String },
    Database,
    FieldPatternSyntax { entity_id: String, field_id: String },
    Execution,
    RuntimeSetup(SchemaTestRuntimeSetupError),
    OutputPreflight,
    OutputCommit,
    Runtime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CredentialDocument {
    api_version: String,
    kind: String,
    bindings: Vec<CredentialBindingDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CredentialBindingDocument {
    journey_id: String,
    step_id: String,
    credential: CredentialDocumentMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "type")]
enum CredentialDocumentMode {
    Anonymous,
    Bearer {
        #[serde(rename = "tokenRef")]
        token_ref: String,
    },
}

pub(crate) fn preflight_output(path: &Path) -> Result<OutputTarget, TestLifecycleError> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || super::has_parent_component(path)
        || path.file_name().is_none()
    {
        return Err(TestLifecycleError::OutputPreflight);
    }
    // Resolving once yields the parent directory descriptor that the receipt
    // publication reuses, so replacing a component of `path` after this
    // preflight cannot redirect the write.
    let destination = SafeEntry::resolve(path).map_err(|_| TestLifecycleError::OutputPreflight)?;
    if destination
        .exists()
        .map_err(|_| TestLifecycleError::OutputPreflight)?
    {
        return Err(TestLifecycleError::OutputPreflight);
    }

    // Prove the destination can be created and removed before a long schema
    // test runs, rather than discovering an unwritable output afterwards.
    let file = destination
        .create_new(0o666)
        .map_err(|_| TestLifecycleError::OutputPreflight)?;
    let opened = match preflight_metadata(&file) {
        Ok(metadata) => metadata,
        Err(_) => {
            // The failed call is the only source of the identity a by-name
            // removal would need to prove it still targets this file, so none
            // is available here; leave the created file rather than unlink
            // whatever the name currently resolves to.
            drop(file);
            return Err(TestLifecycleError::OutputPreflight);
        }
    };
    let synced = file.sync_all();
    drop(file);
    if synced.is_err() {
        cleanup_exact_file(&destination, &opened);
        return Err(TestLifecycleError::OutputPreflight);
    }
    remove_exact_file(&destination, &opened).map_err(|_| TestLifecycleError::OutputPreflight)?;
    destination
        .parent()
        .sync()
        .map_err(|_| TestLifecycleError::OutputPreflight)?;
    Ok(OutputTarget { destination })
}

pub(crate) fn run(
    request: TestLifecycleRequest<'_>,
) -> Result<TestLifecycleOutcome, TestLifecycleError> {
    let config = load_test_runtime_config(request.runtime_config)?;
    request.candidate.validate_runtime_binding(&config)?;
    request
        .candidate
        .prevalidate()
        .map_err(|_| TestLifecycleError::Candidate)?;
    let suite = match validate_fixture_journeys(
        request.candidate.fixture_journeys(),
        request.candidate.registry(),
    ) {
        Ok(suite) => suite,
        Err(error) => {
            return Err(
                diagnose_fixture_journey_shape(request.candidate.fixture_journeys()).unwrap_or(
                    TestLifecycleError::Journeys {
                        message: error.to_string(),
                    },
                ),
            );
        }
    };
    let credentials = load_credentials(request.credentials, &config, &suite)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| TestLifecycleError::Runtime)?;
    let schema_fingerprint = runtime.block_on(async {
        startup::rehearse_schema_fingerprint(&config, request.candidate.registry())
            .await
            .map_err(schema_preparation_error)
    })?;
    if request
        .candidate
        .prevalidation_schema_fingerprint
        .as_ref()
        .is_some_and(|declared| declared != &schema_fingerprint)
    {
        return Err(TestLifecycleError::ReviewFingerprint);
    }
    let prepared = request
        .candidate
        .prepare(schema_fingerprint.clone())
        .map_err(|_| TestLifecycleError::Candidate)?;
    let signing_input_sha256 = sha256(prepared.canonical_signed_bytes());
    let package_revision = prepared.package_revision().to_owned();
    let receipt = runtime.block_on(async {
        let database = startup::prepare_schema_test_database(&config, &prepared)
            .await
            .map_err(schema_preparation_error)?;
        execute_schema_test(database, &config, &prepared, &suite, credentials)
            .await
            .map_err(execution_error)
    })?;
    let successful_journey_ids = receipt.successful_journey_ids().to_vec();
    let receipt_bytes = receipt
        .canonical_bytes()
        .map_err(|_| TestLifecycleError::Execution)?;
    publish_receipt(&request.output, &receipt_bytes)?;
    Ok(TestLifecycleOutcome {
        package_revision,
        schema_fingerprint,
        signing_input_sha256,
        successful_journey_ids,
        receipt_sha256: sha256(&receipt_bytes),
        receipt_bytes: receipt_bytes.len(),
    })
}

fn diagnose_fixture_journey_shape(bytes: &[u8]) -> Option<TestLifecycleError> {
    let value: Value = serde_norway::from_slice(bytes).ok()?;
    let journeys = value.get("journeys")?.as_array()?;
    for (journey_index, journey) in journeys.iter().enumerate() {
        let steps = journey.get("steps")?.as_array()?;
        for (step_index, step) in steps.iter().enumerate() {
            let request = step.get("request")?.as_object()?;
            if request.get("operation").and_then(Value::as_str) != Some("revise_request") {
                continue;
            }
            if request.contains_key("data") {
                return Some(TestLifecycleError::JourneySyntax {
                    path: format!("journeys[{journey_index}].steps[{step_index}].request.data"),
                    message: "revise_request fixture steps require rebase directly under request; remove the data wrapper",
                });
            }
            if !request.get("rebase").is_some_and(Value::is_boolean) {
                return Some(TestLifecycleError::JourneySyntax {
                    path: format!("journeys[{journey_index}].steps[{step_index}].request.rebase"),
                    message: "revise_request fixture steps require a boolean rebase field",
                });
            }
        }
    }
    None
}

fn load_test_runtime_config(path: &Path) -> Result<RuntimeConfig, TestLifecycleError> {
    if !path.is_absolute() || super::has_parent_component(path) {
        return Err(TestLifecycleError::RuntimeConfigPath);
    }
    load_runtime_config(path).map_err(TestLifecycleError::RuntimeConfig)
}

fn load_credentials(
    path: &Path,
    config: &RuntimeConfig,
    suite: &registry_breg::fixtures::ValidatedFixtureJourneys,
) -> Result<SchemaTestCredentialBindings, TestLifecycleError> {
    let bytes = read_credentials(path)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| {
        credentials_refusal("credentials", "the credentials document must be UTF-8")
    })?;
    let document: CredentialDocument = serde_norway::from_str(raw).map_err(|error| {
        let location = error
            .location()
            .map(|location| {
                format!(
                    " at line {} column {}",
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_default();
        credentials_refusal(
            "credentials",
            format!("the credentials document could not be parsed{location}; write a strict SchemaTestCredentials document"),
        )
    })?;
    if document.api_version != CREDENTIALS_API_VERSION {
        return Err(credentials_refusal(
            "apiVersion",
            format!("the credentials document apiVersion must be {CREDENTIALS_API_VERSION}"),
        ));
    }
    if document.kind != CREDENTIALS_KIND {
        return Err(credentials_refusal(
            "kind",
            format!("the credentials document kind must be {CREDENTIALS_KIND}"),
        ));
    }
    let resolver = config.secret_resolver().map_err(|_| {
        credentials_refusal(
            "credentials",
            "the runtime configuration provides no usable secret resolver for credential references",
        )
    })?;
    let journey_ids = suite.journey_ids();
    let mut bound_steps = std::collections::BTreeSet::new();
    let mut bindings = Vec::with_capacity(document.bindings.len());
    for (index, binding) in document.bindings.into_iter().enumerate() {
        if !journey_ids.contains(&binding.journey_id.as_str()) {
            return Err(credentials_refusal(
                format!("bindings[{index}].journeyId"),
                format!(
                    "the packaged journey suite has no journey with this id; it declares {}",
                    journey_ids.join(", ")
                ),
            ));
        }
        if !bound_steps.insert((binding.journey_id.clone(), binding.step_id.clone())) {
            return Err(credentials_refusal(
                format!("bindings[{index}]"),
                format!(
                    "journey {} step {} already has a credential binding; bind every step exactly once",
                    binding.journey_id, binding.step_id
                ),
            ));
        }
        let journey_id = binding.journey_id.clone();
        let step_id = binding.step_id.clone();
        let binding = match binding.credential {
            CredentialDocumentMode::Anonymous => {
                SchemaTestCredentialBinding::anonymous(binding.journey_id, binding.step_id)
            }
            CredentialDocumentMode::Bearer { token_ref } => {
                if !is_protected_secret_reference(&token_ref) {
                    return Err(credentials_refusal(
                        format!("bindings[{index}].credential.tokenRef"),
                        format!("the bearer credential for journey {journey_id} step {step_id} must reference a protected secret, either secret:file/<name> or secret:env/<NAME>"),
                    ));
                }
                let secret = resolver.resolve(&token_ref).map_err(|_| {
                    credentials_refusal(
                        format!("bindings[{index}].credential.tokenRef"),
                        format!("the secret referenced for journey {journey_id} step {step_id} could not be resolved"),
                    )
                })?;
                let token = std::str::from_utf8(secret.expose_secret())
                    .map_err(|_| {
                        credentials_refusal(
                            format!("bindings[{index}].credential.tokenRef"),
                            format!("the secret referenced for journey {journey_id} step {step_id} is not UTF-8"),
                        )
                    })?
                    .to_owned();
                SchemaTestCredentialBinding::bearer(
                    binding.journey_id,
                    binding.step_id,
                    Zeroizing::new(token),
                )
            }
        };
        bindings.push(binding);
    }
    SchemaTestCredentialBindings::new(suite, bindings).map_err(|_| {
        credentials_refusal(
            "bindings",
            format!(
                "bind exactly one credential to every step of journeys {}; anonymous steps require an anonymous binding and protected steps require a well-formed bearer token",
                journey_ids.join(", ")
            ),
        )
    })
}

fn credentials_refusal(path: impl Into<String>, message: impl Into<String>) -> TestLifecycleError {
    TestLifecycleError::Credentials {
        path: path.into(),
        message: message.into(),
    }
}

fn credentials_changed() -> TestLifecycleError {
    credentials_refusal(
        "credentials",
        "the credentials file changed while it was read",
    )
}

/// Refuse a credentials file whose opened descriptor is not the entry that was
/// stat'ed. See `super::ensure_source_entry_identity` for the window a
/// stat-then-open pair leaves open.
fn ensure_credentials_identity(
    stat: EntryStat,
    opened: &fs::Metadata,
) -> Result<(), TestLifecycleError> {
    if stat.is_same_file_as(opened) {
        return Ok(());
    }
    Err(credentials_changed())
}

fn read_credentials(path: &Path) -> Result<Vec<u8>, TestLifecycleError> {
    let unavailable = || {
        credentials_refusal(
            "credentials",
            "the credentials file is not available; supply --credentials with an existing regular file",
        )
    };
    let unreadable = || credentials_refusal("credentials", "the credentials file cannot be read");
    let changed = credentials_changed;
    let bounds = || {
        credentials_refusal(
            "credentials",
            format!(
                "the credentials file must be a non-empty regular file of at most {MAX_CREDENTIAL_DOCUMENT_BYTES} bytes"
            ),
        )
    };
    if !path.is_absolute() || super::has_parent_component(path) {
        return Err(credentials_refusal(
            "credentials",
            "the credentials path must be absolute and must not contain parent traversal",
        ));
    }
    let entry = SafeEntry::resolve(path).map_err(|_| {
        credentials_refusal(
            "credentials",
            "the credentials path must not resolve through a symbolic link",
        )
    })?;
    let stat = entry.stat().map_err(|_| unavailable())?;
    if stat.is_symlink() || !stat.is_file() {
        return Err(credentials_refusal(
            "credentials",
            "the credentials file must be a regular file and must not be a symbolic link",
        ));
    }
    if stat.len() == 0 || stat.len() > MAX_CREDENTIAL_DOCUMENT_BYTES {
        return Err(bounds());
    }
    // The descriptor is opened through the resolved parent with `O_NOFOLLOW`, so
    // no ancestor and no symbolic link can redirect the open. The final name is
    // still resolved a second time here, so the identity check below is what
    // rejects a name relinked between the stat above and this open.
    let file = entry.open_read().map_err(|_| unreadable())?;
    let opened = file.metadata().map_err(|_| unreadable())?;
    if !opened.is_file() {
        return Err(changed());
    }
    ensure_credentials_identity(stat, &opened)?;
    if opened.len() > MAX_CREDENTIAL_DOCUMENT_BYTES {
        return Err(bounds());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| bounds())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_CREDENTIAL_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_CREDENTIAL_DOCUMENT_BYTES {
        return Err(bounds());
    }
    if bytes.len() as u64 != opened.len() {
        return Err(changed());
    }
    Ok(bytes)
}

fn schema_preparation_error(error: startup::StartupError) -> TestLifecycleError {
    match error {
        startup::StartupError::FieldPatternSyntax {
            entity_id,
            field_id,
        } => TestLifecycleError::FieldPatternSyntax {
            entity_id,
            field_id,
        },
        _ => TestLifecycleError::Database,
    }
}

fn execution_error(error: FixtureError) -> TestLifecycleError {
    match error {
        FixtureError::StepFailed {
            journey_index,
            step_index,
            error,
        } => TestLifecycleError::JourneyStep {
            path: format!("journeys[{journey_index}].steps[{step_index}]"),
            message: error.to_string(),
        },
        FixtureError::RuntimeSetup(error) => TestLifecycleError::RuntimeSetup(error),
        FixtureError::CandidateBindingRefused => TestLifecycleError::Database,
        _ => TestLifecycleError::Execution,
    }
}

fn publish_receipt(target: &OutputTarget, bytes: &[u8]) -> Result<(), TestLifecycleError> {
    let parent = target.destination.parent();
    let (temporary, mut file) = create_temporary_file(parent)?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        file.sync_all()
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        let metadata = file
            .metadata()
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        drop(file);
        target
            .destination
            .publish_from(&temporary)
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        parent
            .sync()
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        if target
            .destination
            .stat()
            .map(|after| after.is_symlink() || !after.is_same_file_as(&metadata))
            .unwrap_or(true)
        {
            return Err(TestLifecycleError::OutputCommit);
        }
        Ok(())
    })();
    if result.is_err() {
        cleanup_temporary_file(parent, &temporary);
    }
    result
}

fn create_temporary_file(parent: &SafeDir) -> Result<(OsString, File), TestLifecycleError> {
    for _ in 0..64 {
        let counter = TEST_OUTPUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = OsString::from(format!(
            ".bregctl-test-receipt-{}-{counter}.tmp",
            std::process::id()
        ));
        match parent.create_new(&temporary, 0o666) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(TestLifecycleError::OutputCommit),
        }
    }
    Err(TestLifecycleError::OutputCommit)
}

fn cleanup_temporary_file(parent: &SafeDir, name: &OsStr) {
    let Some(text) = name.to_str() else {
        return;
    };
    if text.starts_with(".bregctl-test-receipt-") && text.ends_with(".tmp") {
        let _ = parent.remove_file(name);
    }
}

/// Remove an entry only when it is still the exact file this process created,
/// so a name swapped underneath the held parent descriptor is left alone.
///
/// The stat and the unlink are two calls against one name, and POSIX offers no
/// identity-bound removal, so the check narrows the window between them rather
/// than closing it: a name relinked in that gap is unlinked as though it were
/// the entry the stat approved. That bound is accepted here rather than worked
/// around. Every name this guards is one this process itself created or
/// promoted through the resolved parent descriptor, and its expected identity
/// comes from the descriptor this process wrote, so a name that changes in the
/// gap can only have been changed by a writer who already holds write access to
/// the resolved parent directory. Quarantining the name first would rename by
/// the same name and add a call to the same window, so it would move the gap
/// rather than remove it.
pub(crate) fn remove_exact_file(
    destination: &SafeEntry,
    expected: &fs::Metadata,
) -> std::io::Result<()> {
    let actual = destination.stat()?;
    if actual.is_symlink() || !actual.is_file() || !actual.is_same_file_as(expected) {
        return Err(std::io::Error::other("output identity changed"));
    }
    destination.remove_file()
}

/// Read the identity of the receipt the preflight just created. A failure here
/// is the only path that leaves the created file in place, so a test-only fault
/// stands in for a platform that cannot answer.
fn preflight_metadata(file: &File) -> std::io::Result<fs::Metadata> {
    if preflight_metadata_faulted() {
        return Err(std::io::Error::other("receipt identity unavailable"));
    }
    file.metadata()
}

#[cfg(test)]
thread_local! {
    static PREFLIGHT_METADATA_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn preflight_metadata_faulted() -> bool {
    PREFLIGHT_METADATA_FAULT.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn preflight_metadata_faulted() -> bool {
    false
}

#[cfg(test)]
fn install_preflight_metadata_fault() -> PreflightMetadataFaultGuard {
    PREFLIGHT_METADATA_FAULT.with(|faulted| faulted.set(true));
    PreflightMetadataFaultGuard
}

#[cfg(test)]
struct PreflightMetadataFaultGuard;

#[cfg(test)]
impl Drop for PreflightMetadataFaultGuard {
    fn drop(&mut self) {
        PREFLIGHT_METADATA_FAULT.with(|faulted| faulted.set(false));
    }
}

fn cleanup_exact_file(destination: &SafeEntry, expected: &fs::Metadata) {
    let _ = remove_exact_file(destination, expected);
}

pub(crate) fn receipt_artifact_path() -> &'static str {
    RECEIPT_ARTIFACT_PATH
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

fn is_protected_secret_reference(value: &str) -> bool {
    let Some(name) = value.strip_prefix("secret:env/") else {
        return is_file_secret_reference(value);
    };
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'A'..=b'Z'))
        && bytes.len() <= 128
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn is_file_secret_reference(value: &str) -> bool {
    let Some(name) = value.strip_prefix("secret:file/") else {
        return false;
    };
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use std::path::PathBuf;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".bregctl-schema-test-unit-{}-{}",
                std::process::id(),
                TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("unit test directory creates");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.path.exists() {
                fs::remove_dir_all(&self.path).expect("unit test directory removes");
            }
        }
    }

    #[test]
    fn output_publish_refuses_a_target_created_after_preflight_without_replacement() {
        let directory = TestDirectory::create();
        let output = directory.path.join("receipt.json");
        let target = preflight_output(&output).expect("output preflights");
        assert!(!output.exists());

        fs::write(&output, b"operator-owned").expect("racing output writes");
        let error = publish_receipt(&target, br#"{"ok":true}"#).expect_err("race is refused");
        assert!(matches!(error, TestLifecycleError::OutputCommit));
        assert_eq!(
            fs::read(&output).expect("racing output remains"),
            b"operator-owned"
        );
        assert!(
            fs::read_dir(&directory.path)
                .expect("directory reads")
                .all(|entry| !entry
                    .expect("entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".bregctl-test-receipt-")),
            "temporary receipt files are cleaned up"
        );
    }

    #[test]
    fn an_exact_removal_refuses_a_name_that_holds_another_file() {
        let directory = TestDirectory::create();
        let output = directory.path.join("receipt.json");
        let created = fs::File::create(&output).expect("the guarded file creates");
        let identity = created.metadata().expect("the created identity reads");
        drop(created);
        let destination = SafeEntry::resolve(&output).expect("the destination resolves");

        // The name now holds a file this process never created, which is what
        // the identity comparison exists to refuse. The other file is created
        // while the guarded one still exists, so its identity differs even on
        // filesystems that hand a freed inode number straight to the next
        // creation under the same name.
        let other = directory.path.join("other.json");
        fs::write(&other, b"operator-owned").expect("another writer creates its file");
        fs::rename(&other, &output).expect("another writer takes the name");
        let refused = remove_exact_file(&destination, &identity)
            .expect_err("a name holding another file is refused");

        assert_eq!(refused.to_string(), "output identity changed");
        assert_eq!(
            fs::read(&output).expect("the other file remains"),
            b"operator-owned"
        );
    }

    #[test]
    fn preflight_leaves_the_receipt_it_created_when_its_identity_is_unknown() {
        let directory = TestDirectory::create();
        let output = directory.path.join("receipt.json");

        let _fault = install_preflight_metadata_fault();
        let error = preflight_output(&output).expect_err("an unidentifiable receipt is refused");

        assert!(matches!(error, TestLifecycleError::OutputPreflight));
        assert!(
            output.exists(),
            "the receipt whose identity the preflight never learned is left in place"
        );
    }

    #[test]
    fn runtime_setup_failures_report_the_configuration_boundary_without_database_advice() {
        use registry_breg::event_destination::EventDestinationActivationError;

        let mut cases = vec![
            (
                SchemaTestRuntimeSetupError::Authentication,
                "test.authentication.setup_failed",
                "authentication",
            ),
            (
                SchemaTestRuntimeSetupError::Audit,
                "test.audit.setup_failed",
                "audit",
            ),
            (
                SchemaTestRuntimeSetupError::Cursor,
                "test.cursor.setup_failed",
                "cursor",
            ),
            (
                SchemaTestRuntimeSetupError::Evidence,
                "test.evidence_providers.activation_failed",
                "evidenceProviders",
            ),
            (
                SchemaTestRuntimeSetupError::EventDestinations(
                    EventDestinationActivationError::InventoryMismatch,
                ),
                "test.event_destinations.inventory_mismatch",
                "eventDestinations",
            ),
        ];
        for error in [
            EventDestinationActivationError::InvalidBinding,
            EventDestinationActivationError::DeliveryCeilingWidening,
            EventDestinationActivationError::Secret,
            EventDestinationActivationError::InvalidSigningMaterial,
            EventDestinationActivationError::InvalidTlsMaterial,
        ] {
            cases.push((
                SchemaTestRuntimeSetupError::EventDestinations(error),
                "test.event_destinations.activation_failed",
                "eventDestinations",
            ));
        }
        for (error, code, path) in cases {
            let report =
                crate::test_lifecycle_failure(execution_error(FixtureError::RuntimeSetup(error)));
            let diagnostic = &report.diagnostics[0];
            assert_eq!(diagnostic.code, code);
            assert_eq!(diagnostic.path, path);
            assert_eq!(
                diagnostic.artifact,
                crate::DiagnosticArtifact::RuntimeConfiguration
            );
            assert_eq!(
                diagnostic.suggested_action,
                crate::SuggestedAction::CorrectRuntimeConfiguration
            );
            assert!(!diagnostic.message.contains("recreate"));
            assert!(diagnostic.message.contains("before retrying"));
            let serialized = serde_json::to_string(&report).expect("failure report serializes");
            assert!(!serialized.contains("recreate_disposable_database"));
        }
    }

    #[test]
    fn failed_step_reports_location_and_http_status_without_payload_or_database_advice() {
        let error = execution_error(FixtureError::StepFailed {
            journey_index: 1,
            step_index: 25,
            error: Box::new(FixtureError::ResponseStatusMismatch {
                expected: 409,
                actual: 412,
            }),
        });
        let report = serde_json::to_value(crate::test_lifecycle_failure(error))
            .expect("step failure report serializes");
        assert_eq!(report["diagnostics"][0]["code"], "test.step.failed");
        assert_eq!(report["diagnostics"][0]["path"], "journeys[1].steps[25]");
        assert_eq!(
            report["diagnostics"][0]["message"],
            "expected HTTP 409, received HTTP 412"
        );
        assert!(!report.to_string().contains("recreate"));
    }

    #[test]
    fn a_refused_logical_reference_reports_which_reference_and_why() {
        use registry_breg::fixtures::LogicalReferenceRefusal;

        let error = execution_error(FixtureError::StepFailed {
            journey_index: 0,
            step_index: 3,
            error: Box::new(FixtureError::LogicalReference(
                LogicalReferenceRefusal::FieldNotWritable,
            )),
        });
        let report = serde_json::to_value(crate::test_lifecycle_failure(error))
            .expect("step failure report serializes");
        assert_eq!(report["diagnostics"][0]["code"], "test.step.failed");
        assert_eq!(report["diagnostics"][0]["path"], "journeys[0].steps[3]");
        assert_eq!(
            report["diagnostics"][0]["message"],
            "the fixture logical reference was refused: the request writes a field the access profile grant does not make writable"
        );
        // The named cause carries no authored field, value or profile.
        assert!(!report.to_string().contains("recreate"));
    }

    #[test]
    fn revise_request_data_body_reports_field_path() {
        let source = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: stale-flow
    steps:
      - id: rebase-primary-request
        request:
          operation: revise_request
          data: {rebase: true}
"#;

        let error = diagnose_fixture_journey_shape(source).expect("specific diagnostic");
        match error {
            TestLifecycleError::JourneySyntax { path, message } => {
                assert_eq!(path, "journeys[0].steps[0].request.data");
                assert!(message.contains("remove the data wrapper"));
            }
            other => panic!("unexpected diagnostic: {other:?}"),
        }
    }

    #[test]
    fn revise_request_missing_rebase_reports_field_path() {
        let source = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: stale-flow
    steps:
      - id: rebase-primary-request
        request:
          operation: revise_request
"#;

        let error = diagnose_fixture_journey_shape(source).expect("specific diagnostic");
        match error {
            TestLifecycleError::JourneySyntax { path, message } => {
                assert_eq!(path, "journeys[0].steps[0].request.rebase");
                assert!(message.contains("boolean rebase"));
            }
            other => panic!("unexpected diagnostic: {other:?}"),
        }
    }

    /// Deterministic ancestor-swap regressions for the receipt and credentials
    /// surfaces this module owns.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod ancestor_swap {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn a_receipt_publication_after_an_ancestor_swap_publishes_only_in_the_named_tree() {
            let tree = race_tree();

            let guard = tree.arm();
            let target = preflight_output(&tree.named("receipt.json")).unwrap();
            publish_receipt(&target, b"receipt").unwrap();
            drop(guard);

            assert_eq!(fs::read(tree.moved("receipt.json")).unwrap(), b"receipt");
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }

        #[test]
        fn a_credentials_read_after_an_ancestor_swap_reads_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("credentials.yaml");
            fs::write(&named, b"genuine").unwrap();
            fs::write(tree.outside("credentials.yaml"), b"decoy").unwrap();

            let guard = tree.arm();
            let bytes = read_credentials(&named).unwrap();
            drop(guard);

            assert_eq!(bytes, b"genuine");
            // The window is real: the same pathname now reaches the tree the
            // operator never named.
            assert_eq!(fs::read(&named).unwrap(), b"decoy");
        }
    }

    /// Coverage for the identity check the credentials reader applies to the
    /// descriptor it opens. A relink landing between the stat and the open
    /// cannot be scheduled from a test, so the check is exercised through its
    /// own seam with the two outcomes a reader can meet.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod relinked_entry {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        /// The stat of the file the operator named, paired with the metadata of
        /// the descriptor a reader holds once that name reaches another regular
        /// file.
        fn stat_and_relinked_metadata() -> (EntryStat, fs::Metadata) {
            let tree = race_tree();
            let named = tree.named("credentials.yaml");
            fs::write(&named, b"genuine").unwrap();
            let relinked = tree.outside("credentials.yaml");
            fs::write(&relinked, b"decoy").unwrap();
            let stat = SafeEntry::resolve(&named).unwrap().stat().unwrap();
            let opened = File::open(&relinked).unwrap().metadata().unwrap();
            (stat, opened)
        }

        /// The stat and the opened metadata of one file, which is what a read
        /// of an untouched credentials file holds.
        fn stat_and_own_metadata() -> (EntryStat, fs::Metadata) {
            let tree = race_tree();
            let named = tree.named("credentials.yaml");
            fs::write(&named, b"genuine").unwrap();
            let entry = SafeEntry::resolve(&named).unwrap();
            let stat = entry.stat().unwrap();
            let opened = entry.open_read().unwrap().metadata().unwrap();
            (stat, opened)
        }

        #[test]
        fn a_credentials_file_opened_as_another_file_is_refused() {
            let (stat, opened) = stat_and_relinked_metadata();

            let refused = ensure_credentials_identity(stat, &opened)
                .expect_err("a descriptor that is not the stat'ed entry is refused");

            match refused {
                TestLifecycleError::Credentials { path, message } => {
                    assert_eq!(path, "credentials");
                    assert_eq!(message, "the credentials file changed while it was read");
                }
                other => panic!("unexpected refusal: {other:?}"),
            }
        }

        #[test]
        fn a_credentials_file_opened_as_the_stat_entry_is_read() {
            let (stat, opened) = stat_and_own_metadata();

            ensure_credentials_identity(stat, &opened).expect("the entry that was stat'ed is read");
        }
    }
}
