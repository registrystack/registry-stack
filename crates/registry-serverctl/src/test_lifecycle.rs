// SPDX-License-Identifier: Apache-2.0
//! Production schema-test orchestration for unsigned package candidates.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_server::fixtures::{
    execute_schema_test, validate_fixture_journeys, FixtureError, SchemaTestCredentialBinding,
    SchemaTestCredentialBindings,
};
use registry_server::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use registry_server::startup;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::CapturedPackageCandidate;

const CREDENTIALS_API_VERSION: &str =
    "registry.registrystack.org/server-schema-test-credentials/v1";
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

#[derive(Debug)]
pub(crate) struct OutputTarget {
    path: PathBuf,
    parent: PathBuf,
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
    Execution,
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
        || path.exists()
    {
        return Err(TestLifecycleError::OutputPreflight);
    }
    let parent = path.parent().ok_or(TestLifecycleError::OutputPreflight)?;
    super::validate_directory_for(
        parent,
        "test.output.parent_invalid",
        "output.parent",
        "the schema-test receipt output parent is not available",
        "the schema-test receipt output parent was refused",
    )
    .map_err(|_| TestLifecycleError::OutputPreflight)?;
    super::ensure_no_symlink_components(path, "test.output.path_invalid", "output")
        .map_err(|_| TestLifecycleError::OutputPreflight)?;

    let file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| TestLifecycleError::OutputPreflight)?;
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(TestLifecycleError::OutputPreflight);
        }
    };
    let result = (|| {
        file.sync_all()
            .map_err(|_| TestLifecycleError::OutputPreflight)?;
        let after = fs::symlink_metadata(path).map_err(|_| TestLifecycleError::OutputPreflight)?;
        if after.file_type().is_symlink()
            || !after.is_file()
            || !super::same_file_metadata(&opened, &after)
        {
            return Err(TestLifecycleError::OutputPreflight);
        }
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        cleanup_exact_file(path, &opened);
        return Err(TestLifecycleError::OutputPreflight);
    }
    remove_exact_file(path, &opened).map_err(|_| TestLifecycleError::OutputPreflight)?;
    sync_parent(parent).map_err(|_| TestLifecycleError::OutputPreflight)?;
    Ok(OutputTarget {
        path: path.to_path_buf(),
        parent: parent.to_path_buf(),
    })
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
            .map_err(|_| TestLifecycleError::Database)
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
            .map_err(|_| TestLifecycleError::Database)?;
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
    suite: &registry_server::fixtures::ValidatedFixtureJourneys,
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

fn read_credentials(path: &Path) -> Result<Vec<u8>, TestLifecycleError> {
    let unavailable = || {
        credentials_refusal(
            "credentials",
            "the credentials file is not available; supply --credentials with an existing regular file",
        )
    };
    let unreadable = || credentials_refusal("credentials", "the credentials file cannot be read");
    let changed = || {
        credentials_refusal(
            "credentials",
            "the credentials file changed while it was read",
        )
    };
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
    super::ensure_no_symlink_components(path, "test.credentials.path_invalid", "credentials")
        .map_err(|_| {
            credentials_refusal(
                "credentials",
                "the credentials path must not resolve through a symbolic link",
            )
        })?;
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(credentials_refusal(
            "credentials",
            "the credentials file must be a regular file and must not be a symbolic link",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_CREDENTIAL_DOCUMENT_BYTES {
        return Err(bounds());
    }
    let file = File::open(path).map_err(|_| unreadable())?;
    let opened = file.metadata().map_err(|_| unreadable())?;
    let after = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if after.file_type().is_symlink()
        || !opened.is_file()
        || !super::same_file_metadata(&metadata, &opened)
        || !super::same_file_metadata(&opened, &after)
    {
        return Err(changed());
    }
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
        FixtureError::CandidateBindingRefused => TestLifecycleError::Database,
        _ => TestLifecycleError::Execution,
    }
}

fn publish_receipt(target: &OutputTarget, bytes: &[u8]) -> Result<(), TestLifecycleError> {
    let (temporary, mut file) = create_temporary_file(&target.parent)?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        file.sync_all()
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        let metadata = file
            .metadata()
            .map_err(|_| TestLifecycleError::OutputCommit)?;
        drop(file);
        publish_temporary_file(&temporary, &target.path)?;
        sync_parent(&target.parent).map_err(|_| TestLifecycleError::OutputCommit)?;
        if fs::symlink_metadata(&target.path)
            .map(|after| {
                after.file_type().is_symlink() || !super::same_file_metadata(&metadata, &after)
            })
            .unwrap_or(true)
        {
            return Err(TestLifecycleError::OutputCommit);
        }
        Ok(())
    })();
    if result.is_err() {
        cleanup_temporary_file(&temporary);
    }
    result
}

fn create_temporary_file(parent: &Path) -> Result<(PathBuf, File), TestLifecycleError> {
    for _ in 0..64 {
        let counter = TEST_OUTPUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".registry-serverctl-test-receipt-{}-{counter}.tmp",
            std::process::id()
        ));
        match File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(TestLifecycleError::OutputCommit),
        }
    }
    Err(TestLifecycleError::OutputCommit)
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn publish_temporary_file(temporary: &Path, output: &Path) -> Result<(), TestLifecycleError> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};

    renameat_with(CWD, temporary, CWD, output, RenameFlags::NOREPLACE)
        .map_err(|_| TestLifecycleError::OutputCommit)
}

#[cfg(target_os = "windows")]
fn publish_temporary_file(temporary: &Path, output: &Path) -> Result<(), TestLifecycleError> {
    fs::rename(temporary, output).map_err(|_| TestLifecycleError::OutputCommit)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
fn publish_temporary_file(_temporary: &Path, _output: &Path) -> Result<(), TestLifecycleError> {
    Err(TestLifecycleError::OutputCommit)
}

fn cleanup_temporary_file(path: &Path) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    if name.starts_with(".registry-serverctl-test-receipt-") && name.ends_with(".tmp") {
        let _ = fs::remove_file(path);
    }
}

fn remove_exact_file(path: &Path, expected: &fs::Metadata) -> std::io::Result<()> {
    let actual = fs::symlink_metadata(path)?;
    if actual.file_type().is_symlink()
        || !actual.is_file()
        || !super::same_file_metadata(expected, &actual)
    {
        return Err(std::io::Error::other("output identity changed"));
    }
    fs::remove_file(path)
}

fn cleanup_exact_file(path: &Path, expected: &fs::Metadata) {
    let _ = remove_exact_file(path, expected);
}

fn sync_parent(parent: &Path) -> std::io::Result<()> {
    File::open(parent)?.sync_all()
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

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".registry-serverctl-schema-test-unit-{}-{}",
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
                    .starts_with(".registry-serverctl-test-receipt-")),
            "temporary receipt files are cleaned up"
        );
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
    fn revise_request_data_body_reports_field_path() {
        let source = br#"apiVersion: registry.registrystack.org/server-journeys/v1
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
        let source = br#"apiVersion: registry.registrystack.org/server-journeys/v1
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
}
