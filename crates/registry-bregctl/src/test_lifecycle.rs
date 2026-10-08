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
use registry_breg::literal_text::{LiteralText, WRITE_THE_VALUE_OR_A_SECRET_REFERENCE};
use registry_breg::postgres::{
    BaselineFingerprintDrift, MigrationRehearsalError, SuccessorMigrationRehearsal,
};
use registry_breg::runtime_config::{load_runtime_config, RuntimeConfig, RuntimeConfigError};
use registry_breg::startup;
use registry_platform_config::SecretReference;
use registry_platform_yaml::{
    tagged_union, ApiVersion, Decoded, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec,
    LocalId, Reader, Report, RetiredApiVersion, Severity,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::safe_path::{EntryStat, SafeDir, SafeEntry};
use crate::CapturedPackageCandidate;

pub(crate) const CREDENTIALS_API_VERSION: &str =
    "id.registrystack.org/formats/breg/schema-test-credentials/v1";
pub(crate) const CREDENTIALS_KIND: &str = "BRegSchemaTestCredentials";
/// The credentials file `bregctl test --credentials` reads.
pub(crate) const CREDENTIALS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CREDENTIALS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CREDENTIALS_API_VERSION)],
        retired_api_versions: &[RetiredApiVersion {
            api_version: "registry.registrystack.org/breg-schema-test-credentials/v1",
            replacement: "Start the file with `apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1` and `kind: BRegSchemaTestCredentials`; the bindings are unchanged.",
        }],
    },
    removed_keys: &[],
};
const CREDENTIALS_ACTION: &str =
    "Bind every step of the packaged journeys exactly once, by its journeyId and stepId.";
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
    pub registry_revision: String,
    pub schema_fingerprint: String,
    pub successful_journey_ids: Vec<String>,
    pub receipt_sha256: String,
    pub receipt_bytes: usize,
    pub baseline_fingerprint_drift: Option<BaselineFingerprintDrift>,
}

#[derive(Debug)]
pub(crate) struct SchemaMeasurement {
    pub registry_revision: String,
    pub schema_fingerprint: String,
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
    ReviewFingerprint { declared: String, measured: String },
    Rehearsal(Box<MigrationRehearsalError>),
    Journeys { message: String },
    JourneyDocument(registry_platform_yaml::Report),
    JourneyStep { path: String, message: String },
    Credentials { path: String, message: String },
    CredentialsDocument(Report),
    Database,
    FieldPatternSyntax { entity_id: String, field_id: String },
    Execution,
    RuntimeSetup(SchemaTestRuntimeSetupError),
    OutputPreflight,
    OutputCommit,
    Runtime,
}

/// The schema-test credentials file: one credential for every step of the
/// packaged journeys, a bearer token only by secret reference (CFG-SEC-1).
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CredentialDocument {
    bindings: Vec<CredentialBindingDocument>,
}

/// The JSON Schema of the credentials members the reader decodes. The header
/// is checked and removed before decoding, so the publisher adds it.
#[cfg(feature = "schema")]
pub(crate) fn credentials_schema() -> schemars::Schema {
    schemars::schema_for!(CredentialDocument)
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CredentialBindingDocument {
    journey_id: LocalId,
    step_id: LocalId,
    credential: CredentialDocumentMode,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
enum CredentialDocumentMode {
    Bearer { token_ref: SecretReference },
}
tagged_union!(CredentialDocumentMode);

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
    request
        .candidate
        .prevalidate()
        .map_err(|_| TestLifecycleError::Candidate)?;
    let suite = match validate_fixture_journeys(
        request.candidate.fixture_journeys(),
        request.candidate.registry(),
    ) {
        Ok(suite) => suite,
        Err(registry_breg::fixtures::FixtureError::JourneyDocument(report)) => {
            return Err(TestLifecycleError::JourneyDocument(report));
        }
        Err(error) => {
            return Err(TestLifecycleError::Journeys {
                message: error.to_string(),
            });
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
    if let Some(declared) = request
        .candidate
        .prevalidation_schema_fingerprint
        .as_ref()
        .filter(|declared| *declared != &schema_fingerprint)
    {
        return Err(TestLifecycleError::ReviewFingerprint {
            declared: declared.clone(),
            measured: schema_fingerprint,
        });
    }
    let rehearsal_baseline = request.candidate.rehearsal_baseline.clone();
    let prepared = request
        .candidate
        .prepare(schema_fingerprint.clone())
        .map_err(|_| TestLifecycleError::Candidate)?;
    let mut baseline_fingerprint_drift = None;
    if let Some(baseline) = &rehearsal_baseline {
        baseline_fingerprint_drift = runtime
            .block_on(startup::rehearse_successor_migration(
                &config,
                SuccessorMigrationRehearsal {
                    predecessor: &baseline.registry,
                    predecessor_schema_fingerprint: &baseline.schema_fingerprint,
                    candidate: &prepared,
                },
            ))
            .map_err(schema_preparation_error)?
            .map_err(|error| TestLifecycleError::Rehearsal(Box::new(error)))?
            .baseline_fingerprint_drift;
    }
    let registry_revision = prepared.registry().revision().to_owned();
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
        registry_revision,
        schema_fingerprint,
        successful_journey_ids,
        receipt_sha256: sha256(&receipt_bytes),
        receipt_bytes: receipt_bytes.len(),
        baseline_fingerprint_drift,
    })
}

/// Measure the schema a fresh install of the candidate produces on the
/// disposable database, rolled back as the full schema test's own measurement
/// is, without validating journeys, resolving credentials, or writing a
/// receipt.
pub(crate) fn measure(
    candidate: CapturedPackageCandidate,
    runtime_config: &Path,
) -> Result<SchemaMeasurement, TestLifecycleError> {
    let config = load_test_runtime_config(runtime_config)?;
    candidate
        .prevalidate()
        .map_err(|_| TestLifecycleError::Candidate)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| TestLifecycleError::Runtime)?;
    let schema_fingerprint = runtime.block_on(async {
        startup::rehearse_schema_fingerprint(&config, candidate.registry())
            .await
            .map_err(schema_preparation_error)
    })?;
    let prepared = candidate
        .prepare(schema_fingerprint.clone())
        .map_err(|_| TestLifecycleError::Candidate)?;
    Ok(SchemaMeasurement {
        registry_revision: prepared.registry().revision().to_owned(),
        schema_fingerprint,
    })
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
    let decoded = read_credentials_document(&path.display().to_string(), &bytes)
        .map_err(TestLifecycleError::CredentialsDocument)?;
    let resolver = config.secret_resolver().map_err(|_| {
        credentials_refusal(
            "credentials",
            "the runtime configuration provides no usable secret resolver for credential references",
        )
    })?;
    let document = &decoded.document;
    let journey_ids = suite.journey_ids();
    let mut bound_steps = std::collections::BTreeSet::new();
    let mut problems = Vec::new();
    let mut bindings = Vec::with_capacity(decoded.value.bindings.len());
    for (index, binding) in decoded.value.bindings.into_iter().enumerate() {
        let journey_id = binding.journey_id.into_string();
        let step_id = binding.step_id.into_string();
        if !journey_ids.contains(&journey_id.as_str()) {
            problems.push(document.diagnostic_at_value(
                Severity::Error,
                "breg.credentials.unknown-journey",
                &format!("/bindings/{index}/journeyId"),
                "the packaged journey suite has no journey with this id",
                "Name a journey of tests/journeys.yaml in journeyId, or remove the binding.",
            ));
            continue;
        }
        if !bound_steps.insert((journey_id.clone(), step_id.clone())) {
            problems.push(duplicate_binding(document, index));
            continue;
        }
        match binding.credential {
            CredentialDocumentMode::Bearer { token_ref } => {
                let pointer = format!("/bindings/{index}/credential/tokenRef");
                let token = resolver
                    .resolve_reference(&token_ref)
                    .ok()
                    .and_then(|secret| {
                        std::str::from_utf8(secret.expose_secret())
                            .ok()
                            .map(|token| Zeroizing::new(token.to_owned()))
                    });
                match token {
                    Some(token) => bindings.push(SchemaTestCredentialBinding::bearer(
                        journey_id, step_id, token,
                    )),
                    None => problems.push(document.diagnostic_at_value(
                        Severity::Error,
                        "breg.credentials.unresolved-secret",
                        &pointer,
                        "the referenced secret could not be resolved as UTF-8 text",
                        "Store the token as UTF-8 text under this reference, through a secret provider the runtime configuration enables.",
                    )),
                }
            }
        }
    }
    if !problems.is_empty() {
        return Err(credentials_document_refusal(problems));
    }
    SchemaTestCredentialBindings::new(suite, bindings).map_err(|_| {
        credentials_document_refusal(vec![document.diagnostic_at_value(
            Severity::Error,
            "breg.credentials.incomplete-bindings",
            "/bindings",
            "the bindings do not give exactly one credential to every step of the packaged journeys; every step requires a well-formed bearer token",
            CREDENTIALS_ACTION,
        )])
    })
}

/// Read a schema-test credentials file through the shared reader. The
/// reader refuses the shape; journey coverage and secret resolution are
/// checked by `bregctl test` against the packaged suite.
pub(crate) fn read_credentials_document(
    file: &str,
    bytes: &[u8],
) -> Result<Decoded<CredentialDocument>, Report> {
    Reader::new(file)
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE_OR_A_SECRET_REFERENCE,
        })
        .decode::<CredentialDocument>(bytes, &Expect::one(&CREDENTIALS_FORMAT))
}

/// Check a credentials document `bregctl check --file` read: every binding
/// names its journey step once. Whether each journey exists, and each
/// secret reference resolves, is checked when `bregctl test` reads the file
/// beside its package and runtime configuration.
pub(crate) fn check_credentials(document: &Document) -> Result<Vec<Diagnostic>, Report> {
    let credentials = document.decode::<CredentialDocument>()?;
    let mut bound_steps = std::collections::BTreeSet::new();
    Ok(credentials
        .bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| {
            !bound_steps.insert((binding.journey_id.as_str(), binding.step_id.as_str()))
        })
        .map(|(index, _)| duplicate_binding(document, index))
        .collect())
}

fn duplicate_binding(document: &Document, index: usize) -> Diagnostic {
    document.diagnostic_at_value(
        Severity::Error,
        "breg.credentials.duplicate-binding",
        &format!("/bindings/{index}"),
        "an earlier binding already gives this journey step a credential",
        "Remove this binding; bind every step exactly once.",
    )
}

fn credentials_document_refusal(diagnostics: Vec<Diagnostic>) -> TestLifecycleError {
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    TestLifecycleError::CredentialsDocument(report)
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
fn remove_exact_file(destination: &SafeEntry, expected: &fs::Metadata) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use std::path::PathBuf;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    const CREDENTIALS_EXAMPLE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/breg/examples/formats/credentials.yaml"
    ));

    fn credentials_codes(source: &str) -> Vec<(String, String, Option<usize>)> {
        let Err(report) = read_credentials_document("credentials.yaml", source.as_bytes()) else {
            panic!("the credentials document is refused");
        };
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.clone(),
                    diagnostic.path.clone(),
                    diagnostic.source.as_ref().and_then(|source| source.line),
                )
            })
            .collect()
    }

    #[test]
    fn the_registered_credentials_example_reads() {
        let decoded = read_credentials_document("credentials.yaml", CREDENTIALS_EXAMPLE.as_bytes())
            .expect("the registered example reads");
        let modes = decoded
            .value
            .bindings
            .iter()
            .map(|binding| match &binding.credential {
                CredentialDocumentMode::Bearer { .. } => "bearer",
            })
            .collect::<Vec<_>>();
        assert_eq!(modes, ["bearer", "bearer", "bearer"]);
    }

    #[test]
    fn credentials_with_a_retired_header_name_the_current_one() {
        let current = "apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1\n";
        let retired = "apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1\n";
        let body = "bindings: []\n";

        let old_kind = credentials_codes(&format!("{retired}kind: SchemaTestCredentials\n{body}"));
        assert_eq!(
            old_kind,
            [("config.wrong-kind".to_owned(), "/kind".to_owned(), Some(2))]
        );

        let source = format!("{retired}kind: BRegSchemaTestCredentials\n{body}");
        let Err(report) = read_credentials_document("credentials.yaml", source.as_bytes()) else {
            panic!("the retired header is refused");
        };
        let [diagnostic] = report.diagnostics() else {
            panic!("one diagnostic");
        };
        assert_eq!(diagnostic.code, "config.retired-api-version");
        assert!(
            diagnostic
                .suggested_action
                .contains(CREDENTIALS_API_VERSION),
            "{}",
            diagnostic.suggested_action
        );

        read_credentials_document(
            "credentials.yaml",
            format!("{current}kind: BRegSchemaTestCredentials\n{body}").as_bytes(),
        )
        .expect("the current header reads");
    }

    #[test]
    fn every_unknown_credentials_key_is_reported_at_its_position() {
        let source = "apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings:
  - journeyId: journey
    stepId: step
    credential:
      type: bearer
      tokenRef: secret:file/token
      scope: unused
    note: unused
";
        assert_eq!(
            credentials_codes(source),
            [
                (
                    "config.unknown-key".to_owned(),
                    "/bindings/0/credential/scope".to_owned(),
                    Some(9)
                ),
                (
                    "config.unknown-key".to_owned(),
                    "/bindings/0/note".to_owned(),
                    Some(10)
                ),
            ]
        );
    }

    #[test]
    fn a_credential_type_is_a_kebab_case_tag_and_a_reference_never_a_literal() {
        let binding = |credential: &str| {
            format!(
                "apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings:
  - journeyId: journey
    stepId: step
    credential:
{credential}"
            )
        };
        let codes = credentials_codes(&binding(
            "      type: Bearer\n      tokenRef: secret:file/token\n",
        ));
        assert_eq!(codes[0].0, "config.unknown-variant");
        assert_eq!(codes[0].1, "/bindings/0/credential/type");

        // The registry serves authenticated callers only, so a step has no
        // credential other than a bearer token.
        let codes = credentials_codes(&binding("      type: anonymous\n"));
        assert_eq!(codes[0].0, "config.unknown-variant");
        assert_eq!(codes[0].1, "/bindings/0/credential/type");

        let source = binding("      type: bearer\n      tokenRef: aaa.bbb.ccc\n");
        let Err(report) = read_credentials_document("credentials.yaml", source.as_bytes()) else {
            panic!("a literal token is refused");
        };
        let [diagnostic] = report.diagnostics() else {
            panic!("one diagnostic");
        };
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(diagnostic.path, "/bindings/0/credential/tokenRef");
        assert!(!diagnostic.message.contains("aaa.bbb.ccc"));
        assert!(!diagnostic.suggested_action.contains("aaa.bbb.ccc"));
    }

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
                SchemaTestRuntimeSetupError::ReviewAuthorities,
                "test.review_authorities.activation_failed",
                "reviewAuthorities",
            ),
            (
                SchemaTestRuntimeSetupError::WasmExecution,
                "test.wasm_execution.setup_failed",
                "wasmExecution",
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
    fn a_refused_rehearsal_step_names_the_step_and_postgres_class_only() {
        use registry_breg::postgres::PostgresFailure;

        let error = TestLifecycleError::Rehearsal(Box::new(MigrationRehearsalError::Step {
            migration_id: "rank-backfill".into(),
            step_id: "backfill-rank".into(),
            failure: PostgresFailure {
                sqlstate: Some("23502".into()),
                table: Some("entity_record".into()),
                column: Some("rank".into()),
                constraint: None,
            },
        }));
        let report = serde_json::to_value(crate::test_lifecycle_failure(error))
            .expect("rehearsal failure report serializes");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], "migration.rehearsal.step_failed");
        assert_eq!(
            diagnostic["path"],
            "reviewedMigrations[rank-backfill].steps[backfill-rank]"
        );
        let message = diagnostic["message"].as_str().unwrap();
        assert!(message.contains("SQLSTATE 23502"), "{message}");
        assert!(
            message.contains("integrity constraint violation"),
            "{message}"
        );
        assert!(message.contains("table entity_record"), "{message}");
        assert!(message.contains("column rank"), "{message}");
        assert!(message.contains("apply would refuse"), "{message}");
    }

    #[test]
    fn a_rehearsal_that_misses_the_candidate_schema_is_a_migration_refusal() {
        let report = serde_json::to_value(crate::test_lifecycle_failure(
            TestLifecycleError::Rehearsal(Box::new(MigrationRehearsalError::FinalSchemaMismatch)),
        ))
        .expect("rehearsal failure report serializes");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "migration.rehearsal.schema_mismatch"
        );
        assert_eq!(report["diagnostics"][0]["path"], "reviewedMigrations");
    }

    #[test]
    fn a_step_the_history_journal_refuses_names_the_step_and_the_reason() {
        let report = serde_json::to_value(crate::test_lifecycle_failure(
            TestLifecycleError::Rehearsal(Box::new(MigrationRehearsalError::HistoryStep {
                migration_id: "rank-backfill".into(),
                step_id: "backfill-rank".into(),
                reason: "history migration supports only direct reviewed UPDATE statements".into(),
            })),
        ))
        .expect("rehearsal failure report serializes");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(
            diagnostic["code"],
            "migration.rehearsal.history_step_refused"
        );
        assert_eq!(
            diagnostic["path"],
            "reviewedMigrations[rank-backfill].steps[backfill-rank]"
        );
        let message = diagnostic["message"].as_str().unwrap();
        assert!(message.contains("cannot be journaled"), "{message}");
        assert!(message.contains("apply would refuse"), "{message}");
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

    /// The shared reader's refusal of a journeys document, as `bregctl test`
    /// receives it for a project at `/project`.
    fn journey_refusal(source: &[u8]) -> crate::DocumentRefusal {
        let Err(FixtureError::JourneyDocument(report)) =
            registry_breg::fixtures::journey_step_profiles(source)
        else {
            panic!("the reader refuses the journeys document");
        };
        crate::DocumentRefusal {
            command: "test",
            subject: "the fixture journeys",
            report: crate::report_in_project(report, Path::new("/project")),
        }
    }

    fn written(refusal: &crate::DocumentRefusal, format: crate::OutputFormat) -> (u8, String) {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = crate::write_document_failure(refusal, format, &mut stdout, &mut stderr);
        let text = if format == crate::OutputFormat::Json {
            assert!(stderr.is_empty());
            stdout
        } else {
            assert!(stdout.is_empty());
            stderr
        };
        let code = if code == std::process::ExitCode::from(crate::DOMAIN_REFUSAL_EXIT) {
            crate::DOMAIN_REFUSAL_EXIT
        } else {
            u8::MAX
        };
        (code, String::from_utf8(text).expect("output is UTF-8"))
    }

    #[test]
    fn revise_request_data_body_prints_the_reader_diagnostic_with_its_position() {
        let source = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: stale-flow
    steps:
      - id: rebase-primary-request
        accessProfile: requester
        request:
          type: revise-request
          recordCapture: request
          etagCapture: request
          data: {rebase: true}
        expect: {outcome: success, status: 200}
"#;

        let (code, human) = written(&journey_refusal(source), crate::OutputFormat::Human);

        assert_eq!(code, crate::DOMAIN_REFUSAL_EXIT);
        assert_eq!(
            human,
            "bregctl test refused the fixture journeys.
error[config.missing-key] /project/tests/journeys.yaml:8:9 /journeys/0/steps/0/request
  the required member `rebase` is missing
  next: Add `rebase`.
error[config.unknown-key] /project/tests/journeys.yaml:12:11 /journeys/0/steps/0/request/data
  `data` is not a member of this mapping
  next: Remove `data`; the accepted keys are `type`, `recordCapture`, `etagCapture`, `rebase`.
2 errors, 0 warnings in 1 file
"
        );
    }

    #[test]
    fn revise_request_missing_rebase_reports_the_reader_shape_in_json() {
        let source = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: stale-flow
    steps:
      - id: rebase-primary-request
        accessProfile: requester
        request:
          type: revise-request
          recordCapture: request
          etagCapture: request
        expect: {outcome: success, status: 200}
"#;

        let (code, json) = written(&journey_refusal(source), crate::OutputFormat::Json);
        let report: serde_json::Value = serde_json::from_str(&json).expect("JSON report");

        assert_eq!(code, crate::DOMAIN_REFUSAL_EXIT);
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "test");
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        assert_eq!(diagnostics.len(), 1, "{json}");
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic["severity"], "error");
        assert_eq!(diagnostic["code"], "config.missing-key");
        assert_eq!(diagnostic["artifact"], "BRegJourneys");
        assert_eq!(diagnostic["path"], "/journeys/0/steps/0/request");
        assert!(
            diagnostic["message"].as_str().unwrap().contains("rebase"),
            "{json}"
        );
        assert_eq!(
            diagnostic["source"],
            serde_json::json!({"file": "/project/tests/journeys.yaml", "line": 8, "column": 9})
        );
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
