//! Executable proof for the complete Evidence Version 1 reference deployments.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use registry_evidence::bundle::{Bundle, DeploymentInputs};
use registry_evidence::config::{ConfigError, SelectorInput};
use registry_evidence::kernel::{
    EvidenceConstruction, KernelError, KernelOutcome, OfflineKernel, ValueProjection,
};
use registry_evidence::model::{
    LookupResult, PublicValue, ScalarOrEntityReference, SubjectBinding,
};
use registry_evidence::problem::ProblemCode;
use registry_evidence::rhai_runtime::{QueryPair, RequestParts};
use registry_evidence::runtime::source_failure_problem;
use registry_evidence::selector::{resolve_offline_fixture_authorization, ResolvedAuthorization};
use registry_evidence::signing::{jwks_document, EvidenceSigner};
use registry_evidence::source::{project_fixture_response, SourceError};
use registry_evidence::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value};
use tempfile::TempDir;
use zeroize::Zeroizing;

const AUDIENCE: &str = "urn:registry-evidence:reference-project-fixtures";
const BINDING_KEY: &[u8] = b"reference-project-binding-key-v1";
const TEST_CA: &str = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureContract {
    fixture: String,
    synthetic_only: bool,
    common: FixtureCommon,
    cases: Vec<FixtureCase>,
    #[serde(rename = "privacyExpectation")]
    privacy_expectation: PrivacyExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCommon {
    observed_at: String,
    #[serde(default)]
    purpose: Option<String>,
    selectors: Value,
    #[serde(default, rename = "verified_token_claims")]
    verified_token_claims: Option<Value>,
    #[serde(default, rename = "derivationSelectorInputs")]
    derivation_selector_inputs: Option<Value>,
    #[serde(rename = "expectedRequestParts")]
    expected_request_parts: ExpectedRequestParts,
    #[serde(rename = "expectedTransport")]
    expected_transport: ExpectedTransport,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    id: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    response: Option<Value>,
    #[serde(default, rename = "sourceFailure")]
    source_failure: Option<String>,
    #[serde(default, rename = "bundleMutation")]
    bundle_mutation: Option<String>,
    #[serde(default, rename = "requestMutation")]
    request_mutation: Option<String>,
    #[serde(default, rename = "derivationMutation")]
    derivation_mutation: Option<String>,
    #[serde(default, rename = "derivationParameterMutation")]
    derivation_parameter_mutation: Option<JsonMap<String, Value>>,
    #[serde(default, rename = "selectorOverrides")]
    selector_overrides: Option<Value>,
    #[serde(default)]
    observed_at: Option<String>,
    expected: Expected,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    #[serde(default)]
    lookup: Option<String>,
    #[serde(default)]
    facts: Option<Value>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    values: Option<Value>,
    #[serde(default, rename = "entityReferenceCount")]
    entity_reference_count: Option<usize>,
    #[serde(default, rename = "rawReferencesDisclosed")]
    raw_references_disclosed: Option<bool>,
    #[serde(default)]
    signed: Option<bool>,
    #[serde(default, rename = "publicProblem")]
    public_problem: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default, rename = "derivationRuns")]
    derivation_runs: Option<bool>,
    #[serde(default)]
    bundle: Option<String>,
    #[serde(default, rename = "outputGate")]
    output_gate: Option<String>,
    #[serde(default, rename = "rejectedBefore")]
    rejected_before: Option<String>,
    #[serde(default, rename = "sourceRequestCount")]
    source_request_count: Option<usize>,
    #[serde(default, rename = "expectedTransport")]
    expected_transport: Option<ExpectedTransport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRequestParts {
    query: Vec<ExpectedQueryPair>,
    body: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedQueryPair {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTransport {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    body: Option<Value>,
    #[serde(default, rename = "fixedHeaders")]
    fixed_headers: Option<Vec<ExpectedHeader>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyExpectation {
    #[serde(rename = "evidenceContains")]
    evidence_contains: Vec<String>,
    #[serde(rename = "evidenceExcludes")]
    evidence_excludes: Vec<String>,
    #[serde(rename = "diagnosticsExclude")]
    diagnostics_exclude: Vec<String>,
}

struct LoadedProject {
    _temporary: TempDir,
    runtime_path: PathBuf,
    bundle: Arc<Bundle>,
    kernel: OfflineKernel,
}

struct FixtureExecution<'a> {
    bundle: &'a Arc<Bundle>,
    kernel: &'a OfflineKernel,
    requirement: &'a registry_evidence::config::RequirementConfig,
    fixture: &'a FixtureContract,
    signer: &'a EvidenceSigner,
}

impl Drop for LoadedProject {
    fn drop(&mut self) {
        set_tree_mode(self._temporary.path(), 0o755, 0o644);
    }
}

#[tokio::test]
async fn reference_deployment_projects_execute_the_closed_fixture_contract() {
    for project_name in [
        "dhis2-tracker-evidence",
        "opencrvs-family-evidence",
        "relay-protected-read-evidence",
    ] {
        let project = load_project(project_name);
        let signer = fixture_signer().await;
        for requirement in &project.bundle.config.requirements {
            let fixture_value = project
                .bundle
                .fixtures
                .get(requirement.fixtures.as_str())
                .unwrap_or_else(|| panic!("{project_name}: fixture artifact missing"));
            let fixture: FixtureContract = serde_json::from_value(
                serde_json::to_value(fixture_value)
                    .unwrap_or_else(|_| panic!("{project_name}: fixture conversion failed")),
            )
            .unwrap_or_else(|_| panic!("{project_name}: fixture vocabulary is not closed"));
            validate_contract_shape(project_name, &fixture);
            execute_fixture(
                project_name,
                &project.bundle,
                &project.kernel,
                requirement,
                &fixture,
                &signer,
            )
            .await;
        }

        assert!(project.runtime_path.exists());
    }
}

fn load_project(project_name: &str) -> LoadedProject {
    let project_root = projects_root().join(project_name);
    let original_runtime = fs::read_to_string(project_root.join("runtime.yaml"))
        .unwrap_or_else(|_| panic!("{project_name}: runtime is unreadable"));
    registry_evidence::config::RuntimeConfig::parse_yaml(original_runtime.as_bytes())
        .unwrap_or_else(|_| panic!("{project_name}: checked-in runtime is invalid"));

    let temporary = tempfile::tempdir().expect("temporary project deployment");
    let bundle_root = temporary.path().join("bundle");
    fs::create_dir(&bundle_root).expect("temporary bundle root");
    copy_tree(&project_root.join("bundle"), &bundle_root);

    let secret_root = temporary.path().join("secrets");
    fs::create_dir(&secret_root).expect("temporary secret root");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("temporary secret root is private");
    let audit_path = temporary.path().join("audit.jsonl");
    let ca_path = temporary.path().join("reference-ca.pem");
    fs::write(&ca_path, TEST_CA).expect("temporary CA writes");

    let mut local_runtime = original_runtime;
    replace_once(
        &mut local_runtime,
        "/etc/registry-evidence/bundle",
        &bundle_root.display().to_string(),
    );
    replace_once(
        &mut local_runtime,
        "/run/secrets/registry-evidence",
        &secret_root.display().to_string(),
    );
    replace_once(
        &mut local_runtime,
        "/var/lib/registry-evidence/audit/evidence.jsonl",
        &audit_path.display().to_string(),
    );
    if local_runtime.contains("/etc/registry-evidence/ca/government-internal.pem") {
        replace_once(
            &mut local_runtime,
            "/etc/registry-evidence/ca/government-internal.pem",
            &ca_path.display().to_string(),
        );
    }
    let runtime_path = temporary.path().join("runtime.yaml");
    fs::write(&runtime_path, local_runtime).expect("temporary runtime writes");
    set_tree_mode(&bundle_root, 0o555, 0o444);
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("temporary runtime is immutable");
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444))
        .expect("temporary CA is immutable");

    let deployment = DeploymentInputs::load(&runtime_path).unwrap_or_else(|error| {
        panic!("{project_name}: production deployment loading failed: {error:?}")
    });
    let bundle = Arc::new(deployment.bundle);
    let kernel = OfflineKernel::compile(Arc::clone(&bundle))
        .unwrap_or_else(|_| panic!("{project_name}: production kernel compilation failed"));
    LoadedProject {
        _temporary: temporary,
        runtime_path,
        bundle,
        kernel,
    }
}

fn validate_contract_shape(project_name: &str, fixture: &FixtureContract) {
    assert!(
        fixture.synthetic_only,
        "{project_name}: fixture is not synthetic"
    );
    assert!(
        fixture.fixture.starts_with("registry.evidence.reference.")
            && fixture.fixture.ends_with("/v1"),
        "{project_name}: fixture identifier is invalid"
    );
    assert!(
        !fixture.cases.is_empty() && fixture.cases.len() <= 256,
        "{project_name}: fixture case count is invalid"
    );
    let mut ids = BTreeSet::new();
    for case in &fixture.cases {
        assert!(
            !case.id.is_empty() && case.id.len() <= 128 && ids.insert(case.id.as_str()),
            "{project_name}: fixture case identifier is invalid or duplicated"
        );
        let primary_inputs = [
            case.response.is_some(),
            case.source_failure.is_some(),
            case.bundle_mutation.is_some(),
            case.request_mutation.is_some(),
            case.derivation_mutation.is_some(),
            case.derivation_parameter_mutation.is_some(),
            case.selector_overrides.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        assert_eq!(
            primary_inputs, 1,
            "{project_name}/{}: case input form is not closed",
            case.id
        );
        assert!(
            !(case.expected.value.is_some() && case.expected.values.is_some()),
            "{project_name}/{}: a case states either one concept value or the complete concept map",
            case.id
        );
    }
}

async fn execute_fixture(
    project_name: &str,
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    requirement: &registry_evidence::config::RequirementConfig,
    fixture: &FixtureContract,
    signer: &EvidenceSigner,
) {
    let execution = FixtureExecution {
        bundle,
        kernel,
        requirement,
        fixture,
        signer,
    };
    let mut verified_payloads = Vec::new();
    for case in &fixture.cases {
        let label = format!("{project_name}/{}", case.id);
        if let Some(mutation) = &case.bundle_mutation {
            require_name(&label, mutation, "duplicate-disclosure-family");
            execute_bundle_mutation(&label, bundle, requirement, &case.expected);
            continue;
        }
        if let Some(mutation) = &case.request_mutation {
            execute_request_mutation(&label, bundle, requirement, fixture, case, mutation);
            continue;
        }

        let case_object = fixture_case_object(fixture, case);
        let common_object = fixture_common_object(fixture);
        let resolved = resolve_offline_fixture_authorization(
            bundle,
            requirement,
            Some(&common_object),
            &case_object,
            AUDIENCE,
        )
        .unwrap_or_else(|_| panic!("{label}: authorization or selector resolution failed"));
        let source = bundle
            .config
            .sources
            .get(&requirement.source)
            .unwrap_or_else(|| panic!("{label}: requirement source is absent"));
        let preparation_selectors = selector_projection(&resolved, &source.request.selector_inputs)
            .unwrap_or_else(|| panic!("{label}: preparation selector projection failed"));
        let prepared = kernel
            .prepare(&requirement.id, &preparation_selectors)
            .unwrap_or_else(|_| panic!("{label}: request preparation failed"));
        if case.selector_overrides.is_none() {
            assert_request_parts(&label, &prepared, &fixture.common.expected_request_parts);
        }
        assert_transport(
            &label,
            source,
            &prepared,
            &fixture.common.expected_transport,
        );
        if let Some(expected) = &case.expected.expected_transport {
            assert_transport(&label, source, &prepared, expected);
        }
        let derivation_selectors =
            selector_projection(&resolved, &requirement.derivation.selector_inputs)
                .unwrap_or_else(|| panic!("{label}: derivation selector projection failed"));
        if case.selector_overrides.is_none() {
            if let Some(expected) = &fixture.common.derivation_selector_inputs {
                assert!(
                    same_json(expected, &derivation_selectors),
                    "{label}: minimized derivation selectors mismatch"
                );
            } else {
                assert_eq!(
                    derivation_selectors,
                    Value::Object(JsonMap::new()),
                    "{label}: derivation selectors were not minimized to empty"
                );
            }
        }

        if case.selector_overrides.is_some() {
            assert_expected_count(&label, &case.expected, 1);
            continue;
        }
        if let Some(failure) = &case.source_failure {
            execute_source_failure(&label, failure, &case.expected);
            continue;
        }
        let observed_at = observed_at(&label, fixture, case);
        if let Some(mutation) = &case.derivation_mutation {
            require_name(&label, mutation, "return-raw-reference");
            execute_derivation_mutation(
                &label,
                &execution,
                &derivation_selectors,
                observed_at,
                &case.expected,
            );
            continue;
        }
        if let Some(mutation) = &case.derivation_parameter_mutation {
            execute_parameter_mutation(
                &label,
                &execution,
                mutation,
                &derivation_selectors,
                observed_at,
                &case.expected,
            );
            continue;
        }

        let response = case
            .response
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: response is absent"));
        let projected = project_fixture_response(source, response)
            .unwrap_or_else(|_| panic!("{label}: production source projection failed"));
        let payload = execute_response(
            &label,
            &execution,
            &resolved,
            &derivation_selectors,
            observed_at,
            &projected,
            &case.expected,
        )
        .await;
        if let Some(payload) = payload {
            verified_payloads.push(payload);
        }
    }
    assert_privacy(
        project_name,
        &fixture.privacy_expectation,
        &verified_payloads,
    );
}

async fn execute_response(
    label: &str,
    execution: &FixtureExecution<'_>,
    resolved: &ResolvedAuthorization,
    derivation_selectors: &Value,
    observed_at: DateTime<Utc>,
    response: &Value,
    expected: &Expected,
) -> Option<Value> {
    let bundle = execution.bundle;
    let kernel = execution.kernel;
    let requirement = execution.requirement;
    let signer = execution.signer;
    assert_expected_count(label, expected, 1);
    let lookup = match kernel.extract(&requirement.id, response) {
        Ok(lookup) => lookup,
        Err(error) => {
            assert_kernel_error(label, expected, error, false);
            return None;
        }
    };
    match lookup {
        LookupResult::NoMatch => {
            assert_lookup(label, expected, "no_match");
            assert_derivation(label, expected, false);
            assert_not_signed(label, expected);
            assert_public_problem(label, expected, "evidence_not_available");
            None
        }
        LookupResult::Ambiguous => {
            assert_lookup(label, expected, "ambiguous");
            assert_derivation(label, expected, false);
            assert_not_signed(label, expected);
            assert_public_problem(label, expected, "evidence_not_available");
            None
        }
        LookupResult::Match(facts) => {
            assert_lookup(label, expected, "match");
            if let Some(expected_facts) = &expected.facts {
                let actual = serde_json::to_value(&facts)
                    .unwrap_or_else(|_| panic!("{label}: facts are not representable"));
                assert!(
                    same_json(expected_facts, &actual),
                    "{label}: exact facts mismatch"
                );
            }
            let values = match kernel.derive_and_validate_with_selectors(
                &requirement.id,
                &facts,
                derivation_selectors,
                observed_at,
                ValueProjection {
                    audience: AUDIENCE,
                    binding_key: BINDING_KEY,
                    binding_key_version: 1,
                },
            ) {
                Ok(values) => values,
                Err(error) => {
                    assert_derivation(label, expected, true);
                    assert_kernel_error(label, expected, error, true);
                    return None;
                }
            };
            assert_derivation(label, expected, true);
            assert_values(label, expected, values.as_slice());

            let issued_at = observed_at + chrono::Duration::seconds(1);
            let subjects = resolved
                .subjects
                .iter()
                .map(|subject| SubjectBinding {
                    role: subject.role.clone(),
                    binding: subject
                        .binding(
                            BINDING_KEY,
                            1,
                            &bundle.config.service.trust_domain,
                            AUDIENCE,
                            &resolved.purpose,
                        )
                        .unwrap_or_else(|_| panic!("{label}: subject binding failed")),
                })
                .collect();
            let evidence_id = format!("urn:ulid:{}", ulid::Ulid::new());
            let evidence = kernel
                .construct_evidence(
                    &requirement.id,
                    values,
                    EvidenceConstruction {
                        evidence_id: &evidence_id,
                        request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                        purpose: &resolved.purpose,
                        audience: AUDIENCE,
                        issued_at,
                        observed_at,
                        subjects,
                    },
                )
                .unwrap_or_else(|_| panic!("{label}: evidence construction failed"));
            let signed = signer
                .sign_json(&evidence)
                .await
                .unwrap_or_else(|_| panic!("{label}: evidence signing failed"));
            let jwks = jwks_document(signer.public_jwk(), [])
                .unwrap_or_else(|_| panic!("{label}: fixture JWKS construction failed"));
            let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
                &evidence,
                registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                Duration::from_secs(31_536_000),
                issued_at,
                Duration::from_secs(0),
            );
            policy.issued_by = bundle.config.issuer.id.clone();
            policy.provided_by = bundle.config.service.provider_id.clone();
            policy.requirement = requirement.id.clone();
            policy.evidence_type = requirement.evidence_type.clone();
            policy.purpose = resolved.purpose.clone();
            policy.audience = AUDIENCE.to_owned();
            policy.configuration_revision = bundle.revision().to_owned();
            let verified = verify_flattened_jws(
                &serde_json::to_vec(&signed)
                    .unwrap_or_else(|_| panic!("{label}: signed evidence encoding failed")),
                &jwks,
                &policy,
            )
            .unwrap_or_else(|_| panic!("{label}: signed evidence verification failed"));
            if expected.signed == Some(false) {
                panic!("{label}: successful case prohibited signing");
            }
            Some(
                serde_json::to_value(verified)
                    .unwrap_or_else(|_| panic!("{label}: verified payload encoding failed")),
            )
        }
    }
}

fn execute_bundle_mutation(
    label: &str,
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    expected: &Expected,
) {
    assert_eq!(
        expected.bundle.as_deref(),
        Some("rejected"),
        "{label}: bundle rejection expectation is absent"
    );
    let mut mutated = bundle.config.clone();
    let mut companion = requirement.clone();
    companion.id.push_str(":fixture-companion");
    companion.evidence_type.push_str(":fixture-companion");
    for concept in &mut companion.concepts {
        concept.id.push_str(":fixture-companion");
    }
    mutated.requirements.push(companion);
    assert_eq!(
        mutated.validate(),
        Err(ConfigError::Invalid(
            "enabled requirements share a disclosure family"
        )),
        "{label}: unsafe disclosure-family mutation was not rejected"
    );
    assert_expected_count(label, expected, 0);
    assert_not_signed(label, expected);
}

fn execute_request_mutation(
    label: &str,
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    fixture: &FixtureContract,
    case: &FixtureCase,
    mutation: &str,
) {
    assert_eq!(
        case.expected.rejected_before.as_deref(),
        Some("source"),
        "{label}: request mutation boundary is not exact"
    );
    let selectors = fixture
        .common
        .selectors
        .as_object()
        .unwrap_or_else(|| panic!("{label}: common selectors are invalid"));
    let mut subjects = selectors
        .iter()
        .map(|(role, selector)| {
            let mut selector = selector
                .as_object()
                .cloned()
                .unwrap_or_else(|| panic!("{label}: common selector is invalid"));
            selector.insert("role".to_owned(), Value::String(role.clone()));
            Value::Object(selector)
        })
        .collect::<Vec<_>>();
    match mutation {
        "swap-subject-roles" => {
            assert_eq!(subjects.len(), 2, "{label}: swap mutation needs two roles");
            let first = subjects[0]["role"].clone();
            subjects[0]["role"] = subjects[1]["role"].clone();
            subjects[1]["role"] = first;
        }
        "supply-grant-derived-candidate" => {}
        _ => panic!("{label}: request mutation name is not closed"),
    }
    let mut case_object = fixture_case_object(fixture, case);
    case_object.insert("subjects".to_owned(), Value::Array(subjects));
    let common_object = fixture_common_object(fixture);
    assert!(
        resolve_offline_fixture_authorization(
            bundle,
            requirement,
            Some(&common_object),
            &case_object,
            AUDIENCE,
        )
        .is_err(),
        "{label}: request mutation crossed the authorization boundary"
    );
    assert_expected_count(label, &case.expected, 0);
    assert_not_signed(label, &case.expected);
}

fn execute_source_failure(label: &str, failure: &str, expected: &Expected) {
    let source_error = match failure {
        "timeout" => SourceError::Timeout,
        "connection-refused" => SourceError::Transport,
        "invalid-media-type" => SourceError::WrongMediaType,
        "oversized" => SourceError::ResponseTooLarge,
        "malformed-json" => SourceError::InvalidJson,
        _ => panic!("{label}: source failure name is not closed"),
    };
    assert_eq!(
        source_failure_problem(&source_error),
        ProblemCode::DependencyUnavailable,
        "{label}: source failure did not use the production safe mapping"
    );
    assert_eq!(
        expected.public_problem.as_deref(),
        Some("dependency_unavailable"),
        "{label}: source failure public problem is not exact"
    );
    assert_expected_count(label, expected, 1);
    assert_derivation(label, expected, false);
    assert_not_signed(label, expected);
}

fn execute_derivation_mutation(
    label: &str,
    execution: &FixtureExecution<'_>,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &Expected,
) {
    let bundle = execution.bundle;
    let requirement = execution.requirement;
    let fixture = execution.fixture;
    assert_eq!(
        expected.output_gate.as_deref(),
        Some("rejected"),
        "{label}: output-gate expectation is absent"
    );
    let mut disposable = bundle.as_ref().clone();
    disposable
        .scripts
        .get_mut(requirement.derivation.script.as_str())
        .unwrap_or_else(|| panic!("{label}: derivation artifact is absent"))
        .source = format!(
        "fn derive(facts, selectors, evaluation_context) {{ [#{{concept_id: \"{}\", value: \"PERSON-SYNTHETIC-A\"}}] }}",
        requirement.concepts[0].id
    );
    let disposable = Arc::new(disposable);
    let kernel = OfflineKernel::compile(Arc::clone(&disposable))
        .unwrap_or_else(|_| panic!("{label}: disposable derivation did not compile"));
    let response = positive_response(label, fixture);
    let source = disposable
        .config
        .sources
        .get(&requirement.source)
        .unwrap_or_else(|| panic!("{label}: source is absent"));
    let projected = project_fixture_response(source, response)
        .unwrap_or_else(|_| panic!("{label}: positive source projection failed"));
    assert_eq!(
        kernel.evaluate_with_selectors(
            &requirement.id,
            &projected,
            selectors,
            observed_at,
            ValueProjection {
                audience: AUDIENCE,
                binding_key: BINDING_KEY,
                binding_key_version: 1,
            },
        ),
        Err(KernelError::Output),
        "{label}: raw-reference derivation crossed the output gate"
    );
    assert_expected_count(label, expected, 1);
    assert_not_signed(label, expected);
}

fn execute_parameter_mutation(
    label: &str,
    execution: &FixtureExecution<'_>,
    mutation: &JsonMap<String, Value>,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &Expected,
) {
    let bundle = execution.bundle;
    let requirement = execution.requirement;
    let fixture = execution.fixture;
    let mut disposable = bundle.as_ref().clone();
    let mut config = serde_json::to_value(&disposable.config)
        .unwrap_or_else(|_| panic!("{label}: config is not representable"));
    let requirements = config["requirements"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("{label}: requirement list is unavailable"));
    let target = requirements
        .iter_mut()
        .find(|candidate| candidate["id"].as_str() == Some(requirement.id.as_str()))
        .unwrap_or_else(|| panic!("{label}: disposable requirement is absent"));
    let parameters = target["derivation"]["parameters"]
        .as_object_mut()
        .unwrap_or_else(|| panic!("{label}: derivation parameters are unavailable"));
    for (name, value) in mutation {
        assert!(
            parameters.contains_key(name),
            "{label}: parameter mutation introduced an unknown parameter"
        );
        parameters.insert(name.clone(), value.clone());
    }
    disposable.config = serde_json::from_value(config)
        .unwrap_or_else(|_| panic!("{label}: parameter mutation is not typed"));
    disposable
        .config
        .validate()
        .unwrap_or_else(|_| panic!("{label}: parameter mutation broke startup validation"));
    let disposable = Arc::new(disposable);
    let kernel = OfflineKernel::compile(Arc::clone(&disposable))
        .unwrap_or_else(|_| panic!("{label}: disposable kernel compilation failed"));
    let source = disposable
        .config
        .sources
        .get(&requirement.source)
        .unwrap_or_else(|| panic!("{label}: source is absent"));
    let projected = project_fixture_response(source, positive_response(label, fixture))
        .unwrap_or_else(|_| panic!("{label}: positive source projection failed"));
    let outcome = kernel.evaluate_with_selectors(
        &requirement.id,
        &projected,
        selectors,
        observed_at,
        ValueProjection {
            audience: AUDIENCE,
            binding_key: BINDING_KEY,
            binding_key_version: 1,
        },
    );
    assert_kernel_error_result(label, expected, outcome, true);
    assert_expected_count(label, expected, 1);
}

fn positive_response<'a>(label: &str, fixture: &'a FixtureContract) -> &'a Value {
    fixture
        .cases
        .iter()
        .find(|case| case.id == "positive")
        .and_then(|case| case.response.as_ref())
        .unwrap_or_else(|| panic!("{label}: positive companion response is absent"))
}

fn assert_kernel_error_result(
    label: &str,
    expected: &Expected,
    outcome: Result<KernelOutcome, KernelError>,
    derivation_ran: bool,
) {
    match outcome {
        Err(error) => assert_kernel_error(label, expected, error, derivation_ran),
        Ok(_) => panic!("{label}: expected failure returned a kernel outcome"),
    }
}

fn assert_kernel_error(label: &str, expected: &Expected, error: KernelError, derivation_ran: bool) {
    let (expected_signal, expected_problem) = match error {
        KernelError::Preparation => ("adapter_input_error", "service_unavailable"),
        KernelError::SourceProtocol => ("source_protocol_error", "dependency_unavailable"),
        // The public class collapses with the unresolved lookup classes so a
        // uniquely found record with inconsistent derivation inputs is not
        // distinguishable from no match.
        KernelError::DerivationInput => ("derivation_input_error", "evidence_not_available"),
        KernelError::Script if derivation_ran => ("derivation_input_error", "service_unavailable"),
        KernelError::Extraction => ("evidence_not_available", "evidence_not_available"),
        _ => ("service_unavailable", "service_unavailable"),
    };
    if let Some(signal) = expected.error.as_deref() {
        assert_eq!(
            signal, expected_signal,
            "{label}: internal error class mismatch"
        );
    }
    if let Some(problem) = expected.public_problem.as_deref() {
        assert_eq!(
            problem, expected_problem,
            "{label}: public problem mismatch"
        );
    }
    if expected.error.is_none() && expected.public_problem.is_none() {
        panic!("{label}: failing case has no exact error expectation");
    }
    assert_not_signed(label, expected);
}

fn assert_values(
    label: &str,
    expected: &Expected,
    values: &[registry_evidence::model::SupportedValue],
) {
    if let Some(expected_value) = &expected.value {
        assert_eq!(values.len(), 1, "{label}: scalar value count mismatch");
        let actual = serde_json::to_value(&values[0].value)
            .unwrap_or_else(|_| panic!("{label}: scalar value encoding failed"));
        assert!(
            same_json(expected_value, &actual),
            "{label}: scalar value mismatch"
        );
    }
    // A requirement disclosing more than one concept states every concept it
    // discloses, so a new or leaked concept cannot pass unnoticed.
    if let Some(expected_values) = &expected.values {
        let expected_values = expected_values
            .as_object()
            .unwrap_or_else(|| panic!("{label}: expected concept map is not an object"));
        assert_eq!(
            values.len(),
            expected_values.len(),
            "{label}: concept value count mismatch"
        );
        for (concept_id, expected_value) in expected_values {
            let value = values
                .iter()
                .find(|value| &value.provides_value_for == concept_id)
                .unwrap_or_else(|| panic!("{label}: expected concept is absent"));
            let actual = serde_json::to_value(&value.value)
                .unwrap_or_else(|_| panic!("{label}: concept value encoding failed"));
            assert!(
                same_json(expected_value, &actual),
                "{label}: concept value mismatch"
            );
        }
    }
    if let Some(expected_count) = expected.entity_reference_count {
        assert_eq!(values.len(), 1, "{label}: reference concept count mismatch");
        let actual_count = match &values[0].value {
            PublicValue::List(items) => items
                .iter()
                .filter(|item| matches!(item, ScalarOrEntityReference::EntityReference(_)))
                .count(),
            _ => 0,
        };
        assert_eq!(
            actual_count, expected_count,
            "{label}: entity-reference count mismatch"
        );
    }
    if let Some(disclosed) = expected.raw_references_disclosed {
        let encoded = serde_json::to_string(values)
            .unwrap_or_else(|_| panic!("{label}: supported value encoding failed"));
        let actual = ["PERSON-SYNTHETIC-A", "PERSON-SYNTHETIC-B"]
            .iter()
            .any(|reference| encoded.contains(reference));
        assert_eq!(
            actual, disclosed,
            "{label}: raw-reference disclosure expectation mismatch"
        );
    }
}

fn assert_request_parts(label: &str, actual: &RequestParts, expected: &ExpectedRequestParts) {
    let expected_query = expected
        .query
        .iter()
        .map(|pair| QueryPair {
            name: pair.name.clone(),
            value: pair.value.clone(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual.query, expected_query,
        "{label}: request query mismatch"
    );
    assert!(
        same_optional_json(expected.body.as_ref(), actual.body.as_ref()),
        "{label}: request body mismatch"
    );
}

fn assert_transport(
    label: &str,
    source: &registry_evidence::config::SourceConfig,
    parts: &RequestParts,
    expected: &ExpectedTransport,
) {
    if let Some(path) = &expected.path {
        assert_eq!(
            source.request.path.as_deref(),
            Some(path.as_str()),
            "{label}: fixed transport path mismatch"
        );
    }
    if let Some(headers) = &expected.fixed_headers {
        let actual = source
            .request
            .fixed_headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect::<Vec<_>>();
        let expected = headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            actual, expected,
            "{label}: fixed transport headers mismatch"
        );
    }
    if let Some(query) = &expected.query {
        assert_eq!(
            encode_query(&parts.query),
            *query,
            "{label}: encoded transport query mismatch"
        );
    }
    if expected.body.is_some() {
        assert!(
            same_optional_json(expected.body.as_ref(), parts.body.as_ref()),
            "{label}: normalized transport body mismatch"
        );
    }
}

fn encode_query(query: &[QueryPair]) -> String {
    let mut encoded = String::new();
    for pair in query {
        if !encoded.is_empty() {
            encoded.push('&');
        }
        encode_query_component(&pair.name, &mut encoded);
        encoded.push('=');
        encode_query_component(&pair.value, &mut encoded);
    }
    encoded
}

fn encode_query_component(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn selector_projection(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Option<Value> {
    let mut output = JsonMap::new();
    for input in inputs {
        let subject = resolved
            .subjects
            .iter()
            .find(|subject| subject.role == input.role)?;
        let alternative = input
            .alternatives
            .iter()
            .find(|alternative| alternative.profile == subject.selector_profile)?;
        let mut values = JsonMap::new();
        for name in &alternative.fields {
            let field = subject.fields.iter().find(|field| &field.name == name)?;
            values.insert(name.clone(), field.value.as_json());
        }
        output.insert(
            input.role.clone(),
            serde_json::json!({"profile": alternative.profile, "values": values}),
        );
    }
    Some(Value::Object(output))
}

fn fixture_common_object(fixture: &FixtureContract) -> JsonMap<String, Value> {
    let mut common = JsonMap::new();
    common.insert("selectors".to_owned(), fixture.common.selectors.clone());
    if let Some(purpose) = &fixture.common.purpose {
        common.insert("purpose".to_owned(), Value::String(purpose.clone()));
    }
    if let Some(claims) = &fixture.common.verified_token_claims {
        common.insert("verified_token_claims".to_owned(), claims.clone());
    }
    common
}

fn fixture_case_object(fixture: &FixtureContract, case: &FixtureCase) -> JsonMap<String, Value> {
    let mut output = JsonMap::new();
    if let Some(overrides) = &case.selector_overrides {
        output.insert("selectorOverrides".to_owned(), overrides.clone());
    }
    if let Some(purpose) = &case.purpose {
        output.insert("purpose".to_owned(), Value::String(purpose.clone()));
    }
    if let Some(claims) = &fixture.common.verified_token_claims {
        output.insert("verified_token_claims".to_owned(), claims.clone());
    }
    output
}

fn observed_at(label: &str, fixture: &FixtureContract, case: &FixtureCase) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(
        case.observed_at
            .as_deref()
            .unwrap_or(&fixture.common.observed_at),
    )
    .map(|value| value.with_timezone(&Utc))
    .unwrap_or_else(|_| panic!("{label}: observation instant is invalid"))
}

fn assert_lookup(label: &str, expected: &Expected, actual: &str) {
    if let Some(expected) = expected.lookup.as_deref() {
        assert_eq!(expected, actual, "{label}: lookup outcome mismatch");
    }
}

fn assert_derivation(label: &str, expected: &Expected, actual: bool) {
    if let Some(expected) = expected.derivation_runs {
        assert_eq!(expected, actual, "{label}: derivation execution mismatch");
    }
}

fn assert_not_signed(label: &str, expected: &Expected) {
    if expected.signed == Some(true) {
        panic!("{label}: unsuccessful case required a signature");
    }
}

fn assert_public_problem(label: &str, expected: &Expected, actual: &str) {
    if let Some(expected) = expected.public_problem.as_deref() {
        assert_eq!(expected, actual, "{label}: public problem mismatch");
    }
}

fn assert_expected_count(label: &str, expected: &Expected, actual: usize) {
    if let Some(expected) = expected.source_request_count {
        assert_eq!(expected, actual, "{label}: source request count mismatch");
    }
    assert!(
        actual <= 1,
        "{label}: fixture attempted multiple source requests"
    );
}

fn assert_privacy(project_name: &str, expectation: &PrivacyExpectation, payloads: &[Value]) {
    let projection = Value::Array(payloads.to_vec());
    let mut strings = Vec::new();
    collect_strings(&projection, &mut strings);
    for required in &expectation.evidence_contains {
        assert!(
            strings.contains(&required.as_str()),
            "{project_name}: required Evidence disclosure is absent"
        );
    }
    for prohibited in &expectation.evidence_excludes {
        assert!(
            !strings.contains(&prohibited.as_str()),
            "{project_name}: prohibited Evidence disclosure is present"
        );
    }
    const DIAGNOSTIC_SURFACES: &[&str] = &[
        "fixture vocabulary is not closed",
        "authorization or selector resolution failed",
        "request preparation failed",
        "exact facts mismatch",
        "scalar value mismatch",
        "concept value mismatch",
        "expected concept is absent",
        "signed evidence verification failed",
    ];
    for prohibited in &expectation.diagnostics_exclude {
        assert!(
            DIAGNOSTIC_SURFACES
                .iter()
                .all(|surface| !surface.contains(prohibited)),
            "{project_name}: protected value appears in a diagnostic template"
        );
    }
}

fn collect_strings<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    match value {
        Value::String(value) => output.push(value),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, output);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                output.push(key);
                collect_strings(value, output);
            }
        }
        _ => {}
    }
}

fn same_json(left: &Value, right: &Value) -> bool {
    serde_json::to_vec(left).ok() == serde_json::to_vec(right).ok()
}

fn same_optional_json(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => same_json(left, right),
        _ => false,
    }
}

fn require_name(label: &str, actual: &str, expected: &str) {
    assert_eq!(actual, expected, "{label}: mutation name is not closed");
}

async fn fixture_signer() -> EvidenceSigner {
    const KEY_ID: &str = "evidence-signing-2026-01";
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_bytes = Zeroizing::new(signing_key.to_bytes());
    let public_bytes = signing_key.verifying_key().to_bytes();
    let private = PrivateJwk {
        kty: "OKP".to_owned(),
        kid: Some(KEY_ID.to_owned()),
        alg: Some("EdDSA".to_owned()),
        crv: Some("Ed25519".to_owned()),
        d: Some(URL_SAFE_NO_PAD.encode(private_bytes.as_slice())),
        x: Some(URL_SAFE_NO_PAD.encode(public_bytes)),
        y: None,
        n: None,
        e: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
    };
    let provider = Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));
    EvidenceSigner::initialize(provider, KEY_ID)
        .await
        .expect("fixture signer initializes")
}

fn projects_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/reference/request-adapter/deployment-projects")
        .canonicalize()
        .expect("reference deployment projects exist")
}

fn replace_once(text: &mut String, from: &str, to: &str) {
    assert_eq!(
        text.matches(from).count(),
        1,
        "runtime fixture binding drifted"
    );
    *text = text.replacen(from, to, 1);
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("reference bundle is readable") {
        let entry = entry.expect("reference bundle entry is readable");
        let destination = target.join(entry.file_name());
        if entry.file_type().expect("entry type is readable").is_dir() {
            fs::create_dir(&destination).expect("reference bundle directory copies");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("reference bundle file copies");
        }
    }
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
            .expect("directory mode updates");
        for entry in fs::read_dir(path).expect("mode target is readable") {
            set_tree_mode(
                &entry.expect("mode target entry is readable").path(),
                directory_mode,
                file_mode,
            );
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
            .expect("file mode updates");
    }
}
