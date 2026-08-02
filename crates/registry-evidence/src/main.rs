//! Evidence Version 1 operator CLI and serving process.

use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    sync::Arc,
};

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use registry_evidence::{
    bundle::{Bundle, BundleError, DeploymentInputs, RuntimeDocument},
    config::{ConfigError, EvidenceConfig, OutboundTlsConfig, SelectorInput},
    kernel::{
        EvidenceConstruction, KernelError, KernelOutcome, OfflineKernel, ValidatedValues,
        ValueProjection,
    },
    model::{LookupResult, PublicValue, ScalarOrEntityReference, SelectorValue, SubjectBinding},
    problem::ProblemCode,
    rhai_runtime::{DerivedConceptValue, DerivedValue, RequestParts},
    runtime::{source_failure_problem, EvidenceRuntime, RuntimeInitializationError},
    secrets::{SecretProvider, SecretResolver},
    selector::{
        resolve_offline_fixture_authorization, resolve_offline_fixture_subjects,
        OfflineFixtureError, ResolvedAuthorization, ResolvedSelectorValue,
    },
    server,
    signing::{jwks_document, EvidenceSigner},
    source::{
        project_fixture_response, ResolvedSourceSelector, SourceError, SourceExecutor, SourceStatus,
    },
    verifier::{verify_flattened_jws, EvidenceVerificationPolicy},
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use serde_json::{Map as JsonMap, Value};
use zeroize::Zeroizing;

const DEFAULT_RUNTIME_PATH: &str = "/etc/registry-evidence/runtime.yaml";
const OFFLINE_AUDIENCE: &str = "urn:registry-evidence:offline-evaluation";
const OFFLINE_BINDING_KEY: [u8; 32] = [0x45; 32];
const ANTI_RECONSTRUCTION_FIXTURE: &[u8] =
    include_bytes!("../../../products/evidence/fixtures/conformance/anti-reconstruction.yaml");

#[derive(Debug, Parser)]
#[command(name = "evidence", version, about = "Registry Evidence Version 1")]
struct Cli {
    /// One closed operator runtime file that binds the governed bundle.
    #[arg(
        long,
        global = true,
        env = "REGISTRY_EVIDENCE_RUNTIME",
        default_value = DEFAULT_RUNTIME_PATH
    )]
    runtime: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate and compile the complete immutable bundle.
    Check,
    /// Evaluate one bundle-owned fixture without source or credential access.
    Evaluate {
        /// Bundle-relative fixture path referenced by exactly one requirement.
        #[arg(long)]
        fixture: PathBuf,
    },
    /// Start the native Evidence HTTP service.
    Serve,
}

#[derive(Debug, PartialEq, Eq)]
struct CliError(&'static str);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CliError {}

#[derive(Debug, Default, PartialEq, Eq)]
struct FixtureSummary {
    evaluated_cases: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("evidence: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Check => {
            let deployment = DeploymentInputs::load(&cli.runtime).map_err(deployment_load_error)?;
            let runtime = deployment.runtime;
            let bundle = Arc::new(deployment.bundle);
            OfflineKernel::compile(Arc::clone(&bundle))
                .map_err(|_| CliError("bundle compilation failed"))?;
            let _source_plans = compile_source_plans(&bundle.config, &runtime)?;
            println!(
                "Evidence deployment {} / {} passed check ({} requirements)",
                bundle.revision(),
                runtime.revision(),
                bundle.config.requirements.len()
            );
            Ok(())
        }
        Command::Evaluate { fixture } => {
            let deployment = DeploymentInputs::load(&cli.runtime).map_err(deployment_load_error)?;
            let runtime = deployment.runtime;
            let bundle = Arc::new(deployment.bundle);
            let kernel = OfflineKernel::compile(Arc::clone(&bundle))
                .map_err(|_| CliError("fixture bundle compilation failed"))?;
            let source_plans = compile_source_plans(&bundle.config, &runtime)?;
            let summary = evaluate_fixture(&bundle, &kernel, &source_plans, &fixture).await?;
            println!(
                "Evidence fixture passed ({} evaluated cases)",
                summary.evaluated_cases
            );
            Ok(())
        }
        Command::Serve => {
            let runtime = Arc::new(
                EvidenceRuntime::initialize(&cli.runtime)
                    .await
                    .map_err(runtime_initialization_error)?,
            );
            server::serve(runtime, shutdown_signal())
                .await
                .map_err(|_| CliError("service failed"))
        }
    }
}

fn deployment_load_error(error: BundleError) -> CliError {
    match error {
        BundleError::Unavailable => CliError("deployment input is unavailable"),
        BundleError::NotImmutable => CliError("deployment input is not immutable"),
        BundleError::UnsupportedEntry => CliError("deployment contains an unsupported entry"),
        BundleError::InvalidPath => CliError("deployment contains an invalid path binding"),
        BundleError::UnknownFile => CliError("deployment artifact closure is invalid"),
        BundleError::TooLarge => CliError("deployment exceeds a Version 1 size bound"),
        BundleError::Config(_) => CliError("deployment configuration is invalid"),
        BundleError::InvalidArtifact(_) => CliError("deployment artifact is invalid"),
        BundleError::InvalidScript => CliError("deployment script is invalid"),
    }
}

fn runtime_initialization_error(error: RuntimeInitializationError) -> CliError {
    match error {
        RuntimeInitializationError::Bundle => CliError("runtime bundle initialization failed"),
        RuntimeInitializationError::Secrets => CliError("runtime secret initialization failed"),
        RuntimeInitializationError::Audit => CliError("runtime audit initialization failed"),
        RuntimeInitializationError::Signing => CliError("runtime signing initialization failed"),
        RuntimeInitializationError::Source => CliError("runtime source initialization failed"),
        RuntimeInitializationError::RateLimit => {
            CliError("runtime rate-limit initialization failed")
        }
    }
}

fn compile_source_plans(
    config: &EvidenceConfig,
    runtime: &RuntimeDocument,
) -> Result<BTreeMap<String, SourceExecutor>, CliError> {
    compile_source_plans_with_runtime(
        config,
        &runtime.config.secret_providers.file.root,
        &runtime.config.outbound_tls,
        &runtime.ca_bundles,
    )
}

fn compile_source_plans_with_runtime(
    config: &EvidenceConfig,
    secret_root: &str,
    outbound_tls: &OutboundTlsConfig,
    ca_bundles: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, SourceExecutor>, CliError> {
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], secret_root)
            .map_err(|_| CliError("source plan compilation failed"))?,
    );
    let mut plans = BTreeMap::new();
    for (source_id, source) in config.sources.iter() {
        let allowed_selector_sets = config.source_selector_sets(source_id);
        let plan = SourceExecutor::new_with_selector_sets_and_tls(
            source,
            &allowed_selector_sets,
            outbound_tls,
            ca_bundles,
            Arc::clone(&secrets),
        )
        .map_err(|_| CliError("source plan compilation failed"))?;
        plans.insert(source_id.to_owned(), plan);
    }
    Ok(plans)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn evaluate_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, SourceExecutor>,
    fixture_path: &Path,
) -> Result<FixtureSummary, CliError> {
    let signer = offline_fixture_signer().await?;
    let fixture_name = safe_fixture_name(fixture_path)?;
    let referenced = bundle
        .config
        .requirements
        .iter()
        .filter(|requirement| requirement.fixtures.as_str() == fixture_name)
        .collect::<Vec<_>>();
    if referenced.len() != 1 {
        return Err(CliError(
            "fixture must be a captured artifact referenced by exactly one requirement",
        ));
    }
    let requirement = referenced[0];
    let fixture = bundle
        .fixtures
        .get(fixture_name)
        .ok_or(CliError("fixture artifact is not captured by the bundle"))?;
    let fixture = serde_json::to_value(fixture)
        .map_err(|_| CliError("fixture contract is not representable"))?;
    let object = fixture
        .as_object()
        .ok_or(CliError("fixture contract must be an object"))?;
    if object.get("synthetic_only") != Some(&Value::Bool(true)) {
        return Err(CliError("fixture is not an approved synthetic definition"));
    }
    if object.get("coequal_acceptance_definition") != Some(&Value::Bool(true)) {
        if object
            .get("fixture")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("registry.evidence.reference.") && id.ends_with("/v1"))
        {
            return evaluate_reference_fixture(
                bundle,
                kernel,
                source_plans,
                &signer,
                requirement,
                object,
            )
            .await;
        }
        return Err(CliError(
            "fixture is not an approved synthetic acceptance definition",
        ));
    }
    let common = object.get("common").and_then(Value::as_object);
    let cases = object
        .get("cases")
        .and_then(Value::as_array)
        .ok_or(CliError("fixture cases are unavailable"))?;
    if cases.is_empty() || cases.len() > 256 {
        return Err(CliError("fixture case count is invalid"));
    }

    let mut summary = FixtureSummary::default();
    let mut successful_values = Vec::new();
    for case in cases {
        let case = case
            .as_object()
            .ok_or(CliError("fixture case is not an object"))?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or(CliError("fixture case identifier is invalid"))?;

        if case.get("subjects").is_some() {
            require_expected(case, "pre-source-selector-rejection")?;
            match resolve_offline_fixture_subjects(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            ) {
                Ok(_) => return Err(CliError("fixture selector rejection did not occur")),
                Err(OfflineFixtureError::Purpose) => {
                    return Err(CliError(FIXTURE_PURPOSE_FAILURE));
                }
                Err(OfflineFixtureError::Authorization(_)) => {}
            }
            summary.evaluated_cases += 1;
            continue;
        }
        if let Some(expected_roles) = case.get("expected_subject_roles") {
            let expected_roles = expected_roles
                .as_array()
                .ok_or(CliError("fixture subject-role expectation is invalid"))?
                .iter()
                .map(|role| {
                    role.as_str()
                        .map(ToOwned::to_owned)
                        .ok_or(CliError("fixture subject-role expectation is invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let actual_roles = resolve_offline_fixture_subjects(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| fixture_failure(error, "fixture subjects did not resolve"))?;
            if actual_roles != expected_roles {
                return Err(CliError("fixture subject roles did not match"));
            }
        }
        let observed_at =
            fixture_observed_at(case, common, requirement.observation_timezone.as_deref())?;

        if let Some(source) = case.get("source") {
            let resolved = resolve_offline_fixture_authorization(
                bundle,
                requirement,
                common,
                case,
                OFFLINE_AUDIENCE,
            )
            .map_err(|error| fixture_failure(error, "fixture subjects did not resolve"))?;
            let derivation_selectors =
                fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
            if let Some(expected) = case
                .get("derivationSelectorInputs")
                .or_else(|| common.and_then(|common| common.get("derivationSelectorInputs")))
            {
                if expected != &derivation_selectors {
                    return Err(CliError(
                        "fixture derivation selector projection did not match",
                    ));
                }
            }
            let source_config = bundle
                .config
                .sources
                .get(&requirement.source)
                .ok_or(CliError("fixture source is unavailable"))?;
            let outcome = match project_fixture_response(source_config, source) {
                Ok(projected) => kernel.evaluate_with_selectors(
                    &requirement.id,
                    &projected,
                    &derivation_selectors,
                    observed_at,
                    ValueProjection {
                        audience: OFFLINE_AUDIENCE,
                        binding_key: &OFFLINE_BINDING_KEY,
                        binding_key_version: 1,
                    },
                ),
                Err(_) => Err(KernelError::SourceProtocol),
            };
            if let Some(values) = validate_case_outcome(id, case, outcome)? {
                successful_values.push(
                    sign_and_verify_fixture_evidence(
                        bundle,
                        kernel,
                        &signer,
                        requirement,
                        &resolved,
                        values,
                        observed_at,
                    )
                    .await?,
                );
            }
            summary.evaluated_cases += 1;
            continue;
        }

        if let Some(injected) = case.get("injected_derivation") {
            validate_injected_rejection(kernel, &requirement.id, injected)?;
            require_expected(case, "output-gate-rejection")?;
            summary.evaluated_cases += 1;
            continue;
        }

        if let Some(source_failure) = case.get("source_failure") {
            validate_source_failure(case, source_failure)?;
            summary.evaluated_cases += 1;
            continue;
        }

        if let Some(companion) = case.get("companion_bundle") {
            validate_companion_rejection(bundle, requirement, case, companion)?;
            summary.evaluated_cases += 1;
            continue;
        }

        return Err(CliError(
            "fixture case has no closed Version 1 evaluation form",
        ));
    }
    validate_privacy_expectation(object, requirement, &successful_values)?;
    Ok(summary)
}

async fn evaluate_reference_fixture(
    bundle: &Arc<Bundle>,
    kernel: &OfflineKernel,
    source_plans: &BTreeMap<String, SourceExecutor>,
    signer: &EvidenceSigner,
    requirement: &registry_evidence::config::RequirementConfig,
    fixture: &JsonMap<String, Value>,
) -> Result<FixtureSummary, CliError> {
    require_exact_keys(
        fixture,
        &[
            "fixture",
            "synthetic_only",
            "common",
            "cases",
            "privacyExpectation",
        ],
    )?;
    let common = fixture
        .get("common")
        .and_then(Value::as_object)
        .ok_or(CliError("reference fixture common block is invalid"))?;
    require_allowed_keys(
        common,
        &[
            "observed_at",
            "purpose",
            "selectors",
            "verified_token_claims",
            "derivationSelectorInputs",
            "expectedRequestParts",
            "expectedTransport",
        ],
    )?;
    for required in [
        "observed_at",
        "selectors",
        "expectedRequestParts",
        "expectedTransport",
    ] {
        if !common.contains_key(required) {
            return Err(CliError("reference fixture common block is incomplete"));
        }
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .filter(|cases| !cases.is_empty() && cases.len() <= 256)
        .ok_or(CliError("reference fixture case count is invalid"))?;
    let mut identifiers = std::collections::BTreeSet::new();
    let mut successful_values = Vec::new();
    let mut summary = FixtureSummary::default();

    for case in cases {
        let case = case
            .as_object()
            .ok_or(CliError("reference fixture case is not an object"))?;
        require_allowed_keys(
            case,
            &[
                "id",
                "purpose",
                "response",
                "sourceFailure",
                "bundleMutation",
                "requestMutation",
                "derivationMutation",
                "derivationParameterMutation",
                "selectorOverrides",
                "observed_at",
                "expected",
            ],
        )?;
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128 && identifiers.insert(*id))
            .ok_or(CliError("reference fixture case identifier is invalid"))?;
        let expected = case
            .get("expected")
            .and_then(Value::as_object)
            .ok_or(CliError("reference fixture expectation is invalid"))?;
        require_allowed_keys(
            expected,
            &[
                "lookup",
                "facts",
                "value",
                "entityReferenceCount",
                "rawReferencesDisclosed",
                "signed",
                "publicProblem",
                "error",
                "derivationRuns",
                "bundle",
                "outputGate",
                "rejectedBefore",
                "sourceRequestCount",
                "expectedTransport",
            ],
        )?;
        let forms = [
            "response",
            "sourceFailure",
            "bundleMutation",
            "requestMutation",
            "derivationMutation",
            "derivationParameterMutation",
            "selectorOverrides",
        ];
        let selected_forms = forms
            .iter()
            .filter(|name| case.contains_key(**name))
            .copied()
            .collect::<Vec<_>>();
        if selected_forms.len() != 1 {
            return Err(CliError("reference fixture case form is not closed"));
        }
        validate_reference_expectation_keys(selected_forms[0], expected)?;

        if let Some(mutation) = case.get("bundleMutation").and_then(Value::as_str) {
            if mutation != "duplicate-disclosure-family"
                || expected.get("bundle").and_then(Value::as_str) != Some("rejected")
            {
                return Err(CliError("reference bundle mutation is invalid"));
            }
            validate_reference_bundle_mutation(bundle, requirement)?;
            summary.evaluated_cases += 1;
            continue;
        }
        if let Some(mutation) = case.get("requestMutation").and_then(Value::as_str) {
            validate_reference_request_mutation(
                bundle,
                requirement,
                common,
                case,
                expected,
                mutation,
            )?;
            summary.evaluated_cases += 1;
            continue;
        }

        let resolved = resolve_offline_fixture_authorization(
            bundle,
            requirement,
            Some(common),
            case,
            OFFLINE_AUDIENCE,
        )
        .map_err(|error| fixture_failure(error, "reference fixture subjects did not resolve"))?;
        let source = bundle
            .config
            .sources
            .get(&requirement.source)
            .ok_or(CliError("reference fixture source is unavailable"))?;
        let source_plan = source_plans
            .get(&requirement.source)
            .ok_or(CliError("reference fixture source plan is unavailable"))?;
        let preparation_selectors =
            fixture_selector_value(&resolved, &source.request.selector_inputs)?;
        let prepared = match kernel.prepare(&requirement.id, &preparation_selectors) {
            Ok(prepared) => prepared,
            Err(error) if case.contains_key("selectorOverrides") => {
                validate_reference_error(expected, error, false)?;
                if expected.get("rejectedBefore").and_then(Value::as_str) != Some("credential") {
                    return Err(CliError(
                        "reference preparation rejection boundary did not match",
                    ));
                }
                require_reference_request_count(expected, 0)?;
                summary.evaluated_cases += 1;
                continue;
            }
            Err(_) => return Err(CliError("reference fixture request preparation failed")),
        };
        if !case.contains_key("selectorOverrides") {
            validate_reference_request_parts(common, &prepared)?;
        }
        let source_selectors =
            reference_source_selectors(&resolved, &source.request.selector_inputs)?;
        validate_reference_transport(
            source,
            source_plan,
            &source_selectors,
            &prepared,
            common
                .get("expectedTransport")
                .and_then(Value::as_object)
                .ok_or(CliError("reference transport expectation is invalid"))?,
        )?;
        if let Some(transport) = expected.get("expectedTransport").and_then(Value::as_object) {
            validate_reference_transport(
                source,
                source_plan,
                &source_selectors,
                &prepared,
                transport,
            )?;
        }
        if case.contains_key("selectorOverrides") {
            if expected.contains_key("error")
                || expected.contains_key("publicProblem")
                || expected.contains_key("rejectedBefore")
            {
                return Err(CliError(
                    "reference successful preparation contradicts its expectation",
                ));
            }
            require_reference_request_count(expected, 1)?;
            summary.evaluated_cases += 1;
            continue;
        }
        let derivation_selectors =
            fixture_selector_value(&resolved, &requirement.derivation.selector_inputs)?;
        if let Some(expected_selectors) = common.get("derivationSelectorInputs") {
            if expected_selectors != &derivation_selectors {
                return Err(CliError("reference derivation selectors did not match"));
            }
        } else if derivation_selectors != Value::Object(JsonMap::new()) {
            return Err(CliError(
                "reference derivation selectors were not minimized",
            ));
        }
        if let Some(failure) = case.get("sourceFailure").and_then(Value::as_str) {
            validate_reference_source_failure(failure, expected)?;
            summary.evaluated_cases += 1;
            continue;
        }

        let observed_at = fixture_observed_at(
            case,
            Some(common),
            requirement.observation_timezone.as_deref(),
        )?;
        if let Some(mutation) = case.get("derivationMutation").and_then(Value::as_str) {
            validate_reference_derivation_mutation(kernel, requirement, expected, mutation)?;
            summary.evaluated_cases += 1;
            continue;
        }
        if let Some(mutation) = case
            .get("derivationParameterMutation")
            .and_then(Value::as_object)
        {
            validate_reference_parameter_mutation(
                bundle,
                requirement,
                cases,
                mutation,
                &derivation_selectors,
                observed_at,
                expected,
            )?;
            summary.evaluated_cases += 1;
            continue;
        }

        let response = case
            .get("response")
            .ok_or(CliError("reference fixture response is unavailable"))?;
        let projected = project_fixture_response(source, response)
            .map_err(|_| CliError("reference fixture source projection failed"))?;
        if let Some(values) = validate_reference_response(
            ReferenceResponseContext {
                bundle,
                kernel,
                signer,
                requirement,
                resolved: &resolved,
            },
            &projected,
            &derivation_selectors,
            observed_at,
            expected,
        )
        .await?
        {
            successful_values.push(values);
        }
        require_reference_request_count(expected, 1)?;
        summary.evaluated_cases += 1;
        let _ = id;
    }

    validate_reference_privacy(fixture, requirement, &successful_values)?;
    Ok(summary)
}

struct ReferenceResponseContext<'a> {
    bundle: &'a Bundle,
    kernel: &'a OfflineKernel,
    signer: &'a EvidenceSigner,
    requirement: &'a registry_evidence::config::RequirementConfig,
    resolved: &'a ResolvedAuthorization,
}

async fn validate_reference_response(
    context: ReferenceResponseContext<'_>,
    response: &Value,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
) -> Result<Option<Value>, CliError> {
    let lookup = match context.kernel.extract(&context.requirement.id, response) {
        Ok(lookup) => lookup,
        Err(error) => {
            validate_reference_error(expected, error, false)?;
            return Ok(None);
        }
    };
    match lookup {
        LookupResult::NoMatch => {
            validate_reference_unresolved(expected, "no_match")?;
            Ok(None)
        }
        LookupResult::Ambiguous => {
            validate_reference_unresolved(expected, "ambiguous")?;
            Ok(None)
        }
        LookupResult::Match(facts) => {
            if expected.get("lookup").and_then(Value::as_str) != Some("match") {
                return Err(CliError("reference lookup outcome did not match"));
            }
            if let Some(exact) = expected.get("facts") {
                let actual = serde_json::to_value(&facts)
                    .map_err(|_| CliError("reference facts are not representable"))?;
                if exact != &actual {
                    return Err(CliError("reference exact facts did not match"));
                }
            }
            let values = match context.kernel.derive_and_validate_with_selectors(
                &context.requirement.id,
                &facts,
                selectors,
                observed_at,
                ValueProjection {
                    audience: OFFLINE_AUDIENCE,
                    binding_key: &OFFLINE_BINDING_KEY,
                    binding_key_version: 1,
                },
            ) {
                Ok(values) => values,
                Err(error) => {
                    validate_reference_error(expected, error, true)?;
                    return Ok(None);
                }
            };
            if expected.get("derivationRuns").and_then(Value::as_bool) != Some(true) {
                return Err(CliError("reference derivation execution did not match"));
            }
            if let Some(exact) = expected.get("value") {
                if values.as_slice().len() != 1
                    || public_json(&values.as_slice()[0].value)? != *exact
                {
                    return Err(CliError("reference scalar value did not match"));
                }
            }
            if let Some(count) = expected.get("entityReferenceCount").and_then(Value::as_u64) {
                let actual = match values.as_slice() {
                    [value] => match &value.value {
                        PublicValue::List(items) => items
                            .iter()
                            .filter(|item| {
                                matches!(item, ScalarOrEntityReference::EntityReference(_))
                            })
                            .count() as u64,
                        _ => 0,
                    },
                    _ => 0,
                };
                if actual != count {
                    return Err(CliError("reference entity-reference count did not match"));
                }
            }
            if expected
                .get("rawReferencesDisclosed")
                .and_then(Value::as_bool)
                == Some(false)
            {
                let encoded = serde_json::to_string(values.as_slice())
                    .map_err(|_| CliError("reference values are not representable"))?;
                let mut protected_source_strings = Vec::new();
                collect_strings(response, &mut protected_source_strings);
                if protected_source_strings
                    .iter()
                    .filter(|value| value.len() >= 8)
                    .any(|value| encoded.contains(value))
                {
                    return Err(CliError("reference raw source reference was disclosed"));
                }
            }
            if expected.get("signed").and_then(Value::as_bool) != Some(true) {
                return Err(CliError("reference signing expectation did not match"));
            }
            sign_and_verify_fixture_evidence(
                context.bundle,
                context.kernel,
                context.signer,
                context.requirement,
                context.resolved,
                values,
                observed_at,
            )
            .await
            .map(Some)
        }
    }
}

async fn sign_and_verify_fixture_evidence(
    bundle: &Bundle,
    kernel: &OfflineKernel,
    signer: &EvidenceSigner,
    requirement: &registry_evidence::config::RequirementConfig,
    resolved: &ResolvedAuthorization,
    values: ValidatedValues,
    observed_at: DateTime<Utc>,
) -> Result<Value, CliError> {
    let subjects = resolved
        .subjects
        .iter()
        .map(|subject| {
            Ok(SubjectBinding {
                role: subject.role.clone(),
                binding: subject
                    .binding(
                        &OFFLINE_BINDING_KEY,
                        1,
                        &bundle.config.service.trust_domain,
                        OFFLINE_AUDIENCE,
                        &resolved.purpose,
                    )
                    .map_err(|_| CliError("fixture subject binding failed"))?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let issued_at = observed_at + chrono::Duration::seconds(1);
    let evidence_id = format!("urn:ulid:{}", ulid::Ulid::new());
    let evidence = kernel
        .construct_evidence(
            &requirement.id,
            values,
            EvidenceConstruction {
                evidence_id: &evidence_id,
                purpose: &resolved.purpose,
                audience: OFFLINE_AUDIENCE,
                issued_at,
                observed_at,
                subjects,
            },
        )
        .map_err(|_| CliError("fixture evidence construction failed"))?;
    let signed = signer
        .sign_json(&evidence)
        .await
        .map_err(|_| CliError("fixture evidence signing failed"))?;
    let jwks = jwks_document(signer.public_jwk(), [])
        .map_err(|_| CliError("fixture verification key construction failed"))?;
    let verified = verify_flattened_jws(
        &serde_json::to_vec(&signed)
            .map_err(|_| CliError("fixture signed evidence is not representable"))?,
        &jwks,
        &EvidenceVerificationPolicy {
            issued_by: bundle.config.issuer.id.clone(),
            provided_by: bundle.config.service.provider_id.clone(),
            requirement: requirement.id.clone(),
            evidence_type: requirement.evidence_type.clone(),
            purpose: resolved.purpose.clone(),
            audience: OFFLINE_AUDIENCE.to_owned(),
            configuration_revision: bundle.revision().to_owned(),
            now: issued_at,
            clock_skew: std::time::Duration::ZERO,
        },
    )
    .map_err(|_| CliError("fixture signed evidence verification failed"))?;
    serde_json::to_value(verified)
        .map_err(|_| CliError("fixture verified evidence is not representable"))
}

async fn offline_fixture_signer() -> Result<EvidenceSigner, CliError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    const KEY_ID: &str = "offline-fixture-signing-key";
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_bytes = Zeroizing::new(signing_key.to_bytes());
    let public_bytes = signing_key.verifying_key().to_bytes();
    let private_jwk = PrivateJwk {
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
    let provider = Arc::new(
        LocalJwkSigner::new(private_jwk)
            .map_err(|_| CliError("offline fixture signer initialization failed"))?,
    );
    EvidenceSigner::initialize(provider, KEY_ID)
        .await
        .map_err(|_| CliError("offline fixture signer self-test failed"))
}

fn validate_reference_unresolved(
    expected: &JsonMap<String, Value>,
    lookup: &str,
) -> Result<(), CliError> {
    if expected.get("lookup").and_then(Value::as_str) != Some(lookup)
        || expected.get("derivationRuns").and_then(Value::as_bool) != Some(false)
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
        || expected.get("publicProblem").and_then(Value::as_str) != Some("evidence_not_available")
    {
        return Err(CliError("reference unresolved outcome did not match"));
    }
    Ok(())
}

fn validate_reference_expectation_keys(
    form: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let allowed: &[&str] = match form {
        "response" => &[
            "lookup",
            "facts",
            "value",
            "entityReferenceCount",
            "rawReferencesDisclosed",
            "signed",
            "publicProblem",
            "error",
            "derivationRuns",
            "sourceRequestCount",
        ],
        "sourceFailure" => &["publicProblem", "signed", "sourceRequestCount"],
        "bundleMutation" => &["bundle"],
        "requestMutation" => &["rejectedBefore", "signed", "sourceRequestCount"],
        "derivationMutation" => &["outputGate", "signed"],
        "derivationParameterMutation" => &["error", "publicProblem", "signed", "derivationRuns"],
        "selectorOverrides" => &[
            "expectedTransport",
            "error",
            "publicProblem",
            "signed",
            "rejectedBefore",
            "sourceRequestCount",
        ],
        _ => return Err(CliError("reference fixture case form is unknown")),
    };
    require_allowed_keys(expected, allowed)
}

fn validate_reference_error(
    expected: &JsonMap<String, Value>,
    error: KernelError,
    derivation_ran: bool,
) -> Result<(), CliError> {
    let (internal, public_problem) = match error {
        KernelError::Preparation => ("adapter_input_error", "service_unavailable"),
        KernelError::SourceProtocol => ("source_protocol_error", "dependency_unavailable"),
        KernelError::Script if derivation_ran => ("derivation_input_error", "service_unavailable"),
        KernelError::Extraction => ("evidence_not_available", "evidence_not_available"),
        _ => ("service_unavailable", "service_unavailable"),
    };
    let expected_error = expected.get("error").and_then(Value::as_str);
    let expected_problem = expected.get("publicProblem").and_then(Value::as_str);
    if expected_error.is_none() && expected_problem.is_none() {
        return Err(CliError("reference failing case has no exact expectation"));
    }
    if expected_error.is_some_and(|expected| expected != internal) {
        return Err(CliError("reference internal error did not match"));
    }
    if expected_problem.is_some_and(|expected| expected != public_problem) {
        return Err(CliError("reference public problem did not match"));
    }
    if expected.get("signed").and_then(Value::as_bool) != Some(false) {
        return Err(CliError(
            "reference failed case signing expectation did not match",
        ));
    }
    if expected.get("derivationRuns").and_then(Value::as_bool) != Some(derivation_ran) {
        return Err(CliError("reference derivation execution did not match"));
    }
    Ok(())
}

fn validate_reference_request_parts(
    common: &JsonMap<String, Value>,
    actual: &RequestParts,
) -> Result<(), CliError> {
    let expected = common
        .get("expectedRequestParts")
        .and_then(Value::as_object)
        .ok_or(CliError("reference request-parts expectation is invalid"))?;
    require_exact_keys(expected, &["query", "body"])?;
    let query = expected
        .get("query")
        .and_then(Value::as_array)
        .ok_or(CliError("reference query expectation is invalid"))?;
    if query.len() != actual.query.len() {
        return Err(CliError("reference prepared query did not match"));
    }
    for (expected, actual) in query.iter().zip(&actual.query) {
        let expected = expected
            .as_object()
            .ok_or(CliError("reference query-pair expectation is invalid"))?;
        require_exact_keys(expected, &["name", "value"])?;
        if expected.get("name").and_then(Value::as_str) != Some(&actual.name)
            || expected.get("value").and_then(Value::as_str) != Some(&actual.value)
        {
            return Err(CliError("reference prepared query did not match"));
        }
    }
    let expected_body = expected.get("body").filter(|body| !body.is_null());
    if expected_body != actual.body.as_ref() {
        return Err(CliError("reference prepared body did not match"));
    }
    Ok(())
}

fn validate_reference_transport(
    source: &registry_evidence::config::SourceConfig,
    source_plan: &SourceExecutor,
    selectors: &[ResolvedSourceSelector],
    parts: &RequestParts,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    require_allowed_keys(expected, &["path", "query", "body", "fixedHeaders"])?;
    let materialized = source_plan
        .materialize_request(selectors, parts)
        .map_err(|_| CliError("reference transport materialization failed"))?;
    if expected
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|path| materialized.path() != path)
    {
        return Err(CliError("reference materialized path did not match"));
    }
    if let Some(query) = expected.get("query").and_then(Value::as_str) {
        if materialized.query().unwrap_or_default() != query {
            return Err(CliError("reference encoded query did not match"));
        }
    }
    if let Some(body) = expected.get("body").filter(|body| !body.is_null()) {
        if materialized.body() != Some(body) {
            return Err(CliError("reference transport body did not match"));
        }
    }
    if let Some(headers) = expected.get("fixedHeaders").and_then(Value::as_array) {
        if headers.len() != source.request.fixed_headers.len() {
            return Err(CliError("reference fixed headers did not match"));
        }
        for (expected, actual) in headers.iter().zip(&source.request.fixed_headers) {
            let expected = expected
                .as_object()
                .ok_or(CliError("reference fixed-header expectation is invalid"))?;
            require_exact_keys(expected, &["name", "value"])?;
            if expected.get("name").and_then(Value::as_str) != Some(&actual.name)
                || expected.get("value").and_then(Value::as_str) != Some(&actual.value)
            {
                return Err(CliError("reference fixed headers did not match"));
            }
        }
    }
    Ok(())
}

fn reference_source_selectors(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Vec<ResolvedSourceSelector>, CliError> {
    inputs
        .iter()
        .map(|input| {
            let subject = resolved
                .subjects
                .iter()
                .find(|subject| subject.role == input.role)
                .ok_or(CliError("reference source selector role is unavailable"))?;
            let alternative = input
                .alternatives
                .iter()
                .find(|alternative| alternative.profile == subject.selector_profile)
                .ok_or(CliError("reference source selector profile is invalid"))?;
            let values = alternative
                .fields
                .iter()
                .map(|name| {
                    let field = subject
                        .fields
                        .iter()
                        .find(|field| &field.name == name)
                        .ok_or(CliError("reference source selector field is unavailable"))?;
                    let value = match &field.value {
                        ResolvedSelectorValue::String(value)
                        | ResolvedSelectorValue::Date(value)
                        | ResolvedSelectorValue::ControlledCode(value) => {
                            SelectorValue::String(value.clone())
                        }
                        ResolvedSelectorValue::Integer(value) => SelectorValue::Integer(*value),
                        ResolvedSelectorValue::Boolean(value) => SelectorValue::Boolean(*value),
                    };
                    Ok((name.clone(), value))
                })
                .collect::<Result<BTreeMap<_, _>, CliError>>()?;
            Ok(ResolvedSourceSelector {
                role: input.role.clone(),
                profile: alternative.profile.clone(),
                values,
            })
        })
        .collect()
}

fn validate_reference_source_failure(
    failure: &str,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let error = match failure {
        "timeout" => SourceError::Timeout,
        "connection-refused" => SourceError::Transport,
        "invalid-media-type" => SourceError::WrongMediaType,
        "oversized" => SourceError::ResponseTooLarge,
        "malformed-json" => SourceError::InvalidJson,
        _ => return Err(CliError("reference source-failure name is invalid")),
    };
    if source_failure_problem(&error) != ProblemCode::DependencyUnavailable
        || expected.get("publicProblem").and_then(Value::as_str) != Some("dependency_unavailable")
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError("reference source-failure mapping is invalid"));
    }
    require_reference_request_count(expected, 1)
}

fn validate_reference_bundle_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
) -> Result<(), CliError> {
    let mut mutated = bundle.config.clone();
    let mut companion = requirement.clone();
    companion.id.push_str(":fixture-companion");
    companion.evidence_type.push_str(":fixture-companion");
    for concept in &mut companion.concepts {
        concept.id.push_str(":fixture-companion");
    }
    mutated.requirements.push(companion);
    if mutated.validate()
        != Err(ConfigError::Invalid(
            "enabled requirements share a disclosure family",
        ))
    {
        return Err(CliError(
            "reference unsafe bundle mutation was not rejected",
        ));
    }
    Ok(())
}

fn validate_reference_request_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    common: &JsonMap<String, Value>,
    case: &JsonMap<String, Value>,
    expected: &JsonMap<String, Value>,
    mutation: &str,
) -> Result<(), CliError> {
    if expected.get("rejectedBefore").and_then(Value::as_str) != Some("source") {
        return Err(CliError("reference request rejection boundary is invalid"));
    }
    let selectors = common
        .get("selectors")
        .and_then(Value::as_object)
        .ok_or(CliError("reference selectors are invalid"))?;
    let mut subjects = selectors
        .iter()
        .map(|(role, selector)| {
            let mut selector = selector
                .as_object()
                .cloned()
                .ok_or(CliError("reference selector is invalid"))?;
            selector.insert("role".to_owned(), Value::String(role.clone()));
            Ok(Value::Object(selector))
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    match mutation {
        "swap-subject-roles" if subjects.len() == 2 => {
            let first = subjects[0]["role"].clone();
            subjects[0]["role"] = subjects[1]["role"].clone();
            subjects[1]["role"] = first;
        }
        "supply-grant-derived-candidate" => {}
        _ => return Err(CliError("reference request-mutation name is invalid")),
    }
    let mut mutated = case.clone();
    mutated.insert("subjects".to_owned(), Value::Array(subjects));
    match resolve_offline_fixture_authorization(
        bundle,
        requirement,
        Some(common),
        &mutated,
        OFFLINE_AUDIENCE,
    ) {
        Ok(_) => return Err(CliError("reference request mutation was authorized")),
        Err(OfflineFixtureError::Purpose) => return Err(CliError(FIXTURE_PURPOSE_FAILURE)),
        Err(OfflineFixtureError::Authorization(_)) => {}
    }
    if expected.get("signed").and_then(Value::as_bool) != Some(false) {
        return Err(CliError("reference rejected request requires signing"));
    }
    require_reference_request_count(expected, 0)
}

fn validate_reference_derivation_mutation(
    kernel: &OfflineKernel,
    requirement: &registry_evidence::config::RequirementConfig,
    expected: &JsonMap<String, Value>,
    mutation: &str,
) -> Result<(), CliError> {
    if mutation != "return-raw-reference"
        || expected.get("outputGate").and_then(Value::as_str) != Some("rejected")
        || expected.get("signed").and_then(Value::as_bool) != Some(false)
    {
        return Err(CliError("reference derivation mutation is invalid"));
    }
    let injected = vec![DerivedConceptValue {
        concept_id: requirement.concepts[0].id.clone(),
        value: DerivedValue::Json(Value::String("PROTECTED-REFERENCE".to_owned())),
    }];
    if kernel
        .validate_values(
            &requirement.id,
            injected,
            ValueProjection {
                audience: OFFLINE_AUDIENCE,
                binding_key: &OFFLINE_BINDING_KEY,
                binding_key_version: 1,
            },
        )
        .is_ok()
    {
        return Err(CliError(
            "reference derivation mutation crossed the output gate",
        ));
    }
    Ok(())
}

fn validate_reference_parameter_mutation(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    cases: &[Value],
    mutation: &JsonMap<String, Value>,
    selectors: &Value,
    observed_at: DateTime<Utc>,
    expected: &JsonMap<String, Value>,
) -> Result<(), CliError> {
    let mut disposable = bundle.clone();
    let mut config = serde_json::to_value(&disposable.config)
        .map_err(|_| CliError("reference configuration is not representable"))?;
    let target = config["requirements"]
        .as_array_mut()
        .and_then(|requirements| {
            requirements
                .iter_mut()
                .find(|candidate| candidate["id"].as_str() == Some(&requirement.id))
        })
        .ok_or(CliError("reference disposable requirement is unavailable"))?;
    let parameters = target["derivation"]["parameters"]
        .as_object_mut()
        .ok_or(CliError("reference derivation parameters are invalid"))?;
    for (name, value) in mutation {
        if !parameters.contains_key(name) {
            return Err(CliError("reference parameter mutation is unknown"));
        }
        parameters.insert(name.clone(), value.clone());
    }
    disposable.config = serde_json::from_value(config)
        .map_err(|_| CliError("reference parameter mutation is invalid"))?;
    disposable
        .config
        .validate()
        .map_err(|_| CliError("reference parameter mutation broke configuration"))?;
    let disposable = Arc::new(disposable);
    let kernel = OfflineKernel::compile(Arc::clone(&disposable))
        .map_err(|_| CliError("reference disposable kernel did not compile"))?;
    let positive = cases
        .iter()
        .find(|case| case.get("id").and_then(Value::as_str) == Some("positive"))
        .and_then(|case| case.get("response"))
        .ok_or(CliError("reference positive response is unavailable"))?;
    let source = disposable
        .config
        .sources
        .get(&requirement.source)
        .ok_or(CliError("reference disposable source is unavailable"))?;
    let projected = project_fixture_response(source, positive)
        .map_err(|_| CliError("reference positive response projection failed"))?;
    let outcome = kernel.evaluate_with_selectors(
        &requirement.id,
        &projected,
        selectors,
        observed_at,
        ValueProjection {
            audience: OFFLINE_AUDIENCE,
            binding_key: &OFFLINE_BINDING_KEY,
            binding_key_version: 1,
        },
    );
    match outcome {
        Err(error) => validate_reference_error(expected, error, true),
        Ok(_) => Err(CliError("reference parameter mutation did not fail")),
    }
}

fn require_reference_request_count(
    expected: &JsonMap<String, Value>,
    actual: u64,
) -> Result<(), CliError> {
    if expected
        .get("sourceRequestCount")
        .and_then(Value::as_u64)
        .is_some_and(|count| count != actual)
        || actual > 1
    {
        return Err(CliError("reference source request count did not match"));
    }
    Ok(())
}

fn validate_reference_privacy(
    fixture: &JsonMap<String, Value>,
    requirement: &registry_evidence::config::RequirementConfig,
    successful_values: &[Value],
) -> Result<(), CliError> {
    let source = fixture
        .get("privacyExpectation")
        .and_then(Value::as_object)
        .ok_or(CliError("reference privacy expectation is invalid"))?;
    require_exact_keys(
        source,
        &["evidenceContains", "evidenceExcludes", "diagnosticsExclude"],
    )?;
    let mut expectation = JsonMap::new();
    for (source_name, target_name) in [
        ("evidenceContains", "evidence_contains"),
        ("evidenceExcludes", "evidence_excludes"),
        ("diagnosticsExclude", "diagnostics_exclude"),
    ] {
        expectation.insert(
            target_name.to_owned(),
            source
                .get(source_name)
                .cloned()
                .ok_or(CliError("reference privacy expectation is incomplete"))?,
        );
    }
    let projection = serde_json::json!({
        "supportsRequirement": requirement.id,
        "isConformantTo": requirement.evidence_type,
        "subjectRoles": requirement
            .subject_roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        "successfulValues": successful_values,
    });
    validate_privacy_projection(&expectation, &projection)
}

const FIXTURE_PURPOSE_FAILURE: &str = "fixture does not select one of the requirement's purposes";

/// Report an unselected fixture purpose as its own failure so a harness
/// omission is never presented as a rejected request.
fn fixture_failure(error: OfflineFixtureError, authorization: &'static str) -> CliError {
    match error {
        OfflineFixtureError::Purpose => CliError(FIXTURE_PURPOSE_FAILURE),
        OfflineFixtureError::Authorization(_) => CliError(authorization),
    }
}

fn require_exact_keys(object: &JsonMap<String, Value>, expected: &[&str]) -> Result<(), CliError> {
    require_allowed_keys(object, expected)?;
    if expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(CliError("reference fixture required key is missing"));
    }
    Ok(())
}

fn require_allowed_keys(object: &JsonMap<String, Value>, allowed: &[&str]) -> Result<(), CliError> {
    if object
        .keys()
        .any(|key| !allowed.iter().any(|allowed| key == allowed))
    {
        return Err(CliError("reference fixture contains an unknown key"));
    }
    Ok(())
}

fn fixture_selector_value(
    resolved: &ResolvedAuthorization,
    inputs: &[SelectorInput],
) -> Result<Value, CliError> {
    let mut selectors = JsonMap::new();
    for input in inputs {
        let subject = resolved
            .subjects
            .iter()
            .find(|subject| subject.role == input.role)
            .ok_or(CliError("fixture selector input role is unavailable"))?;
        let alternative = input
            .alternatives
            .iter()
            .find(|alternative| alternative.profile == subject.selector_profile)
            .ok_or(CliError("fixture selector input profile is unavailable"))?;
        let mut values = JsonMap::new();
        for name in &alternative.fields {
            let field = subject
                .fields
                .iter()
                .find(|field| &field.name == name)
                .ok_or(CliError("fixture selector input field is unavailable"))?;
            values.insert(name.clone(), field.value.as_json());
        }
        let mut selector = JsonMap::new();
        selector.insert(
            "profile".to_owned(),
            Value::String(alternative.profile.clone()),
        );
        selector.insert("values".to_owned(), Value::Object(values));
        if selectors
            .insert(input.role.clone(), Value::Object(selector))
            .is_some()
        {
            return Err(CliError("fixture selector input role is duplicated"));
        }
    }
    Ok(Value::Object(selectors))
}

fn validate_case_outcome(
    _case_id: &str,
    case: &serde_json::Map<String, Value>,
    outcome: Result<KernelOutcome, registry_evidence::kernel::KernelError>,
) -> Result<Option<ValidatedValues>, CliError> {
    let derivation_runs = optional_boolean(case, "derivation_runs")?;
    let signed_success = optional_boolean(case, "signed_success")?;
    let expected_problem = optional_string(case, "expected_public_problem")?;

    if let Some(expected_lookup @ ("no_match" | "ambiguous")) =
        optional_string(case, "expected_lookup")?
    {
        let matches = matches!(
            (expected_lookup, &outcome),
            ("no_match", Ok(KernelOutcome::NoMatch)) | ("ambiguous", Ok(KernelOutcome::Ambiguous))
        );
        if !matches {
            return Err(CliError(
                "fixture lookup outcome did not match its contract",
            ));
        }
        if signed_success != Some(false) || derivation_runs != Some(false) {
            return Err(CliError(
                "unresolved fixture must deny derivation and signed success",
            ));
        }
        if expected_problem != Some("evidence_not_available") {
            return Err(CliError("unresolved fixture public problem is not exact"));
        }
        return Ok(None);
    }
    if optional_string(case, "expected_lookup")?.is_some_and(|lookup| lookup != "match") {
        return Err(CliError("fixture lookup expectation is invalid"));
    }

    if let Some(problem) = expected_problem {
        let exact = matches!(
            (problem, &outcome),
            (
                "evidence_not_available",
                Err(registry_evidence::kernel::KernelError::Extraction)
            ) | (
                "dependency_unavailable",
                Err(registry_evidence::kernel::KernelError::SourceProtocol)
            ) | (
                "service_unavailable",
                Err(registry_evidence::kernel::KernelError::Script
                    | registry_evidence::kernel::KernelError::Output
                    | registry_evidence::kernel::KernelError::Bundle
                    | registry_evidence::kernel::KernelError::Requirement
                    | registry_evidence::kernel::KernelError::Evidence)
            )
        );
        if !exact {
            return Err(CliError(
                "fixture kernel failure did not match its public problem",
            ));
        }
        let derivation_ran = !matches!(
            outcome,
            Err(registry_evidence::kernel::KernelError::Extraction
                | registry_evidence::kernel::KernelError::SourceProtocol)
        );
        if signed_success != Some(false) || derivation_runs != Some(derivation_ran) {
            return Err(CliError(
                "failing fixture execution expectations did not match",
            ));
        }
        return Ok(None);
    }

    let KernelOutcome::Match(values) =
        outcome.map_err(|_| CliError("fixture evaluation failed unexpectedly"))?
    else {
        return Err(CliError("fixture expected a unique match"));
    };
    if optional_string(case, "expected_lookup")? != Some("match") {
        return Err(CliError("matched fixture must require an exact match"));
    }
    if derivation_runs == Some(false) {
        return Err(CliError("matched fixture cannot deny derivation execution"));
    }
    if signed_success == Some(false) {
        return Err(CliError(
            "matched fixture cannot deny signed-success eligibility",
        ));
    }

    let expected_value = case.get("expected_value");
    let expected_values = case.get("expected_values");
    if expected_value.is_some() == expected_values.is_some() {
        return Err(CliError(
            "matched fixture must declare exactly one value expectation",
        ));
    }
    if let Some(expected) = expected_value {
        if values.as_slice().len() != 1 || public_json(&values.as_slice()[0].value)? != *expected {
            return Err(CliError("fixture value did not match its contract"));
        }
    }
    if let Some(expected) = expected_values.and_then(Value::as_object) {
        if values.as_slice().len() != expected.len() {
            return Err(CliError("fixture value set did not match its contract"));
        }
        for (name, expected_value) in expected {
            let actual = values
                .as_slice()
                .iter()
                .filter(|candidate| {
                    candidate.provides_value_for == *name
                        || candidate
                            .provides_value_for
                            .strip_suffix(name)
                            .is_some_and(|prefix| prefix.ends_with(':'))
                })
                .collect::<Vec<_>>();
            if actual.len() != 1 || public_json(&actual[0].value)? != *expected_value {
                return Err(CliError("fixture value set did not match its contract"));
            }
        }
    } else if expected_values.is_some() {
        return Err(CliError("fixture value-set expectation is invalid"));
    }
    if derivation_runs != Some(true) || signed_success != Some(true) {
        return Err(CliError(
            "matched fixture must require derivation and signed success",
        ));
    }
    Ok(Some(values))
}

fn validate_source_failure(
    case: &serde_json::Map<String, Value>,
    source_failure: &Value,
) -> Result<(), CliError> {
    let failure = match source_failure.as_str() {
        Some("timeout") => SourceError::Timeout,
        Some("redirect") => SourceError::Redirect,
        Some("http-503") => SourceError::Status(SourceStatus::ServerError),
        Some("wrong-media-type") => SourceError::WrongMediaType,
        _ => return Err(CliError("fixture source-failure category is invalid")),
    };
    if optional_string(case, "expected_public_problem")? != Some("dependency_unavailable")
        || optional_boolean(case, "signed_success")? != Some(false)
        || source_failure_problem(&failure) != ProblemCode::DependencyUnavailable
    {
        return Err(CliError("fixture source-failure mapping is invalid"));
    }
    Ok(())
}

fn validate_companion_rejection(
    bundle: &Bundle,
    requirement: &registry_evidence::config::RequirementConfig,
    case: &serde_json::Map<String, Value>,
    companion: &Value,
) -> Result<(), CliError> {
    let label = companion
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .ok_or(CliError("fixture companion-bundle label is invalid"))?;
    require_expected(case, "bundle-rejection")?;
    let matrix: Value = serde_norway::from_slice(ANTI_RECONSTRUCTION_FIXTURE)
        .map_err(|_| CliError("anti-reconstruction fixture is invalid"))?;
    let rejected = matrix
        .get("rejected_bundles")
        .and_then(Value::as_array)
        .ok_or(CliError("anti-reconstruction fixture is invalid"))?;
    let declaration = rejected
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(label))
        .and_then(Value::as_object)
        .ok_or(CliError("fixture companion-bundle label is unknown"))?;
    let shared_family = declaration
        .get("shared_disclosure_family")
        .and_then(Value::as_str)
        .ok_or(CliError("anti-reconstruction family is invalid"))?;
    let definitions = declaration
        .get("definitions")
        .and_then(Value::as_array)
        .filter(|definitions| definitions.len() >= 2)
        .ok_or(CliError(
            "anti-reconstruction combination must contain multiple definitions",
        ))?;
    let distinct_definitions = definitions
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<std::collections::BTreeSet<_>, _>>()
        .map_err(|_| CliError("anti-reconstruction definition is invalid"))?;
    if distinct_definitions.len() != definitions.len()
        || !definitions.iter().all(Value::is_object)
        || declaration
            .get("threat")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || declaration
            .get("expected")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(CliError(
            "anti-reconstruction combination declaration is incomplete",
        ));
    }

    let mut unsafe_config = bundle.config.clone();
    let original = unsafe_config
        .requirements
        .iter_mut()
        .find(|candidate| candidate.id == requirement.id)
        .ok_or(CliError("fixture requirement is missing"))?;
    original.disclosure_guard.families = vec![shared_family.to_owned()];
    for index in 1..definitions.len() {
        let suffix = format!(":fixture-companion-{index}");
        let mut companion = requirement.clone();
        companion.id.push_str(&suffix);
        companion.evidence_type.push_str(&suffix);
        companion.disclosure_guard.families = vec![shared_family.to_owned()];
        companion.derivation.script = registry_evidence::config::ArtifactPath::parse(&format!(
            "derivations/fixture-companion-{index}.rhai"
        ))
        .map_err(|_| CliError("fixture companion path is invalid"))?;
        companion.fixtures = registry_evidence::config::ArtifactPath::parse(&format!(
            "fixtures/fixture-companion-{index}.yaml"
        ))
        .map_err(|_| CliError("fixture companion path is invalid"))?;
        for concept in &mut companion.concepts {
            concept.id.push_str(&suffix);
        }
        unsafe_config.requirements.push(companion);
    }
    if unsafe_config.validate()
        != Err(ConfigError::Invalid(
            "enabled requirements share a disclosure family",
        ))
    {
        return Err(CliError("unsafe companion bundle was not rejected"));
    }
    Ok(())
}

fn optional_boolean(
    case: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<bool>, CliError> {
    case.get(name)
        .map(|value| {
            value
                .as_bool()
                .ok_or(CliError("fixture boolean expectation is invalid"))
        })
        .transpose()
}

fn optional_string<'a>(
    case: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>, CliError> {
    case.get(name)
        .map(|value| {
            value
                .as_str()
                .ok_or(CliError("fixture string expectation is invalid"))
        })
        .transpose()
}

fn validate_privacy_expectation(
    fixture: &serde_json::Map<String, Value>,
    requirement: &registry_evidence::config::RequirementConfig,
    successful_values: &[Value],
) -> Result<(), CliError> {
    let expectation = fixture
        .get("privacy_expectation")
        .and_then(Value::as_object)
        .ok_or(CliError("fixture privacy expectation is unavailable"))?;
    let projection = serde_json::json!({
        "supportsRequirement": requirement.id,
        "isConformantTo": requirement.evidence_type,
        "subjectRoles": requirement
            .subject_roles
            .iter()
            .map(|role| role.role.as_str())
            .collect::<Vec<_>>(),
        "successfulValues": successful_values,
    });
    validate_privacy_projection(expectation, &projection)
}

fn validate_privacy_projection(
    expectation: &serde_json::Map<String, Value>,
    projection: &Value,
) -> Result<(), CliError> {
    let mut disclosed_strings = Vec::new();
    collect_strings(projection, &mut disclosed_strings);

    for expected in expectation_strings(expectation, "evidence_contains")? {
        if !disclosed_strings.contains(&expected) {
            return Err(CliError("fixture required disclosure is absent"));
        }
    }
    for prohibited in expectation_strings(expectation, "evidence_excludes")? {
        if disclosed_strings.contains(&prohibited) {
            return Err(CliError("fixture prohibited disclosure is present"));
        }
    }
    // CLI diagnostics are structurally static (`CliError(&'static str)`) and
    // the success line contains counts only. Still exercise every declared
    // diagnostic canary against the exact dynamic-free output templates so a
    // future template change cannot silently weaken this fixture assertion.
    for prohibited in expectation_strings(expectation, "diagnostics_exclude")? {
        if [
            "Evidence fixture passed (0 evaluated cases)",
            "evidence: fixture evaluation failed",
        ]
        .iter()
        .any(|surface| surface.contains(prohibited))
        {
            return Err(CliError("fixture prohibited diagnostic is present"));
        }
    }
    Ok(())
}

fn expectation_strings<'a>(
    expectation: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<&'a str>, CliError> {
    expectation
        .get(name)
        .and_then(Value::as_array)
        .ok_or(CliError("fixture privacy expectation is invalid"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or(CliError("fixture privacy expectation is invalid"))
        })
        .collect()
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

fn validate_injected_rejection(
    kernel: &OfflineKernel,
    requirement_id: &str,
    injected: &Value,
) -> Result<(), CliError> {
    let injected = injected
        .as_array()
        .ok_or(CliError("injected derivation fixture must be an array"))?;
    let mut derived = Vec::with_capacity(injected.len());
    for value in injected {
        let object = value
            .as_object()
            .ok_or(CliError("injected derivation member is invalid"))?;
        if object.len() != 2 {
            return Err(CliError("injected derivation member is not closed"));
        }
        let concept_id = object
            .get("concept_id")
            .and_then(Value::as_str)
            .ok_or(CliError("injected derivation concept is invalid"))?;
        let value = object
            .get("value")
            .cloned()
            .ok_or(CliError("injected derivation value is missing"))?;
        derived.push(DerivedConceptValue {
            concept_id: concept_id.to_owned(),
            value: DerivedValue::Json(value),
        });
    }
    if kernel
        .validate_values(
            requirement_id,
            derived,
            ValueProjection {
                audience: OFFLINE_AUDIENCE,
                binding_key: &OFFLINE_BINDING_KEY,
                binding_key_version: 1,
            },
        )
        .is_ok()
    {
        return Err(CliError("injected derivation was not rejected"));
    }
    Ok(())
}

fn public_json(value: &PublicValue) -> Result<Value, CliError> {
    serde_json::to_value(value).map_err(|_| CliError("fixture value is not representable"))
}

fn fixture_observed_at(
    case: &serde_json::Map<String, Value>,
    common: Option<&serde_json::Map<String, Value>>,
    timezone: Option<&str>,
) -> Result<DateTime<Utc>, CliError> {
    if let Some(observed) = case.get("observed_at").and_then(Value::as_str) {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = case.get("legal_local_date").and_then(Value::as_str) {
        return local_date_at_noon(local_date, timezone);
    }

    if let Some(observed) = common
        .and_then(|value| value.get("observed_at"))
        .and_then(Value::as_str)
    {
        return DateTime::parse_from_rfc3339(observed)
            .map(|value| value.with_timezone(&Utc))
            .map_err(|_| CliError("fixture observation time is invalid"));
    }

    if let Some(local_date) = common
        .and_then(|value| value.get("legal_local_date"))
        .and_then(Value::as_str)
    {
        return local_date_at_noon(local_date, timezone);
    }

    DateTime::parse_from_rfc3339("1970-01-01T12:00:00Z")
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CliError("fixed fixture time is invalid"))
}

fn local_date_at_noon(local_date: &str, timezone: Option<&str>) -> Result<DateTime<Utc>, CliError> {
    let date = NaiveDate::parse_from_str(local_date, "%Y-%m-%d")
        .map_err(|_| CliError("fixture legal local date is invalid"))?;
    let local_noon = date
        .and_hms_opt(12, 0, 0)
        .ok_or(CliError("fixture legal local date is invalid"))?;
    let timezone = timezone
        .map(Tz::from_str)
        .transpose()
        .map_err(|_| CliError("fixture observation timezone is invalid"))?
        .unwrap_or(Tz::UTC);
    timezone
        .from_local_datetime(&local_noon)
        .single()
        .map(|value| value.with_timezone(&Utc))
        .ok_or(CliError("fixture legal local date cannot be resolved"))
}

fn require_expected(case: &serde_json::Map<String, Value>, expected: &str) -> Result<(), CliError> {
    if case.get("expected").and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(CliError("fixture boundary expectation is invalid"))
    }
}

fn safe_fixture_name(path: &Path) -> Result<&str, CliError> {
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(CliError(
            "fixture path must be bundle-relative and normalized",
        ));
    }
    let name = path
        .to_str()
        .filter(|value| value.starts_with("fixtures/") && value.ends_with(".yaml"))
        .ok_or(CliError("fixture path is invalid"))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fixture_paths_never_escape_the_captured_bundle() {
        assert_eq!(
            safe_fixture_name(Path::new("fixtures/cases.yaml")),
            Ok("fixtures/cases.yaml")
        );
        assert!(safe_fixture_name(Path::new("../fixtures/cases.yaml")).is_err());
        assert!(safe_fixture_name(Path::new("/tmp/cases.yaml")).is_err());
    }

    #[test]
    fn offline_dates_are_fixed_and_never_use_ambient_time() {
        let case = serde_json::json!({"legal_local_date": "2026-08-03"});
        let observed = fixture_observed_at(case.as_object().expect("object"), None, None)
            .expect("date converts");
        assert_eq!(observed.to_rfc3339(), "2026-08-03T12:00:00+00:00");
    }

    #[test]
    fn case_local_date_overrides_common_observation_time() {
        let case = serde_json::json!({"legal_local_date": "2026-08-01"});
        let common = serde_json::json!({"observed_at": "2026-08-02T00:00:00Z"});
        let observed = fixture_observed_at(
            case.as_object().expect("case object"),
            common.as_object(),
            Some("Asia/Bangkok"),
        )
        .expect("case-local date converts");
        assert_eq!(observed.to_rfc3339(), "2026-08-01T05:00:00+00:00");
    }

    #[test]
    fn symbolic_source_failures_use_the_production_public_mapper() {
        for category in ["timeout", "redirect", "http-503", "wrong-media-type"] {
            let case = serde_json::json!({
                "source_failure": category,
                "expected_public_problem": "dependency_unavailable",
                "signed_success": false
            });
            let object = case.as_object().expect("object");
            assert_eq!(
                validate_source_failure(object, &object["source_failure"]),
                Ok(())
            );
        }
    }

    #[test]
    fn public_unavailability_requires_an_extraction_failure() {
        let case = serde_json::json!({
            "expected_public_problem": "evidence_not_available",
            "derivation_runs": false,
            "signed_success": false
        });
        let case = case.as_object().expect("object");
        assert!(validate_case_outcome("case", case, Ok(KernelOutcome::NoMatch)).is_err());
        assert!(validate_case_outcome(
            "case",
            case,
            Err(registry_evidence::kernel::KernelError::Script),
        )
        .is_err());
        assert_eq!(
            validate_case_outcome(
                "case",
                case,
                Err(registry_evidence::kernel::KernelError::Extraction),
            ),
            Ok(None)
        );
    }

    #[test]
    fn service_unavailability_requires_an_internal_kernel_failure() {
        let case = serde_json::json!({
            "expected_public_problem": "service_unavailable",
            "derivation_runs": true,
            "signed_success": false
        });
        let case = case.as_object().expect("object");
        assert_eq!(
            validate_case_outcome(
                "case",
                case,
                Err(registry_evidence::kernel::KernelError::Script),
            ),
            Ok(None)
        );
        assert!(validate_case_outcome(
            "case",
            case,
            Err(registry_evidence::kernel::KernelError::Extraction),
        )
        .is_err());
    }

    #[test]
    fn unresolved_lookup_rejects_derivation_or_signed_success_claims() {
        for declaration in [
            serde_json::json!({
                "expected_lookup": "no_match",
                "expected_public_problem": "evidence_not_available",
                "derivation_runs": true
            }),
            serde_json::json!({
                "expected_lookup": "no_match",
                "expected_public_problem": "evidence_not_available",
                "signed_success": true
            }),
        ] {
            assert!(validate_case_outcome(
                "case",
                declaration.as_object().expect("object"),
                Ok(KernelOutcome::NoMatch),
            )
            .is_err());
        }
    }

    #[test]
    fn reference_fixture_forms_reject_irrelevant_expectations() {
        let bundle = serde_json::json!({"bundle": "rejected"});
        assert_eq!(
            validate_reference_expectation_keys(
                "bundleMutation",
                bundle.as_object().expect("object"),
            ),
            Ok(())
        );

        let irrelevant = serde_json::json!({"bundle": "rejected", "signed": false});
        assert!(validate_reference_expectation_keys(
            "bundleMutation",
            irrelevant.as_object().expect("object"),
        )
        .is_err());

        let transport = serde_json::json!({
            "expectedTransport": {"path": "/records"},
            "sourceRequestCount": 1
        });
        assert_eq!(
            validate_reference_expectation_keys(
                "selectorOverrides",
                transport.as_object().expect("object"),
            ),
            Ok(())
        );
        assert!(validate_reference_expectation_keys(
            "response",
            transport.as_object().expect("object"),
        )
        .is_err());
    }

    #[test]
    fn reference_failures_require_exact_unsigned_stage_expectations() {
        let exact = serde_json::json!({
            "error": "source_protocol_error",
            "publicProblem": "dependency_unavailable",
            "derivationRuns": false,
            "signed": false
        });
        assert_eq!(
            validate_reference_error(
                exact.as_object().expect("object"),
                KernelError::SourceProtocol,
                false,
            ),
            Ok(())
        );

        let wrong_public = serde_json::json!({
            "error": "source_protocol_error",
            "publicProblem": "service_unavailable",
            "derivationRuns": false,
            "signed": false
        });
        assert!(validate_reference_error(
            wrong_public.as_object().expect("object"),
            KernelError::SourceProtocol,
            false,
        )
        .is_err());
    }

    #[test]
    fn privacy_expectations_check_exact_projected_strings() {
        let expectation = serde_json::json!({
            "evidence_contains": ["urn:example:concept", "subject"],
            "evidence_excludes": ["raw-source-value"],
            "diagnostics_exclude": ["selector-value"]
        });
        let projection = serde_json::json!({
            "subjectRoles": ["subject"],
            "successfulValues": [{"providesValueFor": "urn:example:concept", "value": true}]
        });
        assert_eq!(
            validate_privacy_projection(
                expectation.as_object().expect("expectation object"),
                &projection,
            ),
            Ok(())
        );

        let leaking = serde_json::json!({"value": "raw-source-value"});
        assert!(validate_privacy_projection(
            expectation.as_object().expect("expectation object"),
            &leaking,
        )
        .is_err());

        let leaking_key = serde_json::json!({"raw-source-value": false});
        assert!(validate_privacy_projection(
            expectation.as_object().expect("expectation object"),
            &leaking_key,
        )
        .is_err());
    }

    #[test]
    fn check_compiles_source_plans_without_resolving_secrets() {
        let valid = std::str::from_utf8(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("fixture is UTF-8");
        let valid_config = EvidenceConfig::parse_yaml(valid.as_bytes()).expect("config validates");
        let outbound_tls = OutboundTlsConfig {
            system_roots: true,
            trust_profiles: Default::default(),
        };
        assert_eq!(
            compile_source_plans_with_runtime(
                &valid_config,
                "/run/secrets/evidence",
                &outbound_tls,
                &Default::default(),
            )
            .map(|plans| plans.len()),
            Ok(valid_config.sources.len())
        );

        let invalid = valid.replacen("timeoutMilliseconds: 3000", "timeoutMilliseconds: 0", 1);
        assert_ne!(invalid, valid, "fixture mutation must remain effective");
        let invalid_config: EvidenceConfig =
            serde_norway::from_str(&invalid).expect("closed typed shape deserializes");
        assert_eq!(
            compile_source_plans_with_runtime(
                &invalid_config,
                "/run/secrets/evidence",
                &outbound_tls,
                &Default::default(),
            )
            .map(|_| ()),
            Err(CliError("source plan compilation failed"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_every_coequal_acceptance_fixture() {
        for definition in [
            "adult-status",
            "residence-region",
            "professional-licence",
            "legal-parent-relationship",
        ] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/fixtures/acceptance")
                .join(definition);
            copy_tree(&source, directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let source_plans = compile_source_plans_with_runtime(
                &bundle.config,
                "/run/secrets/evidence",
                &OutboundTlsConfig {
                    system_roots: true,
                    trust_profiles: Default::default(),
                },
                &Default::default(),
            )
            .expect("source plans compile");
            let fixture = Path::new(bundle.config.requirements[0].fixtures.as_str());
            let expected_cases = bundle.fixtures[fixture.to_str().expect("fixture path")]
                .get("cases")
                .and_then(serde_norway::Value::as_sequence)
                .expect("cases")
                .len();
            assert_eq!(
                evaluate_fixture(&bundle, &kernel, &source_plans, fixture).await,
                Ok(FixtureSummary {
                    evaluated_cases: expected_cases,
                }),
                "{definition}"
            );

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_the_combined_acceptance_bundle() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/all-definitions");
        copy_tree(&source, directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Arc::new(Bundle::load(directory.path()).expect("acceptance bundle loads"));
        let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
        let source_plans = compile_source_plans_with_runtime(
            &bundle.config,
            "/run/secrets/evidence",
            &OutboundTlsConfig {
                system_roots: true,
                trust_profiles: Default::default(),
            },
            &Default::default(),
        )
        .expect("source plans compile");
        for requirement in &bundle.config.requirements {
            let fixture = Path::new(requirement.fixtures.as_str());
            assert!(
                evaluate_fixture(&bundle, &kernel, &source_plans, fixture)
                    .await
                    .is_ok(),
                "combined acceptance fixture failed"
            );
        }

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn offline_cli_evaluates_every_reference_deployment_fixture() {
        for project in ["dhis2-adult-status", "opencrvs-family-evidence"] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/reference/request-adapter/deployment-projects")
                .join(project)
                .join("bundle");
            copy_tree(&source, directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = Arc::new(Bundle::load(directory.path()).expect("reference bundle loads"));
            let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("kernel compiles");
            let outbound_tls: OutboundTlsConfig = if project == "dhis2-adult-status" {
                serde_norway::from_str(
                    "systemRoots: true\ntrustProfiles:\n  government-internal-pki:\n    caBundleFile: /etc/registry-evidence/ca/government-internal.pem\n",
                )
                .expect("private TLS profile parses")
            } else {
                OutboundTlsConfig {
                    system_roots: true,
                    trust_profiles: Default::default(),
                }
            };
            let ca_bundles = if project == "dhis2-adult-status" {
                let certificate =
                    rcgen::generate_simple_self_signed(
                        vec!["tracker.dhis2.gov.example".to_owned()],
                    )
                    .expect("generate private TLS root");
                let certificate = test_certificate_pem(certificate.cert.der().as_ref());
                BTreeMap::from([("government-internal-pki".to_owned(), certificate)])
            } else {
                BTreeMap::new()
            };
            let source_plans = compile_source_plans_with_runtime(
                &bundle.config,
                "/run/secrets/evidence",
                &outbound_tls,
                &ca_bundles,
            )
            .expect("source plans compile");
            for requirement in &bundle.config.requirements {
                let fixture = Path::new(requirement.fixtures.as_str());
                let expected_cases = bundle.fixtures[requirement.fixtures.as_str()]
                    .get("cases")
                    .and_then(serde_norway::Value::as_sequence)
                    .expect("cases")
                    .len();
                assert_eq!(
                    evaluate_fixture(&bundle, &kernel, &source_plans, fixture).await,
                    Ok(FixtureSummary {
                        evaluated_cases: expected_cases,
                    }),
                    "{project}/{}",
                    requirement.id
                );
            }

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create destination");
        for entry in fs::read_dir(source).expect("read source tree") {
            let entry = entry.expect("source entry");
            let target = destination.join(entry.file_name());
            if entry.file_type().expect("source type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("copy artifact");
            }
        }
    }

    #[cfg(unix)]
    fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::symlink_metadata(path).expect("tree metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("read tree") {
                set_tree_mode(
                    &entry.expect("tree entry").path(),
                    directory_mode,
                    file_mode,
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
                .expect("set directory mode");
        } else {
            fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
                .expect("set file mode");
        }
    }

    #[cfg(unix)]
    fn test_certificate_pem(der: &[u8]) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is UTF-8"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem.into_bytes()
    }
}
