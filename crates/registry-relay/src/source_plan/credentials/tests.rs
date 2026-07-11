// SPDX-License-Identifier: Apache-2.0
//! Tests for the closed HTTP Basic credential provider.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt as _;

use registry_platform_crypto::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;
use crate::source_plan::{
    EvidenceClass, PinnedEvidenceArtifact, PinnedSourcePlanArtifact, SourcePlanArtifactBundle,
};

const PACK_DOMAIN: &[u8] = b"registry.relay.integration-pack.v1\0";
const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const POLICY_DOMAIN: &[u8] = b"registry.relay.consultation-policy.v1\0";
const OAUTH_PACK: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/integration-pack.json");
const OAUTH_CONTRACT: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/public-contract.json");
const OAUTH_BINDING: &[u8] =
    include_bytes!("../../../tests/fixtures/source-plan-v1/private-binding.json");
const OAUTH_CONFORMANCE: &[u8] = b"synthetic registry conformance evidence v1\n";
const OAUTH_NEGATIVE_SECURITY: &[u8] = b"synthetic registry negative security evidence v1\n";
const OAUTH_MINIMIZATION: &[u8] = b"synthetic registry minimization proof v1\n";

static ENV_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct EnvironmentGuard {
    name: String,
    previous: Option<OsString>,
}

impl EnvironmentGuard {
    fn set(name: String, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(&name);
        std::env::set_var(&name, value);
        Self { name, previous }
    }

    fn missing(name: String) -> Self {
        let previous = std::env::var_os(&name);
        std::env::remove_var(&name);
        Self { name, previous }
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(&self.name, previous);
        } else {
            std::env::remove_var(&self.name);
        }
    }
}

fn unique_env_name(label: &str) -> String {
    let sequence = ENV_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("REGISTRY_RELAY_BASIC_TEST_{label}_{sequence}")
}

fn catalog(
    reference: &str,
    generation: u64,
    username_env: &str,
    password_env: &str,
) -> ConsultationSourceCredentialCatalogConfig {
    catalog_from_yaml(&format!(
            "- type: basic\n  ref: {reference}\n  generation: {generation}\n  username_env: {username_env}\n  password_env: {password_env}\n"
        ))
}

fn catalog_from_yaml(yaml: &str) -> ConsultationSourceCredentialCatalogConfig {
    serde_saphyr::from_str(yaml).expect("source credential catalog parses")
}

fn basic_registry() -> CompiledSourcePlanRegistry {
    let (contract, pack, binding) = basic_artifacts();
    compile_registry_set(&[&contract], &[&pack], &[&binding])
}

fn basic_and_oauth_registry() -> CompiledSourcePlanRegistry {
    let (contract, pack, binding) = basic_artifacts();
    compile_registry_set(
        &[&contract, OAUTH_CONTRACT],
        &[&pack, OAUTH_PACK],
        &[&binding, OAUTH_BINDING],
    )
}

fn basic_artifacts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut pack = parse_json_strict(OAUTH_PACK).expect("strict source-plan pack");
    pack["id"] = json!("synthetic.person-status.basic");
    pack["spec"]["plan"]["operations"][0]["auth"] = json!({
        "mode": "basic",
        "max_value_bytes": 256
    });
    pack["spec"]["plan"]["credential_destination_slot"] = Value::Null;
    pack["spec"]["plan"]["credential_operation"] = Value::Null;
    pack["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    let pack = serde_json::to_vec(&pack).expect("Basic source-plan pack JSON");
    let pack_hash = typed_hash(PACK_DOMAIN, &pack);

    let mut contract = parse_json_strict(OAUTH_CONTRACT).expect("strict source contract");
    contract["id"] = json!("synthetic.person-status.basic");
    contract["spec"]["integration_pack"]["id"] = json!("synthetic.person-status.basic");
    contract["spec"]["integration_pack"]["hash"] = Value::String(pack_hash.clone());
    contract["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    contract["spec"]["authorization"]["policy"]["id"] =
        json!("relay.synthetic.person-status.basic");
    refresh_policy_hash(&mut contract);
    let contract = serde_json::to_vec(&contract).expect("Basic source contract JSON");

    let mut binding = parse_json_strict(OAUTH_BINDING).expect("strict source binding");
    binding["profile"]["id"] = json!("synthetic.person-status.basic");
    binding["integration_pack"]["id"] = json!("synthetic.person-status.basic");
    binding["integration_pack"]["hash"] = Value::String(pack_hash);
    binding["credential_destination"] = Value::Null;
    binding["credential"]["ref"] = json!("people-basic-reader");
    binding["limits"]
        .as_object_mut()
        .expect("binding limits")
        .remove("max_token_lifetime_ms");
    let binding = serde_json::to_vec(&binding).expect("Basic source binding JSON");
    (contract, pack, binding)
}

fn oauth_registry() -> CompiledSourcePlanRegistry {
    compile_registry_set(&[OAUTH_CONTRACT], &[OAUTH_PACK], &[OAUTH_BINDING])
}

fn compile_registry_set(
    contract_bytes: &[&[u8]],
    pack_bytes: &[&[u8]],
    binding_bytes: &[&[u8]],
) -> CompiledSourcePlanRegistry {
    let contract_hashes = contract_bytes
        .iter()
        .map(|bytes| typed_hash(CONTRACT_DOMAIN, bytes))
        .collect::<Vec<_>>();
    let pack_hashes = pack_bytes
        .iter()
        .map(|bytes| typed_hash(PACK_DOMAIN, bytes))
        .collect::<Vec<_>>();
    let contracts = contract_bytes
        .iter()
        .zip(&contract_hashes)
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let packs = pack_bytes
        .iter()
        .zip(&pack_hashes)
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let evidence_bytes = [
        OAUTH_CONFORMANCE,
        OAUTH_NEGATIVE_SECURITY,
        OAUTH_MINIMIZATION,
    ];
    let evidence_hashes = evidence_bytes.map(raw_hash);
    let evidence = [
        PinnedEvidenceArtifact::new(
            EvidenceClass::Conformance,
            evidence_bytes[0],
            &evidence_hashes[0],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::NegativeSecurity,
            evidence_bytes[1],
            &evidence_hashes[1],
        ),
        PinnedEvidenceArtifact::new(
            EvidenceClass::Minimization,
            evidence_bytes[2],
            &evidence_hashes[2],
        ),
    ];
    CompiledSourcePlanRegistry::compile(
        &SourcePlanArtifactBundle::new(&contracts, &packs, binding_bytes).with_evidence(&evidence),
    )
    .expect("reviewed source plan compiles")
}

fn typed_hash(domain: &[u8], raw: &[u8]) -> String {
    let value = parse_json_strict(raw).expect("strict fixture JSON");
    let canonical = canonicalize_json(&value).expect("canonical fixture JSON");
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    digest_string(hasher.finalize())
}

fn refresh_policy_hash(contract: &mut Value) {
    let authorization = &contract["spec"]["authorization"];
    let policy = &authorization["policy"];
    let preimage = json!({
        "schema": "registry.relay.consultation-policy.v1",
        "enforcement_profile": "registry.relay.consultation-pdp/v1",
        "rule_set": "registry.relay.consultation-policy-rules.v1",
        "id": policy["id"].clone(),
        "action": "consultation_execute",
        "target": {
            "profile": {
                "id": contract["id"].clone(),
                "version": contract["version"].clone()
            },
            "integration_pack": contract["spec"]["integration_pack"].clone()
        },
        "authorization": {
            "workload": authorization["workload"].clone(),
            "required_scope": authorization["required_scope"].clone(),
            "purposes": authorization["purposes"].clone(),
            "legal_basis": authorization["legal_basis"].clone(),
            "consent": authorization["consent"].clone(),
            "mandatory_obligations": authorization["mandatory_obligations"].clone()
        },
        "decision": {
            "permit": "unqualified",
            "decision_cache": policy["decision_cache"].clone(),
            "max_decision_age_ms": policy["max_decision_age_ms"].clone(),
            "unavailable": policy["unavailable"].clone()
        }
    });
    let preimage = serde_json::to_vec(&preimage).expect("policy preimage JSON");
    contract["spec"]["authorization"]["policy"]["hash"] =
        Value::String(typed_hash(POLICY_DOMAIN, &preimage));
}

fn raw_hash(raw: &[u8]) -> String {
    digest_string(Sha256::digest(raw))
}

fn digest_string(digest: impl IntoIterator<Item = u8>) -> String {
    let mut encoded = String::from("sha256:");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[test]
fn closure_errors_precede_environment_access() {
    let registry = basic_registry();
    let missing: ConsultationSourceCredentialCatalogConfig =
        serde_saphyr::from_str("[]").expect("empty catalog");
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&missing, &registry).unwrap_err(),
        SourceCredentialProviderError::MissingCredential
    );

    let username_env = unique_env_name("CLOSURE_USERNAME");
    let password_env = unique_env_name("CLOSURE_PASSWORD");
    let _username = EnvironmentGuard::missing(username_env.clone());
    let _password = EnvironmentGuard::missing(password_env.clone());
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("unreferenced-reader", 1, &username_env, &password_env),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::ExtraCredential
    );
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 8, &username_env, &password_env),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::CredentialGenerationMismatch
    );
    let oauth_only = CompiledBasicSourceCredentialProvider::compile(&missing, &oauth_registry())
        .expect("OAuth-only plans belong to another provider");
    assert_eq!(oauth_only.credentials.len(), 0);
}

#[test]
fn basic_provider_closes_only_basic_subset_of_mixed_registry() {
    let username_env = unique_env_name("MIXED_BASIC_USERNAME");
    let password_env = unique_env_name("MIXED_BASIC_PASSWORD");
    let unused_oauth_env = unique_env_name("MIXED_OAUTH_MUST_NOT_READ");
    let _username = EnvironmentGuard::set(username_env.clone(), "basic-user");
    let _password = EnvironmentGuard::set(password_env.clone(), "basic-password");
    let _oauth_missing = EnvironmentGuard::missing(unused_oauth_env);
    let registry = basic_and_oauth_registry();
    assert_eq!(registry.len(), 2);

    let provider = CompiledBasicSourceCredentialProvider::compile(
        &catalog("people-basic-reader", 7, &username_env, &password_env),
        &registry,
    )
    .expect("Basic and OAuth plans coexist without claiming OAuth material");
    assert_eq!(provider.credentials.len(), 1);
    assert_eq!(provider.operation_bindings.len(), 1);

    let basic_plan = registry
        .iter()
        .find(|plan| {
            plan.operations()
                .any(|operation| operation.auth() == CompiledSourceAuth::Basic)
        })
        .expect("Basic plan");
    let basic_operation = basic_plan.operations().next().expect("Basic operation");
    provider
        .authorization_for(basic_plan, basic_operation)
        .expect("Basic provider claims its exact operation");

    let oauth_plan = registry
        .iter()
        .find(|plan| {
            plan.operations()
                .any(|operation| operation.auth() == CompiledSourceAuth::OAuthClientCredentials)
        })
        .expect("OAuth plan");
    let oauth_operation = oauth_plan.operations().next().expect("OAuth operation");
    assert_eq!(
        provider
            .authorization_for(oauth_plan, oauth_operation)
            .unwrap_err(),
        SourceCredentialProviderError::OperationBindingMismatch
    );
}

#[test]
fn provider_repeats_catalog_bounds_duplicates_and_generation_checks() {
    let registry = basic_registry();
    let duplicate = catalog_from_yaml(
            "- type: basic\n  ref: people-basic-reader\n  generation: 7\n  username_env: USER_A\n  password_env: PASSWORD_A\n- type: basic\n  ref: people-basic-reader\n  generation: 7\n  username_env: USER_B\n  password_env: PASSWORD_B\n",
        );
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&duplicate, &registry).unwrap_err(),
        SourceCredentialProviderError::DuplicateCredentialReference
    );
    let duplicate_env = catalog_from_yaml(
            "- type: basic\n  ref: people-basic-reader\n  generation: 7\n  username_env: SAME_ENV\n  password_env: SAME_ENV\n",
        );
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&duplicate_env, &registry).unwrap_err(),
        SourceCredentialProviderError::DuplicateEnvironmentReference
    );
    let zero_generation = catalog("people-basic-reader", 0, "USER_A", "PASSWORD_A");
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&zero_generation, &registry).unwrap_err(),
        SourceCredentialProviderError::InvalidGeneration
    );

    let mut over_bound = String::new();
    for index in 0..=MAX_CONSULTATION_SOURCE_CREDENTIALS {
        writeln!(
                &mut over_bound,
                "- type: basic\n  ref: reader-{index}\n  generation: 1\n  username_env: USER_{index}\n  password_env: PASSWORD_{index}"
            )
            .expect("catalog YAML");
    }
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&catalog_from_yaml(&over_bound), &registry,)
            .unwrap_err(),
        SourceCredentialProviderError::CatalogOutOfBounds
    );
}

#[test]
fn distinct_references_cannot_retain_identical_basic_material() {
    let username_env_a = unique_env_name("DUPLICATE_MATERIAL_USERNAME_A");
    let password_env_a = unique_env_name("DUPLICATE_MATERIAL_PASSWORD_A");
    let username_env_b = unique_env_name("DUPLICATE_MATERIAL_USERNAME_B");
    let password_env_b = unique_env_name("DUPLICATE_MATERIAL_PASSWORD_B");
    let _username_a = EnvironmentGuard::set(username_env_a.clone(), "shared-user");
    let _password_a = EnvironmentGuard::set(password_env_a.clone(), "shared-password");
    let _username_b = EnvironmentGuard::set(username_env_b.clone(), "shared-user");
    let _password_b = EnvironmentGuard::set(password_env_b.clone(), "shared-password");

    let (contract, pack, binding) = basic_artifacts();
    let mut contract_value = parse_json_strict(&contract).expect("second contract");
    contract_value["id"] = json!("synthetic.person-status.basic-two");
    contract_value["spec"]["authorization"]["policy"]["id"] =
        json!("relay.synthetic.person-status.basic-two");
    refresh_policy_hash(&mut contract_value);
    let second_contract = serde_json::to_vec(&contract_value).expect("second contract JSON");
    let mut binding_value = parse_json_strict(&binding).expect("second binding");
    binding_value["profile"]["id"] = json!("synthetic.person-status.basic-two");
    binding_value["credential"]["ref"] = json!("people-basic-reader-two");
    let second_binding = serde_json::to_vec(&binding_value).expect("second binding JSON");
    let registry = compile_registry_set(
        &[&contract, &second_contract],
        &[&pack],
        &[&binding, &second_binding],
    );
    let catalog = catalog_from_yaml(&format!(
            "- type: basic\n  ref: people-basic-reader\n  generation: 7\n  username_env: {username_env_a}\n  password_env: {password_env_a}\n- type: basic\n  ref: people-basic-reader-two\n  generation: 7\n  username_env: {username_env_b}\n  password_env: {password_env_b}\n"
        ));
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(&catalog, &registry).unwrap_err(),
        SourceCredentialProviderError::DuplicateCredentialMaterial
    );
}

#[test]
fn invalid_environment_material_fails_closed_without_diagnostics() {
    let registry = basic_registry();
    let cases = [
        (
            "EMPTY_USERNAME",
            "",
            "password",
            SourceCredentialProviderError::InvalidBasicMaterial,
        ),
        (
            "EMPTY_PASSWORD",
            "username",
            "",
            SourceCredentialProviderError::InvalidBasicMaterial,
        ),
        (
            "COLON_USERNAME",
            "user:name",
            "password",
            SourceCredentialProviderError::InvalidBasicMaterial,
        ),
        (
            "CONTROL_USERNAME",
            "user\nname",
            "password",
            SourceCredentialProviderError::InvalidBasicMaterial,
        ),
        (
            "CONTROL_PASSWORD",
            "username",
            "pass\rword",
            SourceCredentialProviderError::InvalidBasicMaterial,
        ),
    ];
    for (label, username, password, expected) in cases {
        let username_env = unique_env_name(label);
        let password_env = unique_env_name(label);
        let _username = EnvironmentGuard::set(username_env.clone(), username);
        let _password = EnvironmentGuard::set(password_env.clone(), password);
        let error = CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 7, &username_env, &password_env),
            &registry,
        )
        .unwrap_err();
        assert_eq!(error, expected);
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains(&username_env));
        assert!(!diagnostics.contains(&password_env));
        if !username.is_empty() {
            assert!(!diagnostics.contains(username));
        }
        if !password.is_empty() {
            assert!(!diagnostics.contains(password));
        }
    }

    let username_env = unique_env_name("MISSING");
    let password_env = unique_env_name("MISSING");
    let _username = EnvironmentGuard::missing(username_env.clone());
    let _password = EnvironmentGuard::set(password_env.clone(), "password");
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 7, &username_env, &password_env,),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::EnvironmentLoadFailed
    );
}

#[cfg(unix)]
#[test]
fn non_unicode_environment_material_is_rejected_and_scrubbed() {
    let username_env = unique_env_name("NON_UNICODE");
    let password_env = unique_env_name("NON_UNICODE");
    let _username = EnvironmentGuard::set(
        username_env.clone(),
        OsString::from_vec(vec![b'u', 0xff, b'r']),
    );
    let _password = EnvironmentGuard::set(password_env.clone(), "password");
    let error = CompiledBasicSourceCredentialProvider::compile(
        &catalog("people-basic-reader", 7, &username_env, &password_env),
        &basic_registry(),
    )
    .unwrap_err();
    assert_eq!(error, SourceCredentialProviderError::EnvironmentLoadFailed);
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains(&username_env));
    assert!(!diagnostics.contains(&password_env));
}

#[test]
fn oversized_component_and_rendered_header_are_rejected() {
    let registry = basic_registry();
    let username_env = unique_env_name("PROFILE_HEADER_BOUND");
    let password_env = unique_env_name("PROFILE_HEADER_BOUND");
    let _username = EnvironmentGuard::set(username_env.clone(), "u".repeat(100));
    let _password = EnvironmentGuard::set(password_env.clone(), "p".repeat(100));
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 7, &username_env, &password_env,),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::BasicMaterialTooLarge
    );

    let username_env = unique_env_name("OVERSIZED_COMPONENT");
    let password_env = unique_env_name("OVERSIZED_COMPONENT");
    let _username = EnvironmentGuard::set(username_env.clone(), "u".repeat(4_097));
    let _password = EnvironmentGuard::set(password_env.clone(), "password");
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 7, &username_env, &password_env,),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::BasicMaterialTooLarge
    );

    let username_env = unique_env_name("OVERSIZED_HEADER");
    let password_env = unique_env_name("OVERSIZED_HEADER");
    let _username = EnvironmentGuard::set(username_env.clone(), "u".repeat(4_096));
    let _password = EnvironmentGuard::set(password_env.clone(), "p".repeat(4_096));
    assert_eq!(
        CompiledBasicSourceCredentialProvider::compile(
            &catalog("people-basic-reader", 7, &username_env, &password_env,),
            &registry,
        )
        .unwrap_err(),
        SourceCredentialProviderError::BasicMaterialTooLarge
    );
}

#[test]
fn success_precomputes_exact_payload_and_only_renders_bound_operation() {
    let username_env = unique_env_name("SUCCESS_USERNAME");
    let password_env = unique_env_name("SUCCESS_PASSWORD");
    let username = "aladdin";
    let password = "open: sesame";
    let _username = EnvironmentGuard::set(username_env.clone(), username);
    let _password = EnvironmentGuard::set(password_env.clone(), password);
    let registry = basic_registry();
    let provider = CompiledBasicSourceCredentialProvider::compile(
        &catalog("people-basic-reader", 7, &username_env, &password_env),
        &registry,
    )
    .expect("exact Basic catalog compiles");

    let stored = provider
        .credentials
        .values()
        .next()
        .expect("one credential");
    assert_eq!(
        stored.encoded_payload.as_slice(),
        STANDARD.encode(format!("{username}:{password}")).as_bytes()
    );
    let diagnostics = format!("{provider:?}");
    for marker in [
        username_env.as_str(),
        password_env.as_str(),
        username,
        password,
        "people-basic-reader",
    ] {
        assert!(!diagnostics.contains(marker));
    }

    let plan = registry.iter().next().expect("Basic plan");
    let operation = plan.operations().next().expect("Basic operation");
    let capability = provider
        .authorization_for(plan, operation)
        .expect("exact operation receives capability");
    assert!(!format!("{capability:?}").contains(username));
    capability
        .render(&["registration_status", "2", "benefits", "Person-42"])
        .expect("capability renders only through its compiled operation");

    let oauth = oauth_registry();
    let foreign_plan = oauth.iter().next().expect("foreign plan");
    let foreign_operation = foreign_plan.operations().next().expect("foreign operation");
    assert_eq!(
        provider
            .authorization_for(foreign_plan, foreign_operation)
            .unwrap_err(),
        SourceCredentialProviderError::OperationBindingMismatch
    );
}
