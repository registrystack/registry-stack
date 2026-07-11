// SPDX-License-Identifier: Apache-2.0
//! Closed, restart-only HTTP Basic credentials for compiled consultation plans.

#![allow(
    dead_code,
    reason = "the provider is staged immediately before consultation executor integration"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use registry_platform_httputil::destination::{
    DataDestinationRequest, DestinationAuthorizationValue, DestinationRequestError,
    MAX_DESTINATION_HEADER_VALUE_BYTES,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::{
    ConsultationSourceCredentialCatalogConfig, ConsultationSourceCredentialConfig,
    MAX_CONSULTATION_SOURCE_CREDENTIALS,
};
use crate::consultation::{
    IntegrationPackHash, OperationId, ProfileContractHash, ProfileId, ProfileVersion,
};

use super::{
    CompiledOperation, CompiledRequestCodec, CompiledSourceAuth, CompiledSourcePlan,
    CompiledSourcePlanRegistry, ReadMethod,
};

const MAX_BASIC_COMPONENT_BYTES: usize = 4 * 1024;
const BASIC_SCHEME_PREFIX_BYTES: usize = b"Basic ".len();

/// Value-free startup and binding failures.
///
/// No variant carries a credential reference, environment-variable name,
/// source topology value, or secret-derived diagnostic.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum SourceCredentialProviderError {
    #[error("consultation source-credential catalog exceeds its protocol bound")]
    CatalogOutOfBounds,
    #[error("consultation source-credential catalog contains a duplicate reference")]
    DuplicateCredentialReference,
    #[error("consultation source-credential catalog contains a duplicate environment reference")]
    DuplicateEnvironmentReference,
    #[error("consultation source-credential generation is invalid")]
    InvalidGeneration,
    #[error("compiled consultation plans require a source credential that is not configured")]
    MissingCredential,
    #[error("consultation source-credential catalog contains an unreferenced entry")]
    ExtraCredential,
    #[error("consultation source-credential generation does not match the compiled plan")]
    CredentialGenerationMismatch,
    #[error("compiled consultation source authentication is not supported by this provider")]
    AuthenticationKindMismatch,
    #[error("compiled HTTP Basic operation is outside the closed V1 request shape")]
    BasicOperationShapeMismatch,
    #[error("consultation source-credential environment material could not be loaded")]
    EnvironmentLoadFailed,
    #[error("consultation HTTP Basic credential material is invalid")]
    InvalidBasicMaterial,
    #[error("consultation HTTP Basic credential material exceeds its bound")]
    BasicMaterialTooLarge,
    #[error("consultation source-credential catalog contains duplicate credential material")]
    DuplicateCredentialMaterial,
    #[error("consultation HTTP Basic credential could not be encoded")]
    BasicEncodingFailed,
    #[error("consultation HTTP Basic capability does not match the compiled plan operation")]
    OperationBindingMismatch,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CredentialKey {
    reference: Box<str>,
    generation: u64,
}

impl CredentialKey {
    fn new(reference: &str, generation: u64) -> Self {
        Self {
            reference: reference.into(),
            generation,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct OperationBindingKey {
    profile_id: ProfileId,
    profile_version: ProfileVersion,
    profile_contract_hash: ProfileContractHash,
    integration_pack_hash: IntegrationPackHash,
    private_binding_hash: Box<str>,
    operation_id: OperationId,
}

impl OperationBindingKey {
    fn from_plan_operation(plan: &CompiledSourcePlan, operation: &CompiledOperation) -> Self {
        Self {
            profile_id: plan.profile().id().clone(),
            profile_version: plan.profile().version(),
            profile_contract_hash: plan.profile().contract_hash().clone(),
            integration_pack_hash: plan.integration_pack().hash().clone(),
            private_binding_hash: plan.binding_hash().into(),
            operation_id: operation.id().clone(),
        }
    }
}

struct CredentialRequirement {
    generation: u64,
    operations: Vec<OperationBindingKey>,
}

struct StoredBasicCredential {
    encoded_payload: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for StoredBasicCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredBasicCredential(<redacted>)")
    }
}

/// Immutable credential closure compiled against one source-plan registry.
///
/// The provider is neither cloneable nor serializable. It retains only Base64
/// payloads in zeroizing storage, never raw usernames or passwords. Lookup is
/// possible only through a complete compiled plan and one of that plan's exact
/// Basic-authenticated operations.
pub(crate) struct CompiledBasicSourceCredentialProvider {
    credentials: BTreeMap<CredentialKey, StoredBasicCredential>,
    operation_bindings: BTreeMap<OperationBindingKey, CredentialKey>,
}

impl CompiledBasicSourceCredentialProvider {
    /// Validate exact registry/config closure before reading any environment
    /// value, then load and pre-encode every credential once.
    pub(crate) fn compile(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        let entries = config.entries();
        validate_catalog_structure(entries)?;
        let requirements = compile_registry_requirements(registry)?;
        validate_catalog_closure(entries, &requirements)?;

        let mut credentials = BTreeMap::new();
        for entry in entries {
            let (username_env, password_env) = entry.environment_names();
            let username = read_environment_bytes(username_env.as_str())?;
            let password = read_environment_bytes(password_env.as_str())?;
            let encoded_payload = encode_basic_payload(username, password)?;
            if credentials.values().any(|stored: &StoredBasicCredential| {
                stored.encoded_payload.as_slice() == encoded_payload.as_slice()
            }) {
                return Err(SourceCredentialProviderError::DuplicateCredentialMaterial);
            }
            let key = CredentialKey::new(entry.reference().as_str(), entry.generation());
            credentials.insert(key, StoredBasicCredential { encoded_payload });
        }

        let mut operation_bindings = BTreeMap::new();
        for (reference, requirement) in requirements {
            let credential = CredentialKey::new(&reference, requirement.generation);
            for operation in requirement.operations {
                operation_bindings.insert(operation, credential.clone());
            }
        }
        let provider = Self {
            credentials,
            operation_bindings,
        };
        provider.validate_compiled_operation_bounds(registry)?;
        Ok(provider)
    }

    /// Mint a one-shot Basic authorization capability for one exact compiled
    /// plan operation.
    pub(crate) fn authorization_for<'operation>(
        &self,
        plan: &'operation CompiledSourcePlan,
        operation: &'operation CompiledOperation,
    ) -> Result<BasicAuthorizationCapability<'operation>, SourceCredentialProviderError> {
        if operation.auth() != CompiledSourceAuth::Basic
            || !plan
                .operations()
                .any(|candidate| std::ptr::eq(candidate, operation))
        {
            return Err(SourceCredentialProviderError::OperationBindingMismatch);
        }
        let binding = OperationBindingKey::from_plan_operation(plan, operation);
        let credential_key = self
            .operation_bindings
            .get(&binding)
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;
        let credential = self
            .credentials
            .get(credential_key)
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;

        let mut encoded_payload =
            Zeroizing::new(Vec::with_capacity(credential.encoded_payload.len()));
        encoded_payload.extend_from_slice(credential.encoded_payload.as_slice());
        let authorization = DestinationAuthorizationValue::basic_zeroizing(encoded_payload)
            .map_err(|_| SourceCredentialProviderError::BasicEncodingFailed)?;
        Ok(BasicAuthorizationCapability {
            operation,
            authorization,
        })
    }

    fn validate_compiled_operation_bounds(
        &self,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<(), SourceCredentialProviderError> {
        for plan in registry.iter() {
            for operation in plan
                .operations()
                .filter(|operation| operation.auth() == CompiledSourceAuth::Basic)
            {
                let capability = self.authorization_for(plan, operation)?;
                let empty_query_values = vec![""; operation.query().len()];
                capability
                    .render(&empty_query_values)
                    .map_err(|_| SourceCredentialProviderError::BasicMaterialTooLarge)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CompiledBasicSourceCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledBasicSourceCredentialProvider")
            .field("credential_count", &self.credentials.len())
            .field("operation_binding_count", &self.operation_bindings.len())
            .field("credential_material", &"<redacted>")
            .finish()
    }
}

/// One exact compiled operation paired with one consumable authorization.
///
/// The capability cannot be cloned or serialized. Authorization can only be
/// injected by rendering through its retained operation template. Executor
/// plumbing never receives a standalone authorization value.
pub(crate) struct BasicAuthorizationCapability<'operation> {
    operation: &'operation CompiledOperation,
    authorization: DestinationAuthorizationValue,
}

impl<'operation> BasicAuthorizationCapability<'operation> {
    /// Consume the authorization while rendering its exact compiled request.
    ///
    /// V1 Basic operations are reviewed GETs with compiled query expressions,
    /// no dynamic headers, and no body. Supporting another shape requires an
    /// explicit compiler/provider decision rather than a generic escape hatch.
    pub(crate) fn render(
        self,
        query_values: &[&str],
    ) -> Result<DataDestinationRequest, DestinationRequestError> {
        self.operation.transport_template().render(
            query_values,
            &[],
            Some(self.authorization),
            None,
        )
    }
}

impl fmt::Debug for BasicAuthorizationCapability<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BasicAuthorizationCapability(<operation-bound, redacted>)")
    }
}

fn validate_catalog_structure(
    entries: &[ConsultationSourceCredentialConfig],
) -> Result<(), SourceCredentialProviderError> {
    if entries.len() > MAX_CONSULTATION_SOURCE_CREDENTIALS {
        return Err(SourceCredentialProviderError::CatalogOutOfBounds);
    }
    let mut references = BTreeSet::new();
    let mut environment_names = BTreeSet::new();
    for entry in entries {
        if entry.generation() == 0 || entry.generation() > 9_007_199_254_740_991 {
            return Err(SourceCredentialProviderError::InvalidGeneration);
        }
        if !references.insert(entry.reference().as_str()) {
            return Err(SourceCredentialProviderError::DuplicateCredentialReference);
        }
        let (username_env, password_env) = entry.environment_names();
        if !environment_names.insert(username_env.as_str())
            || !environment_names.insert(password_env.as_str())
        {
            return Err(SourceCredentialProviderError::DuplicateEnvironmentReference);
        }
    }
    Ok(())
}

fn compile_registry_requirements(
    registry: &CompiledSourcePlanRegistry,
) -> Result<BTreeMap<Box<str>, CredentialRequirement>, SourceCredentialProviderError> {
    let mut requirements: BTreeMap<Box<str>, CredentialRequirement> = BTreeMap::new();
    for plan in registry.iter() {
        let basic_operations = plan
            .operations()
            .filter(|operation| operation.auth() == CompiledSourceAuth::Basic)
            .collect::<Vec<_>>();
        // This provider closes only the Basic-owned subset. Plans without a
        // Basic operation belong to another closed provider and must coexist
        // in the same compiled consultation registry without being claimed or
        // causing their environment material to be read here.
        if basic_operations.is_empty() {
            continue;
        }
        if basic_operations.iter().any(|operation| {
            operation.method() != ReadMethod::Get
                || operation.headers().len() != 0
                || operation.body().is_some()
                || operation.request_codec() != CompiledRequestCodec::None
                || operation.request_signer().is_some()
        }) {
            return Err(SourceCredentialProviderError::BasicOperationShapeMismatch);
        }
        if plan.operations().any(|operation| {
            matches!(
                operation.auth(),
                CompiledSourceAuth::StaticBearer | CompiledSourceAuth::OAuthClientCredentials
            )
        }) {
            return Err(SourceCredentialProviderError::AuthenticationKindMismatch);
        }
        let Some((reference, generation)) = plan.credential_reference() else {
            return Err(SourceCredentialProviderError::AuthenticationKindMismatch);
        };

        let requirement =
            requirements
                .entry(reference.into())
                .or_insert_with(|| CredentialRequirement {
                    generation,
                    operations: Vec::new(),
                });
        if requirement.generation != generation {
            return Err(SourceCredentialProviderError::CredentialGenerationMismatch);
        }
        requirement.operations.extend(
            basic_operations
                .into_iter()
                .map(|operation| OperationBindingKey::from_plan_operation(plan, operation)),
        );
    }
    Ok(requirements)
}

fn validate_catalog_closure(
    entries: &[ConsultationSourceCredentialConfig],
    requirements: &BTreeMap<Box<str>, CredentialRequirement>,
) -> Result<(), SourceCredentialProviderError> {
    for entry in entries {
        let Some(requirement) = requirements.get(entry.reference().as_str()) else {
            return Err(SourceCredentialProviderError::ExtraCredential);
        };
        if requirement.generation != entry.generation() {
            return Err(SourceCredentialProviderError::CredentialGenerationMismatch);
        }
    }
    if requirements.keys().any(|reference| {
        !entries
            .iter()
            .any(|entry| entry.reference().as_str() == &**reference)
    }) {
        return Err(SourceCredentialProviderError::MissingCredential);
    }
    Ok(())
}

fn read_environment_bytes(name: &str) -> Result<Zeroizing<Vec<u8>>, SourceCredentialProviderError> {
    let value =
        std::env::var_os(name).ok_or(SourceCredentialProviderError::EnvironmentLoadFailed)?;

    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStringExt as _;
        Zeroizing::new(value.into_vec())
    };
    #[cfg(not(unix))]
    let bytes = Zeroizing::new(
        value
            .into_string()
            .map_err(|_| SourceCredentialProviderError::EnvironmentLoadFailed)?
            .into_bytes(),
    );

    std::str::from_utf8(bytes.as_slice())
        .map_err(|_| SourceCredentialProviderError::EnvironmentLoadFailed)?;
    Ok(bytes)
}

fn encode_basic_payload(
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, SourceCredentialProviderError> {
    if username.is_empty()
        || password.is_empty()
        || username.contains(&b':')
        || contains_control(&username)
        || contains_control(&password)
    {
        return Err(SourceCredentialProviderError::InvalidBasicMaterial);
    }
    if username.len() > MAX_BASIC_COMPONENT_BYTES || password.len() > MAX_BASIC_COMPONENT_BYTES {
        return Err(SourceCredentialProviderError::BasicMaterialTooLarge);
    }

    let raw_len = username
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(password.len()))
        .ok_or(SourceCredentialProviderError::BasicMaterialTooLarge)?;
    let encoded_len = raw_len
        .checked_add(2)
        .map(|length| length / 3 * 4)
        .ok_or(SourceCredentialProviderError::BasicMaterialTooLarge)?;
    if encoded_len
        .checked_add(BASIC_SCHEME_PREFIX_BYTES)
        .is_none_or(|length| length > MAX_DESTINATION_HEADER_VALUE_BYTES)
    {
        return Err(SourceCredentialProviderError::BasicMaterialTooLarge);
    }

    let mut raw = Zeroizing::new(Vec::with_capacity(raw_len));
    raw.extend_from_slice(username.as_slice());
    raw.push(b':');
    raw.extend_from_slice(password.as_slice());
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_len]);
    let written = STANDARD
        .encode_slice(raw.as_slice(), encoded.as_mut_slice())
        .map_err(|_| SourceCredentialProviderError::BasicEncodingFailed)?;
    if written != encoded_len {
        return Err(SourceCredentialProviderError::BasicEncodingFailed);
    }
    Ok(encoded)
}

fn contains_control(value: &[u8]) -> bool {
    std::str::from_utf8(value)
        .map(|value| value.chars().any(char::is_control))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
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
        include_bytes!("../../tests/fixtures/source-plan-v1/integration-pack.json");
    const OAUTH_CONTRACT: &[u8] =
        include_bytes!("../../tests/fixtures/source-plan-v1/public-contract.json");
    const OAUTH_BINDING: &[u8] =
        include_bytes!("../../tests/fixtures/source-plan-v1/private-binding.json");
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
            &SourcePlanArtifactBundle::new(&contracts, &packs, binding_bytes)
                .with_evidence(&evidence),
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
        let oauth_only =
            CompiledBasicSourceCredentialProvider::compile(&missing, &oauth_registry())
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
            CompiledBasicSourceCredentialProvider::compile(&zero_generation, &registry)
                .unwrap_err(),
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
            CompiledBasicSourceCredentialProvider::compile(
                &catalog_from_yaml(&over_bound),
                &registry,
            )
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
}
