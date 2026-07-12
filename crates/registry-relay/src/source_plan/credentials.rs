// SPDX-License-Identifier: Apache-2.0
//! Closed, restart-only source credentials for compiled consultations.

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

use super::compiler::CompiledApiKeyPlacement;
use super::compiler::CompiledCredentialOperation;
use super::registry::CompiledConsultationRegistry;
use super::{
    CompiledOperation, CompiledSourceAuth, CompiledSourcePlan, CompiledSourcePlanRegistry,
};

const MAX_BASIC_COMPONENT_BYTES: usize = 4 * 1024;
const BASIC_SCHEME_PREFIX_BYTES: usize = b"Basic ".len();

/// Validate exact config-to-plan credential closure without reading sources.
pub(crate) fn validate_source_credential_catalog(
    config: &ConsultationSourceCredentialCatalogConfig,
    registry: &CompiledConsultationRegistry,
) -> Result<(), SourceCredentialProviderError> {
    validate_source_credential_catalog_for_plans(config, registry.source_plans_for_credentials())
}

fn validate_source_credential_catalog_for_plans(
    config: &ConsultationSourceCredentialCatalogConfig,
    plans: &CompiledSourcePlanRegistry,
) -> Result<(), SourceCredentialProviderError> {
    let entries = config.entries();
    validate_catalog_structure(entries)?;
    let basic = compile_registry_requirements(plans)?;
    let bearer = compile_static_bearer_registry_requirements(plans)?;
    let api_header =
        compile_api_key_registry_requirements(plans, CompiledSourceAuth::ApiKeyHeader)?;
    let api_query = compile_api_key_registry_requirements(plans, CompiledSourceAuth::ApiKeyQuery)?;
    let oauth = compile_oauth_registry_requirements(plans)?;
    validate_catalog_closure(
        &entries
            .iter()
            .filter(|entry| entry.is_basic())
            .collect::<Vec<_>>(),
        &basic,
    )?;
    validate_catalog_closure(
        &entries
            .iter()
            .filter(|entry| entry.is_static_bearer())
            .collect::<Vec<_>>(),
        &bearer,
    )?;
    validate_catalog_closure(
        &entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    ConsultationSourceCredentialConfig::ApiKeyHeader { .. }
                )
            })
            .collect::<Vec<_>>(),
        &api_header,
    )?;
    validate_catalog_closure(
        &entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    ConsultationSourceCredentialConfig::ApiKeyQuery { .. }
                )
            })
            .collect::<Vec<_>>(),
        &api_query,
    )?;
    validate_catalog_closure(
        &entries
            .iter()
            .filter(|entry| entry.is_oauth_client_credentials())
            .collect::<Vec<_>>(),
        &oauth,
    )
}

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
    #[error("compiled OAuth operation is outside the closed client-credentials shape")]
    OAuthOperationShapeMismatch,
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
        Self::from_plan_operation_id(plan, operation.id())
    }

    fn from_plan_operation_id(plan: &CompiledSourcePlan, operation_id: &OperationId) -> Self {
        Self {
            profile_id: plan.profile().id().clone(),
            profile_version: plan.profile().version(),
            profile_contract_hash: plan.profile().contract_hash().clone(),
            integration_pack_hash: plan.integration_pack().hash().clone(),
            private_binding_hash: plan.binding_hash().into(),
            operation_id: operation_id.clone(),
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

struct StoredOAuthClientCredential {
    client_id: Zeroizing<Vec<u8>>,
    client_secret: Zeroizing<Vec<u8>>,
}

struct StoredStaticBearerCredential {
    token: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for StoredOAuthClientCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredOAuthClientCredential(<redacted>)")
    }
}

impl fmt::Debug for StoredBasicCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredBasicCredential(<redacted>)")
    }
}

impl fmt::Debug for StoredStaticBearerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredStaticBearerCredential(<redacted>)")
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
    /// Compile the Basic credential subset for one exact consultation
    /// activation. Raw source-plan registry access stays inside this module.
    pub(crate) fn compile_for_consultations(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledConsultationRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        Self::compile(config, registry.source_plans_for_credentials())
    }

    /// Validate exact registry/config closure before reading any environment
    /// value, then load and pre-encode every credential once.
    fn compile(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        let entries = config.entries();
        validate_catalog_structure(entries)?;
        let requirements = compile_registry_requirements(registry)?;
        let basic_entries = entries
            .iter()
            .filter(|entry| entry.is_basic())
            .collect::<Vec<_>>();
        validate_catalog_closure(&basic_entries, &requirements)?;

        let mut credentials = BTreeMap::new();
        for entry in basic_entries {
            let ConsultationSourceCredentialConfig::Basic {
                username_env,
                password_env,
                ..
            } = entry
            else {
                return Err(SourceCredentialProviderError::AuthenticationKindMismatch);
            };
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
                let empty_header_values = vec![b"".as_slice(); operation.headers().len()];
                capability
                    .render(None, &empty_query_values, &empty_header_values, None)
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

/// Immutable static-bearer closure bound to exact compiled operations.
pub(crate) struct CompiledStaticBearerSourceCredentialProvider {
    credentials: BTreeMap<CredentialKey, StoredStaticBearerCredential>,
    operation_bindings: BTreeMap<OperationBindingKey, CredentialKey>,
}

impl CompiledStaticBearerSourceCredentialProvider {
    pub(crate) fn compile_for_consultations(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledConsultationRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        Self::compile(config, registry.source_plans_for_credentials())
    }

    fn compile(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        let entries = config.entries();
        validate_catalog_structure(entries)?;
        let requirements = compile_static_bearer_registry_requirements(registry)?;
        let header_requirements =
            compile_api_key_registry_requirements(registry, CompiledSourceAuth::ApiKeyHeader)?;
        let query_requirements =
            compile_api_key_registry_requirements(registry, CompiledSourceAuth::ApiKeyQuery)?;
        let bearer_entries = entries
            .iter()
            .filter(|entry| entry.is_static_bearer())
            .collect::<Vec<_>>();
        validate_catalog_closure(&bearer_entries, &requirements)?;
        let header_entries = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    ConsultationSourceCredentialConfig::ApiKeyHeader { .. }
                )
            })
            .collect::<Vec<_>>();
        let query_entries = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry,
                    ConsultationSourceCredentialConfig::ApiKeyQuery { .. }
                )
            })
            .collect::<Vec<_>>();
        validate_catalog_closure(&header_entries, &header_requirements)?;
        validate_catalog_closure(&query_entries, &query_requirements)?;

        let mut credentials = BTreeMap::new();
        for entry in bearer_entries {
            let ConsultationSourceCredentialConfig::StaticBearer { token_env, .. } = entry else {
                return Err(SourceCredentialProviderError::AuthenticationKindMismatch);
            };
            let token = read_environment_bytes(token_env.as_str())?;
            if token.is_empty()
                || token.len() > MAX_DESTINATION_HEADER_VALUE_BYTES.saturating_sub(7)
                || contains_control(token.as_slice())
            {
                return Err(SourceCredentialProviderError::EnvironmentLoadFailed);
            }
            if credentials
                .values()
                .any(|stored: &StoredStaticBearerCredential| stored.token == token)
            {
                return Err(SourceCredentialProviderError::DuplicateCredentialMaterial);
            }
            credentials.insert(
                CredentialKey::new(entry.reference().as_str(), entry.generation()),
                StoredStaticBearerCredential { token },
            );
        }
        for entry in header_entries.into_iter().chain(query_entries) {
            let value_env = match entry {
                ConsultationSourceCredentialConfig::ApiKeyHeader { value_env, .. }
                | ConsultationSourceCredentialConfig::ApiKeyQuery { value_env, .. } => value_env,
                _ => return Err(SourceCredentialProviderError::AuthenticationKindMismatch),
            };
            let token = read_environment_bytes(value_env.as_str())?;
            if token.is_empty()
                || token.len() > MAX_DESTINATION_HEADER_VALUE_BYTES
                || contains_control(token.as_slice())
            {
                return Err(SourceCredentialProviderError::EnvironmentLoadFailed);
            }
            if credentials
                .values()
                .any(|stored: &StoredStaticBearerCredential| stored.token == token)
            {
                return Err(SourceCredentialProviderError::DuplicateCredentialMaterial);
            }
            credentials.insert(
                CredentialKey::new(entry.reference().as_str(), entry.generation()),
                StoredStaticBearerCredential { token },
            );
        }
        let mut operation_bindings = BTreeMap::new();
        for (reference, requirement) in requirements {
            let credential = CredentialKey::new(&reference, requirement.generation);
            for operation in requirement.operations {
                operation_bindings.insert(operation, credential.clone());
            }
        }
        for (reference, requirement) in header_requirements.into_iter().chain(query_requirements) {
            let credential = CredentialKey::new(&reference, requirement.generation);
            for operation in requirement.operations {
                operation_bindings.insert(operation, credential.clone());
            }
        }
        Ok(Self {
            credentials,
            operation_bindings,
        })
    }

    pub(crate) fn authorization_for<'operation>(
        &self,
        plan: &'operation CompiledSourcePlan,
        operation: &'operation CompiledOperation,
    ) -> Result<StaticBearerAuthorizationCapability<'operation>, SourceCredentialProviderError>
    {
        if operation.auth() != CompiledSourceAuth::StaticBearer
            || !plan
                .operations()
                .any(|candidate| std::ptr::eq(candidate, operation))
        {
            return Err(SourceCredentialProviderError::OperationBindingMismatch);
        }
        let key = self
            .operation_bindings
            .get(&OperationBindingKey::from_plan_operation(plan, operation))
            .and_then(|key| self.credentials.get(key))
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;
        let authorization = DestinationAuthorizationValue::bearer(key.token.to_vec())
            .map_err(|_| SourceCredentialProviderError::OperationBindingMismatch)?;
        Ok(StaticBearerAuthorizationCapability {
            operation,
            authorization,
        })
    }

    pub(crate) fn api_key_for<'operation>(
        &self,
        plan: &'operation CompiledSourcePlan,
        operation: &'operation CompiledOperation,
    ) -> Result<ApiKeyCapability<'operation>, SourceCredentialProviderError> {
        if !matches!(
            operation.auth(),
            CompiledSourceAuth::ApiKeyHeader | CompiledSourceAuth::ApiKeyQuery
        ) || !plan
            .operations()
            .any(|candidate| std::ptr::eq(candidate, operation))
        {
            return Err(SourceCredentialProviderError::OperationBindingMismatch);
        }
        let key = self
            .operation_bindings
            .get(&OperationBindingKey::from_plan_operation(plan, operation))
            .and_then(|key| self.credentials.get(key))
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;
        let mut value = Zeroizing::new(Vec::with_capacity(key.token.len()));
        value.extend_from_slice(&key.token);
        Ok(ApiKeyCapability { operation, value })
    }
}

impl fmt::Debug for CompiledStaticBearerSourceCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledStaticBearerSourceCredentialProvider")
            .field("credential_count", &self.credentials.len())
            .field("operation_binding_count", &self.operation_bindings.len())
            .field("credential_material", &"<redacted>")
            .finish()
    }
}

/// Restart-only OAuth client credentials closed over exact compiled operations.
///
/// Raw client identifiers and secrets remain in zeroizing memory. The provider
/// is not cloneable or serializable and can mint only an operation-bound,
/// consuming credential-request capability.
pub(crate) struct CompiledOAuthSourceCredentialProvider {
    credentials: BTreeMap<CredentialKey, StoredOAuthClientCredential>,
    operation_bindings: BTreeMap<OperationBindingKey, CredentialKey>,
}

impl CompiledOAuthSourceCredentialProvider {
    pub(crate) fn compile_for_consultations(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledConsultationRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        Self::compile(config, registry.source_plans_for_credentials())
    }

    fn compile(
        config: &ConsultationSourceCredentialCatalogConfig,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<Self, SourceCredentialProviderError> {
        let entries = config.entries();
        validate_catalog_structure(entries)?;
        let requirements = compile_oauth_registry_requirements(registry)?;
        let oauth_entries = entries
            .iter()
            .filter(|entry| entry.is_oauth_client_credentials())
            .collect::<Vec<_>>();
        validate_catalog_closure(&oauth_entries, &requirements)?;
        validate_global_credential_material(entries)?;

        let mut credentials = BTreeMap::new();
        for entry in oauth_entries {
            let ConsultationSourceCredentialConfig::OAuthClientCredentials {
                client_id_env,
                client_secret_env,
                ..
            } = entry
            else {
                return Err(SourceCredentialProviderError::AuthenticationKindMismatch);
            };
            let client_id = read_environment_bytes(client_id_env.as_str())?;
            let client_secret = read_environment_bytes(client_secret_env.as_str())?;
            if client_id.is_empty()
                || client_secret.is_empty()
                || contains_control(client_id.as_slice())
                || contains_control(client_secret.as_slice())
            {
                return Err(SourceCredentialProviderError::EnvironmentLoadFailed);
            }
            if credentials
                .values()
                .any(|stored: &StoredOAuthClientCredential| {
                    stored.client_id.as_slice() == client_id.as_slice()
                        && stored.client_secret.as_slice() == client_secret.as_slice()
                })
            {
                return Err(SourceCredentialProviderError::DuplicateCredentialMaterial);
            }
            credentials.insert(
                CredentialKey::new(entry.reference().as_str(), entry.generation()),
                StoredOAuthClientCredential {
                    client_id,
                    client_secret,
                },
            );
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

    pub(crate) fn credentials_for<'operation>(
        &self,
        plan: &'operation CompiledSourcePlan,
        operation: &'operation CompiledCredentialOperation,
    ) -> Result<OAuthClientCredentialsCapability<'operation>, SourceCredentialProviderError> {
        if plan
            .credential_operation()
            .is_none_or(|candidate| !std::ptr::eq(candidate, operation))
        {
            return Err(SourceCredentialProviderError::OperationBindingMismatch);
        }
        let binding = OperationBindingKey::from_plan_operation_id(plan, operation.id());
        let credential_key = self
            .operation_bindings
            .get(&binding)
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;
        let credential = self
            .credentials
            .get(credential_key)
            .ok_or(SourceCredentialProviderError::OperationBindingMismatch)?;
        Ok(OAuthClientCredentialsCapability {
            operation,
            client_id: Zeroizing::new(credential.client_id.to_vec()),
            client_secret: Zeroizing::new(credential.client_secret.to_vec()),
        })
    }

    fn validate_compiled_operation_bounds(
        &self,
        registry: &CompiledSourcePlanRegistry,
    ) -> Result<(), SourceCredentialProviderError> {
        for plan in registry.iter() {
            if let Some(operation) = plan.credential_operation() {
                self.credentials_for(plan, operation)?
                    .render()
                    .map_err(|_| SourceCredentialProviderError::OAuthOperationShapeMismatch)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CompiledOAuthSourceCredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledOAuthSourceCredentialProvider")
            .field("credential_count", &self.credentials.len())
            .field("operation_binding_count", &self.operation_bindings.len())
            .field("credential_material", &"<redacted>")
            .finish()
    }
}

pub(crate) struct OAuthClientCredentialsCapability<'operation> {
    operation: &'operation CompiledCredentialOperation,
    client_id: Zeroizing<Vec<u8>>,
    client_secret: Zeroizing<Vec<u8>>,
}

impl OAuthClientCredentialsCapability<'_> {
    pub(crate) fn render(
        self,
    ) -> Result<
        registry_platform_httputil::destination::CredentialDestinationRequest,
        super::compiler::CredentialOperationFailure,
    > {
        self.operation
            .render_request(self.client_id, self.client_secret)
    }
}

impl fmt::Debug for OAuthClientCredentialsCapability<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OAuthClientCredentialsCapability(<operation-bound, redacted>)")
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

pub(crate) struct StaticBearerAuthorizationCapability<'operation> {
    operation: &'operation CompiledOperation,
    authorization: DestinationAuthorizationValue,
}

pub(crate) struct ApiKeyCapability<'operation> {
    operation: &'operation CompiledOperation,
    value: Zeroizing<Vec<u8>>,
}

impl<'operation> BasicAuthorizationCapability<'operation> {
    /// Consume the authorization while rendering its exact compiled request.
    ///
    /// V1 Basic operations are reviewed GETs with compiled query expressions,
    /// no dynamic headers, and no body. Supporting another shape requires an
    /// explicit compiler/provider decision rather than a generic escape hatch.
    pub(crate) fn render(
        self,
        path_segment: Option<&str>,
        query_values: &[&str],
        header_values: &[&[u8]],
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<DataDestinationRequest, DestinationRequestError> {
        match path_segment {
            Some(path_segment) => self
                .operation
                .transport_template()
                .render_zeroizing_with_path_segment(
                    path_segment,
                    query_values,
                    header_values,
                    Some(self.authorization),
                    body,
                ),
            None => self.operation.transport_template().render_zeroizing(
                query_values,
                header_values,
                Some(self.authorization),
                body,
            ),
        }
    }
}

impl fmt::Debug for BasicAuthorizationCapability<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BasicAuthorizationCapability(<operation-bound, redacted>)")
    }
}

impl StaticBearerAuthorizationCapability<'_> {
    pub(crate) fn render(
        self,
        path_segment: Option<&str>,
        query_values: &[&str],
        header_values: &[&[u8]],
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<DataDestinationRequest, DestinationRequestError> {
        match path_segment {
            Some(path_segment) => self
                .operation
                .transport_template()
                .render_zeroizing_with_path_segment(
                    path_segment,
                    query_values,
                    header_values,
                    Some(self.authorization),
                    body,
                ),
            None => self.operation.transport_template().render_zeroizing(
                query_values,
                header_values,
                Some(self.authorization),
                body,
            ),
        }
    }
}

impl fmt::Debug for StaticBearerAuthorizationCapability<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticBearerAuthorizationCapability(<operation-bound, redacted>)")
    }
}

impl ApiKeyCapability<'_> {
    pub(crate) fn render(
        self,
        path_segment: Option<&str>,
        query_values: &[&str],
        header_values: &[&[u8]],
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<DataDestinationRequest, DestinationRequestError> {
        let mut query_values = query_values.to_vec();
        let mut header_values = header_values.to_vec();
        match self
            .operation
            .api_key()
            .ok_or(DestinationRequestError::InvalidTarget)?
        {
            CompiledApiKeyPlacement::Header { .. } => header_values.push(self.value.as_slice()),
            CompiledApiKeyPlacement::Query { .. } => query_values.push(
                std::str::from_utf8(self.value.as_slice())
                    .map_err(|_| DestinationRequestError::InvalidTarget)?,
            ),
        }
        match path_segment {
            Some(path_segment) => self
                .operation
                .transport_template()
                .render_zeroizing_with_path_segment(
                    path_segment,
                    &query_values,
                    &header_values,
                    None,
                    body,
                ),
            None => self.operation.transport_template().render_zeroizing(
                &query_values,
                &header_values,
                None,
                body,
            ),
        }
    }
}

impl fmt::Debug for ApiKeyCapability<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyCapability(<operation-bound, redacted>)")
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
        if entry
            .environment_names()
            .into_iter()
            .any(|environment_name| !environment_names.insert(environment_name.as_str()))
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

fn compile_static_bearer_registry_requirements(
    registry: &CompiledSourcePlanRegistry,
) -> Result<BTreeMap<Box<str>, CredentialRequirement>, SourceCredentialProviderError> {
    let mut requirements: BTreeMap<Box<str>, CredentialRequirement> = BTreeMap::new();
    for plan in registry.iter() {
        let operations = plan
            .operations()
            .filter(|operation| operation.auth() == CompiledSourceAuth::StaticBearer)
            .collect::<Vec<_>>();
        if operations.is_empty() {
            continue;
        }
        if plan.operations().any(|operation| {
            matches!(
                operation.auth(),
                CompiledSourceAuth::Basic | CompiledSourceAuth::OAuthClientCredentials
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
            operations
                .into_iter()
                .map(|operation| OperationBindingKey::from_plan_operation(plan, operation)),
        );
    }
    Ok(requirements)
}

fn compile_api_key_registry_requirements(
    registry: &CompiledSourcePlanRegistry,
    auth: CompiledSourceAuth,
) -> Result<BTreeMap<Box<str>, CredentialRequirement>, SourceCredentialProviderError> {
    let mut requirements: BTreeMap<Box<str>, CredentialRequirement> = BTreeMap::new();
    for plan in registry.iter() {
        let operations = plan
            .operations()
            .filter(|operation| operation.auth() == auth)
            .collect::<Vec<_>>();
        if operations.is_empty() {
            continue;
        }
        if plan.operations().any(|operation| {
            operation.auth() != CompiledSourceAuth::None && operation.auth() != auth
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
            operations
                .into_iter()
                .map(|operation| OperationBindingKey::from_plan_operation(plan, operation)),
        );
    }
    Ok(requirements)
}

fn compile_oauth_registry_requirements(
    registry: &CompiledSourcePlanRegistry,
) -> Result<BTreeMap<Box<str>, CredentialRequirement>, SourceCredentialProviderError> {
    let mut requirements: BTreeMap<Box<str>, CredentialRequirement> = BTreeMap::new();
    for plan in registry.iter() {
        let Some(credential_operation) = plan.credential_operation() else {
            continue;
        };
        if !plan
            .operations()
            .any(|operation| operation.auth() == CompiledSourceAuth::OAuthClientCredentials)
        {
            return Err(SourceCredentialProviderError::OAuthOperationShapeMismatch);
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
        requirement
            .operations
            .push(OperationBindingKey::from_plan_operation_id(
                plan,
                credential_operation.id(),
            ));
    }
    Ok(requirements)
}

fn validate_catalog_closure(
    entries: &[&ConsultationSourceCredentialConfig],
    requirements: &BTreeMap<Box<str>, CredentialRequirement>,
) -> Result<(), SourceCredentialProviderError> {
    for &entry in entries {
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

fn validate_global_credential_material(
    entries: &[ConsultationSourceCredentialConfig],
) -> Result<(), SourceCredentialProviderError> {
    let mut material = Vec::<Vec<Zeroizing<Vec<u8>>>>::new();
    for entry in entries {
        let components = entry
            .environment_names()
            .into_iter()
            .map(|name| read_environment_bytes(name.as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        if components
            .iter()
            .any(|value| value.is_empty() || contains_control(value.as_slice()))
        {
            return Err(SourceCredentialProviderError::EnvironmentLoadFailed);
        }
        if material.iter().any(|stored| {
            stored.len() == components.len()
                && stored
                    .iter()
                    .zip(&components)
                    .all(|(left, right)| left.as_slice() == right.as_slice())
        }) {
            return Err(SourceCredentialProviderError::DuplicateCredentialMaterial);
        }
        material.push(components);
    }
    Ok(())
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
mod tests;
