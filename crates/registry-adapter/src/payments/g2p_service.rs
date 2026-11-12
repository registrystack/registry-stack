// SPDX-License-Identifier: Apache-2.0
//! G2P custody orchestration for the HTTP and Coordinator-facing operations.

use super::{
    g2p_model::{
        canonical_digest, G2pAttempt, G2pAttemptState, G2pConnectionSnapshot, G2pError,
        G2pHttpAuth, G2pProviderBinding,
    },
    g2p_registry::{bind_inputs_for, confirmation_inputs, G2pInstructionState, G2pRegistryPort},
    g2p_store::{DispatchAuthorization, G2pStore},
    pack::ProviderPackPin,
    provider_mapping::{
        MappedProviderResponse, PaymentEndpointRole, PaymentMappingError, PaymentMappingRegistry,
        PreparedProviderRequest, ProviderAcceptance, ProviderHttpResponse,
    },
};
use async_trait::async_trait;
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::BearerToken;
use registry_platform_httputil::{read_bounded, validate_response_headers, ServiceBaseUrl};
use serde::Serialize;
use serde_json::Value;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum G2pProviderError {
    /// The provider definitely refused this exact mutation. Custody still
    /// holds the first-send mark and never creates a replacement attempt.
    Rejected,
    /// The mutation may have reached the provider.
    OutcomeUnknown,
    /// A read-only provider operation could not complete.
    Unavailable,
}

/// Fully built mutation held in memory between local preflight and the one
/// durable dispatch grant. Polling this future performs the first network I/O;
/// no credential, URL, header or request construction remains afterward.
pub struct PreparedG2pSend {
    send: Pin<Box<dyn Future<Output = Result<ProviderHttpResponse, G2pProviderError>> + Send>>,
}

impl PreparedG2pSend {
    pub fn new(
        send: impl Future<Output = Result<ProviderHttpResponse, G2pProviderError>> + Send + 'static,
    ) -> Self {
        Self {
            send: Box::pin(send),
        }
    }

    pub async fn send(self) -> Result<ProviderHttpResponse, G2pProviderError> {
        self.send.await
    }
}

/// Provider seam used by custody. Recovery is read-only and keyed by the
/// retained correlation; it must never submit or replay the batch command.
#[async_trait]
pub trait G2pProviderPort: Send + Sync {
    async fn preflight_submit(
        &self,
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<PreparedG2pSend, G2pProviderError>;

    async fn recover_acceptance(
        &self,
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<Option<ProviderAcceptance>, G2pProviderError>;

    async fn observe(
        &self,
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<ProviderHttpResponse, G2pProviderError>;
}

pub trait G2pMappingPort: Send + Sync {
    fn ensure_available(&self, pin: &ProviderPackPin) -> Result<(), PaymentMappingError>;
    fn prepare(
        &self,
        pin: &ProviderPackPin,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
    ) -> Result<PreparedProviderRequest, PaymentMappingError>;
    fn interpret(
        &self,
        pin: &ProviderPackPin,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
        response: &ProviderHttpResponse,
    ) -> Result<MappedProviderResponse, PaymentMappingError>;
}

impl G2pMappingPort for PaymentMappingRegistry {
    fn ensure_available(&self, pin: &ProviderPackPin) -> Result<(), PaymentMappingError> {
        self.select(pin).map(|_| ())
    }

    fn prepare(
        &self,
        pin: &ProviderPackPin,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
    ) -> Result<PreparedProviderRequest, PaymentMappingError> {
        self.select(pin)?
            .prepare(role, intent, settings, acceptance)
    }

    fn interpret(
        &self,
        pin: &ProviderPackPin,
        role: PaymentEndpointRole,
        intent: &Value,
        settings: &Value,
        acceptance: Option<&ProviderAcceptance>,
        response: &ProviderHttpResponse,
    ) -> Result<MappedProviderResponse, PaymentMappingError> {
        self.select(pin)?
            .interpret(role, intent, settings, acceptance, response)
    }
}

/// Provider-neutral HTTP host. Bearer requests send only the exact retained
/// request plan. The Mifos legacy signature remains fail closed until its
/// signer and response verifier are integrated into this boundary.
pub struct HttpG2pProvider {
    resolver: Arc<SecretResolver>,
}

impl HttpG2pProvider {
    pub fn new(resolver: Arc<SecretResolver>) -> Self {
        Self { resolver }
    }

    fn bearer_token(&self, binding: &G2pProviderBinding) -> Result<BearerToken, G2pProviderError> {
        let secret = self
            .resolver
            .resolve(binding.credential_ref().as_str())
            .map_err(|_| G2pProviderError::Unavailable)?;
        let token = std::str::from_utf8(secret.expose_secret())
            .map_err(|_| G2pProviderError::Unavailable)?;
        match binding.auth() {
            G2pHttpAuth::Bearer => {
                BearerToken::new(token.to_owned()).map_err(|_| G2pProviderError::Unavailable)
            }
            G2pHttpAuth::MifosLegacySignature { .. } => Err(G2pProviderError::Unavailable),
        }
    }

    fn prepare_url(
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<url::Url, G2pProviderError> {
        request
            .validate_restored(request.role, &request.provider_pack)
            .map_err(|_| G2pProviderError::Unavailable)?;
        let base = ServiceBaseUrl::new(
            url::Url::parse(
                binding
                    .base_url(request.role)
                    .map_err(|_| G2pProviderError::Unavailable)?,
            )
            .map_err(|_| G2pProviderError::Unavailable)?,
        )
        .map_err(|_| G2pProviderError::Unavailable)?;
        let path = request
            .path
            .strip_prefix('/')
            .ok_or(G2pProviderError::Unavailable)?;
        let mut url = base.join(path).map_err(|_| G2pProviderError::Unavailable)?;
        url.query_pairs_mut().extend_pairs(&request.query);
        Ok(url)
    }

    async fn send_prepared(
        &self,
        binding: &G2pProviderBinding,
        prepared: &PreparedProviderRequest,
    ) -> Result<ProviderHttpResponse, G2pProviderError> {
        binding
            .validate()
            .map_err(|_| G2pProviderError::Unavailable)?;
        let url = Self::prepare_url(binding, prepared)?;
        let token = self.bearer_token(binding)?;
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: Duration::from_secs(15),
                connect_timeout: Duration::from_secs(5),
                user_agent: Some("registry-adapter-payment-http/v1"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|_| G2pProviderError::Unavailable)?;
        let mut request = match prepared.method {
            super::provider_mapping::PaymentHttpMethod::Post => client.post(url),
            super::provider_mapping::PaymentHttpMethod::Get => client.get(url),
        };
        for (name, value) in &prepared.headers {
            request = request.header(name, value);
        }
        request = request.header(
            http::header::AUTHORIZATION,
            token.authorization_header_value(),
        );
        if let Some(body) = &prepared.body {
            request = request
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(body.clone());
        }
        let mutation = prepared.role.is_submit();
        let response = request.send().await.map_err(|_| {
            if mutation {
                G2pProviderError::OutcomeUnknown
            } else {
                G2pProviderError::Unavailable
            }
        })?;
        validate_response_headers(response.headers()).map_err(|_| {
            if mutation {
                G2pProviderError::OutcomeUnknown
            } else {
                G2pProviderError::Unavailable
            }
        })?;
        let status = response.status().as_u16();
        let body = read_bounded(response, 131_072).await.map_err(|_| {
            if mutation {
                G2pProviderError::OutcomeUnknown
            } else {
                G2pProviderError::Unavailable
            }
        })?;
        Ok(ProviderHttpResponse { status, body })
    }
}

#[async_trait]
impl G2pProviderPort for HttpG2pProvider {
    async fn preflight_submit(
        &self,
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<PreparedG2pSend, G2pProviderError> {
        binding
            .validate()
            .map_err(|_| G2pProviderError::Unavailable)?;
        if request.role != PaymentEndpointRole::DisbursementSubmit {
            return Err(G2pProviderError::Unavailable);
        }
        let url = Self::prepare_url(binding, request)?;
        let token = self.bearer_token(binding)?;
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: Duration::from_secs(15),
                connect_timeout: Duration::from_secs(5),
                user_agent: Some("registry-adapter-payment-http/v1"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|_| G2pProviderError::Unavailable)?;
        let mut builder = client.post(url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        builder = builder.header(
            http::header::AUTHORIZATION,
            token.authorization_header_value(),
        );
        let body = request.body.as_ref().ok_or(G2pProviderError::Unavailable)?;
        let prepared = builder
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body.clone())
            .build()
            .map_err(|_| G2pProviderError::Unavailable)?;
        Ok(PreparedG2pSend::new(async move {
            let response = client
                .execute(prepared)
                .await
                .map_err(|_| G2pProviderError::OutcomeUnknown)?;
            validate_response_headers(response.headers())
                .map_err(|_| G2pProviderError::OutcomeUnknown)?;
            let status = response.status().as_u16();
            let body = read_bounded(response, 131_072)
                .await
                .map_err(|_| G2pProviderError::OutcomeUnknown)?;
            Ok(ProviderHttpResponse { status, body })
        }))
    }

    async fn recover_acceptance(
        &self,
        _binding: &G2pProviderBinding,
        _request: &PreparedProviderRequest,
    ) -> Result<Option<ProviderAcceptance>, G2pProviderError> {
        Ok(None)
    }

    async fn observe(
        &self,
        binding: &G2pProviderBinding,
        request: &PreparedProviderRequest,
    ) -> Result<ProviderHttpResponse, G2pProviderError> {
        if request.role != PaymentEndpointRole::DisbursementStatus {
            return Err(G2pProviderError::Unavailable);
        }
        self.send_prepared(binding, request).await
    }
}

pub struct G2pService {
    store: G2pStore,
    registry: Arc<dyn G2pRegistryPort>,
    provider: Arc<dyn G2pProviderPort>,
    mapping: Option<Arc<dyn G2pMappingPort>>,
}

impl G2pService {
    pub fn new(
        store: G2pStore,
        registry: Arc<dyn G2pRegistryPort>,
        provider: Arc<dyn G2pProviderPort>,
    ) -> Self {
        Self {
            store,
            registry,
            provider,
            mapping: None,
        }
    }

    pub fn with_mapping(mut self, mapping: Arc<dyn G2pMappingPort>) -> Self {
        self.mapping = Some(mapping);
        self
    }

    /// Strictly local read of a previous request's acceptance. An unresolved
    /// first send has no receipt and cannot be sent again by this endpoint.
    pub async fn request_receipt(
        &self,
        connection: &str,
        principal: &str,
        command_key: &str,
        instruction_record_id: Uuid,
        instruction_version: u64,
    ) -> Result<G2pAttempt, G2pError> {
        let digest = request_digest(instruction_record_id, instruction_version)?;
        let saved = self
            .store
            .lookup_command(connection, principal, command_key, &digest)
            .await?
            .ok_or(G2pError::NotFound)?;
        if saved.provider_acceptance.is_none() {
            return Err(G2pError::RecoveryHeld);
        }
        Ok(saved)
    }

    /// Implements `RequestDisbursement`. The caller supplies only the BReg
    /// record identity/version and its workflow command key. All payment facts
    /// come from the exact authoritative record.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_disbursement(
        &self,
        connection: &str,
        principal: &str,
        command_key: &str,
        instruction_record_id: Uuid,
        instruction_version: u64,
        binding: G2pConnectionSnapshot,
        now_unix_seconds: i64,
    ) -> Result<G2pAttempt, G2pError> {
        if connection.is_empty()
            || principal.is_empty()
            || command_key.is_empty()
            || instruction_record_id.is_nil()
            || instruction_version == 0
        {
            return Err(G2pError::InvalidRequest);
        }
        binding.validate()?;
        let source_namespace = binding.registry.source_namespace()?;
        let request_digest = request_digest(instruction_record_id, instruction_version)?;
        if let Some(saved) = self
            .store
            .find_instruction(
                principal,
                &source_namespace,
                instruction_record_id,
                instruction_version,
            )
            .await?
        {
            if saved.connection != connection {
                return Err(G2pError::Conflict);
            }
            self.store
                .claim_existing_command(&saved, command_key, &request_digest)
                .await?;
            return self
                .resume_request(saved, connection, principal, now_unix_seconds)
                .await;
        }

        let view = self
            .registry
            .read_instruction(&binding.registry, instruction_record_id)
            .await?;
        if view.instruction.instruction_version != instruction_version
            || view.state != G2pInstructionState::InstructionReady
        {
            return Err(G2pError::Conflict);
        }
        binding.validate_instruction(&view.instruction)?;

        let mapping = self.mapping.as_ref().ok_or(G2pError::Unavailable)?;
        mapping
            .ensure_available(&binding.provider_pack)
            .map_err(mapping_read_error)?;
        let provider_intent = binding.provider_intent(&view.instruction)?;
        let intent = serde_json::to_value(&provider_intent).map_err(|_| G2pError::Unavailable)?;
        let prepared_submit = mapping
            .prepare(
                &binding.provider_pack,
                PaymentEndpointRole::DisbursementSubmit,
                &intent,
                binding.provider.settings(),
                None,
            )
            .map_err(mapping_read_error)?;
        let id = Uuid::new_v4();
        let binding_revision = binding.attempt_revision(&prepared_submit)?;
        let bind_key = format!("g2p-bind-{id}");
        let inputs = bind_inputs_for(&view.instruction, id, &binding_revision)?;
        let prepared = self
            .registry
            .prepare_bind(&binding.registry, &bind_key, inputs)
            .await?;
        let candidate = G2pAttempt::new(
            id,
            connection.to_owned(),
            principal.to_owned(),
            view.instruction,
            binding,
            prepared_submit,
            prepared,
        )?;
        let saved = self
            .store
            .reserve(&candidate, command_key, &request_digest)
            .await?;
        self.resume_request(saved, connection, principal, now_unix_seconds)
            .await
    }

    /// Implements `DisbursementStatus`. It may perform provider reads and
    /// retain their exact result, but never binds or dispatches.
    pub async fn disbursement_status(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
    ) -> Result<G2pAttempt, G2pError> {
        let mut attempt = self.store.get_scoped(connection, principal, id).await?;
        if attempt.state == G2pAttemptState::DispatchStarted {
            let recovered = self
                .provider
                .recover_acceptance(&attempt.binding.provider, &attempt.prepared_submit)
                .await
                .map_err(provider_read_error)?;
            let Some(accepted) = recovered else {
                return Ok(attempt);
            };
            attempt = self
                .store
                .record_acceptance(connection, principal, id, accepted)
                .await?;
        }
        if matches!(
            attempt.state,
            G2pAttemptState::ProviderAccepted
                | G2pAttemptState::ProviderPending
                | G2pAttemptState::ProviderUnknown
        ) {
            let accepted = attempt
                .provider_acceptance
                .as_ref()
                .ok_or(G2pError::RecoveryHeld)?;
            let mapping = self.mapping.as_ref().ok_or(G2pError::Unavailable)?;
            mapping
                .ensure_available(&attempt.binding.provider_pack)
                .map_err(mapping_read_error)?;
            let intent = serde_json::to_value(&attempt.provider_intent)
                .map_err(|_| G2pError::Unavailable)?;
            let status_request = mapping
                .prepare(
                    &attempt.binding.provider_pack,
                    PaymentEndpointRole::DisbursementStatus,
                    &intent,
                    attempt.binding.provider.settings(),
                    Some(accepted),
                )
                .map_err(mapping_read_error)?;
            let response = self
                .provider
                .observe(&attempt.binding.provider, &status_request)
                .await
                .map_err(provider_read_error)?;
            let mapped = mapping
                .interpret(
                    &attempt.binding.provider_pack,
                    PaymentEndpointRole::DisbursementStatus,
                    &intent,
                    attempt.binding.provider.settings(),
                    Some(accepted),
                    &response,
                )
                .map_err(mapping_read_error)?;
            let MappedProviderResponse::Observation(observation) = mapped else {
                return Err(G2pError::Unavailable);
            };
            let observation = attempt.validate_mapped_observation(accepted, &observation)?;
            attempt = self
                .store
                .record_observation(connection, principal, id, observation)
                .await?;
        }
        Ok(attempt)
    }

    /// Implements `RecordProviderConfirmation`. Only an exact correlated
    /// `COMPLETED` observation can reach the BReg reporting Action.
    pub async fn record_provider_confirmation(
        &self,
        connection: &str,
        principal: &str,
        command_key: &str,
        id: Uuid,
    ) -> Result<G2pAttempt, G2pError> {
        if command_key.is_empty() {
            return Err(G2pError::InvalidRequest);
        }
        let request_digest = confirmation_request_digest(connection, principal, id)?;
        self.store
            .claim_confirmation_command(connection, principal, id, command_key, &request_digest)
            .await?;
        let mut attempt = self.disbursement_status(connection, principal, id).await?;
        if attempt.state == G2pAttemptState::ConfirmationRecorded {
            return Ok(attempt);
        }
        if attempt.state == G2pAttemptState::ProviderConfirmed {
            let key = format!("g2p-confirm-{id}");
            let inputs = confirmation_inputs(&attempt)?;
            let prepared = self
                .registry
                .prepare_confirmation(&attempt.binding.registry, &key, inputs)
                .await?;
            attempt = self
                .store
                .prepare_confirmation(connection, principal, id, prepared)
                .await?;
        }
        if attempt.state != G2pAttemptState::ConfirmationPrepared {
            return Err(G2pError::RecoveryHeld);
        }
        let prepared = attempt
            .confirmation_action
            .as_ref()
            .ok_or(G2pError::RecoveryHeld)?;
        let invocation = self
            .registry
            .invoke_confirmation(&attempt.binding.registry, prepared)
            .await;
        let view = self
            .registry
            .read_instruction(&attempt.binding.registry, attempt.instruction.record_id)
            .await?;
        if !view.matches_confirmation(&attempt) {
            return match invocation {
                Err(error) => Err(error),
                Ok(()) => Err(G2pError::Conflict),
            };
        }
        self.store
            .record_confirmation(connection, principal, id)
            .await
    }

    async fn resume_request(
        &self,
        mut attempt: G2pAttempt,
        connection: &str,
        principal: &str,
        now_unix_seconds: i64,
    ) -> Result<G2pAttempt, G2pError> {
        if attempt.state == G2pAttemptState::BindPrepared {
            let invocation = self
                .registry
                .invoke_bind(&attempt.binding.registry, &attempt.bind_action)
                .await;
            let view = self
                .registry
                .read_instruction(&attempt.binding.registry, attempt.instruction.record_id)
                .await?;
            if !view.matches_bound(&attempt) {
                return match invocation {
                    Err(error) => Err(error),
                    Ok(()) => Err(G2pError::Conflict),
                };
            }
            attempt = self
                .store
                .record_bound(connection, principal, attempt.id)
                .await?;
        }
        let prepared_send = if attempt.state == G2pAttemptState::Bound {
            self.mapping
                .as_ref()
                .ok_or(G2pError::Unavailable)?
                .ensure_available(&attempt.binding.provider_pack)
                .map_err(mapping_read_error)?;
            Some(
                self.provider
                    .preflight_submit(&attempt.binding.provider, &attempt.prepared_submit)
                    .await
                    .map_err(provider_read_error)?,
            )
        } else {
            None
        };
        match self
            .store
            .begin_dispatch(connection, principal, attempt.id, now_unix_seconds)
            .await?
        {
            DispatchAuthorization::Send(started) => {
                let response = prepared_send
                    .ok_or(G2pError::OutcomeUnknown)?
                    .send()
                    .await
                    .map_err(provider_mutation_error)?;
                let mapping = self.mapping.as_ref().ok_or(G2pError::OutcomeUnknown)?;
                let intent = serde_json::to_value(&started.provider_intent)
                    .map_err(|_| G2pError::OutcomeUnknown)?;
                let mapped = mapping
                    .interpret(
                        &started.binding.provider_pack,
                        PaymentEndpointRole::DisbursementSubmit,
                        &intent,
                        started.binding.provider.settings(),
                        None,
                        &response,
                    )
                    .map_err(|_| G2pError::OutcomeUnknown)?;
                let MappedProviderResponse::Acceptance(accepted) = mapped else {
                    return Err(G2pError::OutcomeUnknown);
                };
                started
                    .validate_acceptance(&accepted)
                    .map_err(|_| G2pError::OutcomeUnknown)?;
                self.store
                    .record_acceptance(connection, principal, started.id, accepted)
                    .await
            }
            DispatchAuthorization::Hold(held) => {
                if held.state != G2pAttemptState::DispatchStarted {
                    return Ok(held);
                }
                let recovered = self
                    .provider
                    .recover_acceptance(&held.binding.provider, &held.prepared_submit)
                    .await
                    .map_err(provider_read_error)?;
                match recovered {
                    Some(accepted) => {
                        self.store
                            .record_acceptance(connection, principal, held.id, accepted)
                            .await
                    }
                    None => Ok(held),
                }
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestIdentity {
    domain: &'static str,
    instruction_record_id: Uuid,
    instruction_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmationRequestIdentity<'a> {
    domain: &'static str,
    operation: &'static str,
    connection: &'a str,
    principal: &'a str,
    disbursement_id: Uuid,
}

fn request_digest(record_id: Uuid, version: u64) -> Result<String, G2pError> {
    canonical_digest(&RequestIdentity {
        domain: "registry-adapter/g2p-request/v1",
        instruction_record_id: record_id,
        instruction_version: version,
    })
}

fn confirmation_request_digest(
    connection: &str,
    principal: &str,
    disbursement_id: Uuid,
) -> Result<String, G2pError> {
    if connection.is_empty() || principal.is_empty() || disbursement_id.is_nil() {
        return Err(G2pError::InvalidRequest);
    }
    canonical_digest(&ConfirmationRequestIdentity {
        domain: "registry-adapter/g2p-command/v1",
        operation: "record-provider-confirmation",
        connection,
        principal,
        disbursement_id,
    })
}

fn provider_mutation_error(error: G2pProviderError) -> G2pError {
    match error {
        G2pProviderError::Rejected => G2pError::Conflict,
        G2pProviderError::OutcomeUnknown | G2pProviderError::Unavailable => {
            G2pError::OutcomeUnknown
        }
    }
}

fn provider_read_error(error: G2pProviderError) -> G2pError {
    match error {
        G2pProviderError::Rejected => G2pError::Conflict,
        G2pProviderError::OutcomeUnknown | G2pProviderError::Unavailable => G2pError::Unavailable,
    }
}

fn mapping_read_error(_error: PaymentMappingError) -> G2pError {
    G2pError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::confirmation_request_digest;
    use uuid::Uuid;

    #[test]
    fn confirmation_request_digest_binds_scope_and_disbursement() {
        let first = Uuid::parse_str("00000000-0000-4000-8000-000000000201").unwrap();
        let second = Uuid::parse_str("00000000-0000-4000-8000-000000000202").unwrap();
        let digest = confirmation_request_digest("g2p", "coordinator", first).unwrap();
        assert_eq!(
            digest,
            confirmation_request_digest("g2p", "coordinator", first).unwrap()
        );
        assert_ne!(
            digest,
            confirmation_request_digest("g2p-renamed", "coordinator", first).unwrap()
        );
        assert_ne!(
            digest,
            confirmation_request_digest("g2p", "another-principal", first).unwrap()
        );
        assert_ne!(
            digest,
            confirmation_request_digest("g2p", "coordinator", second).unwrap()
        );
    }
}
