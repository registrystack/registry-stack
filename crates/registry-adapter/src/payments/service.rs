// SPDX-License-Identifier: Apache-2.0
//! Explicitly initiated collection, observation, and receipt operations.
//! Mifos PH-EE supports collection request and status only: its provider
//! completion observation cannot authorize the BReg paid receipt Action.

use super::{
    config::{CollectionProvider, PaymentBinding, PaymentConnection, PaymentsConfig},
    model::{digest, Attempt, BillSnapshot, CollectionProviderCommand, HttpCollectionCommand},
    provider_mapping::{
        MappedProviderResponse, PaymentEndpointRole, PaymentHttpMethod, PaymentMappingProgram,
        PaymentMappingRegistry, PreparedProviderRequest, ProviderAcceptance, ProviderHttpResponse,
        ProviderObservationState, ProviderPartyRole,
    },
    registry::{binding_inputs, BillState, RegistryPort},
    store::PaymentStore,
};
use crate::serve::Caller;
use async_trait::async_trait;
use registry_payment_mifos_connector::{
    CollectionAccepted as MifosAccepted, ConnectorError as MifosError, MifosClient,
    PaymentState as MifosState, RequestAuth, SubmissionState,
};
use registry_payment_protocol::{
    CollectionAccepted, CollectionState, CollectionStatus, PaymentProblemCode as Error,
    RegistryReceipt, RequestCollection,
};
use registry_payment_simulator_connector::{ConnectorError, Observation, SimulatorClient};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::BearerToken;
use registry_platform_httputil::{read_bounded, validate_response_headers, ServiceBaseUrl};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[async_trait]
pub trait ProviderPort: Send + Sync {
    fn prepare(
        &self,
        binding: &PaymentBinding,
        bill: &BillSnapshot,
    ) -> Result<CollectionProviderCommand, ConnectorError> {
        bill.provider_command(binding)
            .map_err(|_| ConnectorError::Configuration)
    }

    /// Complete every local step needed for a mutation before custody records
    /// its one-send grant. Compiled connectors retain the existing direct seam;
    /// generic live HTTP returns a fully built request whose first poll is the
    /// first network I/O.
    async fn preflight_submit(
        &self,
        _binding: &PaymentBinding,
        _command: &CollectionProviderCommand,
    ) -> Result<ProviderPreflight, ConnectorError> {
        Ok(ProviderPreflight::Direct)
    }

    async fn submit(
        &self,
        binding: &PaymentBinding,
        command: &CollectionProviderCommand,
    ) -> Result<ProviderSubmission, ConnectorError>;
    async fn observe(
        &self,
        binding: &PaymentBinding,
        command: &CollectionProviderCommand,
        transfer: &str,
        acceptance: Option<&ProviderAcceptance>,
    ) -> Result<Observation, ConnectorError>;
}

pub enum ProviderPreflight {
    Direct,
    Prepared(PreparedProviderSend),
}

pub struct PreparedProviderSend {
    send: Pin<Box<dyn Future<Output = Result<ProviderSubmission, ConnectorError>> + Send>>,
}

impl PreparedProviderSend {
    pub fn new(
        send: impl Future<Output = Result<ProviderSubmission, ConnectorError>> + Send + 'static,
    ) -> Self {
        Self {
            send: Box::pin(send),
        }
    }

    pub async fn send(self) -> Result<ProviderSubmission, ConnectorError> {
        self.send.await
    }
}

pub struct ProviderSubmission {
    pub transfer_id: String,
    pub acceptance: Option<ProviderAcceptance>,
}

pub struct SyntheticProvider {
    resolver: Arc<SecretResolver>,
    mappings: Option<Arc<PaymentMappingRegistry>>,
}
impl SyntheticProvider {
    pub fn new(
        resolver: Arc<SecretResolver>,
        mappings: Option<Arc<PaymentMappingRegistry>>,
    ) -> Self {
        Self { resolver, mappings }
    }
    fn token(&self, binding: &PaymentBinding) -> Result<BearerToken, ConnectorError> {
        let secret = self
            .resolver
            .resolve(binding.provider_credential_ref.as_str())
            .map_err(|_| ConnectorError::Unavailable)?;
        let token =
            std::str::from_utf8(secret.expose_secret()).map_err(|_| ConnectorError::Unavailable)?;
        BearerToken::new(token.to_owned()).map_err(|_| ConnectorError::Unavailable)
    }

    fn mapping(
        &self,
        binding: &PaymentBinding,
    ) -> Result<Arc<PaymentMappingProgram>, ConnectorError> {
        let pin = binding
            .provider_pack
            .as_ref()
            .ok_or(ConnectorError::Configuration)?;
        self.mappings
            .as_ref()
            .ok_or(ConnectorError::Configuration)?
            .select(pin)
            .map_err(|_| ConnectorError::Configuration)
    }
}
#[async_trait]
impl ProviderPort for SyntheticProvider {
    fn prepare(
        &self,
        binding: &PaymentBinding,
        bill: &BillSnapshot,
    ) -> Result<CollectionProviderCommand, ConnectorError> {
        let CollectionProvider::Http { settings, .. } = &binding.provider else {
            return bill
                .provider_command(binding)
                .map_err(|_| ConnectorError::Configuration);
        };
        let mapping = self.mapping(binding)?;
        let intent = bill
            .http_intent(binding)
            .map_err(|_| ConnectorError::Configuration)?;
        let prepared_submit = mapping
            .prepare(
                PaymentEndpointRole::CollectionSubmit,
                &intent,
                settings,
                None,
            )
            .map_err(|_| ConnectorError::Configuration)?;
        Ok(CollectionProviderCommand::Http(HttpCollectionCommand {
            intent,
            prepared_submit,
        }))
    }

    async fn preflight_submit(
        &self,
        binding: &PaymentBinding,
        command: &CollectionProviderCommand,
    ) -> Result<ProviderPreflight, ConnectorError> {
        let (
            CollectionProvider::Http {
                submit_base_url,
                settings,
                ..
            },
            CollectionProviderCommand::Http(command),
        ) = (&binding.provider, command)
        else {
            return Ok(ProviderPreflight::Direct);
        };
        let provider_pack = binding
            .provider_pack
            .as_ref()
            .ok_or(ConnectorError::Configuration)?;
        command
            .prepared_submit
            .validate_restored(PaymentEndpointRole::CollectionSubmit, provider_pack)
            .map_err(|_| ConnectorError::Configuration)?;
        let base = ServiceBaseUrl::new(
            url::Url::parse(submit_base_url).map_err(|_| ConnectorError::Configuration)?,
        )
        .map_err(|_| ConnectorError::Configuration)?;
        let path = command
            .prepared_submit
            .path
            .strip_prefix('/')
            .ok_or(ConnectorError::Configuration)?;
        let mut url = base.join(path).map_err(|_| ConnectorError::Configuration)?;
        url.query_pairs_mut()
            .extend_pairs(&command.prepared_submit.query);
        let token = self.token(binding)?;
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: Duration::from_secs(15),
                connect_timeout: Duration::from_secs(5),
                user_agent: Some("registry-adapter-payment-http/v1"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|_| ConnectorError::Configuration)?;
        let mut builder = client.post(url);
        for (name, value) in &command.prepared_submit.headers {
            builder = builder.header(name, value);
        }
        let body = command
            .prepared_submit
            .body
            .as_ref()
            .ok_or(ConnectorError::Configuration)?;
        let request = builder
            .header(
                http::header::AUTHORIZATION,
                token.authorization_header_value(),
            )
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body.clone())
            .build()
            .map_err(|_| ConnectorError::Configuration)?;
        let mapping = self.mapping(binding)?;
        let intent = command.intent.clone();
        let settings = settings.clone();
        Ok(ProviderPreflight::Prepared(PreparedProviderSend::new(
            async move {
                let response = client
                    .execute(request)
                    .await
                    .map_err(|_| ConnectorError::Unknown)?;
                validate_response_headers(response.headers())
                    .map_err(|_| ConnectorError::Unknown)?;
                let status = response.status().as_u16();
                let body = read_bounded(response, 131_072)
                    .await
                    .map_err(|_| ConnectorError::Unknown)?;
                let mapped = mapping
                    .interpret(
                        PaymentEndpointRole::CollectionSubmit,
                        &intent,
                        &settings,
                        None,
                        &ProviderHttpResponse { status, body },
                    )
                    .map_err(|_| ConnectorError::Unknown)?;
                let MappedProviderResponse::Acceptance(acceptance) = mapped else {
                    return Err(ConnectorError::Unknown);
                };
                if intent
                    .get("correlationId")
                    .and_then(serde_json::Value::as_str)
                    != Some(acceptance.correlation_id.as_str())
                {
                    return Err(ConnectorError::Unknown);
                }
                let transfer_id = acceptance
                    .references
                    .values()
                    .next()
                    .cloned()
                    .ok_or(ConnectorError::Unknown)?;
                Ok(ProviderSubmission {
                    transfer_id,
                    acceptance: Some(acceptance),
                })
            },
        )))
    }

    async fn submit(
        &self,
        binding: &PaymentBinding,
        command: &CollectionProviderCommand,
    ) -> Result<ProviderSubmission, ConnectorError> {
        match (&binding.provider, command) {
            (
                CollectionProvider::Simulator {
                    connection: provider,
                },
                CollectionProviderCommand::Simulator(command),
            ) => SimulatorClient::new(provider.clone())?
                .submit(command, &self.token(binding)?)
                .await
                .map(|transfer_id| ProviderSubmission {
                    transfer_id,
                    acceptance: None,
                }),
            (
                CollectionProvider::Mifos {
                    connection: provider,
                    ..
                },
                CollectionProviderCommand::Mifos(command),
            ) => {
                let token = self.token(binding)?;
                let auth = RequestAuth::bearer(&token);
                MifosClient::new(provider.clone())
                    .map_err(map_mifos_error)?
                    .submit_collection(command, &auth)
                    .await
                    .map(|accepted| ProviderSubmission {
                        transfer_id: accepted.transaction_id,
                        acceptance: None,
                    })
                    .map_err(map_mifos_error)
            }
            (CollectionProvider::Http { .. }, CollectionProviderCommand::Http(_)) => {
                Err(ConnectorError::Configuration)
            }
            _ => Err(ConnectorError::Configuration),
        }
    }
    async fn observe(
        &self,
        binding: &PaymentBinding,
        command: &CollectionProviderCommand,
        transfer: &str,
        acceptance: Option<&ProviderAcceptance>,
    ) -> Result<Observation, ConnectorError> {
        match (&binding.provider, command) {
            (
                CollectionProvider::Simulator {
                    connection: provider,
                },
                CollectionProviderCommand::Simulator(command),
            ) => {
                SimulatorClient::new(provider.clone())?
                    .observe(command, transfer, &self.token(binding)?)
                    .await
            }
            (
                CollectionProvider::Mifos {
                    connection: provider,
                    ..
                },
                CollectionProviderCommand::Mifos(command),
            ) => {
                let token = self.token(binding)?;
                let auth = RequestAuth::bearer(&token);
                let observed = MifosClient::new(provider.clone())
                    .map_err(map_mifos_error)?
                    .collection_status(
                        command,
                        &MifosAccepted {
                            transaction_id: transfer.to_owned(),
                            state: SubmissionState::Accepted,
                        },
                        &auth,
                    )
                    .await
                    .map_err(map_mifos_error)?;
                let state = match observed.state {
                    MifosState::Pending => CollectionState::Pending,
                    MifosState::ProviderConfirmed => CollectionState::Confirmed,
                    MifosState::Failed => CollectionState::Failed,
                    MifosState::Unknown => CollectionState::Unknown,
                };
                let observed_at = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
                    .map_err(|_| ConnectorError::Unavailable)?;
                Ok(Observation {
                    state,
                    provider_reference: (state == CollectionState::Confirmed)
                        .then_some(observed.transaction_id),
                    failure_reason: (state == CollectionState::Failed)
                        .then(|| "provider-reported-failure".to_owned()),
                    observed_at,
                })
            }
            (
                CollectionProvider::Http {
                    status_base_url, ..
                },
                CollectionProviderCommand::Http(command),
            ) => {
                let acceptance = acceptance.ok_or(ConnectorError::Protocol)?;
                if command
                    .intent
                    .get("correlationId")
                    .and_then(serde_json::Value::as_str)
                    != Some(acceptance.correlation_id.as_str())
                    || !acceptance
                        .references
                        .values()
                        .any(|value| value == transfer)
                {
                    return Err(ConnectorError::Protocol);
                }
                let mapping = self.mapping(binding)?;
                let prepared = mapping
                    .prepare(
                        PaymentEndpointRole::CollectionStatus,
                        &command.intent,
                        http_settings(binding)?,
                        Some(acceptance),
                    )
                    .map_err(|_| ConnectorError::Protocol)?;
                let response = self
                    .send_prepared(status_base_url, &prepared, &self.token(binding)?)
                    .await?;
                let mapped = mapping
                    .interpret(
                        PaymentEndpointRole::CollectionStatus,
                        &command.intent,
                        http_settings(binding)?,
                        Some(acceptance),
                        &response,
                    )
                    .map_err(|_| ConnectorError::Protocol)?;
                let MappedProviderResponse::Observation(observed) = mapped else {
                    return Err(ConnectorError::Protocol);
                };
                validate_http_observation(binding, command, &observed)?;
                let state = match observed.state {
                    ProviderObservationState::Pending => CollectionState::Pending,
                    ProviderObservationState::ProviderRejected => CollectionState::Failed,
                    ProviderObservationState::ProviderConfirmed => CollectionState::Confirmed,
                };
                let observed_at = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
                    .map_err(|_| ConnectorError::Unavailable)?;
                Ok(Observation {
                    state,
                    provider_reference: (state == CollectionState::Confirmed)
                        .then_some(observed.provider_reference),
                    failure_reason: (state == CollectionState::Failed)
                        .then(|| "provider-reported-failure".to_owned()),
                    observed_at,
                })
            }
            _ => Err(ConnectorError::Configuration),
        }
    }
}

impl SyntheticProvider {
    async fn send_prepared(
        &self,
        base_url: &str,
        prepared: &PreparedProviderRequest,
        token: &BearerToken,
    ) -> Result<ProviderHttpResponse, ConnectorError> {
        let base = ServiceBaseUrl::new(
            url::Url::parse(base_url).map_err(|_| ConnectorError::Configuration)?,
        )
        .map_err(|_| ConnectorError::Configuration)?;
        let path = prepared
            .path
            .strip_prefix('/')
            .ok_or(ConnectorError::Configuration)?;
        let mut url = base.join(path).map_err(|_| ConnectorError::Configuration)?;
        url.query_pairs_mut().extend_pairs(&prepared.query);
        let client = registry_platform_httputil::client::build_client(
            registry_platform_httputil::client::OutboundOptions {
                request_timeout: Duration::from_secs(15),
                connect_timeout: Duration::from_secs(5),
                user_agent: Some("registry-adapter-payment-http/v1"),
                trusted_root_certificates: None,
            },
        )
        .map_err(|_| ConnectorError::Configuration)?;
        let mut request = match prepared.method {
            PaymentHttpMethod::Post => client.post(url),
            PaymentHttpMethod::Get => client.get(url),
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
        let response = request.send().await.map_err(|_| {
            if prepared.method == PaymentHttpMethod::Post {
                ConnectorError::Unknown
            } else {
                ConnectorError::Unavailable
            }
        })?;
        validate_response_headers(response.headers()).map_err(|_| {
            if prepared.method == PaymentHttpMethod::Post {
                ConnectorError::Unknown
            } else {
                ConnectorError::Protocol
            }
        })?;
        let status = response.status().as_u16();
        let body = read_bounded(response, 131_072).await.map_err(|_| {
            if prepared.method == PaymentHttpMethod::Post {
                ConnectorError::Unknown
            } else {
                ConnectorError::Protocol
            }
        })?;
        Ok(ProviderHttpResponse { status, body })
    }
}

fn http_settings(binding: &PaymentBinding) -> Result<&serde_json::Value, ConnectorError> {
    match &binding.provider {
        CollectionProvider::Http { settings, .. } => Ok(settings),
        _ => Err(ConnectorError::Configuration),
    }
}

fn validate_http_observation(
    binding: &PaymentBinding,
    command: &HttpCollectionCommand,
    observed: &super::provider_mapping::ProviderObservation,
) -> Result<(), ConnectorError> {
    let expected_intent = command.intent.as_object().ok_or(ConnectorError::Protocol)?;
    if expected_intent
        .get("correlationId")
        .and_then(serde_json::Value::as_str)
        != Some(observed.correlation_id.as_str())
    {
        return Err(ConnectorError::Protocol);
    }
    let money = expected_intent
        .get("money")
        .and_then(serde_json::Value::as_object)
        .ok_or(ConnectorError::Protocol)?;
    if money
        .get("minorUnits")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value.to_string())
        .as_deref()
        != Some(observed.money.minor_units.as_str())
        || money.get("currency").and_then(serde_json::Value::as_str)
            != Some(observed.money.currency.as_str())
        || money.get("scale").and_then(serde_json::Value::as_u64)
            != Some(u64::from(observed.money.scale))
    {
        return Err(ConnectorError::Protocol);
    }
    let payer_values = observed
        .parties
        .iter()
        .filter(|party| party.role == ProviderPartyRole::Payer)
        .map(|party| party.value.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let payer_id = expected_intent
        .get("payerId")
        .and_then(serde_json::Value::as_str)
        .ok_or(ConnectorError::Protocol)?;
    let payer_address = expected_intent
        .get("payerFinancialAddress")
        .and_then(serde_json::Value::as_str)
        .ok_or(ConnectorError::Protocol)?;
    if observed.parties.len() != 2
        || payer_values.len() != 2
        || !payer_values.contains(payer_id)
        || !payer_values.contains(payer_address)
        || !matches!(&binding.provider, CollectionProvider::Http { .. })
    {
        return Err(ConnectorError::Protocol);
    }
    Ok(())
}

fn map_mifos_error(error: MifosError) -> ConnectorError {
    match error {
        MifosError::Configuration => ConnectorError::Configuration,
        MifosError::Command => ConnectorError::Command,
        MifosError::Protocol => ConnectorError::Protocol,
        MifosError::OutcomeUnknown => ConnectorError::Unknown,
        MifosError::Authentication
        | MifosError::Forbidden
        | MifosError::Rejected
        | MifosError::Unavailable => ConnectorError::Unavailable,
    }
}

pub struct PaymentService {
    config: PaymentsConfig,
    store: PaymentStore,
    registry: Arc<dyn RegistryPort>,
    provider: Arc<dyn ProviderPort>,
    // Each in-flight attempt holds one lock transaction and can use one
    // additional store connection. Bound concurrency leaves pool capacity for
    // commits; try-lock refuses contention without consuming a waiting slot.
    calls: Arc<Semaphore>,
}

impl PaymentService {
    pub fn new(
        config: PaymentsConfig,
        store: PaymentStore,
        registry: Arc<dyn RegistryPort>,
        provider: Arc<dyn ProviderPort>,
    ) -> Result<Self, Error> {
        config.validate().map_err(|_| Error::Unavailable)?;
        Ok(Self {
            config,
            store,
            registry,
            provider,
            calls: Arc::new(Semaphore::new(8)),
        })
    }

    pub async fn audit_access(
        &self,
        caller: &Caller,
        operation: &str,
        id: Option<Uuid>,
        error: Option<Error>,
    ) -> Result<(), Error> {
        let kind = format!("{operation}.{}", error.map_or("released", Error::as_str));
        self.store
            .audit_access(&principal(caller)?, &kind, id)
            .await
    }

    fn connection(&self, id: &str, caller: &Caller) -> Result<&PaymentConnection, Error> {
        let connection = self
            .config
            .connections
            .iter()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)?;
        if !connection.allowed_clients.contains(&caller.client_id)
            || !caller.scopes.contains(&connection.required_scope)
        {
            return Err(Error::Forbidden);
        }
        Ok(connection)
    }

    fn authorize(
        attempt: &Attempt,
        connection: &PaymentConnection,
        principal: &str,
    ) -> Result<(), Error> {
        if attempt.connection != connection.id
            || attempt.principal != principal
            || attempt.bill.institution_id != connection.institution_id
            || attempt.bill.service_id != connection.service_id
        {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    pub async fn request(
        &self,
        id: &str,
        caller: &Caller,
        key: &str,
        request: &RequestCollection,
    ) -> Result<CollectionAccepted, Error> {
        let connection = self.connection(id, caller)?;
        validate_key(key)?;
        request.validate().map_err(|_| Error::InvalidRequest)?;
        let principal = principal(caller)?;
        let request_digest = digest(request)?;
        let _permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let attempt_id = if let Some(saved) = self
            .store
            .lookup_command(id, &principal, "request", key, &request_digest)
            .await?
        {
            saved
        } else if let Some(saved) = self
            .store
            .find_bill(
                &connection.institution_id,
                &connection.service_id,
                request.bill_id,
                request.bill_version,
            )
            .await?
        {
            Self::authorize(&saved, connection, &principal)?;
            self.store
                .claim_command(id, &principal, "request", key, &request_digest, saved.id)
                .await?;
            saved.id
        } else {
            let view = self
                .registry
                .read_bill(&connection.binding, request.bill_id)
                .await?;
            view.snapshot.validate_for(connection)?;
            if view.snapshot.bill_version != request.bill_version
                || view.state != BillState::DueUnbound
                || view.attempt_id.is_some()
            {
                return Err(Error::Conflict);
            }
            let provider_command = self
                .provider
                .prepare(&connection.binding, &view.snapshot)
                .map_err(|_| Error::Unavailable)?;
            let provider_command_digest =
                matches!(&provider_command, CollectionProviderCommand::Http(_))
                    .then(|| digest(&provider_command))
                    .transpose()?;
            let candidate = Attempt {
                id: Uuid::new_v4(),
                connection: id.to_owned(),
                principal: principal.clone(),
                bill_snapshot_digest: view.snapshot.digest()?,
                binding: connection.binding.clone(),
                binding_revision: connection
                    .binding
                    .revision()
                    .map_err(|_| Error::Unavailable)?,
                provider_command,
                provider_command_digest,
                bill: view.snapshot,
                bind_action: None,
                bound: false,
                first_send_at: None,
                transfer_id: None,
                provider_acceptance: None,
                observation: None,
                report_action: None,
                receipt_digest: None,
                receipt: None,
            };
            self.store
                .reserve(&candidate, key, &request_digest)
                .await?
                .id
        };
        let mut lock_client = self
            .store
            .pool
            .get()
            .await
            .map_err(|_| Error::Unavailable)?;
        let lock = lock_client
            .transaction()
            .await
            .map_err(|_| Error::Unavailable)?;
        self.lock_attempt(&lock, attempt_id).await?;
        let mut attempt = self.store.get(attempt_id).await?;
        Self::authorize(&attempt, connection, &principal)?;
        if attempt.transfer_id.is_some() {
            return Ok(attempt.acceptance());
        }
        self.ensure_bound(&mut attempt).await?;
        let bill = self
            .registry
            .read_bill(&attempt.binding, attempt.bill.bill_id)
            .await?;
        if !bill.matches_binding(&attempt) || bill.state != BillState::AttemptBound {
            return Err(Error::Conflict);
        }
        let preflight = self
            .provider
            .preflight_submit(&attempt.binding, &attempt.provider_command)
            .await
            .map_err(|_| Error::Unavailable)?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        attempt.may_dispatch(now)?;
        if attempt.first_send_at.is_none() {
            attempt.first_send_at = Some(now);
        }
        self.store.save(&attempt, "provider.dispatching").await?;
        let result = match preflight {
            ProviderPreflight::Direct => {
                self.provider
                    .submit(&attempt.binding, &attempt.provider_command)
                    .await
            }
            ProviderPreflight::Prepared(send) => send.send().await,
        };
        let submission = match result {
            Ok(transfer) => transfer,
            Err(_) => {
                self.store
                    .save(&attempt, "provider.unknown")
                    .await
                    .map_err(|_| Error::OutcomeUnknown)?;
                return Err(Error::OutcomeUnknown);
            }
        };
        attempt.transfer_id = Some(submission.transfer_id);
        attempt.provider_acceptance = submission.acceptance;
        self.store
            .save(&attempt, "provider.accepted")
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        Ok(attempt.acceptance())
    }

    async fn ensure_bound(&self, attempt: &mut Attempt) -> Result<(), Error> {
        if attempt.bound {
            return Ok(());
        }
        let view = self
            .registry
            .read_bill(&attempt.binding, attempt.bill.bill_id)
            .await?;
        if view.matches_binding(attempt) {
            attempt.bound = true;
            return self.store.save(attempt, "binding.recovered").await;
        }
        if view.snapshot != attempt.bill
            || view.state != BillState::DueUnbound
            || view.attempt_id.is_some()
        {
            return Err(Error::Conflict);
        }
        if attempt.bind_action.is_none() {
            let inputs = binding_inputs(attempt)?;
            let prepared = self
                .registry
                .prepare(
                    &attempt.binding,
                    false,
                    &format!("payment-bind-{}", attempt.id),
                    inputs,
                )
                .await?;
            attempt.bind_action = Some(prepared);
            self.store.save(attempt, "binding.prepared").await?;
        }
        let result = self
            .registry
            .invoke(
                &attempt.binding,
                false,
                attempt.bind_action.as_ref().ok_or(Error::Unavailable)?,
            )
            .await;
        let observed = self
            .registry
            .read_bill(&attempt.binding, attempt.bill.bill_id)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        if !observed.matches_binding(attempt) {
            return Err(result.err().unwrap_or(Error::OutcomeUnknown));
        }
        attempt.bound = true;
        self.store
            .save(attempt, "binding.verified")
            .await
            .map_err(|_| Error::OutcomeUnknown)
    }

    /// Strictly local receipt lookup. It never binds, dispatches or records.
    pub async fn request_receipt(
        &self,
        id: &str,
        caller: &Caller,
        key: &str,
        request: &RequestCollection,
    ) -> Result<CollectionAccepted, Error> {
        let connection = self.connection(id, caller)?;
        validate_key(key)?;
        request.validate().map_err(|_| Error::InvalidRequest)?;
        let principal = principal(caller)?;
        let saved = self
            .store
            .lookup_command(id, &principal, "request", key, &digest(request)?)
            .await?
            .ok_or(Error::ReceiptUnresolved)?;
        let attempt = self.store.get(saved).await?;
        Self::authorize(&attempt, connection, &principal)?;
        if attempt.transfer_id.is_none() {
            return Err(Error::ReceiptUnresolved);
        }
        Ok(attempt.acceptance())
    }

    pub async fn read(
        &self,
        id: &str,
        caller: &Caller,
        collection: Uuid,
    ) -> Result<CollectionStatus, Error> {
        let connection = self.connection(id, caller)?;
        let principal = principal(caller)?;
        let _permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let initial = self.store.get(collection).await?;
        Self::authorize(&initial, connection, &principal)?;
        let mut lock_client = self
            .store
            .pool
            .get()
            .await
            .map_err(|_| Error::Unavailable)?;
        let lock = lock_client
            .transaction()
            .await
            .map_err(|_| Error::Unavailable)?;
        self.lock_attempt(&lock, collection).await?;
        let mut attempt = self.store.get(collection).await?;
        if matches!(
            attempt.status().state,
            CollectionState::Confirmed | CollectionState::Failed
        ) {
            return Ok(attempt.status());
        }
        let Some(transfer) = &attempt.transfer_id else {
            return Ok(attempt.status());
        };
        let observation = self
            .provider
            .observe(
                &attempt.binding,
                &attempt.provider_command,
                transfer,
                attempt.provider_acceptance.as_ref(),
            )
            .await
            .map_err(|e| {
                if e == ConnectorError::Protocol {
                    Error::ProviderProtocol
                } else {
                    Error::Unavailable
                }
            })?;
        if attempt
            .observation
            .as_ref()
            .is_some_and(|old| observation.observed_at < old.observed_at)
        {
            return Err(Error::ProviderProtocol);
        }
        attempt.observation = Some(observation);
        self.store.save(&attempt, "provider.observed").await?;
        Ok(attempt.status())
    }

    pub async fn record_receipt(
        &self,
        id: &str,
        caller: &Caller,
        key: &str,
        collection: Uuid,
    ) -> Result<RegistryReceipt, Error> {
        let connection = self.connection(id, caller)?;
        validate_key(key)?;
        let principal = principal(caller)?;
        let _permit = self
            .calls
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let initial = self.store.get(collection).await?;
        Self::authorize(&initial, connection, &principal)?;
        self.store
            .claim_command(
                id,
                &principal,
                "receipt",
                key,
                &digest(&registry_payment_protocol::RecordReceipt {
                    collection_id: collection,
                })?,
                collection,
            )
            .await?;
        let mut lock_client = self
            .store
            .pool
            .get()
            .await
            .map_err(|_| Error::Unavailable)?;
        let lock = lock_client
            .transaction()
            .await
            .map_err(|_| Error::Unavailable)?;
        self.lock_attempt(&lock, collection).await?;
        let mut attempt = self.store.get(collection).await?;
        if let Some(receipt) = &attempt.receipt {
            return Ok(receipt.clone());
        }
        let status = attempt.status();
        if status.state != CollectionState::Confirmed {
            return Err(Error::Conflict);
        }
        let reference = status.provider_reference.ok_or(Error::Conflict)?;
        match &attempt.binding.provider {
            CollectionProvider::Simulator { .. }
                if status.simulation && reference.starts_with("SIM-") => {}
            CollectionProvider::Mifos { .. } if !status.simulation => {
                // Released PH-EE Operations `SUCCESS` is only a provider
                // observation. It cannot satisfy the BReg Action that advances
                // this bill to `paid` and authorizes service issuance.
                return Err(Error::RecoveryHeld);
            }
            CollectionProvider::Http { .. } if !status.simulation => {
                return Err(Error::RecoveryHeld);
            }
            CollectionProvider::Simulator { .. }
            | CollectionProvider::Mifos { .. }
            | CollectionProvider::Http { .. } => {
                return Err(Error::Conflict);
            }
        }
        let receipt = RegistryReceipt {
            collection_id: attempt.id,
            bill_id: attempt.bill.bill_id,
            bill_version: attempt.bill.bill_version,
            binding_revision: attempt.binding_revision.clone(),
            simulation: attempt.bill.simulation,
            money: attempt.bill.money.clone(),
            provider_reference: reference,
            receipt_id: format!("payment-{}", attempt.id),
        };
        receipt.validate().map_err(|_| Error::Unavailable)?;
        let receipt_digest = digest(&receipt)?
            .strip_prefix("sha256:")
            .ok_or(Error::Unavailable)?
            .to_owned();
        let view = self
            .registry
            .read_bill(&attempt.binding, attempt.bill.bill_id)
            .await?;
        if view.matches_receipt(&attempt, &receipt, &receipt_digest) {
            attempt.receipt = Some(receipt.clone());
            attempt.receipt_digest = Some(receipt_digest);
            self.store.save(&attempt, "receipt.recovered").await?;
            return Ok(receipt);
        }
        if !view.matches_binding(&attempt) || view.state != BillState::AttemptBound {
            return Err(Error::Conflict);
        }
        if attempt.report_action.is_none() {
            let mut inputs = binding_inputs(&attempt)?;
            inputs.insert(
                "paymentReceiptId".into(),
                serde_json::json!(receipt.receipt_id),
            );
            inputs.insert(
                "providerReference".into(),
                serde_json::json!(receipt.provider_reference),
            );
            inputs.insert("receiptDigest".into(), serde_json::json!(receipt_digest));
            attempt.report_action = Some(
                self.registry
                    .prepare(
                        &attempt.binding,
                        true,
                        &format!("payment-receipt-{}", attempt.id),
                        inputs,
                    )
                    .await?,
            );
            attempt.receipt_digest = Some(receipt_digest.clone());
            self.store.save(&attempt, "receipt.prepared").await?;
        }
        if attempt.receipt_digest.as_ref() != Some(&receipt_digest) {
            return Err(Error::RecoveryHeld);
        }
        let result = self
            .registry
            .invoke(
                &attempt.binding,
                true,
                attempt.report_action.as_ref().ok_or(Error::Unavailable)?,
            )
            .await;
        let observed = self
            .registry
            .read_bill(&attempt.binding, attempt.bill.bill_id)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        if !observed.matches_receipt(&attempt, &receipt, &receipt_digest) {
            return Err(result.err().unwrap_or(Error::OutcomeUnknown));
        }
        attempt.receipt = Some(receipt.clone());
        self.store
            .save(&attempt, "receipt.recorded")
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        Ok(receipt)
    }

    async fn lock_attempt(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        id: Uuid,
    ) -> Result<(), Error> {
        let name = format!("adapter-payment/{}/{}", self.store.deployment, id);
        let row = tx
            .query_one(
                "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))",
                &[&name],
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        if row.get::<_, bool>(0) {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}

fn principal(caller: &Caller) -> Result<String, Error> {
    digest(&[&caller.issuer, &caller.client_id, &caller.reference])
}
fn validate_key(key: &str) -> Result<(), Error> {
    if super::config::text(key, 128) {
        Ok(())
    } else {
        Err(Error::InvalidRequest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::{
        config::PaymentsConfig,
        provider_mapping::{
            PreparedProviderRequest, ProviderObservation, ProviderObservedMoney,
            ProviderObservedParty,
        },
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn http_binding() -> PaymentBinding {
        let config: PaymentsConfig = serde_json::from_value(json!({"connections":[{
            "id":"fees","institutionId":"ministry","serviceId":"permit",
            "allowedClients":["coordinator"],"requiredScope":"payments:collections",
            "binding":{"providerPack":{"id":"provider","version":"1","digest":format!("sha256:{}", "a".repeat(64))},
              "simulation":false,"currency":"KES","currencyScale":2,
              "providerCredentialRef":"secret:env/PROVIDER_TOKEN","providerCredentialIdentity":"producer",
              "replayWindowSeconds":3600,
              "provider":{"type":"http","submitBaseUrl":"https://submit.example.test/","statusBaseUrl":"https://status.example.test/","settings":{}},
              "registry":{"baseUrl":"https://registry.example.test/","recordType":"service-fee-bill","recordRoute":"service-fee-bills","readProfile":"reporter","bindProfile":"binder","receiptProfile":"reporter","bindAction":"bind-payment-attempt","receiptAction":"record-payment-receipt","credentialRef":"secret:env/REGISTRY_TOKEN","credentialIdentity":"adapter"}
            }}]})).unwrap();
        config.connections[0].binding.clone()
    }

    fn http_command(binding: &PaymentBinding) -> HttpCollectionCommand {
        let intent = json!({
            "correlationId":"correlation-1",
            "payerFinancialAddress":"254700000001",
            "payerId":"payer-1",
            "money":{"minorUnits":2500,"currency":"KES","scale":2}
        });
        HttpCollectionCommand {
            intent,
            prepared_submit: PreparedProviderRequest {
                provider_pack: binding.provider_pack.clone().unwrap(),
                role: PaymentEndpointRole::CollectionSubmit,
                method: PaymentHttpMethod::Post,
                path: "/collections".into(),
                query: BTreeMap::new(),
                headers: BTreeMap::new(),
                body: Some(br#"{"amount":"25.00"}"#.to_vec()),
            },
        }
    }

    fn observation() -> ProviderObservation {
        ProviderObservation {
            correlation_id: "correlation-1".into(),
            provider_reference: "provider-1".into(),
            state: ProviderObservationState::ProviderConfirmed,
            money: ProviderObservedMoney {
                minor_units: "2500".into(),
                currency: "KES".into(),
                scale: 2,
            },
            parties: vec![
                ProviderObservedParty {
                    role: ProviderPartyRole::Payer,
                    key: "MSISDN".into(),
                    value: "254700000001".into(),
                },
                ProviderObservedParty {
                    role: ProviderPartyRole::Payer,
                    key: "ACCOUNTID".into(),
                    value: "payer-1".into(),
                },
            ],
        }
    }

    #[test]
    fn mapped_collection_observation_must_match_authoritative_payer_and_money() {
        let binding = http_binding();
        let command = http_command(&binding);
        assert!(validate_http_observation(&binding, &command, &observation()).is_ok());

        let mut wrong_money = observation();
        wrong_money.money.minor_units = "2501".into();
        assert_eq!(
            validate_http_observation(&binding, &command, &wrong_money),
            Err(ConnectorError::Protocol)
        );

        let mut wrong_payer = observation();
        wrong_payer.parties[1].value = "different-payer".into();
        assert_eq!(
            validate_http_observation(&binding, &command, &wrong_payer),
            Err(ConnectorError::Protocol)
        );

        let mut wrong_correlation = observation();
        wrong_correlation.correlation_id = "different-correlation".into();
        assert_eq!(
            validate_http_observation(&binding, &command, &wrong_correlation),
            Err(ConnectorError::Protocol)
        );
    }
}
