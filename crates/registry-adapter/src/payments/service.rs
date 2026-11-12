// SPDX-License-Identifier: Apache-2.0
//! Explicitly initiated collection, observation, and receipt operations.

use super::{
    config::{PaymentBinding, PaymentConnection, PaymentsConfig},
    model::{digest, Attempt},
    registry::{binding_inputs, BillState, RegistryPort},
    store::PaymentStore,
};
use crate::serve::Caller;
use async_trait::async_trait;
use registry_payment_protocol::{
    CollectionAccepted, CollectionState, CollectionStatus, PaymentProblemCode as Error,
    RegistryReceipt, RequestCollection,
};
use registry_payment_simulator_connector::{
    ConnectorError, Observation, ProviderCommand, SimulatorClient,
};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::client::BearerToken;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

#[async_trait]
pub trait ProviderPort: Send + Sync {
    async fn submit(
        &self,
        binding: &PaymentBinding,
        command: &ProviderCommand,
    ) -> Result<String, ConnectorError>;
    async fn observe(
        &self,
        binding: &PaymentBinding,
        command: &ProviderCommand,
        transfer: &str,
    ) -> Result<Observation, ConnectorError>;
}

pub struct SyntheticProvider {
    resolver: Arc<SecretResolver>,
}
impl SyntheticProvider {
    pub fn new(resolver: Arc<SecretResolver>) -> Self {
        Self { resolver }
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
}
#[async_trait]
impl ProviderPort for SyntheticProvider {
    async fn submit(
        &self,
        binding: &PaymentBinding,
        command: &ProviderCommand,
    ) -> Result<String, ConnectorError> {
        SimulatorClient::new(binding.provider.clone())?
            .submit(command, &self.token(binding)?)
            .await
    }
    async fn observe(
        &self,
        binding: &PaymentBinding,
        command: &ProviderCommand,
        transfer: &str,
    ) -> Result<Observation, ConnectorError> {
        SimulatorClient::new(binding.provider.clone())?
            .observe(command, transfer, &self.token(binding)?)
            .await
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
                provider_command: view.snapshot.provider_command(&connection.binding)?,
                bill: view.snapshot,
                bind_action: None,
                bound: false,
                first_send_at: None,
                transfer_id: None,
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
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        attempt.may_dispatch(now)?;
        if attempt.first_send_at.is_none() {
            attempt.first_send_at = Some(now);
        }
        self.store.save(&attempt, "provider.dispatching").await?;
        let transfer = match self
            .provider
            .submit(&attempt.binding, &attempt.provider_command)
            .await
        {
            Ok(transfer) => transfer,
            Err(_) => {
                self.store
                    .save(&attempt, "provider.unknown")
                    .await
                    .map_err(|_| Error::OutcomeUnknown)?;
                return Err(Error::OutcomeUnknown);
            }
        };
        attempt.transfer_id = Some(transfer);
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
            .observe(&attempt.binding, &attempt.provider_command, transfer)
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
        if status.state != CollectionState::Confirmed || !status.simulation {
            return Err(Error::Conflict);
        }
        let reference = status.provider_reference.ok_or(Error::Conflict)?;
        if !reference.starts_with("SIM-") {
            return Err(Error::Conflict);
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
