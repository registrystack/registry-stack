// SPDX-License-Identifier: Apache-2.0
//! Restricted BReg bill reads and exact prepared Actions through its public client.

use super::{
    config::PaymentBinding,
    model::{Attempt, BillSnapshot, PreparedRegistryAction},
};
use async_trait::async_trait;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegActionTargetConditionsRequest, BRegIdempotencyKey,
    BRegPreparedAction, BRegRecordOptions, BaseRegistryClient, BaseRegistryClientConfig,
    StaticToken,
};
use registry_payment_protocol::{
    Money, PaymentProblemCode as Error, RegistryReceipt, MAX_MINOR_UNITS,
};
use registry_platform_config::SecretResolver;
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BillState {
    DueUnbound,
    AttemptBound,
    Paid,
    Issued,
}

#[derive(Clone)]
pub struct BillView {
    pub snapshot: BillSnapshot,
    pub state: BillState,
    pub attempt_id: Option<Uuid>,
    pub binding_revision: Option<String>,
    pub receipt_id: Option<String>,
    pub provider_reference: Option<String>,
    pub receipt_digest: Option<String>,
}

impl BillView {
    pub fn decode(id: Uuid, data: BTreeMap<String, Value>) -> Result<Self, Error> {
        let string = |key: &str| {
            data.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Error::Unavailable)
        };
        let integer = |key: &str| {
            data.get(key)
                .and_then(Value::as_u64)
                .filter(|v| *v <= MAX_MINOR_UNITS)
                .ok_or(Error::Unavailable)
        };
        let optional = |key: &str| match data.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
            _ => Err(Error::Unavailable),
        };
        let minor = integer("amountMinor")?;
        let scale = u8::try_from(integer("currencyScale")?).map_err(|_| Error::Unavailable)?;
        if scale > 6 || minor == 0 {
            return Err(Error::Unavailable);
        }
        let factor = 10_u64.pow(u32::from(scale));
        let value = if scale == 0 {
            minor.to_string()
        } else {
            format!(
                "{}.{:0width$}",
                minor / factor,
                minor % factor,
                width = usize::from(scale)
            )
        };
        let money = Money {
            value,
            currency: string("currency")?,
            scale,
        };
        money.minor_units().map_err(|_| Error::Unavailable)?;
        let snapshot = BillSnapshot {
            bill_id: id,
            bill_version: integer("billVersion")?,
            bill_digest: string("billDigest")?,
            institution_id: string("institutionId")?,
            service_id: string("serviceId")?,
            request_id: string("requestId")?,
            tariff_id: string("tariffId")?,
            tariff_version: integer("tariffVersion")?,
            tariff_digest: string("tariffDigest")?,
            payer_id: string("payerId")?,
            payer_financial_address: string("payerFinancialAddress")?,
            money,
            simulation: data
                .get("simulation")
                .and_then(Value::as_bool)
                .ok_or(Error::Unavailable)?,
        };
        let state = match string("paymentState")?.as_str() {
            "due-unbound" => BillState::DueUnbound,
            "attempt-bound" => BillState::AttemptBound,
            "paid" => BillState::Paid,
            "issued" => BillState::Issued,
            _ => return Err(Error::Unavailable),
        };
        let attempt_id = optional("paymentAttemptId")?
            .map(|v| Uuid::parse_str(&v).map_err(|_| Error::Unavailable))
            .transpose()?;
        Ok(Self {
            snapshot,
            state,
            attempt_id,
            binding_revision: optional("providerBindingRevision")?,
            receipt_id: optional("paymentReceiptId")?,
            provider_reference: optional("providerReference")?,
            receipt_digest: optional("receiptDigest")?,
        })
    }

    pub fn matches_binding(&self, attempt: &Attempt) -> bool {
        self.snapshot == attempt.bill
            && self.attempt_id == Some(attempt.id)
            && self.binding_revision.as_deref() == Some(&attempt.binding_revision)
            && matches!(
                self.state,
                BillState::AttemptBound | BillState::Paid | BillState::Issued
            )
    }

    pub fn matches_receipt(
        &self,
        attempt: &Attempt,
        receipt: &RegistryReceipt,
        digest: &str,
    ) -> bool {
        self.matches_binding(attempt)
            && matches!(self.state, BillState::Paid | BillState::Issued)
            && self.receipt_id.as_deref() == Some(&receipt.receipt_id)
            && self.provider_reference.as_deref() == Some(&receipt.provider_reference)
            && self.receipt_digest.as_deref() == Some(digest)
    }
}

pub fn binding_inputs(attempt: &Attempt) -> Result<Map<String, Value>, Error> {
    let bill = &attempt.bill;
    let value = json!({"billId":bill.bill_id,"billVersion":bill.bill_version,"billDigest":bill.bill_digest,
        "institutionId":bill.institution_id,"serviceId":bill.service_id,"requestId":bill.request_id,
        "tariffId":bill.tariff_id,"tariffVersion":bill.tariff_version,"tariffDigest":bill.tariff_digest,
        "payerId":bill.payer_id,"payerFinancialAddress":bill.payer_financial_address,
        "amountMinor":bill.money.minor_units().map_err(|_| Error::Unavailable)?,"currency":bill.money.currency,"currencyScale":bill.money.scale,
        "simulation":bill.simulation,"paymentAttemptId":attempt.id,"providerBindingRevision":attempt.binding_revision});
    value.as_object().cloned().ok_or(Error::Unavailable)
}

#[async_trait]
pub trait RegistryPort: Send + Sync {
    async fn read_bill(&self, binding: &PaymentBinding, id: Uuid) -> Result<BillView, Error>;
    async fn prepare(
        &self,
        binding: &PaymentBinding,
        receipt: bool,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedRegistryAction, Error>;
    async fn invoke(
        &self,
        binding: &PaymentBinding,
        receipt: bool,
        prepared: &PreparedRegistryAction,
    ) -> Result<(), Error>;
}

pub struct BregBridge {
    resolver: Arc<SecretResolver>,
}
impl BregBridge {
    pub fn new(resolver: Arc<SecretResolver>) -> Self {
        Self { resolver }
    }
    fn client(&self, binding: &PaymentBinding) -> Result<BaseRegistryClient, Error> {
        let secret = self
            .resolver
            .resolve(binding.registry.credential_ref.as_str())
            .map_err(|_| Error::Unavailable)?;
        let token = std::str::from_utf8(secret.expose_secret()).map_err(|_| Error::Unavailable)?;
        let provider = StaticToken::new(token.to_owned()).map_err(|_| Error::Unavailable)?;
        let url = url::Url::parse(&binding.registry.base_url).map_err(|_| Error::Unavailable)?;
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(url)
                .with_token_provider(Arc::new(provider))
                .with_attempt_timeout(Duration::from_secs(15))
                .with_connect_timeout(Duration::from_secs(5))
                .with_maximum_response_bytes(65_536)
                .with_maximum_mutation_retries(0),
        )
        .map_err(|_| Error::Unavailable)
    }
}

#[async_trait]
impl RegistryPort for BregBridge {
    async fn read_bill(&self, binding: &PaymentBinding, id: Uuid) -> Result<BillView, Error> {
        let client = self.client(binding)?;
        let options = BRegRecordOptions::default()
            .access_profile(&binding.registry.read_profile)
            .map_err(|_| Error::Unavailable)?;
        let response = client
            .get_record(&binding.registry.record_route, &id.to_string(), &options)
            .await
            .map_err(|_| Error::Unavailable)?
            .value;
        if response.meta.record_type_identifier != binding.registry.record_type
            || response.data.record_identifier != id.to_string()
        {
            return Err(Error::Unavailable);
        }
        BillView::decode(id, response.data.domain_data)
    }

    async fn prepare(
        &self,
        binding: &PaymentBinding,
        receipt: bool,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedRegistryAction, Error> {
        let client = self.client(binding)?;
        let (action, profile) = if receipt {
            (
                &binding.registry.receipt_action,
                &binding.registry.receipt_profile,
            )
        } else {
            (
                &binding.registry.bind_action,
                &binding.registry.bind_profile,
            )
        };
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(|_| Error::Unavailable)?
            .value;
        let selected = metadata
            .select_action(action, profile)
            .map_err(|_| Error::Unavailable)?;
        let key = BRegIdempotencyKey::parse(key).map_err(|_| Error::Unavailable)?;
        let conditions = if selected.required_condition_keys().is_empty() {
            None
        } else {
            let references = selected
                .required_condition_keys()
                .iter()
                .map(|key| inputs.get(key).cloned().map(|v| (key.clone(), v)))
                .collect::<Option<Map<_, _>>>()
                .ok_or(Error::Unavailable)?;
            let request = BRegActionTargetConditionsRequest::new(&selected, references)
                .map_err(|_| Error::Unavailable)?;
            Some(
                client
                    .action_target_conditions(&selected, &request)
                    .await
                    .map_err(|_| Error::Unavailable)?
                    .value,
            )
        };
        let request =
            BRegActionInvocationRequest::new(&selected, inputs.clone(), conditions.as_ref())
                .map_err(|_| Error::Unavailable)?;
        let evidence = client
            .prepare_action(&selected, &request, &key)
            .map_err(|_| Error::Unavailable)?;
        let evidence = std::str::from_utf8(evidence.as_bytes())
            .map_err(|_| Error::Unavailable)?
            .to_owned();
        Ok(PreparedRegistryAction {
            action: action.clone(),
            key: key.as_str().to_owned(),
            inputs,
            evidence,
        })
    }

    async fn invoke(
        &self,
        binding: &PaymentBinding,
        receipt: bool,
        prepared: &PreparedRegistryAction,
    ) -> Result<(), Error> {
        let client = self.client(binding)?;
        let (action, profile) = if receipt {
            (
                &binding.registry.receipt_action,
                &binding.registry.receipt_profile,
            )
        } else {
            (
                &binding.registry.bind_action,
                &binding.registry.bind_profile,
            )
        };
        if action != &prepared.action {
            return Err(Error::RecoveryHeld);
        }
        let metadata = client
            .registry_contract(Some(profile))
            .await
            .map_err(|_| Error::Unavailable)?
            .value;
        let selected = metadata
            .select_action(action, profile)
            .map_err(|_| Error::RecoveryHeld)?;
        let key = BRegIdempotencyKey::parse(&prepared.key).map_err(|_| Error::RecoveryHeld)?;
        let saved = BRegPreparedAction::from_slice(prepared.evidence.as_bytes())
            .map_err(|_| Error::RecoveryHeld)?;
        let request = client
            .recover_action(&selected, &saved, &prepared.inputs, &key)
            .map_err(|_| Error::RecoveryHeld)?;
        client
            .invoke_action(&selected, &request, &key)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        Ok(())
    }
}
