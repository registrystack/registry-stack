// SPDX-License-Identifier: Apache-2.0
//! Restricted BReg bill reads and exact prepared Actions through its public client.

use super::{
    config::{PaymentBinding, RegistryBinding},
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
    peer_policy: registry_platform_httputil::PeerPolicy,
    resolver: Arc<SecretResolver>,
}
impl BregBridge {
    pub fn new(
        resolver: Arc<SecretResolver>,
        peer_policy: registry_platform_httputil::PeerPolicy,
    ) -> Self {
        Self {
            resolver,
            peer_policy,
        }
    }
    fn client(&self, binding: &RegistryBinding) -> Result<BaseRegistryClient, Error> {
        let secret = self
            .resolver
            .resolve(binding.credential_ref.as_str())
            .map_err(|_| Error::Unavailable)?;
        let token = std::str::from_utf8(secret.expose_secret()).map_err(|_| Error::Unavailable)?;
        let provider = StaticToken::new(token.to_owned()).map_err(|_| Error::Unavailable)?;
        let url = url::Url::parse(&binding.base_url).map_err(|_| Error::Unavailable)?;
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(url, self.peer_policy)
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
        let client = self.client(&binding.registry)?;
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
        let client = self.client(&binding.registry)?;
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
        let client = self.client(&binding.registry)?;
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

#[cfg(test)]
mod peer_policy_tests {
    use super::*;
    use registry_breg_client::BaseRegistryClientError;
    use registry_platform_config::{DeclaredPosture, Posture, PostureSource, SecretProvider};

    #[tokio::test]
    async fn payment_registry_bridge_follows_the_declared_peer_policy() {
        const RECORD: &str = "00000000-0000-4000-8000-000000000001";
        const TRACE: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let app = axum::Router::new().fallback(|| async {
                (
                    [
                        ("registry-posture", "development"),
                        ("traceparent", TRACE),
                        ("etag", "\"breg-record-000000000001\""),
                        ("link", "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </v1/schemas/bill>; rel=\"describedby\""),
                    ],
                    axum::Json(json!({
                        "data": {"recordIdentifier": RECORD, "revisionIdentifier": "1", "domainData": {}},
                        "meta": {"registryIdentifier": "billing", "datasetIdentifier": "bills", "recordTypeIdentifier": "bill"}
                    })),
                )
            });
            axum::serve(listener, app).await.unwrap();
        });
        let root = tempfile::tempdir().unwrap();
        let token = root.path().join("token");
        std::fs::write(&token, "synthetic-billing-token").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(token, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let resolver = Arc::new(SecretResolver::new([SecretProvider::File], root.path()).unwrap());
        let binding: RegistryBinding = serde_json::from_value(json!({
            "baseUrl": endpoint, "recordType": "bill", "recordRoute": "bills",
            "readProfile": "billing", "bindProfile": "billing", "receiptProfile": "billing",
            "bindAction": "bind-payment", "receiptAction": "record-receipt",
            "credentialRef": "secret:file/token", "credentialIdentity": "billing"
        }))
        .unwrap();
        let config_file = root.path().join("payments.yaml");
        let api_version = crate::payments::config::API_VERSION;
        let kind = crate::payments::config::KIND;
        std::fs::write(
            &config_file,
            format!("apiVersion: {api_version}\nkind: {kind}\nconnections: []\n"),
        )
        .unwrap();
        for posture in [Posture::Production, Posture::Development] {
            let declared = DeclaredPosture {
                posture,
                source: PostureSource::Flag,
            };
            let loaded = crate::payments::http::load_config(&config_file, declared)
                .loaded
                .unwrap();
            let bridge = BregBridge::new(
                resolver.clone(),
                crate::payments::http::payment_peer_policy(loaded.posture.posture()),
            );
            let result = bridge
                .client(&binding)
                .unwrap()
                .get_record("bills", RECORD, &BRegRecordOptions::default())
                .await;
            match posture {
                Posture::Production => assert!(matches!(
                    result,
                    Err(BaseRegistryClientError::DevelopmentPeer)
                )),
                Posture::Development => assert!(result.is_ok(), "{result:?}"),
            }
        }
        server.abort();
    }
}
