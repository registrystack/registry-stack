// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

use async_trait::async_trait;
use registry_adapter::{
    payments::{
        config::{PaymentBinding, PaymentsConfig},
        model::{BillSnapshot, PreparedRegistryAction},
        registry::{BillState, BillView, RegistryPort},
        service::{PaymentService, ProviderPort},
        store::{migrate, PaymentStore},
    },
    serve::Caller,
};
use registry_payment_protocol::{
    CollectionState, Money, PaymentProblemCode as Error, RequestCollection,
};
use registry_payment_simulator_connector::{ConnectorError, Observation, ProviderCommand};
use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

fn config() -> PaymentsConfig {
    serde_json::from_value(json!({"connections":[{
    "id":"fees","institutionId":"ministry","serviceId":"permit","allowedClients":["coordinator"],"requiredScope":"payments:collections",
    "binding":{"simulation":true,"currency":"USD","currencyScale":2,"providerCredentialRef":"secret:env/SIMULATOR_TOKEN","providerCredentialIdentity":"producer","replayWindowSeconds":3600,
      "provider":{"baseUrl":"http://127.0.0.1:8099/","tenant":"pilot","biller":"ministry","billerName":"Ministry","callbackUrl":"https://programme.example.test/callback","payerFiBic":"SIMBANK"},
      "registry":{"baseUrl":"http://127.0.0.1:8080/","recordType":"service-fee-bill","recordRoute":"service-fee-bills","readProfile":"reporter","bindProfile":"binder","receiptProfile":"reporter","bindAction":"bind-payment-attempt","receiptAction":"record-payment-receipt","credentialRef":"secret:env/REPORTER_TOKEN","credentialIdentity":"payment-adapter"}
    }}]})).unwrap()
}
fn caller() -> Caller {
    Caller {
        reference: "workflow-service".into(),
        issuer: "https://issuer.example.test".into(),
        client_id: "coordinator".into(),
        scopes: vec!["payments:collections".into()],
    }
}
fn bill() -> BillView {
    BillView {
        snapshot: BillSnapshot {
            bill_id: Uuid::new_v4(),
            bill_version: 1,
            bill_digest: "a".repeat(64),
            institution_id: "ministry".into(),
            service_id: "permit".into(),
            request_id: "request1".into(),
            tariff_id: "permit-fee".into(),
            tariff_version: 1,
            tariff_digest: "b".repeat(64),
            payer_id: "payer1".into(),
            payer_financial_address: "synthetic-payer".into(),
            money: Money {
                value: "25.00".into(),
                currency: "USD".into(),
                scale: 2,
            },
            simulation: true,
        },
        state: BillState::DueUnbound,
        attempt_id: None,
        binding_revision: None,
        receipt_id: None,
        provider_reference: None,
        receipt_digest: None,
    }
}

struct Registry {
    bill: Mutex<BillView>,
    fail_read: AtomicBool,
    lose_bind: AtomicBool,
    lose_report: AtomicBool,
    binds: AtomicUsize,
    reports: AtomicUsize,
}
#[async_trait]
impl RegistryPort for Registry {
    async fn read_bill(&self, _: &PaymentBinding, id: Uuid) -> Result<BillView, Error> {
        if self.fail_read.swap(false, Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        let bill = self.bill.lock().unwrap().clone();
        assert_eq!(id, bill.snapshot.bill_id);
        Ok(bill)
    }
    async fn prepare(
        &self,
        _: &PaymentBinding,
        receipt: bool,
        key: &str,
        inputs: Map<String, Value>,
    ) -> Result<PreparedRegistryAction, Error> {
        Ok(PreparedRegistryAction {
            action: if receipt { "report" } else { "bind" }.into(),
            key: key.into(),
            evidence: serde_json::to_string(&inputs).unwrap(),
            inputs,
        })
    }
    async fn invoke(
        &self,
        _: &PaymentBinding,
        receipt: bool,
        prepared: &PreparedRegistryAction,
    ) -> Result<(), Error> {
        assert_eq!(
            serde_json::from_str::<Map<String, Value>>(&prepared.evidence).unwrap(),
            prepared.inputs
        );
        let mut bill = self.bill.lock().unwrap();
        assert_eq!(prepared.inputs["billId"], json!(bill.snapshot.bill_id));
        assert_eq!(prepared.inputs["amountMinor"], json!(2500));
        if receipt {
            self.reports.fetch_add(1, Ordering::SeqCst);
            assert_eq!(bill.state, BillState::AttemptBound);
            bill.state = BillState::Paid;
            bill.receipt_id = Some(prepared.inputs["paymentReceiptId"].as_str().unwrap().into());
            bill.provider_reference = Some(
                prepared.inputs["providerReference"]
                    .as_str()
                    .unwrap()
                    .into(),
            );
            bill.receipt_digest = Some(prepared.inputs["receiptDigest"].as_str().unwrap().into());
            if self.lose_report.swap(false, Ordering::SeqCst) {
                self.fail_read.store(true, Ordering::SeqCst);
                return Err(Error::OutcomeUnknown);
            }
        } else {
            self.binds.fetch_add(1, Ordering::SeqCst);
            assert_eq!(bill.state, BillState::DueUnbound);
            bill.state = BillState::AttemptBound;
            bill.attempt_id =
                Some(serde_json::from_value(prepared.inputs["paymentAttemptId"].clone()).unwrap());
            bill.binding_revision = Some(
                prepared.inputs["providerBindingRevision"]
                    .as_str()
                    .unwrap()
                    .into(),
            );
            if self.lose_bind.swap(false, Ordering::SeqCst) {
                self.fail_read.store(true, Ordering::SeqCst);
                return Err(Error::OutcomeUnknown);
            }
        }
        Ok(())
    }
}
struct Provider {
    registry: Arc<Registry>,
    commands: Mutex<HashMap<u64, ProviderCommand>>,
    tenants: Mutex<Vec<String>>,
    lose_ack: AtomicBool,
    confirmed: AtomicBool,
    failed: AtomicBool,
    sends: AtomicUsize,
}
#[async_trait]
impl ProviderPort for Provider {
    async fn submit(
        &self,
        binding: &PaymentBinding,
        command: &ProviderCommand,
    ) -> Result<String, ConnectorError> {
        assert_eq!(
            self.registry.bill.lock().unwrap().state,
            BillState::AttemptBound,
            "binding must commit before provider dispatch"
        );
        self.sends.fetch_add(1, Ordering::SeqCst);
        self.tenants
            .lock()
            .unwrap()
            .push(binding.provider.tenant.clone());
        let mut commands = self.commands.lock().unwrap();
        if let Some(prior) = commands.get(&command.rtp_id) {
            assert_eq!(prior, command);
        } else {
            commands.insert(command.rtp_id, command.clone());
        }
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            return Err(ConnectorError::Unknown);
        }
        Ok(format!("transfer-{}", command.rtp_id))
    }
    async fn observe(
        &self,
        binding: &PaymentBinding,
        _: &ProviderCommand,
        _: &str,
    ) -> Result<Observation, ConnectorError> {
        self.tenants
            .lock()
            .unwrap()
            .push(binding.provider.tenant.clone());
        let confirmed = self.confirmed.load(Ordering::SeqCst);
        let failed = self.failed.load(Ordering::SeqCst);
        Ok(Observation {
            state: if failed {
                CollectionState::Failed
            } else if confirmed {
                CollectionState::Confirmed
            } else {
                CollectionState::Pending
            },
            provider_reference: confirmed.then(|| "SIM-payment-1".into()),
            failure_reason: failed.then(|| "payer-rejected".into()),
            observed_at: 1,
        })
    }
}
async fn setup() -> (PaymentStore, Arc<Registry>, Arc<Provider>) {
    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let manager = deadpool_postgres::Manager::new(url.parse().unwrap(), tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(24)
        .build()
        .unwrap();
    {
        let mut client = pool.get().await.unwrap();
        migrate(&mut client).await.unwrap();
    }
    let store = PaymentStore::new(pool, format!("payment-service-{}", Uuid::new_v4()));
    let registry = Arc::new(Registry {
        bill: Mutex::new(bill()),
        fail_read: AtomicBool::new(false),
        lose_bind: AtomicBool::new(false),
        lose_report: AtomicBool::new(false),
        binds: AtomicUsize::new(0),
        reports: AtomicUsize::new(0),
    });
    let provider = Arc::new(Provider {
        registry: registry.clone(),
        commands: Mutex::new(HashMap::new()),
        tenants: Mutex::new(Vec::new()),
        lose_ack: AtomicBool::new(false),
        confirmed: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        sends: AtomicUsize::new(0),
    });
    (store, registry, provider)
}

#[tokio::test]
async fn definitive_failure_never_releases_the_bill_for_another_collection() {
    let (store, registry, provider) = setup().await;
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service =
        PaymentService::new(config(), store.clone(), registry.clone(), provider.clone()).unwrap();
    let accepted = service
        .request("fees", &caller(), "first", &request)
        .await
        .unwrap();
    provider.failed.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .read("fees", &caller(), accepted.collection_id)
            .await
            .unwrap()
            .state,
        CollectionState::Failed
    );
    drop(service);
    let recovered =
        PaymentService::new(config(), store, registry.clone(), provider.clone()).unwrap();
    for key in ["first", "different-workflow-key"] {
        assert_eq!(
            recovered
                .request("fees", &caller(), key, &request)
                .await
                .unwrap(),
            accepted
        );
    }
    assert!(recovered
        .record_receipt("fees", &caller(), "report", accepted.collection_id)
        .await
        .is_err());
    assert_eq!(provider.sends.load(Ordering::SeqCst), 1);
    assert_eq!(provider.commands.lock().unwrap().len(), 1);
    assert_eq!(registry.binds.load(Ordering::SeqCst), 1);
    assert_eq!(registry.reports.load(Ordering::SeqCst), 0);
    assert_eq!(registry.bill.lock().unwrap().state, BillState::AttemptBound);
}

#[tokio::test]
async fn lost_bind_provider_and_receipt_responses_recover_without_new_effects() {
    let (store, registry, provider) = setup().await;
    registry.lose_bind.store(true, Ordering::SeqCst);
    provider.lose_ack.store(true, Ordering::SeqCst);
    registry.lose_report.store(true, Ordering::SeqCst);
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service =
        PaymentService::new(config(), store.clone(), registry.clone(), provider.clone()).unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "request-key", &request)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    assert_eq!(provider.sends.load(Ordering::SeqCst), 0);
    let id = store
        .find_bill("ministry", "permit", request.bill_id, 1)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        service.read("fees", &caller(), id).await.unwrap().state,
        CollectionState::Unknown
    );
    assert_eq!(
        service
            .request_receipt("fees", &caller(), "request-key", &request)
            .await
            .unwrap_err(),
        Error::ReceiptUnresolved
    );
    assert_eq!(registry.binds.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.sends.load(Ordering::SeqCst),
        0,
        "reads never dispatch"
    );
    drop(service);
    let mut changed = config();
    changed.connections[0].binding.provider.tenant = "new-tenant".into();
    let service = PaymentService::new(
        changed.clone(),
        store.clone(),
        registry.clone(),
        provider.clone(),
    )
    .unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "request-key", &request)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    drop(service);
    let service = PaymentService::new(
        changed.clone(),
        store.clone(),
        registry.clone(),
        provider.clone(),
    )
    .unwrap();
    let accepted = service
        .request("fees", &caller(), "request-key", &request)
        .await
        .unwrap();
    assert_eq!(accepted.collection_id, id);
    assert_eq!(registry.binds.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
    assert_eq!(provider.commands.lock().unwrap().len(), 1);
    assert_eq!(
        service
            .request("fees", &caller(), "another-run", &request)
            .await
            .unwrap(),
        accepted
    );
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
    assert_eq!(
        service
            .request_receipt("fees", &caller(), "request-key", &request)
            .await
            .unwrap(),
        accepted
    );
    assert_eq!(
        service.read("fees", &caller(), id).await.unwrap().state,
        CollectionState::Pending
    );
    assert_eq!(
        service
            .record_receipt("fees", &caller(), "receipt-key", id)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(registry.reports.load(Ordering::SeqCst), 0);
    provider.confirmed.store(true, Ordering::SeqCst);
    assert_eq!(
        service.read("fees", &caller(), id).await.unwrap().state,
        CollectionState::Confirmed
    );
    assert_eq!(
        service
            .record_receipt("fees", &caller(), "receipt-key", id)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    drop(service);
    let service =
        PaymentService::new(changed, store.clone(), registry.clone(), provider.clone()).unwrap();
    let receipt = service
        .record_receipt("fees", &caller(), "receipt-key", id)
        .await
        .unwrap();
    assert!(receipt.simulation);
    assert_eq!(receipt.provider_reference, "SIM-payment-1");
    assert_eq!(registry.reports.load(Ordering::SeqCst), 1);
    assert_eq!(
        service
            .record_receipt("fees", &caller(), "another-report-key", id)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(registry.reports.load(Ordering::SeqCst), 1);
    assert!(
        provider
            .tenants
            .lock()
            .unwrap()
            .iter()
            .all(|s| s == "pilot"),
        "old attempts use the original tenant after config change"
    );
    let mut other = caller();
    other.reference = "different-service".into();
    assert_eq!(
        service.read("fees", &other, id).await.unwrap_err(),
        Error::NotFound
    );
    other = caller();
    other.scopes.clear();
    assert_eq!(
        service.read("fees", &other, id).await.unwrap_err(),
        Error::Forbidden
    );
    let changed_request = RequestCollection {
        bill_id: Uuid::new_v4(),
        bill_version: 1,
    };
    assert_eq!(
        service
            .request("fees", &caller(), "request-key", &changed_request)
            .await
            .unwrap_err(),
        Error::Conflict
    );
}

#[tokio::test]
async fn uncertain_attempt_is_held_after_its_original_replay_window() {
    let (store, registry, provider) = setup().await;
    provider.lose_ack.store(true, Ordering::SeqCst);
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service =
        PaymentService::new(config(), store.clone(), registry.clone(), provider.clone()).unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "key", &request)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    let mut saved = store
        .find_bill("ministry", "permit", request.bill_id, 1)
        .await
        .unwrap()
        .unwrap();
    saved.first_send_at = Some(time::OffsetDateTime::now_utc().unix_timestamp() - 3601);
    store.save(&saved, "test.clock-advanced").await.unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "key", &request)
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(
        service
            .request("fees", &caller(), "fresh-run", &request)
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(provider.sends.load(Ordering::SeqCst), 1);
    assert_eq!(provider.commands.lock().unwrap().len(), 1);
}
