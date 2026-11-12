// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

use async_trait::async_trait;
use registry_adapter::{
    payments::{
        config::{PaymentBinding, PaymentsConfig},
        model::{digest, BillSnapshot, CollectionProviderCommand, PreparedRegistryAction},
        pack::PaymentProviderPack,
        provider_mapping::{PaymentMappingProgram, PaymentMappingRegistry, ProviderAcceptance},
        registry::{BillState, BillView, RegistryPort},
        service::{PaymentService, ProviderPort, ProviderSubmission, SyntheticProvider},
        store::{migrate, PaymentStore},
    },
    serve::Caller,
};
use registry_payment_protocol::{
    CollectionState, Money, PaymentProblemCode as Error, RequestCollection,
};
use registry_payment_simulator_connector::{ConnectorError, Observation};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
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
      "provider":{"type":"simulator","connection":{"baseUrl":"http://127.0.0.1:8099/","tenant":"pilot","biller":"ministry","billerName":"Ministry","callbackUrl":"https://programme.example.test/callback","payerFiBic":"SIMBANK"}},
      "registry":{"baseUrl":"http://127.0.0.1:8080/","recordType":"service-fee-bill","recordRoute":"service-fee-bills","readProfile":"reporter","bindProfile":"binder","receiptProfile":"reporter","bindAction":"bind-payment-attempt","receiptAction":"record-payment-receipt","credentialRef":"secret:env/REPORTER_TOKEN","credentialIdentity":"payment-adapter"}
    }}]})).unwrap()
}
fn mifos_config() -> PaymentsConfig {
    let mut value = serde_json::to_value(config()).unwrap();
    value["connections"][0]["binding"]["simulation"] = json!(false);
    value["connections"][0]["binding"]["currency"] = json!("KES");
    value["connections"][0]["binding"]["provider"] = json!({
        "type": "mifos",
        "connection": {
            "channelBaseUrl": "https://channel.example.test/",
            "bulkBaseUrl": "https://bulk.example.test/",
            "operationsBaseUrl": "https://operations.example.test/",
            "tenant": "pilot",
            "paymentScheme": "mpesa"
        },
        "payer": {"financialAddressKey": "MSISDN", "payerIdKey": "ACCOUNTID"},
        "transactionType": {
            "scenario": "MPESA", "subScenario": "BUYGOODS",
            "initiator": "PAYEE", "initiatorType": "BUSINESS"
        }
    });
    serde_json::from_value(value).unwrap()
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
    commands: Mutex<Vec<CollectionProviderCommand>>,
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
        command: &CollectionProviderCommand,
    ) -> Result<ProviderSubmission, ConnectorError> {
        assert_eq!(
            self.registry.bill.lock().unwrap().state,
            BillState::AttemptBound,
            "binding must commit before provider dispatch"
        );
        self.sends.fetch_add(1, Ordering::SeqCst);
        self.tenants.lock().unwrap().push(provider_tenant(binding));
        let mut commands = self.commands.lock().unwrap();
        if !commands.contains(command) {
            commands.push(command.clone());
        }
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            return Err(ConnectorError::Unknown);
        }
        let transfer_id = match command {
            CollectionProviderCommand::Simulator(command) => format!("transfer-{}", command.rtp_id),
            CollectionProviderCommand::Mifos(command) => {
                format!("transfer-{}", command.correlation_id)
            }
            CollectionProviderCommand::Http(_) => return Err(ConnectorError::Configuration),
        };
        Ok(ProviderSubmission {
            transfer_id,
            acceptance: None,
        })
    }
    async fn observe(
        &self,
        binding: &PaymentBinding,
        _: &CollectionProviderCommand,
        _: &str,
        _: Option<&ProviderAcceptance>,
    ) -> Result<Observation, ConnectorError> {
        self.tenants.lock().unwrap().push(provider_tenant(binding));
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

fn provider_tenant(binding: &PaymentBinding) -> String {
    match &binding.provider {
        registry_adapter::payments::config::CollectionProvider::Simulator { connection } => {
            connection.tenant.clone()
        }
        registry_adapter::payments::config::CollectionProvider::Mifos { connection, .. } => {
            connection.tenant.clone()
        }
        registry_adapter::payments::config::CollectionProvider::Http { settings, .. } => settings
            .get("tenant")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .to_owned(),
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
        commands: Mutex::new(Vec::new()),
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
    changed.connections[0]
        .binding
        .simulator_mut()
        .unwrap()
        .tenant = "new-tenant".into();
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

#[tokio::test]
async fn an_unknown_mifos_submit_is_never_sent_again() {
    let (store, registry, provider) = setup().await;
    {
        let mut bill = registry.bill.lock().unwrap();
        bill.snapshot.simulation = false;
        bill.snapshot.money.currency = "KES".into();
        bill.snapshot.payer_financial_address = "254700000001".into();
        bill.snapshot.payer_id = "payer-account-1".into();
    }
    provider.lose_ack.store(true, Ordering::SeqCst);
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service =
        PaymentService::new(mifos_config(), store, registry.clone(), provider.clone()).unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "mifos-key", &request)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    assert_eq!(
        service
            .request("fees", &caller(), "mifos-key", &request)
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(provider.sends.load(Ordering::SeqCst), 1);
    assert_eq!(provider.commands.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mifos_provider_success_cannot_advance_the_registry_bill_to_paid() {
    let (store, registry, provider) = setup().await;
    {
        let mut bill = registry.bill.lock().unwrap();
        bill.snapshot.simulation = false;
        bill.snapshot.money.currency = "KES".into();
        bill.snapshot.payer_financial_address = "254700000001".into();
        bill.snapshot.payer_id = "payer-account-1".into();
    }
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service =
        PaymentService::new(mifos_config(), store, registry.clone(), provider.clone()).unwrap();
    let accepted = service
        .request("fees", &caller(), "mifos-key", &request)
        .await
        .unwrap();
    provider.confirmed.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .read("fees", &caller(), accepted.collection_id)
            .await
            .unwrap()
            .state,
        CollectionState::Confirmed
    );
    assert_eq!(
        service
            .record_receipt("fees", &caller(), "mifos-receipt", accepted.collection_id,)
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(registry.reports.load(Ordering::SeqCst), 0);
    assert_eq!(registry.bill.lock().unwrap().state, BillState::AttemptBound);
}

const SECOND_PROVIDER_SCRIPT: &str = r#"
fn submit_request(intent, settings, acceptance) {
    if acceptance != () { throw "submit accepts no prior acceptance"; }
    #{
        pathParameters: #{},
        query: #{mode: "direct"},
        headers: #{"x-provider-tenant": settings.tenant},
        body: #{
            command: #{id: intent.correlationId},
            debtor: #{account: intent.payerId, address: intent.payerFinancialAddress},
            total: intent.money
        }
    }
}

fn submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () || response.status != 202
        || response.body.correlation != intent.correlationId {
        throw "submit response mismatch";
    }
    #{correlationId: intent.correlationId, references: #{payment: response.body.receipt}}
}

fn status_request(intent, settings, acceptance) {
    if intent == () || acceptance == () { throw "status needs retained context"; }
    #{
        pathParameters: #{payment: acceptance.references.payment},
        query: #{view: "full"},
        headers: #{"x-provider-tenant": settings.tenant},
        body: ()
    }
}

fn status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () || response.status != 200
        || response.body.correlation != intent.correlationId
        || response.body.receipt != acceptance.references.payment {
        throw "status response mismatch";
    }
    #{
        correlationId: response.body.correlation,
        providerReference: response.body.receipt,
        state: if response.body.state == "complete" { "provider-confirmed" } else { "pending" },
        money: #{
            minorUnits: response.body.total.minorUnits,
            currency: response.body.total.currency,
            scale: intent.money.scale
        },
        parties: [
            #{role: "payer", key: "account", value: response.body.debtor.account},
            #{role: "payer", key: "address", value: response.body.debtor.address}
        ]
    }
}
"#;

fn generic_provider_pack(id: &str, submit_path: &str, status_path: &str) -> Vec<u8> {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: {id}
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection]
mapping:
  collection:
    auth: bearer
    submit:
      path: {submit_path}
      request: {{file: scripts/provider.rhai, entrypoint: submit_request}}
      response: {{file: scripts/provider.rhai, entrypoint: submit_response}}
    status:
      path: {status_path}
      request: {{file: scripts/provider.rhai, entrypoint: status_request}}
      response: {{file: scripts/provider.rhai, entrypoint: status_response}}
  scripts:
    - path: scripts/provider.rhai
      digest: {}
"#,
        registry_platform_config::sha256_uri(SECOND_PROVIDER_SCRIPT.as_bytes())
    )
    .into_bytes()
}

fn second_provider_pack() -> Vec<u8> {
    generic_provider_pack(
        "second-provider",
        "/v2/payments",
        "/v2/payments/{{payment}}",
    )
}

fn compile_provider(pack_bytes: &[u8]) -> PaymentMappingProgram {
    let pack = PaymentProviderPack::from_yaml(pack_bytes).unwrap();
    PaymentMappingProgram::compile(
        &pack,
        pack_bytes,
        &BTreeMap::from([(
            "scripts/provider.rhai".to_owned(),
            SECOND_PROVIDER_SCRIPT.as_bytes().to_vec(),
        )]),
    )
    .unwrap()
}

#[derive(Clone)]
struct WireProviderState {
    requests: Arc<Mutex<Vec<WireRequest>>>,
    correlation: Arc<Mutex<Option<String>>>,
    mismatched_observation: Arc<AtomicBool>,
    unknown_submit: Arc<AtomicBool>,
}

struct WireRequest {
    method: http::Method,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    tenant: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

async fn second_provider_submit(
    axum::extract::State(state): axum::extract::State<WireProviderState>,
    headers: http::HeaderMap,
    uri: http::Uri,
    body: axum::body::Bytes,
) -> impl axum::response::IntoResponse {
    let decoded: Value = serde_json::from_slice(&body).unwrap();
    let correlation = decoded["command"]["id"].as_str().unwrap().to_owned();
    *state.correlation.lock().unwrap() = Some(correlation.clone());
    state.requests.lock().unwrap().push(WireRequest {
        method: http::Method::POST,
        path: uri.path().to_owned(),
        query: uri.query().map(str::to_owned),
        authorization: headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        tenant: headers
            .get("x-provider-tenant")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        content_type: headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: body.to_vec(),
    });
    let response_correlation = if state.unknown_submit.load(Ordering::SeqCst) {
        "unmatched-correlation".to_owned()
    } else {
        correlation
    };
    (
        http::StatusCode::ACCEPTED,
        axum::Json(json!({"receipt":"beta-transfer-7","correlation":response_correlation})),
    )
}

async fn second_provider_status(
    axum::extract::State(state): axum::extract::State<WireProviderState>,
    headers: http::HeaderMap,
    uri: http::Uri,
) -> impl axum::response::IntoResponse {
    state.requests.lock().unwrap().push(WireRequest {
        method: http::Method::GET,
        path: uri.path().to_owned(),
        query: uri.query().map(str::to_owned),
        authorization: headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        tenant: headers
            .get("x-provider-tenant")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        content_type: headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: Vec::new(),
    });
    let mismatch = state.mismatched_observation.load(Ordering::SeqCst);
    let correlation = state.correlation.lock().unwrap().clone().unwrap();
    axum::Json(json!({
        "receipt":"beta-transfer-7",
        "correlation":correlation,
        "state":"complete",
        "total":{"minorUnits":if mismatch { "2501" } else { "2500" },"currency":"KES","scale":2},
        "debtor":{"account":if mismatch { "other-payer" } else { "payer-account-1" },"address":"254700000001"}
    }))
}

fn generic_provider_config(origin: &str, pack_bytes: &[u8], id: &str) -> PaymentsConfig {
    serde_json::from_value(json!({"connections":[{
        "id":"fees","institutionId":"ministry","serviceId":"permit",
        "allowedClients":["coordinator"],"requiredScope":"payments:collections",
        "binding":{
          "providerPack":{"id":id,"version":"1","digest":registry_platform_config::sha256_uri(pack_bytes)},
          "simulation":false,"currency":"KES","currencyScale":2,
          "providerCredentialRef":"secret:file/provider-token","providerCredentialIdentity":"second-provider-operator",
          "replayWindowSeconds":3600,
          "provider":{"type":"http","submitBaseUrl":origin,"statusBaseUrl":origin,"settings":{"tenant":"pilot-beta"}},
          "registry":{"baseUrl":"http://127.0.0.1:8080/","recordType":"service-fee-bill","recordRoute":"service-fee-bills","readProfile":"reporter","bindProfile":"binder","receiptProfile":"reporter","bindAction":"bind-payment-attempt","receiptAction":"record-payment-receipt","credentialRef":"secret:env/UNUSED_REGISTRY_TOKEN","credentialIdentity":"payment-adapter"}
        }}]})).unwrap()
}

fn second_provider_config(origin: &str, pack_bytes: &[u8]) -> PaymentsConfig {
    generic_provider_config(origin, pack_bytes, "second-provider")
}

async fn start_wire_provider() -> (String, WireProviderState, tokio::task::JoinHandle<()>) {
    let state = WireProviderState {
        requests: Arc::new(Mutex::new(Vec::new())),
        correlation: Arc::new(Mutex::new(None)),
        mismatched_observation: Arc::new(AtomicBool::new(true)),
        unknown_submit: Arc::new(AtomicBool::new(false)),
    };
    let router = axum::Router::new()
        .route("/v2/payments", axum::routing::post(second_provider_submit))
        .route(
            "/v2/payments/{payment}",
            axum::routing::get(second_provider_status),
        )
        .route(
            "/v2/a/payments",
            axum::routing::post(second_provider_submit),
        )
        .route(
            "/v2/a/payments/{payment}",
            axum::routing::get(second_provider_status),
        )
        .route(
            "/v2/b/payments",
            axum::routing::post(second_provider_submit),
        )
        .route(
            "/v2/b/payments/{payment}",
            axum::routing::get(second_provider_status),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (origin, state, server)
}

#[tokio::test]
async fn generic_http_host_freezes_one_post_and_uses_read_only_status_for_a_second_provider() {
    let (origin, state, server) = start_wire_provider().await;

    let pack_bytes = second_provider_pack();
    let program = compile_provider(&pack_bytes);
    let secret_root = tempfile::tempdir().unwrap();
    let token_path = secret_root.path().join("provider-token");
    let resolver =
        Arc::new(SecretResolver::new([SecretProvider::File], secret_root.path()).unwrap());

    let (store, registry, _) = setup().await;
    {
        let mut bill = registry.bill.lock().unwrap();
        bill.snapshot.simulation = false;
        bill.snapshot.money.currency = "KES".into();
        bill.snapshot.payer_financial_address = "254700000001".into();
        bill.snapshot.payer_id = "payer-account-1".into();
    }
    let config = second_provider_config(&origin, &pack_bytes);
    let mut mappings = PaymentMappingRegistry::default();
    mappings.insert(program).unwrap();
    let provider = Arc::new(SyntheticProvider::new(resolver, Some(Arc::new(mappings))));
    let service = PaymentService::new(config, store.clone(), registry.clone(), provider).unwrap();
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    assert_eq!(
        service
            .request("fees", &caller(), "second-provider-request", &request)
            .await
            .unwrap_err(),
        Error::Unavailable,
        "a local credential failure must not consume the one-send grant"
    );
    let preflight_failed = store
        .find_bill("ministry", "permit", request.bill_id, request.bill_version)
        .await
        .unwrap()
        .unwrap();
    assert!(preflight_failed.bound);
    assert!(preflight_failed.first_send_at.is_none());
    assert!(preflight_failed.transfer_id.is_none());
    assert!(state.requests.lock().unwrap().is_empty());

    std::fs::write(&token_path, b"test-only-provider-token").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let accepted = service
        .request("fees", &caller(), "second-provider-request", &request)
        .await
        .unwrap();

    let saved = store.get(accepted.collection_id).await.unwrap();
    let CollectionProviderCommand::Http(command) = &saved.provider_command else {
        panic!("the generic provider must retain its exact prepared request");
    };
    assert_eq!(
        saved.provider_command_digest.as_ref(),
        Some(&digest(&saved.provider_command).unwrap())
    );
    assert_eq!(command.prepared_submit.path, "/v2/payments");
    assert_eq!(command.prepared_submit.query["mode"], "direct");
    assert_eq!(
        command.prepared_submit.headers["x-provider-tenant"],
        "pilot-beta"
    );
    let expected_body = registry_platform_canonical_json::canonicalize_json(&json!({
        "command":{"id":command.intent["correlationId"]},
        "debtor":{"account":"payer-account-1","address":"254700000001"},
        "total":{"minorUnits":2500,"currency":"KES","scale":2}
    }))
    .unwrap();
    assert_eq!(command.prepared_submit.body.as_ref(), Some(&expected_body));

    {
        let requests = state.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let post = &requests[0];
        assert_eq!(post.method, http::Method::POST);
        assert_eq!(post.path, "/v2/payments");
        assert_eq!(post.query.as_deref(), Some("mode=direct"));
        assert!(post.authorization.as_deref() == Some("Bearer test-only-provider-token"));
        assert_eq!(post.tenant.as_deref(), Some("pilot-beta"));
        assert_eq!(post.content_type.as_deref(), Some("application/json"));
        assert_eq!(post.body, expected_body);
    }

    assert_eq!(
        service
            .read("fees", &caller(), accepted.collection_id)
            .await
            .unwrap_err(),
        Error::ProviderProtocol,
        "provider money or payer mismatch must fail closed"
    );
    assert!(store
        .get(accepted.collection_id)
        .await
        .unwrap()
        .observation
        .is_none());
    state.mismatched_observation.store(false, Ordering::SeqCst);
    assert_eq!(
        service
            .read("fees", &caller(), accepted.collection_id)
            .await
            .unwrap()
            .state,
        CollectionState::Confirmed
    );
    assert_eq!(
        service
            .record_receipt(
                "fees",
                &caller(),
                "second-provider-receipt",
                accepted.collection_id,
            )
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(registry.reports.load(Ordering::SeqCst), 0);
    assert_eq!(registry.bill.lock().unwrap().state, BillState::AttemptBound);

    let requests = state.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == http::Method::POST)
            .count(),
        1,
        "status reads and receipt refusal must not repeat the provider effect"
    );
    for get in requests
        .iter()
        .filter(|request| request.method == http::Method::GET)
    {
        assert_eq!(get.path, "/v2/payments/beta-transfer-7");
        assert_eq!(get.query.as_deref(), Some("view=full"));
        assert!(get.authorization.as_deref() == Some("Bearer test-only-provider-token"));
        assert_eq!(get.tenant.as_deref(), Some("pilot-beta"));
        assert!(get.content_type.is_none());
        assert!(get.body.is_empty());
    }
    drop(requests);
    server.abort();
}

fn mapping_registry(
    programs: impl IntoIterator<Item = PaymentMappingProgram>,
) -> Arc<PaymentMappingRegistry> {
    let mut registry = PaymentMappingRegistry::default();
    for program in programs {
        registry.insert(program).unwrap();
    }
    Arc::new(registry)
}

fn install_test_token(root: &std::path::Path) {
    let path = root.join("provider-token");
    std::fs::write(&path, b"test-only-provider-token").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn make_live_bill(registry: &Registry) {
    let mut bill = registry.bill.lock().unwrap();
    bill.snapshot.simulation = false;
    bill.snapshot.money.currency = "KES".into();
    bill.snapshot.payer_financial_address = "254700000001".into();
    bill.snapshot.payer_id = "payer-account-1".into();
}

#[tokio::test]
async fn retained_collection_selects_its_exact_pack_before_post_or_get() {
    let (origin, state, server) = start_wire_provider().await;
    state.mismatched_observation.store(false, Ordering::SeqCst);
    let pack_a =
        generic_provider_pack("provider-a", "/v2/a/payments", "/v2/a/payments/{{payment}}");
    let pack_b =
        generic_provider_pack("provider-b", "/v2/b/payments", "/v2/b/payments/{{payment}}");
    let config_a = generic_provider_config(&origin, &pack_a, "provider-a");
    let config_b = generic_provider_config(&origin, &pack_b, "provider-b");

    let secret_root = tempfile::tempdir().unwrap();
    install_test_token(secret_root.path());
    let resolver =
        Arc::new(SecretResolver::new([SecretProvider::File], secret_root.path()).unwrap());
    let only_a = mapping_registry([compile_provider(&pack_a)]);
    let only_b = mapping_registry([compile_provider(&pack_b)]);
    let both = mapping_registry([compile_provider(&pack_a), compile_provider(&pack_b)]);

    let (accepted_store, accepted_registry, _) = setup().await;
    make_live_bill(&accepted_registry);
    let accepted_request = RequestCollection {
        bill_id: accepted_registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service_a = PaymentService::new(
        config_a.clone(),
        accepted_store.clone(),
        accepted_registry.clone(),
        Arc::new(SyntheticProvider::new(resolver.clone(), Some(only_a))),
    )
    .unwrap();
    let accepted_a = service_a
        .request("fees", &caller(), "accepted-a", &accepted_request)
        .await
        .unwrap();
    assert_eq!(state.requests.lock().unwrap()[0].path, "/v2/a/payments");

    let service_only_b = PaymentService::new(
        config_b.clone(),
        accepted_store.clone(),
        accepted_registry.clone(),
        Arc::new(SyntheticProvider::new(
            resolver.clone(),
            Some(only_b.clone()),
        )),
    )
    .unwrap();
    assert_eq!(
        service_only_b
            .read("fees", &caller(), accepted_a.collection_id)
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(
        state.requests.lock().unwrap().len(),
        1,
        "missing A must not GET"
    );

    let missing_secret_root = tempfile::tempdir().unwrap();
    let missing_resolver =
        Arc::new(SecretResolver::new([SecretProvider::File], missing_secret_root.path()).unwrap());
    let (unsent_store, unsent_registry, _) = setup().await;
    make_live_bill(&unsent_registry);
    let unsent_request = RequestCollection {
        bill_id: unsent_registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let unsent_a = PaymentService::new(
        config_a.clone(),
        unsent_store.clone(),
        unsent_registry.clone(),
        Arc::new(SyntheticProvider::new(
            missing_resolver.clone(),
            Some(mapping_registry([compile_provider(&pack_a)])),
        )),
    )
    .unwrap();
    assert_eq!(
        unsent_a
            .request("fees", &caller(), "unsent-a", &unsent_request)
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    install_test_token(missing_secret_root.path());
    let unsent_only_b = PaymentService::new(
        config_b.clone(),
        unsent_store,
        unsent_registry,
        Arc::new(SyntheticProvider::new(missing_resolver, Some(only_b))),
    )
    .unwrap();
    assert_eq!(
        unsent_only_b
            .request("fees", &caller(), "unsent-a", &unsent_request)
            .await
            .unwrap_err(),
        Error::Unavailable
    );
    assert_eq!(
        state.requests.lock().unwrap().len(),
        1,
        "missing A must not POST"
    );

    let service_both = PaymentService::new(
        config_b.clone(),
        accepted_store,
        accepted_registry,
        Arc::new(SyntheticProvider::new(resolver.clone(), Some(both.clone()))),
    )
    .unwrap();
    assert_eq!(
        service_both
            .read("fees", &caller(), accepted_a.collection_id)
            .await
            .unwrap()
            .state,
        CollectionState::Confirmed
    );
    assert_eq!(
        state.requests.lock().unwrap()[1].path,
        "/v2/a/payments/beta-transfer-7"
    );

    let (new_store, new_registry, _) = setup().await;
    make_live_bill(&new_registry);
    let new_request = RequestCollection {
        bill_id: new_registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let new_b = PaymentService::new(
        config_b,
        new_store,
        new_registry,
        Arc::new(SyntheticProvider::new(resolver, Some(both))),
    )
    .unwrap();
    new_b
        .request("fees", &caller(), "new-b", &new_request)
        .await
        .unwrap();
    assert_eq!(state.requests.lock().unwrap()[2].path, "/v2/b/payments");
    server.abort();
}

#[tokio::test]
async fn unknown_generic_send_never_reauthorizes_the_retained_command() {
    let (origin, state, server) = start_wire_provider().await;
    state.unknown_submit.store(true, Ordering::SeqCst);
    let pack = generic_provider_pack("provider-b", "/v2/b/payments", "/v2/b/payments/{{payment}}");
    let config = generic_provider_config(&origin, &pack, "provider-b");
    let secret_root = tempfile::tempdir().unwrap();
    install_test_token(secret_root.path());
    let resolver =
        Arc::new(SecretResolver::new([SecretProvider::File], secret_root.path()).unwrap());
    let (store, registry, _) = setup().await;
    make_live_bill(&registry);
    let request = RequestCollection {
        bill_id: registry.bill.lock().unwrap().snapshot.bill_id,
        bill_version: 1,
    };
    let service = PaymentService::new(
        config,
        store,
        registry,
        Arc::new(SyntheticProvider::new(
            resolver,
            Some(mapping_registry([compile_provider(&pack)])),
        )),
    )
    .unwrap();
    assert_eq!(
        service
            .request("fees", &caller(), "unknown-b", &request)
            .await
            .unwrap_err(),
        Error::OutcomeUnknown
    );
    state.unknown_submit.store(false, Ordering::SeqCst);
    assert_eq!(
        service
            .request("fees", &caller(), "unknown-b", &request)
            .await
            .unwrap_err(),
        Error::RecoveryHeld
    );
    assert_eq!(
        state
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.method == http::Method::POST)
            .count(),
        1
    );
    server.abort();
}
