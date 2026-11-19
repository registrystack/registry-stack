// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

use async_trait::async_trait;
use registry_adapter::payments::{
    g2p_model::{
        DisbursementInstruction, G2pAttempt, G2pAttemptState, G2pConnectionSnapshot, G2pError,
        G2pHttpAuth, G2pProviderBinding, G2pRegistryBinding, PreparedG2pRegistryAction,
    },
    g2p_registry::{G2pInstructionView, G2pRegistryPort},
    g2p_service::{G2pMappingPort, G2pProviderError, G2pProviderPort, G2pService, PreparedG2pSend},
    g2p_store::{migrate_g2p, DispatchAuthorization, G2pStore},
    pack::ProviderPackPin,
    provider_mapping::{
        MappedProviderResponse, PaymentEndpointRole, PaymentHttpMethod, PaymentMappingError,
        PaymentMappingRegistry, PreparedProviderRequest, ProviderAcceptance, ProviderHttpResponse,
    },
};
use registry_platform_yaml::SecretReference;
use serde_json::{json, Map};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use uuid::Uuid;

#[tokio::test]
async fn concurrent_dispatch_authorizes_exactly_one_provider_send() {
    let store = store().await;
    let candidate = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000100").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000101").unwrap(),
    );
    let saved = store
        .reserve(&candidate, "workflow-command", "request-digest")
        .await
        .unwrap();
    store
        .record_bound("g2p", "coordinator", saved.id)
        .await
        .unwrap();

    let first_store = store.clone();
    let second_store = store.clone();
    let id = saved.id;
    let (first, second) = tokio::join!(
        first_store.begin_dispatch("g2p", "coordinator", id, 1_800_000_000),
        second_store.begin_dispatch("g2p", "coordinator", id, 1_800_000_000),
    );
    let decisions = [first.unwrap(), second.unwrap()];
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, DispatchAuthorization::Send(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, DispatchAuthorization::Hold(_)))
            .count(),
        1
    );
}
#[tokio::test]
async fn uncertain_send_is_held_and_never_reauthorizes_dispatch() {
    let store = store().await;
    let candidate = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000110").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000111").unwrap(),
    );
    let id = candidate.id;
    store
        .reserve(&candidate, "workflow-command", "request-digest")
        .await
        .unwrap();
    store.record_bound("g2p", "coordinator", id).await.unwrap();
    assert!(matches!(
        store
            .begin_dispatch("g2p", "coordinator", id, 1_800_000_000)
            .await
            .unwrap(),
        DispatchAuthorization::Send(_)
    ));
    assert!(matches!(
        store
            .begin_dispatch("g2p", "coordinator", id, 1_800_000_001)
            .await
            .unwrap(),
        DispatchAuthorization::Hold(_)
    ));
}
#[tokio::test]
async fn failed_local_preflight_does_not_consume_the_first_send_grant() {
    let store = store().await;
    let candidate = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000160").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000161").unwrap(),
    );
    let id = candidate.id;
    let binding = candidate.binding.clone();
    store
        .reserve(&candidate, "initial-command", "initial-digest")
        .await
        .unwrap();
    store.record_bound("g2p", "coordinator", id).await.unwrap();

    let provider = Arc::new(PreflightFailureProvider::default());
    let service = G2pService::new(store.clone(), Arc::new(UnusedRegistry), provider.clone())
        .with_mapping(Arc::new(AvailableMapping));
    assert!(matches!(
        service
            .request_disbursement(
                "g2p",
                "coordinator",
                "retry-command",
                candidate.instruction.record_id,
                candidate.instruction.instruction_version,
                binding,
                1_800_000_000,
            )
            .await,
        Err(G2pError::Unavailable)
    ));
    assert_eq!(provider.preflights.load(Ordering::SeqCst), 1);
    let retained = store.get_scoped("g2p", "coordinator", id).await.unwrap();
    assert_eq!(retained.state, G2pAttemptState::Bound);
    assert_eq!(retained.first_send_at_unix_seconds, None);
    assert!(matches!(
        store
            .begin_dispatch("g2p", "coordinator", id, 1_800_000_001)
            .await
            .unwrap(),
        DispatchAuthorization::Send(_)
    ));
}

#[tokio::test]
async fn missing_retained_pack_holds_before_provider_preflight_or_dispatch() {
    let store = store().await;
    let candidate = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000162").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000163").unwrap(),
    );
    let id = candidate.id;
    let binding = candidate.binding.clone();
    store
        .reserve(&candidate, "missing-pack-initial", "missing-pack-digest")
        .await
        .unwrap();
    store.record_bound("g2p", "coordinator", id).await.unwrap();

    let provider = Arc::new(PreflightFailureProvider::default());
    let service = G2pService::new(store.clone(), Arc::new(UnusedRegistry), provider.clone())
        .with_mapping(Arc::new(PaymentMappingRegistry::new()));
    assert!(matches!(
        service
            .request_disbursement(
                "g2p",
                "coordinator",
                "missing-pack-retry",
                candidate.instruction.record_id,
                candidate.instruction.instruction_version,
                binding,
                1_800_000_000,
            )
            .await,
        Err(G2pError::Unavailable)
    ));
    assert_eq!(provider.preflights.load(Ordering::SeqCst), 0);
    let retained = store.get_scoped("g2p", "coordinator", id).await.unwrap();
    assert_eq!(retained.state, G2pAttemptState::Bound);
    assert_eq!(retained.first_send_at_unix_seconds, None);
}
#[tokio::test]
async fn source_instruction_identity_is_unique_across_distinct_record_ids() {
    let store = store().await;
    let instruction_id = Uuid::parse_str("00000000-0000-4000-8000-000000000121").unwrap();
    let first = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000120").unwrap(),
        instruction_id,
    );
    let second = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000122").unwrap(),
        instruction_id,
    );
    store
        .reserve(&first, "first-command", "first-digest")
        .await
        .unwrap();
    assert!(store
        .reserve(&second, "second-command", "second-digest")
        .await
        .is_err());
}
#[tokio::test]
async fn instruction_uniqueness_is_scoped_to_the_authoritative_source_namespace() {
    let store = store().await;
    let record_id = Uuid::parse_str("00000000-0000-4000-8000-000000000140").unwrap();
    let instruction_id = Uuid::parse_str("00000000-0000-4000-8000-000000000141").unwrap();

    let first = attempt_for_registry(
        record_id,
        instruction_id,
        "g2p-primary",
        registry_binding("https://breg.invalid/"),
    );
    let distinct_source = attempt_for_registry(
        record_id,
        instruction_id,
        "g2p-secondary",
        registry_binding("https://other-breg.invalid/"),
    );
    let first_saved = store
        .reserve(&first, "first-source-command", "first-source-digest")
        .await
        .unwrap();
    let second_saved = store
        .reserve(
            &distinct_source,
            "second-source-command",
            "second-source-digest",
        )
        .await
        .unwrap();
    assert_ne!(first_saved.id, second_saved.id);

    let mut renamed_binding = registry_binding("https://BREG.invalid:443");
    renamed_binding.credential_identity = "rotated-g2p-adapter".to_owned();
    renamed_binding.credential_ref =
        SecretReference::new("secret:env/BREG_ROTATED_TEST_TOKEN").unwrap();
    renamed_binding.read_profile = "renamed-g2p-adapter-read".to_owned();
    renamed_binding.bind_profile = "renamed-g2p-adapter-bind".to_owned();
    renamed_binding.report_profile = "renamed-g2p-adapter-report".to_owned();
    let renamed_connection =
        attempt_for_registry(record_id, instruction_id, "g2p-renamed", renamed_binding);
    assert!(store
        .reserve(
            &renamed_connection,
            "renamed-source-command",
            "renamed-source-digest",
        )
        .await
        .is_err());

    store
        .record_bound("g2p-primary", "coordinator", first_saved.id)
        .await
        .unwrap();
    store
        .record_bound("g2p-secondary", "coordinator", second_saved.id)
        .await
        .unwrap();
    assert!(matches!(
        store
            .begin_dispatch("g2p-primary", "coordinator", first_saved.id, 1_800_000_000,)
            .await
            .unwrap(),
        DispatchAuthorization::Send(_)
    ));
    assert!(matches!(
        store
            .begin_dispatch(
                "g2p-secondary",
                "coordinator",
                second_saved.id,
                1_800_000_000,
            )
            .await
            .unwrap(),
        DispatchAuthorization::Send(_)
    ));
    assert!(matches!(
        store
            .begin_dispatch("g2p-primary", "coordinator", first_saved.id, 1_800_000_001,)
            .await
            .unwrap(),
        DispatchAuthorization::Hold(_)
    ));
}
#[tokio::test]
async fn request_receipt_lookup_requires_the_exact_saved_key_digest_and_principal() {
    let store = store().await;
    let candidate = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000130").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000131").unwrap(),
    );
    let saved = store
        .reserve(&candidate, "workflow-command", "request-digest")
        .await
        .unwrap();
    assert_eq!(
        store
            .lookup_command("g2p", "coordinator", "workflow-command", "request-digest")
            .await
            .unwrap()
            .unwrap()
            .id,
        saved.id
    );
    assert!(store
        .lookup_command("g2p", "coordinator", "workflow-command", "changed-digest")
        .await
        .is_err());
    assert!(store
        .lookup_command(
            "g2p",
            "another-caller",
            "workflow-command",
            "request-digest"
        )
        .await
        .unwrap()
        .is_none());
    assert!(store
        .lookup_command("g2p", "coordinator", "other-command", "request-digest")
        .await
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn confirmation_key_is_bound_to_its_operation_scope_and_disbursement() {
    let store = store().await;
    let first = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000150").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000151").unwrap(),
    );
    let second = attempt(
        Uuid::parse_str("00000000-0000-4000-8000-000000000152").unwrap(),
        Uuid::parse_str("00000000-0000-4000-8000-000000000153").unwrap(),
    );
    let first_saved = store
        .reserve(&first, "first-request-command", "first-request-digest")
        .await
        .unwrap();
    let second_saved = store
        .reserve(&second, "second-request-command", "second-request-digest")
        .await
        .unwrap();

    let claimed = store
        .claim_confirmation_command(
            "g2p",
            "coordinator",
            first_saved.id,
            "confirmation-key",
            "confirmation-first-digest",
        )
        .await
        .unwrap();
    assert_eq!(claimed.id, first_saved.id);
    assert_eq!(
        store
            .claim_confirmation_command(
                "g2p",
                "coordinator",
                first_saved.id,
                "confirmation-key",
                "confirmation-first-digest",
            )
            .await
            .unwrap()
            .id,
        first_saved.id
    );
    assert!(store
        .claim_confirmation_command(
            "g2p",
            "coordinator",
            second_saved.id,
            "confirmation-key",
            "confirmation-second-digest",
        )
        .await
        .is_err());
    assert!(store
        .claim_existing_command(&first_saved, "confirmation-key", "request-operation-digest",)
        .await
        .is_err());
}

async fn store() -> G2pStore {
    let url = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("postgres-test requires ADAPTER_TEST_DATABASE_URL");
    let config = url.parse().unwrap();
    let manager = deadpool_postgres::Manager::new(config, tokio_postgres::NoTls);
    let pool = deadpool_postgres::Pool::builder(manager)
        .max_size(8)
        .build()
        .unwrap();
    let mut client = pool.get().await.unwrap();
    migrate_g2p(&mut client).await.unwrap();
    drop(client);
    G2pStore::new(pool, format!("g2p-test-{}", Uuid::new_v4()))
}

fn attempt(record_id: Uuid, instruction_id: Uuid) -> G2pAttempt {
    attempt_for_registry(
        record_id,
        instruction_id,
        "g2p",
        registry_binding("https://breg.invalid/"),
    )
}

fn attempt_for_registry(
    record_id: Uuid,
    instruction_id: Uuid,
    connection: &str,
    registry: G2pRegistryBinding,
) -> G2pAttempt {
    let instruction = DisbursementInstruction {
        record_id,
        instruction_id,
        instruction_version: 1,
        instruction_digest: "a".repeat(64),
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        cycle_id: "cycle-2026-11".to_owned(),
        beneficiary_id: "beneficiary-001".to_owned(),
        beneficiary_destination: "254700000002".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        amount_minor: 100_000,
        currency: "KES".to_owned(),
        currency_scale: 2,
    };
    let binding = G2pConnectionSnapshot {
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        currency: "KES".to_owned(),
        currency_scale: 2,
        provider_pack: ProviderPackPin {
            id: "g2p-test".to_owned(),
            version: "1".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        },
        funding_party_key: "ACCOUNT_ID".to_owned(),
        recipient_party_key: "MSISDN".to_owned(),
        provider: G2pProviderBinding::Http {
            revision: "http-test-v1".to_owned(),
            submit_base_url: "http://127.0.0.1:31002/".to_owned(),
            status_base_url: "http://127.0.0.1:31003/".to_owned(),
            auth: G2pHttpAuth::Bearer {
                credential_identity: "provider-test-client".to_owned(),
                credential_ref: SecretReference::new("secret:env/PROVIDER_TEST_TOKEN").unwrap(),
            },
            settings: json!({"tenant": "default"}),
        },
        registry,
    };
    let intent = binding.provider_intent(&instruction).unwrap();
    let prepared_submit = PreparedProviderRequest {
        provider_pack: binding.provider_pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/bulk/transactions".to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        body: Some(
            registry_platform_canonical_json::canonicalize_json(&json!({
                "correlationId": intent.correlation_id,
                "amountMinor": "100000"
            }))
            .unwrap(),
        ),
    };
    G2pAttempt::new(
        Uuid::new_v4(),
        connection.to_owned(),
        "coordinator".to_owned(),
        instruction,
        binding,
        prepared_submit,
        PreparedG2pRegistryAction {
            action: "bind-payout-attempt".to_owned(),
            key: "g2p-bind-test".to_owned(),
            inputs: Map::new(),
            evidence: "prepared".to_owned(),
        },
    )
    .unwrap()
}

fn registry_binding(base_url: &str) -> G2pRegistryBinding {
    G2pRegistryBinding {
        base_url: base_url.to_owned(),
        credential_identity: "g2p-adapter".to_owned(),
        credential_ref: SecretReference::new("secret:env/BREG_TEST_TOKEN").unwrap(),
        record_route: "disbursement-instructions".to_owned(),
        record_type: "disbursement-instruction".to_owned(),
        read_profile: "g2p-adapter-read".to_owned(),
        bind_action: "bind-payout-attempt".to_owned(),
        bind_profile: "g2p-adapter-bind".to_owned(),
        report_action: "record-provider-confirmation".to_owned(),
        report_profile: "g2p-adapter-report".to_owned(),
    }
}

#[derive(Default)]
struct PreflightFailureProvider {
    preflights: AtomicUsize,
}

#[async_trait]
impl G2pProviderPort for PreflightFailureProvider {
    async fn preflight_submit(
        &self,
        _binding: &G2pProviderBinding,
        _intent: &registry_adapter::payments::g2p_model::G2pProviderIntent,
        _request: &PreparedProviderRequest,
    ) -> Result<PreparedG2pSend, G2pProviderError> {
        self.preflights.fetch_add(1, Ordering::SeqCst);
        Err(G2pProviderError::Unavailable)
    }

    async fn recover_acceptance(
        &self,
        _binding: &G2pProviderBinding,
        _intent: &registry_adapter::payments::g2p_model::G2pProviderIntent,
        _request: &PreparedProviderRequest,
    ) -> Result<Option<ProviderAcceptance>, G2pProviderError> {
        panic!("preflight failure must not enter recovery")
    }

    async fn observe(
        &self,
        _binding: &G2pProviderBinding,
        _intent: &registry_adapter::payments::g2p_model::G2pProviderIntent,
        _request: &PreparedProviderRequest,
    ) -> Result<ProviderHttpResponse, G2pProviderError> {
        panic!("preflight failure must not observe the provider")
    }
}

struct AvailableMapping;

impl G2pMappingPort for AvailableMapping {
    fn ensure_available(&self, _pin: &ProviderPackPin) -> Result<(), PaymentMappingError> {
        Ok(())
    }

    fn prepare(
        &self,
        _pin: &ProviderPackPin,
        _role: PaymentEndpointRole,
        _intent: &serde_json::Value,
        _settings: &serde_json::Value,
        _acceptance: Option<&ProviderAcceptance>,
    ) -> Result<PreparedProviderRequest, PaymentMappingError> {
        Err(PaymentMappingError::ArtifactUnavailable)
    }

    fn interpret(
        &self,
        _pin: &ProviderPackPin,
        _role: PaymentEndpointRole,
        _intent: &serde_json::Value,
        _settings: &serde_json::Value,
        _acceptance: Option<&ProviderAcceptance>,
        _response: &ProviderHttpResponse,
    ) -> Result<MappedProviderResponse, PaymentMappingError> {
        Err(PaymentMappingError::ArtifactUnavailable)
    }
}

struct UnusedRegistry;

#[async_trait]
impl G2pRegistryPort for UnusedRegistry {
    async fn read_instruction(
        &self,
        _binding: &G2pRegistryBinding,
        _record_id: Uuid,
    ) -> Result<G2pInstructionView, G2pError> {
        panic!("retained attempt must not reread BReg before preflight")
    }

    async fn prepare_bind(
        &self,
        _binding: &G2pRegistryBinding,
        _key: &str,
        _inputs: Map<String, serde_json::Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError> {
        panic!("retained bound attempt must not prepare another BReg bind")
    }

    async fn invoke_bind(
        &self,
        _binding: &G2pRegistryBinding,
        _prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError> {
        panic!("retained bound attempt must not invoke another BReg bind")
    }

    async fn prepare_confirmation(
        &self,
        _binding: &G2pRegistryBinding,
        _key: &str,
        _inputs: Map<String, serde_json::Value>,
    ) -> Result<PreparedG2pRegistryAction, G2pError> {
        panic!("preflight failure cannot prepare confirmation")
    }

    async fn invoke_confirmation(
        &self,
        _binding: &G2pRegistryBinding,
        _prepared: &PreparedG2pRegistryAction,
    ) -> Result<(), G2pError> {
        panic!("preflight failure cannot invoke confirmation")
    }
}
