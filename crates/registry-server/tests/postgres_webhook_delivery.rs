// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use postgres_harness::TestDatabase;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::event_destination::ActivatedEventDestinationRegistry;
use registry_server::mutation::{MutationBody, MutationCoordinator, MutationPlan, MutationRequest};
use registry_server::postgres::{
    install_compiled_schema, ClaimContext, ExpectedRegistryIdentity, RegistryLockKey,
    RowBoundaryContext,
};
use registry_server::runtime_config::parse_runtime_config;
use registry_server::webhook::{
    WebhookDeliveryError, WebhookDeliveryService, WebhookDeliveryStatusKind, WebhookWorkOutcome,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const PACKAGE_REVISION: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCHEMA_FINGERPRINT: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SUCCESSOR_PACKAGE_REVISION: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SUCCESSOR_SCHEMA_FINGERPRINT: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const DESTINATION_ID: &str = "case-operations";
const DELIVERY_PATH: &str = "/registry-events";
const HMAC_KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";
const RECORD_VALUE_CANARY: &str = "restricted-record-value-canary";
const KEY_REF_CANARY: &str = "webhook-signing-key-canary";
const CA_REF_CANARY: &str = "webhook-ca-bundle-canary";
const SIGNATURE_DOMAIN: &[u8] = b"registry-server-webhook-signature-v1";

type HmacSha256 = Hmac<Sha256>;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn real_postgres_webhook_delivery_retry_dead_letter_replay_is_package_bound_audited_and_confined(
) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let receiver = HttpsReceiver::start().await;
    let database = TestDatabase::create(12).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs delivery state with the compiled schema");
    let identity = expected_identity();
    initialize_registry_state(&migration, &identity).await;
    migration_task.abort();

    let fixture = DestinationFixture::new(&receiver);
    let destinations = Arc::new(fixture.activate(&compiled));
    let compiled_delivery = compiled.event_deliveries().deliveries[0].clone();
    let destination_binding_digest = destinations
        .lookup(DESTINATION_ID)
        .expect("the exact compiled destination is activated")
        .binding_digest()
        .to_owned();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
        .expect("test owns a keyed audit profile");
    let lock_key = RegistryLockKey::derive("webhook-delivery-registry")
        .expect("test lock identity is bounded");
    let coordinator = MutationCoordinator::new_with_event_destinations(
        lock_key,
        Duration::from_secs(2),
        identity.clone(),
        audit_profile.clone(),
        Some(Arc::clone(&destinations)),
    );
    let service = WebhookDeliveryService::new(
        pool.clone(),
        Arc::clone(&destinations),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
    );
    let plan = MutationPlan::from_compiled(&compiled, "records.case.create")
        .expect("create plan retains the exact compiler delivery");
    let claims = mutation_claims(&compiled);
    let mut mutation_client = pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    assert_eq!(
        service.list(0).await,
        Err(WebhookDeliveryError::Unavailable)
    );
    assert_eq!(
        service.list(101).await,
        Err(WebhookDeliveryError::Unavailable)
    );

    receiver.enqueue(ResponsePlan::Status(500)).await;
    receiver.enqueue(ResponsePlan::Status(204)).await;
    let first = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-first",
        "first",
    )
    .await;
    assert_seed_is_exact(
        &database,
        &first,
        &compiled_delivery,
        &destination_binding_digest,
        &identity,
    )
    .await;

    let (worker_a, worker_b) = tokio::join!(service.deliver_once(), service.deliver_once());
    let outcomes = [
        worker_a.expect("first worker returns a closed outcome"),
        worker_b.expect("second worker returns a closed outcome"),
    ];
    assert!(outcomes.contains(&WebhookWorkOutcome::RetryScheduled));
    assert!(outcomes.contains(&WebhookWorkOutcome::Idle));
    receiver.wait_for_count(1).await;
    let first_attempt = receiver.request(0).await;
    assert_exact_request(&first_attempt, &first).await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &first,
        1,
        1,
        "attempt",
        "attempt_started",
    )
    .await;
    let retry_delay = delivery_retry_delay(&database, &first).await;
    assert_eq!(
        retry_delay,
        Duration::from_millis(1_000),
        "retry waits the exact compiler-produced delay after the failed attempt is finalized"
    );

    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    receiver.wait_for_count(2).await;
    let second_attempt = receiver.request(1).await;
    assert_exact_request(&second_attempt, &first).await;
    assert_eq!(
        header(&first_attempt, "idempotency-key"),
        header(&second_attempt, "idempotency-key"),
        "idempotency is stable across attempts in one generation"
    );
    assert_eq!(
        delivery_state(&database, &first).await,
        (1, "delivered".to_owned(), 2)
    );
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &first,
        1,
        1,
        "terminal",
        "http_non_success",
    )
    .await;
    assert!(!outbox_payload_available(&database, &first).await);
    assert_eq!(
        service
            .replay(first.event_id, &first.compiled_delivery_id, 1)
            .await,
        Err(WebhookDeliveryError::Unavailable),
        "delivered work is never replayable"
    );

    let pending_expired = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-payload-retention-expired",
        "expired-before-egress",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
                SET payload_expires_at = transaction_timestamp() - interval '1 second'
              WHERE event_id = $1",
            &[&pending_expired.event_id],
        )
        .await
        .expect("administrator expires one retained pending payload");
    let egress_before_expiry = receiver.count().await;
    assert_eq!(service.deliver_once().await, Ok(WebhookWorkOutcome::Idle));
    assert_eq!(receiver.count().await, egress_before_expiry);
    assert_eq!(
        delivery_state(&database, &pending_expired).await,
        (1, "expired".to_owned(), 0)
    );
    assert!(!outbox_payload_available(&database, &pending_expired).await);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &pending_expired,
        1,
        0,
        "terminal",
        "payload_expired",
    )
    .await;
    assert_eq!(
        service
            .replay(
                pending_expired.event_id,
                &pending_expired.compiled_delivery_id,
                1,
            )
            .await,
        Err(WebhookDeliveryError::Unavailable)
    );
    let statuses = service
        .list(100)
        .await
        .expect("bounded operator list loads");
    let expired_status = statuses
        .iter()
        .find(|status| status.event_id == pending_expired.event_id)
        .expect("expired work remains visible without values");
    assert_eq!(expired_status.state, WebhookDeliveryStatusKind::Expired);
    assert!(!expired_status.payload_available);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &first,
        1,
        2,
        "terminal",
        "delivered",
    )
    .await;
    receiver
        .enqueue(ResponsePlan::Delay(Duration::from_millis(250), 204))
        .await;
    receiver
        .enqueue(ResponsePlan::Delay(Duration::from_millis(250), 204))
        .await;
    let timeout_event = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-timeout",
        "timeout",
    )
    .await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::RetryScheduled)
    );
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    receiver.wait_for_count(4).await;
    let timeout_first = receiver.request(2).await;
    let timeout_second = receiver.request(3).await;
    assert_eq!(
        header(&timeout_first, "idempotency-key"),
        header(&timeout_second, "idempotency-key")
    );
    assert_eq!(
        delivery_state(&database, &timeout_event).await,
        (1, "dead_lettered".to_owned(), 2)
    );
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &timeout_event,
        1,
        1,
        "terminal",
        "destination_timeout",
    )
    .await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &timeout_event,
        1,
        2,
        "terminal",
        "destination_timeout",
    )
    .await;

    service
        .replay(
            timeout_event.event_id,
            &timeout_event.compiled_delivery_id,
            1,
        )
        .await
        .expect("compiled operator replay resets one terminal generation");
    assert_eq!(
        service
            .replay(
                timeout_event.event_id,
                &timeout_event.compiled_delivery_id,
                1,
            )
            .await,
        Err(WebhookDeliveryError::Unavailable),
        "a stale generation and a nonterminal generation share one refusal"
    );
    receiver.enqueue(ResponsePlan::Status(204)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    receiver.wait_for_count(5).await;
    let replay_request = receiver.request(4).await;
    assert_ne!(
        header(&timeout_first, "idempotency-key"),
        header(&replay_request, "idempotency-key"),
        "operator replay changes the deterministic generation binding"
    );
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &timeout_event,
        2,
        0,
        "replay",
        "replay_requested",
    )
    .await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &timeout_event,
        2,
        1,
        "terminal",
        "delivered",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_deliveries
             SET operator_replay = false
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&timeout_event.event_id, &timeout_event.compiled_delivery_id],
        )
        .await
        .expect("administrator installs a compiled-forbidden replay canary");
    assert_eq!(
        service
            .replay(
                timeout_event.event_id,
                &timeout_event.compiled_delivery_id,
                2,
            )
            .await,
        Err(WebhookDeliveryError::Unavailable)
    );

    receiver.enqueue(ResponsePlan::Status(204)).await;
    let recovered = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-recovery",
        "recovered",
    )
    .await;
    let stale_token = Uuid::new_v4();
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET state = 'leased', attempt = 1, next_attempt_at = NULL,
                 attempt_started_at = transaction_timestamp() - interval '10 seconds',
                 lease_expires_at = transaction_timestamp() - interval '5 seconds',
                 lease_token = $3, updated_at = transaction_timestamp()
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[
                &recovered.event_id,
                &recovered.compiled_delivery_id,
                &stale_token,
            ],
        )
        .await
        .expect("administrator simulates one expired post-audit lease");
    assert_eq!(service.deliver_once().await, Ok(WebhookWorkOutcome::Idle));
    assert_eq!(
        delivery_retry_delay(&database, &recovered).await,
        Duration::from_millis(1_000),
        "interrupted work receives the same full post-finalization backoff"
    );
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "recovery consumes the interrupted attempt before claiming the next bounded attempt"
    );
    receiver.wait_for_count(6).await;
    assert_eq!(
        header(&receiver.request(5).await, "x-registry-delivery-attempt"),
        "2"
    );
    let stale_changed = database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET state = 'pending', next_attempt_at = transaction_timestamp(),
                 attempt_started_at = NULL, lease_expires_at = NULL, lease_token = NULL,
                 delivered_at = NULL, updated_at = transaction_timestamp()
             WHERE event_id = $1 AND compiled_delivery_id = $2
               AND generation = 1 AND attempt = 1 AND state = 'leased'
               AND lease_token = $3",
            &[
                &recovered.event_id,
                &recovered.compiled_delivery_id,
                &stale_token,
            ],
        )
        .await
        .expect("stale-worker CAS probe executes");
    assert_eq!(
        stale_changed, 0,
        "an expired worker token has no transition authority"
    );
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &recovered,
        1,
        1,
        "terminal",
        "worker_interrupted",
    )
    .await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &recovered,
        1,
        2,
        "terminal",
        "delivered",
    )
    .await;

    receiver.enqueue(ResponsePlan::Break).await;
    receiver.enqueue(ResponsePlan::Break).await;
    let transport_event = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-transport-unavailable",
        "transport",
    )
    .await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::RetryScheduled)
    );
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    receiver.wait_for_count(8).await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &transport_event,
        1,
        1,
        "terminal",
        "destination_transport_unavailable",
    )
    .await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &transport_event,
        1,
        2,
        "terminal",
        "destination_transport_unavailable",
    )
    .await;

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
                SET payload_expires_at = transaction_timestamp() - interval '1 second'
              WHERE event_id = $1",
            &[&transport_event.event_id],
        )
        .await
        .expect("administrator expires one retained dead letter");
    assert_eq!(service.deliver_once().await, Ok(WebhookWorkOutcome::Idle));
    assert_eq!(
        delivery_state(&database, &transport_event).await,
        (1, "dead_lettered".to_owned(), 2),
        "retention erasure preserves the terminal failure state"
    );
    assert!(!outbox_payload_available(&database, &transport_event).await);
    let statuses = service
        .list(100)
        .await
        .expect("bounded operator list loads");
    let dead_letter_status = statuses
        .iter()
        .find(|status| status.event_id == transport_event.event_id)
        .expect("dead letter remains visible without values");
    assert_eq!(
        dead_letter_status.state,
        WebhookDeliveryStatusKind::DeadLettered
    );
    assert!(!dead_letter_status.payload_available);
    assert_eq!(
        service
            .replay(
                transport_event.event_id,
                &transport_event.compiled_delivery_id,
                1,
            )
            .await,
        Err(WebhookDeliveryError::Unavailable),
        "an erased dead letter cannot be replayed"
    );

    let egress_before_refusals = receiver.count().await;
    let binding_refused = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-binding-refused",
        "binding",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_deliveries
             SET destination_binding_digest = $3
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[
                &binding_refused.event_id,
                &binding_refused.compiled_delivery_id,
                &"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ],
        )
        .await
        .expect("administrator installs a binding mismatch canary");
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::RetryScheduled)
    );
    assert_eq!(receiver.count().await, egress_before_refusals);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &binding_refused,
        1,
        1,
        "terminal",
        "destination_binding_refused",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    assert_eq!(receiver.count().await, egress_before_refusals);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &binding_refused,
        1,
        2,
        "terminal",
        "destination_binding_refused",
    )
    .await;
    assert_eq!(
        service.verify_retained_bindings().await,
        Err(WebhookDeliveryError::Unavailable),
        "a retained replayable dead letter with an incompatible binding blocks startup"
    );
    assert_eq!(
        service
            .replay(
                binding_refused.event_id,
                &binding_refused.compiled_delivery_id,
                1,
            )
            .await,
        Err(WebhookDeliveryError::Unavailable),
        "replay fails closed when the current destination does not match the captured binding"
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_deliveries
             SET operator_replay = false
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[
                &binding_refused.event_id,
                &binding_refused.compiled_delivery_id,
            ],
        )
        .await
        .expect("administrator disables replay for the incompatible dead letter");
    service
        .verify_retained_bindings()
        .await
        .expect("non-replayable and expired or erased dead letters do not block startup");

    let payload_refused = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-payload-refused",
        "payload",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
             SET payload = $2
             WHERE event_id = $1",
            &[
                &payload_refused.event_id,
                &br#"{"label":"tampered"}"#.as_slice(),
            ],
        )
        .await
        .expect("administrator installs a payload tamper canary");
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::RetryScheduled)
    );
    assert_eq!(receiver.count().await, egress_before_refusals);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &payload_refused,
        1,
        1,
        "terminal",
        "payload_refused",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1_020)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::DeadLettered)
    );
    assert_eq!(receiver.count().await, egress_before_refusals);
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &payload_refused,
        1,
        2,
        "terminal",
        "payload_refused",
    )
    .await;

    let audit_refused = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-audit-refused",
        "audit",
    )
    .await;
    revoke_audit_insert(&database).await;
    assert_eq!(
        service.deliver_once().await,
        Err(WebhookDeliveryError::Unavailable)
    );
    assert_eq!(receiver.count().await, egress_before_refusals);
    assert_eq!(
        delivery_state(&database, &audit_refused).await,
        (1, "pending".to_owned(), 0)
    );
    grant_audit_insert(&database).await;
    receiver.enqueue(ResponsePlan::Status(204)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered)
    );
    receiver.wait_for_count(egress_before_refusals + 1).await;
    assert_eq!(
        delivery_state(&database, &audit_refused).await,
        (1, "delivered".to_owned(), 1)
    );
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &audit_refused,
        1,
        1,
        "terminal",
        "delivered",
    )
    .await;
    let terminal_egress_before = receiver.count().await;

    receiver
        .enqueue(ResponsePlan::Delay(Duration::from_millis(50), 204))
        .await;
    let terminal_audit_refused = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-terminal-audit-refused",
        "terminal-audit",
    )
    .await;
    let service_for_terminal_fault = service.clone();
    let attempt = tokio::spawn(async move { service_for_terminal_fault.deliver_once().await });
    receiver.wait_for_count(terminal_egress_before + 1).await;
    revoke_audit_insert(&database).await;
    assert_eq!(
        attempt.await.expect("terminal audit fault task joins"),
        Err(WebhookDeliveryError::Unavailable)
    );
    grant_audit_insert(&database).await;
    assert_eq!(
        delivery_state(&database, &terminal_audit_refused).await,
        (1, "leased".to_owned(), 1),
        "terminal audit refusal leaves the committed lease for expiry recovery"
    );
    assert_no_audit_outcome(
        &database,
        &audit_profile,
        &terminal_audit_refused,
        1,
        1,
        "terminal",
    )
    .await;

    assert_webhook_audits_are_closed_and_value_free(&database).await;

    drop(mutation_client);
    drop(service);
    drop(pool);
    receiver.stop().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_postgres_webhook_delivery_finishes_prior_package_work_after_compatible_upgrade() {
    let receiver = HttpsReceiver::start().await;
    let database = TestDatabase::create(6).await;
    let (migration, migration_task) = database.connect_migration().await;
    let compiled = compiled_registry();
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("migration installs webhook delivery state");
    let original_identity = expected_identity();
    initialize_registry_state(&migration, &original_identity).await;
    migration_task.abort();

    let fixture = DestinationFixture::new(&receiver);
    let destinations = Arc::new(fixture.activate(&compiled));
    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x7c; 32].into())
        .expect("test owns a keyed audit profile");
    let lock_key = RegistryLockKey::derive("webhook-delivery-registry")
        .expect("test lock identity is bounded");
    let coordinator = MutationCoordinator::new_with_event_destinations(
        lock_key,
        Duration::from_secs(2),
        original_identity.clone(),
        audit_profile.clone(),
        Some(Arc::clone(&destinations)),
    );
    let plan = MutationPlan::from_compiled(&compiled, "records.case.create")
        .expect("create plan retains the exact compiler delivery");
    let claims = mutation_claims(&compiled);
    let mut mutation_client = pool
        .get_for_test()
        .await
        .expect("runtime mutation connection is available");
    let captured = create_event(
        &database,
        &coordinator,
        &mut mutation_client,
        &plan,
        &claims,
        "delivery-before-compatible-upgrade",
        "captured-before-upgrade",
    )
    .await;
    assert_eq!(captured.package_revision, PACKAGE_REVISION);
    assert_eq!(
        captured.data_schema,
        compiled.event_deliveries().deliveries[0].data_schema
    );

    let successor_identity = ExpectedRegistryIdentity {
        package_revision: SUCCESSOR_PACKAGE_REVISION.to_owned(),
        schema_fingerprint: SUCCESSOR_SCHEMA_FINGERPRINT.to_owned(),
        package_sequence: 2,
        ..original_identity
    };
    let changed = database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_revision = $1, schema_fingerprint = $2,
                    package_sequence = $3
              WHERE singleton",
            &[
                &successor_identity.package_revision,
                &successor_identity.schema_fingerprint,
                &successor_identity.package_sequence,
            ],
        )
        .await
        .expect("compatible successor identity activates");
    assert_eq!(changed, 1);

    let service = WebhookDeliveryService::new(
        pool.clone(),
        Arc::clone(&destinations),
        successor_identity,
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
    );
    service
        .verify_retained_bindings()
        .await
        .expect("unchanged destination remains compatible with retained work");
    receiver.enqueue(ResponsePlan::Status(204)).await;
    assert_eq!(
        service.deliver_once().await,
        Ok(WebhookWorkOutcome::Delivered),
        "the successor worker delivers immutable work captured by the prior package"
    );
    receiver.wait_for_count(1).await;
    assert_exact_request(&receiver.request(0).await, &captured).await;
    assert_exact_audit_outcome(
        &database,
        &audit_profile,
        &captured,
        1,
        1,
        "terminal",
        "delivered",
    )
    .await;
    let payload_available: bool = database
        .admin
        .query_one(
            "SELECT payload IS NOT NULL
               FROM registry_internal.registry_outbox
              WHERE event_id = $1",
            &[&captured.event_id],
        )
        .await
        .expect("administrator can inspect post-delivery retention state")
        .get(0);
    assert!(
        !payload_available,
        "successful delivery atomically erases values"
    );

    drop(mutation_client);
    drop(service);
    drop(pool);
    receiver.stop().await;
    database.cleanup().await;
}

#[derive(Clone)]
struct CapturedEvent {
    event_id: Uuid,
    compiled_delivery_id: String,
    payload: Vec<u8>,
    data_schema: String,
    package_revision: String,
    created_at: SystemTime,
}

async fn create_event(
    database: &TestDatabase,
    coordinator: &MutationCoordinator,
    client: &mut deadpool_postgres::Client,
    plan: &MutationPlan,
    claims: &ClaimContext,
    idempotency_key: &str,
    label: &str,
) -> CapturedEvent {
    coordinator
        .execute(
            client,
            MutationRequest {
                plan,
                idempotency_key,
                claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("jurisdiction".to_owned(), json!("zone-a")),
                    ("label".to_owned(), json!(label)),
                    ("restrictedNote".to_owned(), json!(RECORD_VALUE_CANARY)),
                ])),
                response_fields: BTreeSet::from([
                    "jurisdiction".to_owned(),
                    "label".to_owned(),
                    "restricted_note".to_owned(),
                ]),
            },
        )
        .await
        .expect("record mutation atomically captures one webhook delivery");
    let row = database
        .admin
        .query_one(
            "SELECT outbox.event_id, delivery.compiled_delivery_id, outbox.payload,
                    delivery.data_schema, delivery.package_revision, outbox.created_at
             FROM registry_internal.registry_outbox AS outbox
             JOIN registry_internal.registry_webhook_deliveries AS delivery
               ON delivery.event_id = outbox.event_id
             ORDER BY outbox.outbox_id DESC
             LIMIT 1",
            &[],
        )
        .await
        .expect("administrator can inspect the newest capture identity");
    let captured = CapturedEvent {
        event_id: row.get(0),
        compiled_delivery_id: row.get(1),
        payload: row.get(2),
        data_schema: row.get(3),
        package_revision: row.get(4),
        created_at: row.get(5),
    };
    let body: Value =
        serde_json::from_slice(&captured.payload).expect("captured event body is strict JSON");
    let record_id = body
        .get("recordId")
        .and_then(Value::as_str)
        .expect("captured event contains a raw record id");
    Uuid::parse_str(record_id).expect("captured record id is a UUID");
    assert_eq!(
        body,
        json!({
            "entity": "case",
            "recordId": record_id,
            "revision": 1,
            "trigger": "created",
            "packageRevision": PACKAGE_REVISION,
            "values": {
                "label": label,
                "restricted_note": RECORD_VALUE_CANARY,
            },
        }),
        "event body carries only the fixed envelope and declared projection"
    );
    assert_eq!(
        captured.payload,
        canonicalize_json(&body).expect("captured body canonicalizes"),
        "durable and transmitted body bytes are canonical"
    );
    captured
}

async fn assert_seed_is_exact(
    database: &TestDatabase,
    event: &CapturedEvent,
    compiled: &registry_server::model::CompiledEventDelivery,
    binding_digest: &str,
    identity: &ExpectedRegistryIdentity,
) {
    let row = database
        .admin
        .query_one(
            "SELECT delivery.destination_binding_digest, delivery.package_revision,
                    delivery.schema_fingerprint, delivery.payload_digest,
                    delivery.deployed_attempt_timeout_ms,
                    delivery.deployed_maximum_attempts,
                    delivery.retry_delays_ms, state.generation, state.state, state.attempt
             FROM registry_internal.registry_webhook_deliveries AS delivery
             JOIN registry_internal.registry_webhook_delivery_state AS state
               ON state.event_id = delivery.event_id
              AND state.compiled_delivery_id = delivery.compiled_delivery_id
             WHERE delivery.event_id = $1 AND delivery.compiled_delivery_id = $2",
            &[&event.event_id, &event.compiled_delivery_id],
        )
        .await
        .expect("one immutable capture and one mutable state seed join exactly");
    assert_eq!(row.get::<_, String>(0), binding_digest);
    assert_eq!(row.get::<_, String>(1), identity.package_revision);
    assert_eq!(row.get::<_, String>(2), identity.schema_fingerprint);
    assert_eq!(
        row.get::<_, Vec<u8>>(3),
        Sha256::digest(&event.payload).to_vec()
    );
    assert_eq!(row.get::<_, i64>(4), 100);
    assert_eq!(row.get::<_, i16>(5), 2);
    assert_eq!(
        row.get::<_, Vec<i64>>(6),
        compiled
            .retry_delays_ms
            .iter()
            .copied()
            .map(i64::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(row.get::<_, i64>(7), 1);
    assert_eq!(row.get::<_, String>(8), "pending");
    assert_eq!(row.get::<_, i16>(9), 0);
}

async fn delivery_state(database: &TestDatabase, event: &CapturedEvent) -> (i64, String, i16) {
    let row = database
        .admin
        .query_one(
            "SELECT generation, state, attempt
             FROM registry_internal.registry_webhook_delivery_state
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event.event_id, &event.compiled_delivery_id],
        )
        .await
        .expect("administrator can inspect the bounded delivery state");
    (row.get(0), row.get(1), row.get(2))
}

async fn outbox_payload_available(database: &TestDatabase, event: &CapturedEvent) -> bool {
    database
        .admin
        .query_one(
            "SELECT payload IS NOT NULL
               FROM registry_internal.registry_outbox
              WHERE event_id = $1",
            &[&event.event_id],
        )
        .await
        .expect("administrator can inspect retained payload availability")
        .get(0)
}

async fn delivery_retry_delay(database: &TestDatabase, event: &CapturedEvent) -> Duration {
    let row = database
        .admin
        .query_one(
            "SELECT next_attempt_at, updated_at
             FROM registry_internal.registry_webhook_delivery_state
             WHERE event_id = $1 AND compiled_delivery_id = $2",
            &[&event.event_id, &event.compiled_delivery_id],
        )
        .await
        .expect("administrator can inspect the exact retry schedule");
    let next_attempt_at = row.get::<_, SystemTime>(0);
    let updated_at = row.get::<_, SystemTime>(1);
    next_attempt_at
        .duration_since(updated_at)
        .expect("retry is scheduled after finalization")
}

async fn revoke_audit_insert(database: &TestDatabase) {
    database
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON registry_internal.registry_audit FROM \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("administrator injects an audit write fault");
}

async fn grant_audit_insert(database: &TestDatabase) {
    database
        .admin
        .batch_execute(&format!(
            "GRANT INSERT ON registry_internal.registry_audit TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("administrator restores audit write authority");
}

async fn assert_exact_audit_outcome(
    database: &TestDatabase,
    profile: &AuditProfile,
    event: &CapturedEvent,
    generation: i64,
    attempt: i64,
    phase: &str,
    expected: &str,
) {
    assert_eq!(
        audit_outcomes(database, profile, event, generation, attempt, phase,).await,
        [expected.to_owned()],
        "one exact event/generation/attempt audit outcome is committed"
    );
}

async fn assert_no_audit_outcome(
    database: &TestDatabase,
    profile: &AuditProfile,
    event: &CapturedEvent,
    generation: i64,
    attempt: i64,
    phase: &str,
) {
    assert!(
        audit_outcomes(database, profile, event, generation, attempt, phase,)
            .await
            .is_empty(),
        "the refused terminal audit and transition are both absent"
    );
}

async fn audit_outcomes(
    database: &TestDatabase,
    profile: &AuditProfile,
    event: &CapturedEvent,
    generation: i64,
    attempt: i64,
    phase: &str,
) -> Vec<String> {
    let event_reference = profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-webhook-event-v1",
            &event.package_revision,
            &event.event_id.to_string(),
        )
        .expect("test can derive the keyed event reference");
    database
        .admin
        .query(
            "SELECT envelope
             FROM registry_internal.registry_audit
             ORDER BY created_at, envelope_id",
            &[],
        )
        .await
        .expect("administrator can inspect minimized audit envelopes")
        .into_iter()
        .filter_map(|row| serde_json::from_slice::<Value>(&row.get::<_, Vec<u8>>(0)).ok())
        .filter_map(|envelope| envelope.get("record").cloned())
        .filter(|record| {
            record.get("schema").and_then(Value::as_str) == Some("registry-server-webhook-audit/v1")
                && record.get("eventReference").and_then(Value::as_str)
                    == Some(event_reference.as_str())
                && record.get("generation").and_then(Value::as_i64) == Some(generation)
                && record.get("attempt").and_then(Value::as_i64) == Some(attempt)
                && record.get("phase").and_then(Value::as_str) == Some(phase)
        })
        .filter_map(|record| {
            record
                .get("outcome")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

async fn assert_webhook_audits_are_closed_and_value_free(database: &TestDatabase) {
    let audits = database
        .admin
        .query(
            "SELECT convert_from(envelope, 'UTF8') FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator can inspect minimized audit envelopes")
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .filter(|envelope| envelope.contains("registry-server-webhook-audit/v1"))
        .collect::<Vec<_>>();
    assert!(!audits.is_empty());
    let joined = audits.join("\n");
    for forbidden in [
        DESTINATION_ID,
        "https://localhost",
        DELIVERY_PATH,
        RECORD_VALUE_CANARY,
        KEY_REF_CANARY,
        CA_REF_CANARY,
        std::str::from_utf8(HMAC_KEY).expect("test HMAC key is UTF-8"),
        "x-registry-signature",
        "upstream",
    ] {
        assert!(
            !joined.contains(forbidden),
            "webhook audit remains value-free"
        );
    }
}

fn header<'a>(request: &'a ReceivedRequest, name: &str) -> &'a str {
    request
        .headers
        .get(name)
        .map(String::as_str)
        .expect("closed webhook header is present")
}

async fn assert_exact_request(request: &ReceivedRequest, event: &CapturedEvent) {
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, DELIVERY_PATH);
    assert!(
        request.body == event.payload,
        "request body is the exact captured canonical bytes"
    );
    assert_eq!(header(request, "ce-id"), event.event_id.to_string());
    assert_eq!(header(request, "ce-specversion"), "1.0");
    assert_eq!(
        header(request, "ce-source"),
        "urn:registrystack:registry:webhook-delivery-registry:instance:webhook-delivery-instance"
    );
    assert_eq!(header(request, "ce-type"), "case-created");
    assert_eq!(
        header(request, "ce-time"),
        OffsetDateTime::from(event.created_at)
            .format(&Rfc3339)
            .expect("captured event time formats")
    );
    assert_eq!(header(request, "ce-dataschema"), event.data_schema);
    assert_eq!(header(request, "x-registry-event-generation"), "1");
    assert_eq!(header(request, "content-type"), "application/json");
    let signature = independent_signature(IndependentSignatureFields {
        event_id: header(request, "ce-id"),
        source: header(request, "ce-source"),
        event_type: header(request, "ce-type"),
        time: header(request, "ce-time"),
        data_schema: header(request, "ce-dataschema"),
        generation: header(request, "x-registry-event-generation"),
        attempt: header(request, "x-registry-delivery-attempt"),
        delivery_time: header(request, "x-registry-delivery-time"),
        method: &request.method,
        request_target: &request.target,
        content_type: header(request, "content-type"),
        idempotency_key: header(request, "idempotency-key"),
        body: &request.body,
    });
    assert_eq!(header(request, "x-registry-signature"), signature);
}

struct IndependentSignatureFields<'a> {
    event_id: &'a str,
    source: &'a str,
    event_type: &'a str,
    time: &'a str,
    data_schema: &'a str,
    generation: &'a str,
    attempt: &'a str,
    delivery_time: &'a str,
    method: &'a str,
    request_target: &'a str,
    content_type: &'a str,
    idempotency_key: &'a str,
    body: &'a [u8],
}

fn independent_signature(fields: IndependentSignatureFields<'_>) -> String {
    let mut input = SIGNATURE_DOMAIN.to_vec();
    for value in [
        b"1.0".as_slice(),
        fields.event_id.as_bytes(),
        fields.source.as_bytes(),
        fields.event_type.as_bytes(),
        fields.time.as_bytes(),
        fields.data_schema.as_bytes(),
        fields.generation.as_bytes(),
        fields.attempt.as_bytes(),
        fields.delivery_time.as_bytes(),
        fields.method.as_bytes(),
        fields.request_target.as_bytes(),
        fields.content_type.as_bytes(),
        fields.idempotency_key.as_bytes(),
        fields.body,
    ] {
        input.extend_from_slice(&(value.len() as u64).to_be_bytes());
        input.extend_from_slice(value);
    }
    let mut mac = HmacSha256::new_from_slice(HMAC_KEY).expect("test HMAC key is valid");
    mac.update(&input);
    format!("v1={}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"webhook-delivery-registry","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"case","route":"cases","mutationMode":"create_only","classification":"restricted",
            "fields":[
              {"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"},
              {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"},
              {"id":"restricted_note","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "requiredPurposes":["case-management"],
              "operations":["create","get","list"],
              "readableFields":["jurisdiction","label","restricted_note"],
              "writableFields":["jurisdiction","label","restricted_note"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }],
            "events":[{
              "id":"case-created","trigger":"created","projection":["label","restricted_note"],
              "webhook":{
                "destinationId":"case-operations"
              }
            }]
          }]
        }"#,
    )
    .expect("webhook delivery fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("webhook delivery fixture compiles")
}

fn expected_identity() -> ExpectedRegistryIdentity {
    ExpectedRegistryIdentity {
        package_id: "webhook-delivery-registry".to_owned(),
        environment: "local".to_owned(),
        instance_id: "webhook-delivery-instance".to_owned(),
        database_id: "webhook-delivery-database".to_owned(),
        package_revision: PACKAGE_REVISION.to_owned(),
        schema_fingerprint: SCHEMA_FINGERPRINT.to_owned(),
        package_sequence: 1,
    }
}

async fn initialize_registry_state(
    migration: &tokio_postgres::Client,
    identity: &ExpectedRegistryIdentity,
) {
    let changed = migration
        .execute(
            "INSERT INTO registry_internal.registry_state
                 (singleton, package_id, environment, instance_id, database_id,
                  active_package_revision, schema_fingerprint, package_sequence,
                  maintenance_status)
             VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')",
            &[
                &identity.package_id,
                &identity.environment,
                &identity.instance_id,
                &identity.database_id,
                &identity.package_revision,
                &identity.schema_fingerprint,
                &identity.package_sequence,
            ],
        )
        .await
        .expect("migration initializes the exact active package binding");
    assert_eq!(changed, 1);
}

fn mutation_claims(registry: &registry_server::CompiledRegistry) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "case",
        Some("operator-principal".to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("compiled authority context is valid")
}

struct DestinationFixture {
    root: PathBuf,
    secret_root: PathBuf,
    package_root: PathBuf,
    trust_anchor: PathBuf,
    receiver_port: u16,
}

impl DestinationFixture {
    fn new(receiver: &HttpsReceiver) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after epoch")
            .as_nanos();
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes")
            .join(format!(
                "registry-server-webhook-delivery-{suffix}-{}",
                std::process::id()
            ));
        let secret_root = root.join("secrets");
        let package_root = root.join("package");
        fs::create_dir_all(&secret_root).expect("secret root creates");
        fs::create_dir(&package_root).expect("package root creates");
        let trust_anchor = root.join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("trust anchor placeholder writes");
        write_secret(&secret_root.join(KEY_REF_CANARY), HMAC_KEY);
        write_secret(
            &secret_root.join(CA_REF_CANARY),
            receiver.certificate_pem.as_bytes(),
        );
        Self {
            root,
            secret_root,
            package_root,
            trust_anchor,
            receiver_port: receiver.address.port(),
        }
    }

    fn activate(
        &self,
        compiled: &registry_server::CompiledRegistry,
    ) -> ActivatedEventDestinationRegistry {
        let raw = format!(
            r#"
listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct
identity:
  environment: local
  instanceId: webhook-delivery-instance
  databaseId: webhook-delivery-database
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 12
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: source-revision-1
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:webhook-delivery
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations:
  {DESTINATION_ID}:
    origin: https://localhost:{}/
    path: {DELIVERY_PATH}
    networkProfile: pinnedLoopbackHttpsTest
    dnsFamily: ipv4Only
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/{KEY_REF_CANARY}
    classificationCeiling: restricted
    tls:
      caBundleRef: secret:file/{CA_REF_CANARY}
    deliveryCeilings:
      attemptTimeoutMilliseconds: 100
      maximumAttempts: 2
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            self.secret_root.display(),
            self.package_root.display(),
            self.trust_anchor.display(),
            PACKAGE_REVISION,
            self.receiver_port,
        );
        parse_runtime_config(&raw)
            .expect("strict pinned-loopback HTTPS config parses")
            .activate_event_destinations(compiled)
            .expect("exact destination inventory and TLS material activate")
    }
}

impl Drop for DestinationFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_secret(path: &std::path::Path, value: &[u8]) {
    fs::write(path, value).expect("test secret writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("test secret permissions set");
    }
}

#[derive(Clone)]
enum ResponsePlan {
    Status(u16),
    Delay(Duration, u16),
    Break,
}

#[derive(Clone)]
struct ReceivedRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpsReceiver {
    address: std::net::SocketAddr,
    certificate_pem: String,
    plans: Arc<Mutex<VecDeque<ResponsePlan>>>,
    requests: Arc<Mutex<Vec<ReceivedRequest>>>,
    notify: Arc<Notify>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsReceiver {
    async fn start() -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("loopback TLS certificate generates");
        let certificate_der = cert.der().clone();
        let certificate_pem = pem("CERTIFICATE", certificate_der.as_ref());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)
            .expect("loopback TLS server configuration builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback TLS receiver binds");
        let address = listener
            .local_addr()
            .expect("receiver address is available");
        let plans = Arc::new(Mutex::new(VecDeque::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let task_plans = Arc::clone(&plans);
        let task_requests = Arc::clone(&requests);
        let task_notify = Arc::clone(&notify);
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut shutdown_rx => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    return;
                };
                let acceptor = acceptor.clone();
                let plans = Arc::clone(&task_plans);
                let requests = Arc::clone(&task_requests);
                let notify = Arc::clone(&task_notify);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(request) = read_request(&mut stream).await else {
                        return;
                    };
                    requests.lock().await.push(request);
                    notify.notify_waiters();
                    let plan = plans
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or(ResponsePlan::Status(204));
                    let (delay, status) = match plan {
                        ResponsePlan::Status(status) => (Duration::ZERO, status),
                        ResponsePlan::Delay(delay, status) => (delay, status),
                        ResponsePlan::Break => {
                            let _ = stream.shutdown().await;
                            return;
                        }
                    };
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let reason = if status == 204 {
                        "No Content"
                    } else {
                        "Server Error"
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            address,
            certificate_pem,
            plans,
            requests,
            notify,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    async fn enqueue(&self, plan: ResponsePlan) {
        self.plans.lock().await.push_back(plan);
    }

    async fn count(&self) -> usize {
        self.requests.lock().await.len()
    }

    async fn request(&self, index: usize) -> ReceivedRequest {
        self.requests
            .lock()
            .await
            .get(index)
            .cloned()
            .expect("requested receiver observation exists")
    }

    async fn wait_for_count(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.count().await < expected {
                self.notify.notified().await;
            }
        })
        .await
        .expect("confined receiver observes the expected request count");
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

async fn read_request<S>(stream: &mut S) -> Result<ReceivedRequest, ()>
where
    S: AsyncReadExt + Unpin,
{
    let mut bytes = Vec::with_capacity(2_048);
    let header_end = loop {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| ())?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines.next().ok_or(())?.split_whitespace();
    let method = request_line.next().ok_or(())?.to_owned();
    let target = request_line.next().ok_or(())?.to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(())?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or(())?
        .parse::<usize>()
        .map_err(|_| ())?;
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 1_024];
        let read = stream.read(&mut chunk).await.map_err(|_| ())?;
        if read == 0 || bytes.len() + read > 2_097_152 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(ReceivedRequest {
        method,
        target,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}
