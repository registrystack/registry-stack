// SPDX-License-Identifier: Apache-2.0
//! Disposable PostgreSQL conformance coverage for Relay's audit state plane.
//!
//! Run only against a dedicated disposable database:
//!
//! `REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL='postgres://...' cargo test \
//!   -p registry-relay --lib postgres_state_plane -- --ignored --nocapture`

use std::{
    collections::HashMap,
    env, fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use postgres_native_tls::MakeTlsConnector;
use registry_platform_audit::{
    pseudonym_keyring::{
        AuditPseudonymKeyId, AuditPseudonymKeyringMetadata, RetainedAuditPseudonymKeyEpoch,
    },
    verify_chain, AuditChainHasher, AuditEnvelope, ChainVerificationError, DurableAuditOperationId,
    DurableAuditPhase, DurableAuditSink, DurableAuditStreamKind, DurableAuditWrite,
    DurableAuditWriteError, DurableAuditWriteOutcome,
};
use registry_platform_crypto::canonicalize_json;
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tokio::{sync::Barrier, task::JoinHandle};
use tokio_postgres::{error::SqlState, Client, Config, GenericClient};
use ulid::Ulid;

use crate::consultation::{
    audit::{
        terminal_completion_test_hook, FinalizedValidatedConsultation,
        PreparedAtomicConsultationAttempt, PreparedAuditedConsultationDispatch,
        TerminalCompletionTestPoint, ValidatedConsultationBackendResult,
    },
    commitments::KeyedDispatchRequestCommitment,
    response::PublishableConsultationResponse,
    ConsultationId, ConsultationOutcome, NotaryEvaluationId, OperationId,
};
use crate::source_plan::{
    bounded_runtime_vector_plan_fixture, dhis2_completion_seed_fixture,
    maximum_completion_seed_fixture, normal_completion_seed_fixture,
    open_crvs_completion_seed_fixture, rhai_five_operation_two_slot_completion_seed_fixture,
    semantic_alias_completion_seed_fixture, snapshot_completion_seed_fixture,
};

use super::migration::RUNTIME_SESSION_LIMITS_SQL;
use super::pseudonym_keyring::canonical_metadata as canonical_keyring_metadata;
use super::{
    install_postgres_state_plane_v1, AuditChainKeyEpochId, AuditPseudonymKeyringLockKey,
    AuditPseudonymLookupEpoch, AuditPseudonymMaintenanceDatabaseRole,
    AuditPseudonymReaderDatabaseRole, AuditedConsultationDispatch,
    AuthorizedAuditPseudonymLookupSubset, BatchChildReplayContext, CompletionAttemptReference,
    ConsultationCompletionOutcome, ConsultationPermitSet, ConsultationPersistenceError,
    DispatchOperationId, DispatchPermitBudget, DispatchPermitKind, EffectiveQuotaLimits,
    KeyringInitializationOutcome, KnownCompletionDisposition, KnownConsultationCompletionFacts,
    KnownFailureClass, MaterializationGenerationId, MaterializationPublicationBindingId,
    MaterializationPublicationError, MaterializationPublicationOutcome,
    MaterializationPublicationRequest, MaterializationSourceRevision,
    PostgresAuditPseudonymKeyringMaintenance, PostgresAuditPseudonymKeyringReader,
    PostgresAuditPseudonymKeyringRuntime, PostgresDurableAuditStatePlane, PostgresKeyringError,
    PostgresQuotaStatePlane, PostgresServingFence, PseudonymBoundDuplicateRecoveryOutcome,
    PublicConsultationOutcome, PublicQuotaLimits, QuotaError, QuotaGrant, QuotaKey, QuotaReadiness,
    QuotaReservation, RestrictedMaterializationContentDigest, RuntimeDatabaseRole,
    ServingFenceError, ServingFenceLockKey, ServingFenceReadiness, StatePlaneInitializationError,
    StatePlaneInstallError, StatePlaneReadiness, TakeoverCompletionRecoveryAuthority,
    AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1, DURABLE_AUDIT_CAPABILITY_V1,
    PERSISTENT_QUOTA_CAPABILITY_V1, POSTGRES_STATE_PLANE_MIGRATION_V1, SERVING_FENCE_CAPABILITY_V1,
    STATE_PLANE_SCHEMA_FINGERPRINT_V1,
};

const DATABASE_URL_ENV: &str = "REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL";
const PREPARED_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_STATE_PLANE_PREPARED_POSTGRES_TEST_URL";
const UNSAFE_DURABILITY_DATABASE_URL_ENV: &str =
    "REGISTRY_RELAY_STATE_PLANE_UNSAFE_DURABILITY_POSTGRES_TEST_URL";
const TEST_ADVISORY_LOCK: i64 = 7_221_091_441;
const SNAPSHOT_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_snapshot_v1(\
        $1, $2, $3, $4, $5, $6, $7, $8, $9\
    )";
const CAS_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_cas_v1(\
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18\
)";

fn test_serving_fence_lock_key() -> ServingFenceLockKey {
    ServingFenceLockKey::new(7_221_091_442).expect("test fence key is distinct and nonzero")
}

fn test_pseudonym_keyring_lock_key() -> AuditPseudonymKeyringLockKey {
    AuditPseudonymKeyringLockKey::new(7_221_091_443)
        .expect("test keyring lock key is distinct and nonzero")
}

#[derive(Debug)]
struct DirectCandidate {
    predecessor: Option<[u8; 32]>,
    generation: i64,
}

async fn postgres_client(
    url: &str,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    postgres_client_config(url.parse()?).await
}

async fn postgres_client_as(
    url: &str,
    user: &str,
    password: &str,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    let mut config: Config = url.parse()?;
    config.user(user).password(password);
    postgres_client_config(config).await
}

async fn postgres_client_config(
    config: Config,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    let mut builder = native_tls::TlsConnector::builder();
    if let Ok(path) = env::var("REGISTRY_RELAY_STATE_PLANE_POSTGRES_ROOT_CERT_PATH") {
        let pem = fs::read(path)?;
        builder.add_root_certificate(native_tls::Certificate::from_pem(&pem)?);
    }
    let connector = MakeTlsConnector::new(builder.build()?);
    let (client, connection) = config.connect(connector).await?;
    let driver = tokio::spawn(connection);
    Ok((client, driver))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn role_name(kind: &str) -> String {
    format!(
        "relay_sp_{kind}_{}",
        Ulid::new().to_string().to_ascii_lowercase()
    )
}

fn attempt_write(operation_id: &DurableAuditOperationId, marker: &str) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        operation_id.clone(),
        DurableAuditPhase::Attempt,
        json!({
            "authorization": "accepted",
            "test_marker": marker,
        }),
    )
    .expect("test attempt is valid")
}

fn pseudonym_key_id(value: &str) -> AuditPseudonymKeyId {
    AuditPseudonymKeyId::parse(value).expect("valid test pseudonym key id")
}

fn current_unix_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock follows Unix epoch")
            .as_millis(),
    )
    .expect("test time fits i64")
}

fn consultation_attempt_write(
    operation_id: &DurableAuditOperationId,
    key_id: &AuditPseudonymKeyId,
    marker: &str,
) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id.clone(),
        DurableAuditPhase::Attempt,
        json!({
            "authorization": "accepted",
            "commitment_key_id": key_id.as_str(),
            "subject_handle": "hmac-sha256:test-only-redacted-handle",
            "test_marker": marker,
        }),
    )
    .expect("test consultation attempt is valid")
}

fn pseudonym_denial_write(
    operation_id: &DurableAuditOperationId,
    key_id: &AuditPseudonymKeyId,
    marker: &str,
) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Denial,
        operation_id.clone(),
        DurableAuditPhase::DenialDecision,
        json!({
            "commitment_key_id": key_id.as_str(),
            "subject_handle": "hmac-sha256:test-only-redacted-handle",
            "test_marker": marker,
        }),
    )
    .expect("test pseudonym denial is valid")
}

fn atomic_consultation_attempt_write(
    operation_id: &DurableAuditOperationId,
    key_id: &AuditPseudonymKeyId,
    seed: &Value,
    marker: &str,
) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id.clone(),
        DurableAuditPhase::Attempt,
        json!({
            "authorization": "accepted",
            "completion_seed": seed,
            "commitment_key_id": key_id.as_str(),
            "subject_handle": "hmac-sha256:test-only-redacted-handle",
            "input_commitment": "hmac-sha256:test-only-input-commitment",
            "predicate_commitment": "hmac-sha256:test-only-predicate-commitment",
            "consent_evidence_commitment": null,
            "test_marker": marker,
        }),
    )
    .expect("test atomic consultation attempt is valid")
}

fn future_decision_expiry_unix_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock is after the Unix epoch");
    i64::try_from(now.as_millis()).expect("test time fits the v1 integer") + 60_000
}

fn canonical_test_binding(value: &Value) -> (String, [u8; 32]) {
    let canonical = canonicalize_json(value).expect("test value is canonicalizable");
    let digest = Sha256::digest(&canonical).into();
    let canonical = String::from_utf8(canonical).expect("canonical JSON is UTF-8");
    (canonical, digest)
}

fn completion_seed_value(
    plan_kind: &str,
    credential_operation: Option<&str>,
    _data_operations: &[&str],
    data_slot_allowed_operations: &[Vec<&str>],
) -> Value {
    let mut permit_bindings = Vec::new();
    if credential_operation.is_some() {
        permit_bindings.push(json!({
            "kind": "credential",
            "ordinal": 0,
        }));
    }
    permit_bindings.extend(data_slot_allowed_operations.iter().enumerate().map(
        |(ordinal, _allowed)| {
            json!({
                "kind": "data",
                "ordinal": ordinal,
            })
        },
    ));
    let credential_count = if credential_operation.is_some() { 1 } else { 0 };
    let data_count = data_slot_allowed_operations.len() as i64;
    let is_snapshot = plan_kind == "snapshot_exact";
    let acquisition_fields = if is_snapshot {
        json!({
            "registration_status": {
                "type": "string",
                "nullable": false,
                "max_bytes": 65536,
            },
            "source_observed_at": {
                "type": "string",
                "nullable": false,
                "max_bytes": 64,
            },
            "source_revision": {
                "type": "string",
                "nullable": false,
                "max_bytes": 32,
            },
        })
    } else {
        json!({
            "registration_status": {
                "type": "string",
                "nullable": false,
                "max_bytes": 65536,
            },
        })
    };
    json!({
        "schema": "registry.relay.consultation-completion-seed/v1",
        "correlation": {"notary_evaluation_id": null},
        "profile": {
            "id": "test-profile",
            "version": "1",
            "contract_hash": format!("sha256:{}", "1".repeat(64)),
        },
        "integration_pack": {
            "id": "test-pack",
            "version": "1",
            "hash": format!("sha256:{}", "2".repeat(64)),
        },
        "private_binding_hash": format!("sha256:{}", "3".repeat(64)),
        "workload": {
            "id": "test-workload",
            "tenant_id": "test-tenant",
            "registry_id": "test-registry",
        },
        "purpose": "test-purpose",
        "policy": {
            "id": "test-policy",
            "hash": format!("sha256:{}", "4".repeat(64)),
            "legal_basis_id": "test-legal-basis",
            "consent": {
                "required": false,
                "verifier_id": null,
                "contract_hash": null,
                "decision": "not_required",
            },
            "obligations_digest": format!("sha256:{}", "5".repeat(64)),
        },
        "acquisition": {
            "class": if is_snapshot { "materialized_snapshot" } else { "source_projected_exact" },
            "schema": {
                "type": "acquisition_union",
                "fields": acquisition_fields,
            },
            "disclosure_fields": ["registration_status"],
            "public_outcomes": ["match", "no_match"],
            "provenance_contract": {
                "source_observed_at": if is_snapshot {
                    json!({
                        "type": "acquired_rfc3339",
                        "field": "source_observed_at",
                    })
                } else {
                    Value::Null
                },
                "source_revision": if is_snapshot {
                    json!({
                        "type": "acquired_string",
                        "field": "source_revision",
                        "max_bytes": 32,
                    })
                } else {
                    Value::Null
                },
                "snapshot_generation": if is_snapshot { "required" } else { "absent" },
                "snapshot_published_at": if is_snapshot { "required" } else { "absent" },
            },
        },
        "destinations": {
            "credential_destination_id": credential_operation.map(|_| "credential-destination"),
            "data_destination_id": (!is_snapshot).then_some("data-destination"),
        },
        "credential": {
            "reference": credential_operation.map(|_| "test-credential"),
            "generation": credential_operation.map(|_| 1),
        },
        "dispatch": {
            "plan_kind": plan_kind,
            "permit_bindings": permit_bindings,
        },
        "bounds": {
            "source_matches": 1,
            "disclosed_records": 1,
            "data_exchanges": data_count,
            "credential_exchanges": credential_count,
            "data_destinations": if is_snapshot { 0 } else { 1 },
            "source_bytes": 1048576,
            "timeout_ms": 10000,
            "max_in_flight": 16,
            "quota_rate_per_minute": 60,
            "quota_burst": 10,
            "public_response_bytes": 65536,
            "credential_token_lifetime_ms": credential_operation.map(|_| 86400000),
        },
        "request_digest": format!("sha256:{}", "6".repeat(64)),
        "authorization_context_digest": format!("sha256:{}", "7".repeat(64)),
        "execution_plan_digest": format!("sha256:{}", "8".repeat(64)),
    })
}

async fn persist_test_consultation_attempt(
    plane: &PostgresDurableAuditStatePlane,
    fence: &PostgresServingFence,
    keyring_runtime: &PostgresAuditPseudonymKeyringRuntime,
    key_id: &AuditPseudonymKeyId,
    seed: Value,
    permit_set: ConsultationPermitSet,
    marker: &str,
) -> Result<AuditedConsultationDispatch, Box<dyn std::error::Error>> {
    Ok(persist_test_prepared_dispatch(
        plane,
        fence,
        keyring_runtime,
        key_id,
        seed,
        permit_set,
        marker,
        future_decision_expiry_unix_ms(),
    )
    .await?
    .into_dispatch_for_state_test())
}

#[allow(clippy::too_many_arguments)]
async fn persist_test_prepared_dispatch(
    plane: &PostgresDurableAuditStatePlane,
    fence: &PostgresServingFence,
    keyring_runtime: &PostgresAuditPseudonymKeyringRuntime,
    key_id: &AuditPseudonymKeyId,
    seed: Value,
    permit_set: ConsultationPermitSet,
    marker: &str,
    decision_expires_at_unix_ms: i64,
) -> Result<PreparedAuditedConsultationDispatch<'static>, Box<dyn std::error::Error>> {
    let operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    let write = atomic_consultation_attempt_write(&operation_id, key_id, &seed, marker);
    let timeout_ms = seed["bounds"]["timeout_ms"]
        .as_u64()
        .expect("test seed timeout is present");
    let attempt_authority = fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_millis(timeout_ms))?,
            permit_set,
        )
        .await?;
    let pseudonym_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let prepared = PreparedAtomicConsultationAttempt::for_state_test(
        write,
        seed,
        key_id,
        attempt_authority,
        pseudonym_authority,
        decision_expires_at_unix_ms,
    )?;
    plane
        .write_attempt_with_completion_intent(prepared)
        .await
        .map_err(Into::into)
}

async fn persist_prepared_test_consultation_attempt(
    plane: &PostgresDurableAuditStatePlane,
    write: DurableAuditWrite,
    seed: Value,
    key_id: &AuditPseudonymKeyId,
    attempt_authority: super::FencedConsultationAttemptAuthority,
    pseudonym_authority: super::ActiveAuditPseudonymWriteEpoch,
) -> Result<AuditedConsultationDispatch, Box<dyn std::error::Error>> {
    let prepared = PreparedAtomicConsultationAttempt::for_state_test(
        write,
        seed,
        key_id,
        attempt_authority,
        pseudonym_authority,
        future_decision_expiry_unix_ms(),
    )?;
    let persisted = plane.write_attempt_with_completion_intent(prepared).await?;
    Ok(persisted.into_dispatch_for_state_test())
}

fn rotation_successor(
    current: &AuditPseudonymKeyringMetadata,
    activation_time_unix_ms: i64,
    successor_key_id: &str,
) -> Result<AuditPseudonymKeyringMetadata, PostgresKeyringError> {
    let retained_active = RetainedAuditPseudonymKeyEpoch::new(
        current.active_key_id().clone(),
        activation_time_unix_ms,
        activation_time_unix_ms + current.audit_event_retention_ms() + 1_000,
    )
    .map_err(|_| PostgresKeyringError::InvalidRotation)?;
    AuditPseudonymKeyringMetadata::new(
        current.generation() + 1,
        pseudonym_key_id(successor_key_id),
        activation_time_unix_ms,
        current.active_write_deadline_unix_ms() + 120_000,
        current.audit_event_retention_ms(),
        vec![retained_active],
    )
    .map_err(|_| PostgresKeyringError::InvalidRotation)
}

async fn direct_snapshot(
    client: &(impl GenericClient + Sync),
    write: &DurableAuditWrite,
) -> Result<DirectCandidate, Box<dyn std::error::Error>> {
    let row = client
        .query_one(
            SNAPSHOT_SQL,
            &[
                &write.key().stream_kind().as_str(),
                &write.key().operation_id().as_str(),
                &write.key().phase().as_str(),
                &write.payload_digest().as_bytes().as_slice(),
                &"test-chain-key-epoch-1",
                &Option::<&str>::None,
                &Option::<i64>::None,
                &Option::<&[u8]>::None,
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    assert_eq!(row.try_get::<_, &str>("outcome")?, "candidate");
    let predecessor = row
        .try_get::<_, Option<Vec<u8>>>("candidate_predecessor_hash")?
        .map(|bytes| bytes.as_slice().try_into())
        .transpose()?;
    Ok(DirectCandidate {
        predecessor,
        generation: row.try_get("candidate_generation")?,
    })
}

async fn direct_cas(
    client: &(impl GenericClient + Sync),
    write: &DurableAuditWrite,
    candidate: &DirectCandidate,
    envelope: &AuditEnvelope,
) -> Result<String, Box<dyn std::error::Error>> {
    let record_json = serde_json::to_string(&envelope.record)?;
    let envelope_json = serde_json::to_string(envelope)?;
    let predecessor = candidate.predecessor.as_ref().map(<[u8; 32]>::as_slice);
    let no_attempt_envelope: Option<&str> = None;
    let no_attempt_hash: Option<&[u8]> = None;
    let no_pseudonym_key_id: Option<&str> = None;
    let no_pseudonym_generation: Option<i64> = None;
    let no_pseudonym_digest: Option<&[u8]> = None;
    let row = client
        .query_one(
            CAS_SQL,
            &[
                &write.key().stream_kind().as_str(),
                &write.key().operation_id().as_str(),
                &write.key().phase().as_str(),
                &write.payload_digest().as_bytes().as_slice(),
                &candidate.generation,
                &predecessor,
                &envelope.envelope_id,
                &envelope.timestamp_unix_ms,
                &record_json,
                &envelope_json,
                &envelope.record_hash.as_slice(),
                &no_attempt_envelope,
                &no_attempt_hash,
                &no_pseudonym_key_id,
                &no_pseudonym_generation,
                &no_pseudonym_digest,
                &"test-chain-key-epoch-1",
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    Ok(row.try_get("outcome")?)
}

async fn set_role(client: &Client, role: &str) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute(&format!("SET ROLE {}", quote_identifier(role)))
        .await
}

async fn reset_role(client: &Client) -> Result<(), tokio_postgres::Error> {
    client.batch_execute("RESET ROLE").await
}

async fn wait_for_fence_unlock(
    client: &Client,
    lock_key: ServingFenceLockKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let unlocked: bool = client
            .query_one(
                "SELECT NOT EXISTS ( \
                     SELECT 1 FROM pg_catalog.pg_locks AS lock_row \
                     WHERE lock_row.locktype = 'advisory' \
                       AND lock_row.database = ( \
                           SELECT database_row.oid FROM pg_catalog.pg_database AS database_row \
                           WHERE database_row.datname = current_database() \
                       ) \
                       AND lock_row.classid::bigint = (($1::bigint >> 32) & 4294967295) \
                       AND lock_row.objid::bigint = ($1::bigint & 4294967295) \
                       AND lock_row.objsubid = 1 AND lock_row.granted \
                 ) AS unlocked",
                &[&lock_key.as_i64()],
            )
            .await?
            .try_get("unlocked")?;
        if unlocked {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("serving-fence advisory lock did not release".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_blocked_quota_query(
    admin: &Client,
    runtime_role: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    // Test-harness observation window only. Product SQL still owns its fixed
    // two-second lock timeout; allow a loaded test executor time to schedule
    // the contender before deciding that it never reached PostgreSQL.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked = blocked_quota_query_count(admin, runtime_role).await?;
        if blocked > 0 {
            return Ok(blocked);
        }
        if Instant::now() >= deadline {
            return Err("quota query did not reach the PostgreSQL lock wait".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_blocked_consultation_query(
    admin: &Client,
    runtime_role: &str,
    function_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let query_pattern = format!("%{function_name}%");
    loop {
        admin
            .batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
            .await?;
        let blocked: i64 = admin
            .query_one(
                "SELECT count(*) FROM pg_catalog.pg_stat_activity \
                 WHERE usename = $1 AND state = 'active' \
                   AND wait_event_type = 'Lock' AND query LIKE $2",
                &[&runtime_role, &query_pattern],
            )
            .await?
            .try_get(0)?;
        if blocked > 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{function_name} did not reach the PostgreSQL lock wait").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn direct_test_fence_acquire(
    client: &Client,
    lock_key: ServingFenceLockKey,
) -> Result<(String, i64, bool, bool), Box<dyn std::error::Error>> {
    client.batch_execute(RUNTIME_SESSION_LIMITS_SQL).await?;
    let holder_id = Ulid::new().to_string();
    let row = client
        .query_one(
            "SELECT * FROM relay_state_api.serving_fence_acquire_v1($1, $2)",
            &[&lock_key.as_i64(), &holder_id],
        )
        .await?;
    if row.try_get::<_, &str>("outcome")? != "acquired" {
        return Err("direct test successor did not acquire the serving fence".into());
    }
    Ok((
        holder_id,
        row.try_get("fence_generation")?,
        row.try_get("takeover_required")?,
        row.try_get("admission_open")?,
    ))
}

async fn direct_test_fence_finalize(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let row = client
            .query_one(
                "SELECT * FROM relay_state_api.serving_fence_finalize_v1($1, $2, $3)",
                &[&lock_key.as_i64(), &holder_id, &generation],
            )
            .await?;
        match row.try_get::<_, &str>("outcome")? {
            "recovery_ready" => return Ok(row.try_get("recovery_operation_ids")?),
            "barrier_pending" => {
                let remaining_ms = row.try_get::<_, i64>("remaining_ms")?;
                if remaining_ms <= 0 || Instant::now() >= deadline {
                    return Err("direct test successor did not reach its takeover barrier".into());
                }
                tokio::time::sleep(Duration::from_millis(u64::try_from(remaining_ms.min(250))?))
                    .await;
            }
            outcome => return Err(format!("unexpected direct finalize outcome: {outcome}").into()),
        }
    }
}

fn direct_test_recovery_authority(
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
    operation_ids: Vec<String>,
) -> Result<TakeoverCompletionRecoveryAuthority, ServingFenceError> {
    Ok(TakeoverCompletionRecoveryAuthority {
        lock_key,
        holder_id: holder_id.to_owned(),
        fence_generation: generation,
        operation_ids: operation_ids
            .iter()
            .map(|operation_id| DispatchOperationId::parse(operation_id))
            .collect::<Result<Vec<_>, _>>()?,
        next_index: 0,
    })
}

async fn direct_test_fence_open(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(client
        .query_one(
            "SELECT outcome FROM relay_state_api.serving_fence_open_after_recovery_v1(\
                 $1, $2, $3\
             )",
            &[&lock_key.as_i64(), &holder_id, &generation],
        )
        .await?
        .try_get("outcome")?)
}

async fn direct_test_fence_release(
    client: &Client,
    lock_key: ServingFenceLockKey,
    holder_id: &str,
    generation: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let outcome: String = client
        .query_one(
            "SELECT outcome FROM relay_state_api.serving_fence_release_v1($1, $2, $3)",
            &[&lock_key.as_i64(), &holder_id, &generation],
        )
        .await?
        .try_get("outcome")?;
    if outcome != "released" {
        return Err(format!("unexpected direct release outcome: {outcome}").into());
    }
    Ok(())
}

async fn blocked_quota_query_count(
    admin: &Client,
    runtime_role: &str,
) -> Result<i64, tokio_postgres::Error> {
    admin
        .batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
        .await?;
    admin
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_stat_activity \
             WHERE usename = $1 AND state = 'active' \
               AND wait_event_type = 'Lock' \
               AND query LIKE '%relay_state_api.quota_reserve_v1%'",
            &[&runtime_role],
        )
        .await?
        .try_get(0)
}

async fn seed_catalog_for_unsafe_restart(
    client: &Client,
    runtime_role_name: &str,
    maintenance_role_name: &str,
    reader_role_name: &str,
    chain_key_epoch_id: &AuditChainKeyEpochId,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await?;
    client
        .execute(
            "INSERT INTO relay_state_private.state_plane_metadata ( \
                 singleton, schema_version, capability_id, capability_fingerprint, \
                 owner_role_oid, runtime_role_oid, audit_pseudonym_maintenance_role_oid, \
                 audit_pseudonym_reader_role_oid, chain_key_epoch_id, \
                 serving_fence_capability_id, serving_fence_lock_key, quota_capability_id, \
                 audit_pseudonym_keyring_capability_id, audit_pseudonym_keyring_lock_key \
             ) SELECT true, 1, $1, $2, owner_role.oid, runtime_role.oid, \
                      maintenance_role.oid, reader_role.oid, $3, $4, $5, $6, $7, $8 \
             FROM pg_catalog.pg_roles AS owner_role \
             JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.rolname = $9 \
             JOIN pg_catalog.pg_roles AS maintenance_role ON maintenance_role.rolname = $10 \
             JOIN pg_catalog.pg_roles AS reader_role ON reader_role.rolname = $11 \
             WHERE owner_role.rolname = current_user",
            &[
                &DURABLE_AUDIT_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &chain_key_epoch_id.as_str(),
                &SERVING_FENCE_CAPABILITY_V1,
                &test_serving_fence_lock_key().as_i64(),
                &PERSISTENT_QUOTA_CAPABILITY_V1,
                &AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1,
                &test_pseudonym_keyring_lock_key().as_i64(),
                &runtime_role_name,
                &maintenance_role_name,
                &reader_role_name,
            ],
        )
        .await?;
    client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_api TO {runtime}, {maintenance}, {reader}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_phase_snapshot_v1( \
                     text, text, text, bytea, text, text, bigint, bytea, bigint \
                 ) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_phase_duplicate_v1( \
                     text, text, text, bytea, text, bigint \
                 ) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_cas_v1( \
                 text, text, text, bytea, bigint, bytea, text, bigint, \
                 text, text, bytea, text, bytea, text, bigint, bytea, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_open_after_recovery_v1( \
                 bigint, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_attempt_intent_snapshot_v1( \
                 text, bytea, text, bytea, text, bytea, text, bigint, bytea, bigint, \
                 text, bigint, integer, bigint, text[], smallint[], text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_attempt_intent_cas_v1( \
                 text, bytea, bigint, bytea, text, bigint, text, text, bytea, text, \
                 bytea, text, bytea, text, bigint, bytea, bigint, text, bigint, integer, \
                 bigint, text[], smallint[], text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_snapshot_normal_v1( \
                 text, bigint, text, bigint, bigint, text[], smallint[], text, bigint, \
                 bytea, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_snapshot_recovery_v1( \
                 text, bigint, text, bigint, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_normal_v1( \
                 text, bigint, text, bigint, bigint, text[], smallint[], text, bigint, \
                 bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_unfinished_v1( \
                 text, bigint, text, bigint, bigint, text[], smallint[], text, bigint, \
                 bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_recovery_v1( \
                 text, bigint, text, bigint, bytea, bigint, bytea, text, bigint, text, \
                 text, bytea, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_authorize_v1( \
                 bigint, text, bigint, text, text, smallint, text, bigint \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_release_v1(bigint, text, bigint) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.quota_reserve_v1( \
                 text, text, bigint, integer, integer \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_pseudonym_keyring_snapshot_v1( \
                     text, text[], text, bigint \
                 ) \
                 TO {runtime}, {maintenance}, {reader}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_pseudonym_keyring_readiness_v1(text, text) \
                 TO {runtime}, {maintenance}, {reader}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_pseudonym_keyring_initialize_v1( \
                     bigint, bytea, text, text, bigint, bigint, bigint, \
                     text[], bigint[], bigint[], text, bigint \
                 ) TO {maintenance}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_pseudonym_keyring_rotate_v1( \
                     bigint, bytea, bigint, bytea, bigint, bigint, bytea, \
                     text, text, bigint, bigint, bigint, text[], bigint[], bigint[], \
                     text, bigint \
                 ) TO {maintenance}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_pseudonym_keyring_maintain_v1( \
                     bigint, bytea, bigint, bytea, bigint, bigint, bytea, \
                     text, text, bigint, bigint, bigint, text[], bigint[], bigint[], \
                     text, bigint \
                 ) TO {maintenance};",
            runtime = quote_identifier(runtime_role_name),
            maintenance = quote_identifier(maintenance_role_name),
            reader = quote_identifier(reader_role_name),
        ))
        .await?;
    Ok(())
}

fn effective_quota_limits(rate_per_minute: u16, burst_tokens: u8) -> EffectiveQuotaLimits {
    EffectiveQuotaLimits::lowered_from(
        PublicQuotaLimits::v1_default(),
        rate_per_minute,
        burst_tokens,
    )
    .expect("test quota is within the public v1 maxima")
}

fn expect_quota_allowed(reservation: QuotaReservation) -> QuotaGrant {
    match reservation {
        QuotaReservation::Allowed(grant) => grant,
        QuotaReservation::Exhausted(_) => panic!("expected quota authority"),
    }
}

fn expect_quota_exhausted(reservation: QuotaReservation) -> Duration {
    match reservation {
        QuotaReservation::Allowed(_) => panic!("expected quota exhaustion"),
        QuotaReservation::Exhausted(exhaustion) => exhaustion.into_retry_after(),
    }
}

struct QuotaTestContext<'a> {
    database_url: &'a str,
    owner_role: &'a str,
    runtime_role: &'a str,
    runtime_password: &'a str,
    attacker_role: &'a str,
    attacker_password: &'a str,
    chain_key_epoch_id: &'a AuditChainKeyEpochId,
}

async fn exercise_postgres_quota_contract(
    admin: &Client,
    context: QuotaTestContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let QuotaTestContext {
        database_url,
        owner_role,
        runtime_role,
        runtime_password,
        attacker_role,
        attacker_password,
        chain_key_epoch_id,
    } = context;
    let limits = effective_quota_limits(1, 10);
    let (hostile_client, hostile_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    hostile_client
        .batch_execute("BEGIN; SET LOCAL search_path = public; SET LOCAL synchronous_commit = off;")
        .await?;
    let burst_plane =
        PostgresQuotaStatePlane::connect(hostile_client, chain_key_epoch_id.clone()).await?;
    assert_eq!(burst_plane.readiness().await, QuotaReadiness::Ready);
    for _ in 0..10 {
        let grant = expect_quota_allowed(
            burst_plane
                .reserve(QuotaKey::for_test("opencrvs", "quota.burst", 1), limits)
                .await?,
        );
        assert!(!format!("{grant:?}").contains("opencrvs"));
    }
    let retry = expect_quota_exhausted(
        burst_plane
            .reserve(QuotaKey::for_test("opencrvs", "quota.burst", 1), limits)
            .await?,
    );
    assert!(retry > Duration::ZERO && retry <= Duration::from_secs(60));
    drop(burst_plane);
    hostile_driver.abort();

    let (restart_client, restart_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let restart_plane =
        PostgresQuotaStatePlane::connect(restart_client, chain_key_epoch_id.clone()).await?;
    let _ = expect_quota_exhausted(
        restart_plane
            .reserve(QuotaKey::for_test("opencrvs", "quota.burst", 1), limits)
            .await?,
    );
    drop(restart_plane);
    restart_driver.abort();

    let mut concurrent_tasks = Vec::new();
    let mut concurrent_drivers = Vec::new();
    for _ in 0..16 {
        let (client, driver) =
            postgres_client_as(database_url, runtime_role, runtime_password).await?;
        let plane = PostgresQuotaStatePlane::connect(client, chain_key_epoch_id.clone()).await?;
        concurrent_drivers.push(driver);
        concurrent_tasks.push(tokio::spawn(async move {
            plane
                .reserve(QuotaKey::for_test("dhis2", "quota.concurrent", 1), limits)
                .await
        }));
    }
    let mut concurrent_allowed = 0;
    let mut concurrent_exhausted = 0;
    for task in concurrent_tasks {
        let reservation = task.await??;
        match reservation {
            QuotaReservation::Allowed(_grant) => concurrent_allowed += 1,
            QuotaReservation::Exhausted(exhaustion) => {
                assert!(exhaustion.into_retry_after() <= Duration::from_secs(60));
                concurrent_exhausted += 1;
            }
        }
    }
    assert_eq!(concurrent_allowed, 10);
    assert_eq!(concurrent_exhausted, 6);
    for driver in concurrent_drivers {
        driver.abort();
    }

    let (mixed_client_a, mixed_driver_a) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let (mixed_client_b, mixed_driver_b) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let mixed_plane_a =
        PostgresQuotaStatePlane::connect(mixed_client_a, chain_key_epoch_id.clone()).await?;
    let mixed_plane_b =
        PostgresQuotaStatePlane::connect(mixed_client_b, chain_key_epoch_id.clone()).await?;
    let mixed_barrier = Arc::new(Barrier::new(3));
    let barrier_a = Arc::clone(&mixed_barrier);
    let barrier_b = Arc::clone(&mixed_barrier);
    let limits_a = effective_quota_limits(12, 3);
    let limits_b = effective_quota_limits(24, 5);
    let mixed_a = tokio::spawn(async move {
        barrier_a.wait().await;
        let result = mixed_plane_a
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.mixed-first-use", 1),
                limits_a,
            )
            .await;
        (mixed_plane_a, result)
    });
    let mixed_b = tokio::spawn(async move {
        barrier_b.wait().await;
        let result = mixed_plane_b
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.mixed-first-use", 1),
                limits_b,
            )
            .await;
        (mixed_plane_b, result)
    });
    mixed_barrier.wait().await;
    let (mixed_plane_a, result_a) = mixed_a.await?;
    let (mixed_plane_b, result_b) = mixed_b.await?;
    let a_won = matches!(&result_a, Ok(QuotaReservation::Allowed(_)));
    let b_won = matches!(&result_b, Ok(QuotaReservation::Allowed(_)));
    assert_ne!(a_won, b_won, "exactly one first-use configuration wins");
    assert_eq!(
        mixed_plane_a.readiness().await,
        if a_won {
            QuotaReadiness::Ready
        } else {
            QuotaReadiness::Unavailable
        }
    );
    assert_eq!(
        mixed_plane_b.readiness().await,
        if b_won {
            QuotaReadiness::Ready
        } else {
            QuotaReadiness::Unavailable
        }
    );
    let winning_limits = if a_won { (12_i32, 3_i32) } else { (24, 5) };
    let mixed_row = admin
        .query_one(
            "SELECT rate_per_minute, burst_tokens, tokens_numerator \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.mixed-first-use' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    assert_eq!(
        mixed_row.try_get::<_, i32>("rate_per_minute")?,
        winning_limits.0
    );
    assert_eq!(
        mixed_row.try_get::<_, i32>("burst_tokens")?,
        winning_limits.1
    );
    assert_eq!(
        mixed_row.try_get::<_, i64>("tokens_numerator")?,
        i64::from(winning_limits.1) * 60_000_000 - 60_000_000
    );
    match (result_a, result_b) {
        (Ok(QuotaReservation::Allowed(_grant)), Err(QuotaError::LimitMismatch))
        | (Err(QuotaError::LimitMismatch), Ok(QuotaReservation::Allowed(_grant))) => {}
        _ => panic!("mixed first-use race returned an unexpected outcome"),
    }
    drop(mixed_plane_a);
    drop(mixed_plane_b);
    mixed_driver_a.abort();
    mixed_driver_b.abort();

    let (arithmetic_client, arithmetic_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let arithmetic_plane =
        PostgresQuotaStatePlane::connect(arithmetic_client, chain_key_epoch_id.clone()).await?;

    let sustained_limits = effective_quota_limits(60, 1);
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.sustained", 1),
                sustained_limits,
            )
            .await?,
    );
    admin
        .execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() - interval '1 second' \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.sustained' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.sustained", 1),
                sustained_limits,
            )
            .await?,
    );
    let sustained_tokens: i64 = admin
        .query_one(
            "SELECT tokens_numerator \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.sustained' \
               AND profile_version = 1",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(sustained_tokens, 0);

    let retry_limits = effective_quota_limits(7, 1);
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.retry-ceil", 1),
                retry_limits,
            )
            .await?,
    );
    admin
        .execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.retry-ceil' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    let normal_retry = expect_quota_exhausted(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.retry-ceil", 1),
                retry_limits,
            )
            .await?,
    );
    let retry_tokens: i64 = admin
        .query_one(
            "SELECT tokens_numerator \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.retry-ceil' \
               AND profile_version = 1",
            &[],
        )
        .await?
        .try_get(0)?;
    let token_wait_us = (60_000_000 - retry_tokens + 6) / 7;
    let expected_retry_ms = (token_wait_us + 999) / 1_000;
    assert_eq!(normal_retry.as_millis(), expected_retry_ms as u128);

    let fractional_limits = effective_quota_limits(7, 1);
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.fractional", 1),
                fractional_limits,
            )
            .await?,
    );
    admin
        .execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.fractional' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    for _ in 0..8 {
        let _ = expect_quota_exhausted(
            arithmetic_plane
                .reserve(
                    QuotaKey::for_test("dhis2", "quota.fractional", 1),
                    fractional_limits,
                )
                .await?,
        );
    }
    let fractional_tokens: i64 = admin
        .query_one(
            "SELECT tokens_numerator \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.fractional' \
               AND profile_version = 1",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(fractional_tokens > 0);
    assert_eq!(
        fractional_tokens % 7,
        0,
        "fractional refill is never rounded away"
    );
    admin
        .execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET last_refill_at = last_refill_at - \
                 ((60000000 - tokens_numerator + 6) / 7) * interval '1 microsecond' \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.fractional' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.fractional", 1),
                fractional_limits,
            )
            .await?,
    );

    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.backward", 1),
                sustained_limits,
            )
            .await?,
    );
    let backward_before: String = admin
        .query_one(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() + interval '500 milliseconds' \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.backward' \
               AND profile_version = 1 RETURNING last_refill_at::text",
            &[],
        )
        .await?
        .try_get(0)?;
    let rollback_retry = expect_quota_exhausted(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.backward", 1),
                sustained_limits,
            )
            .await?,
    );
    assert!(rollback_retry > Duration::from_millis(1_000));
    assert!(rollback_retry <= Duration::from_millis(1_500));
    let backward_after: String = admin
        .query_one(
            "SELECT last_refill_at::text \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.backward' \
               AND profile_version = 1",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(backward_after, backward_before);

    let forward_limits = effective_quota_limits(1, 2);
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.forward", 1),
                forward_limits,
            )
            .await?,
    );
    admin
        .execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() - interval '100 years' \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.forward' \
               AND profile_version = 1",
            &[],
        )
        .await?;
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.forward", 1),
                forward_limits,
            )
            .await?,
    );
    let capped_tokens: i64 = admin
        .query_one(
            "SELECT tokens_numerator \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.forward' \
               AND profile_version = 1",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(capped_tokens, 60_000_000);

    let bound_limits = effective_quota_limits(30, 5);
    let _grant = expect_quota_allowed(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.bound-limits", 1),
                bound_limits,
            )
            .await?,
    );
    let before_mismatch: (i64, String) = admin
        .query_one(
            "SELECT tokens_numerator, last_refill_at::text \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.bound-limits' \
               AND profile_version = 1",
            &[],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert!(matches!(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.bound-limits", 1),
                effective_quota_limits(20, 4),
            )
            .await,
        Err(QuotaError::LimitMismatch)
    ));
    assert_eq!(
        arithmetic_plane.readiness().await,
        QuotaReadiness::Unavailable
    );
    assert!(matches!(
        arithmetic_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.bound-limits", 1),
                bound_limits,
            )
            .await,
        Err(QuotaError::Unavailable)
    ));
    let after_mismatch: (i64, String) = admin
        .query_one(
            "SELECT tokens_numerator, last_refill_at::text \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' AND profile_id = 'quota.bound-limits' \
               AND profile_version = 1",
            &[],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert_eq!(after_mismatch, before_mismatch);
    drop(arithmetic_plane);
    arithmetic_driver.abort();

    let (clock_client, clock_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let clock_plane =
        PostgresQuotaStatePlane::connect(clock_client, chain_key_epoch_id.clone()).await?;
    let _grant = expect_quota_allowed(
        clock_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.clock-anomaly", 1),
                sustained_limits,
            )
            .await?,
    );
    let clock_before: (i64, String) = admin
        .query_one(
            "UPDATE relay_state_private.consultation_quota_bucket \
             SET tokens_numerator = 0, last_refill_at = clock_timestamp() + interval '2 minutes' \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.clock-anomaly' \
               AND profile_version = 1 \
             RETURNING tokens_numerator, last_refill_at::text",
            &[],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert!(matches!(
        clock_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.clock-anomaly", 1),
                sustained_limits,
            )
            .await,
        Err(QuotaError::ClockAnomaly)
    ));
    assert_eq!(clock_plane.readiness().await, QuotaReadiness::Unavailable);
    let clock_after: (i64, String) = admin
        .query_one(
            "SELECT tokens_numerator, last_refill_at::text \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'dhis2' AND profile_id = 'quota.clock-anomaly' \
               AND profile_version = 1",
            &[],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert_eq!(clock_after, clock_before);
    drop(clock_plane);
    clock_driver.abort();

    admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_api TO {attacker}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.quota_reserve_v1( \
                 text, text, bigint, integer, integer \
             ) TO {attacker};",
            attacker = quote_identifier(attacker_role),
        ))
        .await?;
    let (attacker_client, attacker_driver) =
        postgres_client_as(database_url, attacker_role, attacker_password).await?;
    attacker_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let attacker_error = attacker_client
        .query_one(
            "SELECT * FROM relay_state_api.quota_reserve_v1($1, $2, $3, $4, $5)",
            &[&"attacker", &"quota.denied", &1_i64, &1_i32, &1_i32],
        )
        .await
        .expect_err("unbound role must never reserve quota");
    assert_eq!(
        attacker_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(attacker_client);
    attacker_driver.abort();
    admin
        .batch_execute(&format!(
            "REVOKE EXECUTE ON FUNCTION relay_state_api.quota_reserve_v1( \
                 text, text, bigint, integer, integer \
             ) FROM {attacker}; \
             REVOKE USAGE ON SCHEMA relay_state_api FROM {attacker};",
            attacker = quote_identifier(attacker_role),
        ))
        .await?;

    let (corrupt_client, corrupt_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let corrupt_plane =
        PostgresQuotaStatePlane::connect(corrupt_client, chain_key_epoch_id.clone()).await?;
    let _grant = expect_quota_allowed(
        corrupt_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.corrupt", 1),
                sustained_limits,
            )
            .await?,
    );
    set_role(admin, owner_role).await?;
    admin
        .batch_execute(
            r#"
ALTER TABLE relay_state_private.consultation_quota_bucket
    DROP CONSTRAINT consultation_quota_bucket_tokens_check;
UPDATE relay_state_private.consultation_quota_bucket
SET tokens_numerator = -1
WHERE workload_id = 'dhis2' AND profile_id = 'quota.corrupt' AND profile_version = 1;
CREATE OR REPLACE FUNCTION relay_state_private.capability_valid_v1()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
SELECT true;
$function$;
"#,
        )
        .await?;
    reset_role(admin).await?;
    assert!(matches!(
        corrupt_plane
            .reserve(
                QuotaKey::for_test("dhis2", "quota.corrupt", 1),
                sustained_limits,
            )
            .await,
        Err(QuotaError::CapabilityDrift)
    ));
    assert_eq!(corrupt_plane.readiness().await, QuotaReadiness::Unavailable);
    drop(corrupt_plane);
    corrupt_driver.abort();
    set_role(admin, owner_role).await?;
    admin
        .batch_execute(
            "UPDATE relay_state_private.consultation_quota_bucket \
                 SET tokens_numerator = 0, last_refill_at = clock_timestamp() \
                 WHERE workload_id = 'dhis2' AND profile_id = 'quota.corrupt' \
                   AND profile_version = 1; \
             ALTER TABLE relay_state_private.consultation_quota_bucket \
                 ADD CONSTRAINT consultation_quota_bucket_tokens_check CHECK ( \
                     tokens_numerator BETWEEN 0 AND burst_tokens::bigint * 60000000 \
                 );",
        )
        .await?;
    admin
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await?;
    reset_role(admin).await?;

    let (waiter_client, waiter_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let waiter_plane = Arc::new(
        PostgresQuotaStatePlane::connect(waiter_client, chain_key_epoch_id.clone()).await?,
    );
    admin
        .batch_execute(
            "BEGIN; LOCK TABLE relay_state_private.consultation_quota_bucket \
             IN ACCESS EXCLUSIVE MODE;",
        )
        .await?;
    let plane_a = Arc::clone(&waiter_plane);
    let in_flight_a = tokio::spawn(async move {
        plane_a
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.waiter-a", 1),
                sustained_limits,
            )
            .await
    });
    assert_eq!(
        wait_for_blocked_quota_query(admin, runtime_role).await?,
        1,
        "only A has sent quota SQL"
    );
    let plane_b = Arc::clone(&waiter_plane);
    let queued_b = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            plane_b.reserve(
                QuotaKey::for_test("opencrvs", "quota.waiter-b", 1),
                sustained_limits,
            ),
        )
        .await
    });
    assert!(
        queued_b.await?.is_err(),
        "B is cancelled while queued locally"
    );
    assert_eq!(
        wait_for_blocked_quota_query(admin, runtime_role).await?,
        1,
        "cancelled B sent zero SQL"
    );
    admin.batch_execute("ROLLBACK").await?;
    let _grant = expect_quota_allowed(in_flight_a.await??);
    let waiter_rows = admin
        .query_one(
            "SELECT count(*) FILTER (WHERE profile_id = 'quota.waiter-a') AS a_rows, \
                    count(*) FILTER (WHERE profile_id = 'quota.waiter-b') AS b_rows, \
                    count(*) AS total_rows \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' \
               AND profile_id IN ('quota.waiter-a', 'quota.waiter-b') \
               AND profile_version = 1",
            &[],
        )
        .await?;
    assert_eq!(waiter_rows.try_get::<_, i64>("a_rows")?, 1);
    assert_eq!(waiter_rows.try_get::<_, i64>("b_rows")?, 0);
    assert_eq!(waiter_rows.try_get::<_, i64>("total_rows")?, 1);
    assert_eq!(waiter_plane.readiness().await, QuotaReadiness::Ready);
    let _fresh_grant = expect_quota_allowed(
        waiter_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.waiter-fresh", 1),
                sustained_limits,
            )
            .await?,
    );
    assert_eq!(waiter_plane.readiness().await, QuotaReadiness::Ready);
    drop(waiter_plane);
    waiter_driver.abort();

    let (cancel_client, cancel_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    let cancel_plane = Arc::new(
        PostgresQuotaStatePlane::connect(cancel_client, chain_key_epoch_id.clone()).await?,
    );
    admin
        .batch_execute(
            "BEGIN; LOCK TABLE relay_state_private.consultation_quota_bucket \
             IN ACCESS EXCLUSIVE MODE;",
        )
        .await?;
    let cancel_plane_a = Arc::clone(&cancel_plane);
    let uncertain_a = tokio::spawn(async move {
        cancel_plane_a
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.sealed-a", 1),
                sustained_limits,
            )
            .await
    });
    assert_eq!(wait_for_blocked_quota_query(admin, runtime_role).await?, 1);
    let cancel_plane_b = Arc::clone(&cancel_plane);
    let sealed_waiter_b = tokio::spawn(async move {
        cancel_plane_b
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.sealed-b", 1),
                sustained_limits,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    uncertain_a.abort();
    assert!(uncertain_a
        .await
        .expect_err("A must be cancelled")
        .is_cancelled());
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), sealed_waiter_b).await??,
        Err(QuotaError::Unavailable)
    ));
    assert!(
        blocked_quota_query_count(admin, runtime_role).await? <= 1,
        "sealed B rechecked availability and sent zero SQL"
    );
    assert_eq!(cancel_plane.readiness().await, QuotaReadiness::Unavailable);
    assert!(matches!(
        cancel_plane
            .reserve(
                QuotaKey::for_test("opencrvs", "quota.sealed-fresh", 1),
                sustained_limits,
            )
            .await,
        Err(QuotaError::Unavailable)
    ));
    admin.batch_execute("ROLLBACK").await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cancelled_rows = admin
        .query_one(
            "SELECT count(*) FILTER (WHERE profile_id = 'quota.sealed-a') AS a_rows, \
                    count(*) FILTER (WHERE profile_id = 'quota.sealed-b') AS b_rows, \
                    count(*) AS total_rows \
             FROM relay_state_private.consultation_quota_bucket \
             WHERE workload_id = 'opencrvs' \
               AND profile_id IN ('quota.sealed-a', 'quota.sealed-b') \
               AND profile_version = 1",
            &[],
        )
        .await?;
    assert!((0..=1).contains(&cancelled_rows.try_get::<_, i64>("a_rows")?));
    assert_eq!(cancelled_rows.try_get::<_, i64>("b_rows")?, 0);
    assert!((0..=1).contains(&cancelled_rows.try_get::<_, i64>("total_rows")?));
    drop(cancel_plane);
    cancel_driver.abort();

    Ok(())
}

fn order_chain(mut envelopes: Vec<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let expected_len = envelopes.len();
    let mut by_predecessor: HashMap<Option<[u8; 32]>, AuditEnvelope> = envelopes
        .drain(..)
        .map(|envelope| (envelope.prev_hash, envelope))
        .collect();
    assert_eq!(
        by_predecessor.len(),
        expected_len,
        "stored chain must not fork"
    );
    let mut ordered = Vec::with_capacity(by_predecessor.len());
    let mut predecessor = None;
    while let Some(envelope) = by_predecessor.remove(&predecessor) {
        predecessor = Some(envelope.record_hash);
        ordered.push(envelope);
    }
    assert!(by_predecessor.is_empty(), "stored chain must be linear");
    ordered
}

async fn exercise_batch_child_replay_reservation_contract(
    database_url: &str,
    admin: &Client,
    owner_role: &str,
    runtime_role: &str,
    runtime_password: &str,
    attacker_role: &str,
    attacker_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const RESERVE: &str =
        "SELECT * FROM relay_state_api.consultation_batch_child_reserve_v1($1, $2, $3)";
    const RELEASE: &str = "SELECT relay_state_api.consultation_batch_child_release_v1($1, $2, $3)";
    let (runtime, runtime_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    runtime.batch_execute(RUNTIME_SESSION_LIMITS_SQL).await?;
    let child_key = vec![0x11_u8; 32];
    let binding = vec![0x22_u8; 32];
    let different_binding = vec![0x33_u8; 32];
    let first_operation = Ulid::new().to_string();
    let second_operation = Ulid::new().to_string();

    let reserved = runtime
        .query_one(RESERVE, &[&child_key, &binding, &first_operation])
        .await?;
    assert_eq!(reserved.get::<_, &str>("outcome"), "reserved");
    assert_eq!(
        reserved.get::<_, Option<&str>>("stored_operation_id"),
        Some(first_operation.as_str())
    );
    assert!(reserved
        .get::<_, Option<&str>>("terminal_payload")
        .is_none());

    let in_progress = runtime
        .query_one(RESERVE, &[&child_key, &binding, &second_operation])
        .await?;
    assert_eq!(in_progress.get::<_, &str>("outcome"), "in_progress");
    assert_eq!(
        in_progress.get::<_, Option<&str>>("stored_operation_id"),
        Some(first_operation.as_str())
    );

    let conflict = runtime
        .query_one(
            RESERVE,
            &[&child_key, &different_binding, &second_operation],
        )
        .await?;
    assert_eq!(conflict.get::<_, &str>("outcome"), "conflict");
    assert!(conflict
        .get::<_, Option<&str>>("stored_operation_id")
        .is_none());
    set_role(admin, owner_role).await?;
    let zero_dispatch = admin
        .query_one(
            "SELECT \
                (SELECT count(*) FROM relay_state_private.consultation_quota_bucket) AS quota_rows, \
                (SELECT count(*) FROM relay_state_private.dispatch_permit) AS permit_rows, \
                (SELECT count(*) FROM relay_state_private.audit_phase) AS audit_rows",
            &[],
        )
        .await?;
    assert_eq!(zero_dispatch.get::<_, i64>("quota_rows"), 0);
    assert_eq!(zero_dispatch.get::<_, i64>("permit_rows"), 0);
    assert_eq!(zero_dispatch.get::<_, i64>("audit_rows"), 0);
    reset_role(admin).await?;

    let (attacker, attacker_driver) =
        postgres_client_as(database_url, attacker_role, attacker_password).await?;
    let denied = attacker
        .query_one(RESERVE, &[&child_key, &binding, &second_operation])
        .await
        .expect_err("unbound role cannot execute the private replay capability");
    assert_eq!(denied.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    let private_read = runtime
        .query_one(
            "SELECT child_key FROM relay_state_private.consultation_batch_child_replay LIMIT 1",
            &[],
        )
        .await
        .expect_err("runtime has no direct private replay-table access");
    assert_eq!(private_read.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
    drop(attacker);
    attacker_driver.abort();

    let released: bool = runtime
        .query_one(RELEASE, &[&child_key, &binding, &first_operation])
        .await?
        .get(0);
    assert!(released);
    let reserved_again = runtime
        .query_one(RESERVE, &[&child_key, &binding, &second_operation])
        .await?;
    assert_eq!(reserved_again.get::<_, &str>("outcome"), "reserved");

    set_role(admin, owner_role).await?;
    admin
        .execute(
            "UPDATE relay_state_private.consultation_batch_child_replay \
             SET created_at = expired.at, expires_at = expired.at + interval '15 minutes' \
             FROM (SELECT clock_timestamp() - interval '16 minutes' AS at) AS expired \
             WHERE child_key = $1",
            &[&child_key],
        )
        .await?;
    reset_role(admin).await?;
    let third_operation = Ulid::new().to_string();
    let after_expiry = runtime
        .query_one(RESERVE, &[&child_key, &binding, &third_operation])
        .await?;
    assert_eq!(after_expiry.get::<_, &str>("outcome"), "reserved");
    assert_eq!(
        after_expiry.get::<_, Option<&str>>("stored_operation_id"),
        Some(third_operation.as_str())
    );

    set_role(admin, owner_role).await?;
    let mismatched_terminal = serde_json::to_string(&json!({
        "schema": "registry.relay.batch-terminal/v1",
        "consultation_id": Ulid::new().to_string(),
        "outcome": "no_match",
        "outputs": null,
        "profile": {"id": "synthetic.profile", "contract_hash": format!("sha256:{}", "a".repeat(64))},
        "provenance": {
            "acquired_at": "2026-07-12T12:00:00.000Z",
            "source_observed_at": null,
            "source_revision": null,
            "acquisition_class": "source_projected_exact",
            "integration": {"id": "synthetic.pack", "revision": 1},
            "consent": {"outcome": "not_required", "verifier_id": null, "verifier_revision": null, "checked_at": null, "expires_at": null, "revocation_status": "not_applicable"}
        }
    }))?;
    let mismatch = admin
        .execute(
            "UPDATE relay_state_private.consultation_batch_child_replay \
             SET state = 'terminal', terminal_payload = $2::text::jsonb \
             WHERE child_key = $1",
            &[&child_key, &mismatched_terminal],
        )
        .await
        .expect_err("terminal consultation id must equal the durable operation id");
    assert_eq!(mismatch.code(), Some(&SqlState::CHECK_VIOLATION));
    reset_role(admin).await?;

    let final_release: bool = runtime
        .query_one(RELEASE, &[&child_key, &binding, &third_operation])
        .await?
        .get(0);
    assert!(final_release);
    drop(runtime);
    runtime_driver.abort();
    eprintln!("batch child replay reservation contract passed");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn exercise_batch_terminal_publication_contract(
    database_url: &str,
    admin: &Client,
    owner_role: &str,
    runtime_role: &str,
    runtime_password: &str,
    plane: &PostgresDurableAuditStatePlane,
    fence: &PostgresServingFence,
    keyring: &PostgresAuditPseudonymKeyringRuntime,
) -> Result<(), Box<dyn std::error::Error>> {
    const RESERVE: &str =
        "SELECT * FROM relay_state_api.consultation_batch_child_reserve_v1($1, $2, $3)";
    let consultation_id = ConsultationId::generate();
    let operation_id = DurableAuditOperationId::parse(&consultation_id.to_canonical_string())?;
    let seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    let write = atomic_consultation_attempt_write(
        &operation_id,
        &pseudonym_key_id("epoch-1"),
        &seed,
        "batch-terminal-publication",
    );
    let attempt_authority = fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 1)?,
        )
        .await?;
    let prepared = PreparedAtomicConsultationAttempt::for_state_test(
        write,
        seed,
        &pseudonym_key_id("epoch-1"),
        attempt_authority,
        keyring.current_write_authority().await?.authorize_use()?,
        future_decision_expiry_unix_ms(),
    )?;
    let mut dispatch = plane
        .write_attempt_with_completion_intent(prepared)
        .await?
        .into_dispatch_for_state_test();
    let permit = dispatch
        .next_data_permit_mut()?
        .expect("batch terminal test has one data permit");
    fence
        .authorize_and_dispatch(
            permit,
            KeyedDispatchRequestCommitment::for_test("lookup-registration"),
            |_deadline| async {},
        )
        .await?;

    let child_key = [0x44_u8; 32];
    let binding_digest = [0x55_u8; 32];
    let (runtime, runtime_driver) =
        postgres_client_as(database_url, runtime_role, runtime_password).await?;
    runtime.batch_execute(RUNTIME_SESSION_LIMITS_SQL).await?;
    let reserved = runtime
        .query_one(
            RESERVE,
            &[
                &child_key.as_slice(),
                &binding_digest.as_slice(),
                &operation_id.as_str(),
            ],
        )
        .await?;
    assert_eq!(reserved.get::<_, &str>("outcome"), "reserved");
    let batch = BatchChildReplayContext::for_test(child_key, binding_digest, &operation_id);

    let plan = bounded_runtime_vector_plan_fixture();
    let first_evaluation = NotaryEvaluationId::try_parse("01JYZZZZZZZZZZZZZZZZZZZZZZ")?;
    let replay_evaluation = NotaryEvaluationId::try_parse("01JYZZZZZZZZZZZZZZZZZZZZZY")?;
    let acquired_at_unix_ms = current_unix_ms();
    let initial_response = PublishableConsultationResponse::batch_no_match_for_state_test(
        consultation_id,
        first_evaluation,
        plan.runtime_profile(),
        acquired_at_unix_ms,
    )?;
    let terminal_payload = initial_response.batch_terminal_json_for_state_test()?;
    let mismatched_id = Ulid::new().to_string();
    let invalid_terminal = zeroize::Zeroizing::new(terminal_payload.replacen(
        operation_id.as_str(),
        &mismatched_id,
        1,
    ));
    let facts = KnownConsultationCompletionFacts::public_for_live_test(
        PublicConsultationOutcome::NoMatch,
        acquired_at_unix_ms,
        None,
        None,
    )?;
    assert!(matches!(
        plane
            .finalize_validated_batch_consultation_for_test(
                &mut dispatch,
                &facts,
                &batch,
                invalid_terminal.as_str(),
                keyring.current_write_authority().await?.authorize_use()?,
            )
            .await,
        Err(ConsultationPersistenceError::InvalidInput)
    ));
    assert!(dispatch.lifecycle_is_armed());
    set_role(admin, owner_role).await?;
    let rolled_back = admin
        .query_one(
            "SELECT \
                (SELECT count(*) FROM relay_state_private.audit_phase \
                 WHERE operation_id=$1 AND phase='completion') AS completions, \
                (SELECT state FROM relay_state_private.consultation_batch_child_replay \
                 WHERE child_key=$2) AS replay_state",
            &[&operation_id.as_str(), &child_key.as_slice()],
        )
        .await?;
    assert_eq!(rolled_back.get::<_, i64>("completions"), 0);
    assert_eq!(rolled_back.get::<_, &str>("replay_state"), "reserved");
    reset_role(admin).await?;

    let publication = plane
        .finalize_validated_batch_consultation_for_test(
            &mut dispatch,
            &facts,
            &batch,
            terminal_payload.as_str(),
            keyring.current_write_authority().await?.authorize_use()?,
        )
        .await?;
    assert!(matches!(
        publication,
        KnownCompletionDisposition::Published(_)
    ));
    assert!(!dispatch.lifecycle_is_armed());

    set_role(admin, owner_role).await?;
    let before_replay = admin
        .query_one(
            "SELECT \
                (SELECT count(*) FROM relay_state_private.consultation_quota_bucket) AS quota_rows, \
                (SELECT count(*) FROM relay_state_private.dispatch_permit \
                 WHERE operation_id=$1 AND dispatched_at IS NOT NULL) AS dispatched_rows, \
                (SELECT count(*) FROM relay_state_private.audit_phase \
                 WHERE operation_id=$1 AND phase='completion') AS completion_rows",
            &[&operation_id.as_str()],
        )
        .await?;
    reset_role(admin).await?;
    let duplicate_operation = Ulid::new().to_string();
    let replay = runtime
        .query_one(
            RESERVE,
            &[
                &child_key.as_slice(),
                &binding_digest.as_slice(),
                &duplicate_operation.as_str(),
            ],
        )
        .await?;
    assert_eq!(replay.get::<_, &str>("outcome"), "replay");
    assert_eq!(
        replay.get::<_, Option<&str>>("stored_operation_id"),
        Some(operation_id.as_str())
    );
    let persisted_terminal = replay
        .get::<_, Option<String>>("terminal_payload")
        .expect("terminal replay retains the closed payload");
    let replay_body = PublishableConsultationResponse::replay_http_body_for_state_test(
        zeroize::Zeroizing::new(persisted_terminal),
        operation_id.as_str(),
        plan.runtime_profile(),
        replay_evaluation,
    )?;
    let replay_json: Value = serde_json::from_slice(&replay_body)?;
    assert_eq!(replay_json["consultation_id"], operation_id.as_str());
    assert_eq!(
        replay_json["notary_evaluation_id"],
        replay_evaluation.to_canonical_string()
    );
    assert_ne!(
        replay_json["notary_evaluation_id"],
        first_evaluation.to_canonical_string()
    );
    set_role(admin, owner_role).await?;
    let after_replay = admin
        .query_one(
            "SELECT \
                (SELECT count(*) FROM relay_state_private.consultation_quota_bucket) AS quota_rows, \
                (SELECT count(*) FROM relay_state_private.dispatch_permit \
                 WHERE operation_id=$1 AND dispatched_at IS NOT NULL) AS dispatched_rows, \
                (SELECT count(*) FROM relay_state_private.audit_phase \
                 WHERE operation_id=$1 AND phase='completion') AS completion_rows",
            &[&operation_id.as_str()],
        )
        .await?;
    reset_role(admin).await?;
    for column in ["quota_rows", "dispatched_rows", "completion_rows"] {
        assert_eq!(
            after_replay.get::<_, i64>(column),
            before_replay.get::<_, i64>(column),
            "exact replay must not charge quota, dispatch source, or complete twice"
        );
    }
    assert_eq!(after_replay.get::<_, i64>("dispatched_rows"), 1);
    assert_eq!(after_replay.get::<_, i64>("completion_rows"), 1);
    drop(runtime);
    runtime_driver.abort();
    eprintln!("batch terminal publication and fresh-id replay contract passed");
    Ok(())
}

#[test]
#[ignore = "requires dedicated REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL"]
fn postgres_state_plane_enforces_role_catalog_and_chain_contract() {
    let worker = std::thread::Builder::new()
        .name("relay-state-plane-conformance".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("state-plane conformance runtime builds")
                .block_on(postgres_state_plane_contract())
                .map_err(|_| ())
        })
        .expect("state-plane conformance worker starts");
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(())) => panic!("state-plane conformance returned an error"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn postgres_state_plane_contract() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {DATABASE_URL_ENV} is not set");
        return Ok(());
    };

    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;

    let owner_role = role_name("owner");
    let stale_owner_role = role_name("stale");
    let runtime_role_name = role_name("runtime");
    let keyring_maintenance_role_name = role_name("keymaint");
    let keyring_reader_role_name = role_name("keyreader");
    let private_reader_role = role_name("reader");
    let attacker_role = role_name("attacker");
    let bridge_role = role_name("bridge");
    let runtime_password = Ulid::new().to_string();
    let keyring_maintenance_password = Ulid::new().to_string();
    let keyring_reader_password = Ulid::new().to_string();
    let attacker_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    admin
        .batch_execute(&format!(
            r#"
CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {stale} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {keymaint} LOGIN PASSWORD '{keyring_maintenance_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {keyreader} LOGIN PASSWORD '{keyring_reader_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {reader} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {attacker} LOGIN PASSWORD '{attacker_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {bridge} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT CREATE ON DATABASE {database} TO {owner};
GRANT CREATE ON DATABASE {database} TO {stale};
"#,
            owner = quote_identifier(&owner_role),
            stale = quote_identifier(&stale_owner_role),
            runtime = quote_identifier(&runtime_role_name),
            keymaint = quote_identifier(&keyring_maintenance_role_name),
            keyreader = quote_identifier(&keyring_reader_role_name),
            reader = quote_identifier(&private_reader_role),
            attacker = quote_identifier(&attacker_role),
            bridge = quote_identifier(&bridge_role),
            database = quote_identifier(&database_name),
        ))
        .await?;

    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let keyring_maintenance_role =
        AuditPseudonymMaintenanceDatabaseRole::parse(&keyring_maintenance_role_name)?;
    let keyring_reader_role = AuditPseudonymReaderDatabaseRole::parse(&keyring_reader_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("test-chain-key-epoch-1")?;

    let server = admin
        .query_one(
            "SELECT current_setting('server_version_num')::integer / 10000 AS major, \
                    current_setting('max_prepared_transactions')::integer AS prepared, \
                    NOT pg_catalog.pg_is_in_recovery() AS primary_writable",
            &[],
        )
        .await?;
    let server_major: i32 = server.try_get("major")?;
    assert!(
        (16..=18).contains(&server_major),
        "test requires an explicitly supported PostgreSQL major"
    );
    assert_eq!(server.try_get::<_, i32>("prepared")?, 0);
    assert!(server.try_get::<_, bool>("primary_writable")?);

    // Both directions around both bound roles are forbidden. NOINHERIT does
    // not prevent SET ROLE, and an endpoint edge is necessarily present for
    // every transitive path.
    admin
        .batch_execute(&format!(
            "GRANT {owner} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    let (mut non_superuser_admin, non_superuser_admin_driver) =
        postgres_client_as(&database_url, &attacker_role, &attacker_password).await?;
    set_role(&non_superuser_admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut non_superuser_admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::InvalidMigrationAuthority)
    );
    reset_role(&non_superuser_admin).await?;
    drop(non_superuser_admin);
    non_superuser_admin_driver.abort();
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {owner} FROM {attacker};",
            owner = quote_identifier(&owner_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;

    admin
        .batch_execute(&format!(
            "GRANT {owner} TO {bridge} WITH INHERIT FALSE, SET TRUE; \
             GRANT {bridge} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {bridge} FROM {attacker}; REVOKE {owner} FROM {bridge};",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;

    admin
        .batch_execute(&format!(
            "GRANT {bridge} TO {owner} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {bridge} FROM {owner};",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
        ))
        .await?;

    for (grant, revoke) in [
        (
            format!(
                "GRANT {runtime} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
                runtime = quote_identifier(&runtime_role_name),
                attacker = quote_identifier(&attacker_role),
            ),
            format!(
                "REVOKE {runtime} FROM {attacker};",
                runtime = quote_identifier(&runtime_role_name),
                attacker = quote_identifier(&attacker_role),
            ),
        ),
        (
            format!(
                "GRANT {bridge} TO {runtime} WITH INHERIT FALSE, SET TRUE;",
                runtime = quote_identifier(&runtime_role_name),
                bridge = quote_identifier(&bridge_role),
            ),
            format!(
                "REVOKE {bridge} FROM {runtime};",
                runtime = quote_identifier(&runtime_role_name),
                bridge = quote_identifier(&bridge_role),
            ),
        ),
    ] {
        admin.batch_execute(&grant).await?;
        set_role(&admin, &owner_role).await?;
        assert_eq!(
            install_postgres_state_plane_v1(
                &mut admin,
                &runtime_role,
                &chain_key_epoch_id,
                test_serving_fence_lock_key(),
                &keyring_maintenance_role,
                &keyring_reader_role,
                test_pseudonym_keyring_lock_key(),
            )
            .await,
            Err(StatePlaneInstallError::RuntimeRoleNotIsolated)
        );
        reset_role(&admin).await?;
        admin.batch_execute(&revoke).await?;
    }

    // A partial installation owned by anybody else is never silently adopted.
    set_role(&admin, &stale_owner_role).await?;
    admin
        .batch_execute("CREATE SCHEMA relay_state_private; CREATE SCHEMA relay_state_api;")
        .await?;
    reset_role(&admin).await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;

    // Independent clean installers converge through the fixed transaction
    // advisory lock. The second then observes an exactly attested installation.
    let (mut concurrent_admin, concurrent_admin_driver) = postgres_client(&database_url).await?;
    set_role(&admin, &owner_role).await?;
    set_role(&concurrent_admin, &owner_role).await?;
    let (first_install, second_install) = tokio::join!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        ),
        install_postgres_state_plane_v1(
            &mut concurrent_admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
    );
    assert_eq!(first_install, Ok(()));
    assert_eq!(second_install, Ok(()));
    reset_role(&admin).await?;
    reset_role(&concurrent_admin).await?;
    drop(concurrent_admin);
    concurrent_admin_driver.abort();
    let _ = concurrent_admin_driver.await;

    set_role(&admin, &owner_role).await?;
    install_postgres_state_plane_v1(
        &mut admin,
        &runtime_role,
        &chain_key_epoch_id,
        test_serving_fence_lock_key(),
        &keyring_maintenance_role,
        &keyring_reader_role,
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    reset_role(&admin).await?;

    let metadata = admin
        .query_one(
            r#"
SELECT metadata.owner_role_oid::bigint, metadata.runtime_role_oid::bigint,
       metadata.capability_fingerprint, metadata.chain_key_epoch_id,
       owner_role.rolcanlogin, runtime_role.rolcanlogin
FROM relay_state_private.state_plane_metadata AS metadata
JOIN pg_roles AS owner_role ON owner_role.oid = metadata.owner_role_oid
JOIN pg_roles AS runtime_role ON runtime_role.oid = metadata.runtime_role_oid
WHERE metadata.singleton = true
"#,
            &[],
        )
        .await?;
    assert_ne!(metadata.get::<_, i64>(0), metadata.get::<_, i64>(1));
    assert_eq!(
        metadata.get::<_, &str>(2),
        STATE_PLANE_SCHEMA_FINGERPRINT_V1
    );
    assert_eq!(metadata.get::<_, &str>(3), chain_key_epoch_id.as_str());
    assert!(!metadata.get::<_, bool>(4));
    assert!(metadata.get::<_, bool>(5));

    exercise_batch_child_replay_reservation_contract(
        &database_url,
        &admin,
        &owner_role,
        &runtime_role_name,
        &runtime_password,
        &attacker_role,
        &attacker_password,
    )
    .await?;

    exercise_postgres_quota_contract(
        &admin,
        QuotaTestContext {
            database_url: &database_url,
            owner_role: &owner_role,
            runtime_role: &runtime_role_name,
            runtime_password: &runtime_password,
            attacker_role: &attacker_role,
            attacker_password: &attacker_password,
            chain_key_epoch_id: &chain_key_epoch_id,
        },
    )
    .await?;

    let (unkeyed_client, unkeyed_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            unkeyed_client,
            AuditChainHasher::unkeyed_dev_only(),
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await
        .err()
        .expect("unkeyed production construction must fail"),
        StatePlaneInitializationError::UnkeyedAuditChain
    );
    unkeyed_driver.abort();

    let secret_env = format!(
        "REGISTRY_RELAY_STATE_PLANE_TEST_SECRET_{}",
        Ulid::new().to_string()
    );
    env::set_var(
        &secret_env,
        "test-only-state-plane-chain-secret-at-least-thirty-two-bytes",
    );
    let test_chain_hasher = AuditChainHasher::from_env(&secret_env)?;
    env::remove_var(&secret_env);

    let (keyring_runtime_client, keyring_runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let keyring_runtime = Arc::new(
        PostgresAuditPseudonymKeyringRuntime::connect(
            keyring_runtime_client,
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await?,
    );
    let (keyring_maintenance_client, keyring_maintenance_driver) = postgres_client_as(
        &database_url,
        &keyring_maintenance_role_name,
        &keyring_maintenance_password,
    )
    .await?;
    let keyring_maintenance = Arc::new(
        PostgresAuditPseudonymKeyringMaintenance::connect(
            keyring_maintenance_client,
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await?,
    );
    let (keyring_reader_client, keyring_reader_driver) = postgres_client_as(
        &database_url,
        &keyring_reader_role_name,
        &keyring_reader_password,
    )
    .await?;
    let keyring_reader = Arc::new(
        PostgresAuditPseudonymKeyringReader::connect(
            keyring_reader_client,
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await?,
    );
    assert_eq!(
        keyring_runtime.current_write_authority().await.err(),
        Some(PostgresKeyringError::Uninitialized)
    );
    let initial_now = current_unix_ms();
    let initial_keyring_metadata = AuditPseudonymKeyringMetadata::new(
        1,
        pseudonym_key_id("epoch-1"),
        initial_now - 1_000,
        initial_now + 120_000,
        2_000,
        vec![],
    )?;
    assert_eq!(
        keyring_maintenance
            .initialize(initial_keyring_metadata.clone())
            .await?,
        KeyringInitializationOutcome::Initialized
    );
    assert_eq!(
        keyring_maintenance
            .initialize(initial_keyring_metadata.clone())
            .await?,
        KeyringInitializationOutcome::Identical
    );
    let initial_lookup = keyring_reader
        .lookup_snapshot(AuthorizedAuditPseudonymLookupSubset::for_test([
            pseudonym_key_id("epoch-1"),
        ])?)
        .await?;
    assert_eq!(initial_lookup.epochs().len(), 1);
    assert_eq!(initial_lookup.epochs()[0].key_id().as_str(), "epoch-1");

    let (keyring_shape_runtime, keyring_shape_runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    keyring_shape_runtime
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let empty_lookup_ids = Vec::<String>::new();
    let runtime_shape = keyring_shape_runtime
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_snapshot_v1($1,$2,$3,$4)",
            &[
                &"write",
                &empty_lookup_ids,
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    assert_eq!(runtime_shape.try_get::<_, &str>("outcome")?, "ready");
    assert!(runtime_shape
        .try_get::<_, Option<&str>>("metadata_canonical")?
        .is_none());
    assert!(runtime_shape
        .try_get::<_, Vec<String>>("retained_key_ids")?
        .is_empty());
    assert!(runtime_shape
        .try_get::<_, Option<i64>>("used_key_id_count")?
        .is_none());
    let wrong_purpose = keyring_shape_runtime
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_snapshot_v1($1,$2,$3,$4)",
            &[
                &"lookup",
                &vec!["epoch-1".to_owned()],
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await
        .expect_err("runtime role cannot perform reader lookup");
    assert_eq!(
        wrong_purpose.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let runtime_initialize_denial = keyring_shape_runtime
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_initialize_v1(\
             1,decode(repeat('00',32),'hex'),'{}','epoch-x',0,1,1,\
             ARRAY[]::text[],ARRAY[]::bigint[],ARRAY[]::bigint[],$1,$2)",
            &[
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await
        .expect_err("runtime role cannot initialize keyring");
    assert_eq!(
        runtime_initialize_denial
            .as_db_error()
            .map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let private_read_denial = keyring_shape_runtime
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_pseudonym_keyring",
            &[],
        )
        .await
        .expect_err("runtime has no keyring table read access");
    assert_eq!(
        private_read_denial.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(keyring_shape_runtime);
    keyring_shape_runtime_driver.abort();

    let (keyring_shape_reader, keyring_shape_reader_driver) = postgres_client_as(
        &database_url,
        &keyring_reader_role_name,
        &keyring_reader_password,
    )
    .await?;
    keyring_shape_reader
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let reader_shape = keyring_shape_reader
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_snapshot_v1($1,$2,$3,$4)",
            &[
                &"lookup",
                &vec!["epoch-1".to_owned()],
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    assert_eq!(reader_shape.try_get::<_, &str>("outcome")?, "ready");
    assert!(reader_shape
        .try_get::<_, Option<&str>>("active_key_id")?
        .is_none());
    assert!(reader_shape
        .try_get::<_, Vec<String>>("retained_key_ids")?
        .is_empty());
    assert_eq!(
        reader_shape.try_get::<_, Vec<String>>("lookup_key_ids")?,
        ["epoch-1"]
    );
    let reader_rotate_denial = keyring_shape_reader
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_rotate_v1(\
             1,decode(repeat('00',32),'hex'),1,decode(repeat('00',32),'hex'),0,\
             2,decode(repeat('00',32),'hex'),'{}','epoch-x',0,1,1,\
             ARRAY[]::text[],ARRAY[]::bigint[],ARRAY[]::bigint[],$1,$2)",
            &[
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await
        .expect_err("reader role cannot rotate keyring");
    assert_eq!(
        reader_rotate_denial.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(keyring_shape_reader);
    keyring_shape_reader_driver.abort();

    let (keyring_spoof_client, keyring_spoof_driver) = postgres_client_as(
        &database_url,
        &keyring_maintenance_role_name,
        &keyring_maintenance_password,
    )
    .await?;
    keyring_spoof_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let maintenance_audit_denial = keyring_spoof_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_phase_duplicate_v1(\
             'consultation','00000000000000000000000000','attempt',\
             decode(repeat('00',32),'hex'),$1,$2)",
            &[
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await
        .expect_err("maintenance role cannot call durable audit API");
    assert_eq!(
        maintenance_audit_denial
            .as_db_error()
            .map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let spoof_snapshot = keyring_spoof_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_snapshot_v1($1,$2,$3,$4)",
            &[
                &"rotation",
                &Vec::<String>::new(),
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    assert_eq!(spoof_snapshot.try_get::<_, &str>("outcome")?, "ready");
    let spoof_transition_time: i64 = spoof_snapshot.try_get("authoritative_now_unix_ms")?;
    let spoof_history_count: i64 = spoof_snapshot.try_get("used_key_id_count")?;
    let spoof_history_digest: Vec<u8> = spoof_snapshot.try_get("used_key_ids_digest")?;
    let spoof_successor = rotation_successor(
        &initial_keyring_metadata,
        spoof_transition_time,
        "epoch-spoof",
    )?;
    let spoof_canonical = canonical_keyring_metadata(&spoof_successor)?;
    let initial_binding = initial_keyring_metadata.binding()?;
    let spoof_binding = spoof_successor.binding()?;
    let spoof_retained_key_ids = spoof_successor
        .retained_keys()
        .iter()
        .map(|epoch| epoch.key_id().as_str().to_owned())
        .collect::<Vec<_>>();
    let spoof_retired = spoof_successor
        .retained_keys()
        .iter()
        .map(RetainedAuditPseudonymKeyEpoch::retired_at_unix_ms)
        .collect::<Vec<_>>();
    let spoof_destroy = spoof_successor
        .retained_keys()
        .iter()
        .map(RetainedAuditPseudonymKeyEpoch::destroy_after_unix_ms)
        .collect::<Vec<_>>();
    keyring_spoof_client
        .batch_execute(
            "SELECT set_config('registry.audit_pseudonym_transition_time', 'forged', false)",
        )
        .await?;
    let spoof_apply = keyring_spoof_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_rotate_v1(\
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            &[
                &i64::try_from(initial_keyring_metadata.generation())?,
                &initial_binding.digest().as_slice(),
                &spoof_history_count,
                &spoof_history_digest,
                &spoof_transition_time,
                &i64::try_from(spoof_successor.generation())?,
                &spoof_binding.digest().as_slice(),
                &spoof_canonical,
                &spoof_successor.active_key_id().as_str(),
                &spoof_successor.active_since_unix_ms(),
                &spoof_successor.active_write_deadline_unix_ms(),
                &spoof_successor.audit_event_retention_ms(),
                &spoof_retained_key_ids,
                &spoof_retired,
                &spoof_destroy,
                &chain_key_epoch_id.as_str(),
                &test_pseudonym_keyring_lock_key().as_i64(),
            ],
        )
        .await?;
    assert_eq!(spoof_apply.try_get::<_, &str>("outcome")?, "invalid");
    let context_read_denial = keyring_spoof_client
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_pseudonym_transition_context",
            &[],
        )
        .await
        .expect_err("maintenance identity cannot read private transition context");
    assert_eq!(
        context_read_denial.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(keyring_spoof_client);
    keyring_spoof_driver.abort();

    // SUSET role/database defaults are inherited before Relay receives the
    // Client. The runtime cannot repair session_replication_role, and replica
    // mode disables the origin FK triggers, so both inheritance paths must be
    // rejected on a fresh login.
    for (set_replica, reset_replica) in [
        (
            format!(
                "ALTER ROLE {} SET session_replication_role = 'replica'",
                quote_identifier(&runtime_role_name)
            ),
            format!(
                "ALTER ROLE {} RESET session_replication_role",
                quote_identifier(&runtime_role_name)
            ),
        ),
        (
            format!(
                "ALTER DATABASE {} SET session_replication_role = 'replica'",
                quote_identifier(&database_name)
            ),
            format!(
                "ALTER DATABASE {} RESET session_replication_role",
                quote_identifier(&database_name)
            ),
        ),
    ] {
        admin.batch_execute(&set_replica).await?;
        let (replica_client, replica_driver) =
            postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
        let inherited_mode: String = replica_client
            .query_one("SHOW session_replication_role", &[])
            .await?
            .try_get(0)?;
        let replica_ready: bool = replica_client
            .query_one(
                "SELECT ready FROM relay_state_api.audit_readiness_v1($1)",
                &[&chain_key_epoch_id.as_str()],
            )
            .await?
            .try_get("ready")?;
        let replica_connect = PostgresDurableAuditStatePlane::connect(
            replica_client,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await;
        replica_driver.abort();
        admin.batch_execute(&reset_replica).await?;
        assert_eq!(inherited_mode, "replica");
        assert!(!replica_ready);
        assert_eq!(
            replica_connect
                .err()
                .expect("replica-mode runtime must fail attestation"),
            StatePlaneInitializationError::CapabilityDrift
        );
    }

    // A hostile session-wide read-only default is not silently widened. It is
    // independently attested from the current transaction mode.
    let (read_only_default_client, read_only_default_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    read_only_default_client
        .batch_execute("SET default_transaction_read_only = 'on'")
        .await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            read_only_default_client,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await
        .err()
        .expect("a read-only session default must fail attestation"),
        StatePlaneInitializationError::CapabilityDrift
    );
    read_only_default_driver.abort();

    // The SQL readiness capability itself also fails closed when invoked from
    // an explicit read-only transaction. A constructor-owned rollback may
    // normalize such an input before attestation, but readiness never reports
    // the unnormalized transaction as writable.
    let (read_only_transaction_client, read_only_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    read_only_transaction_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    read_only_transaction_client
        .batch_execute("BEGIN READ ONLY")
        .await?;
    let read_only_ready: bool = read_only_transaction_client
        .query_one(
            "SELECT ready FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?
        .try_get("ready")?;
    assert!(!read_only_ready);
    read_only_transaction_client
        .batch_execute("ROLLBACK")
        .await?;
    drop(read_only_transaction_client);
    read_only_transaction_driver.abort();

    // The constructor owns the supplied session. It must roll back a caller's
    // live transaction before acknowledging durable writes, and must replace
    // hostile session limits before attestation. Without that normalization,
    // the write below appears inserted but is rolled back when the fixed idle
    // transaction timeout disconnects the session.
    let (open_transaction_client, open_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    open_transaction_client
        .batch_execute(
            "SET search_path = public; \
             SET lock_timeout = '0'; \
             SET statement_timeout = '0'; \
             SET idle_in_transaction_session_timeout = '0'; \
             SET synchronous_commit = 'off'; \
             SET client_encoding = 'SQL_ASCII'; \
             SET standard_conforming_strings = 'off'; \
             SET default_transaction_isolation = 'serializable'",
        )
        .await?;
    open_transaction_client.batch_execute("BEGIN").await?;
    let open_transaction_plane = PostgresDurableAuditStatePlane::connect(
        open_transaction_client,
        test_chain_hasher.clone(),
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    assert_eq!(
        open_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready
    );
    let normalized_operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    let normalized_write = attempt_write(&normalized_operation_id, "normalized-open-transaction");
    assert!(matches!(
        open_transaction_plane
            .write_phase(&normalized_write)
            .await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    let visible_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind = $1 AND operation_id = $2 AND phase = $3",
            &[
                &normalized_write.key().stream_kind().as_str(),
                &normalized_write.key().operation_id().as_str(),
                &normalized_write.key().phase().as_str(),
            ],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        visible_rows, 1,
        "acknowledged write must already be visible"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        open_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready,
        "the session must not be killed as idle in the caller's transaction"
    );
    let durable_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind = $1 AND operation_id = $2 AND phase = $3",
            &[
                &normalized_write.key().stream_kind().as_str(),
                &normalized_write.key().operation_id().as_str(),
                &normalized_write.key().phase().as_str(),
            ],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        durable_rows, 1,
        "acknowledged write must survive idle timeout"
    );
    drop(open_transaction_plane);
    open_transaction_driver.abort();

    // ROLLBACK is also the only command that can recover a Client in failed
    // transaction state. Constructor normalization must handle that input.
    let (failed_transaction_client, failed_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    failed_transaction_client.batch_execute("BEGIN").await?;
    let failed_transaction_error = failed_transaction_client
        .batch_execute("SELECT 1 / 0")
        .await
        .expect_err("test must leave the session in failed transaction state");
    assert_eq!(
        failed_transaction_error
            .as_db_error()
            .map(|error| error.code()),
        Some(&SqlState::DIVISION_BY_ZERO)
    );
    let failed_transaction_plane = PostgresDurableAuditStatePlane::connect(
        failed_transaction_client,
        test_chain_hasher.clone(),
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    assert_eq!(
        failed_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready
    );
    let recovered_operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    assert!(matches!(
        failed_transaction_plane
            .write_phase(&attempt_write(
                &recovered_operation_id,
                "normalized-failed-transaction",
            ))
            .await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    drop(failed_transaction_plane);
    failed_transaction_driver.abort();

    let (client_one, driver_one) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let direct_read_error = client_one
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await
        .expect_err("runtime must have no private-table privilege");
    assert_eq!(
        direct_read_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let direct_materialization_read_error = client_one
        .query_one(
            "SELECT count(*) FROM relay_state_private.materialization_publication_history",
            &[],
        )
        .await
        .expect_err("runtime must have no materialization-history table privilege");
    assert_eq!(
        direct_materialization_read_error
            .as_db_error()
            .map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let plane_one = Arc::new(
        PostgresDurableAuditStatePlane::connect(
            client_one,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await?,
    );
    let (client_two, driver_two) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let plane_two = Arc::new(
        PostgresDurableAuditStatePlane::connect(
            client_two,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
            test_pseudonym_keyring_lock_key(),
        )
        .await?,
    );
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    let binding =
        MaterializationPublicationBindingId::parse(&format!("sha256:{}", "a".repeat(64)))?;
    let generation_one = MaterializationGenerationId::parse("01J2D9W2G00000000000000000")?;
    let generation_two = MaterializationGenerationId::parse("01J2D9W2G00000000000000001")?;
    let publication_operation_one = DurableAuditOperationId::from_ulid(Ulid::new());
    let publication_attempt_one = attempt_write(&publication_operation_one, "publication-one");
    let publication_attempt_one_identity =
        match plane_one.write_phase(&publication_attempt_one).await? {
            DurableAuditWriteOutcome::Inserted(identity) => identity,
            _ => panic!("fresh materialization attempt must insert"),
        };
    let publication_completion_one = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        publication_operation_one,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(
                &publication_attempt_one_identity
            ).to_safe_payload_value(),
            "outcome": "known_complete",
            "binding_id": binding.as_str(),
            "generation_id": generation_one.as_str(),
            "content_digest": "restricted-sha256",
        }),
    )?;
    let publication_one_observed_at = current_unix_ms() - 1_000;
    let publication_request_one = MaterializationPublicationRequest::new(
        binding.clone(),
        generation_one.clone(),
        RestrictedMaterializationContentDigest::from_sha256([0x11; 32]),
        Some(MaterializationSourceRevision::parse("source-rev:1")?),
        Some(publication_one_observed_at),
    )?;
    let inserted_one = match plane_one
        .publish_materialization(&publication_completion_one, &publication_request_one)
        .await?
    {
        MaterializationPublicationOutcome::Inserted(publication) => publication,
        MaterializationPublicationOutcome::IdenticalDuplicate(_) => {
            panic!("fresh materialization publication must insert")
        }
    };
    assert_eq!(inserted_one.publication_sequence(), 1);
    assert_eq!(inserted_one.generation_id(), &generation_one);
    assert!(inserted_one.published_at_unix_ms() >= current_unix_ms() - 5_000);
    let publication_counts = admin
        .query_one(
            "SELECT \
                 (SELECT count(*) FROM relay_state_private.materialization_publication_history), \
                 (SELECT count(*) FROM relay_state_private.materialization_active_publication), \
                 (SELECT count(*) FROM relay_state_private.audit_phase \
                    WHERE stream_kind = 'materialization' AND phase = 'completion')",
            &[],
        )
        .await?;
    assert_eq!(publication_counts.get::<_, i64>(0), 1);
    assert_eq!(publication_counts.get::<_, i64>(1), 1);
    assert_eq!(publication_counts.get::<_, i64>(2), 1);
    assert!(matches!(
        plane_two
            .publish_materialization(&publication_completion_one, &publication_request_one)
            .await?,
        MaterializationPublicationOutcome::IdenticalDuplicate(_)
    ));
    let conflicting_request = MaterializationPublicationRequest::new(
        binding.clone(),
        generation_one.clone(),
        RestrictedMaterializationContentDigest::from_sha256([0x22; 32]),
        Some(MaterializationSourceRevision::parse("source-rev:1")?),
        Some(publication_one_observed_at),
    )?;
    assert!(matches!(
        plane_one
            .publish_materialization(&publication_completion_one, &conflicting_request)
            .await,
        Err(MaterializationPublicationError::ConflictingReplay)
    ));
    let publication_count_after_conflict: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.materialization_publication_history",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(publication_count_after_conflict, 1);

    let publication_operation_two = DurableAuditOperationId::from_ulid(Ulid::new());
    let publication_attempt_two = attempt_write(&publication_operation_two, "publication-two");
    let publication_attempt_two_identity =
        match plane_one.write_phase(&publication_attempt_two).await? {
            DurableAuditWriteOutcome::Inserted(identity) => identity,
            _ => panic!("fresh second materialization attempt must insert"),
        };
    let publication_completion_two = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        publication_operation_two,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(
                &publication_attempt_two_identity
            ).to_safe_payload_value(),
            "outcome": "known_complete",
            "binding_id": binding.as_str(),
            "generation_id": generation_two.as_str(),
            "content_digest": "restricted-sha256",
        }),
    )?;
    let publication_request_two = MaterializationPublicationRequest::new(
        binding.clone(),
        generation_two.clone(),
        RestrictedMaterializationContentDigest::from_sha256([0x22; 32]),
        Some(MaterializationSourceRevision::parse("source-rev:2")?),
        Some(current_unix_ms() - 500),
    )?;
    let inserted_two = match plane_two
        .publish_materialization(&publication_completion_two, &publication_request_two)
        .await?
    {
        MaterializationPublicationOutcome::Inserted(publication) => publication,
        MaterializationPublicationOutcome::IdenticalDuplicate(_) => {
            panic!("fresh second materialization publication must insert")
        }
    };
    assert_eq!(inserted_two.publication_sequence(), 2);
    let active_sequence: i64 = admin
        .query_one(
            "SELECT publication_sequence \
             FROM relay_state_private.materialization_active_publication \
             WHERE binding_id = $1",
            &[&binding.as_str()],
        )
        .await?
        .get(0);
    assert_eq!(active_sequence, 2);
    assert_eq!(
        plane_one
            .active_materialization(&binding)
            .await?
            .expect("active materialization")
            .generation_id(),
        &generation_two
    );
    assert_eq!(
        plane_one
            .reconcile_materialization(&publication_request_two)
            .await?
            .completion()
            .envelope_id(),
        inserted_two.completion().envelope_id()
    );

    let rollback_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let rollback_attempt = attempt_write(&rollback_operation, "publication-rollback");
    let rollback_attempt_identity = match plane_one.write_phase(&rollback_attempt).await? {
        DurableAuditWriteOutcome::Inserted(identity) => identity,
        _ => panic!("fresh rollback attempt must insert"),
    };
    let rollback_completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        rollback_operation,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(
                &rollback_attempt_identity
            ).to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    let rollback_request = MaterializationPublicationRequest::new(
        binding.clone(),
        MaterializationGenerationId::parse("01J2D9W2F00000000000000000")?,
        RestrictedMaterializationContentDigest::from_sha256([0x33; 32]),
        None,
        None,
    )?;
    assert!(matches!(
        plane_one
            .publish_materialization(&rollback_completion, &rollback_request)
            .await,
        Err(MaterializationPublicationError::RollbackRejected)
    ));
    let publication_count_after_rollback: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.materialization_publication_history",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(publication_count_after_rollback, 2);

    let reused_generation_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let reused_generation_attempt =
        attempt_write(&reused_generation_operation, "publication-generation-reuse");
    let reused_generation_attempt_identity =
        match plane_one.write_phase(&reused_generation_attempt).await? {
            DurableAuditWriteOutcome::Inserted(identity) => identity,
            _ => panic!("fresh generation-reuse attempt must insert"),
        };
    let reused_generation_completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        reused_generation_operation,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(
                &reused_generation_attempt_identity
            ).to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    let reused_generation_request = MaterializationPublicationRequest::new(
        MaterializationPublicationBindingId::parse(&format!("sha256:{}", "b".repeat(64)))?,
        generation_one,
        RestrictedMaterializationContentDigest::from_sha256([0x44; 32]),
        None,
        None,
    )?;
    assert!(matches!(
        plane_one
            .publish_materialization(&reused_generation_completion, &reused_generation_request)
            .await,
        Err(MaterializationPublicationError::GenerationReused)
    ));
    let materialization_completion_count: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind = 'materialization' AND phase = 'completion'",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(materialization_completion_count, 2);

    // statement_timeout must be armed by the caller before PostgreSQL starts
    // the outer SELECT. Relay does this when it admits the runtime connection;
    // function-local settings cannot retroactively arm an in-flight statement.
    let (timeout_client, timeout_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    timeout_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let timeout_started = Instant::now();
    let timeout_error = timeout_client
        .query_one(
            "SELECT pg_sleep(8), readiness.ready \
             FROM relay_state_api.audit_readiness_v1($1) AS readiness",
            &[&chain_key_epoch_id.as_str()],
        )
        .await
        .expect_err("caller-side statement timeout must cancel the outer SELECT");
    assert_eq!(
        timeout_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::QUERY_CANCELED)
    );
    assert!(timeout_started.elapsed() < Duration::from_secs(7));
    drop(timeout_client);
    timeout_driver.abort();

    let (wrong_epoch_client, wrong_epoch_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            wrong_epoch_client,
            test_chain_hasher.clone(),
            AuditChainKeyEpochId::parse("wrong-epoch")?,
            test_pseudonym_keyring_lock_key(),
        )
        .await
        .err()
        .expect("mismatched chain epoch must fail"),
        StatePlaneInitializationError::CapabilityDrift
    );
    wrong_epoch_driver.abort();

    let fence_key = test_serving_fence_lock_key();
    let (fence_one_client, fence_one_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let fence_one = PostgresServingFence::acquire(
        fence_one_client,
        fence_one_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    assert_eq!(fence_one.generation(), 1);

    exercise_batch_terminal_publication_contract(
        &database_url,
        &admin,
        &owner_role,
        &runtime_role_name,
        &runtime_password,
        &plane_one,
        &fence_one,
        &keyring_runtime,
    )
    .await?;

    let pseudonym_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let pseudonym_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    set_role(&admin, &owner_role).await?;
    let seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&pseudonym_seed)?],
        )
        .await?
        .try_get(0)?;
    let mut subset_outcome_seed = pseudonym_seed.clone();
    subset_outcome_seed["acquisition"]["public_outcomes"] = json!(["match"]);
    let subset_outcomes_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&subset_outcome_seed)?],
        )
        .await?
        .try_get(0)?;
    let mut ambiguous_seed = pseudonym_seed.clone();
    ambiguous_seed["bounds"]["source_matches"] = json!(2);
    ambiguous_seed["acquisition"]["public_outcomes"] = json!(["match", "no_match", "ambiguous"]);
    let ambiguous_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&ambiguous_seed)?],
        )
        .await?
        .try_get(0)?;
    let compiler_normal_seed = normal_completion_seed_fixture();
    let compiler_dhis2_seed = dhis2_completion_seed_fixture();
    let compiler_open_crvs_seed = open_crvs_completion_seed_fixture();
    let compiler_snapshot_seed = snapshot_completion_seed_fixture();
    let compiler_semantic_alias_seed = semantic_alias_completion_seed_fixture();
    let compiler_maximum_seed = maximum_completion_seed_fixture();
    let compiler_rhai_seed = rhai_five_operation_two_slot_completion_seed_fixture();
    let mut exchange_without_reference = compiler_normal_seed.clone();
    exchange_without_reference["credential"]["reference"] = Value::Null;
    exchange_without_reference["credential"]["generation"] = Value::Null;
    let mut direct_basic_half_pair = compiler_dhis2_seed.clone();
    direct_basic_half_pair["credential"]["generation"] = Value::Null;
    let mut direct_basic_with_destination = compiler_dhis2_seed.clone();
    direct_basic_with_destination["destinations"]["credential_destination_id"] =
        json!("unexpected-credential-destination");
    let mut direct_basic_with_token_lifetime = compiler_dhis2_seed.clone();
    direct_basic_with_token_lifetime["bounds"]["credential_token_lifetime_ms"] = json!(60_000);
    let mut snapshot_with_dangling_reference = compiler_snapshot_seed.clone();
    snapshot_with_dangling_reference["credential"] =
        json!({"reference": "unused-snapshot-credential", "generation": 1});
    let conditional_bounded_seed = completion_seed_value(
        "bounded_http",
        None,
        &["step-a", "step-b", "step-c"],
        &[vec!["step-a"], vec!["step-b", "step-c"], vec!["step-c"]],
    );
    assert!(
        canonicalize_json(&compiler_maximum_seed)
            .expect("compiler maximum seed is canonicalizable")
            .len()
            <= 262_144,
        "compiler maximum seed must fit the shared SQL/Rust canonical cap"
    );
    let compiler_normal_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_normal_seed)?],
        )
        .await?
        .try_get(0)?;
    let compiler_open_crvs_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_open_crvs_seed)?],
        )
        .await?
        .try_get(0)?;
    let compiler_snapshot_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_snapshot_seed)?],
        )
        .await?
        .try_get(0)?;
    let mut open_crvs_positive_lifetime = compiler_open_crvs_seed.clone();
    open_crvs_positive_lifetime["bounds"]["credential_token_lifetime_ms"] = json!(60_000);
    let open_crvs_positive_lifetime_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&open_crvs_positive_lifetime)?],
        )
        .await?
        .try_get(0)?;
    let mut obsolete_operation_union = compiler_open_crvs_seed.clone();
    obsolete_operation_union["authorized_operation_union"] = json!([]);
    let obsolete_operation_union_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&obsolete_operation_union)?],
        )
        .await?
        .try_get(0)?;
    let mut out_of_order_ordinal = compiler_open_crvs_seed.clone();
    out_of_order_ordinal["dispatch"]["permit_bindings"][1]["ordinal"] = json!(1);
    out_of_order_ordinal["dispatch"]["permit_bindings"][2]["ordinal"] = json!(0);
    let out_of_order_ordinal_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&out_of_order_ordinal)?],
        )
        .await?
        .try_get(0)?;
    let compiler_semantic_alias_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_semantic_alias_seed)?],
        )
        .await?
        .try_get(0)?;
    let compiler_maximum_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_maximum_seed)?],
        )
        .await?
        .try_get(0)?;
    let compiler_rhai_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&compiler_rhai_seed)?],
        )
        .await?
        .try_get(0)?;
    let conditional_bounded_seed_valid: bool = admin
        .query_one(
            "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
            &[&serde_json::to_string(&conditional_bounded_seed)?],
        )
        .await?
        .try_get(0)?;
    let mut credential_binding_results = Vec::new();
    for (case, seed, expected) in [
        ("direct Basic data credential", &compiler_dhis2_seed, true),
        (
            "outbound credential exchange without a reference",
            &exchange_without_reference,
            false,
        ),
        (
            "direct Basic credential half-pair",
            &direct_basic_half_pair,
            false,
        ),
        (
            "zero-exchange credential destination",
            &direct_basic_with_destination,
            false,
        ),
        (
            "zero-exchange credential token lifetime",
            &direct_basic_with_token_lifetime,
            false,
        ),
        (
            "snapshot dangling credential reference",
            &snapshot_with_dangling_reference,
            false,
        ),
    ] {
        let valid = admin
            .query_one(
                "SELECT relay_state_private.consultation_completion_seed_valid_v1($1)",
                &[&serde_json::to_string(seed)?],
            )
            .await?
            .try_get::<_, bool>(0)?;
        credential_binding_results.push((case, valid, expected));
    }
    reset_role(&admin).await?;
    assert!(seed_valid, "snapshot completion seed must satisfy SQL");
    assert!(
        !subset_outcomes_valid,
        "public outcome subsets must fail closed"
    );
    assert!(
        ambiguous_seed_valid,
        "source_matches=2 admits the exact ambiguous profile"
    );
    assert!(
        compiler_normal_seed_valid,
        "the compiler's ordinary completion seed must satisfy SQL"
    );
    assert!(
        compiler_open_crvs_seed_valid,
        "the compiler's cache-disabled OpenCRVS seed must satisfy SQL"
    );
    assert!(
        compiler_snapshot_seed_valid,
        "the compiler's SnapshotExact seed must satisfy SQL"
    );
    assert!(
        !open_crvs_positive_lifetime_valid,
        "presence-only OAuth must use null, never an expiry-bound lifetime"
    );
    assert!(
        !obsolete_operation_union_valid,
        "the dynamic-ordinal seed must reject obsolete predeclared operation unions"
    );
    assert!(
        !out_of_order_ordinal_valid,
        "the seed validator must enforce exact monotonic dynamic ordinals"
    );
    assert!(
        compiler_semantic_alias_seed_valid,
        "compiler-produced semantic aliases need not equal raw acquisition keys"
    );
    assert!(
        compiler_maximum_seed_valid,
        "the SQL seed validator must accept the compiler's exact-maximum profile"
    );
    assert!(
        compiler_rhai_seed_valid,
        "the SQL seed validator must accept the compiler's five-operation two-slot Rhai profile"
    );
    assert!(
        conditional_bounded_seed_valid,
        "Bounded HTTP permits bind actual-call positions across conditional skips"
    );
    for (case, actual, expected) in credential_binding_results {
        assert_eq!(actual, expected, "SQL credential binding case: {case}");
    }
    let pseudonym_write = atomic_consultation_attempt_write(
        &pseudonym_operation,
        initial_keyring_metadata.active_key_id(),
        &pseudonym_seed,
        "pseudonym-bound-insert",
    );
    assert_eq!(
        plane_one.write_phase(&pseudonym_write).await,
        Err(DurableAuditWriteError::StoreFailure),
        "generic durable sink must never insert a consultation"
    );
    let initial_write_epoch = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let pseudonym_attempt_authority = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let mut pseudonym_dispatch = persist_prepared_test_consultation_attempt(
        &plane_one,
        pseudonym_write.clone(),
        pseudonym_seed.clone(),
        initial_keyring_metadata.active_key_id(),
        pseudonym_attempt_authority,
        initial_write_epoch,
    )
    .await?;
    assert!(pseudonym_dispatch.credential_permit_mut()?.is_none());
    assert!(pseudonym_dispatch.next_data_permit_mut()?.is_none());
    assert!(matches!(
        plane_one
            .recover_pseudonym_bound_duplicate(&pseudonym_write)
            .await?,
        PseudonymBoundDuplicateRecoveryOutcome::IdenticalDuplicate(_)
    ));
    let missing_pseudonym_write = consultation_attempt_write(
        &DurableAuditOperationId::from_ulid(Ulid::new()),
        initial_keyring_metadata.active_key_id(),
        "duplicate-only-must-not-insert",
    );
    let head_before_missing_recovery: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        plane_one
            .recover_pseudonym_bound_duplicate(&missing_pseudonym_write)
            .await?,
        PseudonymBoundDuplicateRecoveryOutcome::NotFound
    );
    let head_after_missing_recovery: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head WHERE singleton",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(head_after_missing_recovery, head_before_missing_recovery);

    let coarse_denial = DurableAuditWrite::new(
        DurableAuditStreamKind::Denial,
        DurableAuditOperationId::from_ulid(Ulid::new()),
        DurableAuditPhase::DenialDecision,
        json!({"reason_class": "authentication"}),
    )?;
    assert!(matches!(
        plane_one.write_phase(&coarse_denial).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    assert_eq!(
        plane_one
            .recover_pseudonym_bound_duplicate(&coarse_denial)
            .await,
        Err(DurableAuditWriteError::StoreFailure),
        "duplicate-only pseudonym recovery must reject a coarse denial"
    );

    let stale_issued_epoch = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let stale_consultation_completion_epoch = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let held_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let held_write = pseudonym_denial_write(
        &held_operation,
        initial_keyring_metadata.active_key_id(),
        "held-shared-keyring-barrier",
    );
    let held_epoch = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let (held_key_id, held_generation, held_digest, held_chain, held_lock_key) =
        held_epoch.postgres_binding();
    let (mut held_client, held_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    held_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let held_transaction = held_client.transaction().await?;
    let held_snapshot = held_transaction
        .query_one(
            SNAPSHOT_SQL,
            &[
                &held_write.key().stream_kind().as_str(),
                &held_write.key().operation_id().as_str(),
                &held_write.key().phase().as_str(),
                &held_write.payload_digest().as_bytes().as_slice(),
                &held_chain.as_str(),
                &Some(held_key_id),
                &Some(held_generation),
                &Some(held_digest.as_slice()),
                &held_lock_key,
            ],
        )
        .await?;
    assert_eq!(held_snapshot.try_get::<_, &str>("outcome")?, "candidate");
    let rotating_maintenance = Arc::clone(&keyring_maintenance);
    let rotation_task = tokio::spawn(async move {
        rotating_maintenance
            .rotate(initial_binding, |current, transition_time| {
                rotation_successor(current, transition_time.unix_ms(), "epoch-2")
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !rotation_task.is_finished(),
        "exclusive rotation must wait behind a held shared CAS barrier"
    );
    held_transaction.rollback().await?;
    drop(held_client);
    held_driver.abort();
    let rotated_binding = rotation_task.await??;
    let current_epoch_2 = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    assert_eq!(current_epoch_2.key_id().as_str(), "epoch-2");
    let (stale_key_id, stale_generation, stale_digest, stale_chain, stale_lock_key) =
        stale_consultation_completion_epoch.postgres_binding();
    let (stale_completion_client, stale_completion_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    stale_completion_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let (pseudonym_permit_kinds, pseudonym_permit_ordinals) =
        pseudonym_dispatch.postgres_permit_arrays();
    let stale_completion_outcome: String = stale_completion_client
        .query_one(
            "SELECT outcome FROM relay_state_api.consultation_completion_snapshot_normal_v1(\
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12\
            )",
            &[
                &pseudonym_dispatch.operation_id.as_str(),
                &pseudonym_dispatch.lock_key.as_i64(),
                &pseudonym_dispatch.holder_id,
                &pseudonym_dispatch.fence_generation,
                &pseudonym_dispatch.deadline_unix_ms,
                &pseudonym_permit_kinds,
                &pseudonym_permit_ordinals,
                &stale_key_id,
                &stale_generation,
                &stale_digest.as_slice(),
                &stale_chain.as_str(),
                &stale_lock_key,
            ],
        )
        .await?
        .try_get("outcome")?;
    assert_eq!(stale_completion_outcome, "pseudonym_authority_stale");
    let stale_completion_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE operation_id=$1 AND phase='completion'",
            &[&pseudonym_dispatch.operation_id.as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        stale_completion_rows, 0,
        "a stale completion epoch must be proven non-mutating"
    );
    drop(stale_completion_client);
    stale_completion_driver.abort();
    let snapshot_acquired_at_unix_ms = current_unix_ms();
    let snapshot_generation = Ulid::new().to_string();
    let snapshot_facts = KnownConsultationCompletionFacts::public_for_snapshot_test(
        PublicConsultationOutcome::NoMatch,
        snapshot_acquired_at_unix_ms,
        Some(snapshot_acquired_at_unix_ms),
        Some("snapshot-revision-1"),
        &snapshot_generation,
        snapshot_acquired_at_unix_ms,
    )?;
    let publication_after_rotation = match plane_one
        .finalize_validated_consultation_for_test(
            pseudonym_dispatch,
            snapshot_facts,
            current_epoch_2,
        )
        .await?
    {
        KnownCompletionDisposition::Published(publication) => publication,
        KnownCompletionDisposition::FinalizedFailure(_) => {
            panic!("SnapshotExact public facts must produce a publication grant")
        }
    };
    assert!(!publication_after_rotation
        .stored_identity()
        .envelope_id()
        .is_empty());
    let stale_after_rotation_write = pseudonym_denial_write(
        &DurableAuditOperationId::from_ulid(Ulid::new()),
        initial_keyring_metadata.active_key_id(),
        "stale-issued-authority",
    );
    assert!(plane_one
        .write_phase_with_pseudonym_authority(&stale_after_rotation_write, stale_issued_epoch)
        .await
        .is_err());
    let stale_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase WHERE operation_id=$1",
            &[&stale_after_rotation_write.key().operation_id().as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(stale_rows, 0);

    let (recovery_client, recovery_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let recovery_plane = PostgresDurableAuditStatePlane::connect(
        recovery_client,
        test_chain_hasher.clone(),
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    assert!(matches!(
        recovery_plane
            .recover_pseudonym_bound_duplicate(&pseudonym_write)
            .await?,
        PseudonymBoundDuplicateRecoveryOutcome::IdenticalDuplicate(_)
    ));
    let conflicting_recovery_write = consultation_attempt_write(
        &pseudonym_operation,
        initial_keyring_metadata.active_key_id(),
        "conflicting-recovery-payload",
    );
    assert!(matches!(
        recovery_plane
            .recover_pseudonym_bound_duplicate(&conflicting_recovery_write)
            .await?,
        PseudonymBoundDuplicateRecoveryOutcome::ConflictingDuplicate(_)
    ));
    drop(recovery_plane);
    recovery_driver.abort();

    let retained_lookup = keyring_reader
        .lookup_snapshot(AuthorizedAuditPseudonymLookupSubset::for_test([
            pseudonym_key_id("epoch-1"),
            pseudonym_key_id("epoch-2"),
        ])?)
        .await?;
    assert_eq!(retained_lookup.epochs().len(), 2);
    assert_eq!(retained_lookup.epochs()[0].key_id().as_str(), "epoch-1");
    assert_eq!(retained_lookup.epochs()[1].key_id().as_str(), "epoch-2");
    let retired_epoch_1_destroy_after = match &retained_lookup.epochs()[0] {
        AuditPseudonymLookupEpoch::Retained(epoch) => epoch.destroy_after_unix_ms(),
        AuditPseudonymLookupEpoch::Active { .. } => {
            panic!("epoch-1 must be retained after rotation")
        }
    };
    let wait_for_retirement_ms = retired_epoch_1_destroy_after
        .saturating_sub(current_unix_ms())
        .saturating_add(25);
    tokio::time::sleep(Duration::from_millis(u64::try_from(
        wait_for_retirement_ms,
    )?))
    .await;
    assert_eq!(
        keyring_reader
            .lookup_snapshot(AuthorizedAuditPseudonymLookupSubset::for_test([
                pseudonym_key_id("epoch-1"),
            ])?)
            .await
            .err(),
        Some(PostgresKeyringError::UnauthorizedLookupSubset)
    );
    assert_eq!(
        keyring_runtime.current_write_authority().await.err(),
        Some(PostgresKeyringError::RetainedEpochExpired)
    );
    let maintained_binding = keyring_maintenance
        .maintain(rotated_binding, |current, _maintenance_time| {
            AuditPseudonymKeyringMetadata::new(
                current.generation() + 1,
                current.active_key_id().clone(),
                current.active_since_unix_ms(),
                current.active_write_deadline_unix_ms(),
                current.audit_event_retention_ms(),
                vec![],
            )
            .map_err(|_| PostgresKeyringError::InvalidMaintenance)
        })
        .await?;
    assert_eq!(
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?
            .key_id()
            .as_str(),
        "epoch-2"
    );
    assert_eq!(
        keyring_maintenance
            .rotate(maintained_binding, |current, transition_time| {
                rotation_successor(current, transition_time.unix_ms(), "epoch-1")
            })
            .await
            .err(),
        Some(PostgresKeyringError::ReusedKeyId)
    );

    let history_transaction = admin.transaction().await?;
    history_transaction
        .batch_execute(&format!("SET ROLE {}", quote_identifier(&owner_role)))
        .await?;
    history_transaction
        .execute(
            "INSERT INTO relay_state_private.audit_pseudonym_used_key_id(\
                 key_id,first_generation,first_activated_at_unix_ms\
             ) SELECT 'k'||lpad(value::text,63,'0'), value+10, 0 \
             FROM generate_series(1,4094) AS value",
            &[],
        )
        .await?;
    let bounded_history = history_transaction
        .query_one(
            "SELECT * FROM relay_state_private.audit_pseudonym_history_snapshot_v1()",
            &[],
        )
        .await?;
    assert_eq!(
        bounded_history.try_get::<_, i64>("used_key_id_count")?,
        4096
    );
    assert_eq!(
        bounded_history
            .try_get::<_, Vec<String>>("used_key_ids")?
            .len(),
        4096
    );
    history_transaction
        .execute(
            "INSERT INTO relay_state_private.audit_pseudonym_used_key_id(\
                 key_id,first_generation,first_activated_at_unix_ms\
             ) VALUES ('k-over-protocol-history-limit',5000,0)",
            &[],
        )
        .await?;
    let history_overflow = history_transaction
        .query_one(
            "SELECT * FROM relay_state_private.audit_pseudonym_history_snapshot_v1()",
            &[],
        )
        .await
        .expect_err("history helper must fail before returning an over-cap array");
    assert_eq!(
        history_overflow.as_db_error().map(|error| error.code()),
        Some(&SqlState::PROGRAM_LIMIT_EXCEEDED)
    );
    history_transaction.rollback().await?;

    let (chain_drift_client, chain_drift_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let chain_drift_runtime = PostgresAuditPseudonymKeyringRuntime::connect(
        chain_drift_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    let (chain_drift_maintenance_client, chain_drift_maintenance_driver) = postgres_client_as(
        &database_url,
        &keyring_maintenance_role_name,
        &keyring_maintenance_password,
    )
    .await?;
    let chain_drift_maintenance = PostgresAuditPseudonymKeyringMaintenance::connect(
        chain_drift_maintenance_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    let (chain_drift_reader_client, chain_drift_reader_driver) = postgres_client_as(
        &database_url,
        &keyring_reader_role_name,
        &keyring_reader_password,
    )
    .await?;
    let chain_drift_reader = PostgresAuditPseudonymKeyringReader::connect(
        chain_drift_reader_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    set_role(&admin, &owner_role).await?;
    admin
        .execute(
            "UPDATE relay_state_private.state_plane_metadata \
             SET chain_key_epoch_id='drifted-chain-epoch' WHERE singleton",
            &[],
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        chain_drift_runtime.current_write_authority().await.err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    assert_eq!(
        chain_drift_maintenance
            .maintain(maintained_binding, |_current, _transition_time| {
                panic!("metadata drift must be rejected before building a successor")
            })
            .await
            .err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    assert_eq!(
        chain_drift_reader
            .lookup_snapshot(AuthorizedAuditPseudonymLookupSubset::for_test([
                pseudonym_key_id("epoch-2"),
            ])?)
            .await
            .err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    set_role(&admin, &owner_role).await?;
    admin
        .execute(
            "UPDATE relay_state_private.state_plane_metadata \
             SET chain_key_epoch_id=$1 WHERE singleton",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?;
    reset_role(&admin).await?;
    drop(chain_drift_runtime);
    chain_drift_driver.abort();
    drop(chain_drift_maintenance);
    chain_drift_maintenance_driver.abort();
    drop(chain_drift_reader);
    chain_drift_reader_driver.abort();

    let (lock_drift_client, lock_drift_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let lock_drift_runtime = PostgresAuditPseudonymKeyringRuntime::connect(
        lock_drift_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    let (lock_drift_maintenance_client, lock_drift_maintenance_driver) = postgres_client_as(
        &database_url,
        &keyring_maintenance_role_name,
        &keyring_maintenance_password,
    )
    .await?;
    let lock_drift_maintenance = PostgresAuditPseudonymKeyringMaintenance::connect(
        lock_drift_maintenance_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    let (lock_drift_reader_client, lock_drift_reader_driver) = postgres_client_as(
        &database_url,
        &keyring_reader_role_name,
        &keyring_reader_password,
    )
    .await?;
    let lock_drift_reader = PostgresAuditPseudonymKeyringReader::connect(
        lock_drift_reader_client,
        chain_key_epoch_id.clone(),
        test_pseudonym_keyring_lock_key(),
    )
    .await?;
    set_role(&admin, &owner_role).await?;
    admin
        .execute(
            "UPDATE relay_state_private.state_plane_metadata \
             SET audit_pseudonym_keyring_lock_key=7221091444 WHERE singleton",
            &[],
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        lock_drift_runtime.current_write_authority().await.err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    assert_eq!(
        lock_drift_maintenance
            .maintain(maintained_binding, |_current, _transition_time| {
                panic!("metadata drift must be rejected before building a successor")
            })
            .await
            .err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    assert_eq!(
        lock_drift_reader
            .lookup_snapshot(AuthorizedAuditPseudonymLookupSubset::for_test([
                pseudonym_key_id("epoch-2"),
            ])?)
            .await
            .err(),
        Some(PostgresKeyringError::CapabilityDrift)
    );
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    admin
        .execute(
            "UPDATE relay_state_private.state_plane_metadata \
             SET audit_pseudonym_keyring_lock_key=$1 WHERE singleton",
            &[&test_pseudonym_keyring_lock_key().as_i64()],
        )
        .await?;
    reset_role(&admin).await?;
    drop(lock_drift_runtime);
    lock_drift_driver.abort();
    drop(lock_drift_maintenance);
    lock_drift_maintenance_driver.abort();
    drop(lock_drift_reader);
    lock_drift_reader_driver.abort();
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    let operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    let write = attempt_write(&operation_id, "identical");
    let (first, second) =
        tokio::join!(plane_one.write_phase(&write), plane_two.write_phase(&write));
    let first = first?;
    let second = second?;
    assert!(matches!(
        (&first, &second),
        (
            DurableAuditWriteOutcome::Inserted(_),
            DurableAuditWriteOutcome::IdenticalDuplicate(_)
        ) | (
            DurableAuditWriteOutcome::IdenticalDuplicate(_),
            DurableAuditWriteOutcome::Inserted(_)
        )
    ));
    assert_eq!(
        first.stored_identity().envelope_id(),
        second.stored_identity().envelope_id()
    );
    assert!(matches!(
        plane_two
            .write_phase(&attempt_write(&operation_id, "conflict"))
            .await?,
        DurableAuditWriteOutcome::ConflictingDuplicate(_)
    ));

    // A snapshot held inside an explicit transaction has no cross-call lock or
    // reservation. A separate writer can advance the head while it remains open.
    let crashed_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let crashed_write = attempt_write(&crashed_operation, "crash-retry");
    let (mut crash_client, crash_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let crash_transaction = crash_client.transaction().await?;
    crash_transaction
        .batch_execute("SET LOCAL synchronous_commit = 'off'")
        .await?;
    let _candidate = direct_snapshot(&crash_transaction, &crashed_write).await?;
    assert_eq!(
        crash_transaction
            .query_one("SHOW lock_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "2s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW statement_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "5s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW idle_in_transaction_session_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "5s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW synchronous_commit", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "on"
    );
    let snapshot_started = Instant::now();
    assert!(matches!(
        plane_two.write_phase(&crashed_write).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    assert!(snapshot_started.elapsed() < Duration::from_secs(3));
    drop(crash_transaction);
    drop(crash_client);
    crash_driver.abort();
    let no_reservation_table: bool = admin
        .query_one(
            "SELECT to_regclass('relay_state_private.audit_phase_preparation') IS NULL",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(no_reservation_table);

    let attempt_identity = first.stored_identity();
    let completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        operation_id,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(attempt_identity)
                .to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    assert!(matches!(
        plane_one.write_phase(&completion).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    let orphan_completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        DurableAuditOperationId::from_ulid(Ulid::new()),
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(attempt_identity)
                .to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    assert_eq!(
        plane_two.write_phase(&orphan_completion).await,
        Err(DurableAuditWriteError::StoreFailure)
    );

    let stored_envelopes = admin
        .query(
            "SELECT envelope_json FROM relay_state_private.audit_phase",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| serde_json::from_str::<AuditEnvelope>(row.get::<_, &str>(0)))
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_chain = order_chain(stored_envelopes);
    let verification = verify_chain(&ordered_chain, &test_chain_hasher)?;
    assert_eq!(verification.records, 16);
    let head: Vec<u8> = admin
        .query_one(
            "SELECT record_hash FROM relay_state_private.audit_chain_head WHERE singleton = true",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        Some(head.as_slice()),
        verification.last_hash.as_ref().map(<[u8; 32]>::as_slice)
    );

    // The serving fence is a separate, dedicated session capability. Runtime
    // role/database GUC inheritance must fail before advisory-lock acquisition.
    admin
        .batch_execute(&format!(
            "ALTER ROLE {} SET session_replication_role = 'replica'",
            quote_identifier(&runtime_role_name)
        ))
        .await?;
    let (replica_fence_client, replica_fence_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let replica_fence_result = PostgresServingFence::acquire(
        replica_fence_client,
        replica_fence_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await;
    admin
        .batch_execute(&format!(
            "ALTER ROLE {} RESET session_replication_role",
            quote_identifier(&runtime_role_name)
        ))
        .await?;
    assert_eq!(
        replica_fence_result
            .err()
            .expect("replica-mode fence client must fail"),
        ServingFenceError::CapabilityDrift
    );

    // A different advisory key cannot create a second deployment fence.
    let (wrong_key_client, wrong_key_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let wrong_key = ServingFenceLockKey::new(fence_key.as_i64() + 1)?;
    assert_eq!(
        PostgresServingFence::acquire(
            wrong_key_client,
            wrong_key_driver,
            &chain_key_epoch_id,
            wrong_key,
        )
        .await
        .err()
        .expect("unbound deployment key must fail"),
        ServingFenceError::Unavailable
    );

    assert_eq!(fence_one.generation(), 1);
    assert_eq!(fence_one.readiness().await, ServingFenceReadiness::Ready);
    let durable_generation: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.serving_fence_state \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(durable_generation, 1);
    let null_backend_error = admin
        .execute(
            "UPDATE relay_state_private.serving_fence_state \
             SET holder_backend_pid = NULL WHERE singleton = true",
            &[],
        )
        .await
        .expect_err("an active fence must always bind a backend PID");
    assert_eq!(
        null_backend_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::CHECK_VIOLATION)
    );

    // A second Relay cannot acquire the same deployment fence while the first
    // dedicated session owns it.
    let (contender_client, contender_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let contention_started = Instant::now();
    assert_eq!(
        PostgresServingFence::acquire(
            contender_client,
            contender_driver,
            &chain_key_epoch_id,
            fence_key,
        )
        .await
        .err()
        .expect("second holder must be rejected"),
        ServingFenceError::Contended
    );
    assert!(contention_started.elapsed() < Duration::from_secs(3));

    // The exact compiler-produced ordinary and maximal seeds also pass the
    // atomic attempt path, not only the standalone SQL validator.
    for (marker, compiler_seed) in [
        ("compiler-normal-seed", compiler_normal_seed.clone()),
        ("compiler-dhis2-basic-seed", compiler_dhis2_seed.clone()),
        ("compiler-maximum-seed", compiler_maximum_seed.clone()),
    ] {
        let credential_count = u8::try_from(
            compiler_seed["bounds"]["credential_exchanges"]
                .as_u64()
                .expect("compiler fixture has typed credential bounds"),
        )?;
        let data_count = u8::try_from(
            compiler_seed["bounds"]["data_exchanges"]
                .as_u64()
                .expect("compiler fixture has typed data bounds"),
        )?;
        let compiler_dispatch = persist_test_consultation_attempt(
            &plane_one,
            &fence_one,
            &keyring_runtime,
            &pseudonym_key_id("epoch-2"),
            compiler_seed,
            ConsultationPermitSet::from_counts(credential_count, data_count)?,
            marker,
        )
        .await?;
        let compiler_receipt = plane_one
            .close_unfinished_consultation_for_test(
                compiler_dispatch,
                keyring_runtime
                    .current_write_authority()
                    .await?
                    .authorize_use()?,
            )
            .await?;
        assert_eq!(
            compiler_receipt.outcome(),
            ConsultationCompletionOutcome::NotStarted
        );
    }

    // Seed rejection occurs inside the same PostgreSQL transaction as attempt,
    // intent, and child insertion. No partial authority-bearing row may remain.
    let invalid_atomic_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let mut invalid_atomic_seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    invalid_atomic_seed["acquisition"]["public_outcomes"] = json!(["match"]);
    let invalid_atomic_write = atomic_consultation_attempt_write(
        &invalid_atomic_operation,
        &pseudonym_key_id("epoch-2"),
        &invalid_atomic_seed,
        "invalid-seed-is-atomic",
    );
    let invalid_atomic_authority = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 1)?,
        )
        .await?;
    let invalid_atomic_prepared = PreparedAtomicConsultationAttempt::for_state_test(
        invalid_atomic_write,
        invalid_atomic_seed,
        &pseudonym_key_id("epoch-2"),
        invalid_atomic_authority,
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?,
        future_decision_expiry_unix_ms(),
    )?;
    assert_eq!(
        plane_one
            .write_attempt_with_completion_intent(invalid_atomic_prepared)
            .await
            .err(),
        Some(ConsultationPersistenceError::InvalidInput)
    );
    let partial_atomic_rows: i64 = admin
        .query_one(
            "SELECT \
                 (SELECT count(*) FROM relay_state_private.audit_phase \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.consultation_completion_intent \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.dispatch_permit \
                  WHERE operation_id=$1)",
            &[&invalid_atomic_operation.as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(partial_atomic_rows, 0);

    // The Rust aggregate cannot shorten or widen the compiler-owned timeout.
    // Both directions fail before any audit, intent, or child permit mutation.
    for (marker, seed_timeout_ms, fence_timeout_ms) in [
        ("timeout-shortening-rejected", 10_000_u64, 9_000_u64),
        ("timeout-widening-rejected", 5_000_u64, 6_000_u64),
    ] {
        let operation = DurableAuditOperationId::from_ulid(Ulid::new());
        let mut seed = completion_seed_value("snapshot_exact", None, &[], &[]);
        seed["bounds"]["timeout_ms"] = json!(seed_timeout_ms);
        let write = atomic_consultation_attempt_write(
            &operation,
            &pseudonym_key_id("epoch-2"),
            &seed,
            marker,
        );
        let fence_authority = fence_one
            .authorize_consultation_attempt(
                DispatchPermitBudget::new(Duration::from_millis(fence_timeout_ms))?,
                ConsultationPermitSet::from_counts(0, 0)?,
            )
            .await?;
        let prepared = PreparedAtomicConsultationAttempt::for_state_test(
            write,
            seed,
            &pseudonym_key_id("epoch-2"),
            fence_authority,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
            future_decision_expiry_unix_ms(),
        )?;
        assert_eq!(
            plane_one
                .write_attempt_with_completion_intent(prepared)
                .await
                .err(),
            Some(ConsultationPersistenceError::InvalidInput)
        );
        let rows: i64 = admin
            .query_one(
                "SELECT \
                     (SELECT count(*) FROM relay_state_private.audit_phase \
                      WHERE operation_id=$1) + \
                     (SELECT count(*) FROM relay_state_private.consultation_completion_intent \
                      WHERE operation_id=$1) + \
                     (SELECT count(*) FROM relay_state_private.dispatch_permit \
                      WHERE operation_id=$1)",
                &[&operation.as_str()],
            )
            .await?
            .try_get(0)?;
        assert_eq!(rows, 0, "timeout mismatch must be non-mutating");
    }

    // The SQL boundary independently rejects both timeout mismatch directions,
    // even when a runtime session bypasses the sealed Rust aggregate.
    let (direct_budget_client, direct_budget_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    direct_budget_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let fence_holder: String = admin
        .query_one(
            "SELECT holder_id FROM relay_state_private.serving_fence_state \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    let direct_epoch = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let (epoch_key_id, epoch_generation, epoch_digest, epoch_chain, epoch_lock_key) =
        direct_epoch.postgres_binding();
    let (bundle_canonical, bundle_digest) = canonical_test_binding(&json!({
        "commitment_key_id": epoch_key_id,
        "subject_handle": "hmac-sha256:test-only-redacted-handle",
        "input_commitment": "hmac-sha256:test-only-input-commitment",
        "predicate_commitment": "hmac-sha256:test-only-predicate-commitment",
        "consent_evidence_commitment": null,
    }));
    let empty_kinds = Vec::<String>::new();
    let empty_ordinals = Vec::<i16>::new();
    for (marker, seed_timeout_ms, supplied_budget_ms) in [
        ("sql-timeout-shortening", 10_000_i64, 9_000_i32),
        ("sql-timeout-widening", 5_000_i64, 6_000_i32),
    ] {
        let operation = DurableAuditOperationId::from_ulid(Ulid::new());
        let mut seed = completion_seed_value("snapshot_exact", None, &[], &[]);
        seed["bounds"]["timeout_ms"] = json!(seed_timeout_ms);
        let (seed_canonical, seed_digest) = canonical_test_binding(&seed);
        let write = atomic_consultation_attempt_write(
            &operation,
            &pseudonym_key_id("epoch-2"),
            &seed,
            marker,
        );
        let payload_digest = write.payload_digest().as_bytes().to_vec();
        let error = direct_budget_client
            .query_one(
                "SELECT * FROM relay_state_api.consultation_attempt_intent_snapshot_v1(\
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18\
                )",
                &[
                    &operation.as_str(),
                    &payload_digest,
                    &seed_canonical,
                    &seed_digest.as_slice(),
                    &bundle_canonical,
                    &bundle_digest.as_slice(),
                    &epoch_key_id,
                    &epoch_generation,
                    &epoch_digest.as_slice(),
                    &fence_key.as_i64(),
                    &fence_holder,
                    &fence_one.generation(),
                    &supplied_budget_ms,
                    &future_decision_expiry_unix_ms(),
                    &empty_kinds,
                    &empty_ordinals,
                    &epoch_chain.as_str(),
                    &epoch_lock_key,
                ],
            )
            .await
            .expect_err("SQL must reject a seed/permit budget mismatch");
        assert_eq!(
            error.as_db_error().map(|error| error.code()),
            Some(&SqlState::INVALID_PARAMETER_VALUE)
        );
        let rows: i64 = admin
            .query_one(
                "SELECT \
                     (SELECT count(*) FROM relay_state_private.audit_phase \
                      WHERE operation_id=$1) + \
                     (SELECT count(*) FROM relay_state_private.consultation_completion_intent \
                      WHERE operation_id=$1) + \
                     (SELECT count(*) FROM relay_state_private.dispatch_permit \
                      WHERE operation_id=$1) + \
                     (SELECT count(*) FROM relay_state_private.consultation_audit_context \
                      WHERE operation_id=$1)",
                &[&operation.as_str()],
            )
            .await?
            .try_get(0)?;
        assert_eq!(rows, 0, "SQL timeout mismatch must be non-mutating");
    }
    drop(direct_budget_client);
    direct_budget_driver.abort();

    // PostgreSQL independently rejects an expired decision before the attempt
    // snapshot's temporary audit context or any durable row can be written.
    let expired_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let expired_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    let expired_write = atomic_consultation_attempt_write(
        &expired_operation,
        &pseudonym_key_id("epoch-2"),
        &expired_seed,
        "database-expired-decision",
    );
    let expired_authority = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let expired_prepared = PreparedAtomicConsultationAttempt::for_state_test(
        expired_write,
        expired_seed,
        &pseudonym_key_id("epoch-2"),
        expired_authority,
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?,
        current_unix_ms() - 1,
    )?;
    assert_eq!(
        plane_one
            .write_attempt_with_completion_intent(expired_prepared)
            .await
            .err(),
        Some(ConsultationPersistenceError::StateConflict)
    );
    let expired_rows: i64 = admin
        .query_one(
            "SELECT \
                 (SELECT count(*) FROM relay_state_private.audit_phase \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.consultation_completion_intent \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.dispatch_permit \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.consultation_audit_context \
                  WHERE operation_id=$1)",
            &[&expired_operation.as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(expired_rows, 0, "expired decision must be non-mutating");
    assert_eq!(
        fence_one.readiness().await,
        ServingFenceReadiness::Ready,
        "an authority stays harmless until a mutating attempt CAS is possible"
    );

    // Expiry is rechecked only after the CAS has serialized behind the audit
    // head. If the decision expires while waiting for that lock, PostgreSQL
    // mutates nothing and Rust disarms the proven-nonmutating lifecycle seal.
    let boundary_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let boundary_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    let boundary_write = atomic_consultation_attempt_write(
        &boundary_operation,
        &pseudonym_key_id("epoch-2"),
        &boundary_seed,
        "decision-expires-between-snapshot-and-cas",
    );
    let boundary_authority = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let boundary_expiry = current_unix_ms() + 1_000;
    let boundary_prepared = PreparedAtomicConsultationAttempt::for_state_test(
        boundary_write,
        boundary_seed,
        &pseudonym_key_id("epoch-2"),
        boundary_authority,
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?,
        boundary_expiry,
    )?;
    let (mut boundary_blocker, boundary_blocker_driver) = postgres_client(&database_url).await?;
    let boundary_transaction = boundary_blocker.transaction().await?;
    boundary_transaction
        .query_one(
            "SELECT singleton FROM relay_state_private.audit_chain_head \
             WHERE singleton = true FOR UPDATE",
            &[],
        )
        .await?;
    let boundary_plane = Arc::clone(&plane_one);
    let boundary_task = tokio::spawn(async move {
        boundary_plane
            .write_attempt_with_completion_intent(boundary_prepared)
            .await
    });
    wait_for_blocked_consultation_query(
        &admin,
        &runtime_role_name,
        "consultation_attempt_intent_cas_v1",
    )
    .await?;
    let remaining_ms = boundary_expiry.saturating_sub(current_unix_ms()) + 50;
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(remaining_ms.max(0)).expect("nonnegative expiry delay"),
    ))
    .await;
    boundary_transaction.commit().await?;
    assert_eq!(
        boundary_task.await?.err(),
        Some(ConsultationPersistenceError::StateConflict)
    );
    let boundary_rows: i64 = admin
        .query_one(
            "SELECT \
                 (SELECT count(*) FROM relay_state_private.audit_phase \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.consultation_completion_intent \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.dispatch_permit \
                  WHERE operation_id=$1) + \
                 (SELECT count(*) FROM relay_state_private.consultation_audit_context \
                  WHERE operation_id=$1)",
            &[&boundary_operation.as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(boundary_rows, 0);
    assert_eq!(fence_one.readiness().await, ServingFenceReadiness::Ready);
    drop(boundary_blocker);
    boundary_blocker_driver.abort();

    // Exact durable replay remains recoverable after the authorization
    // decision expires. The retained dispatch guard then denies backend entry,
    // invokes no closure, and records a terminal not_started completion.
    let replay_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let replay_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    let replay_write = atomic_consultation_attempt_write(
        &replay_operation,
        &pseudonym_key_id("epoch-2"),
        &replay_seed,
        "identical-attempt-dispatch-seal",
    );
    let replay_expiry = current_unix_ms() + 2_000;
    let replay_authority_one = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let replay_prepared_one = PreparedAtomicConsultationAttempt::for_state_test(
        replay_write.clone(),
        replay_seed.clone(),
        &pseudonym_key_id("epoch-2"),
        replay_authority_one,
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?,
        replay_expiry,
    )?;
    let replay_dispatch_one = plane_one
        .write_attempt_with_completion_intent(replay_prepared_one)
        .await?
        .into_dispatch_for_state_test();
    let remaining_ms = replay_expiry.saturating_sub(current_unix_ms()) + 100;
    tokio::time::sleep(Duration::from_millis(
        u64::try_from(remaining_ms.max(0)).expect("nonnegative replay expiry delay"),
    ))
    .await;
    let replay_authority_two = fence_one
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(10))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let replay_prepared_two = PreparedAtomicConsultationAttempt::for_state_test(
        replay_write,
        replay_seed,
        &pseudonym_key_id("epoch-2"),
        replay_authority_two,
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?,
        replay_expiry,
    )?;
    let replay_dispatch_two = plane_one
        .write_attempt_with_completion_intent(replay_prepared_two)
        .await?;
    assert!(replay_dispatch_one.lifecycle_is_armed());
    let replay_backend_invocations = Arc::new(AtomicUsize::new(0));
    let observed_invocations = Arc::clone(&replay_backend_invocations);
    let replay_denied = match replay_dispatch_two
        .run_backend(move |_, _| {
            Box::pin(async move {
                observed_invocations.fetch_add(1, Ordering::SeqCst);
                ValidatedConsultationBackendResult::for_test(
                    (),
                    KnownConsultationCompletionFacts::failure_for_test(
                        KnownFailureClass::SourceUnavailable,
                    ),
                )
            })
        })
        .await
    {
        Err(denied) => denied,
        Ok(_) => panic!("expired exact replay must not enter the backend"),
    };
    assert_eq!(replay_backend_invocations.load(Ordering::SeqCst), 0);
    let replay_completion_two = plane_one
        .close_unfinished_consultation(replay_denied, &keyring_runtime)
        .await?;
    let replay_completion_one = plane_one
        .close_unfinished_consultation_for_test(
            replay_dispatch_one,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;
    assert_eq!(
        replay_completion_one.outcome(),
        ConsultationCompletionOutcome::NotStarted
    );
    assert_eq!(
        replay_completion_two.outcome(),
        ConsultationCompletionOutcome::NotStarted
    );
    assert_eq!(
        replay_completion_one.stored_identity().envelope_id(),
        replay_completion_two.stored_identity().envelope_id()
    );
    assert_eq!(fence_one.readiness().await, ServingFenceReadiness::Ready);

    // An operation outside the sealed slot capability is rejected before the
    // lazy source closure is constructed. The exact accepted operation is
    // then persisted with the one-shot dispatch marker, and an unfinished
    // close derives outcome_unknown solely from that marker.
    let bounded_seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    let mut bounded_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &fence_one,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        bounded_seed,
        ConsultationPermitSet::from_counts(0, 1)?,
        "bounded-selected-operation",
    )
    .await?;
    let bounded_operation_id = bounded_dispatch
        .next_data_permit_mut()?
        .expect("bounded data permit")
        .operation_id()
        .clone();
    let dispatched = Arc::new(AtomicUsize::new(0));
    let request_commitment = KeyedDispatchRequestCommitment::for_test("lookup-registration");
    let expected_commitment = request_commitment.as_str().to_owned();
    {
        let dispatched = Arc::clone(&dispatched);
        let permit = bounded_dispatch
            .next_data_permit_mut()?
            .expect("bounded data permit remains ready");
        fence_one
            .authorize_and_dispatch(permit, request_commitment, move |_deadline| async move {
                dispatched.fetch_add(1, Ordering::SeqCst);
            })
            .await?;
    }
    assert_eq!(dispatched.load(Ordering::SeqCst), 1);
    let persisted_commitment: String = admin
        .query_one(
            "SELECT request_commitment FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='data' AND ordinal=0",
            &[&bounded_operation_id.as_str()],
        )
        .await?
        .try_get(0)?;
    assert_eq!(persisted_commitment, expected_commitment);
    let dispatch_acknowledged: bool = admin
        .query_one(
            "SELECT dispatch_completed_at IS NOT NULL FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='data' AND ordinal=0",
            &[&bounded_operation_id.as_str()],
        )
        .await?
        .try_get(0)?;
    assert!(dispatch_acknowledged);
    let unfinished_receipt = plane_one
        .close_unfinished_consultation_for_test(
            bounded_dispatch,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;
    assert_eq!(
        unfinished_receipt.outcome(),
        ConsultationCompletionOutcome::OutcomeUnknown
    );

    // A known credential failure after only the credential marker is a valid
    // terminal result, but it can return only a receipt, never publication
    // authority for a public response.
    let credential_seed = completion_seed_value(
        "bounded_http",
        Some("fetch-credential"),
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    let mut credential_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &fence_one,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        credential_seed,
        ConsultationPermitSet::from_counts(1, 1)?,
        "credential-only-known-failure",
    )
    .await?;
    let credential_permit = credential_dispatch
        .credential_permit_mut()?
        .expect("credential permit");
    fence_one
        .authorize_and_dispatch(
            credential_permit,
            KeyedDispatchRequestCommitment::for_test("fetch-credential"),
            |_deadline| async {},
        )
        .await?;
    let credential_failure = plane_one
        .finalize_validated_consultation_for_test(
            credential_dispatch,
            KnownConsultationCompletionFacts::failure_for_test(
                KnownFailureClass::CredentialUnavailable,
            ),
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;
    match credential_failure {
        KnownCompletionDisposition::FinalizedFailure(receipt) => {
            assert_eq!(
                receipt.outcome(),
                ConsultationCompletionOutcome::KnownComplete
            );
            assert!(!receipt.stored_identity().envelope_id().is_empty());
        }
        KnownCompletionDisposition::Published(_) => {
            panic!("a known credential failure must not mint publication authority")
        }
    }

    // A SandboxedRhai call-budget slot carries the complete sorted callable
    // data union. Independent consultations may select different operations
    // at the same ordinal without widening or rewriting the sealed manifest.
    for selected_operation in ["lookup-a", "lookup-b"] {
        let rhai_seed = completion_seed_value(
            "sandboxed_rhai",
            None,
            &["lookup-a", "lookup-b"],
            &[vec!["lookup-a", "lookup-b"]],
        );
        let mut rhai_dispatch = persist_test_consultation_attempt(
            &plane_one,
            &fence_one,
            &keyring_runtime,
            &pseudonym_key_id("epoch-2"),
            rhai_seed,
            ConsultationPermitSet::from_counts(0, 1)?,
            "rhai-call-budget-slot",
        )
        .await?;
        let operation_id = rhai_dispatch
            .next_data_permit_mut()?
            .expect("Rhai data permit")
            .operation_id()
            .clone();
        let permit = rhai_dispatch
            .next_data_permit_mut()?
            .expect("Rhai data permit remains ready");
        fence_one
            .authorize_and_dispatch(
                permit,
                KeyedDispatchRequestCommitment::for_test(selected_operation),
                |_deadline| async {},
            )
            .await?;
        let request_commitment_stored: String = admin
            .query_one(
                "SELECT request_commitment FROM relay_state_private.dispatch_permit \
                 WHERE operation_id=$1 AND kind='data' AND ordinal=0",
                &[&operation_id.as_str()],
            )
            .await?
            .try_get(0)?;
        assert_eq!(
            request_commitment_stored,
            KeyedDispatchRequestCommitment::for_test(selected_operation).as_str()
        );
        let receipt = plane_one
            .close_unfinished_consultation_for_test(
                rhai_dispatch,
                keyring_runtime
                    .current_write_authority()
                    .await?
                    .authorize_use()?,
            )
            .await?;
        assert_eq!(
            receipt.outcome(),
            ConsultationCompletionOutcome::OutcomeUnknown
        );
    }

    // Bypassing the safe Rust cursor still cannot authorize Rhai data ordinal
    // one before zero. The rejected SQL call leaves both durable markers
    // untouched; the exact prefix is then accepted in order.
    let ordered_rhai_seed = completion_seed_value(
        "sandboxed_rhai",
        None,
        &["lookup-a", "lookup-b"],
        &[vec!["lookup-a", "lookup-b"], vec!["lookup-a", "lookup-b"]],
    );
    let mut ordered_rhai_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &fence_one,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        ordered_rhai_seed,
        ConsultationPermitSet::from_counts(0, 2)?,
        "rhai-monotonic-prefix",
    )
    .await?;
    let ordered_operation_id = ordered_rhai_dispatch
        .next_data_permit_mut()?
        .expect("first Rhai permit")
        .operation_id()
        .clone();
    let ordered_deadline = ordered_rhai_dispatch.deadline_unix_ms();
    assert_eq!(
        fence_one
            .authorize_permit_position_for_test(
                &ordered_operation_id,
                DispatchPermitKind::Data,
                1,
                KeyedDispatchRequestCommitment::for_test("lookup-b"),
                ordered_deadline,
            )
            .await
            .err(),
        Some(ServingFenceError::PermitOrderViolation)
    );
    let markers_after_gap: Vec<(i16, Option<String>, bool)> = admin
        .query(
            "SELECT ordinal, request_commitment, dispatched_at IS NOT NULL \
             FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='data' ORDER BY ordinal",
            &[&ordered_operation_id.as_str()],
        )
        .await?
        .into_iter()
        .map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)))
        .collect::<Result<_, tokio_postgres::Error>>()?;
    assert_eq!(
        markers_after_gap,
        vec![(0, None, false), (1, None, false)],
        "out-of-order authorization must not mutate either marker"
    );
    fence_one
        .authorize_permit_position_for_test(
            &ordered_operation_id,
            DispatchPermitKind::Data,
            0,
            KeyedDispatchRequestCommitment::for_test("lookup-a"),
            ordered_deadline,
        )
        .await?;
    fence_one
        .authorize_permit_position_for_test(
            &ordered_operation_id,
            DispatchPermitKind::Data,
            1,
            KeyedDispatchRequestCommitment::for_test("lookup-b"),
            ordered_deadline,
        )
        .await?;
    plane_one
        .close_unfinished_consultation_for_test(
            ordered_rhai_dispatch,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;

    // Bounded HTTP steps are fixed and cannot retry or reuse the same
    // operation at a later actual-call ordinal. Conditional skips may widen
    // each ordinal's accepted union, but they cannot turn one compiled step
    // into two outbound calls. Rhai intentionally retains repeatable calls.
    let bounded_reuse_seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-a", "lookup-b", "lookup-c"],
        &[
            vec!["lookup-a"],
            vec!["lookup-b", "lookup-c"],
            vec!["lookup-c"],
        ],
    );
    let mut bounded_reuse_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &fence_one,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        bounded_reuse_seed,
        ConsultationPermitSet::from_counts(0, 3)?,
        "bounded-fixed-step-no-reuse",
    )
    .await?;
    let bounded_reuse_operation = bounded_reuse_dispatch
        .next_data_permit_mut()?
        .expect("first Bounded HTTP permit")
        .operation_id()
        .clone();
    let bounded_reuse_deadline = bounded_reuse_dispatch.deadline_unix_ms();
    fence_one
        .authorize_permit_position_for_test(
            &bounded_reuse_operation,
            DispatchPermitKind::Data,
            0,
            KeyedDispatchRequestCommitment::for_test("lookup-a"),
            bounded_reuse_deadline,
        )
        .await?;
    fence_one
        .authorize_permit_position_for_test(
            &bounded_reuse_operation,
            DispatchPermitKind::Data,
            1,
            KeyedDispatchRequestCommitment::for_test("lookup-c"),
            bounded_reuse_deadline,
        )
        .await?;
    fence_one
        .authorize_permit_position_for_test(
            &bounded_reuse_operation,
            DispatchPermitKind::Data,
            2,
            KeyedDispatchRequestCommitment::for_test("lookup-c"),
            bounded_reuse_deadline,
        )
        .await?;
    let bounded_reuse_marker: (Option<String>, bool) = admin
        .query_one(
            "SELECT request_commitment, dispatched_at IS NOT NULL \
             FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='data' AND ordinal=2",
            &[&bounded_reuse_operation.as_str()],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert_eq!(
        bounded_reuse_marker,
        (
            Some(
                KeyedDispatchRequestCommitment::for_test("lookup-c")
                    .as_str()
                    .to_owned()
            ),
            true,
        ),
        "repeated complete effects remain valid at later monotonic ordinals"
    );
    plane_one
        .close_unfinished_consultation_for_test(
            bounded_reuse_dispatch,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;

    // A cached OAuth token may leave the credential permit unused, but once a
    // data call is recorded the credential exchange cannot be inserted later.
    let credential_order_seed = completion_seed_value(
        "bounded_http",
        Some("fetch-credential"),
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    let mut credential_order_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &fence_one,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        credential_order_seed,
        ConsultationPermitSet::from_counts(1, 1)?,
        "credential-before-data-if-used",
    )
    .await?;
    let credential_order_operation = credential_order_dispatch
        .next_data_permit_mut()?
        .expect("data permit with optional credential")
        .operation_id()
        .clone();
    let credential_order_deadline = credential_order_dispatch.deadline_unix_ms();
    fence_one
        .authorize_permit_position_for_test(
            &credential_order_operation,
            DispatchPermitKind::Data,
            0,
            KeyedDispatchRequestCommitment::for_test("lookup-registration"),
            credential_order_deadline,
        )
        .await?;
    assert_eq!(
        fence_one
            .authorize_permit_position_for_test(
                &credential_order_operation,
                DispatchPermitKind::Credential,
                0,
                KeyedDispatchRequestCommitment::for_test("fetch-credential"),
                credential_order_deadline,
            )
            .await
            .err(),
        Some(ServingFenceError::PermitOrderViolation)
    );
    let credential_marker: (Option<String>, bool) = admin
        .query_one(
            "SELECT request_commitment, dispatched_at IS NOT NULL \
             FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='credential' AND ordinal=0",
            &[&credential_order_operation.as_str()],
        )
        .await
        .and_then(|row| Ok((row.try_get(0)?, row.try_get(1)?)))?;
    assert_eq!(credential_marker, (None, false));
    plane_one
        .close_unfinished_consultation_for_test(
            credential_order_dispatch,
            keyring_runtime
                .current_write_authority()
                .await?
                .authorize_use()?,
        )
        .await?;

    // A runtime session without the advisory lock cannot authorize a child
    // permit, even when it knows the durable holder identity.
    let fence_one_holder: String = admin
        .query_one(
            "SELECT holder_id FROM relay_state_private.serving_fence_state \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    let direct_nonholder_operation = DispatchOperationId::from_ulid(Ulid::new());
    let (direct_nonholder_client, direct_nonholder_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    direct_nonholder_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let direct_nonholder_outcome: String = direct_nonholder_client
        .query_one(
            "SELECT outcome FROM relay_state_api.dispatch_permit_authorize_v1( \
                 $1, $2, $3, $4, $5, $6, $7, $8 \
             )",
            &[
                &fence_key.as_i64(),
                &fence_one_holder,
                &fence_one.generation(),
                &direct_nonholder_operation.as_str(),
                &"data",
                &0_i16,
                &"test-source-operation",
                &(current_unix_ms() + 1_000),
            ],
        )
        .await?
        .try_get("outcome")?;
    assert_eq!(direct_nonholder_outcome, "ownership_lost");
    drop(direct_nonholder_client);
    direct_nonholder_driver.abort();
    fence_one.release().await?;
    wait_for_fence_unlock(&admin, fence_key).await?;

    // Failed caller transactions are normalized before the next generation is
    // durably acquired.
    let (failed_fence_client, failed_fence_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    failed_fence_client.batch_execute("BEGIN").await?;
    let failed_fence_error = failed_fence_client
        .batch_execute("SELECT 1 / 0")
        .await
        .expect_err("test must leave the fence session aborted");
    assert_eq!(
        failed_fence_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::DIVISION_BY_ZERO)
    );
    let failed_fence = PostgresServingFence::acquire(
        failed_fence_client,
        failed_fence_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    assert_eq!(failed_fence.generation(), 2);
    failed_fence.release().await?;
    wait_for_fence_unlock(&admin, fence_key).await?;

    // If the dedicated fence session is lost after a dispatch marker commits,
    // the next generation must wait out the protocol barrier, recover the
    // orphan as outcome_unknown, and open admission only after every recovery
    // authority item has been consumed.
    let (orphan_client, orphan_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let orphan_driver_abort = orphan_driver.abort_handle();
    let orphan_fence =
        PostgresServingFence::acquire(orphan_client, orphan_driver, &chain_key_epoch_id, fence_key)
            .await?;
    assert_eq!(orphan_fence.generation(), 3);
    let orphan_seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    let mut orphan_dispatch = persist_test_consultation_attempt(
        &plane_one,
        &orphan_fence,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        orphan_seed,
        ConsultationPermitSet::from_counts(0, 1)?,
        "takeover-outcome-unknown",
    )
    .await?;
    let (orphan_dispatch_started, orphan_started) = tokio::sync::oneshot::channel();
    let abort_orphan_driver = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), orphan_started)
            .await
            .expect("guarded orphan dispatch must start promptly")
            .expect("guarded orphan dispatch start signal must be delivered");
        orphan_driver_abort.abort();
    });
    let orphan_permit = orphan_dispatch
        .next_data_permit_mut()?
        .expect("orphan data permit");
    assert_eq!(
        orphan_fence
            .authorize_and_dispatch(
                orphan_permit,
                KeyedDispatchRequestCommitment::for_test("lookup-registration"),
                move |_deadline| async move {
                    let _ = orphan_dispatch_started.send(());
                    std::future::pending::<()>().await;
                },
            )
            .await
            .err(),
        Some(ServingFenceError::Unavailable)
    );
    abort_orphan_driver.await?;
    assert!(orphan_dispatch
        .next_data_permit_mut()?
        .expect("uncertain orphan permit remains current")
        .is_uncertain());
    assert_eq!(
        orphan_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    wait_for_fence_unlock(&admin, fence_key).await?;

    let (takeover_client, takeover_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let takeover_started = Instant::now();
    let mut takeover_fence = PostgresServingFence::acquire(
        takeover_client,
        takeover_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    assert!(takeover_started.elapsed() >= Duration::from_secs(11));
    assert_eq!(takeover_fence.generation(), 4);
    assert_eq!(
        takeover_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    let mut recovery_authority = takeover_fence
        .take_takeover_recovery_authority()
        .expect("takeover with one orphan must issue recovery authority");
    assert_eq!(recovery_authority.remaining(), 1);
    let recovered = plane_one
        .recover_orphaned_consultation(&mut recovery_authority)
        .await?;
    assert_eq!(
        recovered.outcome(),
        ConsultationCompletionOutcome::OutcomeUnknown
    );
    assert!(!recovered.stored_identity().envelope_id().is_empty());
    assert_eq!(recovery_authority.remaining(), 0);
    takeover_fence
        .open_after_takeover_recovery(recovery_authority)
        .await?;
    assert_eq!(
        takeover_fence.readiness().await,
        ServingFenceReadiness::Ready
    );
    assert_eq!(
        {
            let orphan_permit = orphan_dispatch
                .next_data_permit_mut()?
                .expect("stale orphan permit remains current");
            takeover_fence
                .authorize_and_dispatch(
                    orphan_permit,
                    KeyedDispatchRequestCommitment::for_test("lookup-registration"),
                    |_deadline| async { panic!("a stale-generation permit must never dispatch") },
                )
                .await
                .err()
        },
        Some(ServingFenceError::StaleGeneration)
    );
    takeover_fence.release().await?;
    wait_for_fence_unlock(&admin, fence_key).await?;

    // A successor must linearize behind an attempt CAS that already validated
    // the prior fence. The audit-head blocker makes the interleaving exact:
    // the CAS holds the fence row in SHARE while no intent is visible yet.
    let (linearized_client, linearized_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let linearized_driver_abort = linearized_driver.abort_handle();
    let linearized_fence = PostgresServingFence::acquire(
        linearized_client,
        linearized_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    let linearized_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let linearized_operation_text = linearized_operation.as_str().to_owned();
    let mut linearized_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    linearized_seed["bounds"]["timeout_ms"] = json!(1);
    let linearized_write = atomic_consultation_attempt_write(
        &linearized_operation,
        &pseudonym_key_id("epoch-2"),
        &linearized_seed,
        "fence-row-linearized-attempt",
    );
    let linearized_authority = linearized_fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_millis(1))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let linearized_pseudonym_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let linearized_prepared = PreparedAtomicConsultationAttempt::for_state_test(
        linearized_write,
        linearized_seed,
        &pseudonym_key_id("epoch-2"),
        linearized_authority,
        linearized_pseudonym_authority,
        future_decision_expiry_unix_ms(),
    )?;
    let (mut head_blocker, head_blocker_driver) = postgres_client(&database_url).await?;
    let head_blocker_transaction = head_blocker.transaction().await?;
    head_blocker_transaction
        .query_one(
            "SELECT singleton FROM relay_state_private.audit_chain_head \
             WHERE singleton = true FOR UPDATE",
            &[],
        )
        .await?;
    let linearized_plane = Arc::clone(&plane_one);
    let linearized_attempt = tokio::spawn(async move {
        linearized_plane
            .write_attempt_with_completion_intent(linearized_prepared)
            .await
    });
    wait_for_blocked_consultation_query(
        &admin,
        &runtime_role_name,
        "consultation_attempt_intent_cas_v1",
    )
    .await?;
    linearized_driver_abort.abort();
    assert_eq!(
        linearized_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    wait_for_fence_unlock(&admin, fence_key).await?;

    let (successor_client, successor_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    successor_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let successor_holder = Ulid::new().to_string();
    let successor_lock_key = fence_key.as_i64();
    let successor_parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 2] =
        [&successor_lock_key, &successor_holder];
    let mut successor_acquire = Box::pin(successor_client.query_one(
        "SELECT * FROM relay_state_api.serving_fence_acquire_v1($1, $2)",
        &successor_parameters,
    ));
    tokio::select! {
        result = successor_acquire.as_mut() => {
            result?;
            return Err("successor crossed an uncommitted attempt CAS".into());
        }
        observed = wait_for_blocked_consultation_query(
            &admin,
            &runtime_role_name,
            "serving_fence_acquire_v1",
        ) => observed?,
    }
    head_blocker_transaction.commit().await?;
    let linearized_dispatch = linearized_attempt.await??.into_dispatch_for_state_test();
    assert!(linearized_dispatch.lifecycle_is_armed());
    let successor_row = successor_acquire.as_mut().await?;
    drop(successor_acquire);
    assert_eq!(successor_row.try_get::<_, &str>("outcome")?, "acquired");
    let successor_generation: i64 = successor_row.try_get("fence_generation")?;
    assert!(successor_row.try_get::<_, bool>("takeover_required")?);
    assert!(!successor_row.try_get::<_, bool>("admission_open")?);
    assert_eq!(
        direct_test_fence_open(
            &successor_client,
            fence_key,
            &successor_holder,
            successor_generation,
        )
        .await?,
        "recovery_incomplete"
    );
    let successor_operations = direct_test_fence_finalize(
        &successor_client,
        fence_key,
        &successor_holder,
        successor_generation,
    )
    .await?;
    assert_eq!(successor_operations, vec![linearized_operation_text]);
    let mut successor_recovery = direct_test_recovery_authority(
        fence_key,
        &successor_holder,
        successor_generation,
        successor_operations,
    )?;
    assert_eq!(
        plane_one
            .recover_orphaned_consultation(&mut successor_recovery)
            .await?
            .outcome(),
        ConsultationCompletionOutcome::NotStarted
    );
    assert_eq!(
        direct_test_fence_open(
            &successor_client,
            fence_key,
            &successor_holder,
            successor_generation,
        )
        .await?,
        "opened"
    );
    direct_test_fence_release(
        &successor_client,
        fence_key,
        &successor_holder,
        successor_generation,
    )
    .await?;
    drop(linearized_dispatch);
    drop(linearized_fence);
    drop(successor_client);
    successor_driver.abort();
    drop(head_blocker);
    head_blocker_driver.abort();
    wait_for_fence_unlock(&admin, fence_key).await?;

    // Dropping a task after its attempt CAS reached PostgreSQL loses the local
    // acknowledgement but not necessarily the commit. The armed authority
    // must fail the old fence closed, and row linearization must force the
    // successor to observe and recover the resulting intent.
    let (lost_attempt_client, lost_attempt_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let lost_attempt_fence = PostgresServingFence::acquire(
        lost_attempt_client,
        lost_attempt_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    let lost_attempt_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let lost_attempt_operation_text = lost_attempt_operation.as_str().to_owned();
    let mut lost_attempt_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    lost_attempt_seed["bounds"]["timeout_ms"] = json!(1);
    let lost_attempt_write = atomic_consultation_attempt_write(
        &lost_attempt_operation,
        &pseudonym_key_id("epoch-2"),
        &lost_attempt_seed,
        "lost-attempt-cas-acknowledgement",
    );
    let lost_attempt_authority = lost_attempt_fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_millis(1))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let lost_attempt_pseudonym_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let lost_attempt_prepared = PreparedAtomicConsultationAttempt::for_state_test(
        lost_attempt_write,
        lost_attempt_seed,
        &pseudonym_key_id("epoch-2"),
        lost_attempt_authority,
        lost_attempt_pseudonym_authority,
        future_decision_expiry_unix_ms(),
    )?;
    let (mut lost_attempt_blocker, lost_attempt_blocker_driver) =
        postgres_client(&database_url).await?;
    let lost_attempt_blocker_transaction = lost_attempt_blocker.transaction().await?;
    lost_attempt_blocker_transaction
        .query_one(
            "SELECT singleton FROM relay_state_private.audit_chain_head \
             WHERE singleton = true FOR UPDATE",
            &[],
        )
        .await?;
    let lost_attempt_plane = Arc::clone(&plane_one);
    let lost_attempt_task = tokio::spawn(async move {
        lost_attempt_plane
            .write_attempt_with_completion_intent(lost_attempt_prepared)
            .await
    });
    wait_for_blocked_consultation_query(
        &admin,
        &runtime_role_name,
        "consultation_attempt_intent_cas_v1",
    )
    .await?;
    lost_attempt_task.abort();
    let lost_attempt_join_error = match lost_attempt_task.await {
        Err(error) => error,
        Ok(_) => panic!("blocked attempt task must be cancelled"),
    };
    assert!(lost_attempt_join_error.is_cancelled());
    assert_eq!(
        lost_attempt_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    wait_for_fence_unlock(&admin, fence_key).await?;
    let (lost_successor_client, lost_successor_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let lost_successor = tokio::spawn(async move {
        let acquired = direct_test_fence_acquire(&lost_successor_client, fence_key)
            .await
            .map_err(|error| error.to_string());
        (lost_successor_client, acquired)
    });
    wait_for_blocked_consultation_query(&admin, &runtime_role_name, "serving_fence_acquire_v1")
        .await?;
    lost_attempt_blocker_transaction.commit().await?;
    let (lost_successor_client, lost_successor_acquired) = lost_successor.await?;
    let (lost_successor_holder, lost_successor_generation, takeover_required, admission_open) =
        lost_successor_acquired.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert!(takeover_required);
    assert!(!admission_open);
    assert_eq!(
        direct_test_fence_open(
            &lost_successor_client,
            fence_key,
            &lost_successor_holder,
            lost_successor_generation,
        )
        .await?,
        "recovery_incomplete"
    );
    let lost_successor_operations = direct_test_fence_finalize(
        &lost_successor_client,
        fence_key,
        &lost_successor_holder,
        lost_successor_generation,
    )
    .await?;
    assert_eq!(lost_successor_operations, vec![lost_attempt_operation_text]);
    let mut lost_successor_recovery = direct_test_recovery_authority(
        fence_key,
        &lost_successor_holder,
        lost_successor_generation,
        lost_successor_operations,
    )?;
    assert_eq!(
        plane_one
            .recover_orphaned_consultation(&mut lost_successor_recovery)
            .await?
            .outcome(),
        ConsultationCompletionOutcome::NotStarted
    );
    assert_eq!(
        direct_test_fence_open(
            &lost_successor_client,
            fence_key,
            &lost_successor_holder,
            lost_successor_generation,
        )
        .await?,
        "opened"
    );
    direct_test_fence_release(
        &lost_successor_client,
        fence_key,
        &lost_successor_holder,
        lost_successor_generation,
    )
    .await?;
    drop(lost_attempt_fence);
    drop(lost_successor_client);
    lost_successor_driver.abort();
    drop(lost_attempt_blocker);
    lost_attempt_blocker_driver.abort();
    wait_for_fence_unlock(&admin, fence_key).await?;

    // Once a one-shot marker is visible, cancelling the task that owns the
    // dispatch must drop its armed lifecycle seal. The old actor closes and
    // takeover derives outcome_unknown from the durable marker.
    let (marker_client, marker_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let marker_fence = Arc::new(
        PostgresServingFence::acquire(marker_client, marker_driver, &chain_key_epoch_id, fence_key)
            .await?,
    );
    let marker_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let marker_operation_text = marker_operation.as_str().to_owned();
    let mut marker_seed = completion_seed_value(
        "bounded_http",
        None,
        &["lookup-registration"],
        &[vec!["lookup-registration"]],
    );
    marker_seed["bounds"]["timeout_ms"] = json!(5_000);
    let marker_write = atomic_consultation_attempt_write(
        &marker_operation,
        &pseudonym_key_id("epoch-2"),
        &marker_seed,
        "cancel-after-visible-marker",
    );
    let marker_authority = marker_fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_secs(5))?,
            ConsultationPermitSet::from_counts(0, 1)?,
        )
        .await?;
    let marker_pseudonym_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let mut marker_dispatch = persist_prepared_test_consultation_attempt(
        &plane_one,
        marker_write,
        marker_seed,
        &pseudonym_key_id("epoch-2"),
        marker_authority,
        marker_pseudonym_authority,
    )
    .await?;
    assert!(marker_dispatch.lifecycle_is_armed());
    let (marker_visible, marker_started) = tokio::sync::oneshot::channel();
    let marker_task_fence = Arc::clone(&marker_fence);
    let marker_source_operation = OperationId::try_from("lookup-registration")?;
    let marker_task = tokio::spawn(async move {
        let permit = marker_dispatch
            .next_data_permit_mut()
            .expect("marker cursor is valid")
            .expect("marker data permit");
        marker_task_fence
            .authorize_and_dispatch(
                permit,
                KeyedDispatchRequestCommitment::for_test(marker_source_operation.as_str()),
                move |_deadline| async move {
                    let _ = marker_visible.send(());
                    std::future::pending::<()>().await;
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), marker_started)
        .await
        .expect("marker authorization must commit promptly")
        .expect("marker dispatch start signal must be delivered");
    let visible_marker: Option<String> = admin
        .query_one(
            "SELECT request_commitment FROM relay_state_private.dispatch_permit \
             WHERE operation_id=$1 AND kind='data' AND ordinal=0",
            &[&marker_operation_text],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        visible_marker.as_deref(),
        Some(KeyedDispatchRequestCommitment::for_test("lookup-registration").as_str())
    );
    marker_task.abort();
    assert!(marker_task
        .await
        .expect_err("marker-owning task must be cancelled")
        .is_cancelled());
    assert_eq!(
        marker_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    wait_for_fence_unlock(&admin, fence_key).await?;
    let (marker_successor_client, marker_successor_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let (
        marker_successor_holder,
        marker_successor_generation,
        marker_takeover_required,
        marker_admission_open,
    ) = direct_test_fence_acquire(&marker_successor_client, fence_key).await?;
    assert!(marker_takeover_required);
    assert!(!marker_admission_open);
    assert_eq!(
        direct_test_fence_open(
            &marker_successor_client,
            fence_key,
            &marker_successor_holder,
            marker_successor_generation,
        )
        .await?,
        "recovery_incomplete"
    );
    let marker_successor_operations = direct_test_fence_finalize(
        &marker_successor_client,
        fence_key,
        &marker_successor_holder,
        marker_successor_generation,
    )
    .await?;
    assert_eq!(marker_successor_operations, vec![marker_operation_text]);
    let mut marker_successor_recovery = direct_test_recovery_authority(
        fence_key,
        &marker_successor_holder,
        marker_successor_generation,
        marker_successor_operations,
    )?;
    assert_eq!(
        plane_one
            .recover_orphaned_consultation(&mut marker_successor_recovery)
            .await?
            .outcome(),
        ConsultationCompletionOutcome::OutcomeUnknown
    );
    assert_eq!(
        direct_test_fence_open(
            &marker_successor_client,
            fence_key,
            &marker_successor_holder,
            marker_successor_generation,
        )
        .await?,
        "opened"
    );
    direct_test_fence_release(
        &marker_successor_client,
        fence_key,
        &marker_successor_holder,
        marker_successor_generation,
    )
    .await?;
    drop(marker_fence);
    drop(marker_successor_client);
    marker_successor_driver.abort();
    wait_for_fence_unlock(&admin, fence_key).await?;

    // Completion uses the same fence-row root. If its acknowledgement is lost
    // while the audit-head update is blocked, dropping the dispatch seals the
    // old actor. The successor cannot advance generation until the terminal
    // write commits, after which no recovery batch is necessary.
    let (completion_race_client, completion_race_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let completion_race_fence = PostgresServingFence::acquire(
        completion_race_client,
        completion_race_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    let completion_race_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let completion_race_operation_text = completion_race_operation.as_str().to_owned();
    let mut completion_race_seed = completion_seed_value("snapshot_exact", None, &[], &[]);
    completion_race_seed["bounds"]["timeout_ms"] = json!(1);
    let completion_race_write = atomic_consultation_attempt_write(
        &completion_race_operation,
        &pseudonym_key_id("epoch-2"),
        &completion_race_seed,
        "lost-completion-cas-acknowledgement",
    );
    let completion_race_authority = completion_race_fence
        .authorize_consultation_attempt(
            DispatchPermitBudget::new(Duration::from_millis(1))?,
            ConsultationPermitSet::from_counts(0, 0)?,
        )
        .await?;
    let completion_race_attempt_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let completion_race_dispatch = persist_prepared_test_consultation_attempt(
        &plane_one,
        completion_race_write,
        completion_race_seed,
        &pseudonym_key_id("epoch-2"),
        completion_race_authority,
        completion_race_attempt_authority,
    )
    .await?;
    assert!(completion_race_dispatch.lifecycle_is_armed());
    let completion_race_pseudonym_authority = keyring_runtime
        .current_write_authority()
        .await?
        .authorize_use()?;
    let (mut completion_head_blocker, completion_head_blocker_driver) =
        postgres_client(&database_url).await?;
    let completion_head_blocker_transaction = completion_head_blocker.transaction().await?;
    completion_head_blocker_transaction
        .query_one(
            "SELECT singleton FROM relay_state_private.audit_chain_head \
             WHERE singleton = true FOR UPDATE",
            &[],
        )
        .await?;
    let completion_race_plane = Arc::clone(&plane_one);
    let completion_race_task = tokio::spawn(async move {
        completion_race_plane
            .close_unfinished_consultation_for_test(
                completion_race_dispatch,
                completion_race_pseudonym_authority,
            )
            .await
    });
    wait_for_blocked_consultation_query(
        &admin,
        &runtime_role_name,
        "consultation_completion_cas_unfinished_v1",
    )
    .await?;
    completion_race_task.abort();
    let completion_join_error = match completion_race_task.await {
        Err(error) => error,
        Ok(_) => panic!("blocked completion task must be cancelled"),
    };
    assert!(completion_join_error.is_cancelled());
    assert_eq!(
        completion_race_fence.readiness().await,
        ServingFenceReadiness::Unavailable
    );
    wait_for_fence_unlock(&admin, fence_key).await?;
    let (completion_successor_client, completion_successor_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let completion_successor = tokio::spawn(async move {
        let acquired = direct_test_fence_acquire(&completion_successor_client, fence_key)
            .await
            .map_err(|error| error.to_string());
        (completion_successor_client, acquired)
    });
    wait_for_blocked_consultation_query(&admin, &runtime_role_name, "serving_fence_acquire_v1")
        .await?;
    completion_head_blocker_transaction.commit().await?;
    let (completion_successor_client, completion_successor_acquired) = completion_successor.await?;
    let (
        completion_successor_holder,
        completion_successor_generation,
        completion_takeover_required,
        completion_admission_open,
    ) = completion_successor_acquired
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert!(!completion_takeover_required);
    assert!(completion_admission_open);
    let terminal_completion: (String, String) = admin
        .query_one(
            "SELECT intent.state, phase_row.record_json::jsonb #>> '{payload,outcome}' \
             FROM relay_state_private.consultation_completion_intent AS intent \
             JOIN relay_state_private.audit_phase AS phase_row \
               ON phase_row.stream_kind='consultation' \
              AND phase_row.operation_id=intent.operation_id \
              AND phase_row.phase='completion' \
             WHERE intent.operation_id=$1",
            &[&completion_race_operation_text],
        )
        .await
        .map(|row| (row.get(0), row.get(1)))?;
    assert_eq!(
        terminal_completion,
        ("completed".into(), "not_started".into())
    );
    direct_test_fence_release(
        &completion_successor_client,
        fence_key,
        &completion_successor_holder,
        completion_successor_generation,
    )
    .await?;
    drop(completion_race_fence);
    drop(completion_successor_client);
    completion_successor_driver.abort();
    drop(completion_head_blocker);
    completion_head_blocker_driver.abort();
    wait_for_fence_unlock(&admin, fence_key).await?;

    // A direct runtime caller can hold a successful CAS open in an explicit
    // transaction, but the function-owned limits bound both the contender and
    // the idle lock holder. The failed contender can then safely rebuild.
    let lock_holder_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let lock_holder_write = attempt_write(&lock_holder_operation, "direct-lock-holder");
    let (mut lock_client, lock_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let lock_transaction = lock_client.transaction().await?;
    let lock_candidate = direct_snapshot(&lock_transaction, &lock_holder_write).await?;
    let lock_envelope = lock_holder_write
        .build_envelope_at_chain_head(lock_candidate.predecessor, &test_chain_hasher)?;
    assert_eq!(
        direct_cas(
            &lock_transaction,
            &lock_holder_write,
            &lock_candidate,
            &lock_envelope,
        )
        .await?,
        "inserted"
    );
    for (setting, expected) in [
        ("lock_timeout", "2s"),
        ("statement_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "5s"),
        ("synchronous_commit", "on"),
    ] {
        let value: String = lock_transaction
            .query_one(&format!("SHOW {setting}"), &[])
            .await?
            .try_get(0)?;
        assert_eq!(value, expected);
    }
    let blocked_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let blocked_write = attempt_write(&blocked_operation, "lock-timeout");
    let started = Instant::now();
    assert_eq!(
        plane_one.write_phase(&blocked_write).await,
        Err(DurableAuditWriteError::StoreUnavailable)
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        lock_transaction.query_one("SELECT 1", &[]).await.is_err(),
        "function-local idle timeout must terminate the explicit transaction"
    );
    drop(lock_transaction);
    drop(lock_client);
    lock_driver.abort();
    let blocked_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE operation_id = $1",
            &[&blocked_operation.as_str()],
        )
        .await?
        .get(0);
    assert_eq!(blocked_rows, 0);
    assert!(matches!(
        plane_one.write_phase(&blocked_write).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));

    // Both production terminal orchestrators retain their exact armed
    // dispatch across pseudonym-key rotation. One rotation is scheduled at
    // the two distinct boundaries: known completion before its snapshot and
    // unfinished completion after its candidate snapshot but before CAS.
    let (terminal_rotation_client, terminal_rotation_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let terminal_rotation_fence = PostgresServingFence::acquire(
        terminal_rotation_client,
        terminal_rotation_driver,
        &chain_key_epoch_id,
        fence_key,
    )
    .await?;
    let completion_rows_before_rotation: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind='consultation' AND phase='completion'",
            &[],
        )
        .await?
        .try_get(0)?;
    let completed_intents_before_rotation: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.consultation_completion_intent \
             WHERE state='completed'",
            &[],
        )
        .await?
        .try_get(0)?;

    let known_rotation_dispatch = persist_test_prepared_dispatch(
        &plane_one,
        &terminal_rotation_fence,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        completion_seed_value("snapshot_exact", None, &[], &[]),
        ConsultationPermitSet::from_counts(0, 0)?,
        "terminal-rotation-before-snapshot",
        current_unix_ms() + 30_000,
    )
    .await?;
    let known_rotation_observed_at = current_unix_ms();
    let known_rotation_facts = KnownConsultationCompletionFacts::public_for_snapshot_test(
        PublicConsultationOutcome::NoMatch,
        known_rotation_observed_at,
        Some(known_rotation_observed_at),
        Some("snapshot-revision-2"),
        &Ulid::new().to_string(),
        known_rotation_observed_at,
    )?;
    let known_rotation_executed = match known_rotation_dispatch
        .run_backend(|_, _| {
            Box::pin(async {
                ValidatedConsultationBackendResult::for_test(42_u8, known_rotation_facts)
            })
        })
        .await
    {
        Ok(executed) => executed,
        Err(_) => panic!("fresh known-completion decision must enter its backend"),
    };

    let unfinished_rotation_expiry = current_unix_ms() + 500;
    let unfinished_rotation_dispatch = persist_test_prepared_dispatch(
        &plane_one,
        &terminal_rotation_fence,
        &keyring_runtime,
        &pseudonym_key_id("epoch-2"),
        completion_seed_value("snapshot_exact", None, &[], &[]),
        ConsultationPermitSet::from_counts(0, 0)?,
        "terminal-rotation-before-cas",
        unfinished_rotation_expiry,
    )
    .await?;
    let remaining_until_denial = unfinished_rotation_expiry
        .saturating_sub(current_unix_ms())
        .saturating_add(25);
    tokio::time::sleep(Duration::from_millis(u64::try_from(
        remaining_until_denial,
    )?))
    .await;
    let unfinished_rotation_denied = match unfinished_rotation_dispatch
        .run_backend::<(), _>(|_, _| Box::pin(async { panic!("expired decision must not run") }))
        .await
    {
        Err(denied) => denied,
        Ok(_) => panic!("expired unfinished-completion decision must be denied"),
    };

    let (known_hook, mut known_control) =
        terminal_completion_test_hook(TerminalCompletionTestPoint::AfterAuthorityMinted);
    let (unfinished_hook, mut unfinished_control) =
        terminal_completion_test_hook(TerminalCompletionTestPoint::AfterCandidateSnapshot);
    let known_completion = plane_one.finalize_validated_consultation_with_test_hook(
        known_rotation_executed,
        &keyring_runtime,
        known_hook,
    );
    let unfinished_completion = plane_one.close_unfinished_consultation_with_test_hook(
        unfinished_rotation_denied,
        &keyring_runtime,
        unfinished_hook,
    );
    let terminal_rotation = async {
        tokio::time::timeout(Duration::from_secs(2), known_control.wait_until_paused())
            .await
            .expect("known completion reaches its authority pause")
            .expect("known completion pause remains connected");
        tokio::time::timeout(
            Duration::from_secs(2),
            unfinished_control.wait_until_paused(),
        )
        .await
        .expect("unfinished completion reaches its candidate pause")
        .expect("unfinished completion pause remains connected");
        let result = keyring_maintenance
            .rotate(maintained_binding, |current, transition_time| {
                if !current.retained_keys().is_empty() {
                    return Err(PostgresKeyringError::InvalidRotation);
                }
                rotation_successor(current, transition_time.unix_ms(), "epoch-3")
            })
            .await;
        known_control
            .resume()
            .expect("known completion pause resumes");
        unfinished_control
            .resume()
            .expect("unfinished completion pause resumes");
        result
    };
    let (known_completion, unfinished_completion, terminal_rotation) =
        tokio::join!(known_completion, unfinished_completion, terminal_rotation);
    terminal_rotation?;
    let (known_publication, known_output) = match known_completion? {
        FinalizedValidatedConsultation::Published { grant, output } => (grant, output),
        FinalizedValidatedConsultation::FinalizedFailure(_) => {
            panic!("validated public facts must mint publication authority")
        }
    };
    let unfinished_receipt = unfinished_completion?;
    assert_eq!(known_output, 42);
    assert_eq!(
        unfinished_receipt.outcome(),
        ConsultationCompletionOutcome::NotStarted
    );
    assert_ne!(
        known_publication.stored_identity().envelope_id(),
        unfinished_receipt.stored_identity().envelope_id()
    );
    assert_eq!(
        keyring_runtime
            .current_write_authority()
            .await?
            .authorize_use()?
            .key_id()
            .as_str(),
        "epoch-3"
    );
    let completion_rows_after_rotation: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind='consultation' AND phase='completion'",
            &[],
        )
        .await?
        .try_get(0)?;
    let completed_intents_after_rotation: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.consultation_completion_intent \
             WHERE state='completed'",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        completion_rows_after_rotation,
        completion_rows_before_rotation + 2
    );
    assert_eq!(
        completed_intents_after_rotation,
        completed_intents_before_rotation + 2
    );
    assert_eq!(
        terminal_rotation_fence.readiness().await,
        ServingFenceReadiness::Ready
    );
    terminal_rotation_fence.release().await?;
    wait_for_fence_unlock(&admin, fence_key).await?;

    // The database can validate structure and referential consistency, but it
    // cannot authenticate an external HMAC or classify arbitrary payload fields
    // as secrets. A credential holder can submit both directly; keyed verification
    // is what detects the forged chain hash.
    let arbitrary_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let arbitrary_write = DurableAuditWrite::new(
        DurableAuditStreamKind::Materialization,
        arbitrary_operation,
        DurableAuditPhase::Attempt,
        json!({
            "operator_supplied_field": {"api_key": "database-cannot-classify-this"},
            "test_marker": "direct-arbitrary-hash",
        }),
    )?;
    let (arbitrary_client, arbitrary_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let arbitrary_candidate = direct_snapshot(&arbitrary_client, &arbitrary_write).await?;
    let mut arbitrary_envelope = arbitrary_write.build_envelope_at_chain_head(
        arbitrary_candidate.predecessor,
        &AuditChainHasher::unkeyed_dev_only(),
    )?;
    arbitrary_envelope.record_hash = [0x5a; 32];
    assert_eq!(
        direct_cas(
            &arbitrary_client,
            &arbitrary_write,
            &arbitrary_candidate,
            &arbitrary_envelope,
        )
        .await?,
        "inserted"
    );
    drop(arbitrary_client);
    arbitrary_driver.abort();
    let forged_chain = order_chain(
        admin
            .query(
                "SELECT envelope_json FROM relay_state_private.audit_phase",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| serde_json::from_str::<AuditEnvelope>(row.get::<_, &str>(0)))
            .collect::<Result<Vec<_>, _>>()?,
    );
    assert!(matches!(
        verify_chain(&forged_chain, &test_chain_hasher),
        Err(ChainVerificationError::RecordHashMismatch { .. })
    ));

    // A third login can be granted EXECUTE accidentally, but every API function
    // still rejects it because session_user is not the persisted runtime OID.
    admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_api TO {attacker}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {attacker};",
            attacker = quote_identifier(&attacker_role)
        ))
        .await?;
    let (attacker_client, attacker_driver) =
        postgres_client_as(&database_url, &attacker_role, &attacker_password).await?;
    let attacker_error = attacker_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await
        .expect_err("unbound session_user must be rejected");
    assert_eq!(
        attacker_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(attacker_client);
    attacker_driver.abort();
    admin
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA relay_state_api FROM {attacker}; \
             REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM {attacker};",
            attacker = quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Any private ACL granted to a third role changes the exact catalog shape.
    admin
        .batch_execute(&format!(
            "GRANT SELECT ON relay_state_private.audit_phase TO {}",
            quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "REVOKE SELECT ON relay_state_private.audit_phase FROM {}",
            quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // NOINHERIT does not close SET ROLE. The installer and live capability both
    // reject even this membership before another source operation is admitted.
    let expected_visible_rows: i64 = admin
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_private TO {reader}; \
             GRANT SELECT ON relay_state_private.audit_phase TO {reader}; \
             GRANT {reader} TO {runtime} WITH INHERIT FALSE, SET TRUE;",
            reader = quote_identifier(&private_reader_role),
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::RuntimeRoleNotIsolated)
    );
    reset_role(&admin).await?;
    let (set_role_client, set_role_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert!(set_role_client
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await
        .is_err());
    set_role(&set_role_client, &private_reader_role).await?;
    let visible_rows: i64 = set_role_client
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await?
        .get(0);
    assert_eq!(
        visible_rows, expected_visible_rows,
        "test proves why all membership is forbidden"
    );
    reset_role(&set_role_client).await?;
    drop(set_role_client);
    set_role_driver.abort();
    admin
        .batch_execute(&format!(
            "REVOKE {reader} FROM {runtime}; \
             REVOKE SELECT ON relay_state_private.audit_phase FROM {reader}; \
             REVOKE USAGE ON SCHEMA relay_state_private FROM {reader};",
            reader = quote_identifier(&private_reader_role),
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Function security/search-path and constraint/metadata fingerprints are
    // checked on every readiness and write admission.
    admin
        .batch_execute(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) \
             SET search_path = public",
        )
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) \
             SET search_path = pg_catalog, relay_state_private",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute(
            "ALTER TABLE relay_state_private.state_plane_metadata \
                 DROP CONSTRAINT state_plane_metadata_schema_version_check; \
             ALTER TABLE relay_state_private.state_plane_metadata \
                 DROP CONSTRAINT state_plane_metadata_fingerprint_check; \
             UPDATE relay_state_private.state_plane_metadata \
                 SET schema_version = 2, capability_fingerprint = 'drifted';",
        )
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            r#"
UPDATE relay_state_private.state_plane_metadata
SET schema_version = 1, capability_fingerprint = '{fingerprint}';
ALTER TABLE relay_state_private.state_plane_metadata
    ADD CONSTRAINT state_plane_metadata_schema_version_check CHECK (schema_version = 1);
ALTER TABLE relay_state_private.state_plane_metadata
    ADD CONSTRAINT state_plane_metadata_fingerprint_check CHECK (
        capability_fingerprint = '{fingerprint}'
    );
"#,
            fingerprint = STATE_PLANE_SCHEMA_FINGERPRINT_V1,
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Durable tables, executable table state, and their constraint-backed
    // indexes are part of the attested capability, not operational tuning.
    admin
        .batch_execute("ALTER TABLE relay_state_private.consultation_quota_bucket SET UNLOGGED")
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute("ALTER TABLE relay_state_private.consultation_quota_bucket SET LOGGED")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase ENABLE ROW LEVEL SECURITY")
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase DISABLE ROW LEVEL SECURITY")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE INDEX audit_phase_unexpected_index \
                 ON relay_state_private.audit_phase (inserted_at)",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute("DROP INDEX relay_state_private.audit_phase_unexpected_index")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE TRIGGER audit_phase_unexpected_trigger \
                 BEFORE UPDATE ON relay_state_private.audit_phase \
                 FOR EACH ROW EXECUTE FUNCTION \
                 pg_catalog.suppress_redundant_updates_trigger()",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "DROP TRIGGER audit_phase_unexpected_trigger \
                 ON relay_state_private.audit_phase",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE RULE audit_phase_unexpected_rule AS \
                 ON INSERT TO relay_state_private.audit_phase DO INSTEAD NOTHING",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "DROP RULE audit_phase_unexpected_rule \
                 ON relay_state_private.audit_phase",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Defense in depth: even if a database owner defeats catalog attestation,
    // a suppressing INSERT trigger cannot advance the head while storing zero
    // phase rows.
    let suppressed_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let suppressed_write = attempt_write(&suppressed_operation, "suppressed-insert");
    let generation_before: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            r#"
CREATE FUNCTION relay_state_private.test_suppress_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN NULL;
END;
$function$;
CREATE TRIGGER audit_phase_suppress_insert
    BEFORE INSERT ON relay_state_private.audit_phase
    FOR EACH ROW EXECUTE FUNCTION relay_state_private.test_suppress_audit_insert();
CREATE OR REPLACE FUNCTION relay_state_private.capability_valid_v1()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
SELECT true;
$function$;
"#,
        )
        .await?;
    reset_role(&admin).await?;
    let (suppressed_client, suppressed_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let suppressed_candidate = direct_snapshot(&suppressed_client, &suppressed_write).await?;
    let suppressed_envelope = suppressed_write
        .build_envelope_at_chain_head(suppressed_candidate.predecessor, &test_chain_hasher)?;
    assert!(direct_cas(
        &suppressed_client,
        &suppressed_write,
        &suppressed_candidate,
        &suppressed_envelope,
    )
    .await
    .is_err());
    drop(suppressed_client);
    suppressed_driver.abort();
    let suppressed_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE operation_id = $1",
            &[&suppressed_operation.as_str()],
        )
        .await?
        .try_get(0)?;
    let generation_after: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(suppressed_rows, 0);
    assert_eq!(generation_after, generation_before);
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "DROP TRIGGER audit_phase_suppress_insert \
                 ON relay_state_private.audit_phase; \
             DROP FUNCTION relay_state_private.test_suppress_audit_insert();",
        )
        .await?;
    admin
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await?;
    reset_role(&admin).await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute(&format!(
            "GRANT SELECT (envelope_json) ON relay_state_private.audit_phase TO {attacker}",
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "REVOKE SELECT (envelope_json) ON relay_state_private.audit_phase FROM {attacker}",
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // A stale function owner is detected even if every other object is intact.
    admin
        .batch_execute(&format!(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO {}",
            quote_identifier(&stale_owner_role)
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO {owner};",
            owner = quote_identifier(&owner_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(&format!(
            "REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM PUBLIC; \
             REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};",
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    reset_role(&admin).await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Renaming one OUT column changes the function ABI. Runtime row decoding
    // must fail closed without panicking, and migration preflight must reject
    // the drift rather than overwriting it.
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(&format!(
            r#"
DROP FUNCTION relay_state_api.audit_readiness_v1(text);
CREATE FUNCTION relay_state_api.audit_readiness_v1(
    p_expected_chain_key_epoch_id text
)
RETURNS TABLE (
    is_ready boolean,
    capability_id text,
    capability_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    chain_key_epoch_id text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    RETURN QUERY
    SELECT relay_state_private.capability_valid_v1()
           AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id,
           metadata.capability_id,
           metadata.capability_fingerprint,
           metadata.owner_role_oid::bigint,
           metadata.runtime_role_oid::bigint,
           metadata.chain_key_epoch_id
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
END;
$function$;
REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};
"#,
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &keyring_maintenance_role,
            &keyring_reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;

    drop(plane_one);
    drop(plane_two);
    drop(keyring_runtime);
    drop(keyring_maintenance);
    drop(keyring_reader);
    driver_one.abort();
    driver_two.abort();
    keyring_runtime_driver.abort();
    keyring_maintenance_driver.abort();
    keyring_reader_driver.abort();
    let _ = driver_one.await;
    let _ = driver_two.await;
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [
        &runtime_role_name,
        &keyring_maintenance_role_name,
        &keyring_reader_role_name,
        &private_reader_role,
        &attacker_role,
        &bridge_role,
        &owner_role,
        &stale_owner_role,
    ] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL with max_prepared_transactions > 0"]
async fn postgres_state_plane_rejects_prepared_transaction_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(PREPARED_DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {PREPARED_DATABASE_URL_ENV} is not set");
        return Ok(());
    };
    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;
    let configured: i32 = admin
        .query_one(
            "SELECT current_setting('max_prepared_transactions')::integer",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(configured > 0);

    let owner_role = role_name("prepared_owner");
    let runtime_role_name = role_name("prepared_runtime");
    let maintenance_role_name = role_name("prepared_maintenance");
    let reader_role_name = role_name("prepared_reader");
    let runtime_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' \
                 NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {maintenance} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {reader} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             GRANT CREATE ON DATABASE {database} TO {owner};",
            owner = quote_identifier(&owner_role),
            runtime = quote_identifier(&runtime_role_name),
            maintenance = quote_identifier(&maintenance_role_name),
            reader = quote_identifier(&reader_role_name),
            runtime_password = runtime_password,
            database = quote_identifier(&database_name),
        ))
        .await?;
    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let maintenance_role = AuditPseudonymMaintenanceDatabaseRole::parse(&maintenance_role_name)?;
    let reader_role = AuditPseudonymReaderDatabaseRole::parse(&reader_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("prepared-rejection-epoch")?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &maintenance_role,
            &reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::UnsafeDatabaseConfiguration)
    );

    // Simulate a previously valid catalog observed after a restart that
    // enabled prepared transactions. The installer cannot create this state
    // under the unsafe setting, but readiness must independently reject it.
    seed_catalog_for_unsafe_restart(
        &admin,
        &runtime_role_name,
        &maintenance_role_name,
        &reader_role_name,
        &chain_key_epoch_id,
    )
    .await?;
    reset_role(&admin).await?;

    let (readiness_client, readiness_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let readiness = readiness_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?;
    assert!(!readiness.try_get::<_, bool>("ready")?);
    drop(readiness_client);
    readiness_driver.abort();

    let secret_env = format!(
        "REGISTRY_RELAY_STATE_PLANE_PREPARED_SECRET_{}",
        Ulid::new().to_string()
    );
    env::set_var(
        &secret_env,
        "prepared-restart-test-chain-secret-at-least-thirty-two-bytes",
    );
    let chain_hasher = AuditChainHasher::from_env(&secret_env)?;
    env::remove_var(&secret_env);
    let (runtime_client, runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            runtime_client,
            chain_hasher,
            chain_key_epoch_id,
            test_pseudonym_keyring_lock_key(),
        )
        .await
        .err()
        .expect("runtime capability must reject prepared transactions after restart"),
        StatePlaneInitializationError::CapabilityDrift
    );
    runtime_driver.abort();

    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; \
             DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [
        &runtime_role_name,
        &maintenance_role_name,
        &reader_role_name,
        &owner_role,
    ] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL with fsync or full_page_writes disabled"]
async fn postgres_state_plane_rejects_unsafe_wal_durability(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(UNSAFE_DURABILITY_DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {UNSAFE_DURABILITY_DATABASE_URL_ENV} is not set");
        return Ok(());
    };
    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;
    let durability = admin
        .query_one(
            "SELECT current_setting('fsync') = 'on' AS fsync_safe, \
                    current_setting('full_page_writes') = 'on' AS page_writes_safe",
            &[],
        )
        .await?;
    assert!(
        !durability.try_get::<_, bool>("fsync_safe")?
            || !durability.try_get::<_, bool>("page_writes_safe")?
    );

    let owner_role = role_name("durability_owner");
    let runtime_role_name = role_name("durability_runtime");
    let maintenance_role_name = role_name("durability_maintenance");
    let reader_role_name = role_name("durability_reader");
    let runtime_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' \
                 NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {maintenance} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {reader} LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             GRANT CREATE ON DATABASE {database} TO {owner};",
            owner = quote_identifier(&owner_role),
            runtime = quote_identifier(&runtime_role_name),
            maintenance = quote_identifier(&maintenance_role_name),
            reader = quote_identifier(&reader_role_name),
            runtime_password = runtime_password,
            database = quote_identifier(&database_name),
        ))
        .await?;
    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let maintenance_role = AuditPseudonymMaintenanceDatabaseRole::parse(&maintenance_role_name)?;
    let reader_role = AuditPseudonymReaderDatabaseRole::parse(&reader_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("unsafe-durability-epoch")?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut admin,
            &runtime_role,
            &chain_key_epoch_id,
            test_serving_fence_lock_key(),
            &maintenance_role,
            &reader_role,
            test_pseudonym_keyring_lock_key(),
        )
        .await,
        Err(StatePlaneInstallError::UnsafeDatabaseConfiguration)
    );
    seed_catalog_for_unsafe_restart(
        &admin,
        &runtime_role_name,
        &maintenance_role_name,
        &reader_role_name,
        &chain_key_epoch_id,
    )
    .await?;
    reset_role(&admin).await?;
    let (runtime_client, runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let readiness = runtime_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?;
    assert!(!readiness.try_get::<_, bool>("ready")?);
    drop(runtime_client);
    runtime_driver.abort();
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; \
             DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [
        &runtime_role_name,
        &maintenance_role_name,
        &reader_role_name,
        &owner_role,
    ] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}
