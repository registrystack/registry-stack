// SPDX-License-Identifier: Apache-2.0

//! Native record-timer ledger, claims, and exact system RLS policies.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use deadpool_postgres::Client;
use registry_platform_audit::{AuditEntry, AuditRequest};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_dispatch::postgres::LEASE_FINALIZATION_ALLOWANCE;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;

use crate::contract::Operation;
use crate::generated_ddl::{quote_identifier, quote_literal};
use crate::model::{
    CompiledActionTargetUseSource, CompiledPlanMutation, CompiledPlanTargetBinding,
    CompiledRegistry,
};
use crate::timer_operator::TimerEffectiveLimits;

use super::{
    begin_registry_transaction, ExpectedRegistryIdentity, GuardedTransaction, PostgresKernelError,
    RegistryLockKey, Result, RuntimePool, RuntimeRevoke, SqlIdentifier,
};

pub(super) const TIMER_CONTROL_TABLE: &str = "registry_internal.registry_record_timer_control";
pub(super) const TIMER_GENERATIONS_TABLE: &str =
    "registry_internal.registry_record_timer_generations";
pub(super) const TIMER_BINDINGS_TABLE: &str = "registry_internal.registry_record_timer_bindings";
pub(super) const TIMER_CURRENT_TABLE: &str = "registry_internal.registry_record_timer_current";
pub(super) const TIMER_ATTEMPTS_TABLE: &str = "registry_internal.registry_record_timer_attempts";
pub(super) const TIMER_DUE_INDEX: &str =
    "registry_internal.registry_record_timer_generations_due_idx";
pub(super) const TIMER_HISTORY_INDEX: &str =
    "registry_internal.registry_record_timer_generations_history_idx";
pub(super) const TIMER_LIVE_LEASE_INDEX: &str =
    "registry_internal.registry_record_timer_generations_live_lease_idx";
pub(super) const TIMER_STATE_BLOCK_INDEX: &str =
    "registry_internal.registry_record_timer_generations_state_block_idx";
pub(super) const TIMER_ACTIVATION_PREVIEW_INDEX: &str =
    "registry_internal.registry_record_timer_generations_activation_preview_idx";
pub(super) const TIMER_BINDINGS_OPEN_INDEX: &str =
    "registry_internal.registry_record_timer_bindings_open_idx";
pub(crate) const SUPPORTED_TIMER_PROTOCOL_VERSION: i32 = 1;
pub(crate) const RECORD_TIMER_MAINTENANCE_AUDIT_SCHEMA: &str =
    "breg-record-timer-maintenance-audit/v1";
pub(crate) const RECORD_TIMER_RETENTION_AUDIT_SCHEMA: &str = "breg-record-timer-retention-audit/v1";
const TIMER_RETENTION_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(feature = "postgres-test")]
const TIMER_CLOCK_FIXTURE_TABLE: &str = "registry_internal.registry_record_timer_clock_fixture";
#[cfg(feature = "postgres-test")]
const TIMER_CLOCK_FIXTURE_FUNCTION: &str = "registry_internal.record_timer_clock_fixture_now()";

pub(crate) const fn production_timer_limits() -> TimerEffectiveLimits {
    TimerEffectiveLimits {
        claim_batch_maximum: 1,
        stale_revision_batch_maximum: 32,
        elapsed_window_batch_maximum: 32,
        maximum_concurrent_attempts: 1,
        operator_list_maximum: crate::timer_operator::MAXIMUM_TIMER_LIST_LIMIT,
    }
}

const PRODUCTION_SCAN_INTERVAL: Duration = Duration::from_millis(250);
const PRODUCTION_FAILURE_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(feature = "postgres-test")]
const NATIVE_BEFORE_CLAIM_WAIT: Duration = Duration::from_secs(30);
#[cfg(feature = "postgres-test")]
const MAX_NATIVE_BARRIER_PATH_BYTES: usize = 4096;

#[cfg(feature = "postgres-test")]
#[derive(Clone)]
struct NativeBeforeClaimBarrier {
    instance_id: String,
    observed_path: std::path::PathBuf,
    release_path: std::path::PathBuf,
}

#[cfg(feature = "postgres-test")]
impl NativeBeforeClaimBarrier {
    fn from_env(instance_id: &str) -> std::result::Result<Option<Self>, ()> {
        let observed = std::env::var_os("BREG_TIMER_TEST_BEFORE_CLAIM_OBSERVED_PATH");
        let release = std::env::var_os("BREG_TIMER_TEST_BEFORE_CLAIM_RELEASE_PATH");
        let (observed, release) = match (observed, release) {
            (None, None) => return Ok(None),
            (Some(observed), Some(release)) => (observed, release),
            _ => return Err(()),
        };
        let observed_path = std::path::PathBuf::from(observed);
        let release_path = std::path::PathBuf::from(release);
        if !valid_native_barrier_path(&observed_path)
            || !valid_native_barrier_path(&release_path)
            || observed_path == release_path
            || observed_path.exists()
            || release_path.exists()
        {
            return Err(());
        }
        Ok(Some(Self {
            instance_id: instance_id.to_owned(),
            observed_path,
            release_path,
        }))
    }

    async fn observe_and_wait(&self, occurrence_id: uuid::Uuid) -> std::result::Result<(), ()> {
        let marker = registry_platform_canonical_json::canonicalize_json(&serde_json::json!({
            "instanceId": self.instance_id,
            "occurrenceId": occurrence_id,
            "processId": std::process::id(),
        }))
        .map_err(|_| ())?;
        let parent = self.observed_path.parent().ok_or(())?;
        let name = self
            .observed_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(())?;
        let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|_| ())?;
        {
            use std::io::Write as _;
            file.write_all(&marker).map_err(|_| ())?;
        }
        file.sync_all().map_err(|_| ())?;
        std::fs::rename(&temporary, &self.observed_path).map_err(|_| ())?;
        tokio::time::timeout(NATIVE_BEFORE_CLAIM_WAIT, async {
            loop {
                match std::fs::symlink_metadata(&self.release_path) {
                    Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
                    Ok(_) => return Err(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(_) => return Err(()),
                }
            }
        })
        .await
        .map_err(|_| ())?
    }
}

#[cfg(feature = "postgres-test")]
fn valid_native_barrier_path(path: &std::path::Path) -> bool {
    use std::path::Component;

    path.is_absolute()
        && !path.as_os_str().as_encoded_bytes().is_empty()
        && path.as_os_str().as_encoded_bytes().len() <= MAX_NATIVE_BARRIER_PATH_BYTES
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
        && path.parent().is_some_and(std::path::Path::is_dir)
        && path.file_name().and_then(|name| name.to_str()).is_some()
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeOutcomeSettlementKind {
    DeclaredRefusal,
    TechnicalFailure,
}

#[cfg(feature = "postgres-test")]
fn native_action_checkpoint_from_env(
    instance_id: &str,
) -> std::result::Result<
    (
        Option<crate::mutation::NativeTimerCheckpoint>,
        Option<NativeOutcomeSettlementKind>,
    ),
    (),
> {
    use crate::mutation::{NativeTimerCheckpoint, NativeTimerCheckpointPhase};

    let configurations = [
        (
            NativeTimerCheckpointPhase::AfterClaim,
            "BREG_TIMER_TEST_AFTER_CLAIM_OBSERVED_PATH",
            "BREG_TIMER_TEST_AFTER_CLAIM_RELEASE_PATH",
        ),
        (
            NativeTimerCheckpointPhase::BeforeCommit,
            "BREG_TIMER_TEST_BEFORE_COMMIT_OBSERVED_PATH",
            "BREG_TIMER_TEST_BEFORE_COMMIT_RELEASE_PATH",
        ),
        (
            NativeTimerCheckpointPhase::AfterCommitBeforeResponseRelease,
            "BREG_TIMER_TEST_AFTER_COMMIT_BEFORE_RESPONSE_OBSERVED_PATH",
            "BREG_TIMER_TEST_AFTER_COMMIT_BEFORE_RESPONSE_RELEASE_PATH",
        ),
        (
            NativeTimerCheckpointPhase::BeforeOutcomeSettlement,
            "BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_OBSERVED_PATH",
            "BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_RELEASE_PATH",
        ),
    ];
    let mut selected = None;
    let mut selected_phase = None;
    for (phase, observed_name, release_name) in configurations {
        let observed = std::env::var_os(observed_name);
        let release = std::env::var_os(release_name);
        let (observed, release) = match (observed, release) {
            (None, None) => continue,
            (Some(observed), Some(release)) => (
                std::path::PathBuf::from(observed),
                std::path::PathBuf::from(release),
            ),
            _ => return Err(()),
        };
        if selected.is_some()
            || !valid_native_barrier_path(&observed)
            || !valid_native_barrier_path(&release)
            || observed == release
            || observed.exists()
            || release.exists()
        {
            return Err(());
        }
        selected = Some(NativeTimerCheckpoint::new(
            phase,
            instance_id,
            observed,
            release,
        ));
        selected_phase = Some(phase);
    }
    let configured_kind = std::env::var_os("BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_KIND");
    let outcome_kind = match (selected_phase, configured_kind) {
        (Some(NativeTimerCheckpointPhase::BeforeOutcomeSettlement), Some(kind)) => {
            match kind.into_string().map_err(|_| ())?.as_str() {
                "declared-refusal" => Some(NativeOutcomeSettlementKind::DeclaredRefusal),
                "technical-failure" => Some(NativeOutcomeSettlementKind::TechnicalFailure),
                _ => return Err(()),
            }
        }
        (Some(NativeTimerCheckpointPhase::BeforeOutcomeSettlement), None) | (_, Some(_)) => {
            return Err(())
        }
        _ => None,
    };
    Ok((selected, outcome_kind))
}

#[cfg(feature = "postgres-test")]
fn native_lease_duration_from_env() -> std::result::Result<Option<Duration>, ()> {
    let Some(value) = std::env::var_os("BREG_TIMER_TEST_LEASE_MILLISECONDS") else {
        return Ok(None);
    };
    let value = value.into_string().map_err(|_| ())?;
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(());
    }
    let milliseconds = value.parse::<u64>().map_err(|_| ())?;
    let maximum = u64::try_from(production_lease_duration().as_millis()).map_err(|_| ())?;
    if milliseconds == 0 || milliseconds > maximum {
        return Err(());
    }
    Ok(Some(Duration::from_millis(milliseconds)))
}

fn production_lease_duration() -> Duration {
    super::mutation::REQUEST_ACTION_TIMEOUT.saturating_add(LEASE_FINALIZATION_ALLOWANCE)
}

#[derive(Clone, Debug)]
pub(super) struct TimerPolicyDescriptor {
    pub(super) table: String,
    pub(super) name: String,
    pub(super) command: &'static str,
    pub(super) has_using: bool,
    pub(super) has_check: bool,
}

pub(super) fn timer_policy_descriptors(registry: &CompiledRegistry) -> Vec<TimerPolicyDescriptor> {
    let mut policies = std::collections::BTreeMap::new();
    for (_, timer) in registry.timers() {
        let Some(action) = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == timer.invoke)
        else {
            continue;
        };
        for target in &timer.system_grant.targets {
            let entity_id = target.entity_id.as_str();
            let Some(entity) = registry.entities().get(entity_id) else {
                continue;
            };
            let supported = match target.operation {
                Operation::Get => true,
                Operation::Patch => action.effects.iter().any(|effect| {
                    effect.target.entity_id == entity_id
                        && effect.operation == Operation::Patch
                        && matches!(
                            effect.target.binding,
                            CompiledPlanTargetBinding::Existing { .. }
                        )
                }),
                Operation::Create => action.effects.iter().any(|effect| {
                    effect.target.entity_id == entity_id
                        && effect.operation == Operation::Create
                        && matches!(effect.target.binding, CompiledPlanTargetBinding::Create)
                }),
                _ => false,
            };
            if !supported {
                continue;
            }
            let descriptors = match target.operation {
                Operation::Get => vec![("select", "r", true, false), ("lock", "w", true, true)],
                Operation::Patch => {
                    vec![("select", "r", true, false), ("update", "w", true, true)]
                }
                Operation::Create => {
                    vec![("select", "r", true, false), ("insert", "a", false, true)]
                }
                _ => Vec::new(),
            };
            for (suffix, command, has_using, has_check) in descriptors {
                policies
                    .entry((
                        timer.record_type.clone(),
                        timer.id.clone(),
                        entity_id.to_owned(),
                        suffix,
                    ))
                    .or_insert(TimerPolicyDescriptor {
                        table: format!("registry_data.{}", entity.physical_table),
                        name: timer_policy_name(&timer.record_type, &timer.id, entity_id, suffix),
                        command,
                        has_using,
                        has_check,
                    });
            }
        }
    }
    policies.into_values().collect()
}

pub(super) async fn install_record_timer_schema(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    if registry.entities().values().any(|entity| {
        entity
            .access_profiles
            .contains_key(crate::mutation::TIMER_ACCESS_PROFILE)
    }) || registry.actions().actions.iter().any(|action| {
        action
            .permissions
            .iter()
            .any(|permission| permission.profile_id == crate::mutation::TIMER_ACCESS_PROFILE)
    }) {
        return Err(PostgresKernelError::Configuration(
            "the system record-timer access discriminator is reserved",
        ));
    }
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_record_timer_control (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 protocol_version integer NOT NULL DEFAULT 1 CHECK (protocol_version > 0),
                 control_state text NOT NULL DEFAULT 'running'
                     CHECK (control_state IN ('running','paused','adoption-hold')),
                 control_epoch bigint NOT NULL DEFAULT 1 CHECK (control_epoch >= 1),
                 bound_instance_epoch bigint NOT NULL DEFAULT 1 CHECK (bound_instance_epoch >= 1),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             INSERT INTO registry_internal.registry_record_timer_control (singleton)
             VALUES (true) ON CONFLICT (singleton) DO NOTHING;
             CREATE TABLE IF NOT EXISTS registry_internal.registry_record_timer_bindings (
                 record_type text NOT NULL CHECK (record_type <> ''),
                 timer_id text NOT NULL CHECK (timer_id <> ''),
                 incarnation bigint NOT NULL CHECK (incarnation >= 1),
                 definition_revision text NOT NULL CHECK (definition_revision ~ '^sha256:[0-9a-f]{64}$'),
                 action_revision text NOT NULL CHECK (action_revision ~ '^sha256:[0-9a-f]{64}$'),
                 system_grant_revision text NOT NULL CHECK (system_grant_revision ~ '^sha256:[0-9a-f]{64}$'),
                 created_activation_id uuid NOT NULL,
                 current_policy_activation_id uuid,
                 removed_activation_id uuid,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 removed_at timestamptz,
                 PRIMARY KEY (record_type,timer_id,incarnation),
                 CHECK ((removed_activation_id IS NULL) = (removed_at IS NULL)),
                 CHECK ((removed_activation_id IS NULL) = (current_policy_activation_id IS NOT NULL))
             );
             CREATE UNIQUE INDEX IF NOT EXISTS registry_record_timer_bindings_open_idx
                 ON registry_internal.registry_record_timer_bindings (record_type,timer_id)
                 WHERE removed_activation_id IS NULL;
             CREATE TABLE IF NOT EXISTS registry_internal.registry_record_timer_generations (
                 record_type text NOT NULL CHECK (record_type <> ''),
                 record_id uuid NOT NULL,
                 timer_id text NOT NULL CHECK (timer_id <> ''),
                 occurrence_id uuid PRIMARY KEY,
                 binding_incarnation bigint NOT NULL CHECK (binding_incarnation >= 1),
                 material_signature text NOT NULL CHECK (material_signature ~ '^sha256:[0-9a-f]{64}$'),
                 due_at timestamptz NOT NULL,
                 not_after timestamptz,
                 retry_at timestamptz,
                 definition_revision text NOT NULL CHECK (definition_revision ~ '^sha256:[0-9a-f]{64}$'),
                 action_revision text NOT NULL CHECK (action_revision ~ '^sha256:[0-9a-f]{64}$'),
                 system_grant_revision text NOT NULL CHECK (system_grant_revision ~ '^sha256:[0-9a-f]{64}$'),
                 gate_open boolean NOT NULL,
                 target_binding_digests jsonb NOT NULL DEFAULT '{}'::jsonb
                     CHECK (jsonb_typeof(target_binding_digests)='object'),
                 state text NOT NULL CHECK (state IN ('pending','leased','completed','refused','blocked','cancelled','superseded','missed')),
                 block_kind text CHECK (block_kind IN ('technical','configuration')),
                 outcome_code text CHECK (outcome_code IN ('completed','declared-refusal','input-refused','effect-conflict','execution-window-expired','control-cleared','anchor-tombstoned','binding-removed','superseded','attempts-exhausted')),
                 executed_attempt_count integer NOT NULL DEFAULT 0 CHECK (executed_attempt_count >= 0),
                 retry_allowance smallint NOT NULL DEFAULT 0 CHECK (retry_allowance IN (0,1)),
                 claim_owner_id uuid,
                 claim_epoch bigint NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
                 claim_token uuid,
                 claim_until timestamptz,
                 claimed_control_epoch bigint,
                 claimed_instance_epoch bigint,
                 claimed_activation_id uuid,
                 created_activation_id uuid NOT NULL,
                 current_policy_activation_id uuid,
                 executed_activation_id uuid,
                 receipt_correlation uuid,
                 completed_at timestamptz,
                 detail_expires_at timestamptz,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 FOREIGN KEY (record_type,timer_id,binding_incarnation)
                     REFERENCES registry_internal.registry_record_timer_bindings (record_type,timer_id,incarnation),
                 CHECK ((state='leased') = (claim_owner_id IS NOT NULL AND claim_token IS NOT NULL
                     AND claim_until IS NOT NULL AND claimed_control_epoch IS NOT NULL
                     AND claimed_instance_epoch IS NOT NULL AND claimed_activation_id IS NOT NULL)),
                 CHECK (state='leased' OR (claim_owner_id IS NULL AND claim_token IS NULL
                     AND claim_until IS NULL AND claimed_control_epoch IS NULL
                     AND claimed_instance_epoch IS NULL AND claimed_activation_id IS NULL)),
                 CHECK ((state='blocked') = (block_kind IS NOT NULL)),
                 CHECK (state <> 'completed' OR (completed_at IS NOT NULL
                     AND receipt_correlation IS NOT NULL AND outcome_code='completed'))
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_record_timer_current (
                 record_type text NOT NULL CHECK (record_type <> ''),
                 record_id uuid NOT NULL,
                 timer_id text NOT NULL CHECK (timer_id <> ''),
                 occurrence_id uuid NOT NULL UNIQUE
                     REFERENCES registry_internal.registry_record_timer_generations (occurrence_id),
                 binding_incarnation bigint NOT NULL CHECK (binding_incarnation >= 1),
                 material_signature text NOT NULL CHECK (material_signature ~ '^sha256:[0-9a-f]{64}$'),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (record_type,record_id,timer_id),
                 FOREIGN KEY (record_type,timer_id,binding_incarnation)
                     REFERENCES registry_internal.registry_record_timer_bindings (record_type,timer_id,incarnation)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_record_timer_attempts (
                 occurrence_id uuid NOT NULL
                     REFERENCES registry_internal.registry_record_timer_generations (occurrence_id),
                 attempt_number integer NOT NULL CHECK (attempt_number >= 1),
                 claim_owner_id uuid NOT NULL,
                 claim_epoch bigint NOT NULL CHECK (claim_epoch >= 1),
                 control_epoch bigint NOT NULL CHECK (control_epoch >= 1),
                 instance_epoch bigint NOT NULL CHECK (instance_epoch >= 1),
                 activation_id uuid NOT NULL,
                 definition_revision text NOT NULL CHECK (definition_revision ~ '^sha256:[0-9a-f]{64}$'),
                 action_revision text NOT NULL CHECK (action_revision ~ '^sha256:[0-9a-f]{64}$'),
                 system_grant_revision text NOT NULL CHECK (system_grant_revision ~ '^sha256:[0-9a-f]{64}$'),
                 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                 finished_at timestamptz,
                 detail_expires_at timestamptz,
                 block_kind text CHECK (block_kind IN ('technical','configuration')),
                 outcome_code text CHECK (outcome_code IN ('completed','declared-refusal','input-refused','effect-conflict','execution-window-expired','control-cleared','anchor-tombstoned','binding-removed','superseded','attempts-exhausted')),
                 technical_code text,
                 receipt_correlation uuid,
                 PRIMARY KEY (occurrence_id,attempt_number),
                 CHECK ((finished_at IS NULL) = (outcome_code IS NULL AND technical_code IS NULL)),
                 CHECK ((finished_at IS NULL) = (detail_expires_at IS NULL))
             );
             CREATE INDEX IF NOT EXISTS registry_record_timer_generations_due_idx
                 ON registry_internal.registry_record_timer_generations (due_at,retry_at,occurrence_id)
                 WHERE gate_open AND state IN ('pending','leased');
             CREATE INDEX IF NOT EXISTS registry_record_timer_generations_history_idx
                 ON registry_internal.registry_record_timer_generations (created_at,occurrence_id);
             CREATE INDEX IF NOT EXISTS registry_record_timer_generations_live_lease_idx
                 ON registry_internal.registry_record_timer_generations
                    (claim_until,claim_owner_id,occurrence_id)
                 WHERE state='leased';
             CREATE INDEX IF NOT EXISTS registry_record_timer_generations_state_block_idx
                 ON registry_internal.registry_record_timer_generations (state,block_kind);
             CREATE INDEX IF NOT EXISTS registry_record_timer_generations_activation_preview_idx
                 ON registry_internal.registry_record_timer_generations
                    (record_type,timer_id,binding_incarnation,due_at,occurrence_id)
                 WHERE state IN ('pending','leased','blocked');
             REVOKE ALL ON TABLE registry_internal.registry_record_timer_control,
                 registry_internal.registry_record_timer_bindings,
                 registry_internal.registry_record_timer_generations,
                 registry_internal.registry_record_timer_current,
                 registry_internal.registry_record_timer_attempts FROM PUBLIC;",
        )
        .await?;
    let revoke = RuntimeRevoke::detect(migration, runtime_role).await?;
    migration
        .batch_execute(&format!(
            "{}\n{}\n{}\n{}\n{}\nGRANT SELECT ON TABLE registry_internal.registry_record_timer_control TO {};\nGRANT UPDATE (control_state,control_epoch,updated_at) ON TABLE registry_internal.registry_record_timer_control TO {};\nGRANT SELECT ON TABLE registry_internal.registry_record_timer_bindings TO {};\nGRANT SELECT,INSERT,UPDATE ON TABLE registry_internal.registry_record_timer_generations, registry_internal.registry_record_timer_current, registry_internal.registry_record_timer_attempts TO {};",
            revoke.revoke_all_on("TABLE registry_internal.registry_record_timer_control"),
            revoke.revoke_all_on("TABLE registry_internal.registry_record_timer_bindings"),
            revoke.revoke_all_on("TABLE registry_internal.registry_record_timer_generations"),
            revoke.revoke_all_on("TABLE registry_internal.registry_record_timer_current"),
            revoke.revoke_all_on("TABLE registry_internal.registry_record_timer_attempts"),
            runtime_role.quoted(),
            runtime_role.quoted(),
            runtime_role.quoted(),
            runtime_role.quoted(),
        ))
        .await?;
    super::timer_retention::install(migration, runtime_role).await?;
    install_timer_policies(migration, registry, runtime_role).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn reconcile_record_timer_runtime_acl_for_test(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_record_timer_schema(migration, registry, runtime_role).await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn install_record_timer_clock_fixture_for_test(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
    initial: DateTime<Utc>,
) -> Result<()> {
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await?
        .with_public();
    migration
        .batch_execute(&format!(
            "CREATE TABLE {table} (
                 singleton boolean PRIMARY KEY CHECK (singleton),
                 database_now timestamptz NOT NULL
             );
             REVOKE ALL ON TABLE {table} FROM {revoke};
             CREATE FUNCTION {function}
                 RETURNS timestamptz
                 LANGUAGE sql STABLE SECURITY DEFINER
                 SET search_path = pg_catalog, registry_internal
                 AS $body$
                     SELECT database_now
                       FROM registry_internal.registry_record_timer_clock_fixture
                      WHERE singleton
                 $body$;
             REVOKE ALL ON FUNCTION {function} FROM {revoke};
             GRANT EXECUTE ON FUNCTION {function} TO {role};",
            table = TIMER_CLOCK_FIXTURE_TABLE,
            function = TIMER_CLOCK_FIXTURE_FUNCTION,
            role = runtime_role.quoted(),
        ))
        .await?;
    migration
        .execute(
            "INSERT INTO registry_internal.registry_record_timer_clock_fixture
                 (singleton,database_now) VALUES (true,$1)",
            &[&initial],
        )
        .await?;
    let policies = migration
        .query(
            "SELECT tablename,policyname,cmd,qual,with_check
               FROM pg_catalog.pg_policies
              WHERE schemaname='registry_data'
                AND policyname ~ '^record_timer_[0-9a-f]{24}_(select|lock|update|insert)$'
              ORDER BY tablename,policyname",
            &[],
        )
        .await?;
    for row in policies {
        let table: String = row.get(0);
        let policy: String = row.get(1);
        let command: String = row.get(2);
        let using: Option<String> = row.get(3);
        let check: Option<String> = row.get(4);
        let command = match command.as_str() {
            "SELECT" | "INSERT" | "UPDATE" => command,
            _ => {
                return Err(PostgresKernelError::CatalogInvariant(
                    "record-timer clock fixture found an unsupported policy command",
                ))
            }
        };
        let using = using.map(|expression| {
            expression.replace("clock_timestamp()", TIMER_CLOCK_FIXTURE_FUNCTION)
        });
        let check = check.map(|expression| {
            expression.replace("clock_timestamp()", TIMER_CLOCK_FIXTURE_FUNCTION)
        });
        migration
            .batch_execute(&format!(
                "DROP POLICY {policy} ON registry_data.{table};
                 CREATE POLICY {policy} ON registry_data.{table}
                 FOR {command} TO {role}{using}{check};",
                policy = quote_identifier(&policy),
                table = quote_identifier(&table),
                role = runtime_role.quoted(),
                using = using
                    .map(|expression| format!(" USING ({expression})"))
                    .unwrap_or_default(),
                check = check
                    .map(|expression| format!(" WITH CHECK ({expression})"))
                    .unwrap_or_default(),
            ))
            .await?;
    }
    super::timer_retention::install_with_clock_for_test(
        migration,
        runtime_role,
        TIMER_CLOCK_FIXTURE_FUNCTION,
    )
    .await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn set_record_timer_clock_for_test(
    migration_or_admin: &impl GenericClient,
    instant: DateTime<Utc>,
) -> Result<()> {
    let updated = migration_or_admin
        .execute(
            "UPDATE registry_internal.registry_record_timer_clock_fixture
                SET database_now=$1
              WHERE singleton",
            &[&instant],
        )
        .await?;
    if updated != 1 {
        return Err(PostgresKernelError::CatalogInvariant(
            "record-timer clock fixture singleton is missing",
        ));
    }
    Ok(())
}

/// Seed the binding-incarnation fence for a fresh activation. Successor
/// reconciliation has a separate lifecycle because removal and re-addition
/// must preserve closed incarnations rather than overwrite them.
pub(super) async fn initialize_record_timer_bindings(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    activation_id: &str,
) -> Result<()> {
    let activation_id = uuid::Uuid::parse_str(activation_id)
        .map_err(|_| PostgresKernelError::Configuration("record-timer activation id is invalid"))?;
    let mut expected = 0_i64;
    for (_, timer) in registry.timers() {
        expected = expected
            .checked_add(1)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        migration
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_bindings (
                     record_type,timer_id,incarnation,definition_revision,action_revision,
                     system_grant_revision,created_activation_id,current_policy_activation_id
                 ) VALUES ($1,$2,1,$3,$4,$5,$6,$6)
                 ON CONFLICT (record_type,timer_id,incarnation) DO NOTHING",
                &[
                    &timer.record_type,
                    &timer.id,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &activation_id,
                ],
            )
            .await?;
        let exact = migration
            .query_opt(
                "SELECT 1
                   FROM registry_internal.registry_record_timer_bindings
                  WHERE record_type=$1 AND timer_id=$2 AND incarnation=1
                    AND definition_revision=$3 AND action_revision=$4
                    AND system_grant_revision=$5
                    AND created_activation_id=$6 AND current_policy_activation_id=$6
                    AND removed_activation_id IS NULL",
                &[
                    &timer.record_type,
                    &timer.id,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &activation_id,
                ],
            )
            .await?;
        if exact.is_none() {
            return Err(PostgresKernelError::CatalogInvariant(
                "fresh record-timer binding fence differs from the compiled registry",
            ));
        }
    }
    let open: i64 = migration
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_record_timer_bindings
              WHERE removed_activation_id IS NULL",
            &[],
        )
        .await?
        .get(0);
    if open != expected {
        return Err(PostgresKernelError::CatalogInvariant(
            "fresh record-timer binding inventory differs from the compiled registry",
        ));
    }
    Ok(())
}

/// Advances the durable binding inventory in the same governed transaction
/// that activates a compiled successor. Existing bindings retain their
/// incarnation across semantic changes, removed bindings are closed rather
/// than deleted, and a later re-addition receives a fresh incarnation.
pub(super) async fn reconcile_record_timer_bindings(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    activation_id: &str,
) -> Result<()> {
    let activation_id = uuid::Uuid::parse_str(activation_id)
        .map_err(|_| PostgresKernelError::Configuration("record-timer activation id is invalid"))?;
    let compiled = registry
        .timers()
        .map(|(_, timer)| ((timer.record_type.clone(), timer.id.clone()), timer))
        .collect::<std::collections::BTreeMap<_, _>>();

    let open = migration
        .query(
            "SELECT record_type,timer_id,incarnation
               FROM registry_internal.registry_record_timer_bindings
              WHERE removed_activation_id IS NULL
              ORDER BY record_type,timer_id
              FOR UPDATE",
            &[],
        )
        .await?;
    for row in open {
        let record_type: String = row.get(0);
        let timer_id: String = row.get(1);
        let incarnation: i64 = row.get(2);
        let changed = if let Some(timer) = compiled.get(&(record_type.clone(), timer_id.clone())) {
            migration
                .execute(
                    "UPDATE registry_internal.registry_record_timer_bindings
                        SET definition_revision=$1,action_revision=$2,
                            system_grant_revision=$3,current_policy_activation_id=$4,
                            updated_at=transaction_timestamp()
                      WHERE record_type=$5 AND timer_id=$6 AND incarnation=$7
                        AND removed_activation_id IS NULL",
                    &[
                        &timer.definition_revision,
                        &timer.action_revision,
                        &timer.system_grant.revision,
                        &activation_id,
                        &record_type,
                        &timer_id,
                        &incarnation,
                    ],
                )
                .await?
        } else {
            migration
                .execute(
                    "UPDATE registry_internal.registry_record_timer_bindings
                        SET current_policy_activation_id=NULL,removed_activation_id=$1,
                            updated_at=transaction_timestamp(),removed_at=transaction_timestamp()
                      WHERE record_type=$2 AND timer_id=$3 AND incarnation=$4
                        AND removed_activation_id IS NULL",
                    &[&activation_id, &record_type, &timer_id, &incarnation],
                )
                .await?
        };
        if changed != 1 {
            return Err(PostgresKernelError::CatalogInvariant(
                "record-timer binding changed during governed activation",
            ));
        }
    }

    for ((record_type, timer_id), timer) in &compiled {
        let existing = migration
            .query_opt(
                "SELECT incarnation
                   FROM registry_internal.registry_record_timer_bindings
                  WHERE record_type=$1 AND timer_id=$2
                    AND removed_activation_id IS NULL",
                &[record_type, timer_id],
            )
            .await?;
        if existing.is_some() {
            continue;
        }
        let prior: Option<i64> = migration
            .query_one(
                "SELECT max(incarnation)
                   FROM registry_internal.registry_record_timer_bindings
                  WHERE record_type=$1 AND timer_id=$2",
                &[record_type, timer_id],
            )
            .await?
            .get(0);
        let incarnation = prior
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(PostgresKernelError::RegistryUnavailable)?;
        let inserted = migration
            .execute(
                "INSERT INTO registry_internal.registry_record_timer_bindings (
                     record_type,timer_id,incarnation,definition_revision,action_revision,
                     system_grant_revision,created_activation_id,current_policy_activation_id
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)",
                &[
                    record_type,
                    timer_id,
                    &incarnation,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &activation_id,
                ],
            )
            .await?;
        if inserted != 1 {
            return Err(PostgresKernelError::CatalogInvariant(
                "record-timer binding was not installed during governed activation",
            ));
        }
    }

    let open_count: i64 = migration
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_record_timer_bindings
              WHERE removed_activation_id IS NULL",
            &[],
        )
        .await?
        .get(0);
    if usize::try_from(open_count).ok() != Some(compiled.len()) {
        return Err(PostgresKernelError::CatalogInvariant(
            "record-timer binding inventory differs from the compiled successor",
        ));
    }
    Ok(())
}

async fn install_timer_policies(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    install_timer_policies_with_clock(migration, registry, runtime_role, "clock_timestamp()").await
}

async fn install_timer_policies_with_clock(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
    database_clock: &str,
) -> Result<()> {
    let prior = migration
        .query(
            "SELECT tablename,policyname
               FROM pg_catalog.pg_policies
              WHERE schemaname='registry_data'
                AND policyname ~ '^record_timer_[0-9a-f]{24}_(select|lock|update|insert)$'
              ORDER BY tablename,policyname",
            &[],
        )
        .await?;
    for row in prior {
        let table: String = row.get(0);
        let policy: String = row.get(1);
        migration
            .batch_execute(&format!(
                "DROP POLICY {} ON registry_data.{}",
                quote_identifier(&policy),
                quote_identifier(&table),
            ))
            .await?;
    }
    for (_, timer) in registry.timers() {
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == timer.invoke)
            .ok_or(PostgresKernelError::Configuration(
                "compiled timer action is missing",
            ))?;
        let mut select_conditions = std::collections::BTreeMap::<String, Vec<String>>::new();
        for target in &timer.system_grant.targets {
            let entity = registry.entities().get(&target.entity_id).ok_or(
                PostgresKernelError::Configuration("compiled timer target is missing"),
            )?;
            let effects = action
                .effects
                .iter()
                .filter(|effect| {
                    effect.target.entity_id == target.entity_id
                        && effect.operation == target.operation
                })
                .collect::<Vec<_>>();
            let table = quote_identifier(&entity.physical_table);
            let role = runtime_role.quoted();
            match target.operation {
                Operation::Get => {
                    let common = timer_policy_common(
                        timer,
                        action,
                        &target.entity_id,
                        Operation::Get,
                        &[],
                        &target.read_fields,
                        &BTreeSet::new(),
                        database_clock,
                    );
                    select_conditions
                        .entry(target.entity_id.clone())
                        .or_default()
                        .push(common.clone());
                    let refresh_common = (target.entity_id == timer.record_type)
                        .then(|| timer_refresh_policy_common(timer, database_clock));
                    if let Some(refresh_common) = &refresh_common {
                        select_conditions
                            .entry(target.entity_id.clone())
                            .or_default()
                            .push(refresh_common.clone());
                    }
                    let lock_name = quote_identifier(&timer_policy_name(
                        &timer.record_type,
                        &timer.id,
                        &target.entity_id,
                        "lock",
                    ));
                    migration
                        .batch_execute(&format!(
                            "DROP POLICY IF EXISTS {lock_name} ON registry_data.{table};
                             CREATE POLICY {lock_name} ON registry_data.{table}
                             FOR UPDATE TO {role}
                             USING (({common} AND record_lifecycle='active'
                                 AND (NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb -> 'lockOnly')='true'::jsonb
                                 AND (NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb ->> 'expectedRevision') IS NULL)
                                 {refresh_using})
                             WITH CHECK (false);"
                            ,
                            refresh_using = refresh_common
                                .map(|condition| format!("OR ({condition})"))
                                .unwrap_or_default(),
                        ))
                        .await?;
                }
                Operation::Patch
                    if effects.iter().any(|effect| {
                        matches!(
                            effect.target.binding,
                            CompiledPlanTargetBinding::Existing { .. }
                        )
                    }) =>
                {
                    let common = timer_policy_common(
                        timer,
                        action,
                        &target.entity_id,
                        Operation::Patch,
                        &effects,
                        &target.fields,
                        &BTreeSet::new(),
                        database_clock,
                    );
                    select_conditions
                        .entry(target.entity_id.clone())
                        .or_default()
                        .push(common.clone());
                    let update_name = quote_identifier(&timer_policy_name(
                        &timer.record_type,
                        &timer.id,
                        &target.entity_id,
                        "update",
                    ));
                    migration
                        .batch_execute(&format!(
                            "DROP POLICY IF EXISTS {update_name} ON registry_data.{table};
                             CREATE POLICY {update_name} ON registry_data.{table}
                             FOR UPDATE TO {role}
                             USING ({common} AND record_lifecycle='active' AND (
                                 ((NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb -> 'lockOnly')='true'::jsonb
                                  AND (NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb ->> 'expectedRevision') IS NULL)
                                 OR
                                 ((NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb -> 'lockOnly')='false'::jsonb
                                  AND record_revision=(NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb ->> 'expectedRevision')::bigint)
                             ))
                             WITH CHECK ({common} AND record_lifecycle='active'
                                 AND (NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb -> 'lockOnly')='false'::jsonb);"
                        ))
                        .await?;
                }
                Operation::Create
                    if effects.iter().any(|effect| {
                        matches!(effect.target.binding, CompiledPlanTargetBinding::Create)
                    }) =>
                {
                    let common = timer_policy_common(
                        timer,
                        action,
                        &target.entity_id,
                        Operation::Create,
                        &effects,
                        &target.fields,
                        &entity
                            .generated_fields()
                            .map(|field| field.id.clone())
                            .collect(),
                        database_clock,
                    );
                    select_conditions
                        .entry(target.entity_id.clone())
                        .or_default()
                        .push(common.clone());
                    let insert_name = quote_identifier(&timer_policy_name(
                        &timer.record_type,
                        &timer.id,
                        &target.entity_id,
                        "insert",
                    ));
                    migration
                        .batch_execute(&format!(
                            "DROP POLICY IF EXISTS {insert_name} ON registry_data.{table};
                             CREATE POLICY {insert_name} ON registry_data.{table}
                             FOR INSERT TO {role}
                             WITH CHECK ({common} AND record_lifecycle='active'
                                 AND (NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb -> 'lockOnly')='false'::jsonb);"
                        ))
                        .await?;
                }
                _ => {}
            }
        }
        for (entity_id, conditions) in select_conditions {
            let entity =
                registry
                    .entities()
                    .get(&entity_id)
                    .ok_or(PostgresKernelError::Configuration(
                        "compiled timer target is missing",
                    ))?;
            let table = quote_identifier(&entity.physical_table);
            let select_name = quote_identifier(&timer_policy_name(
                &timer.record_type,
                &timer.id,
                &entity_id,
                "select",
            ));
            let common = conditions
                .into_iter()
                .map(|condition| format!("({condition})"))
                .collect::<Vec<_>>()
                .join(" OR ");
            migration
                .batch_execute(&format!(
                    "DROP POLICY IF EXISTS {select_name} ON registry_data.{table};
                     CREATE POLICY {select_name} ON registry_data.{table}
                     FOR SELECT TO {}
                     USING (({common}) AND record_lifecycle='active');",
                    runtime_role.quoted()
                ))
                .await?;
        }
    }
    Ok(())
}

fn timer_refresh_policy_common(
    timer: &crate::model::CompiledTimer,
    database_clock: &str,
) -> String {
    let context = "NULLIF(current_setting('registry.record_timer_refresh_context',true),'')::jsonb";
    [
        format!("jsonb_typeof({context})='object'"),
        format!("{context} ->> 'version'='1'"),
        format!("{context} ->> 'actorKind'='system'"),
        format!("{context} ->> 'systemActor'='record-timer-refresh'"),
        format!("{context} ->> 'recordType'={}", quote_literal(&timer.record_type)),
        format!("{context} ->> 'timerId'={}", quote_literal(&timer.id)),
        format!(
            "{context} ->> 'selectedAccessProfile'={}",
            quote_literal(crate::mutation::TIMER_ACCESS_PROFILE)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile'=NULLIF(current_setting('registry.access_profile',true),'')"
        ),
        format!(
            "{context} ->> 'principal'={}",
            quote_literal(crate::mutation::TIMER_PRINCIPAL)
        ),
        format!(
            "{context} ->> 'principal'=NULLIF(current_setting('registry.principal',true),'')"
        ),
        format!(
            "{context} ->> 'activePackageRevision'=NULLIF(current_setting('registry.active_package_revision',true),'')"
        ),
        format!("{context} ->> 'anchorRecordId'=record_id::text"),
        format!(
            "EXISTS (
                SELECT 1
                  FROM registry_internal.registry_record_timer_generations AS generation
                  JOIN registry_internal.registry_record_timer_current AS current
                    ON current.occurrence_id=generation.occurrence_id
                   AND current.record_type=generation.record_type
                   AND current.record_id=generation.record_id
                   AND current.timer_id=generation.timer_id
                   AND current.binding_incarnation=generation.binding_incarnation
                   AND current.material_signature=generation.material_signature
                  JOIN registry_internal.registry_record_timer_bindings AS binding
                    ON binding.record_type=generation.record_type
                   AND binding.timer_id=generation.timer_id
                   AND binding.incarnation=generation.binding_incarnation
                   AND binding.removed_activation_id IS NULL
                   AND binding.current_policy_activation_id=({context} ->> 'activationId')::uuid
                   AND binding.definition_revision={definition_revision}
                   AND binding.action_revision={action_revision}
                   AND binding.system_grant_revision={grant_revision}
                  JOIN registry_internal.registry_record_timer_control AS control
                    ON control.singleton AND control.protocol_version=1
                   AND control.control_state='running'
                  JOIN registry_internal.registry_state AS state
                    ON state.singleton AND state.maintenance_status='ready'
                   AND state.package_id=({context} ->> 'packageId')
                   AND state.database_id=({context} ->> 'databaseId')
                   AND state.active_package_digest=({context} ->> 'packageDigest')
                   AND state.active_activation_id=({context} ->> 'activationId')::uuid
                   AND state.schema_fingerprint=({context} ->> 'schemaFingerprint')
                   AND state.epoch=control.bound_instance_epoch
                 WHERE generation.record_type={record_type}
                   AND generation.record_id=({context} ->> 'anchorRecordId')::uuid
                   AND generation.timer_id={timer_id}
                   AND generation.occurrence_id=({context} ->> 'occurrenceId')::uuid
                   AND generation.binding_incarnation=({context} ->> 'bindingIncarnation')::bigint
                   AND generation.material_signature={context} ->> 'materialSignature'
                   AND generation.definition_revision={context} ->> 'priorDefinitionRevision'
                   AND generation.action_revision={context} ->> 'priorActionRevision'
                   AND generation.system_grant_revision={context} ->> 'priorSystemGrantRevision'
                   AND (
                        generation.state IN ('pending','blocked')
                        OR (
                            generation.state='leased'
                            AND generation.claim_owner_id=({context} ->> 'claimOwnerId')::uuid
                            AND generation.claim_token=({context} ->> 'claimToken')::uuid
                            AND generation.claim_epoch=({context} ->> 'claimEpoch')::bigint
                            AND generation.claim_until=({context} ->> 'claimUntil')::timestamptz
                            AND generation.claimed_control_epoch=({context} ->> 'claimedControlEpoch')::bigint
                            AND generation.claimed_instance_epoch=({context} ->> 'claimedInstanceEpoch')::bigint
                            AND generation.claimed_activation_id=({context} ->> 'claimedActivationId')::uuid
                            AND generation.claim_until < {database_clock}
                        )
                   )
                   AND (
                        generation.definition_revision<>binding.definition_revision
                     OR generation.action_revision<>binding.action_revision
                     OR generation.system_grant_revision<>binding.system_grant_revision
                   )
                   AND control.control_epoch=({context} ->> 'controlEpoch')::bigint
                   AND control.bound_instance_epoch=({context} ->> 'instanceEpoch')::bigint
            )",
            definition_revision = quote_literal(&timer.definition_revision),
            action_revision = quote_literal(&timer.action_revision),
            grant_revision = quote_literal(&timer.system_grant.revision),
            record_type = quote_literal(&timer.record_type),
            timer_id = quote_literal(&timer.id),
            database_clock = database_clock,
        ),
    ]
    .join(" AND ")
}

// Policy generation keeps the independently reviewed operation, effect, field,
// and clock ceilings explicit rather than hiding them in mutable builder state.
#[allow(clippy::too_many_arguments)]
fn timer_policy_common(
    timer: &crate::model::CompiledTimer,
    action: &crate::model::CompiledAction,
    target_entity: &str,
    operation: Operation,
    effects: &[&crate::model::CompiledPlanEffect],
    grant_read_fields: &BTreeSet<String>,
    generated_fields: &BTreeSet<String>,
    database_clock: &str,
) -> String {
    let context =
        "NULLIF(current_setting('registry.immediate_action_target_context',true),'')::jsonb";
    let target_binding = if operation == Operation::Get {
        let mut bindings = Vec::new();
        if target_entity == timer.record_type {
            bindings.push(format!(
                "({context} ->> 'targetInputId' IS NULL AND {context} ->> 'targetRecordId'={context} ->> 'anchorRecordId')"
            ));
        }
        for target_use in &action.target_uses {
            let CompiledActionTargetUseSource::Input { input } = &target_use.source else {
                continue;
            };
            if target_use.entity_id != target_entity
                || target_use.operation != Operation::Get
                || !timer.input.contains_key(input)
            {
                continue;
            }
            let prefix = crate::mutation::timer_target_binding_prefix(input, target_entity);
            bindings.push(format!(
                "({context} ->> 'targetInputId'={input} AND generation.target_binding_digests -> {input} ->> {entity}=encode(sha256(convert_to({prefix} || ({context} ->> 'targetRecordId'),'UTF8')),'hex'))",
                input = quote_literal(input),
                entity = quote_literal(target_entity),
                prefix = quote_literal(&prefix),
            ));
        }
        if bindings.is_empty() {
            "false".to_owned()
        } else {
            format!("({})", bindings.join(" OR "))
        }
    } else if operation == Operation::Patch {
        if target_entity == timer.record_type {
            format!(
                "({context} ->> 'targetInputId' IS NULL AND {context} ->> 'targetRecordId'={context} ->> 'anchorRecordId')"
            )
        } else {
            "false".to_owned()
        }
    } else if operation == Operation::Create {
        let bindings = effects
            .iter()
            .map(|effect| {
                let effect_ids = serde_json::to_string(&vec![effect.id.as_str()])
                    .expect("compiled effect identifier serializes");
                let expected = timer_create_target_id_sql(
                    &action.definition_revision,
                    &effect.id,
                    target_entity,
                );
                format!(
                    "({context} -> 'effectIds' = {effects}::jsonb AND {context} ->> 'targetRecordId'={expected})",
                    effects = quote_literal(&effect_ids),
                )
            })
            .collect::<Vec<_>>();
        if bindings.is_empty() {
            "false".to_owned()
        } else {
            format!("({})", bindings.join(" OR "))
        }
    } else {
        "true".to_owned()
    };
    let effect_shapes = if operation == Operation::Get {
        let mut shapes = Vec::new();
        if target_entity == timer.record_type {
            let mut fields = timer.control_fields.clone();
            fields.extend(timer.predicate_fields.iter().cloned());
            fields.extend(timer.effect_input_fields.iter().cloned());
            if fields.is_subset(grant_read_fields) {
                let fields = serde_json::to_string(&fields).expect("compiled fields serialize");
                shapes.push(format!(
                    "({context} ->> 'targetInputId' IS NULL AND {context} -> 'fields' = {}::jsonb)",
                    quote_literal(&fields)
                ));
            }
        }
        for target_use in &action.target_uses {
            let CompiledActionTargetUseSource::Input { input } = &target_use.source else {
                continue;
            };
            if target_use.entity_id != target_entity
                || target_use.operation != Operation::Get
                || !timer.input.contains_key(input)
                || !target_use.fields.is_subset(grant_read_fields)
            {
                continue;
            }
            let fields =
                serde_json::to_string(&target_use.fields).expect("compiled fields serialize");
            shapes.push(format!(
                "({context} ->> 'targetInputId'={input} AND {context} -> 'fields' = {fields}::jsonb)",
                input = quote_literal(input),
                fields = quote_literal(&fields),
            ));
        }
        format!(
            "({context} -> 'effectIds' = '[]'::jsonb AND ({}))",
            if shapes.is_empty() {
                "false".to_owned()
            } else {
                shapes.join(" OR ")
            }
        )
    } else if operation == Operation::Patch {
        timer_patch_effect_group_expression(context, effects)
    } else {
        effects
            .iter()
            .map(|effect| {
            let effect_ids = serde_json::to_string(&vec![effect.id.as_str()])
                .expect("compiled effect identifier serializes");
            let mut fields = effect
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field.clone(),
                })
                .collect::<BTreeSet<_>>();
            fields.extend(generated_fields.iter().cloned());
            let fields = serde_json::to_string(&fields).expect("compiled fields serialize");
            format!(
                "({context} -> 'effectIds' = {effects}::jsonb AND {context} -> 'fields' = {fields}::jsonb)",
                effects = quote_literal(&effect_ids),
                fields = quote_literal(&fields),
            )
            })
            .collect::<Vec<_>>()
            .join(" OR ")
    };
    let operation = match operation {
        Operation::Get => "get",
        Operation::Create => "create",
        Operation::Patch => "patch",
        _ => "unsupported",
    };
    [
        format!("jsonb_typeof({context})='object'"),
        format!("{context} ->> 'version'='1'"),
        format!("{context} ->> 'actorKind'='system'"),
        format!("{context} ->> 'systemActor'='record-timer'"),
        format!("{context} ->> 'timerId'={}", quote_literal(&timer.id)),
        format!(
            "{context} ->> 'systemGrantRevision'={}",
            quote_literal(&timer.system_grant.revision)
        ),
        format!("{context} ->> 'actionId'={}", quote_literal(&action.id)),
        format!(
            "{context} ->> 'contractFingerprint'={}",
            quote_literal(&action.definition_revision)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile'={}",
            quote_literal(crate::mutation::TIMER_ACCESS_PROFILE)
        ),
        format!(
            "{context} ->> 'selectedAccessProfile'=NULLIF(current_setting('registry.access_profile',true),'')"
        ),
        format!(
            "{context} ->> 'principal'={}",
            quote_literal(crate::mutation::TIMER_PRINCIPAL)
        ),
        format!(
            "{context} ->> 'principal'=NULLIF(current_setting('registry.principal',true),'')"
        ),
        format!("{context} ->> 'purpose' IS NULL"),
        format!(
            "{context} ->> 'targetEntityId'={}",
            quote_literal(target_entity)
        ),
        format!("{context} ->> 'operation'={}", quote_literal(operation)),
        format!(
            "{context} ->> 'activePackageRevision'=NULLIF(current_setting('registry.active_package_revision',true),'')"
        ),
        format!("{context} ->> 'targetRecordId'=record_id::text"),
        format!("({effect_shapes})"),
        format!(
            "EXISTS (
                SELECT 1
                  FROM registry_internal.registry_record_timer_generations AS generation
                  JOIN registry_internal.registry_record_timer_current AS current
                    ON current.occurrence_id=generation.occurrence_id
                   AND current.record_type=generation.record_type
                   AND current.record_id=generation.record_id
                   AND current.timer_id=generation.timer_id
                   AND current.binding_incarnation=generation.binding_incarnation
                   AND current.material_signature=generation.material_signature
                  JOIN registry_internal.registry_record_timer_bindings AS binding
                    ON binding.record_type=generation.record_type
                   AND binding.timer_id=generation.timer_id
                   AND binding.incarnation=generation.binding_incarnation
                   AND binding.removed_activation_id IS NULL
                   AND binding.definition_revision=generation.definition_revision
                   AND binding.action_revision=generation.action_revision
                   AND binding.system_grant_revision=generation.system_grant_revision
                  JOIN registry_internal.registry_record_timer_control AS control ON control.singleton
                  JOIN registry_internal.registry_state AS state ON state.singleton
                 WHERE generation.record_type={record_type}
                   AND generation.record_id=({context} ->> 'anchorRecordId')::uuid
                   AND generation.timer_id={timer_id}
                   AND generation.occurrence_id=({context} ->> 'occurrenceId')::uuid
                   AND generation.claim_token=({context} ->> 'claimToken')::uuid
                   AND generation.claim_owner_id=({context} ->> 'claimOwnerId')::uuid
                   AND generation.claim_epoch=({context} ->> 'claimEpoch')::bigint
                   AND generation.state='leased'
                   AND generation.claim_until > {database_clock}
                   AND generation.due_at <= {database_clock}
                   AND (generation.not_after IS NULL OR {database_clock} < generation.not_after)
                   AND generation.claimed_control_epoch=({context} ->> 'controlEpoch')::bigint
                   AND generation.claimed_instance_epoch=({context} ->> 'instanceEpoch')::bigint
                   AND generation.claimed_activation_id=({context} ->> 'activationId')::uuid
                   AND {context} ->> 'applicationId'=generation.occurrence_id::text
                   AND generation.definition_revision={definition_revision}
                   AND generation.action_revision={action_revision}
                   AND generation.system_grant_revision={grant_revision}
                   AND {target_binding}
                   AND control.control_epoch=generation.claimed_control_epoch
                   AND control.protocol_version=1
                   AND control.control_state='running'
                   AND control.bound_instance_epoch=generation.claimed_instance_epoch
                   AND state.epoch=generation.claimed_instance_epoch
                   AND state.active_activation_id=generation.claimed_activation_id
                   AND binding.current_policy_activation_id=state.active_activation_id
            )",
            record_type = quote_literal(&timer.record_type),
            timer_id = quote_literal(&timer.id),
            definition_revision = quote_literal(&timer.definition_revision),
            action_revision = quote_literal(&timer.action_revision),
            grant_revision = quote_literal(&timer.system_grant.revision),
            target_binding = target_binding,
            database_clock = database_clock,
        ),
    ]
    .join(" AND ")
}

fn timer_patch_effect_group_expression(
    context: &str,
    effects: &[&crate::model::CompiledPlanEffect],
) -> String {
    let allowed_effects = effects
        .iter()
        .map(|effect| quote_literal(&effect.id))
        .collect::<Vec<_>>()
        .join(", ");
    let field_rows = effects
        .iter()
        .flat_map(|effect| {
            effect.mutations.iter().map(|mutation| {
                let field = match mutation {
                    CompiledPlanMutation::Set { field, .. }
                    | CompiledPlanMutation::Clear { field } => field,
                };
                format!("({}, {})", quote_literal(&effect.id), quote_literal(field),)
            })
        })
        .collect::<Vec<_>>()
        .join(", ");
    if allowed_effects.is_empty() || field_rows.is_empty() {
        return "false".to_owned();
    }
    format!(
        "jsonb_typeof({context} -> 'effectIds')='array' \
         AND jsonb_array_length({context} -> 'effectIds') BETWEEN 1 AND 128 \
         AND jsonb_array_length({context} -> 'effectIds')=( \
             SELECT count(DISTINCT selected.effect_id) \
               FROM jsonb_array_elements_text({context} -> 'effectIds') \
                    AS selected(effect_id) \
         ) \
         AND NOT EXISTS ( \
             SELECT 1 \
               FROM jsonb_array_elements_text({context} -> 'effectIds') \
                    AS selected(effect_id) \
              WHERE selected.effect_id NOT IN ({allowed_effects}) \
         ) \
         AND jsonb_typeof({context} -> 'fields')='array' \
         AND {context} -> 'fields'=( \
             SELECT COALESCE( \
                 jsonb_agg(selected_fields.field \
                           ORDER BY selected_fields.field COLLATE \"C\"), \
                 '[]'::jsonb \
             ) \
               FROM ( \
                   SELECT DISTINCT effect_fields.field \
                     FROM (VALUES {field_rows}) AS effect_fields(effect_id,field) \
                    WHERE EXISTS ( \
                         SELECT 1 \
                           FROM jsonb_array_elements_text({context} -> 'effectIds') \
                                AS selected(effect_id) \
                          WHERE selected.effect_id=effect_fields.effect_id \
                    ) \
               ) AS selected_fields \
         )"
    )
}

fn timer_create_target_id_sql(
    action_revision: &str,
    effect_id: &str,
    target_entity_id: &str,
) -> String {
    let prefix =
        crate::mutation::timer_create_target_prefix(action_revision, effect_id, target_entity_id);
    let digest = format!(
        "encode(sha256(convert_to({} || generation.occurrence_id::text,'UTF8')),'hex')",
        quote_literal(&prefix)
    );
    format!(
        "((overlay(overlay(substr({digest},1,32) placing '8' from 13 for 1) placing '8' from 17 for 1))::uuid)::text"
    )
}

fn timer_policy_name(record_type: &str, timer_id: &str, target: &str, suffix: &str) -> String {
    let digest = Sha256::digest(
        [
            record_type.as_bytes(),
            b"\0",
            timer_id.as_bytes(),
            b"\0",
            target.as_bytes(),
        ]
        .concat(),
    );
    format!("record_timer_{}_{}", &hex::encode(digest)[..24], suffix)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TimerProtocolState {
    pub(crate) protocol_version: i32,
    pub(crate) control_state: String,
    pub(crate) control_epoch: i64,
    pub(crate) bound_instance_epoch: i64,
    pub(crate) registry_instance_epoch: i64,
}

/// Read the timer protocol singleton without taking its mutation lock.
///
/// Every runtime transaction uses this as an admission check, including
/// transactions whose Record type has no active timer. Mutations take the
/// control-row lock separately only when they need to stage timer state.
pub(crate) async fn read_timer_protocol(client: &impl GenericClient) -> Result<TimerProtocolState> {
    let row = client
        .query_opt(
            "SELECT control.protocol_version,control.control_state,
                    control.control_epoch,control.bound_instance_epoch,state.epoch
               FROM registry_internal.registry_record_timer_control AS control
               JOIN registry_internal.registry_state AS state ON state.singleton
              WHERE control.singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    Ok(TimerProtocolState {
        protocol_version: row.get(0),
        control_state: row.get(1),
        control_epoch: row.get(2),
        bound_instance_epoch: row.get(3),
        registry_instance_epoch: row.get(4),
    })
}

pub(crate) async fn retained_record_timer_state_exists(
    pool: &RuntimePool,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
) -> Result<bool> {
    let mut client = pool.get().await?;
    let transaction =
        begin_registry_transaction(&mut client, lock_key, lock_timeout, expected).await?;
    transaction
        .set_statement_budget(super::operator_read_statement_budget())
        .await?;
    let exists = transaction
        .transaction()
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_record_timer_generations
                 LIMIT 1
             )",
            &[],
        )
        .await?
        .get(0);
    transaction.commit().await?;
    Ok(exists)
}

#[derive(Clone)]
pub struct RecordTimerWorker {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    coordinator: crate::mutation::MutationTransaction,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    lease_duration: Duration,
    claim_owner_id: uuid::Uuid,
    last_success: Arc<crate::metrics::LastSuccess>,
    next_lane: Arc<std::sync::atomic::AtomicU8>,
    stale_cursor: Arc<std::sync::Mutex<Option<(String, uuid::Uuid)>>>,
    #[cfg(feature = "postgres-test")]
    database_clock_fixture: bool,
    #[cfg(feature = "postgres-test")]
    native_before_claim: Option<NativeBeforeClaimBarrier>,
    #[cfg(feature = "postgres-test")]
    native_action_checkpoint: Option<crate::mutation::NativeTimerCheckpoint>,
    #[cfg(feature = "postgres-test")]
    native_outcome_settlement_kind: Option<NativeOutcomeSettlementKind>,
    #[cfg(feature = "postgres-test")]
    claim_barrier: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    #[cfg(feature = "postgres-test")]
    preflight_barrier: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    #[cfg(feature = "postgres-test")]
    fault: Option<crate::mutation::MutationFaultPoint>,
}

struct ClaimedTimer {
    record_type: String,
    record_id: uuid::Uuid,
    timer_id: String,
    occurrence_id: uuid::Uuid,
    due_at: DateTime<Utc>,
    not_after: Option<DateTime<Utc>>,
    claim_token: uuid::Uuid,
    claim_owner_id: uuid::Uuid,
    claim_epoch: i64,
    control_epoch: i64,
    instance_epoch: i64,
    activation_id: uuid::Uuid,
}

struct StaleTimer {
    record_type: String,
    record_id: uuid::Uuid,
    timer_id: String,
    occurrence_id: uuid::Uuid,
    binding_incarnation: i64,
    material_signature: String,
    definition_revision: String,
    action_revision: String,
    system_grant_revision: String,
    control_epoch: i64,
    instance_epoch: i64,
    claim_owner_id: Option<uuid::Uuid>,
    claim_token: Option<uuid::Uuid>,
    claim_epoch: i64,
    claim_until: Option<DateTime<Utc>>,
    claimed_control_epoch: Option<i64>,
    claimed_instance_epoch: Option<i64>,
    claimed_activation_id: Option<uuid::Uuid>,
}

impl RecordTimerWorker {
    pub(crate) fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        coordinator: crate::mutation::MutationTransaction,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
    ) -> Self {
        Self {
            pool,
            registry,
            coordinator,
            expected,
            lock_key,
            lock_timeout,
            lease_duration: production_lease_duration(),
            claim_owner_id: uuid::Uuid::new_v4(),
            last_success: Arc::default(),
            next_lane: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            stale_cursor: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(feature = "postgres-test")]
            database_clock_fixture: false,
            #[cfg(feature = "postgres-test")]
            native_before_claim: None,
            #[cfg(feature = "postgres-test")]
            native_action_checkpoint: None,
            #[cfg(feature = "postgres-test")]
            native_outcome_settlement_kind: None,
            #[cfg(feature = "postgres-test")]
            claim_barrier: None,
            #[cfg(feature = "postgres-test")]
            preflight_barrier: None,
            #[cfg(feature = "postgres-test")]
            fault: None,
        }
    }

    #[cfg(feature = "postgres-test")]
    pub(crate) fn with_native_test_controls_from_env(
        mut self,
        instance_id: &str,
    ) -> std::result::Result<Self, ()> {
        self.native_before_claim = NativeBeforeClaimBarrier::from_env(instance_id)?;
        (
            self.native_action_checkpoint,
            self.native_outcome_settlement_kind,
        ) = native_action_checkpoint_from_env(instance_id)?;
        if self.native_before_claim.is_some() && self.native_action_checkpoint.is_some() {
            return Err(());
        }
        if let Some(lease_duration) = native_lease_duration_from_env()? {
            self.lease_duration = lease_duration;
        }
        Ok(self)
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        coordinator: crate::mutation::MutationTransaction,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        lease_duration: Duration,
    ) -> Self {
        let mut worker = Self::new(
            pool,
            registry,
            coordinator,
            expected,
            lock_key,
            lock_timeout,
        );
        worker.lease_duration = lease_duration;
        worker
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_claim_barrier_for_test(
        mut self,
        claimed: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.claim_barrier = Some((claimed, resume));
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_database_clock_fixture_for_test(mut self) -> Self {
        self.database_clock_fixture = true;
        self
    }

    fn database_clock_sql<'a>(&self, sql: &'a str) -> Cow<'a, str> {
        #[cfg(feature = "postgres-test")]
        {
            if self.database_clock_fixture {
                return Cow::Owned(
                    sql.replace("clock_timestamp()", TIMER_CLOCK_FIXTURE_FUNCTION)
                        .replace("statement_timestamp()", TIMER_CLOCK_FIXTURE_FUNCTION),
                );
            }
        }
        Cow::Borrowed(sql)
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_preflight_barrier_for_test(
        mut self,
        observed: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    ) -> Self {
        self.preflight_barrier = Some((observed, resume));
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: crate::mutation::MutationFaultPoint) -> Self {
        self.fault = Some(fault);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn prune_retention_once_for_test(
        &self,
    ) -> std::result::Result<u64, crate::mutation::MutationError> {
        self.prune_retention_if_due().await
    }

    pub(crate) fn last_success(&self) -> Arc<crate::metrics::LastSuccess> {
        Arc::clone(&self.last_success)
    }

    pub async fn run_once(&self) -> std::result::Result<usize, crate::mutation::MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let start = usize::from(
            self.next_lane
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % 4,
        );
        let mut claimed = None;
        for offset in 0..4 {
            let worked = match (start + offset) % 4 {
                0 => self.cancel_one_removed(&mut client).await?,
                1 => self.expire_one_elapsed(&mut client).await?,
                2 => self.refresh_one_stale(&mut client).await?,
                3 => {
                    claimed = self.claim_one(&mut client).await?;
                    false
                }
                _ => unreachable!(),
            };
            if worked {
                return Ok(1);
            }
            if claimed.is_some() {
                break;
            }
        }
        let Some(claimed) = claimed else {
            return Ok(0);
        };
        #[cfg(feature = "postgres-test")]
        {
            if let Some(checkpoint) = &self.native_action_checkpoint {
                checkpoint
                    .observe_and_wait(
                        crate::mutation::NativeTimerCheckpointPhase::AfterClaim,
                        claimed.occurrence_id,
                    )
                    .await?;
            }
            if matches!(
                self.fault,
                Some(crate::mutation::MutationFaultPoint::AfterClaim)
            ) {
                return Err(crate::mutation::MutationError::Unavailable);
            }
            if let Some((observed, resume)) = &self.claim_barrier {
                crate::mutation::wait_at_timer_test_barrier(observed, resume).await?;
            }
        }
        let timer = self
            .registry
            .entities()
            .get(&claimed.record_type)
            .and_then(|entity| entity.timers.get(&claimed.timer_id))
            .ok_or(crate::mutation::MutationError::Unavailable)?;
        let authority = crate::mutation::TimerActionAuthority::new(
            &self.registry,
            timer,
            claimed.occurrence_id,
            claimed.record_id,
            claimed.claim_token,
            claimed.claim_owner_id,
            claimed.claim_epoch,
            claimed.due_at,
            claimed.not_after,
            claimed.control_epoch,
            claimed.instance_epoch,
            claimed.activation_id,
            self.coordinator.timer_detail_retention_days(),
        )?;
        #[cfg(feature = "postgres-test")]
        let authority = if self.database_clock_fixture {
            authority.with_database_clock_fixture_for_test()
        } else {
            authority
        };
        #[cfg(feature = "postgres-test")]
        let authority = authority.with_native_checkpoint(self.native_action_checkpoint.clone());
        #[cfg(feature = "postgres-test")]
        let authority = authority.with_preflight_barrier(self.preflight_barrier.clone());
        let correlation = crate::correlation::RequestCorrelation::breg_created();
        let attempt_started_at_sql = self.database_clock_sql("SELECT clock_timestamp()");
        let attempt_started_at: DateTime<Utc> = client
            .query_one(attempt_started_at_sql.as_ref(), &[])
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?
            .get(0);
        let execution = crate::mutation::TimerActionExecution {
            authority: &authority,
            correlation: &correlation,
        };
        #[cfg(feature = "postgres-test")]
        let fault = if self.native_outcome_settlement_kind
            == Some(NativeOutcomeSettlementKind::TechnicalFailure)
        {
            crate::mutation::FaultControl::At(crate::mutation::MutationFaultPoint::BeforeCommit)
        } else {
            self.fault
                .map(crate::mutation::FaultControl::At)
                .unwrap_or(crate::mutation::FaultControl::Disabled)
        };
        #[cfg(not(feature = "postgres-test"))]
        let fault = crate::mutation::FaultControl::Disabled;
        let result = self
            .coordinator
            .execute_timer_action(
                &mut client,
                &self.registry,
                execution,
                fault,
                tokio::time::Instant::now() + super::mutation::REQUEST_ACTION_TIMEOUT,
            )
            .await;
        drop(client);
        match result {
            Ok(
                crate::mutation::TimerActionDisposition::Applied
                | crate::mutation::TimerActionDisposition::Held
                | crate::mutation::TimerActionDisposition::Missed,
            ) => Ok(1),
            Ok(crate::mutation::TimerActionDisposition::Refused(outcome)) => {
                #[cfg(feature = "postgres-test")]
                self.wait_before_outcome_settlement(
                    NativeOutcomeSettlementKind::DeclaredRefusal,
                    claimed.occurrence_id,
                )
                .await?;
                self.settle_refusal(&authority, outcome, attempt_started_at)
                    .await?;
                Ok(1)
            }
            Err(error) => {
                if matches!(error, crate::mutation::MutationError::PreconditionFailed) {
                    match self.settle_clock_transition(&authority).await {
                        Ok(true) => return Ok(1),
                        Ok(false) | Err(crate::mutation::MutationError::PreconditionFailed) => {}
                        Err(settlement_error) => return Err(settlement_error),
                    }
                }
                if let Some(technical_code) = timer_technical_code(&error) {
                    #[cfg(feature = "postgres-test")]
                    self.wait_before_outcome_settlement(
                        NativeOutcomeSettlementKind::TechnicalFailure,
                        claimed.occurrence_id,
                    )
                    .await?;
                    match self
                        .settle_technical_failure(&authority, technical_code, attempt_started_at)
                        .await
                    {
                        Ok(()) | Err(crate::mutation::MutationError::PreconditionFailed) => {}
                        Err(settlement_error) => return Err(settlement_error),
                    }
                }
                Err(error)
            }
        }
    }

    async fn settle_clock_transition(
        &self,
        authority: &crate::mutation::TimerActionAuthority,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let transaction = begin_registry_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let control_epoch = crate::mutation::lock_timer_control(transaction.transaction()).await?;
        if control_epoch != authority.control_epoch {
            transaction
                .commit()
                .await
                .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
            return Ok(false);
        }
        let settled = authority
            .settle_clock_transition(transaction.transaction())
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        Ok(settled)
    }

    #[cfg(feature = "postgres-test")]
    async fn wait_before_outcome_settlement(
        &self,
        kind: NativeOutcomeSettlementKind,
        occurrence_id: uuid::Uuid,
    ) -> std::result::Result<(), crate::mutation::MutationError> {
        if self.native_outcome_settlement_kind != Some(kind) {
            return Ok(());
        }
        self.native_action_checkpoint
            .as_ref()
            .ok_or(crate::mutation::MutationError::Unavailable)?
            .observe_and_wait(
                crate::mutation::NativeTimerCheckpointPhase::BeforeOutcomeSettlement,
                occurrence_id,
            )
            .await
    }

    pub(crate) async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut next_retention = tokio::time::Instant::now();
        loop {
            if *shutdown.borrow() {
                return;
            }
            if tokio::time::Instant::now() >= next_retention {
                next_retention = tokio::time::Instant::now() + TIMER_RETENTION_INTERVAL;
                if self.prune_retention_if_due().await.is_err() {
                    crate::startup::OperationalEvent::RecordTimerIterationFailed.emit();
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() { return; }
                        }
                        () = tokio::time::sleep(PRODUCTION_FAILURE_RETRY_INTERVAL) => {}
                    }
                    continue;
                }
            }
            let delay = match self.run_once().await {
                Ok(0) => {
                    self.last_success.record();
                    Some(PRODUCTION_SCAN_INTERVAL)
                }
                Ok(_) => {
                    self.last_success.record();
                    None
                }
                Err(_) => {
                    crate::startup::OperationalEvent::RecordTimerIterationFailed.emit();
                    Some(PRODUCTION_FAILURE_RETRY_INTERVAL)
                }
            };
            let Some(delay) = delay else {
                continue;
            };
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    async fn prune_retention_if_due(
        &self,
    ) -> std::result::Result<u64, crate::mutation::MutationError> {
        if !self.retention_is_due().await? {
            return Ok(0);
        }

        let correlation = uuid::Uuid::new_v4().to_string();
        let record = |phase: &str, outcome: &str| {
            json!({
                "kind":"recordTimerRetention",
                "phase":phase,
                "outcome":outcome,
                "activationId":self.expected.activation_id,
                "actor":"breg:record-timer-retention-worker",
                "correlation":correlation,
            })
        };
        let mut audit = self
            .coordinator
            .registry_audit()
            .begin(
                AuditEntry::request(
                    RECORD_TIMER_RETENTION_AUDIT_SCHEMA,
                    correlation.clone(),
                    record("attempt", "started"),
                ),
                record("terminal", "unfinished"),
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let result = self.prune_retention_batch().await;
        if matches!(
            result,
            Err(crate::mutation::MutationError::CommitUnresolved)
        ) {
            return result.map(|removed| removed.attempts_pruned + removed.generations_pruned);
        }
        let mut response = record("terminal", if result.is_ok() { "pruned" } else { "failed" });
        if let Ok(removed) = &result {
            response["attemptsPruned"] = json!(removed.attempts_pruned);
            response["generationsPruned"] = json!(removed.generations_pruned);
        }
        audit
            .respond(response)
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        result.map(|removed| removed.attempts_pruned + removed.generations_pruned)
    }

    async fn retention_is_due(&self) -> std::result::Result<bool, crate::mutation::MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let transaction = begin_registry_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        transaction
            .set_statement_budget(super::operator_read_statement_budget())
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let retention_due_sql = self.database_clock_sql(
            "SELECT EXISTS (
                 SELECT 1
                   FROM registry_internal.registry_record_timer_generations AS generation
                  WHERE generation.detail_expires_at IS NOT NULL
                    AND generation.detail_expires_at <= clock_timestamp()
                    AND generation.state IN
                        ('completed','refused','cancelled','superseded','missed')
                    AND (
                        EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_attempts AS attempt
                             WHERE attempt.occurrence_id=generation.occurrence_id
                               AND attempt.finished_at IS NOT NULL
                        )
                        OR (
                            NOT EXISTS (
                                SELECT 1
                                  FROM registry_internal.registry_record_timer_current AS current
                                 WHERE current.occurrence_id=generation.occurrence_id
                            )
                            AND NOT EXISTS (
                                SELECT 1
                                  FROM registry_internal.registry_record_timer_attempts AS attempt
                                 WHERE attempt.occurrence_id=generation.occurrence_id
                            )
                        )
                    )
                 UNION ALL
                 SELECT 1
                   FROM registry_internal.registry_record_timer_attempts AS attempt
                   JOIN registry_internal.registry_record_timer_generations AS generation
                     ON generation.occurrence_id=attempt.occurrence_id
                  WHERE attempt.detail_expires_at IS NOT NULL
                    AND attempt.detail_expires_at <= clock_timestamp()
                    AND generation.state IN ('pending','leased','blocked')
             )",
        );
        let due: bool = transaction
            .transaction()
            .query_one(retention_due_sql.as_ref(), &[])
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?
            .get(0);
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        Ok(due)
    }

    async fn prune_retention_batch(
        &self,
    ) -> std::result::Result<
        super::timer_retention::TimerRetentionBatchResult,
        crate::mutation::MutationError,
    > {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let transaction = begin_registry_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        transaction
            .set_statement_budget(super::operator_read_statement_budget())
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let removed = super::timer_retention::prune_timer_retention_batch(
            &transaction,
            production_timer_limits().elapsed_window_batch_maximum,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            Some(crate::mutation::MutationFaultPoint::AfterCommitBeforeResponseRelease)
        ) {
            return Err(crate::mutation::MutationError::CommitUnresolved);
        }
        Ok(removed)
    }

    async fn claim_one(
        &self,
        client: &mut Client,
    ) -> std::result::Result<Option<ClaimedTimer>, crate::mutation::MutationError> {
        let limits = production_timer_limits();
        if limits.claim_batch_maximum != 1 || limits.maximum_concurrent_attempts != 1 {
            return Err(crate::mutation::MutationError::Unavailable);
        }
        let transaction =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        #[cfg(feature = "postgres-test")]
        if let Some(barrier) = &self.native_before_claim {
            let observed = transaction
                .transaction()
                .query_opt(
                    self.database_clock_sql("SELECT generation.occurrence_id
                       FROM registry_internal.registry_record_timer_generations AS generation
                       JOIN registry_internal.registry_state AS state
                         ON state.singleton AND state.maintenance_status='ready'
                        AND state.package_id=$1 AND state.database_id=$2
                        AND state.active_package_digest=$3
                        AND state.active_activation_id::text=$4
                        AND state.schema_fingerprint=$5
                       JOIN registry_internal.registry_record_timer_control AS control
                         ON control.singleton AND control.protocol_version=1
                        AND control.control_state='running'
                        AND control.bound_instance_epoch=state.epoch
                       JOIN registry_internal.registry_record_timer_current AS current
                         ON current.occurrence_id=generation.occurrence_id
                        AND current.record_type=generation.record_type
                        AND current.record_id=generation.record_id
                        AND current.timer_id=generation.timer_id
                        AND current.binding_incarnation=generation.binding_incarnation
                        AND current.material_signature=generation.material_signature
                       JOIN registry_internal.registry_record_timer_bindings AS binding
                         ON binding.record_type=generation.record_type
                        AND binding.timer_id=generation.timer_id
                        AND binding.incarnation=generation.binding_incarnation
                        AND binding.removed_activation_id IS NULL
                        AND binding.current_policy_activation_id=state.active_activation_id
                        AND binding.definition_revision=generation.definition_revision
                        AND binding.action_revision=generation.action_revision
                        AND binding.system_grant_revision=generation.system_grant_revision
                      WHERE (generation.state='pending'
                         OR (generation.state='leased' AND generation.claim_until < clock_timestamp()))
                        AND generation.gate_open
                        AND (generation.executed_attempt_count < $6
                             OR generation.retry_allowance=1)
                        AND generation.due_at <= clock_timestamp()
                        AND (generation.retry_at IS NULL OR generation.retry_at <= clock_timestamp())
                        AND (generation.not_after IS NULL OR clock_timestamp() < generation.not_after)
                      ORDER BY generation.due_at,generation.record_type,
                               generation.record_id,generation.timer_id
                      LIMIT 1").as_ref(),
                    &[
                        &self.expected.package_id,
                        &self.expected.database_id,
                        &self.expected.package_digest,
                        &self.expected.activation_id,
                        &self.expected.schema_fingerprint,
                        &crate::mutation::MAX_AUTOMATIC_TIMER_ATTEMPTS,
                    ],
                )
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
            let Some(observed) = observed else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
                return Ok(None);
            };
            barrier
                .observe_and_wait(observed.get(0))
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        }
        let control_epoch = crate::mutation::lock_timer_control(transaction.transaction()).await?;
        let control = transaction
            .transaction()
            .query_one(
                "SELECT control.control_state,control.protocol_version,
                        control.bound_instance_epoch,state.epoch
                   FROM registry_internal.registry_record_timer_control AS control
                   JOIN registry_internal.registry_state AS state ON state.singleton
                  WHERE control.singleton",
                &[],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let instance_epoch: i64 = control.get(3);
        if control.get::<_, String>(0) != "running"
            || control.get::<_, i32>(1) != 1
            || control.get::<_, i64>(2) != instance_epoch
        {
            transaction
                .commit()
                .await
                .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
            return Ok(None);
        }
        let lease_millis = i64::try_from(self.lease_duration.as_millis())
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let maximum_lease_millis = i64::try_from(production_lease_duration().as_millis())
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        if lease_millis < 1 || lease_millis > maximum_lease_millis {
            return Err(crate::mutation::MutationError::Unavailable);
        }
        let claim_token = uuid::Uuid::new_v4();
        let active_activation_id = self
            .expected
            .activation_uuid()
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let row = transaction
            .transaction()
            .query_opt(
                self.database_clock_sql("WITH candidate AS (
                     SELECT generation.occurrence_id
                       FROM registry_internal.registry_record_timer_generations AS generation
                       JOIN registry_internal.registry_record_timer_current AS current
                         ON current.occurrence_id=generation.occurrence_id
                        AND current.record_type=generation.record_type
                        AND current.record_id=generation.record_id
                        AND current.timer_id=generation.timer_id
                        AND current.binding_incarnation=generation.binding_incarnation
                        AND current.material_signature=generation.material_signature
                       JOIN registry_internal.registry_record_timer_bindings AS binding
                         ON binding.record_type=generation.record_type
                        AND binding.timer_id=generation.timer_id
                        AND binding.incarnation=generation.binding_incarnation
                        AND binding.removed_activation_id IS NULL
                        AND binding.current_policy_activation_id=$6
                        AND binding.definition_revision=generation.definition_revision
                        AND binding.action_revision=generation.action_revision
                        AND binding.system_grant_revision=generation.system_grant_revision
                      WHERE (generation.state='pending'
                         OR (generation.state='leased' AND generation.claim_until < clock_timestamp()))
                        AND generation.gate_open
                        AND (generation.executed_attempt_count < $7
                             OR generation.retry_allowance=1)
                        AND generation.due_at <= clock_timestamp()
                        AND (generation.retry_at IS NULL OR generation.retry_at <= clock_timestamp())
                        AND (generation.not_after IS NULL OR clock_timestamp() < generation.not_after)
                      ORDER BY generation.due_at,generation.occurrence_id
                      FOR UPDATE OF generation SKIP LOCKED
                      LIMIT 1
                 )
                 UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='leased', claim_owner_id=$1, claim_token=$2, retry_at=NULL,
                        claim_epoch=generation.claim_epoch+1,
                        claim_until=clock_timestamp()+$3::bigint*interval '1 millisecond',
                        claimed_control_epoch=$4, claimed_instance_epoch=$5,
                        claimed_activation_id=$6,
                        updated_at=clock_timestamp()
                   FROM candidate
                  WHERE generation.occurrence_id=candidate.occurrence_id
                 RETURNING generation.record_type,generation.record_id,generation.timer_id,
                           generation.occurrence_id,generation.due_at,generation.not_after,
                           generation.claimed_activation_id,generation.claim_epoch").as_ref(),
                &[
                    &self.claim_owner_id,
                    &claim_token,
                    &lease_millis,
                    &control_epoch,
                    &instance_epoch,
                    &active_activation_id,
                    &crate::mutation::MAX_AUTOMATIC_TIMER_ATTEMPTS,
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let claimed = row.map(|row| ClaimedTimer {
            record_type: row.get(0),
            record_id: row.get(1),
            timer_id: row.get(2),
            occurrence_id: row.get(3),
            due_at: row.get(4),
            not_after: row.get(5),
            claim_token,
            claim_owner_id: self.claim_owner_id,
            claim_epoch: row.get(7),
            control_epoch,
            instance_epoch,
            activation_id: row.get(6),
        });
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        Ok(claimed)
    }

    async fn refresh_one_stale(
        &self,
        client: &mut Client,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let discovery =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let active_activation_id = self
            .expected
            .activation_uuid()
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let query = self.database_clock_sql(
            "SELECT generation.record_type,generation.record_id,generation.timer_id,
                        generation.occurrence_id,generation.binding_incarnation,
                        generation.material_signature,generation.definition_revision,
                        generation.action_revision,generation.system_grant_revision,
                        control.control_epoch,state.epoch,generation.claim_owner_id,
                        generation.claim_token,generation.claim_epoch,generation.claim_until,
                        generation.claimed_control_epoch,generation.claimed_instance_epoch,
                        generation.claimed_activation_id
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                   JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.incarnation=generation.binding_incarnation
                    AND binding.removed_activation_id IS NULL
                    AND binding.current_policy_activation_id=$1
                   JOIN registry_internal.registry_record_timer_control AS control
                     ON control.singleton AND control.protocol_version=1
                    AND control.control_state='running'
                   JOIN registry_internal.registry_state AS state
                     ON state.singleton AND state.maintenance_status='ready'
                    AND state.active_activation_id=$1
                    AND state.epoch=control.bound_instance_epoch
                  WHERE (generation.state IN ('pending','blocked')
                         OR (generation.state='leased'
                             AND generation.claim_until < clock_timestamp()))
                    AND (
                         generation.definition_revision<>binding.definition_revision
                      OR generation.action_revision<>binding.action_revision
                      OR generation.system_grant_revision<>binding.system_grant_revision
                    )
                    AND ($2::text IS NULL OR
                         (generation.record_type,generation.occurrence_id) > ($2,$3::uuid))
                  ORDER BY generation.record_type,generation.occurrence_id
                  LIMIT 1",
        );
        let cursor = self
            .stale_cursor
            .lock()
            .map_err(|_| crate::mutation::MutationError::Unavailable)?
            .clone();
        let cursor_record_type = cursor.as_ref().map(|(record_type, _)| record_type.clone());
        let cursor_occurrence = cursor.as_ref().map(|(_, occurrence_id)| *occurrence_id);
        let mut candidate = discovery
            .transaction()
            .query_opt(
                query.as_ref(),
                &[
                    &active_activation_id,
                    &cursor_record_type,
                    &cursor_occurrence,
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        if candidate.is_none() && cursor.is_some() {
            candidate = discovery
                .transaction()
                .query_opt(
                    query.as_ref(),
                    &[
                        &active_activation_id,
                        &Option::<String>::None,
                        &Option::<uuid::Uuid>::None,
                    ],
                )
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        }
        let candidate = candidate.map(|row| StaleTimer {
            record_type: row.get(0),
            record_id: row.get(1),
            timer_id: row.get(2),
            occurrence_id: row.get(3),
            binding_incarnation: row.get(4),
            material_signature: row.get(5),
            definition_revision: row.get(6),
            action_revision: row.get(7),
            system_grant_revision: row.get(8),
            control_epoch: row.get(9),
            instance_epoch: row.get(10),
            claim_owner_id: row.get(11),
            claim_token: row.get(12),
            claim_epoch: row.get(13),
            claim_until: row.get(14),
            claimed_control_epoch: row.get(15),
            claimed_instance_epoch: row.get(16),
            claimed_activation_id: row.get(17),
        });
        discovery
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        let Some(candidate) = candidate else {
            return Ok(false);
        };
        *self
            .stale_cursor
            .lock()
            .map_err(|_| crate::mutation::MutationError::Unavailable)? =
            Some((candidate.record_type.clone(), candidate.occurrence_id));
        let entity = self
            .registry
            .entities()
            .get(&candidate.record_type)
            .ok_or(crate::mutation::MutationError::Unavailable)?;
        let timer = entity
            .timers
            .get(&candidate.timer_id)
            .ok_or(crate::mutation::MutationError::Unavailable)?;
        let correlation = uuid::Uuid::new_v4().to_string();
        let mut audit = self
            .begin_timer_maintenance_audit(&candidate, &correlation)
            .await?;
        let result = async {
            let transaction = begin_registry_transaction(
                client,
                self.lock_key,
                self.lock_timeout,
                &self.expected,
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
            let control_epoch =
                crate::mutation::lock_timer_control(transaction.transaction()).await?;
            let control = transaction
                .transaction()
                .query_one(
                    "SELECT control_state,bound_instance_epoch
                       FROM registry_internal.registry_record_timer_control
                      WHERE singleton AND protocol_version=1",
                    &[],
                )
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
            if control_epoch != candidate.control_epoch
                || control.get::<_, String>(0) != "running"
                || control.get::<_, i64>(1) != candidate.instance_epoch
            {
                transaction
                    .commit()
                    .await
                    .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
                return Ok(false);
            }
            let context = json!({
                "version":1,
                "actorKind":"system",
                "systemActor":"record-timer-refresh",
                "recordType":candidate.record_type,
                "timerId":candidate.timer_id,
                "occurrenceId":candidate.occurrence_id,
                "anchorRecordId":candidate.record_id,
                "bindingIncarnation":candidate.binding_incarnation,
                "materialSignature":candidate.material_signature,
                "priorDefinitionRevision":candidate.definition_revision,
                "priorActionRevision":candidate.action_revision,
                "priorSystemGrantRevision":candidate.system_grant_revision,
                "controlEpoch":candidate.control_epoch,
                "instanceEpoch":candidate.instance_epoch,
                "claimOwnerId":candidate.claim_owner_id,
                "claimToken":candidate.claim_token,
                "claimEpoch":candidate.claim_epoch,
                "claimUntil":candidate.claim_until,
                "claimedControlEpoch":candidate.claimed_control_epoch,
                "claimedInstanceEpoch":candidate.claimed_instance_epoch,
                "claimedActivationId":candidate.claimed_activation_id,
                "packageId":self.expected.package_id,
                "databaseId":self.expected.database_id,
                "packageDigest":self.expected.package_digest,
                "schemaFingerprint":self.expected.schema_fingerprint,
                "activationId":active_activation_id,
                "activePackageRevision":self.expected.activation_id,
                "selectedAccessProfile":crate::mutation::TIMER_ACCESS_PROFILE,
                "principal":crate::mutation::TIMER_PRINCIPAL,
            });
            let context = String::from_utf8(
                canonicalize_json(&context)
                    .map_err(|_| crate::mutation::MutationError::Unavailable)?,
            )
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
            transaction
                .transaction()
                .execute(
                    "SELECT set_config('registry.principal',$1,true),
                            set_config('registry.access_profile',$2,true),
                            set_config('registry.active_package_revision',$3,true),
                            set_config('registry.record_timer_refresh_context',$4,true)",
                    &[
                        &crate::mutation::TIMER_PRINCIPAL,
                        &crate::mutation::TIMER_ACCESS_PROFILE,
                        &self.expected.activation_id,
                        &context,
                    ],
                )
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
            let mut fields = timer.control_fields.clone();
            fields.extend(timer.predicate_fields.iter().cloned());
            fields.extend(timer.effect_input_fields.iter().cloned());
            let mut projections = vec!["record_id::text".to_owned(), "record_lifecycle".to_owned()];
            for field_id in &fields {
                let field = entity
                    .fields
                    .get(field_id)
                    .ok_or(crate::mutation::MutationError::Unavailable)?;
                projections.push(crate::mutation::field_json_projection(field));
            }
            let Some(row) = transaction
                .transaction()
                .query_opt(
                    &format!(
                        "SELECT {} FROM registry_data.{} WHERE record_id=$1 FOR UPDATE SKIP LOCKED",
                        projections.join(", "),
                        quote_identifier(&entity.physical_table),
                    ),
                    &[&candidate.record_id],
                )
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?
            else {
                transaction
                    .commit()
                    .await
                    .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
                return Ok(false);
            };
            if row.get::<_, String>(0) != candidate.record_id.to_string()
                || row.get::<_, String>(1) != "active"
            {
                return Err(crate::mutation::MutationError::RetryableConflict);
            }
            let mut data = Map::new();
            for (index, field_id) in fields.iter().enumerate() {
                let field = entity
                    .fields
                    .get(field_id)
                    .ok_or(crate::mutation::MutationError::Unavailable)?;
                let projected = row
                    .try_get::<_, Option<Value>>(index + 2)
                    .map_err(|_| crate::mutation::MutationError::Unavailable)?
                    .unwrap_or(Value::Null);
                let value = if field.encryption.is_some() {
                    crate::mutation::envelope_member_from_projection(projected)?
                } else {
                    projected
                };
                data.insert(field_id.clone(), value);
            }
            let metadata = crate::mutation::refreshed_timer_metadata(
                entity,
                timer,
                candidate.record_id,
                data,
                self.coordinator.field_encryption(),
            )?;
            match metadata {
                Some(metadata) => {
                    self.commit_timer_refresh(
                        transaction,
                        &candidate,
                        timer,
                        &metadata,
                        active_activation_id,
                        control_epoch,
                    )
                    .await
                }
                None => {
                    self.commit_timer_refresh_control_cleared(
                        transaction,
                        &candidate,
                        timer,
                        active_activation_id,
                        control_epoch,
                    )
                    .await
                }
            }
        }
        .await;
        self.finish_timer_maintenance_audit(&mut audit, &candidate, &correlation, result)
            .await
    }

    async fn cancel_one_removed(
        &self,
        client: &mut Client,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let discovery =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        discovery
            .set_statement_budget(super::operator_read_statement_budget())
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let candidate = discovery
            .transaction()
            .query_opt(
                "SELECT generation.record_type,generation.record_id,generation.timer_id,
                        generation.occurrence_id,generation.binding_incarnation,
                        generation.material_signature,generation.definition_revision,
                        generation.action_revision,generation.system_grant_revision,
                        control.control_epoch,state.epoch
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                   JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.incarnation=generation.binding_incarnation
                    AND binding.removed_activation_id IS NOT NULL
                   JOIN registry_internal.registry_record_timer_control AS control
                     ON control.singleton AND control.protocol_version=1
                    AND control.control_state IN ('running','paused','adoption-hold')
                   JOIN registry_internal.registry_state AS state
                     ON state.singleton AND state.maintenance_status='ready'
                    AND state.epoch=control.bound_instance_epoch
                  WHERE generation.state IN ('pending','leased','blocked')
                  ORDER BY generation.updated_at,generation.occurrence_id
                  LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?
            .map(|row| StaleTimer {
                record_type: row.get(0),
                record_id: row.get(1),
                timer_id: row.get(2),
                occurrence_id: row.get(3),
                binding_incarnation: row.get(4),
                material_signature: row.get(5),
                definition_revision: row.get(6),
                action_revision: row.get(7),
                system_grant_revision: row.get(8),
                control_epoch: row.get(9),
                instance_epoch: row.get(10),
                claim_owner_id: None,
                claim_token: None,
                claim_epoch: 0,
                claim_until: None,
                claimed_control_epoch: None,
                claimed_instance_epoch: None,
                claimed_activation_id: None,
            });
        discovery
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        let Some(candidate) = candidate else {
            return Ok(false);
        };

        let transaction =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let control_epoch = crate::mutation::lock_timer_control(transaction.transaction()).await?;
        let cancelled = transaction
            .transaction()
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='cancelled',outcome_code='binding-removed',block_kind=NULL,
                        retry_at=NULL,claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                        claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL,completed_at=statement_timestamp(),
                        detail_expires_at=statement_timestamp()+$12::bigint*interval '1 day',
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_bindings AS binding,
                        registry_internal.registry_record_timer_control AS control,
                        registry_internal.registry_state AS state
                  WHERE generation.record_type=$1 AND generation.record_id=$2
                    AND generation.timer_id=$3 AND generation.occurrence_id=$4
                    AND generation.binding_incarnation=$5
                    AND generation.material_signature=$6
                    AND generation.definition_revision=$7
                    AND generation.action_revision=$8
                    AND generation.system_grant_revision=$9
                    AND generation.state IN ('pending','leased','blocked')
                    AND binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.incarnation=generation.binding_incarnation
                    AND binding.removed_activation_id IS NOT NULL
                    AND control.singleton AND control.protocol_version=1
                    AND control.control_epoch=$10 AND control.bound_instance_epoch=$11
                    AND control.control_state IN ('running','paused','adoption-hold')
                    AND state.singleton AND state.maintenance_status='ready'
                    AND state.epoch=$11
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_current AS current
                         WHERE current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.occurrence_id=generation.occurrence_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                    )",
                )
                .as_ref(),
                &[
                    &candidate.record_type,
                    &candidate.record_id,
                    &candidate.timer_id,
                    &candidate.occurrence_id,
                    &candidate.binding_incarnation,
                    &candidate.material_signature,
                    &candidate.definition_revision,
                    &candidate.action_revision,
                    &candidate.system_grant_revision,
                    &control_epoch,
                    &candidate.instance_epoch,
                    &i64::from(self.coordinator.timer_detail_retention_days()),
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        if cancelled != 1 {
            return Err(crate::mutation::MutationError::RetryableConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        Ok(true)
    }

    async fn expire_one_elapsed(
        &self,
        client: &mut Client,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let discovery =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        discovery
            .set_statement_budget(super::operator_read_statement_budget())
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let candidate = discovery
            .transaction()
            .query_opt(
                self.database_clock_sql(
                    "SELECT generation.record_type,generation.record_id,generation.timer_id,
                        generation.occurrence_id,generation.binding_incarnation,
                        generation.material_signature,generation.definition_revision,
                        generation.action_revision,generation.system_grant_revision,
                        control.control_epoch,state.epoch
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                   JOIN registry_internal.registry_state AS state
                     ON state.singleton AND state.maintenance_status='ready'
                    AND state.package_id=$1 AND state.database_id=$2
                    AND state.active_package_digest=$3
                    AND state.active_activation_id::text=$4
                    AND state.schema_fingerprint=$5
                   JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.incarnation=generation.binding_incarnation
                    AND binding.removed_activation_id IS NULL
                    AND binding.current_policy_activation_id=state.active_activation_id
                    AND binding.definition_revision=generation.definition_revision
                    AND binding.action_revision=generation.action_revision
                    AND binding.system_grant_revision=generation.system_grant_revision
                   JOIN registry_internal.registry_record_timer_control AS control
                     ON control.singleton AND control.protocol_version=1
                    AND control.control_state IN ('running','paused','adoption-hold')
                    AND control.bound_instance_epoch=state.epoch
                  WHERE generation.not_after IS NOT NULL
                    AND generation.not_after>generation.due_at
                    AND generation.not_after<=clock_timestamp()
                    AND generation.state IN ('pending','leased','blocked')
                  ORDER BY generation.not_after,generation.record_type,
                           generation.record_id,generation.timer_id
                  LIMIT 1",
                )
                .as_ref(),
                &[
                    &self.expected.package_id,
                    &self.expected.database_id,
                    &self.expected.package_digest,
                    &self.expected.activation_id,
                    &self.expected.schema_fingerprint,
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?
            .map(|row| StaleTimer {
                record_type: row.get(0),
                record_id: row.get(1),
                timer_id: row.get(2),
                occurrence_id: row.get(3),
                binding_incarnation: row.get(4),
                material_signature: row.get(5),
                definition_revision: row.get(6),
                action_revision: row.get(7),
                system_grant_revision: row.get(8),
                control_epoch: row.get(9),
                instance_epoch: row.get(10),
                claim_owner_id: None,
                claim_token: None,
                claim_epoch: 0,
                claim_until: None,
                claimed_control_epoch: None,
                claimed_instance_epoch: None,
                claimed_activation_id: None,
            });
        discovery
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        let Some(candidate) = candidate else {
            return Ok(false);
        };
        let correlation = crate::correlation::RequestCorrelation::breg_created()
            .request_id()
            .to_string();
        let mut audit = self
            .begin_timer_maintenance_audit(&candidate, &correlation)
            .await?;
        let transaction =
            begin_registry_transaction(client, self.lock_key, self.lock_timeout, &self.expected)
                .await
                .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let control_epoch = crate::mutation::lock_timer_control(transaction.transaction()).await?;
        let active_activation_id = self
            .expected
            .activation_uuid()
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let expired = transaction
            .transaction()
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='missed',outcome_code='execution-window-expired',block_kind=NULL,
                        retry_at=NULL,claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                        claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL,completed_at=statement_timestamp(),
                        detail_expires_at=statement_timestamp()+$13::bigint*interval '1 day',
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_bindings AS binding,
                        registry_internal.registry_record_timer_control AS control,
                        registry_internal.registry_state AS state
                  WHERE generation.record_type=$1 AND generation.record_id=$2
                    AND generation.timer_id=$3 AND generation.occurrence_id=$4
                    AND generation.binding_incarnation=$5
                    AND generation.material_signature=$6
                    AND generation.definition_revision=$7
                    AND generation.action_revision=$8
                    AND generation.system_grant_revision=$9
                    AND generation.not_after IS NOT NULL
                    AND generation.not_after>generation.due_at
                    AND generation.not_after<=clock_timestamp()
                    AND generation.state IN ('pending','leased','blocked')
                    AND binding.record_type=generation.record_type
                    AND binding.timer_id=generation.timer_id
                    AND binding.incarnation=generation.binding_incarnation
                    AND binding.removed_activation_id IS NULL
                    AND binding.current_policy_activation_id=$10
                    AND binding.definition_revision=generation.definition_revision
                    AND binding.action_revision=generation.action_revision
                    AND binding.system_grant_revision=generation.system_grant_revision
                    AND control.singleton AND control.protocol_version=1
                    AND control.control_epoch=$11 AND control.bound_instance_epoch=$12
                    AND control.control_state IN ('running','paused','adoption-hold')
                    AND state.singleton AND state.maintenance_status='ready'
                    AND state.active_activation_id=$10 AND state.epoch=$12
                    AND EXISTS (
                        SELECT 1
                          FROM registry_internal.registry_record_timer_current AS current
                         WHERE current.record_type=generation.record_type
                           AND current.record_id=generation.record_id
                           AND current.timer_id=generation.timer_id
                           AND current.occurrence_id=generation.occurrence_id
                           AND current.binding_incarnation=generation.binding_incarnation
                           AND current.material_signature=generation.material_signature
                    )",
                )
                .as_ref(),
                &[
                    &candidate.record_type,
                    &candidate.record_id,
                    &candidate.timer_id,
                    &candidate.occurrence_id,
                    &candidate.binding_incarnation,
                    &candidate.material_signature,
                    &candidate.definition_revision,
                    &candidate.action_revision,
                    &candidate.system_grant_revision,
                    &active_activation_id,
                    &control_epoch,
                    &candidate.instance_epoch,
                    &i64::from(self.coordinator.timer_detail_retention_days()),
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let result = if expired == 1 {
            transaction
                .commit()
                .await
                .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
            Ok(true)
        } else {
            transaction
                .commit()
                .await
                .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
            Ok(false)
        };
        self.finish_timer_maintenance_audit(&mut audit, &candidate, &correlation, result)
            .await
    }

    async fn begin_timer_maintenance_audit(
        &self,
        candidate: &StaleTimer,
        correlation: &str,
    ) -> std::result::Result<AuditRequest, crate::mutation::MutationError> {
        let record = timer_maintenance_audit_record(
            &self.expected,
            candidate,
            correlation,
            "attempt",
            "started",
        );
        self.coordinator
            .registry_audit()
            .begin(
                AuditEntry::request(
                    RECORD_TIMER_MAINTENANCE_AUDIT_SCHEMA,
                    correlation.to_owned(),
                    record,
                ),
                timer_maintenance_audit_record(
                    &self.expected,
                    candidate,
                    correlation,
                    "terminal",
                    "unfinished",
                ),
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)
    }

    async fn finish_timer_maintenance_audit(
        &self,
        audit: &mut AuditRequest,
        candidate: &StaleTimer,
        correlation: &str,
        result: std::result::Result<bool, crate::mutation::MutationError>,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        if matches!(
            &result,
            Err(crate::mutation::MutationError::CommitUnresolved)
        ) {
            return result;
        }
        let (outcome, committed) = match &result {
            Ok(true) => ("refreshed", true),
            Ok(false) => ("refused", false),
            Err(_) => ("failed", false),
        };
        let record = timer_maintenance_audit_record(
            &self.expected,
            candidate,
            correlation,
            "terminal",
            outcome,
        );
        if audit.respond(record).await.is_err() {
            return Err(if committed {
                crate::mutation::MutationError::CommitUnresolved
            } else {
                crate::mutation::MutationError::Unavailable
            });
        }
        result
    }

    async fn commit_timer_refresh(
        &self,
        transaction: GuardedTransaction<'_>,
        candidate: &StaleTimer,
        timer: &crate::model::CompiledTimer,
        metadata: &crate::mutation::RefreshedTimerMetadata,
        active_activation_id: uuid::Uuid,
        control_epoch: i64,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let refreshed = transaction
            .transaction()
            .execute(
                self.database_clock_sql(
                    "WITH refreshed AS (
                     UPDATE registry_internal.registry_record_timer_generations AS generation
                        SET material_signature=$10,due_at=$11,not_after=$12,
                            definition_revision=$13,action_revision=$14,
                            system_grant_revision=$15,gate_open=$16,
                            target_binding_digests=$17,current_policy_activation_id=$18,
                            state=CASE
                                WHEN $21 AND block_kind IS DISTINCT FROM 'technical' THEN 'blocked'
                                WHEN generation.state='leased' THEN 'pending'
                                WHEN block_kind='configuration' THEN 'pending'
                                ELSE state
                            END,
                            block_kind=CASE
                                WHEN $21 AND block_kind IS DISTINCT FROM 'technical'
                                    THEN 'configuration'
                                WHEN block_kind='configuration' THEN NULL
                                ELSE block_kind
                            END,
                            outcome_code=CASE
                                WHEN block_kind='technical' THEN outcome_code
                                WHEN $21 OR block_kind='configuration' THEN NULL
                                ELSE outcome_code
                            END,
                            retry_at=CASE
                                WHEN block_kind='technical' THEN retry_at
                                WHEN $21 OR block_kind='configuration' THEN NULL
                                ELSE retry_at
                            END,
                            claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                            claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                            claimed_activation_id=NULL,
                            updated_at=clock_timestamp()
                       FROM registry_internal.registry_record_timer_bindings AS binding,
                            registry_internal.registry_record_timer_control AS control,
                            registry_internal.registry_state AS state
                      WHERE generation.record_type=$1 AND generation.record_id=$2
                        AND generation.timer_id=$3 AND generation.occurrence_id=$4
                        AND generation.binding_incarnation=$5
                        AND generation.material_signature=$6
                        AND generation.definition_revision=$7
                        AND generation.action_revision=$8
                        AND generation.system_grant_revision=$9
                        AND (
                            generation.state IN ('pending','blocked')
                            OR (
                                generation.state='leased'
                                AND generation.claim_owner_id=$22
                                AND generation.claim_token=$23
                                AND generation.claim_epoch=$24
                                AND generation.claim_until=$25
                                AND generation.claimed_control_epoch=$26
                                AND generation.claimed_instance_epoch=$27
                                AND generation.claimed_activation_id=$28
                                AND generation.claim_until < clock_timestamp()
                            )
                        )
                        AND binding.record_type=generation.record_type
                        AND binding.timer_id=generation.timer_id
                        AND binding.incarnation=generation.binding_incarnation
                        AND binding.removed_activation_id IS NULL
                        AND binding.current_policy_activation_id=$18
                        AND binding.definition_revision=$13
                        AND binding.action_revision=$14
                        AND binding.system_grant_revision=$15
                        AND control.singleton AND control.protocol_version=1
                        AND control.control_state='running' AND control.control_epoch=$19
                        AND control.bound_instance_epoch=$20
                        AND state.singleton AND state.maintenance_status='ready'
                        AND state.active_activation_id=$18 AND state.epoch=$20
                        AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_current AS current
                             WHERE current.record_type=generation.record_type
                               AND current.record_id=generation.record_id
                               AND current.timer_id=generation.timer_id
                               AND current.occurrence_id=generation.occurrence_id
                               AND current.binding_incarnation=generation.binding_incarnation
                               AND current.material_signature=generation.material_signature
                        )
                  RETURNING generation.occurrence_id
                 )
                 UPDATE registry_internal.registry_record_timer_current AS current
                    SET material_signature=$10,updated_at=clock_timestamp()
                   FROM refreshed
                  WHERE current.record_type=$1 AND current.record_id=$2
                    AND current.timer_id=$3 AND current.occurrence_id=refreshed.occurrence_id
                    AND current.binding_incarnation=$5 AND current.material_signature=$6",
                )
                .as_ref(),
                &[
                    &candidate.record_type,
                    &candidate.record_id,
                    &candidate.timer_id,
                    &candidate.occurrence_id,
                    &candidate.binding_incarnation,
                    &candidate.material_signature,
                    &candidate.definition_revision,
                    &candidate.action_revision,
                    &candidate.system_grant_revision,
                    &metadata.material_signature,
                    &metadata.due_at,
                    &metadata.not_after,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &metadata.gate_open,
                    &metadata.target_binding_digests,
                    &active_activation_id,
                    &control_epoch,
                    &candidate.instance_epoch,
                    &metadata.configuration_blocked,
                    &candidate.claim_owner_id,
                    &candidate.claim_token,
                    &candidate.claim_epoch,
                    &candidate.claim_until,
                    &candidate.claimed_control_epoch,
                    &candidate.claimed_instance_epoch,
                    &candidate.claimed_activation_id,
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        if refreshed != 1 {
            return Err(crate::mutation::MutationError::RetryableConflict);
        }
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            Some(crate::mutation::MutationFaultPoint::BeforeCommit)
        ) {
            return Err(crate::mutation::MutationError::Unavailable);
        }
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            Some(crate::mutation::MutationFaultPoint::AfterCommitBeforeResponseRelease)
        ) {
            return Err(crate::mutation::MutationError::CommitUnresolved);
        }
        Ok(true)
    }

    async fn commit_timer_refresh_control_cleared(
        &self,
        transaction: GuardedTransaction<'_>,
        candidate: &StaleTimer,
        timer: &crate::model::CompiledTimer,
        active_activation_id: uuid::Uuid,
        control_epoch: i64,
    ) -> std::result::Result<bool, crate::mutation::MutationError> {
        let cancelled = transaction
            .transaction()
            .execute(
                self.database_clock_sql(
                    "UPDATE registry_internal.registry_record_timer_generations AS generation
                        SET definition_revision=$10,action_revision=$11,
                            system_grant_revision=$12,current_policy_activation_id=$13,
                            state='cancelled',block_kind=NULL,outcome_code='control-cleared',
                            retry_at=NULL,claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                            claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                            claimed_activation_id=NULL,gate_open=false,
                            completed_at=statement_timestamp(),
                            detail_expires_at=statement_timestamp()+$16::bigint*interval '1 day',
                            updated_at=clock_timestamp()
                       FROM registry_internal.registry_record_timer_bindings AS binding,
                            registry_internal.registry_record_timer_control AS control,
                            registry_internal.registry_state AS state
                      WHERE generation.record_type=$1 AND generation.record_id=$2
                        AND generation.timer_id=$3 AND generation.occurrence_id=$4
                        AND generation.binding_incarnation=$5
                        AND generation.material_signature=$6
                        AND generation.definition_revision=$7
                        AND generation.action_revision=$8
                        AND generation.system_grant_revision=$9
                        AND (
                            generation.state IN ('pending','blocked')
                            OR (
                                generation.state='leased'
                                AND generation.claim_owner_id=$17
                                AND generation.claim_token=$18
                                AND generation.claim_epoch=$19
                                AND generation.claim_until=$20
                                AND generation.claimed_control_epoch=$21
                                AND generation.claimed_instance_epoch=$22
                                AND generation.claimed_activation_id=$23
                                AND generation.claim_until < clock_timestamp()
                            )
                        )
                        AND binding.record_type=generation.record_type
                        AND binding.timer_id=generation.timer_id
                        AND binding.incarnation=generation.binding_incarnation
                        AND binding.removed_activation_id IS NULL
                        AND binding.current_policy_activation_id=$13
                        AND binding.definition_revision=$10
                        AND binding.action_revision=$11
                        AND binding.system_grant_revision=$12
                        AND control.singleton AND control.protocol_version=1
                        AND control.control_state='running' AND control.control_epoch=$14
                        AND control.bound_instance_epoch=$15
                        AND state.singleton AND state.maintenance_status='ready'
                        AND state.active_activation_id=$13 AND state.epoch=$15
                        AND EXISTS (
                            SELECT 1
                              FROM registry_internal.registry_record_timer_current AS current
                             WHERE current.record_type=generation.record_type
                               AND current.record_id=generation.record_id
                               AND current.timer_id=generation.timer_id
                               AND current.occurrence_id=generation.occurrence_id
                               AND current.binding_incarnation=generation.binding_incarnation
                               AND current.material_signature=generation.material_signature
                        )",
                )
                .as_ref(),
                &[
                    &candidate.record_type,
                    &candidate.record_id,
                    &candidate.timer_id,
                    &candidate.occurrence_id,
                    &candidate.binding_incarnation,
                    &candidate.material_signature,
                    &candidate.definition_revision,
                    &candidate.action_revision,
                    &candidate.system_grant_revision,
                    &timer.definition_revision,
                    &timer.action_revision,
                    &timer.system_grant.revision,
                    &active_activation_id,
                    &control_epoch,
                    &candidate.instance_epoch,
                    &(self.coordinator.timer_detail_retention_days() as i64),
                    &candidate.claim_owner_id,
                    &candidate.claim_token,
                    &candidate.claim_epoch,
                    &candidate.claim_until,
                    &candidate.claimed_control_epoch,
                    &candidate.claimed_instance_epoch,
                    &candidate.claimed_activation_id,
                ],
            )
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        if cancelled != 1 {
            return Err(crate::mutation::MutationError::RetryableConflict);
        }
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            Some(crate::mutation::MutationFaultPoint::BeforeCommit)
        ) {
            return Err(crate::mutation::MutationError::Unavailable);
        }
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)?;
        #[cfg(feature = "postgres-test")]
        if matches!(
            self.fault,
            Some(crate::mutation::MutationFaultPoint::AfterCommitBeforeResponseRelease)
        ) {
            return Err(crate::mutation::MutationError::CommitUnresolved);
        }
        Ok(true)
    }

    async fn settle_technical_failure(
        &self,
        authority: &crate::mutation::TimerActionAuthority,
        technical_code: &str,
        started_at: DateTime<Utc>,
    ) -> std::result::Result<(), crate::mutation::MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let transaction = begin_registry_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        crate::mutation::lock_timer_control(transaction.transaction()).await?;
        authority
            .settle_technical_failure(transaction.transaction(), technical_code, started_at)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)
    }

    async fn settle_refusal(
        &self,
        authority: &crate::mutation::TimerActionAuthority,
        outcome: crate::mutation::TimerRefusalOutcome,
        started_at: DateTime<Utc>,
    ) -> std::result::Result<(), crate::mutation::MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        let transaction = begin_registry_transaction(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
        )
        .await
        .map_err(|_| crate::mutation::MutationError::Unavailable)?;
        crate::mutation::lock_timer_control(transaction.transaction()).await?;
        authority
            .settle_refusal(transaction.transaction(), outcome, started_at)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| crate::mutation::MutationError::CommitUnresolved)
    }
}

fn timer_maintenance_audit_record(
    expected: &ExpectedRegistryIdentity,
    candidate: &StaleTimer,
    correlation: &str,
    phase: &str,
    outcome: &str,
) -> Value {
    json!({
        "kind":"recordTimerRefresh",
        "phase":phase,
        "outcome":outcome,
        "activationId":expected.activation_id,
        "recordType":candidate.record_type,
        "timer":candidate.timer_id,
        "actor":"breg:record-timer-worker",
        "correlation":correlation,
    })
}

fn timer_technical_code(error: &crate::mutation::MutationError) -> Option<&'static str> {
    match error {
        crate::mutation::MutationError::ActionHandlerFailure(_) => Some("handler-failure"),
        crate::mutation::MutationError::FieldEncryptionUnavailable => {
            Some("field-encryption-unavailable")
        }
        crate::mutation::MutationError::RetryableConflict => Some("concurrency-conflict"),
        crate::mutation::MutationError::CommitUnresolved => Some("commit-unresolved"),
        crate::mutation::MutationError::Unavailable => Some("runtime-unavailable"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_lease_covers_action_budget_and_finalization_allowance() {
        assert_eq!(
            production_lease_duration(),
            super::super::mutation::REQUEST_ACTION_TIMEOUT + LEASE_FINALIZATION_ALLOWANCE
        );
        assert!(production_lease_duration() > super::super::mutation::REQUEST_ACTION_TIMEOUT);
    }
}
