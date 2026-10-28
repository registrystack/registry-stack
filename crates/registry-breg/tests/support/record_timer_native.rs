// SPDX-License-Identifier: Apache-2.0

//! Real-process fixture for record-timer acceptance tests.
//!
//! The fixture deliberately launches the shipped `breg` binary instead of a
//! Router assembled inside the test process. Every replica receives its own
//! listener, process/replica identity, audit file, and PostgreSQL application
//! name, while all replicas share one logical deployment identity, activated
//! package, and disposable database.

use std::{
    fs::{self, File, OpenOptions},
    io::Read as _,
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use registry_breg::{
    compiler::{compile_project, CompileProfile},
    contract::parse_project_yaml,
    package::{
        load_package, prepare_package, PackageBuildRequest, PackageLoadContext,
        PackageMigrationPlanInput, PackageSourceFile, FIXTURE_JOURNEYS_PATH,
    },
    postgres::{
        initialize_compiled_registry_state_for_test, install_compiled_schema,
        managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
    },
    CompiledRegistry,
};
#[cfg(feature = "tooling")]
use registry_breg::{
    migration::{
        apply_verified_package, plan_verified_package, read_recorded_registry_state,
        ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest, PlannedActivation,
    },
    migration_plan::{
        MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
        ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
    },
    package::{compiled_registry_change_set, CompiledRegistryChangeClass},
};
use registry_breg_client::{
    ingestion_prefix_digest, BRegBatchBinding, BRegBatchBuilder, BRegBatchOperation,
    BRegBatchReceipt, BRegBatchRequest, BRegComplete, BRegCreateBinding, BRegCreateRequest,
    BRegDirectWrite, BRegIdempotencyKey, BRegIngestionChunk, BRegIngestionChunkSubmission,
    BRegIngestionRunRequest, BRegIngestionRunStatus, BRegPatchBinding, BRegPatchRequest,
    BRegProblemCode, BRegRecordFormat, BRegRecordOptions, BRegTombstoneBinding, BaseRegistryClient,
    BaseRegistryClientConfig, BearerToken, RegistryRecordSingleResponse,
    BREG_INGESTION_CHUNK_ALGORITHM_VERSION,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_testing::{
    fixtures as testing_fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt,
};
use serde::Deserialize;
use serde_json::{json, Map};
#[cfg(feature = "tooling")]
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use url::Url;
use uuid::Uuid;

use super::postgres_harness::TestDatabase;

const AUDIENCE: &str = "urn:breg:record-timer-native";
const DATABASE_ID: &str = "record-timer-native-database";
const ENVIRONMENT: &str = "local";
const INSTANCE_ID: &str = "record-timer-native-deployment";
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP_REQUEST_MILLISECONDS: u64 = 5_000;
const MUTATION_CHECKPOINT_HTTP_REQUEST_MILLISECONDS: u64 = 12_000;

pub struct NativeTimerHarness {
    database: Option<TestDatabase>,
    pub registry: Arc<CompiledRegistry>,
    scratch: Option<TempDir>,
    package_root: PathBuf,
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    refused_package_root: PathBuf,
    package_id: String,
    package_digest: String,
    schema_fingerprint: String,
    token: String,
    replicas: Vec<NativeReplica>,
    checkpoint: Option<NativeTimerCheckpoint>,
    outcome_checkpoint: Option<NativeOutcomeSettlementKind>,
    lease_milliseconds: Option<u64>,
    mutation_checkpoint_for_new_replicas: bool,
    metrics_for_new_replicas: bool,
    business_refusal_guard: bool,
}

pub struct NativeReplica {
    pub base_url: Url,
    metrics_base_url: Option<Url>,
    child: Child,
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    config_path: PathBuf,
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    audit_path: PathBuf,
    log_path: PathBuf,
    command: NativeProcessIdentity,
    checkpoint_barrier: Option<NativeBarrierFiles>,
    mutation_checkpoint_barrier: Option<NativeOperationBarrierFiles>,
    expected_non_info_codes: std::collections::BTreeMap<String, (usize, usize)>,
    stopped: bool,
}

pub struct NativeHeldAnchorLock {
    release: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl NativeHeldAnchorLock {
    pub async fn release(mut self) -> Result<(), String> {
        self.release
            .take()
            .ok_or_else(|| "native anchor lock was already released".to_owned())?
            .send(())
            .map_err(|_| "native anchor lock task stopped before release".to_owned())?;
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .map_err(|_| "native anchor lock did not release within the bound".to_owned())?
            .map_err(|error| format!("native anchor lock task failed: {error}"))?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTimerCheckpoint {
    BeforeClaim,
    AfterClaim,
    BeforeCommit,
    AfterCommitBeforeResponse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOutcomeSettlementKind {
    DeclaredRefusal,
    TechnicalFailure,
}

impl NativeOutcomeSettlementKind {
    fn label(self) -> &'static str {
        match self {
            Self::DeclaredRefusal => "before-outcome-settlement-declared-refusal",
            Self::TechnicalFailure => "before-outcome-settlement-technical-failure",
        }
    }

    fn selector(self) -> &'static str {
        match self {
            Self::DeclaredRefusal => "declared-refusal",
            Self::TechnicalFailure => "technical-failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeFixtureVariant {
    Maintained,
    #[cfg(feature = "tooling")]
    TimerFree,
    BulkWrites,
    DeclaredRefusal,
    Fairness,
}

impl NativeTimerCheckpoint {
    fn label(self) -> &'static str {
        match self {
            Self::BeforeClaim => "before-claim",
            Self::AfterClaim => "after-claim",
            Self::BeforeCommit => "before-commit",
            Self::AfterCommitBeforeResponse => "after-commit-before-response",
        }
    }

    fn environment(self) -> (&'static str, &'static str) {
        match self {
            Self::BeforeClaim => (
                "BREG_TIMER_TEST_BEFORE_CLAIM_OBSERVED_PATH",
                "BREG_TIMER_TEST_BEFORE_CLAIM_RELEASE_PATH",
            ),
            Self::AfterClaim => (
                "BREG_TIMER_TEST_AFTER_CLAIM_OBSERVED_PATH",
                "BREG_TIMER_TEST_AFTER_CLAIM_RELEASE_PATH",
            ),
            Self::BeforeCommit => (
                "BREG_TIMER_TEST_BEFORE_COMMIT_OBSERVED_PATH",
                "BREG_TIMER_TEST_BEFORE_COMMIT_RELEASE_PATH",
            ),
            Self::AfterCommitBeforeResponse => (
                "BREG_TIMER_TEST_AFTER_COMMIT_BEFORE_RESPONSE_OBSERVED_PATH",
                "BREG_TIMER_TEST_AFTER_COMMIT_BEFORE_RESPONSE_RELEASE_PATH",
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProcessIdentity {
    pub pid: u32,
    pub instance_id: String,
    pub replica_id: String,
    pub launch_id: String,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRunIdentity {
    pub package_id: String,
    pub package_digest: String,
    pub processes: Vec<NativeProcessIdentity>,
}

#[cfg(feature = "tooling")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSuccessorActivationEvidence {
    pub predecessor_package_digest: String,
    pub predecessor_activation_id: String,
    pub successor_package_digest: String,
    pub successor_activation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeOperatorConfig {
    pub path: PathBuf,
    pub application_name: String,
    audit_path: PathBuf,
}

#[allow(dead_code)] // Fields are consumed by the sibling operator integration target.
#[derive(Debug)]
pub struct NativeBregctlOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
    pub executable: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseBlockingEvidence {
    pub blocked_pid: i32,
    pub blocker_pid: i32,
}

pub struct NativeIngestionPatch {
    run_id: Uuid,
    chunk: BRegIngestionChunk,
}

impl NativeIngestionPatch {
    pub const fn run_id(&self) -> Uuid {
        self.run_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIngestionEvidence {
    pub status: String,
    pub next_chunk_index: i64,
    pub committed_items: i64,
    pub chunk_receipts: i64,
    pub linked_records: i64,
}

#[derive(Debug)]
struct NativeBarrierFiles {
    observed: PathBuf,
    release: PathBuf,
}

#[derive(Debug)]
struct NativeOperationBarrierFiles {
    observed: PathBuf,
    release: PathBuf,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BeforeClaimMarker {
    instance_id: String,
    process_id: u32,
    occurrence_id: Uuid,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MutationCheckpointMarker {
    instance_id: String,
    process_id: u32,
    operation: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ClaimTokenEvidence(Uuid);

impl std::fmt::Debug for ClaimTokenEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted-claim-token>")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct TimerEvidence {
    pub state: String,
    pub status: String,
    pub revision: i64,
    pub revisions: i64,
    pub outbox_entries: i64,
    pub action_receipts: i64,
    pub occurrence_id: Uuid,
    pub binding_incarnation: i64,
    pub material_signature: String,
    pub due_at: chrono::DateTime<Utc>,
    pub not_after: Option<chrono::DateTime<Utc>>,
    pub retry_at: Option<chrono::DateTime<Utc>>,
    pub definition_revision: String,
    pub action_revision: String,
    pub system_grant_revision: String,
    pub gate_open: bool,
    pub block_kind: Option<String>,
    pub outcome_code: Option<String>,
    pub executed_attempt_count: i32,
    pub retry_allowance: i16,
    pub claim_owner_id: Option<Uuid>,
    pub claim_epoch: i64,
    pub claim_token: Option<ClaimTokenEvidence>,
    pub completed_at: Option<chrono::DateTime<Utc>>,
    pub claim_until: Option<chrono::DateTime<Utc>>,
    pub claimed_control_epoch: Option<i64>,
    pub claimed_instance_epoch: Option<i64>,
    pub claimed_activation_id: Option<Uuid>,
    pub created_activation_id: Uuid,
    pub current_policy_activation_id: Option<Uuid>,
    pub executed_activation_id: Option<Uuid>,
    pub receipt_correlation: Option<Uuid>,
    pub detail_expires_at: Option<chrono::DateTime<Utc>>,
    pub generation_created_at: chrono::DateTime<Utc>,
    pub generation_updated_at: chrono::DateTime<Utc>,
    pub current_created_at: chrono::DateTime<Utc>,
    pub current_updated_at: chrono::DateTime<Utc>,
    pub protocol_version: i32,
    pub control_state: String,
    pub control_epoch: i64,
    pub bound_instance_epoch: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TimerAttemptEvidence {
    pub attempt_number: i32,
    pub claim_owner_id: Uuid,
    pub claim_epoch: i64,
    pub control_epoch: i64,
    pub instance_epoch: i64,
    pub activation_id: Uuid,
    pub definition_revision: String,
    pub action_revision: String,
    pub system_grant_revision: String,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: Option<chrono::DateTime<Utc>>,
    pub block_kind: Option<String>,
    pub outcome_code: Option<String>,
    pub technical_code: Option<String>,
    pub receipt_correlation: Option<Uuid>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TimerGenerationEvidence {
    pub state: String,
    pub outcome_code: Option<String>,
    pub executed_attempt_count: i32,
    pub is_current: bool,
}

impl NativeTimerHarness {
    pub async fn start() -> Self {
        Self::start_with_variant(NativeFixtureVariant::Maintained).await
    }

    /// Start the maintained Record shape without any timer, timer grant, or
    /// Action. A governed successor can then prove that adding a timer does
    /// not retrospectively arm existing Records.
    #[cfg(feature = "tooling")]
    pub async fn start_timer_free() -> Self {
        Self::start_with_variant(NativeFixtureVariant::TimerFree).await
    }

    /// Start the maintained future-activation project with a private,
    /// bounded Batch contract used only by native lock-order acceptance.
    /// The published example and its ordinary authority remain unchanged.
    pub async fn start_with_bulk_writes_enabled() -> Self {
        Self::start_with_variant(NativeFixtureVariant::BulkWrites).await
    }

    /// Start a private derivative of the maintained example whose Action has
    /// one real Boolean commit guard. The public example remains unchanged.
    pub async fn start_with_business_refusal_enabled() -> Self {
        Self::start_with_variant(NativeFixtureVariant::DeclaredRefusal).await
    }

    /// Start a private derivative with two independently configured Record
    /// types. It is used only to prove bounded worker-lane fairness across
    /// real native replicas; the published example remains unchanged.
    pub async fn start_with_fairness_types() -> Self {
        Self::start_with_variant(NativeFixtureVariant::Fairness).await
    }

    async fn start_with_variant(variant: NativeFixtureVariant) -> Self {
        let database = TestDatabase::create(12).await;
        let scratch_parent = std::env::temp_dir()
            .canonicalize()
            .expect("native timer scratch parent canonicalizes");
        let scratch = tempfile::Builder::new()
            .prefix("breg-record-timer-native-")
            .tempdir_in(scratch_parent)
            .expect("native timer scratch directory creates");
        set_private_directory_permissions(scratch.path());

        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/future-activation")
            .canonicalize()
            .expect("public future-activation example root canonicalizes");
        let mut project_bytes = fs::read(fixture_root.join("registry.yaml"))
            .expect("record-timer native project reads");
        match variant {
            NativeFixtureVariant::Maintained => {}
            #[cfg(feature = "tooling")]
            NativeFixtureVariant::TimerFree => {
                project_bytes = timer_free_project_bytes(&project_bytes);
            }
            NativeFixtureVariant::BulkWrites => {
                project_bytes = bulk_timer_project_bytes(&project_bytes);
            }
            NativeFixtureVariant::DeclaredRefusal => {
                project_bytes = business_refusal_project_bytes(&project_bytes);
            }
            NativeFixtureVariant::Fairness => {
                project_bytes = fairness_project_bytes(&project_bytes);
            }
        }
        let journey_bytes = fs::read(fixture_root.join(FIXTURE_JOURNEYS_PATH))
            .expect("record-timer native journeys read");
        let project = parse_project_yaml(&project_bytes)
            .expect("record-timer native project follows the strict contract");
        let registry = Arc::new(
            compile_project(&project, &[], CompileProfile::Production)
                .expect("record-timer native project compiles for Production"),
        );

        let provisional_root = publish_package(
            scratch.path(),
            "provisional",
            &project_bytes,
            &journey_bytes,
            fingerprint(0x31),
        );
        let provisional = load_package(&provisional_root, &package_context())
            .expect("provisional timer package verifies");
        assert_eq!(provisional.registry(), registry.as_ref());

        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("record-timer native schema installs");
        let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
        let schema_fingerprint =
            managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
                .await
                .expect("record-timer managed schema fingerprint computes");
        drop(provisional);

        let package_root = publish_package(
            scratch.path(),
            "active",
            &project_bytes,
            &journey_bytes,
            schema_fingerprint.clone(),
        );
        let package =
            load_package(&package_root, &package_context()).expect("active timer package verifies");
        let package_id = package.manifest().package_id.clone();
        let package_digest = package.package_digest().to_owned();
        initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            package.registry(),
            RegistryStateTestIdentity {
                package_id: &package.manifest().package_id,
                database_id: DATABASE_ID,
                label: package.package_digest(),
            },
        )
        .await
        .expect("record-timer package activates in the isolated database");
        drop(package);
        drop(migration);
        migration_task.abort();

        let token = signed_token();
        Self {
            database: Some(database),
            registry,
            scratch: Some(scratch),
            package_root,
            refused_package_root: provisional_root,
            package_id,
            package_digest,
            schema_fingerprint,
            token,
            replicas: Vec::new(),
            checkpoint: None,
            outcome_checkpoint: None,
            lease_milliseconds: None,
            mutation_checkpoint_for_new_replicas: false,
            metrics_for_new_replicas: false,
            business_refusal_guard: variant == NativeFixtureVariant::DeclaredRefusal,
        }
    }

    pub fn enable_before_claim_barrier(&mut self) -> Result<(), String> {
        self.enable_checkpoint(NativeTimerCheckpoint::BeforeClaim, None)
    }

    pub fn disable_before_claim_barrier(&mut self) {
        self.checkpoint = None;
        self.lease_milliseconds = None;
    }

    pub fn enable_checkpoint(
        &mut self,
        checkpoint: NativeTimerCheckpoint,
        lease_milliseconds: Option<u64>,
    ) -> Result<(), String> {
        if !self.replicas.is_empty() {
            return Err("native timer checkpoint must be enabled before replicas start".to_owned());
        }
        if self.outcome_checkpoint.is_some() {
            return Err("native timer tests select only one checkpoint pair".to_owned());
        }
        if lease_milliseconds == Some(0) {
            return Err("native timer test lease must be positive".to_owned());
        }
        self.checkpoint = Some(checkpoint);
        self.lease_milliseconds = lease_milliseconds;
        Ok(())
    }

    pub fn enable_outcome_checkpoint(
        &mut self,
        kind: NativeOutcomeSettlementKind,
        lease_milliseconds: u64,
    ) -> Result<(), String> {
        if !self.replicas.is_empty() {
            return Err(
                "native outcome checkpoint must be enabled before replicas start".to_owned(),
            );
        }
        if self.checkpoint.is_some() || self.outcome_checkpoint.is_some() {
            return Err("native timer tests select only one checkpoint pair".to_owned());
        }
        if lease_milliseconds == 0 {
            return Err("native timer test lease must be positive".to_owned());
        }
        self.outcome_checkpoint = Some(kind);
        self.lease_milliseconds = Some(lease_milliseconds);
        Ok(())
    }

    pub fn disable_outcome_checkpoint(&mut self) {
        self.outcome_checkpoint = None;
        self.lease_milliseconds = None;
    }

    /// Configure only subsequently launched replicas with the ordinary
    /// mutation pre-commit checkpoint. Tests disable it before starting the
    /// timer-worker replica so a timer Action cannot consume the writer marker.
    pub fn enable_mutation_checkpoint_for_new_replicas(&mut self) {
        self.mutation_checkpoint_for_new_replicas = true;
    }

    pub fn disable_mutation_checkpoint_for_new_replicas(&mut self) {
        self.mutation_checkpoint_for_new_replicas = false;
    }

    /// Configure a distinct operator-private metrics listener for every
    /// subsequently launched native replica.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub fn enable_metrics_for_new_replicas(&mut self) -> Result<(), String> {
        if !self.replicas.is_empty() {
            return Err("native timer metrics must be enabled before replicas start".to_owned());
        }
        self.metrics_for_new_replicas = true;
        Ok(())
    }

    /// Start `count` independent operating-system processes against the same
    /// package and PostgreSQL database. Calling this repeatedly adds replicas,
    /// with at most three concurrently live processes.
    pub async fn start_replicas(&mut self, count: usize) -> Result<(), String> {
        let mut active_replicas = std::collections::BTreeSet::new();
        for replica in &mut self.replicas {
            if replica.stopped {
                continue;
            }
            match replica
                .child
                .try_wait()
                .map_err(|_| "native timer replica status could not be read".to_owned())?
            {
                Some(_) => replica.stopped = true,
                None => {
                    active_replicas.insert(replica.command.replica_id.clone());
                }
            }
        }
        if count == 0 || active_replicas.len().saturating_add(count) > 3 {
            return Err("native timer tests start between one and three replicas".to_owned());
        }
        for _ in 0..count {
            let replica_id = (1..=3)
                .map(|ordinal| format!("replica-{ordinal}"))
                .find(|candidate| !active_replicas.contains(candidate))
                .ok_or_else(|| "native timer replica identity budget is exhausted".to_owned())?;
            active_replicas.insert(replica_id.clone());
            let launch_id = format!("{replica_id}-launch-{}", self.replicas.len() + 1);
            let address = available_loopback_address()?;
            let metrics_address = self
                .metrics_for_new_replicas
                .then(available_loopback_address)
                .transpose()?;
            let http_request_milliseconds = if self.mutation_checkpoint_for_new_replicas {
                MUTATION_CHECKPOINT_HTTP_REQUEST_MILLISECONDS
            } else {
                HTTP_REQUEST_MILLISECONDS
            };
            let config_path = self.write_runtime_config(
                INSTANCE_ID,
                &launch_id,
                address,
                metrics_address,
                http_request_milliseconds,
            )?;
            let audit_path = config_path
                .parent()
                .ok_or_else(|| "native timer runtime configuration has no parent".to_owned())?
                .join("audit.bregctl.jsonl");
            let log_path = self.scratch_path().join(format!("{launch_id}.jsonl"));
            let log = private_log(&log_path)?;
            let stderr = log
                .try_clone()
                .map_err(|_| "native timer process log could not be cloned".to_owned())?;
            let executable = PathBuf::from(env!("CARGO_BIN_EXE_breg"));
            let arguments = vec![
                "--runtime-config".to_owned(),
                config_path.display().to_string(),
            ];
            let checkpoint_label =
                self.checkpoint
                    .map(NativeTimerCheckpoint::label)
                    .or_else(|| {
                        self.outcome_checkpoint
                            .map(NativeOutcomeSettlementKind::label)
                    });
            let checkpoint_barrier = checkpoint_label.map(|label| NativeBarrierFiles {
                observed: self
                    .scratch_path()
                    .join(format!("{launch_id}.{label}.observed.json")),
                release: self
                    .scratch_path()
                    .join(format!("{launch_id}.{label}.release")),
            });
            let mutation_checkpoint_barrier =
                self.mutation_checkpoint_for_new_replicas
                    .then(|| NativeOperationBarrierFiles {
                        observed: self
                            .scratch_path()
                            .join(format!("{launch_id}.mutation-before-commit.observed.json")),
                        release: self
                            .scratch_path()
                            .join(format!("{launch_id}.mutation-before-commit.release")),
                    });
            let mut command = Command::new(&executable);
            command
                .arg("--runtime-config")
                .arg(&config_path)
                .env("BREG_LOG", "info")
                .env("TOKIO_WORKER_THREADS", "2")
                .stdin(Stdio::null())
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(stderr));
            if let (Some(checkpoint), Some(barrier)) = (self.checkpoint, &checkpoint_barrier) {
                let (observed, release) = checkpoint.environment();
                command
                    .env(observed, &barrier.observed)
                    .env(release, &barrier.release);
            }
            if let (Some(kind), Some(barrier)) = (self.outcome_checkpoint, &checkpoint_barrier) {
                command
                    .env(
                        "BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_OBSERVED_PATH",
                        &barrier.observed,
                    )
                    .env(
                        "BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_RELEASE_PATH",
                        &barrier.release,
                    )
                    .env(
                        "BREG_TIMER_TEST_BEFORE_OUTCOME_SETTLEMENT_KIND",
                        kind.selector(),
                    );
            }
            if let Some(lease_milliseconds) = self.lease_milliseconds {
                command.env(
                    "BREG_TIMER_TEST_LEASE_MILLISECONDS",
                    lease_milliseconds.to_string(),
                );
            }
            if let Some(barrier) = &mutation_checkpoint_barrier {
                command
                    .env(
                        "BREG_MUTATION_TEST_BEFORE_COMMIT_OBSERVED_PATH",
                        &barrier.observed,
                    )
                    .env(
                        "BREG_MUTATION_TEST_BEFORE_COMMIT_RELEASE_PATH",
                        &barrier.release,
                    );
            }
            let child = command
                .spawn()
                .map_err(|_| "native breg timer replica did not spawn".to_owned())?;
            let base_url = Url::parse(&format!("http://{address}"))
                .map_err(|_| "native timer loopback URL is invalid".to_owned())?;
            let metrics_base_url = metrics_address
                .map(|address| Url::parse(&format!("http://{address}")))
                .transpose()
                .map_err(|_| "native timer metrics loopback URL is invalid".to_owned())?;
            self.replicas.push(NativeReplica {
                base_url,
                metrics_base_url,
                config_path,
                audit_path,
                command: NativeProcessIdentity {
                    pid: child.id(),
                    instance_id: INSTANCE_ID.to_owned(),
                    replica_id,
                    launch_id,
                    executable,
                    arguments,
                },
                child,
                log_path,
                checkpoint_barrier,
                mutation_checkpoint_barrier,
                expected_non_info_codes: std::collections::BTreeMap::new(),
                stopped: false,
            });
            self.wait_ready(self.replicas.len() - 1).await?;
        }
        Ok(())
    }

    /// Return non-secret process and package identity for acceptance output.
    /// Runtime configuration contents and database credentials are excluded.
    pub fn run_identity(&self) -> NativeRunIdentity {
        NativeRunIdentity {
            package_id: self.package_id.clone(),
            package_digest: self.package_digest.clone(),
            processes: self
                .replicas
                .iter()
                .map(|replica| replica.command.clone())
                .collect(),
        }
    }

    /// Build, verify, plan, and apply a private sealed successor of the
    /// maintained future-activation example. The only authored policy change
    /// changes the timer predicate from `paused=false` to `paused=true`, so an
    /// already cached false gate becomes eligible without changing the Record
    /// controls.
    #[cfg(feature = "tooling")]
    pub async fn activate_reviewed_predicate_successor(
        &mut self,
    ) -> Result<NativeSuccessorActivationEvidence, String> {
        self.activate_reviewed_successor(reviewed_predicate_successor_project_bytes())
            .await
    }

    /// Apply a reviewed successor that removes the maintained Record timer.
    /// The predecessor process remains live so native tests can prove its
    /// package fence before the successor performs metadata-only cleanup.
    #[cfg(feature = "tooling")]
    pub async fn activate_reviewed_timer_removal_successor(
        &mut self,
    ) -> Result<NativeSuccessorActivationEvidence, String> {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/future-activation");
        let project_bytes = fs::read(fixture_root.join("registry.yaml")).map_err(|_| {
            "maintained timer-removal successor project could not be read".to_owned()
        })?;
        self.activate_reviewed_successor(timer_free_project_bytes(&project_bytes))
            .await
    }

    /// Apply the unchanged maintained timer package as a governed successor
    /// of the timer-free derivative used by the historical-record proof.
    #[cfg(feature = "tooling")]
    pub async fn activate_maintained_timer_successor(
        &mut self,
    ) -> Result<NativeSuccessorActivationEvidence, String> {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/future-activation");
        let project_bytes = fs::read(fixture_root.join("registry.yaml"))
            .map_err(|_| "maintained timer successor project could not be read".to_owned())?;
        self.activate_reviewed_successor(project_bytes).await
    }

    #[cfg(feature = "tooling")]
    async fn activate_reviewed_successor(
        &mut self,
        project_bytes: Vec<u8>,
    ) -> Result<NativeSuccessorActivationEvidence, String> {
        let predecessor_digest = self.package_digest.clone();
        let predecessor_registry = self.registry.as_ref().clone();
        let predecessor = read_recorded_registry_state(
            &self.database().migration_config,
            &self.package_id,
            &self.database().migration_role,
            ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(5))
                .map_err(|_| "native timer predecessor read timeouts were invalid".to_owned())?,
        )
        .await
        .map_err(|error| format!("native timer predecessor state read failed: {error}"))?
        .ok_or_else(|| "native timer predecessor state was absent".to_owned())?;
        if !predecessor.ready
            || !predecessor.activation_applied
            || predecessor.identity.package_digest != predecessor_digest
        {
            return Err(format!(
                "native timer predecessor was not the ready applied package: {predecessor:?}"
            ));
        }
        let project = parse_project_yaml(&project_bytes)
            .map_err(|_| "native timer successor project did not parse".to_owned())?;
        let successor_registry = compile_project(&project, &[], CompileProfile::Production)
            .map_err(|_| "native timer successor project did not compile".to_owned())?;
        let successor_schema_fingerprint = measure_compiled_schema(&successor_registry).await?;
        let change_set = compiled_registry_change_set(
            &predecessor_registry,
            &successor_registry,
            &predecessor_digest,
        );
        let review = metadata_only_review_source(
            &change_set.changes,
            &predecessor_digest,
            &self.schema_fingerprint,
            &successor_schema_fingerprint,
        )?;
        let journey_bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/breg/examples/future-activation")
                .join(FIXTURE_JOURNEYS_PATH),
        )
        .map_err(|_| "native timer successor journeys could not be read".to_owned())?;
        let successor_root = publish_successor_package(
            self.scratch_path(),
            &project_bytes,
            &journey_bytes,
            successor_schema_fingerprint,
            self.schema_fingerprint.clone(),
            &predecessor_digest,
            predecessor_registry,
            review,
        )?;
        let successor = load_package(&successor_root, &package_context())
            .map_err(|error| format!("native timer sealed successor did not verify: {error}"))?;
        let roles = ApplyRoles::new(
            &self.database().migration_role,
            &self.database().runtime_role,
        );
        let timeouts = ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(5))
            .map_err(|_| "native timer successor timeouts were invalid".to_owned())?;
        let planned = plan_verified_package(ApplyVerifiedPackageRequest::plan(
            &self.database().migration_config,
            &successor,
            ActivationDeployment::new(ENVIRONMENT, INSTANCE_ID, DATABASE_ID),
            ApplyPrecondition::Successor {
                current: &predecessor.identity,
            },
            roles,
            timeouts,
        ))
        .await
        .map_err(|error| format!("native timer reviewed successor plan failed: {error}"))?;
        if planned.activation != PlannedActivation::Successor {
            return Err("native timer reviewed package did not plan as a successor".to_owned());
        }
        let active = apply_verified_package(ApplyVerifiedPackageRequest::new(
            &self.database().migration_config,
            &successor,
            ActivationDeployment::new(ENVIRONMENT, INSTANCE_ID, DATABASE_ID),
            ApplyPrecondition::Successor {
                current: &predecessor.identity,
            },
            roles,
            timeouts,
            self.database().activation_audit(),
        ))
        .await
        .map_err(|error| format!("native timer reviewed successor apply failed: {error}"))?;

        let evidence = NativeSuccessorActivationEvidence {
            predecessor_package_digest: predecessor_digest,
            predecessor_activation_id: predecessor.identity.activation_id,
            successor_package_digest: active.package_digest.clone(),
            successor_activation_id: active.activation_id.clone(),
        };
        self.registry = Arc::new(successor.registry().clone());
        self.package_root = successor_root;
        self.package_id = successor.manifest().package_id.clone();
        self.package_digest = successor.package_digest().to_owned();
        self.schema_fingerprint = successor.manifest().schema_fingerprint.clone();
        Ok(evidence)
    }

    /// Wait until a still-live predecessor process refuses readiness after a
    /// governed successor changes the active package identity.
    #[cfg(feature = "tooling")]
    pub async fn wait_replica_unready(
        &mut self,
        replica: usize,
        timeout: Duration,
    ) -> Result<NativeProcessIdentity, String> {
        let process = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .command
            .clone();
        let client = BaseRegistryClient::new(BaseRegistryClientConfig::new(
            self.replicas[replica].base_url.clone(),
        ))
        .map_err(|error| format!("native timer readiness client failed: {error}"))?;
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(status) = self.replicas[replica]
                    .child
                    .try_wait()
                    .map_err(|_| "native timer predecessor status could not be read".to_owned())?
                {
                    return Err(format!(
                        "native timer predecessor exited instead of refusing readiness: {status}"
                    ));
                }
                if client.ready().await.is_err() {
                    return Ok(process.clone());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "native timer predecessor remained ready after successor apply".to_owned())?
    }

    /// Return the owner-only absolute fixture runtime configuration used by
    /// one native replica. It contains secret references, never secret values.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub fn operator_runtime_config_path(&self, replica: usize) -> Result<PathBuf, String> {
        self.replicas
            .get(replica)
            .map(|replica| replica.config_path.clone())
            .ok_or_else(|| "native timer replica does not exist".to_owned())
    }

    /// Write a separate owner-only operator configuration with a unique
    /// PostgreSQL application name and companion audit destination.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub fn write_operator_runtime_config(
        &self,
        label: &str,
    ) -> Result<NativeOperatorConfig, String> {
        if label.is_empty()
            || label.len() > 40
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("native timer operator label is invalid".to_owned());
        }
        let launch_id = format!("operator-{label}");
        let path = self.write_runtime_config(
            INSTANCE_ID,
            &launch_id,
            available_loopback_address()?,
            None,
            HTTP_REQUEST_MILLISECONDS,
        )?;
        let audit_path = path
            .parent()
            .ok_or_else(|| "native timer operator configuration has no parent".to_owned())?
            .join("audit.bregctl.jsonl");
        Ok(NativeOperatorConfig {
            path,
            application_name: format!("breg-timer-{launch_id}"),
            audit_path,
        })
    }

    /// Run the exact Cargo-discovered bregctl binary without nesting Cargo in
    /// the integration test. Output is private, bounded, and reaped on timeout.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn run_bregctl(
        &self,
        label: &str,
        arguments: &[String],
    ) -> Result<NativeBregctlOutput, String> {
        if label.is_empty()
            || label.len() > 40
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("native bregctl invocation label is invalid".to_owned());
        }
        let executable = std::env::var_os("BREG_TEST_BREGCTL_BINARY")
            .map(PathBuf::from)
            .ok_or_else(|| "BREG_TEST_BREGCTL_BINARY is required".to_owned())?;
        if !executable.is_absolute() {
            return Err("BREG_TEST_BREGCTL_BINARY must be absolute".to_owned());
        }
        let executable = fs::canonicalize(&executable)
            .map_err(|_| "BREG_TEST_BREGCTL_BINARY could not be resolved".to_owned())?;
        let metadata = fs::metadata(&executable)
            .map_err(|_| "BREG_TEST_BREGCTL_BINARY metadata was unavailable".to_owned())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err("BREG_TEST_BREGCTL_BINARY is not an executable file".to_owned());
        }
        let scratch = self
            .scratch
            .as_ref()
            .ok_or_else(|| "native timer scratch is unavailable".to_owned())?;
        let stdout_path = scratch.path().join(format!("bregctl-{label}.stdout"));
        let stderr_path = scratch.path().join(format!("bregctl-{label}.stderr"));
        let stdout = private_log(&stdout_path)?;
        let stderr = private_log(&stderr_path)?;
        let mut child = Command::new(&executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| "bregctl did not start".to_owned())?;
        let status = match tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|_| "bregctl status was unavailable".to_owned())?
                {
                    return Ok::<_, String>(status);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        {
            Ok(status) => status?,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("bregctl exceeded the acceptance timeout".to_owned());
            }
        };
        let stdout = read_bounded_text(&stdout_path, "bregctl stdout")?;
        let stderr = read_bounded_text(&stderr_path, "bregctl stderr")?;
        Ok(NativeBregctlOutput {
            status,
            stdout,
            stderr,
            executable,
        })
    }

    /// Write an owner-only fixture configuration that resolves a signed but
    /// inactive package. This exercises active-package admission without
    /// weakening package verification or changing the live registry.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub fn write_package_refused_operator_config(&self, replica: usize) -> Result<PathBuf, String> {
        let source = self.operator_runtime_config_path(replica)?;
        let config = fs::read_to_string(&source)
            .map_err(|_| "native timer runtime configuration could not be read".to_owned())?;
        let active = format!("  root: {}\n", self.package_root.display());
        if config.matches(&active).count() != 1 {
            return Err("native timer runtime package root was not unique".to_owned());
        }
        let refused = format!("  root: {}\n", self.refused_package_root.display());
        let config = config.replacen(&active, &refused, 1);
        let target = source.with_file_name("runtime-package-refused.yaml");
        write_private(&target, config.as_bytes())?;
        Ok(target)
    }

    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub fn operator_audit_entries(&self, replica: usize) -> Result<Vec<serde_json::Value>, String> {
        let path = &self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .audit_path;
        read_bounded_audit_entries(path)
    }

    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub fn separate_operator_audit_entries(
        &self,
        config: &NativeOperatorConfig,
    ) -> Result<Vec<serde_json::Value>, String> {
        read_bounded_audit_entries(&config.audit_path)
    }

    /// Scrape one configured operator-private metrics listener with a bounded
    /// body. Runtime configuration and database credentials never enter the
    /// returned error.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn scrape_metrics(&self, replica: usize) -> Result<String, String> {
        let base = self
            .replicas
            .get(replica)
            .and_then(|replica| replica.metrics_base_url.as_ref())
            .ok_or_else(|| "native timer replica has no metrics listener".to_owned())?;
        let response = reqwest::Client::new()
            .get(
                base.join("metrics")
                    .map_err(|_| "native timer metrics URL was invalid".to_owned())?,
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| "native timer metrics scrape failed".to_owned())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!(
                "native timer metrics scrape returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| "native timer metrics body could not be read".to_owned())?;
        if bytes.len() > MAX_LOG_BYTES as usize {
            return Err("native timer metrics body exceeded its acceptance bound".to_owned());
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| "native timer metrics body was not UTF-8".to_owned())
    }

    pub async fn wait_for_timer_worker_age_at_least(
        &self,
        minimum: Duration,
        timeout: Duration,
    ) -> Result<Vec<f64>, String> {
        tokio::time::timeout(timeout, async {
            loop {
                let mut ages = Vec::with_capacity(self.replicas.len());
                for replica in 0..self.replicas.len() {
                    ages.push(self.timer_worker_last_success_age(replica).await?);
                }
                if ages.iter().all(|age| *age >= minimum.as_secs_f64()) {
                    return Ok(ages);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "timer workers did not remain held through the progress bound".to_owned())?
    }

    pub async fn wait_for_timer_worker_progress_reset(
        &self,
        held_ages: &[f64],
        timeout: Duration,
    ) -> Result<(), String> {
        if held_ages.len() != self.replicas.len() {
            return Err("timer worker progress baseline did not match the replica set".to_owned());
        }
        tokio::time::timeout(timeout, async {
            loop {
                let mut advanced = true;
                for (replica, held_age) in held_ages.iter().enumerate() {
                    let age = self.timer_worker_last_success_age(replica).await?;
                    if age >= 0.5 || age >= *held_age {
                        advanced = false;
                        break;
                    }
                }
                if advanced {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| {
            "timer workers did not report a new successful iteration after release".to_owned()
        })?
    }

    /// Require each named native replica to report at least one successful
    /// Record timer worker iteration. The sample is absent until the worker
    /// succeeds, so this distinguishes a live replacement worker from a
    /// process that started but stalled before its first scan.
    pub async fn wait_for_timer_worker_first_success(
        &self,
        replicas: &[usize],
        timeout: Duration,
    ) -> Result<(), String> {
        if replicas.is_empty() {
            return Err("timer worker progress requires at least one replica".to_owned());
        }
        tokio::time::timeout(timeout, async {
            loop {
                let mut every_worker_succeeded = true;
                for replica in replicas {
                    let body = self.scrape_metrics(*replica).await?;
                    let prefix = "breg_worker_last_success_age_seconds{worker=\"record-timer\"} ";
                    let samples = body
                        .lines()
                        .filter_map(|line| line.strip_prefix(prefix))
                        .collect::<Vec<_>>();
                    match samples.as_slice() {
                        [] => every_worker_succeeded = false,
                        [sample] => {
                            let age = sample.parse::<f64>().map_err(|_| {
                                "timer worker progress metric was not numeric".to_owned()
                            })?;
                            if !age.is_finite() || age < 0.0 {
                                return Err("timer worker progress metric was outside its domain"
                                    .to_owned());
                            }
                        }
                        _ => return Err("timer worker progress metric was not singular".to_owned()),
                    }
                }
                if every_worker_succeeded {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "timer workers did not report their first successful iteration".to_owned())?
    }

    async fn timer_worker_last_success_age(&self, replica: usize) -> Result<f64, String> {
        let body = self.scrape_metrics(replica).await?;
        let prefix = "breg_worker_last_success_age_seconds{worker=\"record-timer\"} ";
        let samples = body
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .collect::<Vec<_>>();
        if samples.len() != 1 {
            return Err("timer worker progress metric was not singular".to_owned());
        }
        let age = samples[0]
            .parse::<f64>()
            .map_err(|_| "timer worker progress metric was not numeric".to_owned())?;
        if !age.is_finite() || age < 0.0 {
            return Err("timer worker progress metric was outside its finite range".to_owned());
        }
        Ok(age)
    }

    /// Read one value-free operational probe status from the Registry
    /// listener. The response body is deliberately not reflected in errors.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn probe_status(&self, replica: usize, path: &str) -> Result<u16, String> {
        if !matches!(path, "/health" | "/ready") {
            return Err("native timer probe path was not closed".to_owned());
        }
        let base = &self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .base_url;
        reqwest::Client::new()
            .get(
                base.join(path.trim_start_matches('/'))
                    .map_err(|_| "native timer probe URL was invalid".to_owned())?,
            )
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map(|response| response.status().as_u16())
            .map_err(|_| "native timer probe request failed".to_owned())
    }

    /// Revoke only the attempts-table read used by timer metrics, scrape once,
    /// then restore the grant before returning even when the scrape fails.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn scrape_with_timer_attempt_read_revoked(
        &self,
        replica: usize,
    ) -> Result<String, String> {
        let role = self.database().runtime_role.as_str();
        self.database()
            .admin
            .batch_execute(&format!(
                "REVOKE SELECT ON registry_internal.registry_record_timer_attempts FROM \"{role}\""
            ))
            .await
            .map_err(|_| "timer metrics fixture could not revoke its scoped read".to_owned())?;
        let scrape = self.scrape_metrics(replica).await;
        let restored = self
            .database()
            .admin
            .batch_execute(&format!(
                "GRANT SELECT ON registry_internal.registry_record_timer_attempts TO \"{role}\""
            ))
            .await
            .map_err(|_| "timer metrics fixture could not restore its scoped read".to_owned());
        match (scrape, restored) {
            (_, Err(error)) => Err(error),
            (result, Ok(())) => result,
        }
    }

    /// Wait for one exact operator session to be blocked by one exact native
    /// replica. PostgreSQL's blocker relation is authoritative; elapsed time
    /// is not used as contention evidence.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn wait_for_database_blocking_relation(
        &self,
        blocked_application_name: &str,
        blocking_replica: usize,
        timeout: Duration,
    ) -> Result<DatabaseBlockingEvidence, String> {
        let blocking_launch_id = self
            .replicas
            .get(blocking_replica)
            .ok_or_else(|| "native timer blocking replica does not exist".to_owned())?
            .command
            .launch_id
            .clone();
        let blocking_application_name = format!("breg-timer-{blocking_launch_id}");
        tokio::time::timeout(timeout, async {
            loop {
                let rows = self
                    .database()
                    .admin
                    .query(
                        "SELECT blocked.pid,blocker.pid
                           FROM pg_catalog.pg_stat_activity AS blocked
                           JOIN LATERAL unnest(pg_catalog.pg_blocking_pids(blocked.pid))
                                AS blocker_pid(pid) ON true
                           JOIN pg_catalog.pg_stat_activity AS blocker
                             ON blocker.pid=blocker_pid.pid
                          WHERE blocked.datname=current_database()
                            AND blocked.application_name=$1
                            AND blocked.wait_event_type='Lock'
                            AND blocker.application_name=$2",
                        &[&blocked_application_name, &blocking_application_name],
                    )
                    .await
                    .map_err(|_| "native timer blocker-relation query failed".to_owned())?;
                if rows.len() == 1 {
                    return Ok(DatabaseBlockingEvidence {
                        blocked_pid: rows[0].get(0),
                        blocker_pid: rows[0].get(1),
                    });
                }
                if rows.len() > 1 {
                    return Err("native timer blocker relation was not unique".to_owned());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "operator did not enter the exact database blocker relation".to_owned())?
    }

    pub async fn wait_for_replica_blocked_by(
        &self,
        blocked_replica: usize,
        blocking_replica: usize,
        timeout: Duration,
    ) -> Result<DatabaseBlockingEvidence, String> {
        let blocked_launch_id = self
            .replicas
            .get(blocked_replica)
            .ok_or_else(|| "native timer blocked replica does not exist".to_owned())?
            .command
            .launch_id
            .clone();
        self.wait_for_database_blocking_relation(
            &format!("breg-timer-{blocked_launch_id}"),
            blocking_replica,
            timeout,
        )
        .await
    }

    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn assert_runtime_timer_control_column_acl(&self) -> Result<(), String> {
        let pool = self
            .database()
            .runtime_config
            .build_pool()
            .map_err(|_| "native operator runtime pool could not be built".to_owned())?;
        let client = pool
            .get_for_test()
            .await
            .map_err(|_| "native operator runtime connection was unavailable".to_owned())?;
        for column in ["protocol_version", "bound_instance_epoch"] {
            let statement = format!(
                "UPDATE registry_internal.registry_record_timer_control
                    SET {column}={column}
                  WHERE singleton"
            );
            if client.execute(&statement, &[]).await.is_ok() {
                return Err(format!(
                    "runtime role unexpectedly updated migration-owned timer control column {column}"
                ));
            }
        }
        Ok(())
    }

    pub async fn wait_before_claim_observed(
        &mut self,
        occurrence_id: Uuid,
        timeout: Duration,
    ) -> Result<Vec<NativeProcessIdentity>, String> {
        tokio::time::timeout(timeout, async {
            loop {
                let mut observed = Vec::new();
                for replica in &mut self.replicas {
                    let barrier = replica.checkpoint_barrier.as_ref().ok_or_else(|| {
                        "native replica has no before-claim barrier".to_owned()
                    })?;
                    if barrier.observed.exists() {
                        validate_checkpoint_marker(replica, barrier, occurrence_id)?;
                        observed.push(replica.command.clone());
                    } else if let Some(status) = replica
                        .child
                        .try_wait()
                        .map_err(|_| "native timer replica status could not be read".to_owned())?
                    {
                        return Err(format!(
                            "native timer replica exited before claim observation with {status}; inspect {}",
                            replica.log_path.display()
                        ));
                    }
                }
                if observed.len() == self.replicas.len() {
                    return Ok(observed);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "native replicas did not all observe eligibility before the bound".to_owned())?
    }

    pub async fn wait_before_claim_observed_any(
        &mut self,
        occurrence_ids: &std::collections::BTreeSet<Uuid>,
        timeout: Duration,
    ) -> Result<Vec<(Uuid, NativeProcessIdentity)>, String> {
        self.wait_checkpoint_observed_any(occurrence_ids, timeout)
            .await
    }

    pub async fn wait_checkpoint_observed_any(
        &mut self,
        occurrence_ids: &std::collections::BTreeSet<Uuid>,
        timeout: Duration,
    ) -> Result<Vec<(Uuid, NativeProcessIdentity)>, String> {
        if occurrence_ids.is_empty() {
            return Err("native timer observation set was empty".to_owned());
        }
        tokio::time::timeout(timeout, async {
            loop {
                let mut observed = Vec::new();
                for replica in &mut self.replicas {
                    let barrier = replica.checkpoint_barrier.as_ref().ok_or_else(|| {
                        "native replica has no before-claim barrier".to_owned()
                    })?;
                    if barrier.observed.exists() {
                        let marker = read_checkpoint_marker(replica, barrier)?;
                        if !occurrence_ids.contains(&marker.occurrence_id) {
                            return Err(format!(
                                "native timer observed an occurrence outside the exact race set: {marker:?}"
                            ));
                        }
                        observed.push((marker.occurrence_id, replica.command.clone()));
                    } else if let Some(status) = replica
                        .child
                        .try_wait()
                        .map_err(|_| "native timer replica status could not be read".to_owned())?
                    {
                        return Err(format!(
                            "native timer replica exited before claim observation with {status}; inspect {}",
                            replica.log_path.display()
                        ));
                    }
                }
                if observed.len() == self.replicas.len() {
                    return Ok(observed);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "native replicas did not observe the exact race set before the bound".to_owned())?
    }

    pub fn release_before_claim_barriers(&self) -> Result<(), String> {
        self.release_checkpoint_barriers()
    }

    pub fn release_checkpoint_barriers(&self) -> Result<(), String> {
        for replica in &self.replicas {
            let barrier = replica
                .checkpoint_barrier
                .as_ref()
                .ok_or_else(|| "native replica has no before-claim barrier".to_owned())?;
            write_private(&barrier.release, b"release")?;
        }
        Ok(())
    }

    pub async fn wait_for_one_checkpoint(
        &mut self,
        occurrence_id: Uuid,
        timeout: Duration,
    ) -> Result<(usize, NativeProcessIdentity), String> {
        tokio::time::timeout(timeout, async {
            loop {
                for (index, replica) in self.replicas.iter_mut().enumerate() {
                    let barrier = replica
                        .checkpoint_barrier
                        .as_ref()
                        .ok_or_else(|| "native replica has no timer checkpoint".to_owned())?;
                    if barrier.observed.exists() {
                        validate_checkpoint_marker(replica, barrier, occurrence_id)?;
                        return Ok((index, replica.command.clone()));
                    }
                    if let Some(status) = replica
                        .child
                        .try_wait()
                        .map_err(|_| "native timer replica status could not be read".to_owned())?
                    {
                        return Err(format!(
                            "native timer replica exited before checkpoint with {status}; inspect {}",
                            replica.log_path.display()
                        ));
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "no native replica reached the timer checkpoint before the bound".to_owned())?
    }

    pub async fn wait_for_checkpoint_except(
        &mut self,
        occurrence_id: Uuid,
        excluded: usize,
        timeout: Duration,
    ) -> Result<(usize, NativeProcessIdentity), String> {
        tokio::time::timeout(timeout, async {
            loop {
                for (index, replica) in self.replicas.iter_mut().enumerate() {
                    if index == excluded {
                        continue;
                    }
                    let barrier = replica
                        .checkpoint_barrier
                        .as_ref()
                        .ok_or_else(|| "native replica has no timer checkpoint".to_owned())?;
                    if barrier.observed.exists() {
                        validate_checkpoint_marker(replica, barrier, occurrence_id)?;
                        return Ok((index, replica.command.clone()));
                    }
                    if let Some(status) = replica
                        .child
                        .try_wait()
                        .map_err(|_| "native timer replica status could not be read".to_owned())?
                    {
                        return Err(format!(
                            "native timer replica exited before checkpoint with {status}; inspect {}",
                            replica.log_path.display()
                        ));
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "no peer replica reached the timer checkpoint before the bound".to_owned())?
    }

    pub fn release_checkpoint(&self, replica: usize) -> Result<(), String> {
        let barrier = self
            .replicas
            .get(replica)
            .and_then(|replica| replica.checkpoint_barrier.as_ref())
            .ok_or_else(|| "native replica has no timer checkpoint".to_owned())?;
        if !barrier.release.exists() {
            write_private(&barrier.release, b"release")?;
        }
        Ok(())
    }

    pub fn release_checkpoints_except(&self, excluded: usize) -> Result<(), String> {
        for index in 0..self.replicas.len() {
            if index != excluded {
                self.release_checkpoint(index)?;
            }
        }
        Ok(())
    }

    pub async fn wait_for_mutation_checkpoint(
        &self,
        replica: usize,
        expected_operation: &str,
        timeout: Duration,
    ) -> Result<NativeProcessIdentity, String> {
        let replica = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native mutation checkpoint replica does not exist".to_owned())?;
        let barrier = replica
            .mutation_checkpoint_barrier
            .as_ref()
            .ok_or_else(|| "native replica has no mutation checkpoint".to_owned())?;
        tokio::time::timeout(timeout, async {
            loop {
                if barrier.observed.exists() {
                    validate_mutation_checkpoint_marker(replica, barrier, expected_operation)?;
                    return Ok(replica.command.clone());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "ordinary mutation did not reach its pre-commit checkpoint".to_owned())?
    }

    pub fn release_mutation_checkpoint(&self, replica: usize) -> Result<(), String> {
        let barrier = self
            .replicas
            .get(replica)
            .and_then(|replica| replica.mutation_checkpoint_barrier.as_ref())
            .ok_or_else(|| "native replica has no mutation checkpoint".to_owned())?;
        if !barrier.release.exists() {
            write_private(&barrier.release, b"release")?;
        }
        Ok(())
    }

    pub fn client(&self, replica: usize) -> Result<BaseRegistryClient, String> {
        self.client_with_attempt_timeout(replica, Duration::from_secs(5))
    }

    pub fn checkpoint_race_client(&self, replica: usize) -> Result<BaseRegistryClient, String> {
        self.client_with_attempt_timeout(replica, Duration::from_secs(12))
    }

    fn client_with_attempt_timeout(
        &self,
        replica: usize,
        attempt_timeout: Duration,
    ) -> Result<BaseRegistryClient, String> {
        let base_url = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .base_url
            .clone();
        let token = BearerToken::new(self.token.clone())
            .map_err(|_| "native timer bearer token is invalid".to_owned())?;
        BaseRegistryClient::new(
            BaseRegistryClientConfig::new(base_url)
                .with_attempt_timeout(attempt_timeout)
                .with_connect_timeout(Duration::from_secs(2))
                .with_maximum_mutation_retries(0),
        )
        .map(|client| client.with_bearer_token(token))
        .map_err(|error| format!("native timer client configuration failed: {error}"))
    }

    pub async fn create_binding(
        &self,
        client: &BaseRegistryClient,
    ) -> Result<BRegCreateBinding, String> {
        self.create_binding_for(client, "service").await
    }

    pub async fn create_binding_for(
        &self,
        client: &BaseRegistryClient,
        record_type: &str,
    ) -> Result<BRegCreateBinding, String> {
        let metadata = client
            .registry_contract(Some("service-editor"))
            .await
            .map_err(|error| format!("timer Registry metadata request failed: {error}"))?;
        match metadata
            .value
            .select_direct_write(&format!("records.{record_type}.create"), "service-editor")
            .map_err(|error| format!("timer Create binding selection failed: {error}"))?
        {
            BRegDirectWrite::Create(binding) => Ok(binding),
            BRegDirectWrite::Patch(_) => Err("timer Create operation selected a Patch".to_owned()),
        }
    }

    pub async fn patch_binding(
        &self,
        client: &BaseRegistryClient,
    ) -> Result<BRegPatchBinding, String> {
        let metadata = client
            .registry_contract(Some("service-editor"))
            .await
            .map_err(|error| format!("timer Registry metadata request failed: {error}"))?;
        match metadata
            .value
            .select_direct_write("records.service.patch", "service-editor")
            .map_err(|error| format!("timer Patch binding selection failed: {error}"))?
        {
            BRegDirectWrite::Patch(binding) => Ok(binding),
            BRegDirectWrite::Create(_) => Err("timer Patch operation selected a Create".to_owned()),
        }
    }

    pub async fn tombstone_binding(
        &self,
        client: &BaseRegistryClient,
    ) -> Result<BRegTombstoneBinding, String> {
        client
            .registry_contract(Some("service-editor"))
            .await
            .map_err(|error| format!("timer Registry metadata request failed: {error}"))?
            .value
            .select_tombstone("service", "service-editor")
            .map_err(|error| format!("timer Tombstone binding selection failed: {error}"))
    }

    pub async fn batch_binding(
        &self,
        client: &BaseRegistryClient,
    ) -> Result<BRegBatchBinding, String> {
        client
            .registry_contract(Some("service-editor"))
            .await
            .map_err(|error| format!("timer Registry metadata request failed: {error}"))?
            .value
            .select_batch("service", "service-editor")
            .map_err(|error| format!("timer Batch binding selection failed: {error}"))
    }

    pub async fn reschedule_batch_and_replay(
        client: BaseRegistryClient,
        binding: BRegBatchBinding,
        records: Vec<BRegComplete<RegistryRecordSingleResponse>>,
        due_at: chrono::DateTime<Utc>,
    ) -> Result<BRegComplete<BRegBatchReceipt>, String> {
        let request = reschedule_batch_request(&binding, &records, due_at)?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-batch-{}", Uuid::new_v4()))
            .map_err(|_| "timer Batch idempotency key is invalid".to_owned())?;
        let committed = client
            .batch_records(&binding, &request, &key)
            .await
            .map_err(|error| format!("timer Batch failed: {error}"))?;
        let replay = client
            .batch_records(&binding, &request, &key)
            .await
            .map_err(|error| format!("timer Batch replay failed: {error}"))?;
        if replay.value != committed.value {
            return Err("timer Batch replay did not return the retained receipt".to_owned());
        }
        Ok(committed)
    }

    pub async fn reschedule_batch_expect_precondition_failure(
        client: BaseRegistryClient,
        binding: BRegBatchBinding,
        records: Vec<BRegComplete<RegistryRecordSingleResponse>>,
        due_at: chrono::DateTime<Utc>,
    ) -> Result<(), String> {
        let request = reschedule_batch_request(&binding, &records, due_at)?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-stale-batch-{}", Uuid::new_v4()))
            .map_err(|_| "stale timer Batch idempotency key is invalid".to_owned())?;
        let error = client
            .batch_records(&binding, &request, &key)
            .await
            .err()
            .ok_or_else(|| "stale timer Batch unexpectedly committed".to_owned())?;
        Self::expect_precondition_failure(error, "Batch")
    }

    pub async fn prepare_reschedule_ingestion(
        &self,
        client: &BaseRegistryClient,
        records: &[BRegComplete<RegistryRecordSingleResponse>],
        due_at: chrono::DateTime<Utc>,
    ) -> Result<NativeIngestionPatch, String> {
        let items = reschedule_ingestion_items(records, due_at)?;
        let mut input = Vec::new();
        for item in &items {
            let mut line = registry_platform_canonical_json::canonicalize_json(item)
                .map_err(|_| "timer ingestion source item could not be canonicalized".to_owned())?;
            line.push(b'\n');
            input.extend_from_slice(&line);
        }
        let input_digest = ingestion_prefix_digest(&input);
        let request = BRegIngestionRunRequest::builder()
            .operation(BRegBatchOperation::Patch)
            .profile("service-editor")
            .map_err(|error| format!("timer ingestion profile was invalid: {error}"))?
            .package_revision(&self.package_digest)
            .map_err(|error| format!("timer ingestion package revision was invalid: {error}"))?
            .schema_fingerprint(&self.schema_fingerprint)
            .map_err(|error| format!("timer ingestion schema fingerprint was invalid: {error}"))?
            .input_digest(&input_digest)
            .map_err(|error| format!("timer ingestion input digest was invalid: {error}"))?
            .input_length(
                u64::try_from(input.len())
                    .map_err(|_| "timer ingestion input length exceeded u64".to_owned())?,
            )
            .item_count(
                u64::try_from(items.len())
                    .map_err(|_| "timer ingestion item count exceeded u64".to_owned())?,
            )
            .map_err(|error| format!("timer ingestion item count was invalid: {error}"))?
            .chunk_count(1)
            .map_err(|error| format!("timer ingestion chunk count was invalid: {error}"))?
            .chunk_algorithm_version(BREG_INGESTION_CHUNK_ALGORITHM_VERSION)
            .map_err(|error| format!("timer ingestion algorithm was invalid: {error}"))?
            .build()
            .map_err(|error| format!("timer ingestion announcement was invalid: {error}"))?;
        let run = client
            .create_ingestion_run("services", &request)
            .await
            .map_err(|error| format!("timer ingestion run could not be created: {error}"))?;
        if run.value.status() != BRegIngestionRunStatus::Open
            || run.value.next_chunk_index() != 0
            || run.value.committed_items() != 0
        {
            return Err(format!(
                "timer ingestion run did not start at the empty checkpoint: status={:?}, next={}, committed={}",
                run.value.status(),
                run.value.next_chunk_index(),
                run.value.committed_items()
            ));
        }
        let chunk = BRegIngestionChunk::new(0, items, input_digest)
            .map_err(|error| format!("timer ingestion chunk was invalid: {error}"))?;
        Ok(NativeIngestionPatch {
            run_id: run.value.run_id(),
            chunk,
        })
    }

    pub async fn submit_ingestion_and_replay(
        client: BaseRegistryClient,
        patch: NativeIngestionPatch,
    ) -> Result<BRegComplete<BRegIngestionChunkSubmission>, String> {
        let committed = client
            .submit_ingestion_chunk("services", patch.run_id, &patch.chunk, "service-editor")
            .await
            .map_err(|error| format!("timer ingestion chunk failed: {error}"))?;
        let replay = client
            .submit_ingestion_chunk("services", patch.run_id, &patch.chunk, "service-editor")
            .await
            .map_err(|error| format!("timer ingestion replay failed: {error}"))?;
        if !committed.value.run().complete()
            || !replay.value.run().complete()
            || committed.value.run().next_chunk_index() != 1
            || replay.value.run().next_chunk_index() != 1
            || committed.value.run().committed_items() != 2
            || replay.value.run().committed_items() != 2
            || committed.value.receipt().batch() != replay.value.receipt().batch()
            || committed.value.receipt().replayed()
            || !replay.value.receipt().replayed()
        {
            return Err("timer ingestion replay did not return the retained receipt".to_owned());
        }
        Ok(committed)
    }

    pub async fn submit_ingestion_expect_precondition_failure(
        client: BaseRegistryClient,
        patch: NativeIngestionPatch,
    ) -> Result<(), String> {
        let error = client
            .submit_ingestion_chunk("services", patch.run_id, &patch.chunk, "service-editor")
            .await
            .err()
            .ok_or_else(|| "stale timer ingestion chunk unexpectedly committed".to_owned())?;
        Self::expect_precondition_failure(error, "ingestion chunk")
    }

    pub async fn create_scheduled_service(
        &self,
        client: &BaseRegistryClient,
        binding: &BRegCreateBinding,
        due_at: chrono::DateTime<Utc>,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let not_after = due_at + chrono::Duration::seconds(30);
        self.create_timer_record(client, binding, due_at, not_after, false)
            .await
    }

    pub async fn create_timer_record(
        &self,
        client: &BaseRegistryClient,
        binding: &BRegCreateBinding,
        due_at: chrono::DateTime<Utc>,
        not_after: chrono::DateTime<Utc>,
        paused: bool,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let mut values = Map::from_iter([
            ("status".to_owned(), json!("scheduled")),
            (
                "activatesAt".to_owned(),
                json!(due_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            ),
            (
                "activationNotAfter".to_owned(),
                json!(not_after.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            ),
            ("activationRevision".to_owned(), json!(Uuid::new_v4())),
            ("paused".to_owned(), json!(paused)),
            (
                "description".to_owned(),
                json!("native future activation canary"),
            ),
            ("jurisdiction".to_owned(), json!("zone-a")),
        ]);
        if self.business_refusal_guard {
            values.insert("approved".to_owned(), json!(false));
        }
        let request = BRegCreateRequest::new(values)
            .map_err(|error| format!("timer Create body failed: {error}"))?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-{}", Uuid::new_v4()))
            .map_err(|_| "timer idempotency key is invalid".to_owned())?;
        client
            .create_record(binding, &request, &key, BRegRecordFormat::Json)
            .await
            .map_err(|error| format!("scheduled service Create failed: {error}"))
    }

    pub async fn get_service(
        &self,
        client: &BaseRegistryClient,
        record_id: &str,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let options = BRegRecordOptions::default()
            .access_profile("service-editor")
            .map_err(|error| format!("timer Get options failed: {error}"))?;
        client
            .get_record("services", record_id, &options)
            .await
            .map_err(|error| format!("scheduled service Get failed: {error}"))
    }

    pub async fn replace_description(
        &self,
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        description: &str,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "unrelated Record read did not expose an ETag".to_owned())?;
        let patch = BRegPatchRequest::builder()
            .replace("description", json!(description))
            .map_err(|error| format!("unrelated Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("unrelated Record patch body failed: {error}"))?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-unrelated-{}", Uuid::new_v4()))
            .map_err(|_| "unrelated Record idempotency key is invalid".to_owned())?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "unrelated Record identifier is not a UUID".to_owned())?;
        client
            .patch_record(
                binding,
                record_id,
                etag,
                &patch,
                &key,
                BRegRecordFormat::Json,
            )
            .await
            .map_err(|error| format!("unrelated Record patch failed: {error}"))
    }

    pub async fn replace_description_expect_precondition_failure(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        description: &str,
    ) -> Result<(), String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "racing Record read did not expose an ETag".to_owned())?;
        let patch = BRegPatchRequest::builder()
            .replace("description", json!(description))
            .map_err(|error| format!("racing Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("racing Record patch body failed: {error}"))?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-racing-{}", Uuid::new_v4()))
            .map_err(|_| "racing Record idempotency key is invalid".to_owned())?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "racing Record identifier is not a UUID".to_owned())?;
        let error = client
            .patch_record(
                binding,
                record_id,
                etag,
                &patch,
                &key,
                BRegRecordFormat::Json,
            )
            .await
            .err()
            .ok_or_else(|| "stale racing Record patch unexpectedly committed".to_owned())?;
        if error.status() != Some(412)
            || error.problem_code() != Some(BRegProblemCode::PreconditionFailed)
        {
            return Err(format!(
                "stale racing Record patch returned the wrong refusal: status={:?}, code={:?}",
                error.status(),
                error.problem_code()
            ));
        }
        Ok(())
    }

    pub async fn reschedule_activation(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        due_at: chrono::DateTime<Utc>,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "rescheduling Record read did not expose an ETag".to_owned())?;
        let not_after = due_at + chrono::Duration::seconds(30);
        let patch = BRegPatchRequest::builder()
            .replace(
                "activatesAt",
                json!(due_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            )
            .map_err(|error| format!("rescheduling Record patch body failed: {error}"))?
            .replace(
                "activationNotAfter",
                json!(not_after.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            )
            .map_err(|error| format!("rescheduling Record patch body failed: {error}"))?
            .replace("activationRevision", json!(Uuid::new_v4()))
            .map_err(|error| format!("rescheduling Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("rescheduling Record patch body failed: {error}"))?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-reschedule-{}", Uuid::new_v4()))
            .map_err(|_| "rescheduling Record idempotency key is invalid".to_owned())?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "rescheduling Record identifier is not a UUID".to_owned())?;
        client
            .patch_record(
                binding,
                record_id,
                etag,
                &patch,
                &key,
                BRegRecordFormat::Json,
            )
            .await
            .map_err(|error| format!("rescheduling Record patch failed: {error}"))
    }

    pub async fn set_paused(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        paused: bool,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let patch = BRegPatchRequest::builder()
            .replace("paused", json!(paused))
            .map_err(|error| format!("pause Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("pause Record patch body failed: {error}"))?;
        Self::patch_service(client, binding, record, &patch, "pause").await
    }

    pub async fn set_activation_not_after(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        not_after: chrono::DateTime<Utc>,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let patch = BRegPatchRequest::builder()
            .replace(
                "activationNotAfter",
                json!(not_after.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            )
            .map_err(|error| format!("window-end Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("window-end Record patch body failed: {error}"))?;
        Self::patch_service(client, binding, record, &patch, "window-end").await
    }

    pub async fn set_approved(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        approved: bool,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let patch = BRegPatchRequest::builder()
            .replace("approved", json!(approved))
            .map_err(|error| format!("approval Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("approval Record patch body failed: {error}"))?;
        Self::patch_service(client, binding, record, &patch, "approval").await
    }

    pub async fn clear_activation(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let patch = BRegPatchRequest::builder()
            .remove("activatesAt")
            .map_err(|error| format!("clear-date Record patch body failed: {error}"))?
            .remove("activationNotAfter")
            .map_err(|error| format!("clear-date Record patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("clear-date Record patch body failed: {error}"))?;
        Self::patch_service(client, binding, record, &patch, "clear-date").await
    }

    pub async fn set_paused_expect_precondition_failure(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        paused: bool,
    ) -> Result<(), String> {
        let patch = BRegPatchRequest::builder()
            .replace("paused", json!(paused))
            .map_err(|error| format!("racing pause patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("racing pause patch body failed: {error}"))?;
        Self::patch_service_expect_precondition_failure(client, binding, record, &patch, "pause")
            .await
    }

    pub async fn clear_activation_expect_precondition_failure(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
    ) -> Result<(), String> {
        let patch = BRegPatchRequest::builder()
            .remove("activatesAt")
            .map_err(|error| format!("racing clear-date patch body failed: {error}"))?
            .remove("activationNotAfter")
            .map_err(|error| format!("racing clear-date patch body failed: {error}"))?
            .build()
            .map_err(|error| format!("racing clear-date patch body failed: {error}"))?;
        Self::patch_service_expect_precondition_failure(
            client,
            binding,
            record,
            &patch,
            "clear-date",
        )
        .await
    }

    pub async fn tombstone_service(
        client: &BaseRegistryClient,
        binding: &BRegTombstoneBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "Tombstone Record read did not expose an ETag".to_owned())?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "Tombstone Record identifier is not a UUID".to_owned())?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-tombstone-{}", Uuid::new_v4()))
            .map_err(|_| "Tombstone Record idempotency key is invalid".to_owned())?;
        client
            .tombstone_record(binding, record_id, etag, &key, BRegRecordFormat::Json)
            .await
            .map_err(|error| format!("Tombstone Record mutation failed: {error}"))
    }

    pub async fn tombstone_service_expect_precondition_failure(
        client: &BaseRegistryClient,
        binding: &BRegTombstoneBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
    ) -> Result<(), String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "racing Tombstone read did not expose an ETag".to_owned())?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "racing Tombstone identifier is not a UUID".to_owned())?;
        let key =
            BRegIdempotencyKey::parse(format!("native-timer-racing-tombstone-{}", Uuid::new_v4()))
                .map_err(|_| "racing Tombstone idempotency key is invalid".to_owned())?;
        let error = client
            .tombstone_record(binding, record_id, etag, &key, BRegRecordFormat::Json)
            .await
            .err()
            .ok_or_else(|| "stale racing Tombstone unexpectedly committed".to_owned())?;
        Self::expect_precondition_failure(error, "Tombstone")
    }

    async fn patch_service(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        patch: &BRegPatchRequest,
        label: &str,
    ) -> Result<BRegComplete<RegistryRecordSingleResponse>, String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| format!("{label} Record read did not expose an ETag"))?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| format!("{label} Record identifier is not a UUID"))?;
        let key = BRegIdempotencyKey::parse(format!("native-timer-{label}-{}", Uuid::new_v4()))
            .map_err(|_| format!("{label} Record idempotency key is invalid"))?;
        client
            .patch_record(
                binding,
                record_id,
                etag,
                patch,
                &key,
                BRegRecordFormat::Json,
            )
            .await
            .map_err(|error| format!("{label} Record patch failed: {error}"))
    }

    async fn patch_service_expect_precondition_failure(
        client: &BaseRegistryClient,
        binding: &BRegPatchBinding,
        record: &BRegComplete<RegistryRecordSingleResponse>,
        patch: &BRegPatchRequest,
        label: &str,
    ) -> Result<(), String> {
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| format!("racing {label} Record read did not expose an ETag"))?;
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| format!("racing {label} Record identifier is not a UUID"))?;
        let key =
            BRegIdempotencyKey::parse(format!("native-timer-racing-{label}-{}", Uuid::new_v4()))
                .map_err(|_| format!("racing {label} idempotency key is invalid"))?;
        let error = client
            .patch_record(
                binding,
                record_id,
                etag,
                patch,
                &key,
                BRegRecordFormat::Json,
            )
            .await
            .err()
            .ok_or_else(|| format!("stale racing {label} patch unexpectedly committed"))?;
        Self::expect_precondition_failure(error, label)
    }

    fn expect_precondition_failure(
        error: registry_breg_client::BaseRegistryClientError,
        label: &str,
    ) -> Result<(), String> {
        if error.status() != Some(412)
            || error.problem_code() != Some(BRegProblemCode::PreconditionFailed)
        {
            return Err(format!(
                "stale racing {label} returned the wrong refusal: status={:?}, code={:?}",
                error.status(),
                error.problem_code()
            ));
        }
        Ok(())
    }

    pub async fn record_lifecycle(&self, record_id: &str) -> Result<String, String> {
        let entity = &self.registry.entities()["service"];
        self.database()
            .admin
            .query_one(
                &format!(
                    "SELECT record_lifecycle FROM registry_data.\"{}\" WHERE record_id=$1::text::uuid",
                    entity.physical_table
                ),
                &[&record_id],
            )
            .await
            .map(|row| row.get(0))
            .map_err(|_| "native timer Record lifecycle query failed".to_owned())
    }

    pub async fn timer_evidence(&self, record_id: &str) -> Result<TimerEvidence, String> {
        self.timer_evidence_for("service", "activate", record_id)
            .await
    }

    pub async fn timer_evidence_for(
        &self,
        record_type: &str,
        timer_id: &str,
        record_id: &str,
    ) -> Result<TimerEvidence, String> {
        let database = self.database();
        let entity = self
            .registry
            .entities()
            .get(record_type)
            .ok_or_else(|| "native timer evidence Record type is unknown".to_owned())?;
        let status = &entity.fields["status"].physical_name;
        let record_id = Uuid::parse_str(record_id)
            .map_err(|_| "native timer evidence Record identifier is not a UUID".to_owned())?;
        let row = database
            .admin
            .query_one(
                &format!(
                    "SELECT generation.state AS timer_state,\n\
                            anchor.\"{status}\" AS record_status,\n\
                            anchor.record_revision,\n\
                         (SELECT count(*) FROM registry_internal.registry_revisions\n\
                           WHERE entity_id=$1 AND record_id=$3) AS revision_count,\n\
                         (SELECT count(*) FROM registry_internal.registry_outbox\n\
                           WHERE entity_id=$1 AND application_reference IS NOT NULL\n\
                             AND EXISTS (\n\
                                 SELECT 1\n\
                                   FROM registry_internal.registry_revisions AS revision\n\
                                  WHERE revision.entity_id=$1\n\
                                    AND revision.record_id=$3\n\
                                    AND revision.record_reference=registry_outbox.record_reference\n\
                                    AND revision.record_revision=registry_outbox.record_revision\n\
                                    AND revision.package_revision=registry_outbox.package_revision\n\
                             )) AS outbox_count,\n\
                         (SELECT count(*) FROM registry_internal.registry_idempotency\n\
                           WHERE result_kind='immediate_action') AS action_receipt_count,\n\
                         generation.occurrence_id, generation.binding_incarnation,\n\
                         generation.material_signature, generation.due_at,\n\
                         generation.not_after, generation.retry_at,\n\
                         generation.definition_revision, generation.action_revision,\n\
                         generation.system_grant_revision, generation.gate_open,\n\
                         generation.block_kind, generation.outcome_code,\n\
                         generation.executed_attempt_count, generation.retry_allowance,\n\
                         generation.claim_owner_id, generation.claim_epoch,\n\
                         generation.claim_token, generation.completed_at,\n\
                         generation.claim_until, generation.claimed_control_epoch,\n\
                         generation.claimed_instance_epoch, generation.claimed_activation_id,\n\
                         generation.created_activation_id,\n\
                         generation.current_policy_activation_id,\n\
                         generation.executed_activation_id, generation.receipt_correlation,\n\
                         generation.detail_expires_at,\n\
                         generation.created_at AS generation_created_at,\n\
                         generation.updated_at AS generation_updated_at,\n\
                         current.created_at AS current_created_at,\n\
                         current.updated_at AS current_updated_at,\n\
                         control.protocol_version, control.control_state,\n\
                         control.control_epoch, control.bound_instance_epoch\n\
                    FROM registry_internal.registry_record_timer_current AS current\n\
                    JOIN registry_internal.registry_record_timer_generations AS generation\n\
                      ON generation.occurrence_id=current.occurrence_id\n\
                     AND generation.record_type=current.record_type\n\
                     AND generation.record_id=current.record_id\n\
                     AND generation.timer_id=current.timer_id\n\
                     AND generation.binding_incarnation=current.binding_incarnation\n\
                     AND generation.material_signature=current.material_signature\n\
                    JOIN registry_data.\"{}\" AS anchor ON anchor.record_id=current.record_id\n\
                    CROSS JOIN registry_internal.registry_record_timer_control AS control\n\
                   WHERE current.record_type=$1\n\
                     AND current.timer_id=$2\n\
                     AND current.record_id=$3\n\
                     AND control.singleton",
                    entity.physical_table
                ),
                &[&record_type, &timer_id, &record_id],
            )
            .await
            .map_err(|_| "native timer durable evidence query failed".to_owned())?;
        Ok(TimerEvidence {
            state: row.get("timer_state"),
            status: row.get("record_status"),
            revision: row.get("record_revision"),
            revisions: row.get("revision_count"),
            outbox_entries: row.get("outbox_count"),
            action_receipts: row.get("action_receipt_count"),
            occurrence_id: row.get("occurrence_id"),
            binding_incarnation: row.get("binding_incarnation"),
            material_signature: row.get("material_signature"),
            due_at: row.get("due_at"),
            not_after: row.get("not_after"),
            retry_at: row.get("retry_at"),
            definition_revision: row.get("definition_revision"),
            action_revision: row.get("action_revision"),
            system_grant_revision: row.get("system_grant_revision"),
            gate_open: row.get("gate_open"),
            block_kind: row.get("block_kind"),
            outcome_code: row.get("outcome_code"),
            executed_attempt_count: row.get("executed_attempt_count"),
            retry_allowance: row.get("retry_allowance"),
            claim_owner_id: row.get("claim_owner_id"),
            claim_epoch: row.get("claim_epoch"),
            claim_token: row
                .get::<_, Option<Uuid>>("claim_token")
                .map(ClaimTokenEvidence),
            completed_at: row.get("completed_at"),
            claim_until: row.get("claim_until"),
            claimed_control_epoch: row.get("claimed_control_epoch"),
            claimed_instance_epoch: row.get("claimed_instance_epoch"),
            claimed_activation_id: row.get("claimed_activation_id"),
            created_activation_id: row.get("created_activation_id"),
            current_policy_activation_id: row.get("current_policy_activation_id"),
            executed_activation_id: row.get("executed_activation_id"),
            receipt_correlation: row.get("receipt_correlation"),
            detail_expires_at: row.get("detail_expires_at"),
            generation_created_at: row.get("generation_created_at"),
            generation_updated_at: row.get("generation_updated_at"),
            current_created_at: row.get("current_created_at"),
            current_updated_at: row.get("current_updated_at"),
            protocol_version: row.get("protocol_version"),
            control_state: row.get("control_state"),
            control_epoch: row.get("control_epoch"),
            bound_instance_epoch: row.get("bound_instance_epoch"),
        })
    }

    /// Return current-marker and generation counts without requiring either
    /// row to exist. This is intentionally narrower than `timer_evidence` so
    /// the historical-record proof can observe the required absence.
    #[cfg(feature = "tooling")]
    pub async fn timer_metadata_counts(&self, record_id: &str) -> Result<(i64, i64), String> {
        let record_id = Uuid::parse_str(record_id)
            .map_err(|_| "native timer Record identifier is not a UUID".to_owned())?;
        self.database()
            .admin
            .query_one(
                "SELECT (SELECT count(*)::bigint
                           FROM registry_internal.registry_record_timer_current
                          WHERE record_type='service' AND record_id=$1
                            AND timer_id='activate'),
                        (SELECT count(*)::bigint
                           FROM registry_internal.registry_record_timer_generations
                          WHERE record_type='service' AND record_id=$1
                            AND timer_id='activate')",
                &[&record_id],
            )
            .await
            .map(|row| (row.get(0), row.get(1)))
            .map_err(|_| "native timer metadata counts could not be read".to_owned())
    }

    pub async fn timer_attempt_evidence(
        &self,
        occurrence_id: Uuid,
    ) -> Result<Vec<TimerAttemptEvidence>, String> {
        self.database()
            .admin
            .query(
                "SELECT attempt_number,claim_owner_id,claim_epoch,control_epoch,\n\
                        instance_epoch,activation_id,definition_revision,action_revision,\n\
                        system_grant_revision,started_at,finished_at,block_kind,outcome_code,\n\
                        technical_code,receipt_correlation\n\
                   FROM registry_internal.registry_record_timer_attempts\n\
                  WHERE occurrence_id=$1\n\
                  ORDER BY attempt_number",
                &[&occurrence_id],
            )
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| TimerAttemptEvidence {
                        attempt_number: row.get("attempt_number"),
                        claim_owner_id: row.get("claim_owner_id"),
                        claim_epoch: row.get("claim_epoch"),
                        control_epoch: row.get("control_epoch"),
                        instance_epoch: row.get("instance_epoch"),
                        activation_id: row.get("activation_id"),
                        definition_revision: row.get("definition_revision"),
                        action_revision: row.get("action_revision"),
                        system_grant_revision: row.get("system_grant_revision"),
                        started_at: row.get("started_at"),
                        finished_at: row.get("finished_at"),
                        block_kind: row.get("block_kind"),
                        outcome_code: row.get("outcome_code"),
                        technical_code: row.get("technical_code"),
                        receipt_correlation: row.get("receipt_correlation"),
                    })
                    .collect()
            })
            .map_err(|_| "native timer attempt evidence query failed".to_owned())
    }

    pub async fn timer_generation_evidence(
        &self,
        occurrence_id: Uuid,
    ) -> Result<TimerGenerationEvidence, String> {
        self.database()
            .admin
            .query_one(
                "SELECT generation.state,generation.outcome_code,
                        generation.executed_attempt_count,
                        current.occurrence_id IS NOT NULL AS is_current
                   FROM registry_internal.registry_record_timer_generations AS generation
                   LEFT JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                  WHERE generation.occurrence_id=$1",
                &[&occurrence_id],
            )
            .await
            .map(|row| TimerGenerationEvidence {
                state: row.get("state"),
                outcome_code: row.get("outcome_code"),
                executed_attempt_count: row.get("executed_attempt_count"),
                is_current: row.get("is_current"),
            })
            .map_err(|_| "native timer generation evidence query failed".to_owned())
    }

    pub async fn fixture_only_mark_current_timer_stale(
        &self,
        record_type: &str,
        timer_id: &str,
        record_id: &str,
    ) -> Result<Uuid, String> {
        let record_id = Uuid::parse_str(record_id)
            .map_err(|_| "stale timer fixture Record identifier is not a UUID".to_owned())?;
        let row = self
            .database()
            .admin
            .query_opt(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET definition_revision='sha256:'||repeat('e',64),
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current,
                        registry_internal.registry_record_timer_bindings AS binding
                  WHERE current.record_type=$1
                    AND current.record_id=$2
                    AND current.timer_id=$3
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                    AND binding.record_type=current.record_type
                    AND binding.timer_id=current.timer_id
                    AND binding.incarnation=current.binding_incarnation
                    AND binding.removed_activation_id IS NULL
                    AND generation.state='pending'
                    AND generation.definition_revision=binding.definition_revision
                    AND binding.definition_revision<>'sha256:'||repeat('e',64)
              RETURNING generation.occurrence_id",
                &[&record_type, &record_id, &timer_id],
            )
            .await
            .map_err(|_| "semantic-staleness fixture update failed".to_owned())?
            .ok_or_else(|| {
                "semantic-staleness fixture did not update one current timer".to_owned()
            })?;
        Ok(row.get(0))
    }

    pub async fn wait_for_current_timer_revision(
        &self,
        record_type: &str,
        timer_id: &str,
        record_id: &str,
        timeout: Duration,
    ) -> Result<TimerEvidence, String> {
        let expected = &self
            .registry
            .entities()
            .get(record_type)
            .and_then(|entity| entity.timers.get(timer_id))
            .ok_or_else(|| "current timer revision fixture binding is unknown".to_owned())?
            .definition_revision;
        tokio::time::timeout(timeout, async {
            loop {
                let evidence = self
                    .timer_evidence_for(record_type, timer_id, record_id)
                    .await?;
                if &evidence.definition_revision == expected {
                    return Ok(evidence);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "stale timer did not refresh within the bound".to_owned())?
    }

    pub async fn timer_generation_states(
        &self,
        record_type: &str,
        timer_id: &str,
        record_id: &str,
    ) -> Result<Vec<TimerGenerationEvidence>, String> {
        let record_id = Uuid::parse_str(record_id)
            .map_err(|_| "timer generations Record identifier is not a UUID".to_owned())?;
        self.database()
            .admin
            .query(
                "SELECT generation.state,generation.outcome_code,
                        generation.executed_attempt_count,
                        current.occurrence_id IS NOT NULL AS is_current
                   FROM registry_internal.registry_record_timer_generations AS generation
                   LEFT JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                  WHERE generation.record_type=$1
                    AND generation.timer_id=$2
                    AND generation.record_id=$3
                  ORDER BY generation.created_at,generation.occurrence_id",
                &[&record_type, &timer_id, &record_id],
            )
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| TimerGenerationEvidence {
                        state: row.get("state"),
                        outcome_code: row.get("outcome_code"),
                        executed_attempt_count: row.get("executed_attempt_count"),
                        is_current: row.get("is_current"),
                    })
                    .collect()
            })
            .map_err(|_| "native timer generation states query failed".to_owned())
    }

    pub async fn hold_anchor_lock(
        &self,
        record_type: &str,
        record_id: &str,
    ) -> Result<NativeHeldAnchorLock, String> {
        let entity = self
            .registry
            .entities()
            .get(record_type)
            .ok_or_else(|| "native anchor lock Record type is unknown".to_owned())?;
        let table = entity.physical_table.clone();
        let record_id = Uuid::parse_str(record_id)
            .map_err(|_| "native anchor lock Record identifier is not a UUID".to_owned())?;
        let (mut client, connection) = self.database().connect_admin().await;
        let (acquired_send, acquired_receive) = tokio::sync::oneshot::channel();
        let (release_send, release_receive) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let result = async {
                let transaction = client
                    .transaction()
                    .await
                    .map_err(|_| "native anchor lock transaction could not begin".to_owned())?;
                transaction
                    .query_one(
                        &format!(
                            "SELECT record_id FROM registry_data.\"{table}\" \
                              WHERE record_id=$1 FOR UPDATE"
                        ),
                        &[&record_id],
                    )
                    .await
                    .map_err(|_| "native anchor lock could not be acquired".to_owned())?;
                let _ = acquired_send.send(Ok::<(), String>(()));
                release_receive
                    .await
                    .map_err(|_| "native anchor lock release signal was lost".to_owned())?;
                transaction
                    .rollback()
                    .await
                    .map_err(|_| "native anchor lock transaction could not roll back".to_owned())
            }
            .await;
            connection.abort();
            result
        });
        tokio::time::timeout(Duration::from_secs(5), acquired_receive)
            .await
            .map_err(|_| "native anchor lock was not acquired within the bound".to_owned())?
            .map_err(|_| "native anchor lock task stopped before acknowledgement".to_owned())??;
        Ok(NativeHeldAnchorLock {
            release: Some(release_send),
            task,
        })
    }

    pub async fn ingestion_evidence(
        &self,
        run_id: Uuid,
    ) -> Result<NativeIngestionEvidence, String> {
        self.database()
            .admin
            .query_one(
                "SELECT run.status,run.next_chunk_index,run.committed_items,
                        (SELECT count(*)::bigint
                           FROM registry_internal.registry_ingestion_run_chunks AS chunk
                          WHERE chunk.run_id=run.run_id),
                        (SELECT count(*)::bigint
                           FROM registry_internal.registry_ingestion_run_chunk_records AS link
                          WHERE link.run_id=run.run_id)
                   FROM registry_internal.registry_ingestion_runs AS run
                  WHERE run.run_id=$1",
                &[&run_id],
            )
            .await
            .map(|row| NativeIngestionEvidence {
                status: row.get(0),
                next_chunk_index: row.get(1),
                committed_items: row.get(2),
                chunk_receipts: row.get(3),
                linked_records: row.get(4),
            })
            .map_err(|_| "native timer ingestion evidence query failed".to_owned())
    }

    /// Read the authoritative scheduling clock from the same PostgreSQL
    /// database used by every replica. The native wall-clock proof never
    /// derives its due instant from application or host time.
    pub async fn database_now(&self) -> Result<chrono::DateTime<Utc>, String> {
        self.database()
            .admin
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map(|row| row.get(0))
            .map_err(|_| "native timer database clock could not be read".to_owned())
    }

    pub async fn wait_for_completion(
        &self,
        record_id: &str,
        timeout: Duration,
    ) -> Result<TimerEvidence, String> {
        self.wait_for_completion_for("service", "activate", record_id, timeout)
            .await
    }

    pub async fn wait_for_completion_for(
        &self,
        record_type: &str,
        timer_id: &str,
        record_id: &str,
        timeout: Duration,
    ) -> Result<TimerEvidence, String> {
        tokio::time::timeout(timeout, async {
            loop {
                let evidence = self
                    .timer_evidence_for(record_type, timer_id, record_id)
                    .await?;
                if evidence.state == "completed" && evidence.status == "active" {
                    return Ok(evidence);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "native timer did not complete within the bounded wait".to_owned())?
    }

    /// Stop every live replica while keeping the database and package ready
    /// for replacement-process restart evidence.
    pub fn crash_all_replicas(&mut self) -> Result<(), String> {
        for replica in &mut self.replicas {
            replica.stop()?;
        }
        Ok(())
    }

    pub fn crash_replica(&mut self, replica: usize) -> Result<NativeProcessIdentity, String> {
        let replica = self
            .replicas
            .get_mut(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?;
        let identity = replica.command.clone();
        replica.stop()?;
        Ok(identity)
    }

    pub fn suspend_replica(&mut self, replica: usize) -> Result<NativeProcessIdentity, String> {
        self.signal_replica(replica, "-STOP")
    }

    pub fn resume_replica(&mut self, replica: usize) -> Result<NativeProcessIdentity, String> {
        self.signal_replica(replica, "-CONT")
    }

    pub fn expect_non_info_code(
        &mut self,
        replica: usize,
        code: &str,
        count: usize,
    ) -> Result<(), String> {
        let replica = self
            .replicas
            .get_mut(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?;
        replica
            .expected_non_info_codes
            .insert(code.to_owned(), (count, count));
        Ok(())
    }

    pub fn expect_non_info_code_range(
        &mut self,
        replica: usize,
        code: &str,
        minimum: usize,
        maximum: usize,
    ) -> Result<(), String> {
        if minimum > maximum {
            return Err("native timer expected log-code range is invalid".to_owned());
        }
        let replica = self
            .replicas
            .get_mut(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?;
        replica
            .expected_non_info_codes
            .insert(code.to_owned(), (minimum, maximum));
        Ok(())
    }

    pub async fn wait_for_log_code(
        &self,
        replica: usize,
        code: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let replica = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?;
        let needle = format!("\"code\":\"{code}\"");
        tokio::time::timeout(timeout, async {
            loop {
                let rendered = fs::read_to_string(&replica.log_path)
                    .map_err(|_| "native timer process log could not be read".to_owned())?;
                if rendered.contains(&needle) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "native timer process did not emit the expected log code".to_owned())?
    }

    /// Terminate only the PostgreSQL sessions owned by one native process.
    /// Every launch has a unique application name, so another replica remains
    /// connected and can recover the durable occurrence after lease expiry.
    pub async fn terminate_replica_database_sessions(&self, replica: usize) -> Result<u64, String> {
        let launch_id = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .command
            .launch_id
            .clone();
        let application_name = format!("breg-timer-{launch_id}");
        let row = self
            .database()
            .admin
            .query_one(
                "SELECT count(*)::bigint
                   FROM (
                         SELECT pg_terminate_backend(pid) AS terminated
                           FROM pg_catalog.pg_stat_activity
                          WHERE datname=current_database()
                            AND application_name=$1
                            AND pid<>pg_backend_pid()
                        ) AS terminated_sessions
                  WHERE terminated",
                &[&application_name],
            )
            .await
            .map_err(|_| "native timer replica sessions could not be terminated".to_owned())?;
        let count: i64 = row.get(0);
        u64::try_from(count)
            .map_err(|_| "native timer terminated-session count was invalid".to_owned())
    }

    /// Wait until this replica has a PostgreSQL session blocked on a database
    /// lock. The replica-specific application name avoids inferring
    /// contention from task timing alone.
    pub async fn wait_for_replica_database_lock_wait(
        &self,
        replica: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let launch_id = self
            .replicas
            .get(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?
            .command
            .launch_id
            .clone();
        let application_name = format!("breg-timer-{launch_id}");
        tokio::time::timeout(timeout, async {
            loop {
                let count: i64 = self
                    .database()
                    .admin
                    .query_one(
                        "SELECT count(*)::bigint
                           FROM pg_catalog.pg_stat_activity
                          WHERE datname=current_database()
                            AND application_name=$1
                            AND wait_event_type='Lock'",
                        &[&application_name],
                    )
                    .await
                    .map_err(|_| "native timer lock-wait evidence query failed".to_owned())?
                    .get(0);
                if count > 0 {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "native replica did not enter the expected database lock wait".to_owned())?
    }

    /// Fixture-only pause control used to isolate scheduler lifecycle behavior.
    /// This is deliberately not operator-command evidence.
    pub async fn set_scheduler_paused(&self, paused: bool) -> Result<i64, String> {
        self.database()
            .admin
            .query_one(
                "UPDATE registry_internal.registry_record_timer_control
                    SET control_state=CASE WHEN $1 THEN 'paused' ELSE 'running' END,
                        control_epoch=control_epoch+1,
                        updated_at=clock_timestamp()
                  WHERE singleton AND control_state<>'adoption-hold'
              RETURNING control_epoch",
                &[&paused],
            )
            .await
            .map(|row| row.get(0))
            .map_err(|_| "native timer pause control update failed".to_owned())
    }

    /// Fixture-only future-state control setup for global readiness and
    /// private metrics acceptance. This is not operator-transition evidence.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn fixture_only_set_timer_control(
        &self,
        state: &str,
        protocol_version: i32,
        instance_epoch_offset: i64,
    ) -> Result<i64, String> {
        if !matches!(state, "running" | "paused" | "adoption-hold")
            || protocol_version < 1
            || !matches!(instance_epoch_offset, 0 | 1)
        {
            return Err("timer control fixture input was outside its closed contract".to_owned());
        }
        self.database()
            .admin
            .query_one(
                "UPDATE registry_internal.registry_record_timer_control AS control
                    SET protocol_version=$1,
                        control_state=$2,
                        control_epoch=control.control_epoch+1,
                        bound_instance_epoch=state.epoch+$3,
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_state AS state
                  WHERE control.singleton AND state.singleton
              RETURNING control.control_epoch",
                &[&protocol_version, &state, &instance_epoch_offset],
            )
            .await
            .map(|row| row.get(0))
            .map_err(|_| "timer control fixture update failed".to_owned())
    }

    /// Change only the disposable database's active-package digest so metrics
    /// can prove their process/package compatibility signal. This never loads
    /// or admits the replacement as a package.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn fixture_only_set_active_package_match(
        &self,
        matches_process: bool,
    ) -> Result<(), String> {
        let digest = if matches_process {
            self.package_digest.as_str()
        } else {
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        };
        let updated = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_digest=$1
                  WHERE singleton",
                &[&digest],
            )
            .await
            .map_err(|_| "active package metric fixture update failed".to_owned())?;
        if updated != 1 {
            return Err("active package metric fixture did not update one row".to_owned());
        }
        Ok(())
    }

    /// Populate a bounded, value-canary-bearing timer operational sample.
    /// These rows exercise metrics projection only, not worker lifecycle.
    #[allow(dead_code)] // Consumed by the sibling timer-metrics target.
    pub async fn fixture_only_seed_timer_metrics(
        &self,
        include_truncation_sentinel: bool,
    ) -> Result<(), String> {
        self.database()
            .admin
            .batch_execute(
                "WITH binding AS (
                     SELECT * FROM registry_internal.registry_record_timer_bindings
                      WHERE record_type='service' AND timer_id='activate'
                        AND removed_activation_id IS NULL
                 ), fixture AS MATERIALIZED (
                     SELECT fixture.*,gen_random_uuid() AS record_id,
                            gen_random_uuid() AS occurrence_id,
                            gen_random_uuid() AS claim_owner_id
                       FROM (VALUES
                         ('live-a','leased',true,-20::bigint,NULL::bigint,60::bigint,NULL::text,1,false,true),
                         ('live-b','leased',true,-19,NULL,60,NULL,2,false,true),
                         ('expired-lease','leased',true,-18,NULL,-1,NULL,3,false,true),
                         ('non-current-lease','leased',true,-17,NULL,60,NULL,4,false,false),
                         ('oldest-due','pending',true,-16,NULL,NULL,NULL,5,false,true),
                         ('future','pending',true,60,NULL,NULL,NULL,6,false,true),
                         ('false-gate','pending',false,-60,NULL,NULL,NULL,7,false,true),
                         ('retry-delayed','pending',true,-50,60,NULL,NULL,8,false,true),
                         ('technical-block','blocked',true,-40,NULL,NULL,'technical',9,false,true),
                         ('configuration-block','blocked',true,-30,NULL,NULL,'configuration',10,false,true),
                         ('stale-revision','pending',true,90,NULL,NULL,NULL,11,true,true)
                       ) AS fixture(
                         label,state,gate_open,due_offset_seconds,retry_offset_seconds,
                         claim_offset_seconds,block_kind,attempt_count,stale_revision,is_current
                       )
                 ), inserted AS (
                     INSERT INTO registry_internal.registry_record_timer_generations (
                         record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                         material_signature,due_at,retry_at,definition_revision,
                         action_revision,system_grant_revision,gate_open,state,block_kind,
                         executed_attempt_count,claim_owner_id,claim_epoch,claim_token,
                         claim_until,claimed_control_epoch,claimed_instance_epoch,
                         claimed_activation_id,created_activation_id,
                         current_policy_activation_id,created_at,updated_at
                     )
                     SELECT binding.record_type,fixture.record_id,binding.timer_id,
                            fixture.occurrence_id,binding.incarnation,
                            'sha256:'||repeat('a',64),
                            clock_timestamp()+fixture.due_offset_seconds*interval '1 second',
                            CASE WHEN fixture.retry_offset_seconds IS NULL THEN NULL
                                 ELSE clock_timestamp()+fixture.retry_offset_seconds*interval '1 second' END,
                            CASE WHEN fixture.stale_revision THEN 'sha256:'||repeat('f',64)
                                 ELSE binding.definition_revision END,
                            binding.action_revision,binding.system_grant_revision,
                            fixture.gate_open,fixture.state,fixture.block_kind,
                            fixture.attempt_count,
                            CASE WHEN fixture.state='leased' THEN fixture.claim_owner_id END,
                            CASE WHEN fixture.state='leased' THEN 1 ELSE 0 END,
                            CASE WHEN fixture.state='leased' THEN gen_random_uuid() END,
                            CASE WHEN fixture.state='leased'
                                 THEN clock_timestamp()+fixture.claim_offset_seconds*interval '1 second' END,
                            CASE WHEN fixture.state='leased' THEN control.control_epoch END,
                            CASE WHEN fixture.state='leased' THEN registry.epoch END,
                            CASE WHEN fixture.state='leased' THEN registry.active_activation_id END,
                            binding.created_activation_id,binding.current_policy_activation_id,
                            clock_timestamp()-interval '1 hour',clock_timestamp()-interval '1 hour'
                       FROM fixture CROSS JOIN binding
                       JOIN registry_internal.registry_record_timer_control AS control ON control.singleton
                       JOIN registry_internal.registry_state AS registry ON registry.singleton
                  RETURNING record_type,record_id,timer_id,occurrence_id,
                            binding_incarnation,material_signature
                 )
                 INSERT INTO registry_internal.registry_record_timer_current (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                     material_signature,created_at,updated_at
                 )
                 SELECT inserted.record_type,inserted.record_id,inserted.timer_id,
                        inserted.occurrence_id,inserted.binding_incarnation,
                        inserted.material_signature,clock_timestamp()-interval '1 hour',
                        clock_timestamp()-interval '1 hour'
                   FROM inserted
                   JOIN fixture USING (occurrence_id)
                  WHERE fixture.is_current;

                 INSERT INTO registry_internal.registry_record_timer_attempts (
                     occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                     control_epoch,instance_epoch,activation_id,
                     definition_revision,action_revision,system_grant_revision,
                     started_at,finished_at,detail_expires_at,block_kind,technical_code
                 )
                 SELECT generation.occurrence_id,9,gen_random_uuid(),1,
                        control.control_epoch,registry.epoch,registry.active_activation_id,
                        generation.definition_revision,generation.action_revision,
                        generation.system_grant_revision,
                        clock_timestamp()-interval '1 second',clock_timestamp(),
                        clock_timestamp()+interval '7 days',
                        'technical','unknown-technical-code-canary'
                   FROM registry_internal.registry_record_timer_generations AS generation
                   JOIN registry_internal.registry_record_timer_current AS current
                     ON current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                   JOIN registry_internal.registry_record_timer_control AS control
                     ON control.singleton
                   JOIN registry_internal.registry_state AS registry ON registry.singleton
                  WHERE generation.block_kind='technical'
                    AND generation.executed_attempt_count=9;

                 UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET current_policy_activation_id=gen_random_uuid(),
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                  WHERE current.occurrence_id=generation.occurrence_id
                    AND current.record_type=generation.record_type
                    AND current.record_id=generation.record_id
                    AND current.timer_id=generation.timer_id
                    AND current.binding_incarnation=generation.binding_incarnation
                    AND current.material_signature=generation.material_signature
                    AND generation.executed_attempt_count=6;",
            )
            .await
            .map_err(|_| "timer metrics fixture could not insert its operational sample".to_owned())?;

        if include_truncation_sentinel {
            self.database()
                .admin
                .batch_execute(
                    "WITH binding AS (
                         SELECT * FROM registry_internal.registry_record_timer_bindings
                          WHERE record_type='service' AND timer_id='activate'
                            AND removed_activation_id IS NULL
                     ), fixture AS MATERIALIZED (
                         SELECT gen_random_uuid() AS record_id,gen_random_uuid() AS occurrence_id
                           FROM generate_series(1,10001)
                     ), inserted AS (
                         INSERT INTO registry_internal.registry_record_timer_generations (
                             record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                             material_signature,due_at,definition_revision,action_revision,
                             system_grant_revision,gate_open,state,executed_attempt_count,
                             claim_epoch,created_activation_id,current_policy_activation_id
                         )
                         SELECT binding.record_type,fixture.record_id,binding.timer_id,
                                fixture.occurrence_id,binding.incarnation,
                                'sha256:'||repeat('b',64),clock_timestamp()+interval '1 day',
                                binding.definition_revision,binding.action_revision,
                                binding.system_grant_revision,false,'cancelled',0,0,
                                binding.created_activation_id,binding.current_policy_activation_id
                           FROM fixture CROSS JOIN binding
                      RETURNING record_type,record_id,timer_id,occurrence_id,
                                binding_incarnation,material_signature
                     )
                     INSERT INTO registry_internal.registry_record_timer_current (
                         record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                         material_signature
                     )
                     SELECT record_type,record_id,timer_id,occurrence_id,
                            binding_incarnation,material_signature
                       FROM inserted;",
                )
                .await
                .map_err(|_| {
                    "timer metrics fixture could not insert its truncation sentinel".to_owned()
                })?;
        }
        Ok(())
    }

    /// Populate older terminal markers before saturated pending and technical
    /// categories, then one later configuration block. This proves bounded
    /// operator projections by category, not lifecycle.
    #[allow(dead_code)] // Consumed by the operator and metrics integration targets.
    pub async fn fixture_only_seed_terminal_history_before_later_blocks(
        &self,
    ) -> Result<(), String> {
        self.database()
            .admin
            .batch_execute(
                "WITH binding AS (
                     SELECT * FROM registry_internal.registry_record_timer_bindings
                      WHERE record_type='service' AND timer_id='activate'
                        AND removed_activation_id IS NULL
                 ), fixture AS MATERIALIZED (
                     SELECT gen_random_uuid() AS record_id,gen_random_uuid() AS occurrence_id
                       FROM generate_series(1,10001)
                 ), inserted AS (
                     INSERT INTO registry_internal.registry_record_timer_generations (
                         record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                         material_signature,due_at,definition_revision,action_revision,
                         system_grant_revision,gate_open,state,executed_attempt_count,
                         claim_epoch,created_activation_id,current_policy_activation_id,
                         created_at,updated_at
                     )
                     SELECT binding.record_type,fixture.record_id,binding.timer_id,
                            fixture.occurrence_id,binding.incarnation,
                            'sha256:'||repeat('c',64),clock_timestamp()+interval '1 day',
                            binding.definition_revision,binding.action_revision,
                            binding.system_grant_revision,false,'cancelled',0,0,
                            binding.created_activation_id,binding.current_policy_activation_id,
                            clock_timestamp()-interval '2 hours',
                            clock_timestamp()-interval '2 hours'
                       FROM fixture CROSS JOIN binding
                  RETURNING record_type,record_id,timer_id,occurrence_id,
                            binding_incarnation,material_signature,created_at,updated_at
                 )
                 INSERT INTO registry_internal.registry_record_timer_current (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                     material_signature,created_at,updated_at
                 )
                 SELECT record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                        material_signature,created_at,updated_at
                   FROM inserted;

                 WITH binding AS (
                     SELECT * FROM registry_internal.registry_record_timer_bindings
                      WHERE record_type='service' AND timer_id='activate'
                        AND removed_activation_id IS NULL
                 ), fixture_source AS (
                     SELECT 'pending'::text AS state,NULL::text AS block_kind,
                            NULL::text AS outcome_code,0 AS attempt_count,
                            -3600::bigint AS created_offset_seconds
                       FROM generate_series(1,10001)
                     UNION ALL
                     SELECT 'blocked','technical','attempts-exhausted',5,-1800::bigint
                       FROM generate_series(1,10001)
                     UNION ALL
                     SELECT 'blocked','configuration',NULL::text,0,0::bigint
                 ), fixture AS MATERIALIZED (
                     SELECT fixture_source.*,gen_random_uuid() AS record_id,
                            gen_random_uuid() AS occurrence_id
                       FROM fixture_source
                 ), inserted AS (
                     INSERT INTO registry_internal.registry_record_timer_generations (
                         record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                         material_signature,due_at,definition_revision,action_revision,
                         system_grant_revision,gate_open,state,block_kind,outcome_code,
                         executed_attempt_count,claim_epoch,created_activation_id,
                         current_policy_activation_id,created_at,updated_at
                     )
                     SELECT binding.record_type,fixture.record_id,binding.timer_id,
                            fixture.occurrence_id,binding.incarnation,
                            'sha256:'||repeat('d',64),clock_timestamp()+interval '1 day',
                            binding.definition_revision,binding.action_revision,
                            binding.system_grant_revision,true,fixture.state,fixture.block_kind,
                            fixture.outcome_code,fixture.attempt_count,0,
                            binding.created_activation_id,binding.current_policy_activation_id,
                            clock_timestamp()+fixture.created_offset_seconds*interval '1 second',
                            clock_timestamp()+fixture.created_offset_seconds*interval '1 second'
                       FROM fixture CROSS JOIN binding
                  RETURNING record_type,record_id,timer_id,occurrence_id,
                            binding_incarnation,material_signature,created_at,updated_at
                 )
                 INSERT INTO registry_internal.registry_record_timer_current (
                     record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                     material_signature,created_at,updated_at
                 )
                 SELECT record_type,record_id,timer_id,occurrence_id,binding_incarnation,
                        material_signature,created_at,updated_at
                   FROM inserted;",
            )
            .await
            .map_err(|_| {
                "timer operator fixture could not insert ordered terminal and blocked history"
                    .to_owned()
            })
    }

    /// Fixture-only ledger transition for operator read projection. This does
    /// not establish worker lifecycle behavior for binding removal.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_block_timer_and_remove_binding(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        let occurrence_updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='blocked', block_kind='technical', outcome_code=NULL,
                        retry_allowance=0, updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                  WHERE current.record_type='service'
                    AND current.timer_id='activate'
                    AND current.record_id=$1::text::uuid
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                    AND generation.state='pending'",
                &[&record_id],
            )
            .await
            .map_err(|_| "operator fixture could not technical-block the occurrence".to_owned())?;
        if occurrence_updates != 1 {
            return Err(
                "operator fixture did not technical-block exactly one occurrence".to_owned(),
            );
        }
        let removed_activation_id = Uuid::new_v4();
        let binding_updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_bindings
                    SET current_policy_activation_id=NULL,
                        removed_activation_id=$1,
                        removed_at=clock_timestamp(),
                        updated_at=clock_timestamp()
                  WHERE record_type='service'
                    AND timer_id='activate'
                    AND removed_activation_id IS NULL",
                &[&removed_activation_id],
            )
            .await
            .map_err(|_| "operator fixture could not close the timer binding".to_owned())?;
        if binding_updates != 1 {
            return Err("operator fixture did not close exactly one timer binding".to_owned());
        }
        Ok(())
    }

    /// Fixture-only catalog drift for status projection. This does not model a
    /// reviewed activation or establish reconciliation lifecycle behavior.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_change_timer_binding_revision(&self) -> Result<(), String> {
        let replacement = format!("sha256:{}", "f".repeat(64));
        let updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_bindings
                    SET definition_revision=$1, updated_at=clock_timestamp()
                  WHERE record_type='service'
                    AND timer_id='activate'
                    AND removed_activation_id IS NULL",
                &[&replacement],
            )
            .await
            .map_err(|_| "operator fixture could not drift the timer binding".to_owned())?;
        if updates != 1 {
            return Err("operator fixture did not drift exactly one timer binding".to_owned());
        }
        Ok(())
    }

    /// Fixture-only setup for public retry-control projection. Execution-owned
    /// real-PostgreSQL tests establish actual technical exhaustion.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_set_technical_retry_candidate(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        self.fixture_only_set_blocked_state(record_id, "technical", 5, true)
            .await
    }

    /// Set one exact current occurrence to the permitted technical-block shape
    /// that lacks the attempts-exhausted outcome required by operator retry.
    /// This proves read projection only, not worker lifecycle behavior.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_set_non_exhausted_technical_block(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        self.fixture_only_set_blocked_state(record_id, "technical", 5, false)
            .await
    }

    /// Advance only the persisted retry gate after one real technical
    /// settlement. This keeps native acceptance bounded while leaving the
    /// production backoff calculation and cumulative attempt history intact.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_release_technical_retry(
        &self,
        record_id: &str,
        expected_attempt_count: i32,
    ) -> Result<(), String> {
        if !(1..5).contains(&expected_attempt_count) {
            return Err("technical retry fixture attempt count was invalid".to_owned());
        }
        let updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET retry_at=clock_timestamp(),updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                  WHERE current.record_type='service'
                    AND current.timer_id='activate'
                    AND current.record_id=$1::text::uuid
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                    AND generation.state='pending'
                    AND generation.block_kind IS NULL
                    AND generation.outcome_code IS NULL
                    AND generation.retry_allowance=0
                    AND generation.executed_attempt_count=$2
                    AND generation.retry_at IS NOT NULL",
                &[&record_id, &expected_attempt_count],
            )
            .await
            .map_err(|_| "technical retry fixture could not advance the retry gate".to_owned())?;
        if updates != 1 {
            return Err(
                "technical retry fixture did not advance one exact current occurrence".to_owned(),
            );
        }
        Ok(())
    }

    /// Fixture-only historical activation metadata drift for operator read
    /// projection. This does not model a reviewed activation or reconciliation.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_change_generation_policy_activation(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        let replacement = Uuid::new_v4();
        let updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET current_policy_activation_id=$2, updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                   JOIN registry_internal.registry_record_timer_bindings AS binding
                     ON binding.record_type=current.record_type
                    AND binding.timer_id=current.timer_id
                    AND binding.removed_activation_id IS NULL
                  WHERE current.record_type='service'
                    AND current.timer_id='activate'
                    AND current.record_id=$1::text::uuid
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                    AND generation.state='blocked'
                    AND generation.block_kind='technical'
                    AND binding.current_policy_activation_id IS DISTINCT FROM $2",
                &[&record_id, &replacement],
            )
            .await
            .map_err(|_| {
                "operator fixture could not drift historical policy activation metadata".to_owned()
            })?;
        if updates != 1 {
            return Err(
                "operator fixture did not drift exactly one current technical occurrence"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Fixture-only setup for a configuration block that operator retry must
    /// refuse. This does not model configuration-block lifecycle.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_set_configuration_block(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        self.fixture_only_set_blocked_state(record_id, "configuration", 0, false)
            .await
    }

    /// Fixture-only setup for a technical block outside its execution window.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_set_expired_technical_block(
        &self,
        record_id: &str,
    ) -> Result<(), String> {
        self.fixture_only_set_blocked_state(record_id, "technical", 5, true)
            .await?;
        let updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET due_at=clock_timestamp()-interval '2 seconds',
                        not_after=clock_timestamp()-interval '1 second',
                        updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                  WHERE current.record_type='service'
                    AND current.timer_id='activate'
                    AND current.record_id=$1::text::uuid
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature",
                &[&record_id],
            )
            .await
            .map_err(|_| "operator fixture could not expire the technical block".to_owned())?;
        if updates != 1 {
            return Err("operator fixture did not expire exactly one technical block".to_owned());
        }
        Ok(())
    }

    /// Fixture-only retained technical attempt for operator projection tests.
    /// Runtime-owned PostgreSQL tests establish actual failure settlement.
    #[allow(dead_code)] // Consumed by the sibling operator integration target.
    pub async fn fixture_only_set_retained_technical_attempt(
        &self,
        record_id: &str,
        technical_code: &str,
    ) -> Result<Uuid, String> {
        if technical_code.is_empty() || technical_code.len() > 64 {
            return Err("operator technical-code fixture input was invalid".to_owned());
        }
        let claim_owner_id = Uuid::new_v4();
        let row = self
            .database()
            .admin
            .query_one(
                "WITH blocked AS (
                     UPDATE registry_internal.registry_record_timer_generations AS generation
                        SET state='blocked',block_kind='technical',outcome_code='attempts-exhausted',
                            executed_attempt_count=1,retry_allowance=0,retry_at=NULL,
                            claim_owner_id=NULL,claim_token=NULL,claim_until=NULL,
                            claimed_control_epoch=NULL,claimed_instance_epoch=NULL,
                            claimed_activation_id=NULL,updated_at=clock_timestamp()
                       FROM registry_internal.registry_record_timer_current AS current
                      WHERE current.record_type='service'
                        AND current.timer_id='activate'
                        AND current.record_id=$1::text::uuid
                        AND generation.occurrence_id=current.occurrence_id
                        AND generation.record_type=current.record_type
                        AND generation.record_id=current.record_id
                        AND generation.timer_id=current.timer_id
                        AND generation.binding_incarnation=current.binding_incarnation
                        AND generation.material_signature=current.material_signature
                        AND generation.state='pending'
                  RETURNING generation.*
                 )
                 INSERT INTO registry_internal.registry_record_timer_attempts (
                     occurrence_id,attempt_number,claim_owner_id,claim_epoch,
                     control_epoch,instance_epoch,activation_id,
                     definition_revision,action_revision,system_grant_revision,
                     started_at,finished_at,detail_expires_at,block_kind,
                     outcome_code,technical_code
                 )
                 SELECT blocked.occurrence_id,1,$2,1,control.control_epoch,state.epoch,
                        blocked.created_activation_id,blocked.definition_revision,
                        blocked.action_revision,blocked.system_grant_revision,
                        clock_timestamp()-interval '1 second',clock_timestamp(),
                        clock_timestamp()+interval '7 days',
                        'technical',NULL,$3
                   FROM blocked
                   JOIN registry_internal.registry_record_timer_control AS control ON control.singleton
                   JOIN registry_internal.registry_state AS state ON state.singleton
              RETURNING occurrence_id",
                &[&record_id, &claim_owner_id, &technical_code],
            )
            .await
            .map_err(|_| "operator fixture could not retain a technical attempt".to_owned())?;
        Ok(row.get(0))
    }

    async fn fixture_only_set_blocked_state(
        &self,
        record_id: &str,
        block_kind: &str,
        attempt_count: i32,
        exhausted: bool,
    ) -> Result<(), String> {
        let outcome_code = exhausted.then_some("attempts-exhausted");
        let updates = self
            .database()
            .admin
            .execute(
                "UPDATE registry_internal.registry_record_timer_generations AS generation
                    SET state='blocked', block_kind=$2, outcome_code=$3,
                        executed_attempt_count=$4, retry_allowance=0, retry_at=NULL,
                        claim_owner_id=NULL, claim_token=NULL, claim_until=NULL,
                        claimed_control_epoch=NULL, claimed_instance_epoch=NULL,
                        claimed_activation_id=NULL, updated_at=clock_timestamp()
                   FROM registry_internal.registry_record_timer_current AS current
                  WHERE current.record_type='service'
                    AND current.timer_id='activate'
                    AND current.record_id=$1::text::uuid
                    AND generation.occurrence_id=current.occurrence_id
                    AND generation.record_type=current.record_type
                    AND generation.record_id=current.record_id
                    AND generation.timer_id=current.timer_id
                    AND generation.binding_incarnation=current.binding_incarnation
                    AND generation.material_signature=current.material_signature
                    AND generation.state='pending'",
                &[&record_id, &block_kind, &outcome_code, &attempt_count],
            )
            .await
            .map_err(|_| "operator fixture could not set the blocked timer state".to_owned())?;
        if updates != 1 {
            return Err("operator fixture did not block exactly one timer occurrence".to_owned());
        }
        Ok(())
    }

    /// Stop every child before cleaning the database. On failure, the bounded
    /// and value-checked logs are retained and their directory is returned.
    pub async fn finish(mut self, succeeded: bool) -> Result<Option<PathBuf>, String> {
        let mut failures = Vec::new();
        for replica in &mut self.replicas {
            if let Err(error) = replica.stop() {
                failures.push(error);
            }
        }
        if let Err(error) = self.assert_logs_safe() {
            failures.push(error);
        }
        if let Some(database) = self.database.take() {
            database.cleanup().await;
        }
        let retained = if succeeded && failures.is_empty() {
            None
        } else {
            self.scratch.take().map(TempDir::keep)
        };
        if failures.is_empty() {
            Ok(retained)
        } else {
            Err(format!(
                "native timer cleanup found {} failure(s); logs retained at {}",
                failures.len(),
                retained
                    .as_deref()
                    .map(Path::display)
                    .map(|path| path.to_string())
                    .unwrap_or_else(|| "<unavailable>".to_owned())
            ))
        }
    }

    fn database(&self) -> &TestDatabase {
        self.database
            .as_ref()
            .expect("native timer database exists until finish")
    }

    fn signal_replica(
        &mut self,
        replica: usize,
        signal: &str,
    ) -> Result<NativeProcessIdentity, String> {
        let replica = self
            .replicas
            .get_mut(replica)
            .ok_or_else(|| "native timer replica does not exist".to_owned())?;
        if replica.stopped
            || replica
                .child
                .try_wait()
                .map_err(|_| "native timer replica status could not be read".to_owned())?
                .is_some()
        {
            return Err("native timer replica is not live for a process signal".to_owned());
        }
        let status = Command::new("/bin/kill")
            .arg(signal)
            .arg(replica.command.pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "native timer process signal could not be sent".to_owned())?;
        if !status.success() {
            return Err("native timer process signal was refused".to_owned());
        }
        Ok(replica.command.clone())
    }

    fn scratch_path(&self) -> &Path {
        self.scratch
            .as_ref()
            .expect("native timer scratch exists until finish")
            .path()
    }

    async fn wait_ready(&mut self, replica: usize) -> Result<(), String> {
        let client = BaseRegistryClient::new(BaseRegistryClientConfig::new(
            self.replicas[replica].base_url.clone(),
        ))
        .map_err(|error| format!("native timer readiness client failed: {error}"))?;
        tokio::time::timeout(READY_TIMEOUT, async {
            loop {
                if let Some(status) = self.replicas[replica]
                    .child
                    .try_wait()
                    .map_err(|_| "native timer replica status could not be read".to_owned())?
                {
                    return Err(format!(
                        "native timer replica exited before readiness with {status}; inspect {}",
                        self.replicas[replica].log_path.display()
                    ));
                }
                if client.ready().await.is_ok() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| {
            format!(
                "native timer replica readiness timed out; inspect {}",
                self.replicas[replica].log_path.display()
            )
        })?
    }

    fn write_runtime_config(
        &self,
        instance_id: &str,
        launch_id: &str,
        listener: SocketAddr,
        metrics_listener: Option<SocketAddr>,
        http_request_milliseconds: u64,
    ) -> Result<PathBuf, String> {
        let replica_root = self.scratch_path().join(launch_id);
        let secrets = replica_root.join("secrets");
        fs::create_dir_all(&secrets)
            .map_err(|_| "native timer secret directory could not be created".to_owned())?;
        set_private_directory_permissions(&replica_root);
        set_private_directory_permissions(&secrets);
        let suffix = self
            .database()
            .runtime_role
            .as_str()
            .strip_prefix("breg_runtime_")
            .ok_or_else(|| "native timer runtime role has an unexpected shape".to_owned())?;
        let database_name = format!("breg_test_{suffix}");
        let password = format!("rs{suffix}password");
        let runtime_url = role_database_url(
            self.database().runtime_role.as_str(),
            &password,
            &database_name,
            &format!("breg-timer-{launch_id}"),
        )?;
        let migration_url = role_database_url(
            self.database().migration_role.as_str(),
            &password,
            &database_name,
            &format!("breg-timer-migration-{launch_id}"),
        )?;
        write_private(&secrets.join("database-url"), runtime_url.as_bytes())?;
        write_private(
            &secrets.join("migration-database-url"),
            migration_url.as_bytes(),
        )?;
        write_private(&secrets.join("audit-key"), &[0x71; 32])?;
        write_private(&secrets.join("cursor-key"), &[0x43; 32])?;
        write_private(&secrets.join("event-key"), &[0x65; 32])?;
        let private = PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
            .expect("test signing key parses");
        write_private(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(&private))
                .expect("static timer JWKS serializes"),
        )?;
        let audit_path = replica_root.join("audit.jsonl");
        let config_path = replica_root.join("runtime.yaml");
        let metrics_listener = metrics_listener.map_or_else(String::new, |bind| {
            format!("metricsListener:\n  bind: {bind}\n")
        });
        let config = format!(
            r#"apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: {listener}
{metrics_listener}identity:
  environment: {ENVIRONMENT}
  instanceId: {instance_id}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: {ENVIRONMENT}
secretProviders:
  file:
    root: {secret_root}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  testOnlyPlaintext: true
  pool:
    maximumConnections: 4
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {migration_role}
    runtime: {runtime_role}
package:
  root: {package_root}
authentication:
  oidc:
    issuer: https://auth.example.test
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: unrestricted
    maximumTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      type: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maximumDocumentBytes: 65536
      attemptTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: purpose
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit_path}
cursor:
  secretRef: secret:file/cursor-key
  maximumAgeSeconds: 300
destinations:
  hooks:
    service-events:
      origin: https://consumer.example/
      path: /events
      networkProfile: production-https
      dnsFamily: dual-stack-strict
      allowedPrivateCidrs: []
      hmacSha256KeyRef: secret:file/event-key
      classificationCeiling: internal
      deliveryCeilings:
        attemptTimeoutMilliseconds: 1000
        maximumAttempts: 2
operationalTimeouts:
  httpRequestMilliseconds: {http_request_milliseconds}
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
            secret_root = secrets.display(),
            migration_role = self.database().migration_role.as_str(),
            runtime_role = self.database().runtime_role.as_str(),
            package_root = self.package_root.display(),
            audit_path = audit_path.display(),
        );
        write_private(&config_path, config.as_bytes())?;
        Ok(config_path)
    }

    fn assert_logs_safe(&self) -> Result<(), String> {
        for replica in &self.replicas {
            let metadata = fs::metadata(&replica.log_path)
                .map_err(|_| "native timer process log metadata is unavailable".to_owned())?;
            if metadata.len() > MAX_LOG_BYTES {
                return Err("native timer process log exceeded its acceptance bound".to_owned());
            }
            let mut bytes = Vec::new();
            File::open(&replica.log_path)
                .and_then(|file| file.take(MAX_LOG_BYTES + 1).read_to_end(&mut bytes))
                .map_err(|_| "native timer process log could not be read".to_owned())?;
            let rendered = String::from_utf8_lossy(&bytes);
            let mut pg_stat_unavailable = 0;
            let mut non_info_codes = std::collections::BTreeMap::new();
            for line in rendered.lines() {
                let record: serde_json::Value = serde_json::from_str(line)
                    .map_err(|_| "native timer process log is not JSON Lines".to_owned())?;
                let level = record
                    .get("level")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "native timer process log omitted its level".to_owned())?;
                let code = record
                    .pointer("/fields/code")
                    .and_then(serde_json::Value::as_str);
                if code == Some("postgres.pg_stat_statements.unavailable") {
                    pg_stat_unavailable += 1;
                }
                if matches!(level, "WARN" | "ERROR") {
                    *non_info_codes
                        .entry(code.unwrap_or("<none>").to_owned())
                        .or_insert(0) += 1;
                }
            }
            if non_info_codes
                .keys()
                .any(|code| !replica.expected_non_info_codes.contains_key(code))
                || replica
                    .expected_non_info_codes
                    .iter()
                    .any(|(code, (minimum, maximum))| {
                        let actual = non_info_codes.get(code).copied().unwrap_or(0);
                        actual < *minimum || actual > *maximum
                    })
            {
                return Err(format!(
                    "native timer process log warning/error codes differed: expected_ranges={:?}, actual={non_info_codes:?}",
                    replica.expected_non_info_codes
                ));
            }
            if pg_stat_unavailable > 1 {
                return Err(
                    "native timer log repeated the pg_stat_statements availability diagnostic"
                        .to_owned(),
                );
            }
            println!(
                "record-timer-native instance_id={} diagnostic=postgres.pg_stat_statements.unavailable count={pg_stat_unavailable}",
                replica.command.instance_id
            );
            let suffix = self
                .database()
                .runtime_role
                .as_str()
                .strip_prefix("breg_runtime_")
                .ok_or_else(|| "native timer runtime role has an unexpected shape".to_owned())?;
            let database_password = format!("rs{suffix}password");
            for forbidden in [
                self.token.as_str(),
                "native future activation canary",
                "unrelated edit after native timer completion",
                "unrelated write completed during timer contention",
                "timer-first stale writer canary",
                database_password.as_str(),
            ] {
                if rendered.contains(forbidden) {
                    return Err("native timer process log exposed a protected value".to_owned());
                }
            }
        }
        Ok(())
    }
}

fn validate_checkpoint_marker(
    replica: &NativeReplica,
    barrier: &NativeBarrierFiles,
    occurrence_id: Uuid,
) -> Result<(), String> {
    let marker = read_checkpoint_marker(replica, barrier)?;
    if marker.occurrence_id != occurrence_id {
        return Err(format!(
            "native timer checkpoint did not identify the expected occurrence: {marker:?}"
        ));
    }
    Ok(())
}

fn read_checkpoint_marker(
    replica: &NativeReplica,
    barrier: &NativeBarrierFiles,
) -> Result<BeforeClaimMarker, String> {
    let bytes = fs::read(&barrier.observed)
        .map_err(|_| "native timer checkpoint marker could not be read".to_owned())?;
    if bytes.len() > 1024 {
        return Err("native timer checkpoint marker exceeded its bound".to_owned());
    }
    let marker: BeforeClaimMarker = serde_json::from_slice(&bytes)
        .map_err(|_| "native timer checkpoint marker is invalid".to_owned())?;
    let canonical = registry_platform_canonical_json::canonicalize_json(
        &serde_json::to_value(&marker)
            .map_err(|_| "native timer checkpoint marker could not be encoded".to_owned())?,
    )
    .map_err(|_| "native timer checkpoint marker could not be canonicalized".to_owned())?;
    if bytes != canonical {
        return Err("native timer checkpoint marker was not canonical JSON".to_owned());
    }
    if marker.instance_id != replica.command.instance_id || marker.process_id != replica.command.pid
    {
        return Err(format!(
            "native timer checkpoint did not identify the expected process: {marker:?}"
        ));
    }
    Ok(marker)
}

fn validate_mutation_checkpoint_marker(
    replica: &NativeReplica,
    barrier: &NativeOperationBarrierFiles,
    expected_operation: &str,
) -> Result<(), String> {
    let bytes = fs::read(&barrier.observed)
        .map_err(|_| "native mutation checkpoint marker could not be read".to_owned())?;
    if bytes.len() > 1024 {
        return Err("native mutation checkpoint marker exceeded its bound".to_owned());
    }
    let marker: MutationCheckpointMarker = serde_json::from_slice(&bytes)
        .map_err(|_| "native mutation checkpoint marker is invalid".to_owned())?;
    let canonical = registry_platform_canonical_json::canonicalize_json(
        &serde_json::to_value(&marker)
            .map_err(|_| "native mutation checkpoint marker could not be encoded".to_owned())?,
    )
    .map_err(|_| "native mutation checkpoint marker could not be canonicalized".to_owned())?;
    if bytes != canonical {
        return Err("native mutation checkpoint marker was not canonical JSON".to_owned());
    }
    if marker.instance_id != replica.command.instance_id
        || marker.process_id != replica.command.pid
        || marker.operation != expected_operation
    {
        return Err(format!(
            "native mutation checkpoint did not identify the expected process and operation: {marker:?}"
        ));
    }
    Ok(())
}

impl NativeReplica {
    fn stop(&mut self) -> Result<(), String> {
        if self.stopped {
            return Ok(());
        }
        if self
            .child
            .try_wait()
            .map_err(|_| "native timer replica status could not be read".to_owned())?
            .is_none()
        {
            self.child
                .kill()
                .map_err(|_| "native timer replica could not be stopped".to_owned())?;
        }
        self.child
            .wait()
            .map_err(|_| "native timer replica could not be reaped".to_owned())?;
        self.stopped = true;
        Ok(())
    }
}

impl Drop for NativeReplica {
    fn drop(&mut self) {
        if !self.stopped && self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        if !self.stopped {
            let _ = self.child.wait();
        }
    }
}

impl Drop for NativeTimerHarness {
    fn drop(&mut self) {
        for replica in &mut self.replicas {
            let _ = replica.stop();
        }
        if std::thread::panicking() {
            if let Some(scratch) = self.scratch.take() {
                let _ = scratch.keep();
            }
        }
    }
}

fn reschedule_batch_request(
    binding: &BRegBatchBinding,
    records: &[BRegComplete<RegistryRecordSingleResponse>],
    due_at: chrono::DateTime<Utc>,
) -> Result<BRegBatchRequest, String> {
    if records.len() != 2 {
        return Err("native timer bulk fixture requires exactly two Records".to_owned());
    }
    let mut builder = BRegBatchBuilder::new(binding);
    for record in records {
        let record_id = Uuid::parse_str(&record.value.data.record_identifier)
            .map_err(|_| "timer Batch Record identifier was not a UUID".to_owned())?;
        let etag = record
            .metadata
            .etag()
            .ok_or_else(|| "timer Batch Record omitted its ETag".to_owned())?;
        let patch = reschedule_patch(due_at)?;
        builder = builder
            .patch(record_id, etag, &patch)
            .map_err(|error| format!("timer Batch item was invalid: {error}"))?;
    }
    builder
        .build()
        .map_err(|error| format!("timer Batch request was invalid: {error}"))
}

fn reschedule_ingestion_items(
    records: &[BRegComplete<RegistryRecordSingleResponse>],
    due_at: chrono::DateTime<Utc>,
) -> Result<Vec<serde_json::Value>, String> {
    if records.len() != 2 {
        return Err("native timer ingestion fixture requires exactly two Records".to_owned());
    }
    let not_after = due_at + chrono::Duration::seconds(30);
    records
        .iter()
        .map(|record| {
            let record_id = Uuid::parse_str(&record.value.data.record_identifier)
                .map_err(|_| "timer ingestion Record identifier was not a UUID".to_owned())?;
            let etag = record
                .metadata
                .etag()
                .ok_or_else(|| "timer ingestion Record omitted its ETag".to_owned())?;
            Ok(json!({
                "operation": "patch",
                "recordId": record_id,
                "ifMatch": etag.as_str(),
                "patch": [
                    {
                        "op": "replace",
                        "path": "/data/activatesAt",
                        "value": due_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                    },
                    {
                        "op": "replace",
                        "path": "/data/activationNotAfter",
                        "value": not_after.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                    },
                    {
                        "op": "replace",
                        "path": "/data/activationRevision",
                        "value": Uuid::new_v4()
                    }
                ]
            }))
        })
        .collect()
}

fn reschedule_patch(due_at: chrono::DateTime<Utc>) -> Result<BRegPatchRequest, String> {
    let not_after = due_at + chrono::Duration::seconds(30);
    BRegPatchRequest::builder()
        .replace(
            "activatesAt",
            json!(due_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
        )
        .map_err(|error| format!("timer bulk reschedule patch was invalid: {error}"))?
        .replace(
            "activationNotAfter",
            json!(not_after.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
        )
        .map_err(|error| format!("timer bulk reschedule patch was invalid: {error}"))?
        .replace("activationRevision", json!(Uuid::new_v4()))
        .map_err(|error| format!("timer bulk reschedule patch was invalid: {error}"))?
        .build()
        .map_err(|error| format!("timer bulk reschedule patch was invalid: {error}"))
}

fn bulk_timer_project_bytes(project_bytes: &[u8]) -> Vec<u8> {
    let project =
        std::str::from_utf8(project_bytes).expect("public future-activation project is UTF-8");
    let tombstone = "    tombstone: true\n";
    let operations = "          operations: [create, get, list, patch, tombstone]\n";
    assert_eq!(
        project.matches(tombstone).count(),
        1,
        "public future-activation project has one Record type"
    );
    assert_eq!(
        project.matches(operations).count(),
        1,
        "public future-activation project has one service-editor operation list"
    );
    project
        .replacen(
            tombstone,
            "    tombstone: true\n    batch: {maximumItems: 2, maximumBytes: 32768}\n",
            1,
        )
        .replacen(
            operations,
            "          operations: [create, get, list, patch, tombstone, batch]\n",
            1,
        )
        .into_bytes()
}

#[cfg(feature = "tooling")]
fn timer_free_project_bytes(project_bytes: &[u8]) -> Vec<u8> {
    let mut project = std::str::from_utf8(project_bytes)
        .expect("public future-activation project is UTF-8")
        .to_owned();
    let timer_start = project
        .find("    timers:\n")
        .expect("public future-activation project has a timer block");
    let hooks_start = timer_start
        + project[timer_start..]
            .find("    hooks:\n")
            .expect("public future-activation project has a hooks block after its timer");
    project.replace_range(timer_start..hooks_start, "");

    let grants_start = project
        .find("timerGrants:\n")
        .expect("public future-activation project has timer grants");
    let profiles_start = project[grants_start..]
        .find("accessProfiles:\n")
        .map(|offset| grants_start + offset)
        .expect("public future-activation project has access profiles after its Actions");
    project.replace_range(grants_start..profiles_start, "");
    project.into_bytes()
}

fn business_refusal_project_bytes(project_bytes: &[u8]) -> Vec<u8> {
    let project =
        std::str::from_utf8(project_bytes).expect("public future-activation project is UTF-8");
    let paused_field =
        "      - {id: paused, type: boolean, required: true, classification: internal}\n";
    let permission_field = "            - paused\n";
    let operation_input =
        "      - {id: operation-id, type: uuid, required: true, classification: internal}\n";
    assert_eq!(
        project.matches(paused_field).count(),
        1,
        "public future-activation project has one paused field"
    );
    assert_eq!(
        project.matches(permission_field).count(),
        2,
        "public future-activation project exposes paused through read and write authority"
    );
    assert_eq!(
        project.matches(operation_input).count(),
        1,
        "public future-activation project has one timer operation input"
    );
    project
        .replacen(
            paused_field,
            concat!(
                "      - {id: paused, type: boolean, required: true, classification: internal}\n",
                "      - {id: approved, type: boolean, required: true, classification: internal}\n"
            ),
            1,
        )
        .replacen(
            permission_field,
            "            - paused\n            - approved\n",
            2,
        )
        .replacen(
            operation_input,
            concat!(
                "      - {id: operation-id, type: uuid, required: true, classification: internal}\n",
                "    commitGuards:\n",
                "      targets:\n",
                "        - {input: service, field: approved, equals: true, reason: service-not-approved}\n"
            ),
            1,
        )
        .into_bytes()
}

fn fairness_project_bytes(project_bytes: &[u8]) -> Vec<u8> {
    let mut project = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(project_bytes)
        .expect("public future-activation project scans")
        .expect("public future-activation project has one document")
        .to_json_value();

    let datasets = project["datasets"]
        .as_array_mut()
        .expect("public future-activation datasets are an array");
    let mut cases = datasets
        .first()
        .expect("public future-activation has one dataset")
        .clone();
    cases["id"] = json!("cases");
    cases["display"]["label"] = json!("Cases");
    cases["display"]["description"] =
        json!("Synthetic future-effective case records used for fairness proof.");
    datasets.push(cases);

    let record_types = project["recordTypes"]
        .as_array_mut()
        .expect("public future-activation Record types are an array");
    let mut case = record_types
        .first()
        .expect("public future-activation has one Record type")
        .clone();
    case["id"] = json!("case");
    case["route"] = json!("cases");
    case["primaryDataset"] = json!("cases");
    case["display"]["label"] = json!("Case");
    case["display"]["description"] =
        json!("A second future-effective Record type used for fairness proof.");
    case["timers"][0]["invoke"] = json!("activate-case");
    case["hooks"][0]["id"] = json!("case-activated-v1");
    record_types.push(case);

    let timer_grants = project["timerGrants"]
        .as_array_mut()
        .expect("public future-activation timer grants are an array");
    let mut case_grant = timer_grants
        .first()
        .expect("public future-activation has one timer grant")
        .clone();
    case_grant["recordType"] = json!("case");
    timer_grants.push(case_grant);

    let actions = project["actions"]
        .as_array_mut()
        .expect("public future-activation Actions are an array");
    let mut case_action = actions
        .first()
        .expect("public future-activation has one Action")
        .clone();
    case_action["id"] = json!("activate-case");
    case_action["display"]["label"] = json!("Activate case");
    case_action["display"]["description"] =
        json!("Materialize a previously authorized future case activation.");
    case_action["inputs"][0]["target"] = json!("case");
    case_action["plan"]["effects"][0]["id"] = json!("activated-case");
    actions.push(case_action);

    let permissions = project["accessProfiles"][0]["permissions"]["records"]
        .as_array_mut()
        .expect("public future-activation Record permissions are an array");
    let mut case_permission = permissions
        .first()
        .expect("public future-activation has one Record permission")
        .clone();
    case_permission["recordType"] = json!("case");
    permissions.push(case_permission);

    serde_json::to_vec(&project).expect("fairness project serializes")
}

fn publish_package(
    parent: &Path,
    label: &str,
    project_bytes: &[u8],
    journey_bytes: &[u8],
    schema_fingerprint: String,
) -> PathBuf {
    let project = parse_project_yaml(project_bytes).expect("timer project parses for packaging");
    let source_revision = project
        .package
        .as_ref()
        .expect("native timer package identity exists")
        .source_revision
        .clone();
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: source_revision,
        schema_fingerprint,
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes.to_vec(),
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: journey_bytes.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("native timer package prepares");
    let root = parent.join(format!("package-{label}"));
    prepared
        .publish_to_directory(&root)
        .expect("native timer package publishes");
    root
}

#[cfg(feature = "tooling")]
fn reviewed_predicate_successor_project_bytes() -> Vec<u8> {
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/future-activation");
    let source = fs::read_to_string(fixture_root.join("registry.yaml"))
        .expect("public future-activation project reads as UTF-8");
    let predecessor_gate = "equals: {status: scheduled, paused: false}";
    assert_eq!(
        source.matches(predecessor_gate).count(),
        1,
        "public future-activation project has one timer predicate"
    );
    source
        .replacen(
            predecessor_gate,
            "equals: {status: scheduled, paused: true}",
            1,
        )
        .into_bytes()
}

#[cfg(feature = "tooling")]
// The package fixture keeps predecessor and successor identities explicit so
// a test cannot accidentally derive one side from the other.
#[allow(clippy::too_many_arguments)]
fn publish_successor_package(
    parent: &Path,
    project_bytes: &[u8],
    journey_bytes: &[u8],
    successor_schema_fingerprint: String,
    predecessor_schema_fingerprint: String,
    predecessor_digest: &str,
    predecessor_registry: CompiledRegistry,
    review: ReviewedMigrationSource,
) -> Result<PathBuf, String> {
    let project = parse_project_yaml(project_bytes)
        .map_err(|_| "native timer successor project did not parse for packaging".to_owned())?;
    let source_revision = project
        .package
        .as_ref()
        .ok_or_else(|| "native timer successor package identity was absent".to_owned())?
        .source_revision
        .clone();
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: Some(predecessor_digest.to_owned()),
        compiler_source_revision: source_revision,
        schema_fingerprint: successor_schema_fingerprint,
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes.to_vec(),
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: journey_bytes.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(predecessor_registry),
            prior_schema_fingerprint: predecessor_schema_fingerprint,
            migrations: vec![review],
        },
    })
    .map_err(|error| format!("native timer reviewed successor did not prepare: {error}"))?;
    let root = parent.join("package-reviewed-successor");
    prepared
        .publish_to_directory(&root)
        .map_err(|error| format!("native timer reviewed successor did not publish: {error}"))?;
    Ok(root)
}

#[cfg(feature = "tooling")]
fn metadata_only_review_source(
    changes: &[registry_breg::package::CompiledRegistryChange],
    predecessor_digest: &str,
    predecessor_schema_fingerprint: &str,
    successor_schema_fingerprint: &str,
) -> Result<ReviewedMigrationSource, String> {
    let reviewed_classes = changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(|change| change.class)
        .collect::<std::collections::BTreeSet<_>>();
    if reviewed_classes
        != std::collections::BTreeSet::from([CompiledRegistryChangeClass::AccessOrDisclosureChange])
    {
        return Err(format!(
            "native timer successor required unexpected reviewed classes: {reviewed_classes:?}"
        ));
    }
    let mut covers = changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    if covers.is_empty() {
        return Err("native timer successor did not require reviewed coverage".to_owned());
    }
    let base = "modules/core/migrations/timer-predicate";
    let descriptor = ReviewedMigrationDescriptor {
        id: "timer-predicate".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 2_000,
        statement_timeout_ms: 5_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = registry_platform_canonical_json::canonicalize_json(
        &serde_json::to_value(descriptor)
            .map_err(|_| "native timer review descriptor did not serialize".to_owned())?,
    )
    .map_err(|_| "native timer review descriptor did not canonicalize".to_owned())?;
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: predecessor_digest.to_owned(),
        prior_schema_fingerprint: predecessor_schema_fingerprint.to_owned(),
        plan_sha256: format!(
            "sha256:{}",
            lowercase_hex(Sha256::digest(&descriptor_bytes).as_slice())
        ),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 17,
        row_assertions: Vec::new(),
        final_schema_fingerprint: successor_schema_fingerprint.to_owned(),
    };
    let receipt_bytes = registry_platform_canonical_json::canonicalize_json(
        &serde_json::to_value(receipt)
            .map_err(|_| "native timer rehearsal receipt did not serialize".to_owned())?,
    )
    .map_err(|_| "native timer rehearsal receipt did not canonicalize".to_owned())?;
    Ok(ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: format!("{base}/rehearsal.json"),
            bytes: receipt_bytes,
        }],
    })
}

#[cfg(feature = "tooling")]
async fn measure_compiled_schema(registry: &CompiledRegistry) -> Result<String, String> {
    let database = TestDatabase::create(2).await;
    let (migration, task) = database.connect_migration().await;
    let result = async {
        install_compiled_schema(&migration, registry, &database.runtime_role)
            .await
            .map_err(|_| "native timer successor measurement schema did not install".to_owned())?;
        managed_schema_fingerprint(
            &migration,
            &database.runtime_role,
            &ExpectedManagedCatalog::compiled(registry),
        )
        .await
        .map_err(|_| "native timer successor schema fingerprint did not measure".to_owned())
    }
    .await;
    drop(migration);
    task.abort();
    database.cleanup().await;
    result
}

#[cfg(feature = "tooling")]
fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn package_context() -> PackageLoadContext<'static> {
    PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    }
}

fn signed_token() -> String {
    let now = Utc::now().timestamp();
    sign_ed25519_compact_jwt(
        testing_fixtures::ED25519_PRIVATE_JWK,
        "JWT",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": "https://auth.example.test",
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "scope": "registry:services:write",
            "registry_actor_kind": "service",
            "registry_principal": "native-timer-editor",
            "purpose": "service-administration",
            "jurisdiction": "zone-a"
        }),
    )
}

fn role_database_url(
    role: &str,
    password: &str,
    database: &str,
    application_name: &str,
) -> Result<String, String> {
    let mut url = Url::parse(
        &std::env::var("BREG_TEST_DATABASE_URL")
            .map_err(|_| "BREG_TEST_DATABASE_URL is required for native timer tests".to_owned())?,
    )
    .map_err(|_| "BREG_TEST_DATABASE_URL is invalid".to_owned())?;
    url.set_username(role)
        .map_err(|_| "native timer database role could not be encoded".to_owned())?;
    url.set_password(Some(password))
        .map_err(|_| "native timer database credential could not be encoded".to_owned())?;
    url.set_path(&format!("/{database}"));
    url.query_pairs_mut()
        .append_pair("application_name", application_name);
    Ok(url.to_string())
}

fn read_bounded_audit_entries(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err("native operator audit could not be read".to_owned()),
    };
    if bytes.len() > MAX_LOG_BYTES as usize {
        return Err("native operator audit exceeded its acceptance bound".to_owned());
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| "native operator audit was not UTF-8".to_owned())?
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|_| "native operator audit was not JSON Lines".to_owned())
        })
        .collect()
}

fn read_bounded_text(path: &Path, label: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|_| format!("{label} could not be read"))?;
    if bytes.len() > MAX_LOG_BYTES as usize {
        return Err(format!("{label} exceeded the acceptance bound"));
    }
    String::from_utf8(bytes).map_err(|_| format!("{label} was not UTF-8"))
}

fn available_loopback_address() -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|_| "native timer loopback port reservation failed".to_owned())?;
    let address = listener
        .local_addr()
        .map_err(|_| "native timer loopback address could not be read".to_owned())?;
    drop(listener);
    Ok(address)
}

fn private_log(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| "native timer process log could not be created".to_owned())?;
    set_private_file_permissions(path);
    Ok(file)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes)
        .map_err(|_| "native timer private fixture file could not be written".to_owned())?;
    set_private_file_permissions(path);
    Ok(())
}

fn set_private_directory_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("native timer directory permissions set");
    }
}

fn set_private_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("native timer private file permissions set");
    }
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}
