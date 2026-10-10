// SPDX-License-Identifier: Apache-2.0
//! Coordinator-owned durable rows, driven by the shared Dispatch lease engine.

use crate::{
    definition::{Definition, Step},
    protected_state::StateKeys,
    protocol::CallRequest,
    CoordinatorError, Result,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use registry_platform_audit::{AuditEntry, AuditProfile, AuditWriter};
use registry_platform_dispatch::postgres::{
    enqueue, AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection,
    DispatchEvent, DispatchSql, DispatchStore, Dispatcher, Disposition, ExpirySql, JobKey,
    JobState, JobTable, LeasedJob, ReplayAudit, SelectSql, TargetAction, Transition,
    TransitionAudit, TransitionOutcome,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, DispatchError, JobPolicy, RetrySchedule, UncertainOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_postgres::{Client, NoTls, Row, Transaction};
use uuid::Uuid;

mod readiness;
mod recovery;
pub use recovery::DoctorStatus;

enum InspectionBinding<'a> {
    RecordedOrRuntime(&'a crate::runtime::RuntimeConfig),
    Supplied(&'a str),
}

pub(crate) const SCHEMA_VERSION: i32 = 4;

const NAMESPACE_MARKER: &str = "registry-coordinator/v2 protected-state";

pub(crate) const AUDIT_SCHEMA: &str = "registry-coordinator/audit/v1";

const JOIN: &str = "JOIN {schema}.runs AS run ON run.run_id = state.run_id JOIN {schema}.control AS control ON control.id";
const SELECT: SelectSql = SelectSql {
    columns: "run.snapshot, run.input, run.outputs, run.deadline_at, run.binding_digest, state.command, state.uncertain, state.receipt_expired, run.deadline_at > transaction_timestamp(), state.pure, run.start_identity, run.cancel_requested, control.restore_hold, run.owner_hash, run.restore_review_required",
    joins: JOIN, predicate: "true",
};

#[derive(Clone)]
pub struct Store {
    config: tokio_postgres::Config,
    database: String,
    namespace: String,
    table: JobTable,
    replay_binding: Option<String>,
    replay_actor: Option<Actor>,
    security: Arc<StoreSecurity>,
    tls: Option<tokio_postgres_rustls::MakeRustlsConnect>,
    package_digest: Option<String>,
}

/// Construct only from a token verified and authorized by the service boundary.
#[derive(Clone)]
pub struct Actor {
    pub issuer: String,
    pub subject: String,
    pub client_id: String,
    pub operator: bool,
}

pub struct StoreSecurity {
    pub database_id: String,
    pub keys: StateKeys,
    pub audit: AuditWriter,
    pub audit_profile: AuditProfile,
}

/// Safe progress metadata plus the workflow author's declared terminal output.
/// Source records, prepared commands, raw admission keys and credentials are omitted.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunStatus {
    pub run_id: Uuid,
    pub workflow_id: String,
    pub workflow_version: String,
    pub definition_digest: String,
    pub binding_digest: String,
    pub step: String,
    pub state: String,
    pub outcome: Option<String>,
    pub output: Option<Value>,
    pub failure_code: Option<String>,
    pub admitted_at: DateTime<Utc>,
    pub deadline_at: DateTime<Utc>,
    pub next_due_at: Option<DateTime<Utc>>,
    pub uncertain: bool,
    pub restore_review_required: bool,
    pub cancel_requested: bool,
}

/// Bounded durable step state from Dispatch, without prepared request contents.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StepStatus {
    pub step: String,
    pub state: String,
    pub generation: i64,
    pub attempt: i16,
    pub next_due_at: Option<DateTime<Utc>>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub command_prepared: bool,
    pub uncertain: bool,
    pub receipt_expired: bool,
    pub failure_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetryBlockReason {
    NotRecoverable,
    DeadlineReached,
    ReceiptExpired,
    BindingChanged,
    OtherBindingLive,
    SnapshotIncompatible,
    Cancelled,
    RestoreHold,
    RestoreReviewRequired,
    PayloadErased,
    EvaluationUncertain,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatus {
    pub retry_allowed: bool,
    pub reason: Option<RetryBlockReason>,
    /// Pinned public contract, not proof of current downstream authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<crate::operations::OperationIdentity>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunInspection {
    pub run: RunStatus,
    pub steps: Vec<StepStatus>,
    pub recovery: RecoveryStatus,
}

#[derive(Clone)]
#[doc(hidden)]
pub struct Job {
    pub snapshot: Value,
    pub input: Value,
    pub outputs: Value,
    pub deadline_at: DateTime<Utc>,
    pub binding_digest: String,
    pub command: Option<Value>,
    pub uncertain: bool,
    pub receipt_expired: bool,
    pub before_deadline: bool,
    pub pure: bool,
    pub start_identity: String,
    pub cancel_requested: bool,
    pub restore_hold: bool,
    pub owner_hash: String,
    pub restore_review_required: bool,
}

pub(crate) struct Payload {
    pub snapshot: String,
    pub input: Value,
    pub outputs: BTreeMap<String, Value>,
    pub command: Option<FrozenCommand>,
}

/// The exact command frozen before dispatch. An operation that requires
/// preparation additionally carries opaque evidence owned by its client;
/// these bytes never contain credentials and never grant current authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FrozenCommand {
    request: CallRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preparation: Option<Vec<u8>>,
}

impl FrozenCommand {
    pub(crate) fn new(request: CallRequest, preparation: Option<Vec<u8>>) -> Self {
        Self {
            request,
            preparation,
        }
    }

    pub(crate) fn request(&self) -> &CallRequest {
        &self.request
    }

    pub(crate) fn preparation(&self) -> Option<&[u8]> {
        self.preparation.as_deref()
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct Detail {
    pub next: Option<String>,
    pub output: Option<Value>,
    pub outcome: Option<String>,
    pub failure_code: Option<&'static str>,
    pub uncertain: bool,
    pub receipt_expired: bool,
}
impl Detail {
    pub(crate) fn failure(code: &'static str, uncertain: bool) -> Self {
        Self {
            next: None,
            output: None,
            outcome: None,
            failure_code: Some(code),
            uncertain,
            receipt_expired: false,
        }
    }
}

fn unavailable(_: impl std::fmt::Display) -> CoordinatorError {
    CoordinatorError::new(
        "coordinator.command.store-unavailable",
        "durable state is unavailable",
    )
}
fn refused(code: &'static str, message: &'static str) -> CoordinatorError {
    CoordinatorError::new(code, message)
}

impl Store {
    /// Test-only harness. Production callers must supply explicit custody
    /// and a durable audit writer through `open`.
    #[cfg(feature = "postgres-test")]
    pub async fn connect(database_url: &str, namespace: &str) -> Result<Self> {
        Self::open(
            database_url,
            namespace,
            StoreSecurity {
                database_id: namespace.to_owned(),
                keys: StateKeys::new(1, BTreeMap::from([(1, [0x11; 32])]), [0x22; 32])?,
                audit: AuditWriter::from_line_sink(Box::new(std::io::sink())),
                audit_profile: AuditProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
                    vec![0x33; 32],
                ))
                .map_err(unavailable)?,
            },
            None,
        )
        .await
    }

    pub async fn open(
        database_url: &str,
        namespace: &str,
        security: StoreSecurity,
        tls: Option<tokio_postgres_rustls::MakeRustlsConnect>,
    ) -> Result<Self> {
        if !namespace.starts_with("coordinator_") || namespace.len() > 60 {
            return Err(refused(
                "coordinator.command.namespace-invalid",
                "use a dedicated coordinator_ lowercase SQL namespace",
            ));
        }
        let table = JobTable::new(namespace, "jobs", "run_id", "step").map_err(unavailable)?;
        let config: tokio_postgres::Config = database_url.parse().map_err(unavailable)?;
        let local = !config.get_hosts().is_empty()
            && config.get_hosts().iter().all(|host| match host {
                tokio_postgres::config::Host::Tcp(name) => {
                    name == "localhost"
                        || name
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                }
                #[cfg(unix)]
                tokio_postgres::config::Host::Unix(_) => true,
            });
        if tls.is_none() && !local
            || tls.is_some() && config.get_ssl_mode() != tokio_postgres::config::SslMode::Require
        {
            return Err(refused("coordinator.command.database-tls-required", "use verified TLS with sslmode=require for PostgreSQL; plaintext is restricted to an explicit local connection"));
        }
        if security.database_id.is_empty() || security.database_id.len() > 128 {
            return Err(refused(
                "coordinator.command.database-identity-invalid",
                "configure a bounded persistent deployment database identity",
            ));
        }
        let database = config
            .get_dbname()
            .ok_or_else(|| {
                refused(
                    "coordinator.command.database-invalid",
                    "name the PostgreSQL database explicitly",
                )
            })?
            .to_owned();
        let store = Self {
            config,
            database,
            namespace: namespace.into(),
            table,
            replay_binding: None,
            replay_actor: None,
            security: Arc::new(security),
            tls,
            package_digest: None,
        };
        let client = store.client().await.map_err(unavailable)?;
        let version: i32 = client
            .query_one("SELECT current_setting('server_version_num')::integer", &[])
            .await
            .map_err(unavailable)?
            .get(0);
        if version < 170000 {
            return Err(refused(
                "coordinator.command.database-version",
                "PostgreSQL 17 or later is required",
            ));
        }
        Ok(store)
    }

    pub fn with_package_digest(mut self, digest: String) -> Self {
        self.package_digest = Some(digest);
        self
    }

    pub(crate) async fn client(&self) -> std::result::Result<Client, DispatchError> {
        let client = if let Some(tls) = &self.tls {
            let (client, connection) = self.config.connect(tls.clone()).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        } else {
            let (client, connection) = self.config.connect(NoTls).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        };
        client
            .batch_execute(&format!(
                "SET search_path TO {}, pg_catalog",
                self.namespace
            ))
            .await?;
        Ok(client)
    }

    #[cfg(feature = "postgres-test")]
    pub async fn migrate(&self) -> Result<()> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.migrate_in(&tx).await?;
        tx.commit().await.map_err(unavailable)
    }

    pub(crate) async fn migrate_in(&self, tx: &Transaction<'_>) -> Result<()> {
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            &[&self.namespace],
        )
        .await
        .map_err(unavailable)?;
        let marker = tx
            .query_opt(
                "SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname=$1",
                &[&self.namespace],
            )
            .await
            .map_err(unavailable)?;
        match marker {
            Some(row) if row.get::<_, Option<String>>(0).as_deref() != Some(NAMESPACE_MARKER) => {
                return Err(refused(
                    "coordinator.command.namespace-occupied",
                    "choose an unused Coordinator namespace; existing data was not changed",
                ));
            }
            Some(_) => {}
            None => self.create_in(tx).await?,
        }
        // Activation, admission and replay all take this guard before control.
        tx.query_one(
            &format!(
                "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
                self.namespace
            ),
            &[],
        )
        .await
        .map_err(unavailable)?;
        let custody=tx.query_one(&format!("SELECT database_id,admission_key_commitment,state_key_commitments,schema_version FROM {}.control WHERE id FOR UPDATE",self.namespace),&[]).await.map_err(unavailable)?;
        if custody.get::<_, String>(0) != self.security.database_id
            || custody.get::<_, String>(1) != self.admission_key_marker()
        {
            return Err(refused("coordinator.command.state-key-custody","preserve the deployment database identity and stable admission key; recover original custody before apply"));
        }
        // A store is created at one revision and is never changed in place.
        if custody.get::<_, i32>(3) != SCHEMA_VERSION {
            return Err(refused(
                "coordinator.command.schema-version",
                "this database records another Coordinator schema revision; apply to a new database, existing data was not changed",
            ));
        }
        self.security.keys.verify_custody(
            &self.security.database_id,
            &custody.get::<_, Value>(2),
            true,
        )?;
        tx.execute(
            &format!(
                "UPDATE {}.control SET state_key_commitments=state_key_commitments || $1 WHERE id",
                self.namespace
            ),
            &[&self
                .security
                .keys
                .custody_markers(&self.security.database_id)],
        )
        .await
        .map_err(unavailable)?;
        self.verify_transaction(tx).await.map_err(unavailable)?;
        Ok(())
    }

    /// Create every relation of an unused namespace at the current revision.
    async fn create_in(&self, tx: &Transaction<'_>) -> Result<()> {
        tx.batch_execute(&format!("CREATE SCHEMA {0}; COMMENT ON SCHEMA {0} IS '{1}';
            CREATE TABLE {0}.control (
            id boolean PRIMARY KEY CHECK(id), database_id text NOT NULL, schema_version integer NOT NULL CHECK(schema_version={2}),
            restore_hold boolean NOT NULL DEFAULT false, admissions_hold boolean NOT NULL DEFAULT false, restore_evidence_hash text, admission_recovery_hash text, active_package_digest text, admission_key_commitment text NOT NULL, state_key_commitments jsonb NOT NULL);
            CREATE TABLE {0}.runs (
            run_id uuid PRIMARY KEY, start_identity text UNIQUE NOT NULL, input_digest text NOT NULL, owner_hash text NOT NULL,
            workflow_id text NOT NULL, workflow_version text NOT NULL, definition_digest text NOT NULL,
            snapshot jsonb, input jsonb, outputs jsonb,
            binding_digest text NOT NULL, step text NOT NULL, state text NOT NULL DEFAULT 'running',
            outcome text, terminal_output jsonb, failure_code text, admitted_at timestamptz NOT NULL, deadline_at timestamptz NOT NULL,
            cancel_requested boolean NOT NULL DEFAULT false, restore_review_required boolean NOT NULL DEFAULT false, completed_at timestamptz, payload_erased_at timestamptz);
            CREATE TABLE {0}.admission_lock (id boolean PRIMARY KEY CHECK(id));
            INSERT INTO {0}.admission_lock VALUES(true)", self.namespace, NAMESPACE_MARKER, SCHEMA_VERSION)).await.map_err(unavailable)?;
        for sql in self.table.create_statements() {
            tx.batch_execute(&sql).await.map_err(unavailable)?;
        }
        // The job table admits one state beside the shared Dispatch shape: a
        // dead-lettered hold of a step that prepared no command and made no attempt.
        tx.batch_execute(&format!(
            "ALTER TABLE {0}.jobs ADD COLUMN command jsonb,
            ADD COLUMN uncertain boolean NOT NULL DEFAULT false,
            ADD COLUMN receipt_expired boolean NOT NULL DEFAULT false,
            ADD COLUMN pure boolean NOT NULL DEFAULT false,
            ADD COLUMN failure_code text;
            ALTER TABLE {0}.jobs DROP CONSTRAINT jobs_shape;
            ALTER TABLE {0}.jobs ADD CONSTRAINT jobs_shape CHECK (({1}) OR (
                state='dead-lettered' AND attempt=0 AND command IS NULL
                AND NOT uncertain AND NOT receipt_expired
                AND next_attempt_at IS NULL AND attempt_started_at IS NULL
                AND lease_expires_at IS NULL AND lease_token IS NULL
                AND delivered_at IS NULL AND expired_at IS NULL
                AND dead_lettered_at IS NOT NULL
                AND failure_code IS NOT DISTINCT FROM 'restore-pre-command-held'))",
            self.namespace,
            JobTable::shape_predicate()
        ))
        .await
        .map_err(unavailable)?;
        tx.execute(&format!("INSERT INTO {}.control(id,database_id,schema_version,admission_key_commitment,state_key_commitments) VALUES(true,$1,{},$2,$3)",self.namespace,SCHEMA_VERSION), &[&self.security.database_id,&self.admission_key_marker(),&self.security.keys.custody_markers(&self.security.database_id)]).await.map_err(unavailable)?;
        Ok(())
    }

    fn seal<T: Serialize>(&self, run: Uuid, purpose: &str, step: &str, value: &T) -> Result<Value> {
        self.security.keys.seal(
            &self.security.database_id,
            &run.to_string(),
            purpose,
            step,
            value,
        )
    }
    fn open_value<T: serde::de::DeserializeOwned>(
        &self,
        run: Uuid,
        purpose: &str,
        step: &str,
        value: &Value,
    ) -> Result<T> {
        self.security.keys.open(
            &self.security.database_id,
            &run.to_string(),
            purpose,
            step,
            value,
        )
    }
    pub(crate) fn payload(&self, run: Uuid, step: &str, job: &Job) -> Result<Payload> {
        Ok(Payload {
            snapshot: self.open_value(run, "snapshot", "", &job.snapshot)?,
            input: self.open_value(run, "input", "", &job.input)?,
            outputs: self.open_value(run, "outputs", "", &job.outputs)?,
            command: job
                .command
                .as_ref()
                .map(|value| self.open_value(run, "command", step, value))
                .transpose()?,
        })
    }
    fn admission_key_marker(&self) -> String {
        self.security.keys.commitment(
            "admission-key-custody",
            &[self.security.database_id.as_bytes()],
        )
    }
    pub(crate) fn command_key(&self, start_identity: &str, step: &str) -> String {
        self.security.keys.commitment(
            "command",
            &[
                self.security.database_id.as_bytes(),
                start_identity.as_bytes(),
                step.as_bytes(),
            ],
        )
    }

    pub async fn admit(
        &self,
        definition: &Definition,
        input: Value,
        producer: &str,
        key: &str,
        binding_digest: &str,
    ) -> Result<Uuid> {
        self.admit_bound(definition, input, producer, key, binding_digest, None)
            .await
    }

    async fn admit_bound(
        &self,
        definition: &Definition,
        input: Value,
        producer: &str,
        key: &str,
        binding_digest: &str,
        runtime: Option<&crate::runtime::RuntimeConfig>,
    ) -> Result<Uuid> {
        if producer.is_empty()
            || key.is_empty()
            || producer.len() > 256
            || key.len() > 256
            || binding_digest.is_empty()
            || binding_digest.len() > 256
        {
            return Err(refused(
                "coordinator.command.admission-invalid",
                "producer, start key and binding digest must be bounded nonempty values",
            ));
        }
        crate::functions::check_value(&input).map_err(|_| {
            refused(
                "coordinator.command.input-invalid",
                "input must fit the documented structured value bounds",
            )
        })?;
        let input_bytes = zeroize::Zeroizing::new(
            registry_platform_canonical_json::canonicalize_json(&input).map_err(|_| {
                refused(
                    "coordinator.command.input-invalid",
                    "input must have an unambiguous canonical JSON representation",
                )
            })?,
        );
        let identity = self.security.keys.commitment(
            "start",
            &[
                self.security.database_id.as_bytes(),
                producer.as_bytes(),
                definition.workflow.id.as_bytes(),
                key.as_bytes(),
            ],
        );
        let input_digest = self
            .security
            .keys
            .commitment("input", &[identity.as_bytes(), &input_bytes]);
        let snapshot = definition.snapshot()?;
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        tx.query_one(
            &format!(
                "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
                self.namespace
            ),
            &[],
        )
        .await
        .map_err(unavailable)?;
        let held: bool = tx
            .query_one(
                &format!(
                    "SELECT admissions_hold FROM {}.control WHERE id FOR SHARE",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?
            .get(0);
        if held {
            return Err(refused("coordinator.command.restore-admissions-held","recover complete admission history before enabling starts; inspect known runs while ingress is held"));
        }
        if let Some(runtime) = runtime {
            self.check_live_bindings(&tx, runtime).await?;
        }
        self.check_definition_history(&tx, definition).await?;
        if let Some(row) = tx
            .query_opt(
                &format!(
                    "SELECT run_id,input_digest FROM {}.runs WHERE start_identity=$1",
                    self.namespace
                ),
                &[&identity],
            )
            .await
            .map_err(unavailable)?
        {
            if row.get::<_, String>(1) != input_digest {
                return Err(refused(
                    "coordinator.command.start-conflict",
                    "this producer, workflow and start key already names different admitted work",
                ));
            }
            // A retry of admission belongs to its first run, irrespective of a
            // newer supplied version or that version's input schema.
            return Ok(row.get(0));
        }
        definition.validate_input(&input)?;
        self.require_unheld(&tx).await?;
        let now: DateTime<Utc> = tx
            .query_one("SELECT transaction_timestamp()", &[])
            .await
            .map_err(unavailable)?
            .get(0);
        let deadline = definition.deadline_at(now)?;
        let due = definition.initial_due(&input, now)?;
        let run = Uuid::new_v4();
        let sealed_snapshot = self.seal(run, "snapshot", "", &snapshot)?;
        let sealed_input = self.seal(run, "input", "", &input)?;
        let sealed_outputs = self.seal(run, "outputs", "", &BTreeMap::<String, Value>::new())?;
        tx.execute(&format!("INSERT INTO {}.runs (run_id,start_identity,input_digest,workflow_id,workflow_version,definition_digest,snapshot,input,binding_digest,step,admitted_at,deadline_at,outputs,owner_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", self.namespace), &[&run, &identity, &input_digest, &definition.workflow.id, &definition.workflow.version, &definition.digest, &sealed_snapshot, &sealed_input, &binding_digest, &definition.workflow.start, &now, &deadline, &sealed_outputs, &producer]).await.map_err(unavailable)?;
        enqueue(
            &tx,
            &self.table,
            &JobKey::new(run, definition.workflow.start.clone()).map_err(unavailable)?,
            due.map(SystemTime::from),
        )
        .await
        .map_err(unavailable)?;
        let pure = matches!(
            definition.workflow.steps.get(&definition.workflow.start),
            Some(Step::Choose { .. } | Step::Finish { .. })
        );
        tx.execute(
            &format!(
                "UPDATE {}.jobs SET pure=$3 WHERE run_id=$1 AND step=$2",
                self.namespace
            ),
            &[&run, &definition.workflow.start, &pure],
        )
        .await
        .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(run)
    }

    async fn require_unheld(&self, tx: &Transaction<'_>) -> Result<()> {
        let row = tx
            .query_one(
                &format!(
                    "SELECT restore_hold,active_package_digest FROM {}.control WHERE id FOR SHARE",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?;
        let held: bool = row.get(0);
        if self
            .package_digest
            .as_ref()
            .is_some_and(|expected| row.get::<_, Option<String>>(1).as_ref() != Some(expected))
        {
            return Err(refused(
                "coordinator.command.activation-changed",
                "start the service with the currently activated package",
            ));
        }
        if held {
            return Err(refused("coordinator.command.restore-hold", "execution is held until the prior deployment is externally fenced and recovery is reviewed"));
        }
        Ok(())
    }

    fn status_select(&self) -> String {
        format!("SELECT r.workflow_id,r.workflow_version,r.definition_digest,r.binding_digest,r.step,CASE WHEN r.restore_review_required THEN 'attention' WHEN r.cancel_requested THEN r.state WHEN r.state='finished' THEN 'finished' WHEN j.state IN ('pending','leased') THEN 'running' WHEN j.state='unknown' THEN 'attention' WHEN j.state='expired' THEN 'expired' WHEN j.state='dead-lettered' THEN 'failed' ELSE r.state END,r.outcome,r.failure_code,r.admitted_at,r.deadline_at,j.next_attempt_at,j.uncertain,r.terminal_output,r.run_id,r.restore_review_required,r.cancel_requested FROM {}.runs r JOIN {}.jobs j ON j.run_id=r.run_id AND j.step=r.step", self.namespace, self.namespace)
    }

    pub async fn status(&self, run: Uuid) -> Result<RunStatus> {
        let client = self.client().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                &format!("{} WHERE r.run_id=$1", self.status_select()),
                &[&run],
            )
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused("coordinator.command.run-absent", "run was not found"))?;
        self.status_from_row(&row)
    }

    /// Most recently admitted runs. The bound also limits authored final outputs.
    pub async fn list_runs(&self, limit: u32) -> Result<Vec<RunStatus>> {
        if !(1..=100).contains(&limit) {
            return Err(refused(
                "coordinator.command.list-limit-invalid",
                "choose a run list limit between 1 and 100",
            ));
        }
        let client = self.client().await.map_err(unavailable)?;
        let rows = client
            .query(
                &format!(
                    "{} ORDER BY r.admitted_at DESC,r.run_id DESC LIMIT $1",
                    self.status_select()
                ),
                &[&i64::from(limit)],
            )
            .await
            .map_err(unavailable)?;
        rows.iter().map(|row| self.status_from_row(row)).collect()
    }

    /// A consistent, read-only view of progress and whether same-command recovery
    /// is available under the caller's current configured binding.
    pub async fn inspect(&self, run: Uuid, current_binding_digest: &str) -> Result<RunInspection> {
        self.inspect_bound(run, InspectionBinding::Supplied(current_binding_digest))
            .await
    }

    async fn inspect_runtime(
        &self,
        run: Uuid,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<RunInspection> {
        self.inspect_bound(run, InspectionBinding::RecordedOrRuntime(runtime))
            .await
    }

    async fn inspect_bound(
        &self,
        run: Uuid,
        binding: InspectionBinding<'_>,
    ) -> Result<RunInspection> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(unavailable)?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        let row = tx
            .query_opt(
                &format!("{} WHERE r.run_id=$1", self.status_select()),
                &[&run],
            )
            .await
            .map_err(unavailable)?
            .ok_or_else(|| refused("coordinator.command.run-absent", "run was not found"))?;
        let status = self.status_from_row(&row)?;
        let rows = tx.query(&format!("SELECT step,state,generation,attempt,next_attempt_at,lease_expires_at,command IS NOT NULL,uncertain,receipt_expired,failure_code FROM {}.jobs WHERE run_id=$1 ORDER BY updated_at,step LIMIT 65", self.namespace), &[&run]).await.map_err(unavailable)?;
        if rows.len() > 64 {
            return Err(refused(
                "coordinator.command.run-state-invalid",
                "durable step state exceeds the workflow bound",
            ));
        }
        let steps = rows
            .iter()
            .map(|row| StepStatus {
                step: row.get(0),
                state: row.get(1),
                generation: row.get(2),
                attempt: row.get(3),
                next_due_at: row.get(4),
                lease_expires_at: row.get(5),
                command_prepared: row.get(6),
                uncertain: row.get(7),
                receipt_expired: row.get(8),
                failure_code: row.get(9),
            })
            .collect::<Vec<_>>();
        let row = tx.query_one(&format!("SELECT r.snapshot,j.state,j.receipt_expired,j.pure OR r.deadline_at>transaction_timestamp(),r.cancel_requested,r.payload_erased_at, (SELECT restore_hold FROM {0}.control WHERE id), ({1}) AND NOT r.restore_review_required FROM {0}.runs r JOIN {0}.jobs j ON j.run_id=r.run_id AND j.step=r.step WHERE r.run_id=$1", self.namespace,self.terminal_retention_predicate()), &[&run]).await.map_err(unavailable)?;
        // Only genuinely settled terminal history may use its recorded binding.
        // Decide inside this same repeatable-read inspection, never from a stale
        // HTTP status label. Recovery targets must still resolve current bindings.
        let current_binding_digest = match binding {
            InspectionBinding::Supplied(digest) => digest.to_owned(),
            InspectionBinding::RecordedOrRuntime(_) if row.get::<_, bool>(7) => {
                status.binding_digest.clone()
            }
            InspectionBinding::RecordedOrRuntime(runtime) => {
                let sealed: Option<Value> = row.get(0);
                let snapshot: String = self.open_value(
                    run,
                    "snapshot",
                    "",
                    sealed.as_ref().ok_or_else(|| {
                        refused(
                            "coordinator.command.payload-erased",
                            "this run retains only its spent-key tombstone",
                        )
                    })?,
                )?;
                let definition = Definition::from_snapshot(&snapshot)?;
                runtime.binding_digest_for(&definition.workflow).map_err(|error| error.suggest("restore this run's original connections before inspecting or recovering unresolved work"))?
            }
        };
        let snapshot: Option<Value> = row.get(0);
        let definition = snapshot
            .as_ref()
            .and_then(|value| self.open_value::<String>(run, "snapshot", "", value).ok())
            .and_then(|snapshot| Definition::from_snapshot(&snapshot).ok());
        let operation = definition.as_ref().and_then(|definition| {
            match definition.workflow.steps.get(&status.step) {
                Some(Step::Call { call, .. }) => Some(call.operation.identity()),
                _ => None,
            }
        });
        let reason = if row.get::<_, Option<DateTime<Utc>>>(5).is_some() {
            Some(RetryBlockReason::PayloadErased)
        } else if status.binding_digest != current_binding_digest {
            Some(RetryBlockReason::BindingChanged)
        } else if row.get::<_, bool>(2) {
            Some(RetryBlockReason::ReceiptExpired)
        } else if !row.get::<_, bool>(3) {
            Some(RetryBlockReason::DeadlineReached)
        } else if status.restore_review_required {
            Some(RetryBlockReason::RestoreReviewRequired)
        } else if row.get::<_, bool>(4) {
            Some(RetryBlockReason::Cancelled)
        } else if row.get::<_, bool>(6) {
            Some(RetryBlockReason::RestoreHold)
        } else if definition.is_none() {
            Some(RetryBlockReason::SnapshotIncompatible)
        } else if status.uncertain
            && operation.as_ref().is_some_and(|operation| {
                operation.recovery == crate::protocol::RecoverySemantics::HoldAfterDispatch
            })
        {
            Some(RetryBlockReason::EvaluationUncertain)
        } else if !matches!(
            row.get::<_, String>(1).as_str(),
            "unknown" | "dead-lettered"
        ) {
            Some(RetryBlockReason::NotRecoverable)
        } else {
            None
        };
        tx.commit().await.map_err(unavailable)?;
        Ok(RunInspection {
            run: status,
            steps,
            recovery: RecoveryStatus {
                retry_allowed: reason.is_none(),
                reason,
                operation,
            },
        })
    }

    pub async fn retry_same(&self, run: Uuid, binding_digest: &str) -> Result<()> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        let status = self.status(run).await?;
        if status.binding_digest != binding_digest {
            return Err(refused(
                "coordinator.command.binding-conflict",
                "retry requires the original connection binding",
            ));
        }
        let row = tx
            .query_one(
                &format!(
                    "SELECT j.receipt_expired,j.generation,r.snapshot,j.uncertain FROM {}.jobs j JOIN {}.runs r ON r.run_id=j.run_id WHERE j.run_id=$1 AND j.step=$2",
                    self.namespace,self.namespace
                ),
                &[&run, &status.step],
            )
            .await
            .map_err(unavailable)?;
        if row.get::<_, bool>(0) {
            return Err(refused(
                "coordinator.command.receipt-expired",
                "receipt recovery expired; this run remains held for attention",
            ));
        }
        let sealed: Option<Value> = row.get(2);
        let snapshot: String = self.open_value(
            run,
            "snapshot",
            "",
            sealed.as_ref().ok_or_else(|| {
                refused(
                    "coordinator.command.payload-erased",
                    "only the spent-key tombstone is retained",
                )
            })?,
        )?;
        let definition = Definition::from_snapshot(&snapshot).map_err(|_| refused("coordinator.command.definition-incompatible", "this binary cannot safely interpret the pinned run snapshot; retain its compatible worker"))?;
        if row.get::<_, bool>(3)
            && matches!(definition.workflow.steps.get(&status.step), Some(Step::Call {call, ..}) if !call.operation.can_retry_after_unknown())
        {
            return Err(refused("coordinator.command.evaluation-uncertain", "the evaluation may have completed remotely; preserve its original request and inspect or cancel the held run without reevaluating"));
        }
        let generation: i64 = row.get(1);
        tx.commit().await.map_err(unavailable)?;
        let mut replay_store = self.clone();
        replay_store.replay_binding = Some(binding_digest.to_owned());
        replay_store
            .dispatcher()?
            .replay(
                &JobKey::new(run, status.step).map_err(unavailable)?,
                generation,
            )
            .await
            .map_err(|_| {
                refused(
                    "coordinator.command.retry-refused",
                    "only held work before its deadline can retry its original command",
                )
            })?;
        Ok(())
    }

    pub(crate) fn dispatcher(&self) -> Result<Dispatcher<Self>> {
        Dispatcher::new(
            self.clone(),
            DispatchConfig {
                table: self.table.clone(),
                sql: DispatchSql {
                    claim: SelectSql {predicate:"NOT control.restore_hold AND NOT run.restore_review_required AND NOT run.cancel_requested AND run.payload_erased_at IS NULL",..SELECT},
                    lapsed: SELECT,
                    expiry: Some(ExpirySql {
                        states: &[JobState::Pending],
                        select: SelectSql {
                            predicate:
                                "NOT state.pure AND run.deadline_at <= transaction_timestamp()",
                            ..SELECT
                        },
                        order_by: "run.deadline_at",
                        lock_of: "state",
                    }),
                    target: SELECT,
                },
                attempt_timeout: AttemptTimeoutBound::new(
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .map_err(unavailable)?,
                replayable: &[JobState::Unknown, JobState::DeadLettered],
            },
        )
        .map_err(unavailable)
    }

    /// Freeze the exact dispatch command under a live fence before any effect.
    pub(crate) async fn freeze(
        &self,
        job: &LeasedJob<Job>,
        command: FrozenCommand,
    ) -> Result<FrozenCommand> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        let fence = job.fence();
        let row = tx.query_opt(&format!("SELECT command FROM {}.jobs WHERE run_id=$1 AND step=$2 AND generation=$3 AND attempt=$4 AND lease_token=$5 AND state='leased' AND lease_expires_at>transaction_timestamp() FOR UPDATE", self.namespace), &[&fence.id, &fence.part, &fence.generation, &fence.attempt, &fence.lease_token]).await.map_err(unavailable)?.ok_or_else(|| refused("coordinator.command.lease-stale", "the worker no longer owns this step"))?;
        let existing: Option<Value> = row.get(0);
        let value = if let Some(value) = existing {
            value
        } else {
            let value = self.seal(fence.id, "command", fence.part, &command)?;
            tx.execute(
                &format!(
                    "UPDATE {}.jobs SET command=$3 WHERE run_id=$1 AND step=$2",
                    self.namespace
                ),
                &[&fence.id, &fence.part, &value],
            )
            .await
            .map_err(unavailable)?;
            value
        };
        tx.commit().await.map_err(unavailable)?;
        self.open_value(fence.id, "command", fence.part, &value)
    }

    async fn apply_success(
        &self,
        tx: &Transaction<'_>,
        id: Uuid,
        step: &str,
        payload: Payload,
        detail: &Detail,
        cancelled: bool,
    ) -> std::result::Result<bool, DispatchError> {
        let definition =
            Definition::from_snapshot(&payload.snapshot).map_err(|_| DispatchError::Unavailable)?;
        // A delivered local timer wake is not an accepted product effect. The
        // run is locked by write_attempt: check fresh database time here, not
        // the claim's captured deadline, before enqueueing even pure successors.
        // Actual accepted calls retain their receipt finalization semantics.
        if !cancelled
            && matches!(definition.workflow.steps.get(step), Some(Step::WaitUntil { .. }))
            && tx
                .execute(
                    &format!(
                        "UPDATE {}.runs SET state='expired',failure_code='deadline-reached',completed_at=clock_timestamp() WHERE run_id=$1 AND deadline_at<=clock_timestamp()",
                        self.namespace
                    ),
                    &[&id],
                )
                .await?
                > 0
        {
            return Ok(false);
        }
        let dispatch_risk = matches!(definition.workflow.steps.get(step),Some(Step::Call{call,..}) if call.operation.has_dispatch_risk());
        let mut outputs = payload.outputs;
        if let Some(value) = &detail.output {
            outputs.insert(step.to_owned(), value.clone());
        }
        // A known successful step must commit even when the authored mapping
        // for its following wait is invalid. Keep the delivered step current;
        // no runnable wait job or replayable mutation is created on failure.
        let mut mapping_failed = false;
        let due = if !cancelled {
            match detail
                .next
                .as_deref()
                .map(|next| definition.workflow.steps.get(next))
            {
                Some(Some(Step::WaitUntil { .. })) => {
                    let mapped = definition
                        .evaluate(detail.next.as_deref().unwrap(), &payload.input, &outputs)
                        .ok()
                        .and_then(|value| {
                            value
                                .as_str()
                                .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
                        });
                    match mapped {
                        Some(value) => Some(SystemTime::from(value.with_timezone(&Utc))),
                        None => {
                            mapping_failed = true;
                            None
                        }
                    }
                }
                Some(None) => return Err(DispatchError::Unavailable),
                _ => None,
            }
        } else {
            None
        };
        let next = if cancelled || mapping_failed {
            step
        } else {
            detail.next.as_deref().unwrap_or(step)
        };
        let state = if cancelled && dispatch_risk {
            "cancelled-after-effect"
        } else if cancelled {
            "cancelled"
        } else if mapping_failed {
            "failed"
        } else if detail.outcome.is_some() {
            "finished"
        } else {
            "running"
        };
        let failure_code = mapping_failed.then_some("mapping-invalid");
        let terminal = if !cancelled && detail.outcome.is_some() {
            detail
                .output
                .as_ref()
                .map(|v| self.seal(id, "terminal", "", v))
                .transpose()
                .map_err(|_| DispatchError::Unavailable)?
        } else {
            None
        };
        tx.execute(&format!("UPDATE {}.runs SET outputs=$2,step=$3,state=$4,outcome=$5,terminal_output=$6,failure_code=$7,completed_at=CASE WHEN $4<>'running' THEN transaction_timestamp() ELSE NULL END WHERE run_id=$1",self.namespace),&[&id,&self.seal(id,"outputs","",&outputs).map_err(|_|DispatchError::Unavailable)?,&next,&state,&if cancelled{None}else{detail.outcome.as_deref()},&terminal,&failure_code]).await?;
        if !cancelled && !mapping_failed {
            if let Some(next) = &detail.next {
                enqueue(
                    tx,
                    &self.table,
                    &JobKey::new(id, next).map_err(|_| DispatchError::Unavailable)?,
                    due,
                )
                .await?;
                let pure = matches!(
                    definition.workflow.steps.get(next),
                    Some(Step::Choose { .. } | Step::Finish { .. })
                );
                tx.execute(
                    &format!(
                        "UPDATE {}.jobs SET pure=$3 WHERE run_id=$1 AND step=$2",
                        self.namespace
                    ),
                    &[&id, &next, &pure],
                )
                .await?;
            }
        }
        Ok(mapping_failed)
    }

    pub(crate) async fn before_io(
        &self,
        job: &LeasedJob<Job>,
        dispatch_risk: bool,
    ) -> Result<bool> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        // Hold control through the intent commit so restore/cancel races have a
        // truthful winner; effects already past this fence remain uncertain.
        match self.require_unheld(&tx).await {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.code.as_str(),
                    "coordinator.command.restore-hold" | "coordinator.command.activation-changed"
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
        let fence = job.fence();
        let row=tx.query_opt(&format!("SELECT r.cancel_requested OR r.restore_review_required,r.deadline_at>clock_timestamp() FROM {}.jobs j JOIN {}.runs r ON r.run_id=j.run_id WHERE j.run_id=$1 AND j.step=$2 AND j.generation=$3 AND j.attempt=$4 AND j.lease_token=$5 AND j.state='leased' AND j.lease_expires_at>clock_timestamp() FOR UPDATE OF j,r",self.namespace,self.namespace),&[&fence.id,&fence.part,&fence.generation,&fence.attempt,&fence.lease_token]).await.map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(false);
        };
        if row.get::<_, bool>(0) || !row.get::<_, bool>(1) {
            return Ok(false);
        }
        if dispatch_risk {
            tx.execute(
                &format!(
                    "UPDATE {}.jobs SET uncertain=true WHERE run_id=$1 AND step=$2",
                    self.namespace
                ),
                &[&fence.id, &fence.part],
            )
            .await
            .map_err(unavailable)?;
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(true)
    }
}

impl Store {
    fn status_from_row(&self, row: &Row) -> Result<RunStatus> {
        Ok(RunStatus {
            run_id: row.get(13),
            workflow_id: row.get(0),
            workflow_version: row.get(1),
            definition_digest: row.get(2),
            binding_digest: row.get(3),
            step: row.get(4),
            state: row.get(5),
            outcome: row.get(6),
            failure_code: row.get(7),
            admitted_at: row.get(8),
            deadline_at: row.get(9),
            next_due_at: row.get(10),
            uncertain: row.get(11),
            restore_review_required: row.get(14),
            cancel_requested: row.get(15),
            output: row
                .get::<_, Option<Value>>(12)
                .as_ref()
                .map(|value| self.open_value(row.get(13), "terminal", "", value))
                .transpose()?,
        })
    }
}

fn decode(row: &Row, first: usize) -> std::result::Result<Job, DispatchError> {
    let command: Option<Value> = row.try_get(first + 5)?;
    Ok(Job {
        snapshot: row.try_get(first)?,
        input: row.try_get(first + 1)?,
        outputs: row.try_get(first + 2)?,
        deadline_at: row.try_get(first + 3)?,
        binding_digest: row.try_get(first + 4)?,
        command,
        uncertain: row.try_get(first + 6)?,
        receipt_expired: row.try_get(first + 7)?,
        before_deadline: row.try_get(first + 8)?,
        pure: row.try_get(first + 9)?,
        start_identity: row.try_get(first + 10)?,
        cancel_requested: row.try_get(first + 11)?,
        restore_hold: row.try_get(first + 12)?,
        owner_hash: row.try_get(first + 13)?,
        restore_review_required: row.try_get(first + 14)?,
    })
}
fn policy(job: &Job) -> JobPolicy {
    // A task-grant read can use four sequential two-second HTTP exchanges.
    // Dispatch owns the additional five-second lease finalization allowance.
    JobPolicy {
        attempt_timeout: Duration::from_secs(10),
        maximum_attempts: 3,
        retry: RetrySchedule::Frozen {
            delays_ms: vec![100, 500],
        },
        on_uncertain: UncertainOutcome::Hold,
        expires_at: (!job.pure).then(|| job.deadline_at.into()),
    }
}

#[async_trait]
impl DispatchStore for Store {
    type Job = Job;
    type Record = Job;
    type Detail = Detail;
    type Context = Uuid;
    fn capture_context(&self) -> Uuid {
        Uuid::new_v4()
    }
    async fn connection(&self) -> std::result::Result<DispatchConnection, DispatchError> {
        Ok(Box::new(Box::new(self.client().await?)))
    }
    async fn verify_transaction(
        &self,
        tx: &Transaction<'_>,
    ) -> std::result::Result<(), DispatchError> {
        let database: String = tx.query_one("SELECT current_database()", &[]).await?.get(0);
        if database != self.database {
            return Err(DispatchError::Unavailable);
        }
        let row = tx
            .query_one(
                &format!(
                    "SELECT database_id,schema_version,active_package_digest,admission_key_commitment,state_key_commitments FROM {}.control WHERE id",
                    self.namespace
                ),
                &[],
            )
            .await?;
        if row.get::<_, String>(0) != self.security.database_id
            || row.get::<_, i32>(1) != SCHEMA_VERSION
            || row.get::<_, String>(3) != self.admission_key_marker()
            || self
                .package_digest
                .as_ref()
                .is_some_and(|expected| row.get::<_, Option<String>>(2).as_ref() != Some(expected))
        {
            return Err(DispatchError::Unavailable);
        }
        self.security
            .keys
            .verify_custody(&self.security.database_id, &row.get::<_, Value>(4), false)
            .map_err(|_| DispatchError::Unavailable)?;
        if self.replay_binding.is_some() {
            // The replay-only clone acquires this lock in Dispatch's owned
            // transaction, so caller cancellation cannot release it early.
            // Admission and replay take this lock before any job lock; ordinary
            // worker transactions never acquire it.
            tx.query_one(
                &format!(
                    "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
                    self.namespace
                ),
                &[],
            )
            .await?;
            self.require_unheld(tx)
                .await
                .map_err(|_| DispatchError::Unavailable)?;
        }
        Ok(())
    }
    fn decode_claim(
        &self,
        row: &Row,
        first: usize,
    ) -> std::result::Result<Decoded<Job>, ClaimRefusal> {
        let job = decode(row, first).map_err(|_| ClaimRefusal::Unavailable)?;
        Ok(Decoded {
            policy: policy(&job),
            job,
        })
    }
    fn claim_record(&self, job: &Job) -> Job {
        job.clone()
    }
    fn decode_lapsed(
        &self,
        row: &Row,
        first: usize,
    ) -> std::result::Result<Decoded<Job>, DispatchError> {
        let job = decode(row, first)?;
        Ok(Decoded {
            policy: policy(&job),
            job,
        })
    }
    fn decode_expired(&self, row: &Row, first: usize) -> std::result::Result<Job, DispatchError> {
        decode(row, first)
    }
    fn decode_expired_on_uncertain(
        &self,
        _: &Row,
        _: usize,
    ) -> std::result::Result<UncertainOutcome, DispatchError> {
        Ok(UncertainOutcome::RetryThenHold)
    }
    fn decode_target(
        &self,
        row: &Row,
        first: usize,
        key: &JobKey,
        action: TargetAction,
    ) -> std::result::Result<Option<Job>, DispatchError> {
        let job = decode(row, first)?;
        if self.replay_actor.as_ref().is_some_and(|actor| {
            !actor.operator && self.owner(actor).ok().as_deref() != Some(job.owner_hash.as_str())
        }) {
            return Ok(None);
        }
        if self
            .replay_binding
            .as_ref()
            .is_some_and(|binding| binding != &job.binding_digest)
        {
            return Ok(None);
        }
        // Enforce capability under Dispatch's replay fence, not just inspection.
        if matches!(action, TargetAction::Replay) && job.uncertain {
            let payload = self
                .payload(key.id(), key.part(), &job)
                .map_err(|_| DispatchError::Unavailable)?;
            let definition = Definition::from_snapshot(&payload.snapshot)
                .map_err(|_| DispatchError::Unavailable)?;
            if matches!(definition.workflow.steps.get(key.part()), Some(Step::Call {call, ..}) if !call.operation.can_retry_after_unknown())
            {
                return Ok(None);
            }
        }
        if matches!(action, TargetAction::Replay)
            && (job.cancel_requested
                || job.restore_review_required
                || job.restore_hold
                || job.receipt_expired
                || !job.pure && !job.before_deadline)
        {
            return Ok(None);
        }
        Ok(Some(job))
    }
    async fn write_replay(
        &self,
        tx: &Transaction<'_>,
        audit: &ReplayAudit<Job>,
    ) -> std::result::Result<(), DispatchError> {
        let snapshot: String = self
            .open_value(audit.key.id(), "snapshot", "", &audit.record.snapshot)
            .map_err(|_| DispatchError::Unavailable)?;
        let definition =
            Definition::from_snapshot(&snapshot).map_err(|_| DispatchError::Unavailable)?;
        if !matches!(
            definition.workflow.steps.get(audit.key.part()),
            Some(Step::WaitUntil { .. })
        ) {
            return Ok(());
        }
        let payload = self
            .payload(audit.key.id(), audit.key.part(), &audit.record)
            .map_err(|_| DispatchError::Unavailable)?;
        let instant = definition
            .evaluate(audit.key.part(), &payload.input, &payload.outputs)
            .map_err(|_| DispatchError::Unavailable)?;
        let due =
            crate::definition::parse_timestamp(&instant).map_err(|_| DispatchError::Unavailable)?;
        // Replays of held waits must retain their protected authored instant.
        // This runs after Dispatch's reset under the same job/control locks;
        // a refused schedule write cannot leave an immediately runnable job.
        let changed = tx.execute(
            &format!("UPDATE {}.jobs SET next_attempt_at=GREATEST($3::timestamptz,transaction_timestamp()) WHERE run_id=$1 AND step=$2 AND generation=$4 AND state='pending'", self.namespace),
            &[&audit.key.id(), &audit.key.part(), &due, &audit.generation],
        ).await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        Ok(())
    }

    async fn write_attempt(
        &self,
        tx: &Transaction<'_>,
        job: &LeasedJob<Job>,
        audit: AttemptAudit<'_, Detail>,
    ) -> std::result::Result<(), DispatchError> {
        let AttemptAudit::Finished { sent, disposition } = audit else {
            return Ok(());
        };
        let detail = &sent.detail;
        let id = job.key.id();
        let step = job.key.part();
        tx.execute(&format!("UPDATE {}.jobs SET uncertain=$3,receipt_expired=receipt_expired OR $4,failure_code=COALESCE($5,failure_code) WHERE run_id=$1 AND step=$2", self.namespace), &[&id, &step, &detail.uncertain, &detail.receipt_expired, &detail.failure_code]).await?;
        let state = match disposition {
            Disposition::Delivered if detail.outcome.is_some() => "finished",
            Disposition::Delivered | Disposition::RetryPending => "running",
            Disposition::Unknown => "attention",
            Disposition::Expired => "expired",
            _ => "failed",
        };
        let cancelled: bool = tx
            .query_one(
                &format!(
                    "SELECT cancel_requested FROM {}.runs WHERE run_id=$1 FOR UPDATE",
                    self.namespace
                ),
                &[&id],
            )
            .await?
            .get(0);
        if disposition == Disposition::Delivered {
            let payload = self
                .payload(id, step, &job.job)
                .map_err(|_| DispatchError::Unavailable)?;
            self.apply_success(tx, id, step, payload, detail, cancelled)
                .await?;
        } else {
            tx.execute(
                &format!(
                    "UPDATE {}.runs SET state=$2,failure_code=$3,completed_at=CASE WHEN $2 IN ('cancelled','expired','failed') THEN transaction_timestamp() ELSE completed_at END WHERE run_id=$1",
                    self.namespace
                ),
                &[&id, &if cancelled && !detail.uncertain {"cancelled"} else {state}, &detail.failure_code],
            )
            .await?;
        }
        Ok(())
    }
    async fn write_transition(
        &self,
        tx: &Transaction<'_>,
        audit: &TransitionAudit<Job>,
    ) -> std::result::Result<(), DispatchError> {
        let uncertain = audit.record.uncertain;
        let state = if matches!(audit.transition, Transition::Cancelled)
            || audit.record.cancel_requested && !uncertain
        {
            "cancelled"
        } else if !uncertain && matches!(audit.transition, Transition::Expired { .. }) {
            "expired"
        } else {
            "attention"
        };
        tx.execute(
            &format!(
                "UPDATE {}.jobs SET uncertain=$3,failure_code=$4 WHERE run_id=$1 AND step=$2",
                self.namespace
            ),
            &[
                &audit.key.id(),
                &audit.key.part(),
                &uncertain,
                &audit.transition.as_str(),
            ],
        )
        .await?;
        tx.execute(
            &format!(
                "UPDATE {}.runs SET state=$2,failure_code=$3,completed_at=CASE WHEN $2 IN ('cancelled','expired','failed') THEN transaction_timestamp() ELSE completed_at END WHERE run_id=$1",
                self.namespace
            ),
            &[&audit.key.id(), &state, &audit.transition.as_str()],
        )
        .await?;
        Ok(())
    }
    async fn may_have_reached_receiver(
        &self,
        tx: &Transaction<'_>,
        key: &JobKey,
        _: i64,
        _: i16,
    ) -> std::result::Result<bool, DispatchError> {
        Ok(tx
            .query_one(
                &format!(
                    "SELECT uncertain FROM {}.jobs WHERE run_id=$1 AND step=$2",
                    self.namespace
                ),
                &[&key.id(), &key.part()],
            )
            .await?
            .get(0))
    }
    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<Job>,
        audit: AttemptAudit<'_, Detail>,
        context: &Uuid,
    ) -> std::result::Result<(), DispatchError> {
        let (request, outcome) = match audit {
            AttemptAudit::Started => (true, "intent"),
            AttemptAudit::Finished { disposition, .. } => (false, disposition.as_str()),
            AttemptAudit::Interrupted { .. } => (false, "unknown"),
        };
        self.dispatch_audit(
            *context,
            "attempt",
            job.key.id(),
            job.key.part(),
            request,
            outcome,
        )
        .await
    }
    async fn begin_transition_audit(
        &self,
        audit: &TransitionAudit<Job>,
        context: &Uuid,
    ) -> std::result::Result<(), DispatchError> {
        self.dispatch_audit(
            *context,
            audit.transition.as_str(),
            audit.key.id(),
            audit.key.part(),
            true,
            "intent",
        )
        .await
    }
    async fn record_transition_audit(
        &self,
        audit: &TransitionAudit<Job>,
        outcome: TransitionOutcome,
        context: &Uuid,
    ) -> std::result::Result<(), DispatchError> {
        self.dispatch_audit(
            *context,
            audit.transition.as_str(),
            audit.key.id(),
            audit.key.part(),
            false,
            match outcome {
                TransitionOutcome::Committed => "committed",
                TransitionOutcome::Refused => "refused",
                TransitionOutcome::Unfinished => "unknown",
            },
        )
        .await
    }
    async fn record_replay_audit(
        &self,
        audit: &ReplayAudit<Job>,
        context: &Uuid,
    ) -> std::result::Result<(), DispatchError> {
        use registry_platform_dispatch::postgres::ReplayOutcome;
        self.dispatch_audit(
            *context,
            "retry-same",
            audit.key.id(),
            audit.key.part(),
            audit.outcome == ReplayOutcome::Requested,
            match audit.outcome {
                ReplayOutcome::Requested => "intent",
                ReplayOutcome::Committed => "committed",
                ReplayOutcome::Refused => "refused",
                ReplayOutcome::Unfinished => "unknown",
            },
        )
        .await
    }
    fn operational_event(&self, _: DispatchEvent) {}
}

impl Store {
    async fn dispatch_audit(
        &self,
        context: Uuid,
        action: &str,
        run: Uuid,
        step: &str,
        request: bool,
        outcome: &str,
    ) -> std::result::Result<(), DispatchError> {
        let record = serde_json::json!({"action":action,"runRef":self.reference("run-v1",&run.to_string()),"stepRef":self.reference("step-v1",step),"outcome":outcome});
        let correlation = format!("{context}:{action}:{}", self.reference("step-v1", step));
        let entry = if request {
            AuditEntry::request(AUDIT_SCHEMA, correlation, record)
        } else {
            AuditEntry::response(AUDIT_SCHEMA, correlation, record)
        };
        self.security
            .audit
            .append(entry)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Operation;

    #[test]
    fn a_frozen_command_has_one_stored_shape() {
        let request = CallRequest {
            connection: "records".into(),
            operation: Operation::ReadRecord,
            input: serde_json::json!({"recordId": "synthetic"}),
            idempotency_key: None,
        };
        let bare = serde_json::to_value(&request).unwrap();
        assert!(serde_json::from_value::<FrozenCommand>(bare.clone()).is_err());

        let unprepared = serde_json::to_value(FrozenCommand::new(request.clone(), None)).unwrap();
        assert_eq!(unprepared, serde_json::json!({"request": bare}));
        let restored: FrozenCommand = serde_json::from_value(unprepared).unwrap();
        assert!(restored.preparation().is_none());

        let prepared = serde_json::to_value(FrozenCommand::new(request, Some(vec![1, 2]))).unwrap();
        assert_eq!(
            prepared,
            serde_json::json!({"request": bare, "preparation": [1, 2]})
        );
        let restored: FrozenCommand = serde_json::from_value(prepared).unwrap();
        assert_eq!(restored.preparation(), Some(&[1, 2][..]));
    }
}
