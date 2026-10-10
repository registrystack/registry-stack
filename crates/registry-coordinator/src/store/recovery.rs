// SPDX-License-Identifier: Apache-2.0
//! Owned access, cancellation, observation and custody maintenance.
use super::*;
use crate::protocol::{AdapterSet, ReconciliationOutcome};
use registry_platform_audit::AuditRequest;
use serde_json::json;
use std::future::Future;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorStatus {
    pub database_id: String,
    pub schema_version: i32,
    pub restore_hold: bool,
    pub admissions_hold: bool,
    pub restore_review_required: i64,
    pub audit_ready: bool,
    pub states: BTreeMap<String, i64>,
    pub uncertain: i64,
    pub oldest_due_at: Option<DateTime<Utc>>,
    /// Terminal payloads that are safe to erase once the operator's cutoff passes.
    pub terminal_payloads: i64,
    pub oldest_terminal_payload_at: Option<DateTime<Utc>>,
}

impl Store {
    pub fn audit_writer(&self) -> AuditWriter {
        self.security.audit.clone()
    }
    pub(super) fn owner(&self, actor: &Actor) -> Result<String> {
        if [&actor.issuer, &actor.subject, &actor.client_id]
            .iter()
            .any(|v| v.is_empty() || v.len() > 512)
        {
            return Err(refused(
                "access.denied",
                "verified bounded caller identity is required",
            ));
        }
        Ok(self.security.keys.commitment(
            "owner",
            &[
                self.security.database_id.as_bytes(),
                actor.issuer.as_bytes(),
                actor.subject.as_bytes(),
            ],
        ))
    }
    async fn authorize_run(&self, tx: &Transaction<'_>, run: Uuid, actor: &Actor) -> Result<()> {
        self.verify_transaction(tx).await.map_err(unavailable)?;
        let owner = self.owner(actor)?;
        if tx
            .query_opt(
                &format!(
                    "SELECT 1 FROM {}.runs WHERE run_id=$1 AND (owner_hash=$2 OR $3)",
                    self.namespace
                ),
                &[&run, &owner, &actor.operator],
            )
            .await
            .map_err(unavailable)?
            .is_none()
        {
            return Err(refused("run-absent", "run was not found"));
        }
        Ok(())
    }
    fn operator(actor: &Actor) -> Result<()> {
        if !actor.operator {
            return Err(refused(
                "access.denied",
                "this operation requires the configured operator policy",
            ));
        }
        Ok(())
    }
    fn reason(reason: &str) -> Result<()> {
        if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            return Err(refused(
                "reason-invalid",
                "supply a bounded reference to the operation's reason or evidence",
            ));
        }
        Ok(())
    }
    pub(super) fn reference(&self, class: &str, value: &str) -> String {
        self.security
            .audit_profile
            .key_hasher()
            .audit_reference_hash(class, &self.security.database_id, value)
            .expect("static audit class and nonempty reference")
    }
    async fn audit_begin(
        &self,
        action: &str,
        actor: &Actor,
        run: Option<Uuid>,
    ) -> Result<AuditRequest> {
        let owner = self.owner(actor)?;
        self.security.audit.begin(AUDIT_SCHEMA,Uuid::new_v4().to_string(),
            json!({"action":action,"actorRef":self.reference("actor-v1",&owner),"runRef":run.map(|r|self.reference("run-v1",&r.to_string()))}),
            json!({"action":action,"outcome":"unknown"})).await.map_err(|_|refused("audit-unavailable","durable audit is unavailable"))
    }
    async fn audited<T>(
        &self,
        action: &str,
        actor: &Actor,
        run: Option<Uuid>,
        work: impl Future<Output = Result<T>>,
    ) -> Result<T> {
        let request = self.audit_begin(action, actor, run).await?;
        let result = work.await;
        request.finish(json!({"action":action,"outcome":if result.is_ok(){"accepted"}else{"unknown"}})).await.map_err(|_|refused("audit-response-unavailable","the operation may have completed; recover its original identity before trying again"))?;
        result
    }
    pub async fn admit_owned(
        &self,
        definition: &Definition,
        input: Value,
        actor: &Actor,
        key: &str,
        binding: &str,
    ) -> Result<Uuid> {
        self.audited("admit", actor, None, async {
            self.admit(definition, input, &self.owner(actor)?, key, binding)
                .await
        })
        .await
    }
    pub async fn admit_runtime_owned(
        &self,
        definition: &Definition,
        input: Value,
        actor: &Actor,
        key: &str,
        binding: &str,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<Uuid> {
        self.audited("admit", actor, None, async {
            self.admit_bound(
                definition,
                input,
                &self.owner(actor)?,
                key,
                binding,
                Some(runtime),
            )
            .await
        })
        .await
    }

    pub async fn status_owned(&self, run: Uuid, actor: &Actor) -> Result<RunStatus> {
        self.audited("status", actor, Some(run), async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            let row = tx
                .query_one(
                    &format!("{} WHERE r.run_id=$1", self.status_select()),
                    &[&run],
                )
                .await
                .map_err(unavailable)?;
            self.status_from_row(&row)
        })
        .await
    }
    pub async fn definition_owned(&self, run: Uuid, actor: &Actor) -> Result<Definition> {
        self.audited("definition-read", actor, Some(run), async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            let row = tx
                .query_one(
                    &format!(
                        "SELECT snapshot FROM {}.runs WHERE run_id=$1",
                        self.namespace
                    ),
                    &[&run],
                )
                .await
                .map_err(unavailable)?;
            let sealed: Option<Value> = row.get(0);
            let snapshot: String = self.open_value(
                run,
                "snapshot",
                "",
                sealed.as_ref().ok_or_else(|| {
                    refused(
                        "payload-erased",
                        "this terminal run retains only its spent-key tombstone",
                    )
                })?,
            )?;
            Definition::from_snapshot(&snapshot)
        })
        .await
    }
    pub async fn list_owned(
        &self,
        limit: u32,
        actor: &Actor,
        allowed_flows: &[String],
    ) -> Result<Vec<RunStatus>> {
        self.audited("list",actor,None,async {
            if !(1..=100).contains(&limit){return Err(refused("list-limit-invalid","choose a run list limit between 1 and 100"));}
            if allowed_flows.len()>64 || allowed_flows.iter().any(|flow|flow.is_empty() || flow.len()>128){return Err(refused("list-flow-invalid","choose at most 64 bounded nonempty workflow identities"));}
            let mut client=self.client().await.map_err(unavailable)?;
            let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            let rows=tx.query(&format!("{} WHERE (r.owner_hash=$1 OR $2) AND r.workflow_id=ANY($3) ORDER BY r.admitted_at DESC,r.run_id DESC LIMIT $4",self.status_select()),&[&self.owner(actor)?,&actor.operator,&allowed_flows,&i64::from(limit)]).await.map_err(unavailable)?;
            rows.iter().map(|r|self.status_from_row(r)).collect()
        }).await
    }
    pub async fn inspect_owned(
        &self,
        run: Uuid,
        binding: &str,
        actor: &Actor,
    ) -> Result<RunInspection> {
        self.audited("inspect", actor, Some(run), async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            self.inspect(run, binding).await
        })
        .await
    }
    pub async fn inspect_runtime_owned(
        &self,
        run: Uuid,
        runtime: &crate::runtime::RuntimeConfig,
        actor: &Actor,
    ) -> Result<RunInspection> {
        self.audited("inspect", actor, Some(run), async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            self.inspect_runtime(run, runtime).await
        })
        .await
    }

    pub async fn retry_same_owned(
        &self,
        run: Uuid,
        binding: &str,
        actor: &Actor,
        reason: &str,
    ) -> Result<()> {
        Self::reason(reason)?;
        self.audited("retry-same", actor, Some(run), async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            let mut owned = self.clone();
            owned.replay_actor = Some(actor.clone());
            owned.retry_same(run, binding).await
        })
        .await
    }
    /// Stop further progression. An in-flight effect remains uncertain until an
    /// authoritative receipt is observed. Cancellation never undoes a product effect.
    pub async fn cancel_owned(&self, run: Uuid, actor: &Actor, reason: &str) -> Result<RunStatus> {
        Self::reason(reason)?;
        self.audited("cancel",actor,Some(run),async {
            let mut client=self.client().await.map_err(unavailable)?;
            let tx=client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx,run,actor).await?;
            // Match Dispatch's job-then-run lock order. The product stop flag
            // fences every subsequent I/O check and next-step enqueue.
            let row=tx.query_one(&format!("SELECT j.step,j.state,j.uncertain,r.state,r.restore_review_required FROM {}.jobs j JOIN {}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE j.run_id=$1 FOR UPDATE OF j,r",self.namespace,self.namespace),&[&run]).await.map_err(unavailable)?;
            let step:String=row.get(0);let state:String=row.get(1);
            let settled_failure=row.get::<_,String>(3)=="failed" && state=="delivered" && !row.get::<_,bool>(2) && !row.get::<_,bool>(4);
            if !settled_failure && !matches!(row.get::<_,String>(3).as_str(),"finished"|"cancelled"|"cancelled-after-effect") {
                let next=if row.get::<_,bool>(2)||state=="leased"||row.get::<_,bool>(4) {"attention"} else if state=="pending" {"cancel-requested"} else {"cancelled"};
                tx.execute(&format!("UPDATE {}.runs SET cancel_requested=true,state=$2,completed_at=CASE WHEN $2='cancelled' THEN transaction_timestamp() ELSE completed_at END WHERE run_id=$1",self.namespace),&[&run,&next]).await.map_err(unavailable)?;
            }
            tx.commit().await.map_err(unavailable)?;
            if state=="pending" && !row.get::<_,bool>(4) { let _outcome=self.dispatcher()?.cancel(&JobKey::new(run,step).map_err(unavailable)?).await.map_err(unavailable)?; }
            self.status(run).await
        }).await
    }
    pub async fn reconcile_owned(
        &self,
        run: Uuid,
        binding: &str,
        actor: &Actor,
        reason: &str,
        adapters: &dyn AdapterSet,
    ) -> Result<RunInspection> {
        Self::reason(reason)?;
        self.audited("reconcile",actor,Some(run),async {
            let mut client=self.client().await.map_err(unavailable)?;
            let tx=client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx,run,actor).await?;
            let row=tx.query_one(&format!("SELECT r.step,r.snapshot,j.command,j.generation,j.state,r.outputs,r.binding_digest,j.lease_expires_at>clock_timestamp() FROM {}.runs r JOIN {}.jobs j ON j.run_id=r.run_id AND j.step=r.step WHERE r.run_id=$1",self.namespace,self.namespace),&[&run]).await.map_err(unavailable)?;
            let step:String=row.get(0);let generation:i64=row.get(3);
            if row.get::<_,String>(6)!=binding || row.get::<_,String>(4)=="leased" && row.get::<_,Option<bool>>(7).unwrap_or(true){return Err(refused("reconcile-refused","preserve the original binding and wait for the active lease to settle"));}
            let sealed:Option<Value>=row.get(2);
            let command:FrozenCommand=self.open_value(run,"command",&step,sealed.as_ref().ok_or_else(||refused("reconcile-refused","the run has no prepared product command"))?)?;
            if command.request().operation.is_read(){return Err(refused("reconcile-refused","use same-command retry for a read operation"));}
            if !command.request().operation.supports_read_receipt(){return Err(refused("reconciliation-unavailable","this operation has no authoritative original-result lookup; inspect its declared recovery capability or cancel the held run"));}
            let snapshot:String=self.open_value(run,"snapshot","",&row.get::<_,Value>(1))?;
            let definition=Definition::from_snapshot(&snapshot)?;
            let outputs:BTreeMap<String,Value>=self.open_value(run,"outputs","",&row.get::<_,Value>(5))?;
            tx.commit().await.map_err(unavailable)?;
            let observation=tokio::time::timeout(Duration::from_secs(10),adapters.reconcile(command.request(),outputs.get(&step))).await;
            if let Ok(ReconciliationOutcome::Confirmed(value))=observation {
                crate::functions::check_value(&value)?;
                let tx=client.transaction().await.map_err(unavailable)?;
                self.authorize_run(&tx,run,actor).await?;
                // An expired lease may still be persisted in recovery-only mode.
                // Recheck its expiry under the job/run locks so a renewed lease
                // cannot race receipt observation and settle active work.
                let current=tx.query_one(&format!("SELECT j.generation,j.state,r.step,j.command,r.cancel_requested,j.lease_expires_at>clock_timestamp() FROM {}.jobs j JOIN {}.runs r ON r.run_id=j.run_id WHERE j.run_id=$1 AND j.step=$2 FOR UPDATE OF j,r",self.namespace,self.namespace),&[&run,&step]).await.map_err(unavailable)?;
                if current.get::<_,i64>(0)!=generation || current.get::<_,String>(2)!=step || current.get::<_,Option<Value>>(3)!=sealed || current.get::<_,String>(1)=="leased" && current.get::<_,Option<bool>>(5).unwrap_or(true) {
                    return Err(refused("reconcile-raced","run progress changed; inspect its current state"));
                }
                let Some(Step::Call{next,..})=definition.workflow.steps.get(&step) else{return Err(refused("definition-invalid","pinned step is not a product call"));};
                let input_row=tx.query_one(&format!("SELECT input FROM {}.runs WHERE run_id=$1",self.namespace),&[&run]).await.map_err(unavailable)?;
                let input:Value=self.open_value(run,"input","",&input_row.get::<_,Value>(0))?;
                let payload=Payload{snapshot,input,outputs,command:Some(command)};
                let detail=Detail{next:Some(next.clone()),output:Some(value),outcome:None,failure_code:None,uncertain:false,receipt_expired:false};
                let mapping_failed=self.apply_success(&tx,run,&step,payload,&detail,current.get(4)).await.map_err(unavailable)?;
                tx.execute(&format!("UPDATE {}.jobs SET state='delivered',attempt=GREATEST(attempt,1),uncertain=false,next_attempt_at=NULL,attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL,delivered_at=transaction_timestamp(),dead_lettered_at=NULL,expired_at=NULL,failure_code=NULL WHERE run_id=$1 AND step=$2",self.namespace),&[&run,&step]).await.map_err(unavailable)?;
                if mapping_failed || Self::no_external_calls_after(&definition,next) {
                    tx.execute(&format!("UPDATE {}.runs SET restore_review_required=false WHERE run_id=$1",self.namespace),&[&run]).await.map_err(unavailable)?;
                }
                tx.commit().await.map_err(unavailable)?;
            }
            // Missing, expired or unavailable receipts never prove no effect.
            self.inspect(run,binding).await
        }).await
    }
    /// Workflow versions remain bound to one artifact after payload erasure.
    /// Admission and activation both hold admission_lock while checking history.
    pub(crate) async fn check_definition_history(
        &self,
        tx: &Transaction<'_>,
        definition: &Definition,
    ) -> Result<()> {
        if tx.query_opt(&format!("SELECT 1 FROM {}.runs WHERE workflow_id=$1 AND workflow_version=$2 AND definition_digest<>$3 LIMIT 1", self.namespace), &[&definition.workflow.id, &definition.workflow.version, &definition.digest]).await.map_err(unavailable)?.is_some() {
            return Err(refused("workflow-version-conflict", "this workflow version already names another immutable definition; give the changed definition a new version"));
        }
        Ok(())
    }
    // Failed dead letters remain recoverable. Only a delivered current step
    // identifies the settled workflow failure that has no command left to retry.
    pub(super) fn terminal_retention_predicate(&self) -> String {
        format!("(r.state IN ('finished','cancelled','cancelled-after-effect','expired') OR (r.state='failed' AND EXISTS(SELECT 1 FROM {0}.jobs current_job WHERE current_job.run_id=r.run_id AND current_job.step=r.step AND current_job.state='delivered'))) AND NOT EXISTS(SELECT 1 FROM {0}.jobs j WHERE j.run_id=r.run_id AND (j.uncertain OR j.state IN ('pending','leased','unknown')))", self.namespace)
    }
    /// Serialize service startup/status checks with activation and admission.
    pub(crate) async fn check_runtime_bindings(
        &self,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<()> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.check_live_bindings(&tx, runtime).await?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }

    /// Validate each retained live definition against its own logical bindings.
    /// Called after activation audit intent, while the activation transaction
    /// holds admission_lock so new runs cannot invalidate the observation.
    pub(crate) async fn check_live_bindings(
        &self,
        tx: &Transaction<'_>,
        runtime: &crate::runtime::RuntimeConfig,
    ) -> Result<()> {
        tx.query_one(
            &format!(
                "SELECT id FROM {}.admission_lock WHERE id FOR UPDATE",
                self.namespace
            ),
            &[],
        )
        .await
        .map_err(unavailable)?;
        let mut after = Uuid::nil();
        loop {
            let rows=tx.query(&format!("SELECT r.run_id,r.snapshot,r.binding_digest FROM {}.runs r WHERE r.run_id>$1 AND r.payload_erased_at IS NULL AND (NOT ({}) OR r.restore_review_required) ORDER BY r.run_id LIMIT 100",self.namespace,self.terminal_retention_predicate()),&[&after]).await.map_err(unavailable)?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let id: Uuid = row.get(0);
                let snapshot: String =
                    self.open_value(id, "snapshot", "", &row.get::<_, Value>(1))?;
                let definition = Definition::from_snapshot(&snapshot)?;
                let advice = "a live run requires its original connections; restore those bindings before normal serving or apply, or start --recovery-only to investigate without admissions or dispatch";
                let digest = runtime
                    .binding_digest_for(&definition.workflow)
                    .map_err(|_| refused("live-binding-conflict", advice))?;
                if digest != row.get::<_, String>(2) {
                    return Err(refused("live-binding-conflict", advice));
                }
                after = id;
            }
        }
        Ok(())
    }

    pub async fn doctor(&self) -> Result<DoctorStatus> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        let row = tx
            .query_one(
                &format!(
                    "SELECT database_id,schema_version,restore_hold,admissions_hold FROM {}.control WHERE id",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?;
        let states = tx
            .query(
                &format!(
                    "SELECT state,count(*) FROM {}.runs GROUP BY state",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        let counts=tx.query_one(&format!("SELECT count(*) FILTER(WHERE uncertain),min(next_attempt_at) FILTER(WHERE state='pending') FROM {}.jobs",self.namespace),&[]).await.map_err(unavailable)?;
        let retained = tx.query_one(&format!(
            "SELECT count(*),min(r.completed_at) FROM {}.runs r WHERE {} AND r.payload_erased_at IS NULL AND r.completed_at IS NOT NULL AND NOT r.restore_review_required",
            self.namespace, self.terminal_retention_predicate()), &[]).await.map_err(unavailable)?;
        Ok(DoctorStatus {
            database_id: row.get(0),
            schema_version: row.get(1),
            restore_hold: row.get(2),
            admissions_hold: row.get(3),
            restore_review_required: tx
                .query_one(
                    &format!(
                        "SELECT count(*) FROM {}.runs WHERE restore_review_required",
                        self.namespace
                    ),
                    &[],
                )
                .await
                .map_err(unavailable)?
                .get(0),
            audit_ready: self.security.audit.ready().await,
            states,
            uncertain: counts.get(0),
            oldest_due_at: counts.get(1),
            terminal_payloads: retained.get(0),
            oldest_terminal_payload_at: retained.get(1),
        })
    }
    pub async fn set_restore_hold(&self, actor: &Actor, reason: &str) -> Result<()> {
        Self::operator(actor)?;
        Self::reason(reason)?;
        self.audited("restore-hold", actor, None, async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            tx.execute(
                &format!(
                    "UPDATE {}.control SET restore_hold=true,admissions_hold=true,restore_evidence_hash=NULL,admission_recovery_hash=NULL WHERE id",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?;
            tx.execute(&format!("UPDATE {}.runs SET restore_review_required=true WHERE state NOT IN ('finished','cancelled','cancelled-after-effect') OR EXISTS(SELECT 1 FROM {}.jobs j WHERE j.run_id=runs.run_id AND (j.uncertain OR j.state IN ('pending','leased','unknown')))",self.namespace,self.namespace),&[]).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)
        })
        .await
    }
    /// `evidence` references the operator's external fencing and recovery record.
    /// A database cannot observe a prior deployment or prove that it is stopped.
    pub async fn release_restore_hold(&self, actor: &Actor, evidence: &str) -> Result<()> {
        Self::operator(actor)?;
        Self::reason(evidence)?;
        self.audited("release-restore-hold",actor,None,async {
            let mut client=self.client().await.map_err(unavailable)?;let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            // Serialize release with restore/cancellation I/O fences. No replay
            // is triggered by releasing this deployment-wide hold.
            tx.query_one(&format!("SELECT id FROM {}.control WHERE id FOR UPDATE",self.namespace),&[]).await.map_err(unavailable)?;
            if self.restore_has_unresolved_work(&tx).await? {return Err(refused("restore-unresolved","wait for active leases, complete fenced execution recovery for safe expired leases or cancelled evaluations, and reconcile uncertain mutations before releasing the restore hold"));}
            tx.execute(&format!("UPDATE {}.control SET restore_hold=false,restore_evidence_hash=$1 WHERE id AND restore_hold",self.namespace),&[&self.reference("restore-evidence-v1",evidence)]).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)
        }).await
    }
    /// A trusted operator attests to complete admission history and external
    /// fencing. This does not manufacture missing history or prove it from the
    /// restored database. Leave ingress held when those facts are unknown.
    pub async fn complete_execution_recovery(
        &self,
        actor: &Actor,
        recovery_reference: &str,
        execution_history_complete: bool,
        prior_deployment_fenced: bool,
    ) -> Result<()> {
        Self::operator(actor)?;
        Self::reason(recovery_reference)?;
        if !execution_history_complete || !prior_deployment_fenced {
            return Err(refused("restore-review-required","recover complete execution history and fence the prior deployment before clearing review"));
        }
        self.audited("complete-execution-recovery",actor,None,async {
            let mut client=self.client().await.map_err(unavailable)?;let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            let held:bool=tx.query_one(&format!("SELECT restore_hold FROM {}.control WHERE id FOR UPDATE",self.namespace),&[]).await.map_err(unavailable)?.get(0);
            if !held{return Err(refused("restore-hold-required","enter recovery hold before attesting recovered execution history"));}
            self.hold_attested_recovery_work(&tx).await?;
            self.review_cancelled_evaluations(&tx).await?;
            // Keep review on work that can still change after this attestation.
            // In particular, a live worker may return a definite retryable
            // mutation later; its prepared Pending command must be held by a
            // subsequent recovery decision before execution can reopen.
            tx.execute(&format!("UPDATE {0}.runs r SET restore_review_required=false WHERE restore_review_required AND NOT EXISTS(SELECT 1 FROM {0}.jobs j WHERE j.run_id=r.run_id AND (j.uncertain OR j.state IN ('leased','unknown')))",self.namespace),&[]).await.map_err(unavailable)?;
            tx.execute(&format!("UPDATE {}.control SET restore_evidence_hash=$1 WHERE id",self.namespace),&[&self.reference("execution-recovery-v1",recovery_reference)]).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)
        }).await
    }

    /// Cancellation abandons future use of an evaluation, not its unknown
    /// provider completion. Only the original current prepared evaluation can
    /// qualify; protected evidence and the spent start identity remain retained.
    async fn cancelled_evaluation_abandoned(
        &self,
        tx: &Transaction<'_>,
        run: Uuid,
        step: &str,
        require_reviewed: bool,
    ) -> Result<bool> {
        let row = tx.query_opt(&format!("SELECT r.snapshot,j.command,j.state,j.lease_expires_at>clock_timestamp(),r.cancel_requested,r.restore_review_required,j.uncertain FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE j.run_id=$1 AND j.step=$2 FOR UPDATE OF j,r",self.namespace),&[&run,&step]).await.map_err(unavailable)?;
        let Some(row) = row else { return Ok(false) };
        if !row.get::<_, bool>(4)
            || require_reviewed && row.get::<_, bool>(5)
            || !row.get::<_, bool>(6)
        {
            return Ok(false);
        }
        match row.get::<_, String>(2).as_str() {
            "unknown" | "dead_lettered" | "expired" | "delivered" => {}
            "leased" if !row.get::<_, Option<bool>>(3).unwrap_or(true) => {}
            _ => return Ok(false),
        }
        let snapshot: Option<Value> = row.get(0);
        let command: Option<Value> = row.get(1);
        let (Some(snapshot), Some(command)) = (snapshot, command) else {
            return Ok(false);
        };
        let snapshot: String = self.open_value(run, "snapshot", "", &snapshot)?;
        let definition = Definition::from_snapshot(&snapshot)?;
        let command: FrozenCommand = self.open_value(run, "command", step, &command)?;
        let Some(Step::Call { call, .. }) = definition.workflow.steps.get(step) else {
            return Ok(false);
        };
        Ok(call.operation.is_evaluation()
            && !call.operation.can_retry_after_unknown()
            && command.request().operation == call.operation
            && command.request().connection == call.connection
            && command.request().idempotency_key.is_none()
            && command.preparation().is_some_and(|bytes| !bytes.is_empty()))
    }

    async fn review_cancelled_evaluations(&self, tx: &Transaction<'_>) -> Result<()> {
        let mut after = Uuid::nil();
        loop {
            let rows = tx.query(&format!("SELECT r.run_id,r.step FROM {0}.runs r JOIN {0}.jobs j ON j.run_id=r.run_id AND j.step=r.step WHERE r.run_id>$1 AND r.cancel_requested AND r.restore_review_required AND j.uncertain ORDER BY r.run_id LIMIT 100",self.namespace),&[&after]).await.map_err(unavailable)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let run: Uuid = row.get(0);
                let step: String = row.get(1);
                if self
                    .cancelled_evaluation_abandoned(tx, run, &step, false)
                    .await?
                {
                    tx.execute(
                        &format!(
                            "UPDATE {}.runs SET restore_review_required=false WHERE run_id=$1",
                            self.namespace
                        ),
                        &[&run],
                    )
                    .await
                    .map_err(unavailable)?;
                }
                after = run;
            }
        }
        Ok(())
    }

    async fn restore_has_unresolved_work(&self, tx: &Transaction<'_>) -> Result<bool> {
        let mut after = Uuid::nil();
        let mut after_step = String::new();
        loop {
            let rows = tx.query(&format!("SELECT j.run_id,j.step FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id WHERE (j.run_id,j.step)>($1,$2) AND (j.uncertain OR j.state IN ('leased','unknown') OR r.restore_review_required) ORDER BY j.run_id,j.step LIMIT 100",self.namespace),&[&after,&after_step]).await.map_err(unavailable)?;
            if rows.is_empty() {
                return Ok(false);
            }
            for row in rows {
                let run: Uuid = row.get(0);
                let step: String = row.get(1);
                if !self
                    .cancelled_evaluation_abandoned(tx, run, &step, true)
                    .await?
                {
                    return Ok(true);
                }
                after = run;
                after_step = step;
            }
        }
    }

    // Dispatch's public claim also leases new work, and its private lapse path
    // holds every uncertain attempt. This attested product transition never
    // claims work: it holds control, then jobs, then runs, and leaves safe work
    // dead-lettered for the existing explicit same-command retry gate. Restored
    // pre-command Pending steps and prepared mutation retries also need that
    // explicit decision. Prepared safe-read retries retain their ordinary policy.
    async fn hold_attested_recovery_work(&self, tx: &Transaction<'_>) -> Result<()> {
        let invalid = || {
            refused(
                "restore-lease-incompatible",
                "restore the exact protected snapshot and command before completing lease recovery",
            )
        };
        let eligible = "((j.state='leased' AND j.lease_expires_at<=clock_timestamp()) OR (j.state='unknown' AND j.attempt>0 AND j.delivered_at IS NULL AND j.dead_lettered_at IS NULL AND j.expired_at IS NULL AND j.attempt_started_at IS NULL AND j.lease_expires_at IS NULL AND j.lease_token IS NULL AND j.next_attempt_at IS NULL) OR j.state='pending')";
        let mut after = Uuid::nil();
        loop {
            // Lock active/unresolved jobs too, even when they cannot be held.
            // Otherwise completion could turn a live attempt into Pending
            // between this scan and clearing its run's review mark.
            let rows = tx.query(&format!("SELECT j.run_id,j.step,j.generation,j.attempt,j.lease_token,j.command,j.pure,j.state,({eligible} AND NOT j.uncertain AND NOT j.receipt_expired) FROM {0}.jobs j JOIN {0}.runs r ON r.run_id=j.run_id AND r.step=j.step WHERE j.run_id>$1 AND ({eligible} OR j.uncertain OR j.state IN ('leased','unknown')) ORDER BY j.run_id LIMIT 100 FOR UPDATE OF j", self.namespace), &[&after]).await.map_err(unavailable)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let run: Uuid = row.get(0);
                let step: String = row.get(1);
                after = run;
                if !row.get::<_, Option<bool>>(8).unwrap_or(false) {
                    continue;
                }
                // Acquire the run only after its job, matching Dispatch finish
                // and cancellation. No current worker can change this pair.
                let current = tx.query_one(&format!("SELECT step,snapshot,cancel_requested FROM {}.runs WHERE run_id=$1 FOR UPDATE", self.namespace), &[&run]).await.map_err(unavailable)?;
                if current.get::<_, String>(0) != step {
                    return Err(invalid());
                }
                let snapshot: Option<Value> = current.get(1);
                let snapshot: String = self
                    .open_value(run, "snapshot", "", snapshot.as_ref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                let definition = Definition::from_snapshot(&snapshot).map_err(|_| invalid())?;
                let sealed: Option<Value> = row.get(5);
                let command: Option<FrozenCommand> = sealed
                    .as_ref()
                    .map(|value| self.open_value(run, "command", &step, value))
                    .transpose()
                    .map_err(|_| invalid())?;
                let pure: bool = row.get(6);
                let pending = row.get::<_, String>(7) == "pending";
                let safe = match definition.workflow.steps.get(&step) {
                    Some(Step::Call { call, .. }) => {
                        if pure
                            || command.as_ref().is_some_and(|command| {
                                command.request().operation != call.operation
                                    || command.request().connection != call.connection
                            })
                        {
                            return Err(invalid());
                        }
                        // The worker freezes before recording remote dispatch intent.
                        // Under complete authoritative history and fencing,
                        // an absent command is still pre-I/O, even for a mutation
                        // or model evaluation.
                        if pending {
                            command.is_none() || call.operation.has_dispatch_risk()
                        } else {
                            call.operation.is_read() || command.is_none()
                        }
                    }
                    Some(Step::WaitUntil { .. }) => {
                        // Waits have no remote effect, but their original
                        // deadline still applies, so Dispatch marks them non-pure.
                        if pure || command.is_some() {
                            return Err(invalid());
                        }
                        true
                    }
                    Some(Step::Choose { .. } | Step::Finish { .. }) => {
                        if !pure || command.is_some() {
                            return Err(invalid());
                        }
                        true
                    }
                    None => return Err(invalid()),
                };
                if !safe {
                    continue;
                }
                let failure_code = if pending && command.is_none() {
                    "restore-pre-command-held"
                } else if pending {
                    "restore-prepared-retry-held"
                } else {
                    "restore-safe-lease-expired"
                };
                // Preserve the original command, generation, attempt, deadline
                // and input. Clearing the token and leased state fences a prior
                // paused worker; only a separate explicit replay may run again.
                let changed = tx.execute(&format!("UPDATE {}.jobs j SET state='dead_lettered',next_attempt_at=NULL,attempt_started_at=NULL,lease_expires_at=NULL,lease_token=NULL,delivered_at=NULL,expired_at=NULL,dead_lettered_at=clock_timestamp(),failure_code=$7,updated_at=clock_timestamp() WHERE j.run_id=$1 AND j.step=$2 AND j.generation=$3 AND j.attempt=$4 AND j.lease_token IS NOT DISTINCT FROM $5 AND j.state=$6 AND {eligible} AND NOT j.uncertain AND NOT j.receipt_expired", self.namespace), &[&run,&step,&row.get::<_,i64>(2),&row.get::<_,i16>(3),&row.get::<_,Option<Uuid>>(4),&row.get::<_,String>(7),&failure_code]).await.map_err(unavailable)?;
                if changed != 1 {
                    return Err(invalid());
                }
                let state = if current.get::<_, bool>(2) {
                    "cancelled"
                } else {
                    "failed"
                };
                tx.execute(&format!("UPDATE {}.runs SET state=$2,failure_code=$3,completed_at=clock_timestamp() WHERE run_id=$1",self.namespace),&[&run,&state,&failure_code]).await.map_err(unavailable)?;
            }
        }
        Ok(())
    }

    fn no_external_calls_after(definition: &Definition, start: &str) -> bool {
        let mut pending = vec![start];
        let mut visited = std::collections::BTreeSet::new();
        while let Some(step) = pending.pop() {
            if !visited.insert(step) {
                continue;
            }
            match definition.workflow.steps.get(step) {
                Some(Step::Call { .. }) | None => return false,
                Some(Step::Choose { cases, .. }) => {
                    pending.extend(cases.values().map(String::as_str))
                }
                Some(Step::WaitUntil { next, .. }) => pending.push(next.as_str()),
                Some(Step::Finish { .. }) => {}
            }
        }
        true
    }

    pub async fn release_admission_hold(
        &self,
        actor: &Actor,
        recovery_reference: &str,
        admission_history_complete: bool,
        prior_deployment_fenced: bool,
    ) -> Result<()> {
        Self::operator(actor)?;
        Self::reason(recovery_reference)?;
        if !admission_history_complete || !prior_deployment_fenced {
            return Err(refused(
                "restore-admissions-held",
                "complete admission history and fence the prior deployment before enabling starts",
            ));
        }
        self.audited("release-admission-hold",actor,None,async {
            let mut client=self.client().await.map_err(unavailable)?;let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            let row=tx.query_one(&format!("SELECT restore_hold FROM {}.control WHERE id FOR UPDATE",self.namespace),&[]).await.map_err(unavailable)?;
            if row.get::<_,bool>(0){return Err(refused("restore-hold","reconcile known work and release the execution hold first"));}
            tx.execute(&format!("UPDATE {}.control SET admissions_hold=false,admission_recovery_hash=$1 WHERE id",self.namespace),&[&self.reference("admission-recovery-v1",recovery_reference)]).await.map_err(unavailable)?;
            tx.commit().await.map_err(unavailable)
        }).await
    }

    pub async fn retain_terminal(
        &self,
        before: DateTime<Utc>,
        limit: u32,
        actor: &Actor,
    ) -> Result<u64> {
        Self::operator(actor)?;
        self.audited("retention",actor,None,async {
            if !(1..=100).contains(&limit)||before>Utc::now(){return Err(refused("retention-invalid","choose a past cutoff and a limit between 1 and 100"));}
            let mut client=self.client().await.map_err(unavailable)?;let tx=client.transaction().await.map_err(unavailable)?;
            self.verify_transaction(&tx).await.map_err(unavailable)?;
            let rows=tx.query(&format!("SELECT r.run_id FROM {}.runs r WHERE r.completed_at<$1 AND {} AND r.payload_erased_at IS NULL AND NOT r.restore_review_required ORDER BY r.completed_at,r.run_id LIMIT $2",self.namespace,self.terminal_retention_predicate()),&[&before,&i64::from(limit)]).await.map_err(unavailable)?;
            let mut erased=0;
            for row in &rows {
                let run:Uuid=row.get(0);
                // Same job-then-run order as Dispatch and cancellation. Recheck
                // eligibility after locking; a stale candidate is never erased.
                tx.query(&format!("SELECT step FROM {}.jobs WHERE run_id=$1 ORDER BY step FOR UPDATE",self.namespace),&[&run]).await.map_err(unavailable)?;
                let eligible=tx.query_opt(&format!("SELECT run_id FROM {}.runs r WHERE run_id=$1 AND completed_at<$2 AND {} AND payload_erased_at IS NULL AND NOT restore_review_required FOR UPDATE",self.namespace,self.terminal_retention_predicate()),&[&run,&before]).await.map_err(unavailable)?;
                if eligible.is_none(){continue;}
                tx.execute(&format!("UPDATE {}.runs SET snapshot=NULL,input=NULL,outputs=NULL,terminal_output=NULL,payload_erased_at=transaction_timestamp() WHERE run_id=$1",self.namespace),&[&run]).await.map_err(unavailable)?;
                tx.execute(&format!("UPDATE {}.jobs SET command=NULL WHERE run_id=$1",self.namespace),&[&run]).await.map_err(unavailable)?;
                erased+=1;
            }
            tx.commit().await.map_err(unavailable)?;Ok(erased)
        }).await
    }
}
