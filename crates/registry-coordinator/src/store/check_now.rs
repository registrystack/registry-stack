// SPDX-License-Identifier: Apache-2.0
//! Check now: an operator asks a waiting step to read its product early.
use super::*;

/// What a Check now left scheduled for the wait.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckNowAnswer {
    pub run_id: Uuid,
    pub step: String,
    /// When the early read is due; absent while a read is already in flight.
    pub next_observation_at: Option<DateTime<Utc>>,
    pub observations: u32,
    pub observation_limit: u32,
}

impl Store {
    /// Bring the next read of a waiting step forward through `wake`, so it
    /// keeps the read floor and counts against the wait's budget like any
    /// other read. The run must be visible to the caller.
    pub async fn check_now_owned(
        &self,
        run: Uuid,
        step: &str,
        actor: &Actor,
    ) -> Result<CheckNowAnswer> {
        self.audited("check-now", actor, Some(run), None, async {
            let mut client = self.client().await.map_err(unavailable)?;
            let tx = client.transaction().await.map_err(unavailable)?;
            self.authorize_run(&tx, run, actor).await?;
            tx.commit().await.map_err(unavailable)?;
            drop(client);
            let not_waiting = || refused("check-not-waiting", "that step is not waiting");
            self.open_wait(run, step).await?.ok_or_else(not_waiting)?;
            self.wake_step(run, step).await?;
            self.open_wait(run, step).await?.ok_or_else(not_waiting)
        })
        .await
    }

    /// The wait of a step, while its read is still scheduled or in flight. A
    /// wait held for recovery has no read to bring forward.
    async fn open_wait(&self, run: Uuid, step: &str) -> Result<Option<CheckNowAnswer>> {
        let client = self.client().await.map_err(unavailable)?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT j.next_attempt_at,w.interval_seconds,w.observations,w.started_at,w.timeout_at FROM {0}.completion_waits w JOIN {0}.jobs j ON j.run_id=w.run_id AND j.step=w.step WHERE w.run_id=$1 AND w.step=$2 AND j.state IN ('pending','leased')",
                    self.namespace
                ),
                &[&run, &step],
            )
            .await
            .map_err(unavailable)?;
        Ok(row.map(|row| CheckNowAnswer {
            run_id: run,
            step: step.to_owned(),
            next_observation_at: row.get(0),
            observations: row.get::<_, i32>(2) as u32,
            observation_limit: observation_limit(
                row.get(3),
                row.get(4),
                row.get::<_, i32>(1) as u32,
            ),
        }))
    }
}
