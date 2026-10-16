// SPDX-License-Identifier: Apache-2.0
//! Fresh constant-size readiness gates, separate from operator diagnostics.
use super::*;

impl Store {
    pub(crate) async fn is_ready(&self) -> Result<bool> {
        let mut client = self.client().await.map_err(unavailable)?;
        let tx = client.transaction().await.map_err(unavailable)?;
        self.verify_transaction(&tx).await.map_err(unavailable)?;
        let held: bool = tx
            .query_one(
                &format!(
                    "SELECT restore_hold OR admissions_hold FROM {}.control WHERE id",
                    self.namespace
                ),
                &[],
            )
            .await
            .map_err(unavailable)?
            .get(0);
        Ok(!held && self.security.audit.ready().await)
    }
}
