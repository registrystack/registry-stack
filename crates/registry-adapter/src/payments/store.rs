// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL attempt custody, separate from generic record-facade idempotency.

use super::model::Attempt;
use deadpool_postgres::Pool;
use registry_payment_protocol::PaymentProblemCode as Error;
use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS adapter_payment_attempts (
    id uuid PRIMARY KEY,
    deployment text NOT NULL,
    connection text NOT NULL,
    principal text NOT NULL,
    institution text NOT NULL,
    service text NOT NULL,
    bill_id uuid NOT NULL,
    bill_version bigint NOT NULL CHECK (bill_version > 0),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (deployment, institution, service, bill_id, bill_version)
);
CREATE TABLE IF NOT EXISTS adapter_payment_commands (
    deployment text NOT NULL,
    connection text NOT NULL,
    principal text NOT NULL,
    operation text NOT NULL,
    command_key text NOT NULL,
    request_digest text NOT NULL,
    attempt_id uuid NOT NULL,
    PRIMARY KEY (deployment, connection, principal, operation, command_key)
);
CREATE TABLE IF NOT EXISTS adapter_payment_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment text NOT NULL,
    attempt_id uuid NOT NULL,
    principal text NOT NULL,
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
"#;

pub async fn migrate(client: &mut Client) -> Result<(), Error> {
    let tx = client.transaction().await.map_err(|_| Error::Unavailable)?;
    tx.execute("SELECT pg_advisory_xact_lock(1879751387, 1)", &[])
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.batch_execute(SCHEMA)
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.commit().await.map_err(|_| Error::Unavailable)
}

#[derive(Clone)]
pub struct PaymentStore {
    pub(crate) pool: Pool,
    pub(crate) deployment: String,
}

impl PaymentStore {
    pub fn new(pool: Pool, deployment: String) -> Self {
        Self { pool, deployment }
    }

    pub async fn audit_access(
        &self,
        principal: &str,
        kind: &str,
        id: Option<Uuid>,
    ) -> Result<(), Error> {
        let client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        client.execute("INSERT INTO adapter_payment_events (deployment,attempt_id,principal,kind) VALUES ($1,$2,$3,$4)",
            &[&self.deployment,&id.unwrap_or(Uuid::nil()),&principal,&kind]).await.map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    pub async fn check_privileges(&self) -> Result<(), Error> {
        let client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        for (table, privileges) in [
            (
                "adapter_payment_attempts",
                &["SELECT", "INSERT", "UPDATE"][..],
            ),
            ("adapter_payment_commands", &["SELECT", "INSERT"][..]),
            ("adapter_payment_events", &["SELECT", "INSERT"][..]),
        ] {
            if !crate::journal::missing_table_privileges(&client, table, privileges)
                .await
                .map_err(|_| Error::Unavailable)?
                .is_empty()
            {
                return Err(Error::Unavailable);
            }
        }
        let row = client
            .query_one(
                "SELECT has_sequence_privilege(current_user, $1, 'USAGE')",
                &[&"adapter_payment_events_sequence_seq"],
            )
            .await
            .map_err(|_| Error::Unavailable)?;
        if !row.get::<_, bool>(0) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub async fn lookup_command(
        &self,
        connection: &str,
        principal: &str,
        operation: &str,
        key: &str,
        digest: &str,
    ) -> Result<Option<Uuid>, Error> {
        let client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        command(
            &**client,
            &self.deployment,
            connection,
            principal,
            operation,
            key,
            digest,
        )
        .await
    }

    pub async fn claim_command(
        &self,
        connection: &str,
        principal: &str,
        operation: &str,
        key: &str,
        digest: &str,
        id: Uuid,
    ) -> Result<(), Error> {
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(|_| Error::Unavailable)?;
        claim(
            &*tx,
            &self.deployment,
            connection,
            principal,
            operation,
            key,
            digest,
            id,
        )
        .await?;
        tx.commit().await.map_err(|_| Error::Unavailable)
    }

    /// A bill is unique across command keys and workflow runs. Another admitted
    /// key for the same caller/connection aliases the retained original attempt.
    pub async fn reserve(
        &self,
        candidate: &Attempt,
        key: &str,
        request_digest: &str,
    ) -> Result<Attempt, Error> {
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(|_| Error::Unavailable)?;
        let document = serde_json::to_value(candidate).map_err(|_| Error::Unavailable)?;
        let version =
            i64::try_from(candidate.bill.bill_version).map_err(|_| Error::InvalidRequest)?;
        let inserted=tx.execute(
            "INSERT INTO adapter_payment_attempts (id,deployment,connection,principal,institution,service,bill_id,bill_version,document) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
            &[&candidate.id,&self.deployment,&candidate.connection,&candidate.principal,&candidate.bill.institution_id,&candidate.bill.service_id,&candidate.bill.bill_id,&version,&document]
        ).await.map_err(|_| Error::Unavailable)?;
        let row=tx.query_one("SELECT document FROM adapter_payment_attempts WHERE deployment=$1 AND institution=$2 AND service=$3 AND bill_id=$4 AND bill_version=$5",
            &[&self.deployment,&candidate.bill.institution_id,&candidate.bill.service_id,&candidate.bill.bill_id,&version]).await.map_err(|_| Error::Unavailable)?;
        let saved: Attempt = serde_json::from_value(row.get(0)).map_err(|_| Error::Unavailable)?;
        if saved.connection != candidate.connection || saved.principal != candidate.principal {
            return Err(Error::Conflict);
        }
        claim(
            &*tx,
            &self.deployment,
            &saved.connection,
            &saved.principal,
            "request",
            key,
            request_digest,
            saved.id,
        )
        .await?;
        if inserted == 1 {
            event(&*tx, &self.deployment, &saved, "attempt.reserved").await?;
        }
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        saved.validate_integrity()?;
        Ok(saved)
    }

    pub async fn find_bill(
        &self,
        institution: &str,
        service: &str,
        bill: Uuid,
        version: u64,
    ) -> Result<Option<Attempt>, Error> {
        let client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let version = i64::try_from(version).map_err(|_| Error::InvalidRequest)?;
        let row=client.query_opt("SELECT document FROM adapter_payment_attempts WHERE deployment=$1 AND institution=$2 AND service=$3 AND bill_id=$4 AND bill_version=$5",
            &[&self.deployment,&institution,&service,&bill,&version]).await.map_err(|_| Error::Unavailable)?;
        row.map(|row| decode(row.get(0))).transpose()
    }

    pub async fn get(&self, id: Uuid) -> Result<Attempt, Error> {
        let client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT document FROM adapter_payment_attempts WHERE deployment=$1 AND id=$2",
                &[&self.deployment, &id],
            )
            .await
            .map_err(|_| Error::Unavailable)?
            .ok_or(Error::NotFound)?;
        decode(row.get(0))
    }

    /// Called under the attempt's transaction-scoped advisory lock. The write
    /// and its audit event commit before any corresponding outbound mutation.
    pub async fn save(&self, attempt: &Attempt, kind: &str) -> Result<(), Error> {
        attempt.validate_integrity()?;
        let document = serde_json::to_value(attempt).map_err(|_| Error::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client.transaction().await.map_err(|_| Error::Unavailable)?;
        let count=tx.execute("UPDATE adapter_payment_attempts SET document=$3,updated_at=clock_timestamp() WHERE deployment=$1 AND id=$2",&[&self.deployment,&attempt.id,&document]).await.map_err(|_| Error::Unavailable)?;
        if count != 1 {
            return Err(Error::Unavailable);
        }
        event(&*tx, &self.deployment, attempt, kind).await?;
        tx.commit().await.map_err(|_| Error::Unavailable)
    }
}

fn decode(value: serde_json::Value) -> Result<Attempt, Error> {
    let attempt: Attempt = serde_json::from_value(value).map_err(|_| Error::Unavailable)?;
    attempt.validate_integrity()?;
    Ok(attempt)
}
async fn command(
    client: &impl GenericClient,
    deployment: &str,
    connection: &str,
    principal: &str,
    operation: &str,
    key: &str,
    digest: &str,
) -> Result<Option<Uuid>, Error> {
    let row=client.query_opt("SELECT request_digest,attempt_id FROM adapter_payment_commands WHERE deployment=$1 AND connection=$2 AND principal=$3 AND operation=$4 AND command_key=$5",
        &[&deployment,&connection,&principal,&operation,&key]).await.map_err(|_| Error::Unavailable)?;
    match row {
        Some(row) if row.get::<_, String>(0) != digest => Err(Error::Conflict),
        Some(row) => Ok(Some(row.get(1))),
        None => Ok(None),
    }
}
#[allow(clippy::too_many_arguments)]
async fn claim(
    client: &impl GenericClient,
    deployment: &str,
    connection: &str,
    principal: &str,
    operation: &str,
    key: &str,
    digest: &str,
    id: Uuid,
) -> Result<(), Error> {
    client.execute("INSERT INTO adapter_payment_commands (deployment,connection,principal,operation,command_key,request_digest,attempt_id) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        &[&deployment,&connection,&principal,&operation,&key,&digest,&id]).await.map_err(|_| Error::Unavailable)?;
    if command(
        client, deployment, connection, principal, operation, key, digest,
    )
    .await?
        != Some(id)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn event(
    client: &impl GenericClient,
    deployment: &str,
    attempt: &Attempt,
    kind: &str,
) -> Result<(), Error> {
    client.execute("INSERT INTO adapter_payment_events (deployment,attempt_id,principal,kind) VALUES ($1,$2,$3,$4)",&[&deployment,&attempt.id,&attempt.principal,&kind]).await.map_err(|_| Error::Unavailable)?;
    Ok(())
}
