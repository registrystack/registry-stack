// SPDX-License-Identifier: Apache-2.0
//! PostgreSQL custody for one-send G2P attempts.

use super::g2p_model::{
    canonical_digest, G2pAttempt, G2pAttemptState, G2pError, G2pObservationState,
    G2pProviderObservation, PreparedG2pRegistryAction,
};
use super::provider_mapping::ProviderAcceptance;
use deadpool_postgres::{GenericClient, Pool, Transaction};
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS adapter_g2p_attempts (
    id uuid PRIMARY KEY,
    deployment text NOT NULL,
    connection text NOT NULL,
    principal text NOT NULL,
    source_namespace text NOT NULL,
    instruction_record_id uuid NOT NULL,
    instruction_id uuid NOT NULL,
    instruction_version bigint NOT NULL CHECK (instruction_version > 0),
    state text NOT NULL,
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (deployment, source_namespace, instruction_record_id, instruction_version),
    UNIQUE (deployment, source_namespace, instruction_id, instruction_version)
);
CREATE TABLE IF NOT EXISTS adapter_g2p_commands (
    deployment text NOT NULL,
    connection text NOT NULL,
    principal text NOT NULL,
    command_key text NOT NULL,
    request_digest text NOT NULL,
    attempt_id uuid NOT NULL,
    PRIMARY KEY (deployment, connection, principal, command_key)
);
CREATE TABLE IF NOT EXISTS adapter_g2p_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment text NOT NULL,
    attempt_id uuid NOT NULL,
    principal text NOT NULL,
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
"#;

pub async fn migrate_g2p(client: &mut tokio_postgres::Client) -> Result<(), G2pError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| G2pError::Unavailable)?;
    tx.execute("SELECT pg_advisory_xact_lock(1879751387, 2)", &[])
        .await
        .map_err(|_| G2pError::Unavailable)?;
    tx.batch_execute(SCHEMA)
        .await
        .map_err(|_| G2pError::Unavailable)?;
    tx.commit().await.map_err(|_| G2pError::Unavailable)
}

#[derive(Clone)]
pub struct G2pStore {
    pool: Pool,
    deployment: String,
}

#[derive(Clone)]
pub enum DispatchAuthorization {
    /// This transaction durably recorded the first-send intent. The caller may
    /// perform exactly one provider mutation with the returned command.
    Send(G2pAttempt),
    /// A send was already attempted or the attempt advanced. Only provider
    /// reads and exact retained-state recovery are permitted.
    Hold(G2pAttempt),
}

impl G2pStore {
    pub fn new(pool: Pool, deployment: String) -> Self {
        Self { pool, deployment }
    }

    /// Resolve only the exact previously admitted workflow command. This read
    /// never creates an attempt or authorizes another provider submission.
    pub async fn lookup_command(
        &self,
        connection: &str,
        principal: &str,
        command_key: &str,
        request_digest: &str,
    ) -> Result<Option<G2pAttempt>, G2pError> {
        let client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT a.document,c.request_digest FROM adapter_g2p_commands c JOIN adapter_g2p_attempts a ON a.id=c.attempt_id AND a.deployment=c.deployment WHERE c.deployment=$1 AND c.connection=$2 AND c.principal=$3 AND c.command_key=$4",
                &[&self.deployment, &connection, &principal, &command_key],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let Some(row) = row else { return Ok(None) };
        if row.get::<_, String>(1) != request_digest {
            return Err(G2pError::Conflict);
        }
        decode(row.get(0)).map(Some)
    }

    pub async fn check_privileges(&self) -> Result<(), G2pError> {
        let client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        for (table, privileges) in [
            ("adapter_g2p_attempts", &["SELECT", "INSERT", "UPDATE"][..]),
            ("adapter_g2p_commands", &["SELECT", "INSERT"][..]),
            ("adapter_g2p_events", &["SELECT", "INSERT"][..]),
        ] {
            if !crate::journal::missing_table_privileges(&client, table, privileges)
                .await
                .map_err(|_| G2pError::Unavailable)?
                .is_empty()
            {
                return Err(G2pError::Unavailable);
            }
        }
        let row = client
            .query_one(
                "SELECT has_sequence_privilege(current_user, $1, 'USAGE')",
                &[&"adapter_g2p_events_sequence_seq"],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?;
        if !row.get::<_, bool>(0) {
            return Err(G2pError::Unavailable);
        }
        Ok(())
    }

    /// Reserve one attempt and its workflow command atomically. Both the BReg
    /// record identity and the immutable source instruction identity are
    /// unique across all command keys for the same authoritative source.
    pub async fn reserve(
        &self,
        candidate: &G2pAttempt,
        command_key: &str,
        request_digest: &str,
    ) -> Result<G2pAttempt, G2pError> {
        candidate.validate_integrity()?;
        if candidate.state != G2pAttemptState::BindPrepared {
            return Err(G2pError::InvalidRequest);
        }
        let version = i64::try_from(candidate.instruction.instruction_version)
            .map_err(|_| G2pError::InvalidRequest)?;
        let document = serde_json::to_value(candidate).map_err(|_| G2pError::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let inserted = tx
            .execute(
                "INSERT INTO adapter_g2p_attempts (id,deployment,connection,principal,source_namespace,instruction_record_id,instruction_id,instruction_version,state,document) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING",
                &[
                    &candidate.id,
                    &self.deployment,
                    &candidate.connection,
                    &candidate.principal,
                    &candidate.source_namespace,
                    &candidate.instruction.record_id,
                    &candidate.instruction.instruction_id,
                    &version,
                    &state_name(candidate.state),
                    &document,
                ],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let row = tx
            .query_opt(
                "SELECT document,source_namespace FROM adapter_g2p_attempts WHERE deployment=$1 AND source_namespace=$2 AND instruction_version=$3 AND (instruction_record_id=$4 OR instruction_id=$5) FOR UPDATE",
                &[
                    &self.deployment,
                    &candidate.source_namespace,
                    &version,
                    &candidate.instruction.record_id,
                    &candidate.instruction.instruction_id,
                ],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?
            .ok_or(G2pError::Conflict)?;
        let saved = decode(row.get(0))?;
        if row.get::<_, String>(1) != saved.source_namespace
            || saved.connection != candidate.connection
            || saved.principal != candidate.principal
            || saved.source_namespace != candidate.source_namespace
            || saved.instruction.record_id != candidate.instruction.record_id
            || saved.instruction.instruction_id != candidate.instruction.instruction_id
        {
            return Err(G2pError::Conflict);
        }
        claim_command(
            &tx,
            &self.deployment,
            &saved.connection,
            &saved.principal,
            command_key,
            request_digest,
            saved.id,
        )
        .await?;
        if inserted == 1 {
            event(&tx, &self.deployment, &saved, "g2p.attempt-reserved").await?;
        }
        tx.commit().await.map_err(|_| G2pError::Unavailable)?;
        Ok(saved)
    }

    pub async fn find_instruction(
        &self,
        principal: &str,
        source_namespace: &str,
        record_id: Uuid,
        version: u64,
    ) -> Result<Option<G2pAttempt>, G2pError> {
        let version = i64::try_from(version).map_err(|_| G2pError::InvalidRequest)?;
        let client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT document,source_namespace FROM adapter_g2p_attempts WHERE deployment=$1 AND principal=$2 AND source_namespace=$3 AND instruction_record_id=$4 AND instruction_version=$5",
                &[&self.deployment, &principal, &source_namespace, &record_id, &version],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?;
        row.map(|row| {
            let attempt = decode(row.get(0))?;
            if row.get::<_, String>(1) != attempt.source_namespace {
                return Err(G2pError::Unavailable);
            }
            Ok(attempt)
        })
        .transpose()
    }

    /// Bind an additional workflow command key to an already retained
    /// instruction attempt. A reused key with a different request remains a
    /// conflict; this method never creates or advances an attempt.
    pub async fn claim_existing_command(
        &self,
        attempt: &G2pAttempt,
        command_key: &str,
        request_digest: &str,
    ) -> Result<(), G2pError> {
        attempt.validate_integrity()?;
        let mut client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let retained = locked(
            &tx,
            &self.deployment,
            &attempt.connection,
            &attempt.principal,
            attempt.id,
        )
        .await?;
        if retained.instruction != attempt.instruction {
            return Err(G2pError::Conflict);
        }
        claim_command(
            &tx,
            &self.deployment,
            &attempt.connection,
            &attempt.principal,
            command_key,
            request_digest,
            attempt.id,
        )
        .await?;
        tx.commit().await.map_err(|_| G2pError::Unavailable)
    }

    /// Bind the caller's confirmation command before any BReg reporting
    /// effect. The command table's scope and digest comparison make an exact
    /// retry resumable while refusing reuse for another operation or attempt.
    pub async fn claim_confirmation_command(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        command_key: &str,
        request_digest: &str,
    ) -> Result<G2pAttempt, G2pError> {
        if command_key.is_empty() || request_digest.is_empty() {
            return Err(G2pError::InvalidRequest);
        }
        let mut client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let attempt = locked(&tx, &self.deployment, connection, principal, id).await?;
        claim_command(
            &tx,
            &self.deployment,
            connection,
            principal,
            command_key,
            request_digest,
            id,
        )
        .await?;
        tx.commit().await.map_err(|_| G2pError::Unavailable)?;
        Ok(attempt)
    }

    pub async fn get_scoped(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
    ) -> Result<G2pAttempt, G2pError> {
        let client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let row = client
            .query_opt(
                "SELECT document FROM adapter_g2p_attempts WHERE deployment=$1 AND connection=$2 AND principal=$3 AND id=$4",
                &[&self.deployment, &connection, &principal, &id],
            )
            .await
            .map_err(|_| G2pError::Unavailable)?
            .ok_or(G2pError::NotFound)?;
        decode(row.get(0))
    }

    pub async fn record_bound(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
    ) -> Result<G2pAttempt, G2pError> {
        self.transition(
            connection,
            principal,
            id,
            "g2p.instruction-bound",
            |attempt| {
                if attempt.state != G2pAttemptState::BindPrepared {
                    return Err(G2pError::Conflict);
                }
                attempt.state = G2pAttemptState::Bound;
                Ok(())
            },
        )
        .await
    }

    /// Atomically grants the only provider mutation authorization this
    /// attempt can ever produce. All later calls return `Hold`.
    pub async fn begin_dispatch(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        now_unix_seconds: i64,
    ) -> Result<DispatchAuthorization, G2pError> {
        if now_unix_seconds <= 0 {
            return Err(G2pError::InvalidRequest);
        }
        let mut client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let mut attempt = locked(&tx, &self.deployment, connection, principal, id).await?;
        if attempt.state != G2pAttemptState::Bound {
            tx.commit().await.map_err(|_| G2pError::Unavailable)?;
            return Ok(DispatchAuthorization::Hold(attempt));
        }
        attempt.first_send_at_unix_seconds = Some(now_unix_seconds);
        attempt.state = G2pAttemptState::DispatchStarted;
        persist(&tx, &self.deployment, &attempt, "g2p.dispatch-started").await?;
        tx.commit().await.map_err(|_| G2pError::Unavailable)?;
        Ok(DispatchAuthorization::Send(attempt))
    }

    pub async fn record_acceptance(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        accepted: ProviderAcceptance,
    ) -> Result<G2pAttempt, G2pError> {
        self.transition(
            connection,
            principal,
            id,
            "g2p.provider-accepted",
            |attempt| {
                attempt.validate_acceptance(&accepted)?;
                if attempt.state == G2pAttemptState::ProviderAccepted
                    && attempt.provider_acceptance.as_ref() == Some(&accepted)
                {
                    return Ok(());
                }
                if attempt.state != G2pAttemptState::DispatchStarted {
                    return Err(G2pError::Conflict);
                }
                attempt.provider_acceptance = Some(accepted);
                attempt.state = G2pAttemptState::ProviderAccepted;
                Ok(())
            },
        )
        .await
    }

    /// Retain an exact, correlated provider read. `Unknown` is represented as
    /// its own held state and is never converted into `Failed` by custody.
    pub async fn record_observation(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        observation: G2pProviderObservation,
    ) -> Result<G2pAttempt, G2pError> {
        self.transition(
            connection,
            principal,
            id,
            "g2p.provider-observed",
            |attempt| {
                let accepted = attempt
                    .provider_acceptance
                    .as_ref()
                    .ok_or(G2pError::RecoveryHeld)?;
                attempt.validate_observation(accepted, &observation)?;
                if matches!(
                    attempt.state,
                    G2pAttemptState::ProviderConfirmed
                        | G2pAttemptState::ProviderFailed
                        | G2pAttemptState::ConfirmationPrepared
                        | G2pAttemptState::ConfirmationRecorded
                ) {
                    if attempt.provider_observation.as_ref() == Some(&observation) {
                        return Ok(());
                    }
                    return Err(G2pError::Conflict);
                }
                if !matches!(
                    attempt.state,
                    G2pAttemptState::ProviderAccepted
                        | G2pAttemptState::ProviderPending
                        | G2pAttemptState::ProviderUnknown
                ) {
                    return Err(G2pError::RecoveryHeld);
                }
                let digest = canonical_digest(&observation)?;
                attempt.state = match observation.state {
                    G2pObservationState::Pending => G2pAttemptState::ProviderPending,
                    G2pObservationState::ProviderConfirmed => G2pAttemptState::ProviderConfirmed,
                    G2pObservationState::ProviderRejected => G2pAttemptState::ProviderFailed,
                };
                attempt.provider_observation = Some(observation);
                attempt.provider_result_digest = Some(digest);
                Ok(())
            },
        )
        .await
    }

    pub async fn prepare_confirmation(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        action: PreparedG2pRegistryAction,
    ) -> Result<G2pAttempt, G2pError> {
        self.transition(
            connection,
            principal,
            id,
            "g2p.confirmation-prepared",
            |attempt| {
                if attempt.state == G2pAttemptState::ConfirmationPrepared
                    && attempt.confirmation_action.as_ref() == Some(&action)
                {
                    return Ok(());
                }
                if attempt.state != G2pAttemptState::ProviderConfirmed
                    || action.action != attempt.binding.registry.report_action
                {
                    return Err(G2pError::Conflict);
                }
                attempt.confirmation_action = Some(action);
                attempt.state = G2pAttemptState::ConfirmationPrepared;
                Ok(())
            },
        )
        .await
    }

    pub async fn record_confirmation(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
    ) -> Result<G2pAttempt, G2pError> {
        self.transition(
            connection,
            principal,
            id,
            "g2p.confirmation-recorded",
            |attempt| {
                if attempt.state == G2pAttemptState::ConfirmationRecorded {
                    return Ok(());
                }
                if attempt.state != G2pAttemptState::ConfirmationPrepared {
                    return Err(G2pError::Conflict);
                }
                attempt.state = G2pAttemptState::ConfirmationRecorded;
                Ok(())
            },
        )
        .await
    }

    async fn transition(
        &self,
        connection: &str,
        principal: &str,
        id: Uuid,
        event_kind: &str,
        update: impl FnOnce(&mut G2pAttempt) -> Result<(), G2pError>,
    ) -> Result<G2pAttempt, G2pError> {
        let mut client = self.pool.get().await.map_err(|_| G2pError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| G2pError::Unavailable)?;
        let mut attempt = locked(&tx, &self.deployment, connection, principal, id).await?;
        let before = serde_json::to_value(&attempt).map_err(|_| G2pError::Unavailable)?;
        update(&mut attempt)?;
        attempt.validate_integrity()?;
        let after = serde_json::to_value(&attempt).map_err(|_| G2pError::Unavailable)?;
        if before != after {
            persist(&tx, &self.deployment, &attempt, event_kind).await?;
        }
        tx.commit().await.map_err(|_| G2pError::Unavailable)?;
        Ok(attempt)
    }
}

async fn locked(
    tx: &Transaction<'_>,
    deployment: &str,
    connection: &str,
    principal: &str,
    id: Uuid,
) -> Result<G2pAttempt, G2pError> {
    let row = tx
        .query_opt(
            "SELECT document FROM adapter_g2p_attempts WHERE deployment=$1 AND connection=$2 AND principal=$3 AND id=$4 FOR UPDATE",
            &[&deployment, &connection, &principal, &id],
        )
        .await
        .map_err(|_| G2pError::Unavailable)?
        .ok_or(G2pError::NotFound)?;
    decode(row.get(0))
}

async fn persist(
    tx: &Transaction<'_>,
    deployment: &str,
    attempt: &G2pAttempt,
    event_kind: &str,
) -> Result<(), G2pError> {
    attempt.validate_integrity()?;
    let document = serde_json::to_value(attempt).map_err(|_| G2pError::Unavailable)?;
    let count = tx
        .execute(
            "UPDATE adapter_g2p_attempts SET state=$3,document=$4,updated_at=clock_timestamp() WHERE deployment=$1 AND id=$2",
            &[&deployment, &attempt.id, &state_name(attempt.state), &document],
        )
        .await
        .map_err(|_| G2pError::Unavailable)?;
    if count != 1 {
        return Err(G2pError::Unavailable);
    }
    event(tx, deployment, attempt, event_kind).await
}

async fn event(
    client: &impl GenericClient,
    deployment: &str,
    attempt: &G2pAttempt,
    kind: &str,
) -> Result<(), G2pError> {
    client
        .execute(
            "INSERT INTO adapter_g2p_events (deployment,attempt_id,principal,kind) VALUES ($1,$2,$3,$4)",
            &[&deployment, &attempt.id, &attempt.principal, &kind],
        )
        .await
        .map_err(|_| G2pError::Unavailable)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn claim_command(
    client: &impl GenericClient,
    deployment: &str,
    connection: &str,
    principal: &str,
    command_key: &str,
    request_digest: &str,
    id: Uuid,
) -> Result<(), G2pError> {
    client
        .execute(
            "INSERT INTO adapter_g2p_commands (deployment,connection,principal,command_key,request_digest,attempt_id) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
            &[&deployment, &connection, &principal, &command_key, &request_digest, &id],
        )
        .await
        .map_err(|_| G2pError::Unavailable)?;
    let row = client
        .query_one(
            "SELECT request_digest,attempt_id FROM adapter_g2p_commands WHERE deployment=$1 AND connection=$2 AND principal=$3 AND command_key=$4",
            &[&deployment, &connection, &principal, &command_key],
        )
        .await
        .map_err(|_| G2pError::Unavailable)?;
    if row.get::<_, String>(0) != request_digest || row.get::<_, Uuid>(1) != id {
        return Err(G2pError::Conflict);
    }
    Ok(())
}

fn decode(value: serde_json::Value) -> Result<G2pAttempt, G2pError> {
    let attempt: G2pAttempt = serde_json::from_value(value).map_err(|_| G2pError::Unavailable)?;
    attempt.validate_integrity()?;
    Ok(attempt)
}

fn state_name(state: G2pAttemptState) -> &'static str {
    match state {
        G2pAttemptState::BindPrepared => "bind-prepared",
        G2pAttemptState::Bound => "bound",
        G2pAttemptState::DispatchStarted => "dispatch-started",
        G2pAttemptState::ProviderAccepted => "provider-accepted",
        G2pAttemptState::ProviderPending => "provider-pending",
        G2pAttemptState::ProviderUnknown => "provider-unknown",
        G2pAttemptState::ProviderConfirmed => "provider-confirmed",
        G2pAttemptState::ProviderFailed => "provider-failed",
        G2pAttemptState::ConfirmationPrepared => "confirmation-prepared",
        G2pAttemptState::ConfirmationRecorded => "confirmation-recorded",
    }
}
