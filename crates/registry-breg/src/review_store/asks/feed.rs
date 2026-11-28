// SPDX-License-Identifier: Apache-2.0
//! Stage remote observations before committing a complete, cursor-fenced page.
use super::*;
use registry_review_client::{ReviewAsk, ReviewAskFeedEntry, ReviewAskResponse};
use serde_json::json;

struct Binding {
    action: String,
    proposal: Uuid,
    version: i64,
    accepted: ReviewRequestAccepted,
}
struct Observation {
    entry: ReviewAskFeedEntry,
    binding: Option<Binding>,
    ask: Option<ReviewAsk>,
    state: &'static str,
    error: Option<&'static str>,
}

fn transient(error: &ReviewClientError) -> bool {
    match error {
        ReviewClientError::Problem { status, .. } => retryable_status(*status),
        ReviewClientError::Protocol { status, .. } => retryable_status(*status),
        ReviewClientError::Transport { .. } => true,
        _ => false,
    }
}

pub(crate) async fn consume_feed(
    client: &mut tokio_postgres::Client,
    authority: &ReviewAuthorityClient,
    mutations: &crate::postgres::PostgresRecordMutationService,
) -> Result<bool, MutationError> {
    let token = authority
        .token_provider
        .bearer_token()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let cursor = checkpoint(client, &authority.authority).await?;
    let page = match authority
        .client
        .ask_feed(
            ReviewAuth::new(&token, &authority.profile),
            cursor,
            Some(100),
        )
        .await
    {
        Ok(page) => page.value,
        Err(ReviewClientError::Problem { status: 410, .. }) if cursor.is_some() => {
            // Compare the old cursor so a late reset cannot erase another worker's progress.
            client.execute("UPDATE registry_internal.registry_proposal_review_ask_feed_checkpoints SET cursor=NULL,updated_at=transaction_timestamp() WHERE authority=$1 AND cursor=$2",&[&authority.authority,&cursor]).await.map_err(|_| MutationError::Unavailable)?;
            return Ok(true);
        }
        Err(_) => return Err(MutationError::Unavailable),
    };
    let changed = !page.items.is_empty();
    let next = page
        .next_cursor
        .or_else(|| page.items.last().map(|entry| entry.event_id))
        .or(cursor);
    let mut staged = Vec::with_capacity(page.items.len());
    for entry in page.items {
        let row = client.query_opt("SELECT action_id,proposal_id,submission_version,accepted_binding FROM registry_internal.registry_proposal_review_submissions WHERE authority=$1 AND producer_id=$2 AND accepted_binding->>'requestId'=$3",&[&authority.authority,&authority.producer_id,&entry.request_id.to_string()]).await.map_err(|_| MutationError::Unavailable)?;
        let Some(row) = row else {
            staged.push(Observation {
                entry,
                binding: None,
                ask: None,
                state: "unknown",
                error: Some("ask-request-unknown"),
            });
            continue;
        };
        let binding = Binding {
            action: row.get(0),
            proposal: row.get(1),
            version: row.get(2),
            accepted: serde_json::from_value(row.get(3)).map_err(|_| MutationError::Unavailable)?,
        };
        let (ask, state, error) = match authority
            .client
            .ask(
                ReviewAuth::new(&token, &authority.profile),
                &binding.accepted,
                entry.ask_id,
            )
            .await
        {
            Ok(ReviewAskResponse::Available(ask)) => (Some(ask.value), "mirrored", None),
            Ok(ReviewAskResponse::ConcealedOrUnknown { .. }) => {
                (None, "refused", Some("ask-concealed-or-unknown"))
            }
            Err(error) if transient(&error) => return Err(MutationError::Unavailable),
            Err(_) => (None, "refused", Some("ask-protocol-refused")),
        };
        staged.push(Observation {
            entry,
            binding: Some(binding),
            ask,
            state,
            error,
        });
    }
    // No outbound I/O below this point. A page commits all observations and its cursor together.
    let tx = client
        .transaction()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext('breg-ask-feed'),hashtext($1))",
        &[&authority.authority],
    )
    .await
    .map_err(|_| MutationError::Unavailable)?;
    if checkpoint(&tx, &authority.authority).await? != cursor {
        return Ok(false);
    }
    for observation in staged {
        let Observation {
            entry,
            binding,
            ask,
            state,
            error,
        } = observation;
        let recorded = tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_ask_feed_events WHERE authority=$1 AND event_id=$2",&[&authority.authority,&entry.event_id]).await.map_err(|_| MutationError::Unavailable)?;
        if recorded.is_some() {
            continue;
        }
        let mut state = state;
        let mut error = error;
        if let (Some(binding), Some(ask)) = (binding, ask) {
            // Parent first, matching lifecycle commands, delivery and operator erasure.
            let row = tx.query_opt("SELECT state,submission_version,blocked_reason FROM registry_internal.registry_proposal_state WHERE action_id=$1 AND proposal_id=$2 FOR UPDATE",&[&binding.action,&binding.proposal]).await.map_err(|_| MutationError::Unavailable)?.ok_or(MutationError::Unavailable)?;
            let current = row.get::<_, String>(0) == "submitted"
                && row.get::<_, i64>(1) == binding.version
                && row.get::<_, Option<String>>(2).is_none();
            let retained = tx.query_opt("SELECT NOT withdrawn FROM registry_internal.registry_proposal_review_submissions WHERE authority=$1 AND action_id=$2 AND proposal_id=$3 AND submission_version=$4 AND accepted_binding=$5 AND producer_id=$6",&[&authority.authority,&binding.action,&binding.proposal,&binding.version,&json!(binding.accepted),&authority.producer_id]).await.map_err(|_| MutationError::Unavailable)?;
            if let Some(retained) = retained {
                let open = current && retained.get::<_, bool>(0);
                let remote =
                    serde_json::to_value(ask.state).map_err(|_| MutationError::Unavailable)?;
                let incoming = if open {
                    remote.as_str().ok_or(MutationError::Unavailable)?
                } else {
                    "closed"
                };
                let inserted = tx.execute("INSERT INTO registry_internal.registry_proposal_review_asks (authority,review_request_id,ask_id,action_id,proposal_id,submission_version,text,wants,asked_at,asked_at_wire,due_at,due_at_wire,state,answered_at,closed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $13='closed' THEN GREATEST(transaction_timestamp(),$9) ELSE $15 END) ON CONFLICT(authority,review_request_id,ask_id) DO NOTHING",&[&authority.authority,&entry.request_id,&entry.ask_id,&binding.action,&binding.proposal,&binding.version,&ask.text,&json!(ask.wants),&ask.asked_at,&ask.asked_at.to_rfc3339(),&ask.due_at,&ask.due_at.map(|at|at.to_rfc3339()),&incoming,&ask.answered_at,&ask.closed_at]).await.map_err(|_| MutationError::Unavailable)?;
                if inserted == 0 {
                    tx.execute("UPDATE registry_internal.registry_proposal_review_asks SET state=$4,answered_at=$5,closed_at=CASE WHEN $4='closed' THEN GREATEST(transaction_timestamp(),asked_at) ELSE $6 END WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3 AND state='open' AND detail_erased_at IS NULL",&[&authority.authority,&entry.request_id,&entry.ask_id,&incoming,&ask.answered_at,&ask.closed_at]).await.map_err(|_| MutationError::Unavailable)?;
                } else if incoming == "open" {
                    mutations
                        .record_review_change(
                            &tx,
                            &authority.authority,
                            &binding.action,
                            binding.proposal,
                            binding.version,
                            "asked",
                        )
                        .await?;
                }
            } else {
                state = "unknown";
                error = Some("ask-binding-changed");
            }
        }
        tx.execute("INSERT INTO registry_internal.registry_proposal_review_ask_feed_events(authority,event_id,review_request_id,ask_id,state,error_code) VALUES($1,$2,$3,$4,$5,$6)",&[&authority.authority,&entry.event_id,&entry.request_id,&entry.ask_id,&state,&error]).await.map_err(|_| MutationError::Unavailable)?;
        if state != "mirrored" {
            tracing::debug!(
                outcome = state,
                code = error,
                "BReg skipped an ask announcement"
            );
        }
    }
    tx.execute("INSERT INTO registry_internal.registry_proposal_review_ask_feed_checkpoints(authority,cursor) VALUES($1,$2) ON CONFLICT(authority) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=transaction_timestamp()",&[&authority.authority,&next]).await.map_err(|_| MutationError::Unavailable)?;
    tx.commit().await.map_err(|_| MutationError::Unavailable)?;
    Ok(changed)
}

async fn checkpoint(
    client: &impl GenericClient,
    authority: &str,
) -> Result<Option<Uuid>, MutationError> {
    Ok(client.query_opt("SELECT cursor FROM registry_internal.registry_proposal_review_ask_feed_checkpoints WHERE authority=$1",&[&authority]).await.map_err(|_| MutationError::Unavailable)?.and_then(|row|row.get(0)))
}
