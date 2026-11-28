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
    park_until: Option<DateTime<Utc>>,
    parked: bool,
}

fn transient(error: &ReviewClientError) -> bool {
    match error {
        ReviewClientError::Problem { status, .. } | ReviewClientError::Protocol { status, .. } => {
            matches!(status, 401 | 403 | 408) || retryable_status(*status)
        }
        ReviewClientError::Transport { .. } => true,
        _ => false,
    }
}

pub(crate) async fn consume_feed(
    client: &mut tokio_postgres::Client,
    authority: &ReviewAuthorityClient,
    mutations: &crate::postgres::PostgresRecordMutationService,
) -> Result<bool, MutationError> {
    // Deadline cleanup must not depend on credentials or authority availability.
    let expired = expire_announcements(client, &authority.authority).await?;
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
    let next = page
        .next_cursor
        .or_else(|| page.items.last().map(|entry| entry.event_id))
        .or(cursor);
    let mut entries = page
        .items
        .into_iter()
        .map(|entry| (entry, false, false))
        .collect::<Vec<_>>();
    // Unbound announcements contain only transport identifiers and time, never a question.
    // Unmatched rows wait without I/O until a binding appears or their deadline passes.
    for row in client.query("SELECT announcement,expires_at<=transaction_timestamp() FROM registry_internal.registry_proposal_review_ask_announcements a WHERE a.authority=$1 AND a.producer_id=$2 AND (a.expires_at<=transaction_timestamp() OR EXISTS(SELECT 1 FROM registry_internal.registry_proposal_review_submissions s WHERE s.authority=a.authority AND s.producer_id=a.producer_id AND s.accepted_binding->>'requestId'=a.review_request_id::text)) ORDER BY a.expires_at,a.ask_id LIMIT 100",&[&authority.authority,&authority.producer_id]).await.map_err(|_| MutationError::Unavailable)? {
        entries.push((serde_json::from_value(row.get(0)).map_err(|_| MutationError::Unavailable)?, true, row.get(1)));
    }
    let changed = expired > 0 || !entries.is_empty();
    let mut staged = Vec::with_capacity(entries.len());
    for (entry, parked, expired) in entries {
        let mut observation = Observation {
            entry,
            binding: None,
            ask: None,
            state: "unknown",
            error: Some("ask-request-unknown"),
            park_until: None,
            parked,
        };
        if expired {
            staged.push(observation);
            continue;
        }
        // A nonunique index permits upgrading a database that already contains duplicates.
        // Ambiguous authority output is counted and skipped rather than stalling the page.
        let rows = client.query("SELECT action_id,proposal_id,submission_version,accepted_binding,recovery_deadline<=transaction_timestamp() FROM registry_internal.registry_proposal_review_submissions WHERE authority=$1 AND producer_id=$2 AND accepted_binding->>'requestId'=$3 LIMIT 2",&[&authority.authority,&authority.producer_id,&observation.entry.request_id.to_string()]).await.map_err(|_| MutationError::Unavailable)?;
        if rows.len() > 1 {
            observation.error = Some("ask-request-ambiguous");
        } else if let Some(row) = rows.first() {
            if parked && row.get::<_, bool>(4) {
                staged.push(observation);
                continue;
            }
            let binding = Binding {
                action: row.get(0),
                proposal: row.get(1),
                version: row.get(2),
                accepted: serde_json::from_value(row.get(3))
                    .map_err(|_| MutationError::Unavailable)?,
            };
            let (ask, state, error) = match authority
                .client
                .ask(
                    ReviewAuth::new(&token, &authority.profile),
                    &binding.accepted,
                    observation.entry.ask_id,
                )
                .await
            {
                Ok(ReviewAskResponse::Available(ask)) => (Some(ask.value), "mirrored", None),
                Ok(ReviewAskResponse::ConcealedOrUnknown { .. }) => {
                    (None, "refused", Some("ask-concealed-or-unknown"))
                }
                Err(error) if transient(&error) => return Err(MutationError::Unavailable),
                Err(ReviewClientError::Configuration { .. }) => {
                    (None, "refused", Some("ask-read-configuration"))
                }
                Err(ReviewClientError::InvalidRequest { .. }) => {
                    (None, "refused", Some("ask-read-invalid-request"))
                }
                Err(_) => (None, "refused", Some("ask-protocol-refused")),
            };
            observation.binding = Some(binding);
            observation.ask = ask;
            observation.state = state;
            observation.error = error;
        } else {
            // Before acceptance there is no trustworthy request-to-submission mapping.
            // Retain only the announcement, no longer than any candidate hand-off can recover.
            observation.park_until = client.query_one("SELECT max(s.recovery_deadline) FROM registry_internal.registry_proposal_review_submissions s JOIN registry_internal.registry_proposal_submissions p USING(action_id,proposal_id,submission_version) WHERE s.authority=$1 AND s.producer_id=$2 AND s.accepted_binding IS NULL AND s.state IN ('pending','submitting','uncertain') AND NOT s.withdrawn AND p.erased_at IS NULL AND s.recovery_deadline>transaction_timestamp()",&[&authority.authority,&authority.producer_id]).await.map_err(|_| MutationError::Unavailable)?.get(0);
        }
        staged.push(observation);
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
            mut binding,
            mut ask,
            mut state,
            mut error,
            park_until,
            parked,
        } = observation;
        let recorded = tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_ask_feed_events WHERE authority=$1 AND event_id=$2",&[&authority.authority,&entry.event_id]).await.map_err(|_| MutationError::Unavailable)?;
        if recorded.is_some() {
            remove_parked(&tx, &authority.authority, &entry).await?;
            continue;
        }
        if parked && tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_ask_announcements WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3 AND expires_at>transaction_timestamp()",&[&authority.authority,&entry.request_id,&entry.ask_id]).await.map_err(|_|MutationError::Unavailable)?.is_none() {
            // An observation fetched before expiry cannot restore question detail afterward.
            binding=None;
            ask=None;
            state="unknown";
            error=Some("ask-request-unknown");
        }
        if let Some(deadline) = park_until {
            let count:i64 = tx.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_ask_announcements WHERE authority=$1 AND review_request_id=$2",&[&authority.authority,&entry.request_id]).await.map_err(|_| MutationError::Unavailable)?.get(0);
            let already_parked=tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_ask_announcements WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3",&[&authority.authority,&entry.request_id,&entry.ask_id]).await.map_err(|_|MutationError::Unavailable)?.is_some();
            if count < crate::contract::MAX_MIRRORED_REVIEW_ASKS as i64 || already_parked {
                let inserted = tx.execute("INSERT INTO registry_internal.registry_proposal_review_ask_announcements(authority,producer_id,review_request_id,ask_id,event_id,announcement,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7 WHERE $7>transaction_timestamp() ON CONFLICT(authority,review_request_id,ask_id) DO NOTHING",&[&authority.authority,&authority.producer_id,&entry.request_id,&entry.ask_id,&entry.event_id,&json!(entry),&deadline]).await.map_err(|_| MutationError::Unavailable)?;
                if inserted > 0 || already_parked {
                    continue;
                }
            }
            error = Some(
                if count >= crate::contract::MAX_MIRRORED_REVIEW_ASKS as i64 {
                    "ask-limit-reached"
                } else {
                    "ask-request-unknown"
                },
            );
        }
        if let (Some(binding), Some(ask)) = (binding, ask) {
            // Parent first, matching lifecycle commands, delivery and operator erasure.
            let row = tx.query_opt("SELECT state,submission_version,blocked_reason FROM registry_internal.registry_proposal_state WHERE action_id=$1 AND proposal_id=$2 FOR UPDATE",&[&binding.action,&binding.proposal]).await.map_err(|_| MutationError::Unavailable)?.ok_or(MutationError::Unavailable)?;
            let current = row.get::<_, String>(0) == "submitted"
                && row.get::<_, i64>(1) == binding.version
                && row.get::<_, Option<String>>(2).is_none();
            let retained = tx.query_opt("SELECT NOT s.withdrawn,p.erased_at IS NOT NULL FROM registry_internal.registry_proposal_review_submissions s JOIN registry_internal.registry_proposal_submissions p USING(action_id,proposal_id,submission_version) WHERE s.authority=$1 AND s.action_id=$2 AND s.proposal_id=$3 AND s.submission_version=$4 AND s.accepted_binding=$5 AND s.producer_id=$6",&[&authority.authority,&binding.action,&binding.proposal,&binding.version,&json!(binding.accepted),&authority.producer_id]).await.map_err(|_| MutationError::Unavailable)?;
            if let Some(retained) = retained {
                if retained.get::<_, bool>(1) {
                    state = "unknown";
                    error = Some("ask-submission-erased");
                } else {
                    let existing = tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_asks WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3",&[&authority.authority,&entry.request_id,&entry.ask_id]).await.map_err(|_| MutationError::Unavailable)?.is_some();
                    let count:i64 = tx.query_one("SELECT count(*) FROM registry_internal.registry_proposal_review_asks WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",&[&binding.action,&binding.proposal,&binding.version]).await.map_err(|_| MutationError::Unavailable)?.get(0);
                    if !existing && count >= crate::contract::MAX_MIRRORED_REVIEW_ASKS as i64 {
                        state = "unknown";
                        error = Some("ask-limit-reached");
                    } else {
                        let open = current && retained.get::<_, bool>(0);
                        let remote = serde_json::to_value(ask.state)
                            .map_err(|_| MutationError::Unavailable)?;
                        let incoming = if open {
                            remote.as_str().ok_or(MutationError::Unavailable)?
                        } else {
                            "closed"
                        };
                        let inserted = tx.execute("INSERT INTO registry_internal.registry_proposal_review_asks (authority,review_request_id,ask_id,action_id,proposal_id,submission_version,text,wants,asked_at,asked_at_wire,due_at,due_at_wire,state,answered_at,closed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $13='closed' THEN GREATEST(transaction_timestamp(),$9) ELSE $15 END) ON CONFLICT(authority,review_request_id,ask_id) DO NOTHING",&[&authority.authority,&entry.request_id,&entry.ask_id,&binding.action,&binding.proposal,&binding.version,&ask.text,&json!(ask.wants),&ask.asked_at,&ask.asked_at.to_rfc3339(),&ask.due_at,&ask.due_at.map(|at|at.to_rfc3339()),&incoming,&ask.answered_at,&ask.closed_at]).await.map_err(|_| MutationError::Unavailable)?;
                        if inserted == 0 && incoming != "open" {
                            let updated = tx.execute("UPDATE registry_internal.registry_proposal_review_asks SET state=$4,answered_at=$5,closed_at=CASE WHEN $4='closed' THEN GREATEST(transaction_timestamp(),asked_at) ELSE $6 END WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3 AND state='open' AND detail_erased_at IS NULL",&[&authority.authority,&entry.request_id,&entry.ask_id,&incoming,&ask.answered_at,&ask.closed_at]).await.map_err(|_| MutationError::Unavailable)?;
                            if updated > 0 && current {
                                mutations
                                    .record_review_change(
                                        &tx,
                                        &authority.authority,
                                        &binding.action,
                                        binding.proposal,
                                        binding.version,
                                        "ask-state-changed",
                                    )
                                    .await?;
                            }
                        } else if inserted > 0 && incoming == "open" {
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
                    }
                }
            } else {
                state = "unknown";
                error = Some("ask-binding-changed");
            }
        }
        if parked {
            remove_parked(&tx, &authority.authority, &entry).await?;
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

async fn expire_announcements(
    client: &mut tokio_postgres::Client,
    authority: &str,
) -> Result<u64, MutationError> {
    let tx = client
        .transaction()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext('breg-ask-feed'),hashtext($1))",
        &[&authority],
    )
    .await
    .map_err(|_| MutationError::Unavailable)?;
    let count=tx.execute("WITH expired AS (DELETE FROM registry_internal.registry_proposal_review_ask_announcements WHERE authority=$1 AND expires_at<=transaction_timestamp() RETURNING event_id,review_request_id,ask_id) INSERT INTO registry_internal.registry_proposal_review_ask_feed_events(authority,event_id,review_request_id,ask_id,state,error_code) SELECT $1,event_id,review_request_id,ask_id,'unknown','ask-request-unknown' FROM expired ON CONFLICT(authority,event_id) DO NOTHING",&[&authority]).await.map_err(|_|MutationError::Unavailable)?;
    tx.commit().await.map_err(|_| MutationError::Unavailable)?;
    Ok(count)
}

async fn remove_parked(
    client: &impl GenericClient,
    authority: &str,
    entry: &ReviewAskFeedEntry,
) -> Result<(), MutationError> {
    client.execute("DELETE FROM registry_internal.registry_proposal_review_ask_announcements WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3",&[&authority,&entry.request_id,&entry.ask_id]).await.map_err(|_|MutationError::Unavailable)?;
    Ok(())
}

async fn checkpoint(
    client: &impl GenericClient,
    authority: &str,
) -> Result<Option<Uuid>, MutationError> {
    Ok(client.query_opt("SELECT cursor FROM registry_internal.registry_proposal_review_ask_feed_checkpoints WHERE authority=$1",&[&authority]).await.map_err(|_|MutationError::Unavailable)?.and_then(|row|row.get(0)))
}
