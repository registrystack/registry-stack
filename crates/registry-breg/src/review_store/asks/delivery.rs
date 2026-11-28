// SPDX-License-Identifier: Apache-2.0
//! Lease a value-free answer notification before I/O, then fence its receipt.
use super::*;
use registry_review_client::{
    ReviewAsk, ReviewAskAnswer, ReviewAskAnswerResponse, ReviewAskResponse,
};
use serde_json::json;

enum Outcome {
    Delivered(Box<ReviewAsk>),
    Refused(String),
    Retry,
}

fn outcome(reply: Result<ReviewAskAnswerResponse, ReviewClientError>) -> Outcome {
    match reply {
        Ok(ReviewAskAnswerResponse::Answered(answer)) => Outcome::Delivered(Box::new(answer.value)),
        Ok(ReviewAskAnswerResponse::NotOpen { .. }) => {
            Outcome::Refused("review.ask-not-open".into())
        }
        Ok(ReviewAskAnswerResponse::ConcealedOrUnknown { .. }) => {
            Outcome::Refused("ask-concealed-or-unknown".into())
        }
        Err(ReviewClientError::Problem { status, problem })
            if (400..500).contains(&status) && status != 429 =>
        {
            Outcome::Refused(problem.code.as_str().into())
        }
        Err(ReviewClientError::Protocol { status, .. })
            if (400..500).contains(&status) && status != 429 =>
        {
            Outcome::Refused("answer-delivery-refused".into())
        }
        Err(_) => Outcome::Retry,
    }
}

pub(crate) async fn deliver_one(
    client: &mut tokio_postgres::Client,
    authority: &ReviewAuthorityClient,
) -> Result<bool, MutationError> {
    let expired = client.execute("UPDATE registry_internal.registry_proposal_review_ask_answers SET delivery_state='refused',last_error_code=CASE WHEN delivery_deadline<=transaction_timestamp() THEN 'answer-delivery-expired' ELSE 'answer-delivery-attempts-exhausted' END,claim_token=NULL,lease_until=NULL WHERE authority=$1 AND delivery_state='pending' AND (delivery_deadline<=transaction_timestamp() OR attempt_count>=1000) AND (lease_until IS NULL OR lease_until<transaction_timestamp())",&[&authority.authority]).await.map_err(|_| MutationError::Unavailable)?;
    let claim = Uuid::new_v4();
    let row = client.query_opt("UPDATE registry_internal.registry_proposal_review_ask_answers a SET claim_token=$3,lease_until=transaction_timestamp()+($4::bigint*interval '1 second'),attempt_count=attempt_count+1 WHERE (a.authority,a.review_request_id,a.ask_id)=(SELECT j.authority,j.review_request_id,j.ask_id FROM registry_internal.registry_proposal_review_ask_answers j JOIN registry_internal.registry_proposal_review_submissions s USING(action_id,proposal_id,submission_version) JOIN registry_internal.registry_proposal_state p USING(action_id,proposal_id,submission_version) WHERE j.authority=$1 AND s.authority=j.authority AND s.producer_id=$2 AND s.accepted_binding->>'requestId'=j.review_request_id::text AND s.state='accepted' AND NOT s.withdrawn AND p.state='submitted' AND p.blocked_reason IS NULL AND j.delivery_state='pending' AND j.delivery_deadline>transaction_timestamp() AND j.attempt_count<1000 AND j.next_attempt_at<=transaction_timestamp() AND (j.lease_until IS NULL OR j.lease_until<transaction_timestamp()) ORDER BY j.next_attempt_at,j.answered_at,j.ask_id FOR UPDATE OF j SKIP LOCKED LIMIT 1) RETURNING a.action_id,a.proposal_id,a.submission_version,a.review_request_id,a.ask_id,a.answered_at,a.delivery_key,a.attempt_count",&[&authority.authority,&authority.producer_id,&claim,&authority.lease_seconds]).await.map_err(|_| MutationError::Unavailable)?;
    let Some(row) = row else {
        return Ok(expired > 0);
    };
    let action: String = row.get(0);
    let proposal: Uuid = row.get(1);
    let version: i64 = row.get(2);
    let request: Uuid = row.get(3);
    let ask: Uuid = row.get(4);
    let answered_at: DateTime<Utc> = row.get(5);
    let key: String = row.get(6);
    let attempts: i32 = row.get(7);
    // The claim is committed before token acquisition or authority calls.
    let accepted: ReviewRequestAccepted=serde_json::from_value(client.query_one("SELECT accepted_binding FROM registry_internal.registry_proposal_review_submissions WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",&[&action,&proposal,&version]).await.map_err(|_| MutationError::Unavailable)?.get(0)).map_err(|_| MutationError::Unavailable)?;
    let token = authority.token_provider.bearer_token().await.ok();
    let delivery = match &token {
        Some(token) => outcome(
            authority
                .client
                .answer_ask(
                    ReviewAuth::new(token, &authority.profile),
                    &key,
                    &accepted,
                    ask,
                    &ReviewAskAnswer {
                        subject: accepted.subject.clone(),
                        answered_at,
                    },
                )
                .await,
        ),
        None => Outcome::Retry,
    };
    let mut observed = None;
    if matches!(&delivery,Outcome::Refused(code) if code=="review.ask-not-open") {
        if let Some(token) = &token {
            if let Ok(ReviewAskResponse::Available(ask)) = authority
                .client
                .ask(ReviewAuth::new(token, &authority.profile), &accepted, ask)
                .await
            {
                observed = Some(Box::new(ask.value));
            }
        }
    }
    let tx = client
        .transaction()
        .await
        .map_err(|_| MutationError::Unavailable)?;
    tx.query_one("SELECT 1 FROM registry_internal.registry_proposal_state WHERE action_id=$1 AND proposal_id=$2 FOR UPDATE",&[&action,&proposal]).await.map_err(|_| MutationError::Unavailable)?;
    let current = tx.query_opt("SELECT 1 FROM registry_internal.registry_proposal_review_ask_answers a JOIN registry_internal.registry_proposal_review_submissions s USING(action_id,proposal_id,submission_version) JOIN registry_internal.registry_proposal_state p USING(action_id,proposal_id,submission_version) WHERE a.authority=$1 AND a.review_request_id=$2 AND a.ask_id=$3 AND a.claim_token=$4 AND a.delivery_state='pending' AND s.accepted_binding=$5 AND s.authority=a.authority AND s.producer_id=$6 AND NOT s.withdrawn AND s.state='accepted' AND p.state='submitted' AND p.blocked_reason IS NULL",&[&authority.authority,&request,&ask,&claim,&json!(accepted),&authority.producer_id]).await.map_err(|_| MutationError::Unavailable)?.is_some();
    if !current {
        return Ok(false);
    }
    let (state, code, remote) = match delivery {
        Outcome::Delivered(ask) => ("delivered", None, Some(ask)),
        Outcome::Refused(code) => ("refused", Some(code), observed),
        Outcome::Retry => ("pending", Some("answer-delivery-unavailable".into()), None),
    };
    let delay = i64::try_from(feed_backoff_delay(attempts as u32).as_secs())
        .map_err(|_| MutationError::Unavailable)?;
    tx.execute("UPDATE registry_internal.registry_proposal_review_ask_answers SET delivery_state=$5,last_error_code=$6,claim_token=NULL,lease_until=NULL,next_attempt_at=transaction_timestamp()+($7::bigint*interval '1 second'),delivered_at=CASE WHEN $5='delivered' THEN transaction_timestamp() ELSE delivered_at END WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3 AND claim_token=$4",&[&authority.authority,&request,&ask,&claim,&state,&code,&delay]).await.map_err(|_| MutationError::Unavailable)?;
    if let Some(remote) = remote {
        let incoming =
            serde_json::to_value(remote.state).map_err(|_| MutationError::Unavailable)?;
        let incoming = incoming.as_str().ok_or(MutationError::Unavailable)?;
        if incoming != "open" {
            // A stored on-time notification can settle an expired provider ask.
            tx.execute("UPDATE registry_internal.registry_proposal_review_asks SET state=$4,answered_at=$5,closed_at=$6 WHERE authority=$1 AND review_request_id=$2 AND ask_id=$3 AND detail_erased_at IS NULL",&[&authority.authority,&request,&ask,&incoming,&remote.answered_at,&remote.closed_at]).await.map_err(|_| MutationError::Unavailable)?;
        }
    }
    tx.commit().await.map_err(|_| MutationError::Unavailable)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_review_client::{ReviewComplete, ReviewProtocolFailure};

    #[test]
    fn delivery_outcomes_separate_receipts_refusals_and_ambiguous_exchanges() {
        let ask: ReviewAsk = serde_json::from_value(json!({
            "askId":Uuid::new_v4(),"requestId":Uuid::new_v4(),
            "subject":{"source":"source","type":"proposal","id":Uuid::new_v4().to_string(),"version":"1","digest":format!("sha256:{}","a".repeat(64))},
            "text":"Why?","wants":[],"askedAt":"2026-11-27T00:00:00Z","state":"answered","answeredAt":"2026-11-27T01:00:00Z"
        })).unwrap();
        assert!(matches!(
            outcome(Ok(ReviewAskAnswerResponse::Answered(Box::new(
                ReviewComplete {
                    value: ask,
                    trace_id: "trace".into()
                }
            )))),
            Outcome::Delivered(_)
        ));
        assert!(
            matches!(outcome(Ok(ReviewAskAnswerResponse::NotOpen{trace_id:"trace".into()})),Outcome::Refused(code) if code=="review.ask-not-open")
        );
        assert!(
            matches!(outcome(Ok(ReviewAskAnswerResponse::ConcealedOrUnknown{trace_id:"trace".into()})),Outcome::Refused(code) if code=="ask-concealed-or-unknown")
        );
        for status in [200, 201, 429, 500, 503] {
            assert!(matches!(
                outcome(Err(ReviewClientError::Protocol {
                    status,
                    failure: ReviewProtocolFailure::Body,
                    trace_id: None
                })),
                Outcome::Retry
            ));
        }
        for status in [400, 401, 403, 409, 422] {
            assert!(
                matches!(outcome(Err(ReviewClientError::Protocol {status,failure:ReviewProtocolFailure::Body,trace_id:None})),Outcome::Refused(code) if code=="answer-delivery-refused")
            );
        }
    }
}
