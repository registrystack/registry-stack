// SPDX-License-Identifier: Apache-2.0
//! Source-owned ask detail and answer delivery. Remote calls never hold a transaction.
use super::*;
mod delivery;
mod feed;
pub(super) use delivery::deliver_one;
pub(super) use feed::consume_feed;

pub(super) async fn install(client: &impl GenericClient) -> Result<(), MutationError> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_asks (
            authority text NOT NULL,
            review_request_id uuid NOT NULL,
            ask_id uuid NOT NULL,
            action_id text NOT NULL,
            proposal_id uuid NOT NULL,
            submission_version bigint NOT NULL,
            text text CHECK (text IS NULL OR octet_length(text) BETWEEN 1 AND 2000),
            wants jsonb NOT NULL CHECK (jsonb_typeof(wants)='array' AND jsonb_array_length(wants)<=8),
            asked_at timestamptz NOT NULL,
            asked_at_wire text NOT NULL CHECK (octet_length(asked_at_wire)<=64),
            due_at timestamptz,
            due_at_wire text CHECK (due_at_wire IS NULL OR octet_length(due_at_wire)<=64),
            state text NOT NULL CHECK (state IN ('open','answered','expired','closed')),
            answered_at timestamptz,
            closed_at timestamptz,
            detail_erased_at timestamptz,
            PRIMARY KEY (authority,review_request_id,ask_id),
            UNIQUE (authority,review_request_id,ask_id,action_id,proposal_id,submission_version),
            FOREIGN KEY (action_id,proposal_id,submission_version)
                REFERENCES registry_internal.registry_proposal_review_submissions
        );
        CREATE INDEX IF NOT EXISTS registry_proposal_review_asks_version
            ON registry_internal.registry_proposal_review_asks(action_id,proposal_id,submission_version,asked_at DESC,ask_id);
        CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_ask_answers (
            authority text NOT NULL,
            review_request_id uuid NOT NULL,
            ask_id uuid NOT NULL,
            action_id text NOT NULL,
            proposal_id uuid NOT NULL,
            submission_version bigint NOT NULL,
            text text CHECK (text IS NULL OR octet_length(text)<=2000),
            answered_by text,
            answered_at timestamptz NOT NULL,
            delivery_key text NOT NULL UNIQUE CHECK (octet_length(delivery_key) BETWEEN 1 AND 128),
            delivery_state text NOT NULL CHECK (delivery_state IN ('pending','delivered','refused','superseded')),
            attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1000),
            next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            lease_until timestamptz,
            claim_token uuid,
            delivery_deadline timestamptz NOT NULL CHECK (delivery_deadline>answered_at),
            delivered_at timestamptz,
            last_error_code text CHECK (last_error_code IS NULL OR octet_length(last_error_code) BETWEEN 1 AND 128),
            detail_erased_at timestamptz,
            PRIMARY KEY (authority,review_request_id,ask_id),
            UNIQUE (authority,review_request_id,ask_id,action_id,proposal_id,submission_version),
            FOREIGN KEY (authority,review_request_id,ask_id,action_id,proposal_id,submission_version)
                REFERENCES registry_internal.registry_proposal_review_asks
                    (authority,review_request_id,ask_id,action_id,proposal_id,submission_version)
        );
        CREATE INDEX IF NOT EXISTS registry_proposal_review_ask_answer_jobs
            ON registry_internal.registry_proposal_review_ask_answers(next_attempt_at,answered_at)
            WHERE delivery_state='pending';
        CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_ask_files (
            authority text NOT NULL,
            review_request_id uuid NOT NULL,
            ask_id uuid NOT NULL,
            action_id text NOT NULL,
            proposal_id uuid NOT NULL,
            submission_version bigint NOT NULL,
            addition_id uuid NOT NULL,
            PRIMARY KEY (action_id,proposal_id,submission_version,addition_id),
            FOREIGN KEY (authority,review_request_id,ask_id,action_id,proposal_id,submission_version)
                REFERENCES registry_internal.registry_proposal_review_ask_answers
                    (authority,review_request_id,ask_id,action_id,proposal_id,submission_version),
            FOREIGN KEY (action_id,proposal_id,submission_version,addition_id)
                REFERENCES registry_internal.registry_proposal_additions
                    (action_id,proposal_id,submission_version,addition_id)
        );
        CREATE INDEX IF NOT EXISTS registry_proposal_review_submissions_request
            ON registry_internal.registry_proposal_review_submissions
                (authority, producer_id, (accepted_binding->>'requestId'))
            WHERE accepted_binding IS NOT NULL;
        CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_ask_announcements (
            authority text NOT NULL CHECK (octet_length(authority) BETWEEN 1 AND 128),
            producer_id text NOT NULL CHECK (octet_length(producer_id) BETWEEN 1 AND 128),
            review_request_id uuid NOT NULL,
            ask_id uuid NOT NULL,
            event_id uuid NOT NULL,
            announcement jsonb NOT NULL CHECK (jsonb_typeof(announcement)='object' AND octet_length(announcement::text)<=1024),
            expires_at timestamptz NOT NULL,
            PRIMARY KEY (authority,review_request_id,ask_id)
        );
        CREATE INDEX IF NOT EXISTS registry_proposal_review_ask_announcements_expiry
            ON registry_internal.registry_proposal_review_ask_announcements(authority,expires_at);
        CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_ask_feed_checkpoints (
            authority text PRIMARY KEY CHECK (octet_length(authority) BETWEEN 1 AND 128),
            cursor uuid,
            updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
        );
        CREATE TABLE IF NOT EXISTS registry_internal.registry_proposal_review_ask_feed_events (
            authority text NOT NULL CHECK (octet_length(authority) BETWEEN 1 AND 128),
            event_id uuid NOT NULL,
            review_request_id uuid NOT NULL,
            ask_id uuid NOT NULL,
            state text NOT NULL CHECK (state IN ('mirrored','unknown','refused')),
            error_code text CHECK (error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 128),
            observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
            PRIMARY KEY (authority,event_id)
        );"
    ).await.map_err(|_| MutationError::Unavailable)
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnswerBody {
    pub(crate) text: Option<String>,
    #[serde(default)]
    pub(crate) additions: Vec<Uuid>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnswerMutation {
    pub(crate) ask_id: Uuid,
    pub(crate) body: AnswerBody,
}

impl AnswerBody {
    pub(crate) fn validate(
        &self,
        wants: &[registry_review_client::ReviewAskWant],
    ) -> Result<(), &'static str> {
        let requires_text = wants
            .iter()
            .any(|want| matches!(want, registry_review_client::ReviewAskWant::Answer {}));
        if self
            .text
            .as_ref()
            .is_some_and(|text| text.trim().is_empty() || text.len() > 2000 || text.contains('\0'))
            || (requires_text && self.text.is_none())
        {
            return Err("text");
        }
        let distinct = self
            .additions
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self.additions.len() > 32
            || distinct.len() != self.additions.len()
            || self.additions.iter().any(Uuid::is_nil)
            || (wants
                .iter()
                .any(|want| matches!(want, registry_review_client::ReviewAskWant::Document {}))
                && self.additions.is_empty())
        {
            return Err("additions");
        }
        if self.text.is_none() && self.additions.is_empty() {
            return Err("text");
        }
        Ok(())
    }
}

pub(crate) fn answer_time(now: DateTime<Utc>, asked: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let asked = asked.timestamp_micros().checked_add(i64::from(
        !asked.timestamp_subsec_nanos().is_multiple_of(1000),
    ))?;
    DateTime::from_timestamp_micros(now.timestamp_micros().max(asked))
}

fn retryable_status(status: u16) -> bool {
    status == 429 || status >= 500
}

/// Lifecycle commands hold the Proposal parent lock before closing this version.
pub(super) async fn close_submission(
    client: &impl GenericClient,
    action: &str,
    proposal: Uuid,
    version: i64,
) -> Result<(), MutationError> {
    client.execute("UPDATE registry_internal.registry_proposal_review_asks SET state='closed',closed_at=GREATEST(transaction_timestamp(),asked_at) WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND state='open'",&[&action,&proposal,&version]).await.map_err(|_|MutationError::Unavailable)?;
    client.execute("UPDATE registry_internal.registry_proposal_review_ask_answers SET delivery_state='superseded',claim_token=NULL,lease_until=NULL,last_error_code=NULL WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3 AND delivery_state='pending'",&[&action,&proposal,&version]).await.map_err(|_|MutationError::Unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_review_client::ReviewAskWant;
    use serde_json::json;

    #[test]
    fn answer_text_is_required_nonblank_and_bounded_in_utf8_bytes() {
        let wants = [ReviewAskWant::Answer {}];
        for text in [
            None,
            Some("  ".to_owned()),
            Some("é".repeat(1001)),
            Some("\0".to_owned()),
        ] {
            let body = AnswerBody {
                text,
                additions: vec![],
            };
            assert_eq!(body.validate(&wants), Err("text"));
        }
        let body = AnswerBody {
            text: Some("A multiline\nanswer".to_owned()),
            additions: vec![],
        };
        assert_eq!(body.validate(&wants), Ok(()));
        assert!(serde_json::from_value::<AnswerBody>(json!({"other":"private"})).is_err());
    }

    #[test]
    fn empty_wants_still_require_an_answer_content() {
        assert_eq!(
            AnswerBody {
                text: None,
                additions: vec![]
            }
            .validate(&[]),
            Err("text")
        );
        assert!(AnswerBody {
            text: Some("explanation".into()),
            additions: vec![]
        }
        .validate(&[])
        .is_ok());
        assert!(AnswerBody {
            text: None,
            additions: vec![Uuid::new_v4()]
        }
        .validate(&[])
        .is_ok());
    }

    #[test]
    fn document_answers_require_distinct_non_nil_addition_ids() {
        let wants = [ReviewAskWant::Document {}];
        let id = Uuid::new_v4();
        for additions in [
            vec![],
            vec![Uuid::nil()],
            vec![id, id],
            (0..33).map(|_| Uuid::new_v4()).collect(),
        ] {
            assert_eq!(
                AnswerBody {
                    text: None,
                    additions
                }
                .validate(&wants),
                Err("additions")
            );
        }
        assert_eq!(
            AnswerBody {
                text: None,
                additions: vec![id]
            }
            .validate(&wants),
            Ok(())
        );
        assert_eq!(
            AnswerBody {
                text: None,
                additions: vec![]
            }
            .validate(&[]),
            Err("text")
        );
    }

    #[test]
    fn answer_time_never_precedes_a_future_nanosecond_ask() {
        let asked = "2026-11-27T10:00:00.123456001Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let now = asked - chrono::Duration::hours(1);
        let stored = answer_time(now, asked).unwrap();
        assert!(stored >= asked);
        assert_eq!(stored.timestamp_subsec_nanos() % 1000, 0);
        assert_eq!(stored.timestamp_micros(), asked.timestamp_micros() + 1);
        let later = asked + chrono::Duration::hours(1);
        assert_eq!(
            answer_time(later, asked).unwrap().timestamp_micros(),
            later.timestamp_micros()
        );
    }

    #[test]
    fn delivery_retries_rate_limits_and_server_errors_but_not_other_client_refusals() {
        assert!(retryable_status(429));
        assert!(retryable_status(503));
        for status in [400, 401, 403, 404, 409, 422] {
            assert!(!retryable_status(status));
        }
    }
}
