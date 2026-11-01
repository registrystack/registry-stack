// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "breg")]
//! Mock boundary tests for the BReg connector's immediate Action family
//! (N3) and Proposal Action family (N4): prepared evidence, the
//! receipt-horizon refusals, exact-same-key recovery, the observed
//! completion, and the status read, against a scripted in-process BReg.

#[path = "support/mod.rs"]
mod support;

use axum::http::StatusCode;
use registry_adapter_connectors::operation::{
    CommandKey, NativeState, Observable, Operation, OutcomeCategory, PreparedAttempt,
};
use registry_breg_client::BRegProblemCode;
use serde_json::{json, Value};

use support::{
    action_receipt, problem, proposal, Mock, APPLICATION_ID, PROPOSAL_ID, RECORD_ID, TOKEN,
};

fn key(step: &str) -> CommandKey {
    CommandKey::new(format!("adapter-unit/company/{step}")).expect("derived key")
}

#[tokio::test(flavor = "multi_thread")]
async fn immediate_action_catalog_and_prepared_bytes_without_credentials() {
    let mock = Mock::start("immediate", false).await;
    let names: Vec<&str> = mock
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(names.contains(&"breg.action.invoke"));
    assert!(!names.contains(&"breg.proposal.start"));
    let prepared = mock
        .connector
        .action_invoke()
        .prepare(
            &json!({"input": {"legalName": "Action Ltd"}}),
            key("invoke"),
        )
        .expect("prepares");
    assert_eq!(prepared.operation(), "breg.action.invoke");
    let bytes = String::from_utf8_lossy(prepared.as_bytes()).to_string();
    assert!(!bytes.contains(TOKEN));
    assert!(mock.exchanges().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn immediate_action_send_completes_on_the_receipt() {
    let mock = Mock::start("immediate", false).await;
    mock.push(support::mutation_json(StatusCode::OK, action_receipt()));
    let outcome = {
        let prepared = mock
            .connector
            .action_invoke()
            .prepare(
                &json!({"input": {"legalName": "Action Ltd"}}),
                key("invoke"),
            )
            .expect("prepares");
        mock.connector.action_invoke().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    // The correlation names the application identity and its first result
    // record, the surfaces observation reads back.
    assert_eq!(
        outcome.correlation.as_deref(),
        Some(format!("{APPLICATION_ID}/company/{RECORD_ID}").as_str())
    );
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].uri,
        "/tenant/prefix/v1/actions/register-company?accessProfile=writer"
    );
    assert_eq!(
        requests[0].idempotency_key.as_deref(),
        Some("adapter-unit/company/invoke")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn immediate_action_unknown_outcome_recovers_with_no_duplicate_effect() {
    let mock = Mock::start("immediate", false).await;
    // First attempt: the exchange is sent, then held past the timeout.
    mock.push(support::mutation_json(StatusCode::OK, json!({})).hanging());
    let stored = {
        let prepared = mock
            .connector
            .action_invoke()
            .prepare(
                &json!({"input": {"legalName": "Action Ltd"}}),
                key("invoke"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let uncertain = {
        let prepared =
            registry_adapter_connectors::breg::action::PreparedInvoke::from_bytes(&stored)
                .expect("restores");
        mock.connector.action_invoke().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(uncertain.category, OutcomeCategory::Uncertain);
    // Recovery sends the identical prepared form under the same key; the
    // destination answers the same-command exchange, proving no duplicate
    // key was minted.
    mock.push(support::mutation_json(StatusCode::OK, action_receipt()));
    let recovered = {
        let prepared =
            registry_adapter_connectors::breg::action::PreparedInvoke::from_bytes(&stored)
                .expect("restores");
        mock.connector.action_invoke().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(recovered.category, OutcomeCategory::Completed);
    let requests = mock.requests.lock().unwrap();
    // Every exchange for this command, retries included, carries the same
    // key and byte-identical body: no duplicate key was minted.
    let sent: Vec<(&str, String)> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .map(|request| {
            (request.idempotency_key.as_deref().unwrap_or_default(), {
                let value: Value = serde_json::from_slice(&request.body).expect("body");
                serde_json::to_string(&value).expect("canonical body")
            })
        })
        .collect();
    assert!(
        sent.len() >= 2,
        "the first attempt and its recovery both ran"
    );
    assert!(sent
        .iter()
        .all(|(key, _)| *key == "adapter-unit/company/invoke"));
    assert!(sent.windows(2).all(|pair| pair[0].1 == pair[1].1));
}

#[tokio::test(flavor = "multi_thread")]
async fn immediate_action_observes_the_result_record() {
    let mock = Mock::start("immediate", false).await;
    mock.push({
        let mut body = support::record_body();
        body["data"]["revisionIdentifier"] = json!("7");
        support::MockResponse::json(StatusCode::OK, body)
            .with_header("etag", support::SERVER_ETAG)
            .with_header(
                "link",
                "<https://id.registrystack.org/profiles/registry-record/v1>; rel=\"profile\", </tenant/prefix/v1/schemas/company>; rel=\"describedby\"",
            )
    });
    let state: NativeState = mock
        .connector
        .action_invoke()
        .observe(&format!("{APPLICATION_ID}/company/{RECORD_ID}"))
        .expect("observation answers");
    assert_eq!(state.state, "present");
    assert!(state
        .details
        .iter()
        .any(|(name, value)| name == "application" && value == APPLICATION_ID));
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_families_enable_under_a_proposal_action() {
    let mock = Mock::start("proposal", false).await;
    let names: Vec<&str> = mock
        .connector
        .catalog()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect();
    assert!(names.contains(&"breg.proposal.start"));
    assert!(names.contains(&"breg.proposal.submit"));
    assert!(!names.contains(&"breg.action.invoke"));
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_start_accepts_with_the_draft_correlation() {
    let mock = Mock::start("proposal", false).await;
    mock.push(support::mutation_json(
        StatusCode::CREATED,
        proposal("draft", 2),
    ));
    let outcome = {
        let prepared = mock
            .connector
            .proposal_start()
            .prepare(
                &json!({"input": {"legalName": "Proposed Ltd"}}),
                key("start"),
            )
            .expect("prepares");
        mock.connector.proposal_start().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Accepted);
    assert_eq!(outcome.correlation.as_deref(), Some(PROPOSAL_ID));
    let bytes = {
        let prepared = mock
            .connector
            .proposal_start()
            .prepare(
                &json!({"input": {"legalName": "Proposed Ltd"}}),
                key("start"),
            )
            .expect("prepares");
        String::from_utf8_lossy(prepared.as_bytes()).to_string()
    };
    assert!(!bytes.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_start_refusal_surfaces_the_product_word() {
    let mock = Mock::start("proposal", false).await;
    mock.push(problem(BRegProblemCode::IdempotencyConflict));
    let outcome = {
        let prepared = mock
            .connector
            .proposal_start()
            .prepare(
                &json!({"input": {"legalName": "Proposed Ltd"}}),
                key("spent"),
            )
            .expect("prepares");
        mock.connector.proposal_start().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused);
    assert_eq!(
        outcome.native_problem.as_deref(),
        Some("idempotency.key-reused")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_submit_completes_at_the_submitted_receipt() {
    let mock = Mock::start("proposal", false).await;
    // The send's fresh authorized read, then the transition.
    mock.push(support::mutation_json(StatusCode::OK, proposal("draft", 2)));
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("submitted", 3),
    ));
    let outcome = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        assert!(mock.exchanges().is_empty(), "prepare is I/O free");
        mock.connector.proposal_submit().send(&prepared)
    }
    .expect("send answers");
    assert_eq!(outcome.category, OutcomeCategory::Completed);
    assert_eq!(outcome.correlation.as_deref(), Some(PROPOSAL_ID));
    let requests = mock.exchanges();
    assert_eq!(requests.len(), 2, "one fresh read, one transition");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[1].method, "POST");
    assert_eq!(
        requests[1].idempotency_key.as_deref(),
        Some("adapter-unit/company/submit")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_submit_horizon_refusals_surface_and_recover_by_reading() {
    // Send answers 409 key-reused: refused, never a fallback.
    let mock = Mock::start("proposal", false).await;
    mock.push(support::mutation_json(StatusCode::OK, proposal("draft", 2)));
    mock.push(problem(BRegProblemCode::IdempotencyConflict));
    let stored = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let refused = {
        let prepared =
            registry_adapter_connectors::breg::proposal::PreparedSubmit::from_bytes(&stored)
                .expect("restores");
        mock.connector.proposal_submit().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(refused.category, OutcomeCategory::Refused);
    assert_eq!(
        refused.native_problem.as_deref(),
        Some("idempotency.key-reused")
    );

    // Send answers 410 expired: refused, and recovery reads the resource
    // and returns the observed outcome without sending again.
    let mock = Mock::start("proposal", false).await;
    mock.push(support::mutation_json(StatusCode::OK, proposal("draft", 2)));
    mock.push(problem(BRegProblemCode::IdempotencyExpired));
    let refused = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        mock.connector.proposal_submit().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(refused.category, OutcomeCategory::Refused);
    assert_eq!(
        refused.native_problem.as_deref(),
        Some("idempotency.expired")
    );
    // The read shows the transition already holds: observed completion.
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("submitted", 3),
    ));
    let recovered = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        mock.connector.proposal_submit().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(recovered.category, OutcomeCategory::Completed);
    assert_eq!(recovered.correlation.as_deref(), Some(PROPOSAL_ID));
    let requests = mock.exchanges();
    assert_eq!(
        requests.len(),
        3,
        "read, 410 answer, settle read; no resend"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_submit_unknown_outcome_recovers_to_the_observed_or_replayed_result() {
    let mock = Mock::start("proposal", false).await;
    // First send: the fresh read answers, then the transition hangs.
    mock.push(support::mutation_json(StatusCode::OK, proposal("draft", 2)));
    mock.push(support::mutation_json(StatusCode::OK, json!({})).hanging());
    let stored = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        prepared.as_bytes().to_vec()
    };
    let uncertain = {
        let prepared =
            registry_adapter_connectors::breg::proposal::PreparedSubmit::from_bytes(&stored)
                .expect("restores");
        mock.connector.proposal_submit().send(&prepared)
    }
    .expect("uncertainty is an outcome");
    assert_eq!(uncertain.category, OutcomeCategory::Uncertain);
    // Recovery: the fresh read proves the draft still holds, so the exact
    // prepared transition is re-armed and executed under the same key.
    mock.push(support::mutation_json(StatusCode::OK, proposal("draft", 2)));
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("submitted", 3),
    ));
    let recovered = {
        let prepared =
            registry_adapter_connectors::breg::proposal::PreparedSubmit::from_bytes(&stored)
                .expect("restores");
        mock.connector.proposal_submit().recover(&prepared)
    }
    .expect("recovery answers");
    assert_eq!(recovered.category, OutcomeCategory::Completed);
    let requests = mock.exchanges();
    // Every submit exchange, the lost attempt and its recovery included,
    // carries the one command key.
    let keys: Vec<Option<&str>> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .map(|request| request.idempotency_key.as_deref())
        .collect();
    assert!(
        keys.len() >= 2,
        "the lost attempt and its recovery both ran"
    );
    assert!(keys
        .iter()
        .all(|key| *key == Some("adapter-unit/company/submit")));
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_submit_refuses_when_the_draft_left_the_transition_behind() {
    let mock = Mock::start("proposal", false).await;
    // The read shows the draft was cancelled: the transition can never
    // run, and no mode falls back.
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("cancelled", 3),
    ));
    let outcome = {
        let prepared = mock
            .connector
            .proposal_submit()
            .prepare(
                &json!({"proposal": PROPOSAL_ID, "submissionVersion": 1, "body": {}}),
                key("submit"),
            )
            .expect("prepares");
        mock.connector.proposal_submit().send(&prepared)
    }
    .expect("refusal is an outcome");
    assert_eq!(outcome.category, OutcomeCategory::Refused);
    assert_eq!(outcome.native_problem.as_deref(), Some("cancelled"));
    assert_eq!(mock.exchanges().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn proposal_status_read_and_observation_agree() {
    let mock = Mock::start("proposal", false).await;
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("submitted", 3),
    ));
    mock.push(support::mutation_json(
        StatusCode::OK,
        proposal("submitted", 3),
    ));
    let summary = mock
        .connector
        .reads()
        .proposal_summary(PROPOSAL_ID)
        .expect("status read answers");
    assert_eq!(summary.id, PROPOSAL_ID);
    assert_eq!(summary.submission_version, 1);
    let state = mock
        .connector
        .proposal_submit()
        .observe(PROPOSAL_ID)
        .expect("observation answers");
    // The same read, value-free: the state word and the lifecycle facts.
    let observed: NativeState = state;
    assert_eq!(observed.state, "submitted");
    assert!(observed
        .details
        .iter()
        .any(|(name, value)| name == "submissionVersion" && value == "1"));
}
