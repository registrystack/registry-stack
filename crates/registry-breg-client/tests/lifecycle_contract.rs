#![allow(dead_code)]

#[path = "../src/lifecycle.rs"]
mod breg_lifecycle;
#[path = "../src/strict_json.rs"]
mod strict_json;

use std::collections::BTreeMap;

use breg_lifecycle::*;
use serde_json::{json, Value};

pub struct RegistryRecord {
    pub record_identifier: String,
    pub revision_identifier: String,
    pub domain_data: BTreeMap<String, Value>,
    pub extensions: BTreeMap<String, Value>,
}

pub struct RegistryRecordMeta {
    pub registry_identifier: String,
    pub dataset_identifier: String,
    pub entity_type_identifier: String,
}

const RECORD_ID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_ID: &str = "00000000-0000-4000-8000-000000000002";
const APPLICATION_ID: &str = "00000000-0000-4000-8000-000000000003";
const RESULT_ID: &str = "00000000-0000-4000-8000-000000000004";
const EVENT_ID: &str = "00000000-0000-4000-8000-000000000005";
const TARGET_ID: &str = "00000000-0000-4000-8000-000000000006";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACTION_ETAG: &str =
    "\"breg-action-hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

#[test]
fn four_actions_promote_and_synthesize_exact_bodies() {
    let metadata = BRegRequestMetadata::from_value(request_metadata(all_actions()), false).unwrap();
    let actions = metadata
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap();
    assert_eq!(actions.len(), 4);
    let expected = [
        (BRegLifecycleOperation::SubmitRequest, json!({})),
        (
            BRegLifecycleOperation::ReviseRequest,
            json!({"rebase": true}),
        ),
        (BRegLifecycleOperation::CancelRequest, json!({})),
        (
            BRegLifecycleOperation::ApplyRequest,
            json!({"proposalVersion": 7, "effectDigest": DIGEST}),
        ),
    ];
    for (action, (operation, body)) in actions.iter().zip(expected) {
        assert_eq!(action.operation(), operation);
        assert_eq!(action.body().to_value(), body);
        assert_eq!(serde_json::to_value(action.body()).unwrap(), body);
        assert_eq!(action.if_match().as_str(), ACTION_ETAG);
        assert!(action.href().starts_with("/v1/records/cases/"));
        assert!(action.href().ends_with("?accessProfile=case-worker"));
        assert!(action.matches_source("https://registry.example/base/"));
        assert!(action.matches_record_identifier(RECORD_ID));
    }
}

#[test]
fn only_apply_accepts_a_bounded_reason() {
    let metadata = BRegRequestMetadata::from_value(request_metadata(all_actions()), false).unwrap();
    let actions = metadata
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap();
    for action in actions {
        if action.operation() != BRegLifecycleOperation::ApplyRequest {
            assert!(action.with_reason("explanation").is_err());
            continue;
        }
        let reason = "  applied after external approval\nเหตุผล 📝  ";
        let with_reason = action.with_reason(reason).unwrap();
        assert_eq!(with_reason.body().to_value()["reason"], reason);
        assert!(!format!("{with_reason:?}").contains(reason));
        assert!(action.with_reason("📝".repeat(4097)).is_err());
        assert!(action.with_reason("contains\0NUL").is_err());
    }
}

#[test]
fn legacy_actions_states_and_projection_members_are_refused() {
    for operation in ["approve_request", "reject_request", "request_revision"] {
        let mut value = request_metadata(Vec::new());
        value["actions"] = json!([{"operation": operation, "method": "POST", "href": "/v1/records/cases/00000000-0000-4000-8000-000000000001/actions/approve?accessProfile=case-worker", "ifMatch": ACTION_ETAG}]);
        assert_eq!(
            BRegRequestMetadata::from_value(value, false).unwrap_err(),
            BRegLifecycleDecodeError::Profile
        );
    }
    for state in ["approved", "needs_changes", "rejected", "canceled"] {
        let mut value = request_metadata(Vec::new());
        value["bregState"] = json!(state);
        assert!(BRegRequestMetadata::from_value(value, false).is_err());
    }
    for member in ["decisions", "reviewTiming"] {
        let mut value = request_metadata(Vec::new());
        value[member] = json!([]);
        assert!(BRegRequestMetadata::from_value(value, false).is_err());
    }
    let mut value = request_metadata(Vec::new());
    value["proposal"] = json!({"reviewMode":"staged", "applicationDisposition":"apply"});
    assert!(BRegRequestMetadata::from_value(value, false).is_err());
}

#[test]
fn review_requirement_is_closed_and_typed() {
    let required = BRegRequestMetadata::from_value(request_metadata(Vec::new()), false).unwrap();
    let BRegRequestReviewRequirement::External(requirement) = required.proposal().unwrap().review()
    else {
        panic!("external")
    };
    assert_eq!(requirement.authority(), "casework");
    assert_eq!(requirement.policy_id(), "address-review");

    let mut none = request_metadata(Vec::new());
    none["proposal"] = json!({"review":{"mode":"none"}});
    let none = BRegRequestMetadata::from_value(none, false).unwrap();
    assert_eq!(
        none.proposal().unwrap().review(),
        &BRegRequestReviewRequirement::None
    );

    for invalid in [
        json!({"review":{"mode":"external","authority":"casework","policyId":"p"}}),
        json!({"review":{"authority":"casework"}}),
        json!({"review":{"mode":"none","policyId":"p"}}),
    ] {
        let mut value = request_metadata(Vec::new());
        value["proposal"] = invalid;
        assert!(BRegRequestMetadata::from_value(value, false).is_err());
    }
}

#[test]
fn external_review_status_is_strict_typed_and_value_redacted() {
    let mut value = request_metadata(Vec::new());
    value["review"] = accepted_review();
    let decoded = BRegRequestMetadata::from_value(value, false).unwrap();
    let review = decoded.review().unwrap();
    assert_eq!(
        review.submission().state(),
        BRegExternalReviewSubmissionState::Accepted
    );
    assert_eq!(review.submission().request_id(), Some(OTHER_ID));
    assert_eq!(
        review.result().state(),
        BRegExternalReviewResultState::Approved
    );
    assert_eq!(review.delivery().event_id(), Some(EVENT_ID));
    assert_eq!(
        review.application().mode(),
        BRegExternalReviewApplicationMode::Automatic
    );
    assert_eq!(review.application().application_id(), Some(APPLICATION_ID));
    assert_eq!(
        review.recovery().state(),
        BRegExternalReviewRecoveryState::None
    );
    let debug = format!("{decoded:?}");
    for secret in [
        OTHER_ID,
        RESULT_ID,
        EVENT_ID,
        APPLICATION_ID,
        DIGEST,
        "casework",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn external_review_status_refuses_partial_or_inconsistent_correlations() {
    let mut cases = Vec::new();
    let mut missing_policy = accepted_review();
    missing_policy["submission"]
        .as_object_mut()
        .unwrap()
        .remove("policy");
    cases.push(missing_policy);
    let mut pending_with_id = accepted_review();
    pending_with_id["submission"]["state"] = json!("pending");
    cases.push(pending_with_id);
    let mut result_partial = accepted_review();
    result_partial["result"]
        .as_object_mut()
        .unwrap()
        .remove("availableUntil");
    cases.push(result_partial);
    let mut delivery_partial = accepted_review();
    delivery_partial["delivery"]
        .as_object_mut()
        .unwrap()
        .remove("receivedAt");
    cases.push(delivery_partial);
    let mut manual_executor = accepted_review();
    manual_executor["application"]["mode"] = json!("manual");
    cases.push(manual_executor);
    let mut non_utc = accepted_review();
    non_utc["result"]["completedAt"] = json!("2026-09-19T08:00:00+07:00");
    cases.push(non_utc);
    for review in cases {
        let mut value = request_metadata(Vec::new());
        value["review"] = review;
        assert!(BRegRequestMetadata::from_value(value, false).is_err());
    }
}

#[test]
fn exact_authority_record_href_and_precondition_binding_is_required() {
    let metadata = BRegRequestMetadata::from_value(request_metadata(all_actions()), false).unwrap();
    assert!(metadata
        .promote_actions(&authority("other"), &record_binding())
        .is_err());
    let other = BRegLifecycleRecordBinding::new(
        "registry".into(),
        "requests".into(),
        "cases".into(),
        OTHER_ID.into(),
        4,
    )
    .unwrap();
    assert!(metadata
        .promote_actions(&authority("case-worker"), &other)
        .is_err());

    let mut changed = request_metadata(all_actions());
    changed["actions"][0]["href"] = json!(format!(
        "/v1/records/cases/{OTHER_ID}/actions/submit?accessProfile=case-worker"
    ));
    let changed = BRegRequestMetadata::from_value(changed, false).unwrap();
    assert!(changed
        .promote_actions(&authority("case-worker"), &record_binding())
        .is_err());

    let mut duplicate = request_metadata(all_actions());
    let first = duplicate["actions"][0].clone();
    duplicate["actions"].as_array_mut().unwrap().push(first);
    assert!(BRegRequestMetadata::from_value(duplicate, false).is_err());
}

#[test]
fn receipt_acceptance_uses_exact_action_state_and_application_binding() {
    let metadata = BRegRequestMetadata::from_value(request_metadata(all_actions()), false).unwrap();
    let actions = metadata
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap();
    for action in actions {
        let receipt = receipt_for(action.operation());
        assert!(action.accepts_receipt(&receipt));
        let mut wrong = receipt.to_value();
        wrong["id"] = json!(OTHER_ID);
        assert!(!action.accepts_receipt(&BRegLifecycleActionReceipt::from_value(wrong).unwrap()));
    }
}

fn request_metadata(actions: Vec<Value>) -> Value {
    json!({
        "bregState": "submitted",
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "proposal": {"review": {"authority": "casework", "policyId": "address-review"}},
        "editable": false,
        "actions": actions,
    })
}

fn all_actions() -> Vec<Value> {
    BRegLifecycleOperation::ALL
        .into_iter()
        .map(action)
        .collect()
}

fn action(operation: BRegLifecycleOperation) -> Value {
    let mut value = json!({
        "operation": operation.identifier(),
        "method": "POST",
        "href": format!("/v1/records/cases/{RECORD_ID}{}?accessProfile=case-worker", action_suffix(operation)),
        "ifMatch": ACTION_ETAG,
    });
    match operation {
        BRegLifecycleOperation::ReviseRequest => value["rebase"] = json!(true),
        BRegLifecycleOperation::ApplyRequest => {
            value["proposalVersion"] = json!(7);
            value["effectDigest"] = json!(DIGEST);
        }
        _ => {}
    }
    value
}

fn authority(profile: &str) -> BRegLifecycleAuthority {
    let bindings = BRegLifecycleOperation::ALL
        .into_iter()
        .map(|operation| {
            BRegLifecycleOperationBinding::new(
                operation,
                format!(
                    "/v1/records/cases/{{record_id}}{}",
                    action_suffix(operation)
                ),
            )
        })
        .collect();
    BRegLifecycleAuthority::new(
        "registry".into(),
        "requests".into(),
        "sha256:metadata-revision".into(),
        "cases".into(),
        profile.into(),
        "https://registry.example/base/".into(),
        bindings,
    )
    .unwrap()
}

fn action_suffix(operation: BRegLifecycleOperation) -> &'static str {
    match operation {
        BRegLifecycleOperation::SubmitRequest => "/actions/submit",
        BRegLifecycleOperation::ReviseRequest => "/actions/revise",
        BRegLifecycleOperation::CancelRequest => "/actions/cancel",
        BRegLifecycleOperation::ApplyRequest => "/actions/apply",
    }
}

fn record_binding() -> BRegLifecycleRecordBinding {
    BRegLifecycleRecordBinding::new(
        "registry".into(),
        "requests".into(),
        "cases".into(),
        RECORD_ID.into(),
        4,
    )
    .unwrap()
}

fn accepted_review() -> Value {
    json!({
        "submission": {"state":"accepted", "authority":"casework", "requestId":OTHER_ID, "submissionDigest":DIGEST, "policy":{"id":"address-review", "version":"1", "digest":DIGEST}},
        "result": {"state":"approved", "resultId":RESULT_ID, "completedAt":"2026-09-19T01:00:00Z", "availableUntil":"2026-10-19T01:00:00Z"},
        "delivery": {"state":"received", "eventId":EVENT_ID, "receivedAt":"2026-09-19T01:00:01Z"},
        "application": {"mode":"automatic", "state":"applied", "executor":"breg-worker", "applicationId":APPLICATION_ID},
        "recovery": {"state":"none"},
    })
}

fn receipt_for(operation: BRegLifecycleOperation) -> BRegLifecycleActionReceipt {
    let (state, proposal_version, effect_digest, application) = match operation {
        BRegLifecycleOperation::SubmitRequest => {
            ("submitted", json!(7), json!(DIGEST), Value::Null)
        }
        BRegLifecycleOperation::ReviseRequest => ("draft", json!(8), Value::Null, Value::Null),
        BRegLifecycleOperation::CancelRequest => {
            ("cancelled", json!(7), json!(DIGEST), Value::Null)
        }
        BRegLifecycleOperation::ApplyRequest => (
            "applied",
            json!(7),
            json!(DIGEST),
            json!({"applicationId":APPLICATION_ID,"proposalVersion":7,"effectDigest":DIGEST,"appliedAt":"2026-09-19T01:00:00Z"}),
        ),
    };
    BRegLifecycleActionReceipt::from_value(json!({
        "id": RECORD_ID,
        "revision": 5,
        "snapshot": format!("breg1_{OTHER_ID}"),
        "request": {"bregState":state,"proposalVersion":proposal_version,"effectDigest":effect_digest,"application":application}
    }))
    .unwrap()
}

#[test]
fn retained_history_exposes_exact_inert_application_results() {
    let mut request = request_metadata(vec![]);
    request["bregState"] = json!("applied");
    request["application"] = retained_application();
    request["history"] = json!({
        "proposals": [retained_proposal(
            7,
            true,
            Some(APPLICATION_ID),
            vec![json!({
                "targetEntityId": "case-target",
                "targetRecordId": TARGET_ID,
                "targetRevision": 4
            })]
        )],
        "nextAfterProposalVersion": 7
    });
    let decoded = BRegRequestMetadata::from_value(request, false).unwrap();
    let history = decoded.retained_history().expect("history was loaded");
    assert_eq!(history.next_after_proposal_version().unwrap().get(), 7);
    let proposal = history
        .find_application(
            "case-request",
            uuid::Uuid::parse_str(RECORD_ID).unwrap(),
            decoded.proposal_version(),
            uuid::Uuid::parse_str(APPLICATION_ID).unwrap(),
        )
        .expect("exact application is on this page");
    assert_eq!(proposal.breg_state(), BRegRequestState::Applied);
    assert_eq!(proposal.result_link_count(), 1);
    assert_eq!(proposal.result_references().len(), 1);
    assert_eq!(
        proposal.result_references()[0].target_entity_identifier(),
        "case-target"
    );
    assert_eq!(proposal.result_references()[0].target_revision(), 4);
    assert!(history
        .find_application(
            "case-request",
            uuid::Uuid::parse_str(RECORD_ID).unwrap(),
            decoded.proposal_version(),
            uuid::Uuid::parse_str(TARGET_ID).unwrap(),
        )
        .is_none());

    let debug = format!(
        "{history:?} {proposal:?} {:?}",
        proposal.result_references()
    );
    for secret in [RECORD_ID, TARGET_ID, APPLICATION_ID, "case-target"] {
        assert!(!debug.contains(secret), "debug output leaked {secret}");
    }
}

#[test]
fn retained_history_distinguishes_not_loaded_from_an_observed_empty_result_list() {
    let mut absent = request_metadata(vec![]);
    absent.as_object_mut().unwrap().remove("history");
    assert!(BRegRequestMetadata::from_value(absent, false)
        .unwrap()
        .retained_history()
        .is_none());

    let mut exhausted = request_metadata(vec![]);
    exhausted["history"] = Value::Null;
    assert!(BRegRequestMetadata::from_value(exhausted, false)
        .unwrap()
        .retained_history()
        .is_none());

    let mut observed = request_metadata(vec![]);
    observed["history"] = json!({
        "proposals": [retained_proposal(6, false, None, vec![])],
        "nextAfterProposalVersion": null
    });
    let observed = BRegRequestMetadata::from_value(observed, false).unwrap();
    let proposal = &observed.retained_history().unwrap().proposals()[0];
    assert_eq!(proposal.result_link_count(), 0);
    assert!(proposal.result_references().is_empty());
}

#[test]
fn applied_history_accepts_an_earlier_unapplied_proposal() {
    let mut request = request_metadata(vec![]);
    request["bregState"] = json!("applied");
    request["application"] = retained_application();
    let mut earlier = retained_proposal(6, false, None, vec![]);
    earlier["bregState"] = json!("applied");
    request["history"] = json!({
        "proposals": [
            earlier,
            retained_proposal(7, true, Some(APPLICATION_ID), vec![]),
        ],
        "nextAfterProposalVersion": null
    });

    let decoded = BRegRequestMetadata::from_value(request, false).unwrap();
    let history = decoded.retained_history().expect("history was loaded");
    assert_eq!(history.proposals().len(), 2);
    assert!(history.proposals()[0].application_identifier().is_none());
    assert_eq!(
        history.proposals()[0].breg_state(),
        BRegRequestState::Applied
    );
    assert!(history.proposals()[1].application_identifier().is_some());
}

#[test]
fn retained_history_refuses_malformed_and_inconsistent_shapes() {
    let valid_result = json!({
        "targetEntityId": "case-target",
        "targetRecordId": TARGET_ID,
        "targetRevision": 4
    });
    let valid = retained_proposal(7, true, Some(APPLICATION_ID), vec![valid_result.clone()]);
    let candidates = [
        ("requestEntityId", json!("bad id")),
        ("requestId", json!("not-a-uuid")),
        ("proposalVersion", json!(0)),
        ("resultLinkCount", json!(2)),
        ("applicationId", Value::Null),
        ("bregState", json!("submitted")),
        ("unknown", json!(true)),
    ];
    for (field, value) in candidates {
        let mut request = request_metadata(vec![]);
        request["bregState"] = json!("applied");
        let mut proposal = valid.clone();
        proposal[field] = value;
        request["history"] = json!({"proposals": [proposal], "nextAfterProposalVersion": null});
        assert!(
            BRegRequestMetadata::from_value(request, false).is_err(),
            "accepted {field}"
        );
    }
    for (field, value) in [
        ("targetEntityId", json!("bad id")),
        ("targetRecordId", json!("not-a-uuid")),
        ("targetRevision", json!(0)),
        ("targetRevision", json!(9_007_199_254_740_992_u64)),
        ("unknown", json!(true)),
    ] {
        let mut request = request_metadata(vec![]);
        request["bregState"] = json!("applied");
        let mut result = valid_result.clone();
        result[field] = value;
        request["history"] = json!({
            "proposals": [retained_proposal(7, true, Some(APPLICATION_ID), vec![result])],
            "nextAfterProposalVersion": null
        });
        assert!(
            BRegRequestMetadata::from_value(request, false).is_err(),
            "accepted {field}"
        );
    }
    let mut invalid_cursor = request_metadata(vec![]);
    invalid_cursor["history"] = json!({
        "proposals": [retained_proposal(6, false, None, vec![])],
        "nextAfterProposalVersion": 5
    });
    assert!(BRegRequestMetadata::from_value(invalid_cursor, false).is_err());
}

fn retained_proposal(
    proposal_version: u32,
    current: bool,
    application_id: Option<&str>,
    result_links: Vec<Value>,
) -> Value {
    json!({
        "requestEntityId": "case-request",
        "requestId": RECORD_ID,
        "proposalVersion": proposal_version,
        "bregState": if application_id.is_some() { "applied" } else { "submitted" },
        "current": current,
        "contractFingerprint": DIGEST,
        "detailErased": false,
        "applicationId": application_id,
        "resultLinkCount": result_links.len(),
        "resultLinks": result_links,
        "effectDigest": DIGEST
    })
}

fn retained_application() -> Value {
    json!({
        "applicationId": APPLICATION_ID,
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "appliedAt": "2026-09-19T01:00:00Z"
    })
}
