#![allow(dead_code)]

#[path = "../src/server_lifecycle.rs"]
mod server_lifecycle;
#[path = "../src/strict_json.rs"]
mod strict_json;

use std::collections::BTreeMap;

use serde_json::{json, Value};
use server_lifecycle::*;

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
const TARGET_ID: &str = "00000000-0000-4000-8000-000000000002";
const APPLICATION_ID: &str = "00000000-0000-4000-8000-000000000003";
const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACTION_ETAG: &str =
    "\"rs-action-hmac-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"";

#[test]
fn all_seven_actions_promote_and_synthesize_exact_bodies() {
    let metadata =
        RegistryServerRequestMetadata::from_value(request_metadata(all_actions()), false)
            .expect("request metadata conforms");
    let actions = metadata
        .promote_actions(&authority("case-worker"), &record_binding())
        .expect("every action is metadata and record bound");

    assert_eq!(actions.len(), 7);
    let expected = [
        (RegistryServerLifecycleOperation::SubmitRequest, json!({})),
        (
            RegistryServerLifecycleOperation::ApproveRequest,
            json!({"proposalVersion": 7, "effectDigest": DIGEST}),
        ),
        (
            RegistryServerLifecycleOperation::RejectRequest,
            json!({"proposalVersion": 7, "effectDigest": DIGEST}),
        ),
        (
            RegistryServerLifecycleOperation::RequestRevision,
            json!({"proposalVersion": 7, "effectDigest": DIGEST}),
        ),
        (
            RegistryServerLifecycleOperation::ReviseRequest,
            json!({"rebase": true}),
        ),
        (RegistryServerLifecycleOperation::CancelRequest, json!({})),
        (
            RegistryServerLifecycleOperation::ApplyRequest,
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
        assert_eq!(action.registry_revision(), "sha256:metadata-revision");
        assert!(action.matches_source("https://registry.example/base/"));
        assert!(!action.matches_source("https://other.example/base/"));
        assert!(action.matches_record_identifier(RECORD_ID));
        assert!(!action.matches_record_identifier(TARGET_ID));
    }
    assert_eq!(
        actions[1].stage(),
        Some("review"),
        "review actions retain their exact metadata-bound stage"
    );
    assert_eq!(actions[1].review().unwrap().targets().len(), 1);
    assert_eq!(
        actions[1].review().unwrap().targets()[0].operation(),
        RegistryServerReviewOperation::Patch
    );
}

#[test]
fn advisory_links_do_not_promote_across_profile_record_route_or_metadata_context() {
    let metadata = RegistryServerRequestMetadata::from_value(
        request_metadata(vec![action(
            RegistryServerLifecycleOperation::SubmitRequest,
            None,
        )]),
        false,
    )
    .unwrap();

    assert_eq!(
        metadata
            .promote_actions(&authority("other-profile"), &record_binding())
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );

    let wrong_record = RegistryServerLifecycleRecordBinding::new(
        "case-registry".to_owned(),
        "case-dataset".to_owned(),
        "case".to_owned(),
        TARGET_ID.to_owned(),
        8,
    )
    .unwrap();
    assert_eq!(
        metadata
            .promote_actions(&authority("case-worker"), &wrong_record)
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );

    let wrong_entity = RegistryServerLifecycleRecordBinding::new(
        "case-registry".to_owned(),
        "case-dataset".to_owned(),
        "other-entity".to_owned(),
        RECORD_ID.to_owned(),
        8,
    )
    .unwrap();
    assert_eq!(
        metadata
            .promote_actions(&authority("case-worker"), &wrong_entity)
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );

    let wrong_dataset = RegistryServerLifecycleRecordBinding::new(
        "case-registry".to_owned(),
        "other-dataset".to_owned(),
        "case".to_owned(),
        RECORD_ID.to_owned(),
        8,
    )
    .unwrap();
    assert_eq!(
        metadata
            .promote_actions(&authority("case-worker"), &wrong_dataset)
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );

    let mut bindings = operation_bindings();
    bindings[0] = RegistryServerLifecycleOperationBinding::new(
        RegistryServerLifecycleOperation::SubmitRequest,
        "/v1/records/other/{record_id}/actions/submit".to_owned(),
        None,
    );
    let wrong_route = RegistryServerLifecycleAuthority::new(
        "case-registry".to_owned(),
        "case-dataset".to_owned(),
        "sha256:metadata-revision".to_owned(),
        "case".to_owned(),
        "case-worker".to_owned(),
        "https://registry.example/base/".to_owned(),
        bindings,
    )
    .unwrap();
    assert_eq!(
        metadata
            .promote_actions(&wrong_route, &record_binding())
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );
}

#[test]
fn action_links_refuse_non_relative_origins_generic_etags_and_inexact_bindings() {
    let base = action(RegistryServerLifecycleOperation::SubmitRequest, None);
    for mutation in [
        ("href", json!("https://attacker.test/actions/submit")),
        ("href", json!("//attacker.test/actions/submit")),
        (
            "href",
            json!(format!(
                "/v1/records/cases/{RECORD_ID}/actions/submit?accessProfile=case-worker&next=1"
            )),
        ),
        ("ifMatch", json!("\"rs-ordinary-record\"")),
        ("method", json!("PATCH")),
    ] {
        let mut candidate = base.clone();
        candidate[mutation.0] = mutation.1;
        assert!(RegistryServerRequestMetadata::from_value(
            request_metadata(vec![candidate]),
            false
        )
        .is_err());
    }

    let mut duplicate = base.clone();
    duplicate["ifMatch"] = json!(
        "\"rs-action-hmac-sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
    );
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![base, duplicate]),
        false
    )
    .is_err());
}

#[test]
fn proposal_digest_stage_review_and_rebase_are_operation_bound() {
    let mut approve = action(
        RegistryServerLifecycleOperation::ApproveRequest,
        Some("review"),
    );
    approve.as_object_mut().unwrap().remove("effectDigest");
    assert!(
        RegistryServerRequestMetadata::from_value(request_metadata(vec![approve]), false).is_err()
    );

    let mut uppercase_digest = action(RegistryServerLifecycleOperation::ApplyRequest, None);
    uppercase_digest["effectDigest"] = json!(DIGEST.to_ascii_uppercase());
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![uppercase_digest]),
        false
    )
    .is_err());

    let mut zero_version = action(
        RegistryServerLifecycleOperation::RejectRequest,
        Some("review"),
    );
    zero_version["proposalVersion"] = json!(0);
    assert!(
        RegistryServerRequestMetadata::from_value(request_metadata(vec![zero_version]), false)
            .is_err()
    );

    let mut submit_with_stage = action(RegistryServerLifecycleOperation::SubmitRequest, None);
    submit_with_stage["stage"] = json!("review");
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![submit_with_stage]),
        false
    )
    .is_err());

    let mut revise_without_rebase = action(RegistryServerLifecycleOperation::ReviseRequest, None);
    revise_without_rebase
        .as_object_mut()
        .unwrap()
        .remove("rebase");
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![revise_without_rebase]),
        false
    )
    .is_err());

    let mut submit_with_rebase = action(RegistryServerLifecycleOperation::SubmitRequest, None);
    submit_with_rebase["rebase"] = json!(false);
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![submit_with_rebase]),
        false
    )
    .is_err());

    let mut stale_record_projection = request_metadata(vec![action(
        RegistryServerLifecycleOperation::ApplyRequest,
        None,
    )]);
    stale_record_projection["proposalVersion"] = json!(8);
    let stale_record_projection =
        RegistryServerRequestMetadata::from_value(stale_record_projection, false).unwrap();
    assert_eq!(
        stale_record_projection
            .promote_actions(&authority("case-worker"), &record_binding())
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );
}

#[test]
fn review_previews_enforce_target_and_object_bounds() {
    let review_action = action(
        RegistryServerLifecycleOperation::ApproveRequest,
        Some("review"),
    );
    let target = review_action["review"]["targets"][0].clone();

    let mut too_many_targets = review_action.clone();
    too_many_targets["review"]["targets"] =
        Value::Array(vec![target.clone(); MAX_REGISTRY_SERVER_REVIEW_TARGETS + 1]);
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![too_many_targets]),
        false
    )
    .is_err());

    let mut too_many_members = review_action.clone();
    too_many_members["review"]["targets"][0]["after"] = Value::Object(
        (0..=MAX_REGISTRY_SERVER_REVIEW_OBJECT_MEMBERS)
            .map(|index| (format!("field{index}"), json!(index)))
            .collect(),
    );
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![too_many_members]),
        false
    )
    .is_err());

    let mut create_with_patch_binding = review_action;
    let preview = &mut create_with_patch_binding["review"]["targets"][0];
    preview["operation"] = json!("create");
    assert!(RegistryServerRequestMetadata::from_value(
        request_metadata(vec![create_with_patch_binding]),
        false
    )
    .is_err());
}

#[test]
fn record_application_shape_tracks_retained_or_erased_detail() {
    let retained =
        RegistryServerRequestMetadata::from_value(request_metadata(Vec::new()), false).unwrap();
    assert!(matches!(
        retained.application(),
        Some(RegistryServerRecordApplication::Retained(_))
    ));

    let mut redacted_retained = request_metadata(Vec::new());
    redacted_retained["application"]
        .as_object_mut()
        .unwrap()
        .remove("effectDigest");
    let redacted_retained =
        RegistryServerRequestMetadata::from_value(redacted_retained, false).unwrap();
    let Some(RegistryServerRecordApplication::Retained(application)) =
        redacted_retained.application()
    else {
        panic!("redacted retained application is modeled distinctly from erasure");
    };
    assert!(application.effect_digest().is_none());

    let erased_value = json!({
        "serverState": "applied",
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "editable": false,
        "detailErased": true,
        "application": {
            "applicationId": APPLICATION_ID,
            "proposalVersion": 7
        }
    });
    let erased = RegistryServerRequestMetadata::from_value(erased_value.clone(), true).unwrap();
    assert!(matches!(
        erased.application(),
        Some(RegistryServerRecordApplication::Erased(_))
    ));

    assert!(
        RegistryServerRequestMetadata::from_value(erased_value_with_full_application(), true)
            .is_err()
    );
    assert!(RegistryServerRequestMetadata::from_value(erased_value, false).is_err());

    let mut false_marker = request_metadata(Vec::new());
    false_marker["detailErased"] = json!(false);
    assert!(RegistryServerRequestMetadata::from_value(false_marker, false).is_err());

    let mut null_application = request_metadata(Vec::new());
    null_application["application"] = Value::Null;
    assert!(RegistryServerRequestMetadata::from_value(null_application, false).is_ok());
}

#[test]
fn action_receipt_is_distinct_exact_and_requires_full_application() {
    assert!(RegistryServerLifecycleActionReceipt::from_slice(
        br#"{"id":"00000000-0000-4000-8000-000000000001","id":"00000000-0000-4000-8000-000000000002","revision":9,"snapshot":"rs1_00000000-0000-4000-8000-000000000001","request":{"serverState":"canceled","proposalVersion":7,"effectDigest":null,"application":null}}"#
    )
    .is_err());
    let receipt = RegistryServerLifecycleActionReceipt::from_value(json!({
        "id": RECORD_ID,
        "revision": 9,
        "snapshot": format!("rs1_{RECORD_ID}"),
        "request": {
            "serverState": "applied",
            "proposalVersion": 7,
            "effectDigest": DIGEST,
            "application": retained_application()
        }
    }))
    .expect("action receipt conforms");
    assert_eq!(receipt.record_identifier(), RECORD_ID);
    assert_eq!(receipt.revision(), 9);
    assert_eq!(
        receipt.request().server_state(),
        RegistryServerRequestState::Applied
    );
    assert_eq!(
        receipt.request().application().unwrap().applied_at(),
        "2026-09-01T12:00:00Z"
    );

    for invalid in [
        json!({
            "id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "revision": 9, "snapshot": "rs1_x",
            "request": {"serverState":"applied", "proposalVersion":7, "effectDigest":DIGEST, "application":retained_application()}
        }),
        json!({
            "id": RECORD_ID, "revision": 0, "snapshot": "rs1_x",
            "request": {"serverState":"applied", "proposalVersion":7, "effectDigest":DIGEST, "application":retained_application()}
        }),
        json!({
            "id": RECORD_ID, "revision": 9, "snapshot": "",
            "request": {"serverState":"applied", "proposalVersion":7, "effectDigest":DIGEST, "application":retained_application()}
        }),
        json!({
            "id": RECORD_ID, "revision": 9, "snapshot": "rs1_x",
            "request": {"serverState":"applied", "proposalVersion":7, "effectDigest":DIGEST,
                "application":{"applicationId":APPLICATION_ID,"proposalVersion":7}}
        }),
    ] {
        assert!(RegistryServerLifecycleActionReceipt::from_value(invalid).is_err());
    }

    let nullable = RegistryServerLifecycleActionReceipt::from_value(json!({
        "id": RECORD_ID,
        "revision": 1,
        "snapshot": "opaque",
        "request": {
            "serverState": "canceled",
            "proposalVersion": null,
            "effectDigest": null,
            "application": null
        }
    }))
    .unwrap();
    assert!(nullable.request().proposal_version().is_none());
    assert!(nullable.request().effect_digest().is_none());
    assert!(nullable.request().application().is_none());
}

#[test]
fn receipt_acceptance_tracks_operation_specific_proposal_transitions() {
    let draft = RegistryServerRequestMetadata::from_value(
        json!({
            "serverState": "draft",
            "proposalVersion": 7,
            "effectDigest": null,
            "editable": true,
            "actions": [action(RegistryServerLifecycleOperation::SubmitRequest, None)]
        }),
        false,
    )
    .unwrap();
    let submit = draft
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap()
        .remove(0);
    let submitted = lifecycle_receipt("submitted", 7, Some(DIGEST));
    assert!(submit.accepts_receipt(&submitted));
    assert!(!submit.accepts_receipt(&lifecycle_receipt("submitted", 7, None)));
    assert!(!submit.accepts_receipt(&lifecycle_receipt_at(10, "submitted", 7, Some(DIGEST),)));

    let approve = RegistryServerRequestMetadata::from_value(
        request_metadata(vec![action(
            RegistryServerLifecycleOperation::ApproveRequest,
            Some("review"),
        )]),
        false,
    )
    .unwrap()
    .promote_actions(&authority("case-worker"), &record_binding())
    .unwrap()
    .remove(0);
    assert!(approve.accepts_receipt(&lifecycle_receipt("submitted", 7, Some(DIGEST))));
    assert!(approve.accepts_receipt(&lifecycle_receipt("approved", 7, Some(DIGEST))));
    assert!(!approve.accepts_receipt(&lifecycle_receipt("draft", 7, Some(DIGEST))));

    let needs_changes = RegistryServerRequestMetadata::from_value(
        json!({
            "serverState": "needs_changes",
            "proposalVersion": 7,
            "effectDigest": DIGEST,
            "editable": true,
            "actions": [action(RegistryServerLifecycleOperation::ReviseRequest, None)]
        }),
        false,
    )
    .unwrap();
    let revise = needs_changes
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap()
        .remove(0);
    assert!(revise.accepts_receipt(&lifecycle_receipt("draft", 8, None)));
    assert!(!revise.accepts_receipt(&lifecycle_receipt("draft", 7, Some(DIGEST))));
}

#[test]
fn record_helpers_extract_exact_extension_and_bind_envelope_context() {
    let request = request_metadata(vec![action(
        RegistryServerLifecycleOperation::SubmitRequest,
        None,
    )]);
    let record = RegistryRecord {
        record_identifier: RECORD_ID.to_owned(),
        revision_identifier: "8".to_owned(),
        domain_data: BTreeMap::from([("title".to_owned(), json!("case"))]),
        extensions: BTreeMap::from([("request".to_owned(), request)]),
    };
    let metadata = RegistryServerRequestMetadata::from_record(&record)
        .unwrap()
        .expect("request extension is present");
    let meta = RegistryRecordMeta {
        registry_identifier: "case-registry".to_owned(),
        dataset_identifier: "case-dataset".to_owned(),
        entity_type_identifier: "case".to_owned(),
    };
    let binding = RegistryServerLifecycleRecordBinding::from_record(&meta, &record).unwrap();
    assert_eq!(
        metadata
            .promote_actions(&authority("case-worker"), &binding)
            .unwrap()
            .len(),
        1
    );

    let noncanonical_revision = RegistryRecord {
        record_identifier: RECORD_ID.to_owned(),
        revision_identifier: "08".to_owned(),
        domain_data: BTreeMap::new(),
        extensions: BTreeMap::new(),
    };
    assert_eq!(
        RegistryServerLifecycleRecordBinding::from_record(&meta, &noncanonical_revision)
            .unwrap_err(),
        RegistryServerLifecyclePromotionError::Binding
    );

    let ordinary = RegistryRecord {
        record_identifier: RECORD_ID.to_owned(),
        revision_identifier: "8".to_owned(),
        domain_data: BTreeMap::new(),
        extensions: BTreeMap::new(),
    };
    assert!(RegistryServerRequestMetadata::from_record(&ordinary)
        .unwrap()
        .is_none());

    let authority = authority("case-worker");
    assert_eq!(authority.registry_revision(), "sha256:metadata-revision");
    assert!(authority.matches_source("https://registry.example/base/"));
    assert!(!authority.matches_source("https://other.example/base/"));
}

#[test]
fn errors_and_debug_output_do_not_echo_response_controlled_values() {
    let secret = "citizen-national-identifier-123";
    let error = RegistryServerRequestMetadata::from_value(
        json!({"serverState": "attacker", "proposalVersion": 1, "editable": false, secret: secret}),
        false,
    )
    .unwrap_err();
    assert!(!format!("{error:?}").contains(secret));
    assert!(!error.to_string().contains(secret));

    let metadata =
        RegistryServerRequestMetadata::from_value(request_metadata(all_actions()), false).unwrap();
    let debug = format!("{metadata:?}");
    for value in [
        RECORD_ID,
        TARGET_ID,
        APPLICATION_ID,
        DIGEST,
        ACTION_ETAG,
        "case-worker",
    ] {
        assert!(!debug.contains(value), "debug output leaked {value}");
    }
    let promoted = metadata
        .promote_actions(&authority("case-worker"), &record_binding())
        .unwrap();
    let debug = format!("{:?}", promoted[1]);
    for value in [RECORD_ID, TARGET_ID, DIGEST, ACTION_ETAG, "case-worker"] {
        assert!(
            !debug.contains(value),
            "promoted debug output leaked {value}"
        );
    }
}

fn request_metadata(actions: Vec<Value>) -> Value {
    json!({
        "serverState": "submitted",
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "editable": false,
        "actions": actions,
        "application": retained_application(),
        "history": {"proposals": [], "nextAfterProposalVersion": null}
    })
}

fn erased_value_with_full_application() -> Value {
    json!({
        "serverState": "applied",
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "editable": false,
        "detailErased": true,
        "application": retained_application()
    })
}

fn retained_application() -> Value {
    json!({
        "applicationId": APPLICATION_ID,
        "proposalVersion": 7,
        "effectDigest": DIGEST,
        "appliedAt": "2026-09-01T12:00:00Z"
    })
}

fn lifecycle_receipt(
    state: &str,
    proposal_version: u32,
    effect_digest: Option<&str>,
) -> RegistryServerLifecycleActionReceipt {
    lifecycle_receipt_at(9, state, proposal_version, effect_digest)
}

fn lifecycle_receipt_at(
    revision: u64,
    state: &str,
    proposal_version: u32,
    effect_digest: Option<&str>,
) -> RegistryServerLifecycleActionReceipt {
    RegistryServerLifecycleActionReceipt::from_value(json!({
        "id": RECORD_ID,
        "revision": revision,
        "snapshot": format!("rs1_{RECORD_ID}"),
        "request": {
            "serverState": state,
            "proposalVersion": proposal_version,
            "effectDigest": effect_digest,
            "application": null
        }
    }))
    .unwrap()
}

fn all_actions() -> Vec<Value> {
    vec![
        action(RegistryServerLifecycleOperation::SubmitRequest, None),
        action(
            RegistryServerLifecycleOperation::ApproveRequest,
            Some("review"),
        ),
        action(
            RegistryServerLifecycleOperation::RejectRequest,
            Some("review"),
        ),
        action(
            RegistryServerLifecycleOperation::RequestRevision,
            Some("review"),
        ),
        action(RegistryServerLifecycleOperation::ReviseRequest, None),
        action(RegistryServerLifecycleOperation::CancelRequest, None),
        action(RegistryServerLifecycleOperation::ApplyRequest, None),
    ]
}

fn action(operation: RegistryServerLifecycleOperation, stage: Option<&str>) -> Value {
    let path = action_path(operation, stage).replace("{record_id}", RECORD_ID);
    let mut value = json!({
        "operation": operation.identifier(),
        "method": "POST",
        "href": format!("{path}?accessProfile=case-worker"),
        "ifMatch": ACTION_ETAG
    });
    if let Some(stage) = stage {
        value["stage"] = json!(stage);
    }
    if operation == RegistryServerLifecycleOperation::ReviseRequest {
        value["rebase"] = json!(true);
    }
    if matches!(
        operation,
        RegistryServerLifecycleOperation::ApproveRequest
            | RegistryServerLifecycleOperation::RejectRequest
            | RegistryServerLifecycleOperation::RequestRevision
            | RegistryServerLifecycleOperation::ApplyRequest
    ) {
        value["proposalVersion"] = json!(7);
        value["effectDigest"] = json!(DIGEST);
    }
    if operation.review_for_test() {
        value["review"] = json!({
            "targets": [{
                "entityId": "case-target",
                "recordId": TARGET_ID,
                "operation": "patch",
                "baseRevision": 3,
                "before": {"status": "old"},
                "after": {"status": "new"}
            }]
        });
    }
    value
}

trait ReviewOperationTest {
    fn review_for_test(self) -> bool;
}

impl ReviewOperationTest for RegistryServerLifecycleOperation {
    fn review_for_test(self) -> bool {
        matches!(
            self,
            Self::ApproveRequest | Self::RejectRequest | Self::RequestRevision
        )
    }
}

fn authority(access_profile: &str) -> RegistryServerLifecycleAuthority {
    RegistryServerLifecycleAuthority::new(
        "case-registry".to_owned(),
        "case-dataset".to_owned(),
        "sha256:metadata-revision".to_owned(),
        "case".to_owned(),
        access_profile.to_owned(),
        "https://registry.example/base/".to_owned(),
        operation_bindings(),
    )
    .unwrap()
}

fn operation_bindings() -> Vec<RegistryServerLifecycleOperationBinding> {
    RegistryServerLifecycleOperation::ALL
        .into_iter()
        .map(|operation| {
            let stage = operation.review_for_test().then(|| "review".to_owned());
            RegistryServerLifecycleOperationBinding::new(
                operation,
                action_path(operation, stage.as_deref()),
                stage,
            )
        })
        .collect()
}

fn action_path(operation: RegistryServerLifecycleOperation, stage: Option<&str>) -> String {
    let base = "/v1/records/cases/{record_id}/actions";
    match operation {
        RegistryServerLifecycleOperation::SubmitRequest => format!("{base}/submit"),
        RegistryServerLifecycleOperation::ApproveRequest => {
            format!("{base}/stages/{}/approve", stage.unwrap())
        }
        RegistryServerLifecycleOperation::RejectRequest => {
            format!("{base}/stages/{}/reject", stage.unwrap())
        }
        RegistryServerLifecycleOperation::RequestRevision => {
            format!("{base}/stages/{}/request-revision", stage.unwrap())
        }
        RegistryServerLifecycleOperation::ReviseRequest => format!("{base}/revise"),
        RegistryServerLifecycleOperation::CancelRequest => format!("{base}/cancel"),
        RegistryServerLifecycleOperation::ApplyRequest => format!("{base}/apply"),
    }
}

fn record_binding() -> RegistryServerLifecycleRecordBinding {
    RegistryServerLifecycleRecordBinding::new(
        "case-registry".to_owned(),
        "case-dataset".to_owned(),
        "case".to_owned(),
        RECORD_ID.to_owned(),
        8,
    )
    .unwrap()
}
