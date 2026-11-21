// SPDX-License-Identifier: Apache-2.0

//! Proposal review canaries.
//!
//! A reviewer reads a Proposal through its review context. Record-sourced
//! values and change sets are evaluated against the record's current state,
//! so a profile a disclosure condition binds never sees a withheld member.
//! Inputs and attachments are submitter content and are not filtered.

use super::client_http;

use super::fixture::{
    assert_has_sentinel, assert_no_sentinel, body_shape, compile_fixture, project_source,
    quote_identifier, CANARY_ADDRESS, CANARY_EMAIL, CANARY_PHONE, OPEN_PERSON_ID, PERSON_ID,
    PROTECTION_OFFICER, REGISTRAR, RESIDENCE_ID,
};
use registry_breg::api::VerifiedRequestClaims;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::disclosure::plan;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegIdempotencyKey, BRegProposal, BRegProposalState,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const PACKAGE_LABEL: &str = "client-capability-package-1";

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "reviewer",
        BTreeSet::new(),
        None,
        BTreeMap::new(),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}

fn action_grant(action: &str, record_type: &str, context: &[&str]) -> (Value, Value) {
    (
        json!({"action": action, "operations": ["start"],
            "targets": [{"recordType": record_type, "rowBoundaries": "unrestricted"}]}),
        json!({"action": action, "ownership": "caller",
            "operations": ["get", "list", "edit", "submit", "revise", "rebase", "retry",
                           "cancel", "apply", "get-review-context"],
            "readableAttachments": [], "writableAttachments": [],
            "readableContextFields": context,
            "targets": [{"recordType": record_type, "rowBoundaries": "unrestricted"}]}),
    )
}

/// The disclosure fixture with three Proposal Actions: a person correction
/// that reviews a contact and its changes, a person registration whose change
/// set is a create, and a residence correction.
fn proposal_project() -> Value {
    let mut source = project_source();
    source["recordTypes"]["person"]["mutationPolicy"] = json!({"patch": "proposal-required"});
    source["recordTypes"]["residence"]["mutationPolicy"] = json!({"patch": "proposal-required"});
    let proposal = |review: Value, attachments: Value| {
        json!({"review": {"type": "none"}, "application": {"mode": "manual"},
            "retention": {"mode": "operator-erase"}, "attachments": attachments,
            "reviewContext": review})
    };
    source["actions"] = json!({
        "correct-person": {"execution": {"mode": "proposal", "proposal": proposal(
            json!({"id": "review-person", "fields": {
                "contact": {"type": "record", "input": "target", "field": "email-address"},
                "changes": {"type": "changes", "recordType": "person",
                    "fields": ["family-name", "email-address"]}}}), json!([]))},
         "inputs": [
            {"id": "target", "type": "reference", "target": "person", "required": true, "classification": "internal"},
            {"id": "value", "type": "string", "required": true, "maximumLength": 64, "classification": "internal"}],
         "commitGuards": {"targets": [{"input": "target", "revision": "unchanged"}]},
         "plan": {"type": "fixed", "effects": [{"id": "name", "target": {"fromInput": "target"},
            "operation": "patch", "set": {"family-name": {"fromInput": "value"}}}]}},
        "register-person": {"execution": {"mode": "proposal", "proposal": proposal(
            json!({"id": "review-registration", "fields": {
                "changes": {"type": "changes", "recordType": "person",
                    "fields": ["family-name", "protection-level", "email-address"]}}}), json!([]))},
         "inputs": [
            {"id": "name", "type": "string", "required": true, "maximumLength": 64, "classification": "internal"},
            {"id": "level", "type": "string", "required": true, "maximumLength": 32, "classification": "internal"},
            {"id": "email", "type": "string", "required": true, "maximumLength": 128, "classification": "internal"}],
         "plan": {"type": "fixed", "effects": [{"id": "person", "operation": "create",
            "target": {"recordType": "person"}, "set": {
                "family-name": {"fromInput": "name"}, "protection-level": {"fromInput": "level"},
                "email-address": {"fromInput": "email"}}}]}},
        "correct-residence": {"execution": {"mode": "proposal", "proposal": proposal(
            json!({"id": "review-residence", "fields": {
                "residence": {"type": "changes", "recordType": "residence", "fields": ["address"]}}}),
            json!([]))},
         "inputs": [
            {"id": "target", "type": "reference", "target": "residence", "required": true, "classification": "internal"},
            {"id": "value", "type": "string", "required": true, "maximumLength": 128, "classification": "internal"}],
         "commitGuards": {"targets": [{"input": "target", "revision": "unchanged"}]},
         "plan": {"type": "fixed", "effects": [{"id": "address", "target": {"fromInput": "target"},
            "operation": "patch", "set": {"address": {"fromInput": "value"}}}]}}});
    for profile in source["accessProfiles"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        profile["principalClaim"] = json!("sub");
        let records = profile["permissions"]["records"].as_array_mut().unwrap();
        for grant in records.iter_mut() {
            let writable: &[&str] = match grant["recordType"].as_str().unwrap() {
                "person" => &["family-name", "protection-level", "email-address"],
                "residence" => &["address"],
                _ => &[],
            };
            grant["writableFields"] = json!(writable);
        }
        let mut actions = Vec::new();
        let mut proposals = Vec::new();
        for (action, record_type, context) in [
            ("correct-person", "person", &["contact", "changes"][..]),
            ("register-person", "person", &["changes"][..]),
            ("correct-residence", "residence", &["residence"][..]),
        ] {
            let (start, lifecycle) = action_grant(action, record_type, context);
            actions.push(start);
            proposals.push(lifecycle);
        }
        profile["permissions"]["actions"] = json!(actions);
        profile["permissions"]["proposals"] = json!(proposals);
    }
    source
}

async fn start_fixture() -> client_http::ClientFixture {
    let project = parse_project_json(&serde_json::to_vec(&proposal_project()).unwrap())
        .expect("proposal fixture parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("proposal fixture compiles");
    let fixture = client_http::ClientFixture::start(registry, claims()).await;
    seed(
        &fixture,
        "person",
        PERSON_ID,
        &[
            ("family-name", "Protected"),
            ("protection-level", "protected"),
            ("email-address", CANARY_EMAIL),
            ("phone-number", CANARY_PHONE),
        ],
    )
    .await;
    seed(
        &fixture,
        "person",
        OPEN_PERSON_ID,
        &[
            ("family-name", "Open"),
            ("protection-level", "none"),
            ("email-address", "open@example.invalid"),
        ],
    )
    .await;
    seed(
        &fixture,
        "residence",
        RESIDENCE_ID,
        &[
            ("person-id", OPEN_PERSON_ID),
            ("protection-level", "none"),
            ("address", CANARY_ADDRESS),
        ],
    )
    .await;
    fixture
}

fn physical(fixture: &client_http::ClientFixture, record_type: &str, field: &str) -> String {
    let entity = &fixture.registry.entities()[record_type];
    quote_identifier(&entity.fields[field].physical_name)
}

async fn seed(
    fixture: &client_http::ClientFixture,
    record_type: &str,
    record_id: &str,
    values: &[(&str, &str)],
) {
    let entity = &fixture.registry.entities()[record_type];
    let mut columns = vec![
        "record_id".to_owned(),
        "active_package_revision".to_owned(),
        "record_lifecycle".to_owned(),
    ];
    let mut placeholders = vec![
        "$1::text::uuid".to_owned(),
        format!("'{PACKAGE_LABEL}'"),
        "'active'".to_owned(),
    ];
    let mut params = vec![record_id.to_owned()];
    for (field, value) in values {
        let compiled = &entity.fields[*field];
        columns.push(quote_identifier(&compiled.physical_name));
        params.push((*value).to_owned());
        let cast = match compiled.field_type {
            registry_breg::contract::FieldTypeSource::Uuid => "::text::uuid",
            _ => "",
        };
        placeholders.push(format!("${}{cast}", params.len()));
    }
    let refs = params
        .iter()
        .map(|param| param as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect::<Vec<_>>();
    fixture
        .database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{} ({}) VALUES ({})",
                quote_identifier(&entity.physical_table),
                columns.join(", "),
                placeholders.join(", ")
            ),
            &refs,
        )
        .await
        .unwrap_or_else(|error| panic!("{record_type} row seeds: {error:?}"));
}

/// Submit a Proposal for `action` as the registrar and return it.
async fn submit(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    inputs: Value,
    label: &str,
) -> BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some(REGISTRAR)).await.unwrap();
    let action = metadata.value.select_action(action_id, REGISTRAR).unwrap();
    let request = BRegActionInvocationRequest::new(&action, map(inputs), None).unwrap();
    let draft = client
        .start_proposal(&action, &request, &key(&format!("{label}-start")))
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &key(&format!("{label}-submit")),
        )
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    submitted
}

/// Fail unless `withheld` is the answer a Proposal whose target row is gone
/// gets: same status, same problem code and same body shape. A Proposal cannot
/// be started against an identifier that never existed, so the absent target is
/// a row removed after submission.
async fn assert_absent_like_a_random_target(
    fixture: &client_http::ClientFixture,
    withheld: (u16, String),
) {
    const GONE_ID: &str = "00000000-0000-0000-0000-00000000d0ee";
    seed(
        fixture,
        "residence",
        GONE_ID,
        &[
            ("person-id", OPEN_PERSON_ID),
            ("protection-level", "none"),
            ("address", "Gone"),
        ],
    )
    .await;
    let missing = submit(
        fixture,
        "correct-residence",
        json!({"target": GONE_ID, "value": "Nowhere"}),
        "gone-target",
    )
    .await;
    fixture
        .database
        .admin
        .execute(
            &format!(
                "DELETE FROM registry_data.{} WHERE record_id = $1::text::uuid",
                quote_identifier(&fixture.registry.entities()["residence"].physical_table)
            ),
            &[&GONE_ID.to_owned()],
        )
        .await
        .unwrap();
    let random = review(fixture, &missing, REGISTRAR).await;
    assert_ne!(
        random.0, 200,
        "an absent target is not reviewable: {}",
        random.1
    );
    assert_eq!(withheld.0, random.0, "{} against {}", withheld.1, random.1);
    let parse = |body: &str| serde_json::from_str::<Value>(body).unwrap();
    let (withheld, random) = (parse(&withheld.1), parse(&random.1));
    assert_eq!(withheld.get("code"), random.get("code"));
    assert_eq!(body_shape(&withheld), body_shape(&random));
}

/// The review-context answer for `profile`: status and raw body.
async fn review(
    fixture: &client_http::ClientFixture,
    proposal: &BRegProposal,
    profile: &str,
) -> (u16, String) {
    let response = reqwest::get(format!(
        "{}/v1/proposals/{}/review-context?accessProfile={profile}",
        fixture.http.base_url,
        proposal.id()
    ))
    .await
    .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

fn fields_of(body: &str) -> Value {
    serde_json::from_str::<Value>(body).unwrap()["context"]["fields"].clone()
}

#[test]
fn a_record_that_is_not_flagged_withholds_nothing_in_review() {
    let registry = compile_fixture();
    let person = &registry.entities()["person"];
    let empty = Map::new();
    let registrar = plan(person, REGISTRAR);
    assert!(!registrar.withholds_record(&empty).unwrap());
    assert!(registrar.withheld_fields(&empty).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_sourced_review_field_is_null_for_a_profile_the_condition_binds() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "correct-person",
        json!({"target": PERSON_ID, "value": "Renamed"}),
        "record-field",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "{body}");
    assert_no_sentinel(&body);
    assert_eq!(fields_of(&body)["contact"], Value::Null);
    // The exempt profile still reads the value, so the canary cannot pass on
    // lost data.
    let (status, body) = review(&fixture, &proposal, PROTECTION_OFFICER).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(fields_of(&body)["contact"], json!(CANARY_EMAIL));
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_sourced_review_field_is_shown_when_the_record_is_not_marked() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "correct-person",
        json!({"target": OPEN_PERSON_ID, "value": "Renamed"}),
        "record-open",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(fields_of(&body)["contact"], json!("open@example.invalid"));
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_drops_withheld_members_for_a_profile_the_condition_binds() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "correct-person",
        json!({"target": PERSON_ID, "value": "Renamed"}),
        "changes-patch",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "{body}");
    assert_no_sentinel(&body);
    let change = &fields_of(&body)["changes"][0];
    for side in ["before", "after"] {
        let members = change[side].as_object().unwrap();
        assert!(members.contains_key("family-name"), "{body}");
        assert!(!members.contains_key("email-address"), "{body}");
    }
    let (status, body) = review(&fixture, &proposal, PROTECTION_OFFICER).await;
    assert_eq!(status, 200, "{body}");
    assert_has_sentinel(&body, CANARY_EMAIL);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_change_set_is_evaluated_on_its_after_state() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "register-person",
        json!({"name": "Newcomer", "level": "protected", "email": CANARY_EMAIL}),
        "changes-create",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "{body}");
    assert_no_sentinel(&body);
    let after = fields_of(&body)["changes"][0]["after"].clone();
    assert_eq!(after["protection-level"], json!("protected"), "{body}");
    assert!(after.get("email-address").is_none(), "{body}");
    let (status, body) = review(&fixture, &proposal, PROTECTION_OFFICER).await;
    assert_eq!(status, 200, "{body}");
    assert_has_sentinel(&body, CANARY_EMAIL);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_on_a_record_withheld_after_submission_is_refused() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "correct-residence",
        json!({"target": RESIDENCE_ID, "value": "New address"}),
        "changes-withheld",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "the unmarked residence is reviewable: {body}");
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'protected' WHERE record_id = $1::text::uuid",
                quote_identifier(&fixture.registry.entities()["residence"].physical_table),
                physical(&fixture, "residence", "protection-level")
            ),
            &[&RESIDENCE_ID.to_owned()],
        )
        .await
        .unwrap();
    let withheld = review(&fixture, &proposal, REGISTRAR).await;
    assert_no_sentinel(&withheld.1);
    assert_absent_like_a_random_target(&fixture, withheld).await;
    // The exempt profile still reviews it.
    let (status, body) = review(&fixture, &proposal, PROTECTION_OFFICER).await;
    assert_eq!(status, 200, "{body}");
    assert_has_sentinel(&body, CANARY_ADDRESS);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_on_a_record_whose_history_is_withheld_after_submission_is_refused() {
    let fixture = start_fixture().await;
    let proposal = submit(
        &fixture,
        "correct-person",
        json!({"target": OPEN_PERSON_ID, "value": "Renamed"}),
        "changes-history",
    )
    .await;
    let (status, body) = review(&fixture, &proposal, REGISTRAR).await;
    assert_eq!(status, 200, "the unmarked person is reviewable: {body}");
    let person = &fixture.registry.entities()["person"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = TRUE WHERE record_id = $1::text::uuid",
                quote_identifier(&person.physical_table),
                physical(&fixture, "person", "history-protected")
            ),
            &[&OPEN_PERSON_ID.to_owned()],
        )
        .await
        .unwrap();
    let withheld = review(&fixture, &proposal, REGISTRAR).await;
    assert_absent_like_a_random_target(&fixture, withheld).await;
    // The profile exempt from history still reviews it.
    let (status, body) = review(&fixture, &proposal, PROTECTION_OFFICER).await;
    assert_eq!(status, 200, "{body}");
    fixture.finish().await;
}
