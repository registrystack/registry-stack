// SPDX-License-Identifier: Apache-2.0

//! Write canaries. A profile that a condition binds may not overwrite a field
//! the condition withholds from it, nor lift the mark that withholds it, on any
//! write path: Patch, batch, an immediate Action and a Proposal apply. Nor may
//! it tombstone a record the condition matches. It may still set a mark and
//! write a field no condition names. A profile the condition exempts writes as
//! before.

use super::*;

const SHIELDED_EMAIL: &str = "shielded@example.invalid";
const SHIELDED_PHONE: &str = "555-0199";
const REDIRECTED_EMAIL: &str = "redirected@example.invalid";

/// The history fixture, with person patches, batches and tombstones and
/// residence tombstones for every profile, and three Actions that set a
/// person's email: an immediate one, a Proposal one applied by hand and a
/// Proposal one applied automatically.
fn writes_source() -> Value {
    let mut source = history_source();
    for record in source["recordTypes"].as_array_mut().unwrap() {
        if record["id"] == "residence" {
            record["tombstone"] = json!(true);
        }
    }
    let inputs = json!([
        {"id": "person", "apiName": "personId", "type": "reference", "target": "person",
         "required": true, "classification": "internal"},
        {"id": "email", "apiName": "email", "type": "string", "maximumLength": 128,
         "required": true, "classification": "internal"}]);
    let plan = json!({"type": "fixed", "effects": [
        {"id": "contact", "target": {"fromInput": "person"}, "operation": "patch",
         "set": {"email-address": {"fromInput": "email"}}}]});
    let proposal = |application: Value| {
        json!({"mode": "proposal", "proposal": {"review": {"type": "none"},
            "application": application, "retention": {"mode": "operator-erase"}}})
    };
    let guards = json!({"targets": [{"input": "person", "revision": "unchanged"}]});
    source["actions"].as_array_mut().unwrap().extend([
        json!({"id": "set-person-email", "inputs": inputs, "plan": plan,
            "execution": {"mode": "immediate"}}),
        json!({"id": "propose-person-email", "inputs": inputs, "plan": plan,
            "commitGuards": guards, "execution": proposal(json!({"mode": "manual"}))}),
        json!({"id": "correct-person-email", "inputs": inputs, "plan": plan,
            "commitGuards": guards,
            "execution": proposal(json!({"mode": "automatic", "maximumAttempts": 1}))}),
    ]);
    let targets = json!([{"recordType": "person", "rowBoundaries": "unrestricted"}]);
    let lifecycle =
        json!(["get", "list", "edit", "submit", "revise", "rebase", "retry", "cancel", "apply"]);
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        let writer = profile["id"] == WRITER;
        let permissions = &mut profile["permissions"];
        if !writer {
            let grant = &mut permissions["records"][0];
            assert_eq!(grant["recordType"], "person");
            grant["operations"] = json!([
                "get",
                "list",
                "patch",
                "batch",
                "tombstone",
                "snapshot",
                "revisions"
            ]);
            grant["writableFields"] = json!(PERSON_FIELDS);
            let residence = &mut permissions["records"][1];
            assert_eq!(residence["recordType"], "residence");
            residence["operations"]
                .as_array_mut()
                .unwrap()
                .push(json!("tombstone"));
        }
        for list in ["actions", "proposals"] {
            if permissions[list].is_null() {
                permissions[list] = json!([]);
            }
        }
        permissions["actions"].as_array_mut().unwrap().extend([
            json!({"action": "set-person-email", "operations": ["invoke"], "targets": targets}),
            json!({"action": "propose-person-email", "operations": ["start"], "targets": targets}),
            json!({"action": "correct-person-email", "operations": ["start"], "targets": targets}),
        ]);
        permissions["proposals"].as_array_mut().unwrap().extend([
            json!({"action": "propose-person-email", "ownership": "caller",
                "operations": lifecycle, "targets": targets}),
            json!({"action": "correct-person-email", "ownership": "caller",
                "operations": lifecycle, "targets": targets}),
        ]);
    }
    source
}

/// The write fixture, with person constraints that tie fields the contacts
/// condition does not withhold to fields it does: `group-code` shares a
/// uniqueness constraint with the phone number, `status` decides a partial
/// uniqueness constraint on the email address, and `listed-on` is compared
/// with the withheld `contact-since`.
fn tied_source() -> Value {
    let mut source = writes_source();
    let tied = ["group-code", "status", "listed-on", "contact-since"];
    for record in source["recordTypes"].as_array_mut().unwrap() {
        if record["id"] != "person" {
            continue;
        }
        record["fields"].as_array_mut().unwrap().extend([
            json!({"id": "group-code", "type": "string", "maximumLength": 16, "classification": "internal"}),
            json!({"id": "status", "type": "string", "maximumLength": 16, "classification": "internal"}),
            json!({"id": "listed-on", "type": "date", "classification": "internal"}),
            json!({"id": "contact-since", "type": "date", "classification": "internal"}),
        ]);
        let contacts = &mut record["disclosureConditions"][0];
        assert_eq!(contacts["id"], "hide-contacts");
        contacts["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!("contact-since"));
        record["constraints"] = json!([
            {"id": "group-phone", "type": "unique", "fields": ["group-code", "phone-number"]},
            {"id": "active-email", "type": "unique", "fields": ["email-address"],
             "when": [{"type": "field-equals", "field": "status", "value": "active"}]},
            {"id": "listed-before-contact", "type": "compare", "left": "listed-on",
             "operator": "less-than-or-equal", "right": "contact-since"}]);
    }
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        for grant in profile["permissions"]["records"].as_array_mut().unwrap() {
            if grant["recordType"] != "person" {
                continue;
            }
            for member in ["readableFields", "writableFields"] {
                if let Some(fields) = grant[member].as_array_mut() {
                    fields.extend(tied.map(|field| json!(field)));
                }
            }
        }
    }
    source
}

async fn start() -> History {
    start_with(writes_source()).await
}

async fn start_with(source: Value) -> History {
    let project =
        parse_project_json(&serde_json::to_vec(&source).unwrap()).expect("write fixture parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring)
        .unwrap_or_else(|errors| panic!("write fixture compiles: {errors:#?}"));
    History {
        fixture: ClientFixture::start(registry, claims()).await,
        http: reqwest::Client::new(),
        keys: std::cell::Cell::new(0),
    }
}

fn person(id: &str) -> String {
    format!("/v1/records/people/{id}")
}

/// The entity tag `profile` reads for a person.
async fn etag_as(history: &History, profile: &str, id: &str) -> String {
    let current = history.get(&person(id), profile).await;
    assert_eq!(current.status, 200, "{}", current.text());
    current.etag.expect("a read carries an entity tag")
}

/// PATCH a person as `profile` against the entity tag it reads.
async fn patch_as(history: &History, profile: &str, id: &str, operations: Value) -> Reply {
    let etag = etag_as(history, profile, id).await;
    let key = history.key();
    history
        .send(
            Method::PATCH,
            &person(id),
            profile,
            &[("idempotency-key", &key), ("if-match", &etag)],
            Some((
                "application/json-patch+json",
                serde_json::to_vec(&operations).unwrap(),
            )),
        )
        .await
}

/// POST one batch of person patches as `profile`, one item per `(id, patch)`.
async fn batch_as(history: &History, profile: &str, items: &[(&str, Value)]) -> Reply {
    let mut documents = Vec::new();
    for (id, patch) in items {
        let etag = etag_as(history, profile, id).await;
        documents.push(json!({"operation": "patch", "recordIdentifier": id,
            "ifMatch": etag, "patch": patch}));
    }
    let key = history.key();
    history
        .send(
            Method::POST,
            "/v1/records/people:batch",
            profile,
            &[("idempotency-key", &key)],
            Some((
                "application/json",
                serde_json::to_vec(&json!({ "items": documents })).unwrap(),
            )),
        )
        .await
}

/// Invoke the immediate Action that sets a person's email, as `profile`.
async fn set_email_as(history: &History, profile: &str, id: &str, email: &str) -> Reply {
    let conditions = history
        .send(
            Method::POST,
            "/v1/actions/set-person-email/target-conditions",
            profile,
            &[],
            Some((
                "application/json",
                serde_json::to_vec(&json!({"input": {"personId": id}})).unwrap(),
            )),
        )
        .await;
    assert_eq!(conditions.status, 200, "{}", conditions.text());
    let key = history.key();
    history
        .send(
            Method::POST,
            "/v1/actions/set-person-email",
            profile,
            &[("idempotency-key", &key)],
            Some((
                "application/json",
                serde_json::to_vec(&json!({
                    "input": {"personId": id, "email": email},
                    "preconditions": conditions.body["preconditions"].clone()
                }))
                .unwrap(),
            )),
        )
        .await
}

/// Start and submit a Proposal of `action` as `profile`.
async fn submit_as(
    history: &History,
    profile: &str,
    action: &str,
    id: &str,
    email: &str,
) -> registry_breg_client::BRegProposal {
    let client = &history.fixture.http.client;
    let metadata = client.registry_contract(Some(profile)).await.unwrap();
    let action = metadata.value.select_action(action, profile).unwrap();
    let Value::Object(input) = json!({"personId": id, "email": email}) else {
        unreachable!()
    };
    let request = BRegActionInvocationRequest::new(&action, input, None).unwrap();
    let start_key = BRegIdempotencyKey::parse(history.key()).unwrap();
    let draft = client
        .start_proposal(&action, &request, &start_key)
        .await
        .unwrap()
        .value;
    let submit_key = BRegIdempotencyKey::parse(history.key()).unwrap();
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &submit_key)
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    submitted
}

/// Apply a submitted Proposal by hand.
async fn apply(
    history: &History,
    submitted: &registry_breg_client::BRegProposal,
) -> Result<registry_breg_client::BRegProposal, registry_breg_client::BaseRegistryClientError> {
    let client = &history.fixture.http.client;
    let key = BRegIdempotencyKey::parse(history.key()).unwrap();
    let apply = client
        .prepare_proposal(
            submitted,
            "apply",
            json!({"submissionVersion": submitted.submission_version(),
                "effectDigest": submitted.effect_digest().unwrap()}),
            &key,
        )
        .unwrap();
    client
        .execute_proposal(&apply)
        .await
        .map(|reply| reply.value)
}

/// DELETE a record of `route` as `profile`, against the entity tag `etag`.
async fn tombstone_as(
    history: &History,
    profile: &str,
    route: &str,
    id: &str,
    etag: &str,
) -> Reply {
    let key = history.key();
    history
        .send(
            Method::DELETE,
            &format!("/v1/records/{route}/{id}"),
            profile,
            &[("idempotency-key", &key), ("if-match", etag)],
            None,
        )
        .await
}

/// The person as the protection officer, exempt from every condition, reads it.
async fn stored(history: &History, id: &str) -> Value {
    let reply = history.get(&person(id), PROTECTION_OFFICER).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.body["data"]["domainData"].clone()
}

/// Fail unless `reply` is the boundary refusal and carries no withheld value.
fn assert_refused(reply: &Reply, what: &str) {
    assert_eq!(reply.status, 403, "{what}: {}", reply.text());
    assert_eq!(reply.body["code"], "write.outside-boundary", "{what}");
    let text = reply.text();
    assert_no_sentinel(&text);
    assert!(!text.contains(SHIELDED_EMAIL), "{what}: {text}");
    assert!(!text.contains(SHIELDED_PHONE), "{what}: {text}");
}

fn replace(member: &str, value: Value) -> Value {
    json!([{"op": "replace", "path": format!("/data/{member}"), "value": value}])
}

/// The refused writes of the review: lift the contacts mark, lift the history
/// mark, redirect the email, clear the phone and write back the shown null.
fn refused_patches(seeded: &Seeded) -> Vec<(&'static str, String, Value)> {
    vec![
        (
            "lift protectionLevel",
            seeded.f.clone(),
            replace("protectionLevel", json!("none")),
        ),
        (
            "lift historyProtected",
            seeded.p.clone(),
            replace("historyProtected", json!(false)),
        ),
        (
            "replace email",
            seeded.f.clone(),
            replace("emailAddress", json!(REDIRECTED_EMAIL)),
        ),
        (
            "clear phone",
            seeded.f.clone(),
            json!([{"op": "remove", "path": "/data/phoneNumber"}]),
        ),
        (
            "write back null",
            seeded.p.clone(),
            replace("emailAddress", Value::Null),
        ),
    ]
}

/// Fail unless `p` and `f` still hold their seeded marks and contacts.
async fn assert_unchanged(history: &History, seeded: &Seeded) {
    let p = stored(history, &seeded.p).await;
    assert_eq!(p["protectionLevel"], "protected");
    assert_eq!(p["historyProtected"], true);
    assert_eq!(p["emailAddress"], CANARY_EMAIL);
    assert_eq!(p["phoneNumber"], CANARY_PHONE);
    let f = stored(history, &seeded.f).await;
    assert_eq!(f["protectionLevel"], "protected");
    assert_eq!(f["emailAddress"], SHIELDED_EMAIL);
    assert_eq!(f["phoneNumber"], SHIELDED_PHONE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_patch_cannot_lift_a_mark_or_overwrite_a_withheld_field() {
    let history = start().await;
    let seeded = seed(&history).await;
    for (what, id, patch) in refused_patches(&seeded) {
        let reply = patch_as(&history, REGISTRAR, &id, patch).await;
        assert_refused(&reply, what);
    }
    assert_unchanged(&history, &seeded).await;
    assert_eq!(
        history
            .revisions("people", &seeded.p, REGISTRAR)
            .await
            .status,
        404,
        "the history mark still holds"
    );

    // The protection officer, whom both conditions exempt, makes every write.
    for (what, id, patch) in refused_patches(&seeded) {
        let reply = patch_as(&history, PROTECTION_OFFICER, &id, patch).await;
        assert_eq!(reply.status, 200, "{what}: {}", reply.text());
    }
    let f = stored(&history, &seeded.f).await;
    assert_eq!(f["protectionLevel"], "none");
    assert_eq!(f["emailAddress"], REDIRECTED_EMAIL);
    assert_eq!(f["phoneNumber"], Value::Null);
    let p = stored(&history, &seeded.p).await;
    assert_eq!(p["historyProtected"], false);
    assert_eq!(p["emailAddress"], Value::Null);
    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_patch_still_sets_a_mark_and_writes_an_unnamed_field() {
    let history = start().await;
    let seeded = seed(&history).await;
    let renamed = patch_as(
        &history,
        REGISTRAR,
        &seeded.p,
        replace("familyName", json!("Renamed")),
    )
    .await;
    assert_eq!(renamed.status, 200, "{}", renamed.text());
    assert_no_sentinel(&renamed.text());
    assert_eq!(stored(&history, &seeded.p).await["familyName"], "Renamed");

    // Marking an open person, with the contacts it is marked for, is allowed.
    let marked = patch_as(
        &history,
        REGISTRAR,
        &seeded.open,
        json!([
            {"op": "replace", "path": "/data/protectionLevel", "value": "protected"},
            {"op": "replace", "path": "/data/historyProtected", "value": true},
            {"op": "replace", "path": "/data/emailAddress", "value": REDIRECTED_EMAIL}]),
    )
    .await;
    assert_eq!(marked.status, 200, "{}", marked.text());
    assert!(
        !marked.text().contains(REDIRECTED_EMAIL),
        "{}",
        marked.text()
    );
    let open = stored(&history, &seeded.open).await;
    assert_eq!(open["protectionLevel"], "protected");
    assert_eq!(open["emailAddress"], REDIRECTED_EMAIL);
    let read = history.get(&person(&seeded.open), REGISTRAR).await;
    assert_eq!(read.body["data"]["domainData"]["emailAddress"], Value::Null);
    assert_eq!(
        history
            .revisions("people", &seeded.open, REGISTRAR)
            .await
            .status,
        404
    );

    // Once marked, the registrar can no longer lift the mark it set.
    let lifted = patch_as(
        &history,
        REGISTRAR,
        &seeded.open,
        replace("protectionLevel", json!("none")),
    )
    .await;
    assert_refused(&lifted, "lift a mark the writer set");
    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_is_refused_only_by_a_condition_that_binds_the_writer() {
    let history = start().await;
    let seeded = seed(&history).await;
    // The emergency registrar is exempt from the contacts condition but bound
    // by the history one.
    let email = patch_as(
        &history,
        EMERGENCY_REGISTRAR,
        &seeded.p,
        replace("emailAddress", json!(REDIRECTED_EMAIL)),
    )
    .await;
    assert_eq!(email.status, 200, "{}", email.text());
    assert_eq!(
        stored(&history, &seeded.p).await["emailAddress"],
        REDIRECTED_EMAIL
    );
    let lifted = patch_as(
        &history,
        EMERGENCY_REGISTRAR,
        &seeded.p,
        replace("historyProtected", json!(false)),
    )
    .await;
    assert_eq!(lifted.status, 403, "{}", lifted.text());
    assert_eq!(lifted.body["code"], "write.outside-boundary");
    assert_eq!(stored(&history, &seeded.p).await["historyProtected"], true);
    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_refuses_what_a_patch_refuses() {
    let history = start().await;
    let seeded = seed(&history).await;
    for (what, id, patch) in refused_patches(&seeded) {
        // Beside a harmless item, the whole batch is refused.
        let reply = batch_as(
            &history,
            REGISTRAR,
            &[
                (&seeded.open, replace("familyName", json!("Harmless"))),
                (&id, patch),
            ],
        )
        .await;
        assert_refused(&reply, what);
    }
    assert_unchanged(&history, &seeded).await;
    assert_eq!(stored(&history, &seeded.open).await["familyName"], "Open");

    for (what, id, patch) in refused_patches(&seeded) {
        let reply = batch_as(&history, PROTECTION_OFFICER, &[(&id, patch)]).await;
        assert_eq!(reply.status, 200, "{what}: {}", reply.text());
    }
    let f = stored(&history, &seeded.f).await;
    assert_eq!(f["protectionLevel"], "none");
    assert_eq!(f["emailAddress"], REDIRECTED_EMAIL);
    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_immediate_action_refuses_what_a_patch_refuses() {
    let history = start().await;
    let seeded = seed(&history).await;
    let reply = set_email_as(&history, REGISTRAR, &seeded.f, REDIRECTED_EMAIL).await;
    assert_refused(&reply, "Action replaces email");
    assert_unchanged(&history, &seeded).await;

    let reply = set_email_as(&history, PROTECTION_OFFICER, &seeded.f, REDIRECTED_EMAIL).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        stored(&history, &seeded.f).await["emailAddress"],
        REDIRECTED_EMAIL
    );
    history.fixture.finish().await;
}

const ACTION_CLERK: &str = "action-clerk";

/// The write fixture with an `action-clerk` profile that holds no record grant,
/// only the immediate email Action on `person`. The contacts condition exempts
/// it when `exempt` holds.
fn action_clerk_source(exempt: bool) -> Value {
    let mut source = writes_source();
    source["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id": ACTION_CLERK, "principalClaim": "registry_principal", "requiredScopes": "unrestricted",
        "permissions": {"actions": [
            {"action": "set-person-email", "operations": ["invoke"],
             "targets": [{"recordType": "person", "rowBoundaries": "unrestricted"}]}]}}));
    if exempt {
        let person = source["recordTypes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["id"] == "person")
            .unwrap();
        let contacts = &mut person["disclosureConditions"][0];
        assert_eq!(contacts["id"], "hide-contacts");
        contacts["exemptProfiles"]
            .as_array_mut()
            .unwrap()
            .push(json!(ACTION_CLERK));
    }
    source
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_condition_exempts_a_profile_that_writes_only_through_an_action() {
    let history = start_with(action_clerk_source(false)).await;
    let seeded = seed(&history).await;
    let reply = set_email_as(&history, ACTION_CLERK, &seeded.f, REDIRECTED_EMAIL).await;
    assert_refused(&reply, "Action-only profile the condition binds");
    assert_unchanged(&history, &seeded).await;
    history.fixture.finish().await;

    let history = start_with(action_clerk_source(true)).await;
    let seeded = seed(&history).await;
    let reply = set_email_as(&history, ACTION_CLERK, &seeded.f, REDIRECTED_EMAIL).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        stored(&history, &seeded.f).await["emailAddress"],
        REDIRECTED_EMAIL
    );
    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proposal_applied_by_a_bound_profile_is_refused() {
    let history = start().await;
    let seeded = seed(&history).await;
    let submitted = submit_as(
        &history,
        REGISTRAR,
        "propose-person-email",
        &seeded.f,
        REDIRECTED_EMAIL,
    )
    .await;
    let refusal = apply(&history, &submitted)
        .await
        .expect_err("a bound apply is refused");
    assert_eq!(
        refusal.problem_code(),
        Some(registry_breg_client::BRegProblemCode::WriteOutsideBoundary),
        "{refusal:?}"
    );
    assert_no_sentinel(&format!("{refusal:?}"));
    assert_unchanged(&history, &seeded).await;

    let submitted = submit_as(
        &history,
        PROTECTION_OFFICER,
        "propose-person-email",
        &seeded.f,
        REDIRECTED_EMAIL,
    )
    .await;
    let applied = apply(&history, &submitted)
        .await
        .expect("an exempt apply succeeds");
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(
        stored(&history, &seeded.f).await["emailAddress"],
        REDIRECTED_EMAIL
    );
    history.fixture.finish().await;
}

/// Run one automatic application attempt and return the Proposal's
/// application status, as the protection officer reads it.
async fn run_automatic(history: &History, submitted: &registry_breg_client::BRegProposal) -> Value {
    history
        .fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .expect("the automatic attempt runs");
    let proposal = history
        .get(
            &format!("/v1/proposals/{}", submitted.id()),
            PROTECTION_OFFICER,
        )
        .await;
    assert_eq!(proposal.status, 200, "{}", proposal.text());
    proposal.body["applicationStatus"].clone()
}

/// An automatic Proposal is checked against the profile that submitted it. An
/// exempt submitter's Proposal writes the withheld field.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automatic_proposal_of_an_exempt_submitter_applies() {
    let history = start().await;
    let seeded = seed(&history).await;
    let submitted = submit_as(
        &history,
        PROTECTION_OFFICER,
        "correct-person-email",
        &seeded.f,
        REDIRECTED_EMAIL,
    )
    .await;
    let application = run_automatic(&history, &submitted).await;
    assert_eq!(application["state"], "applied", "{application}");
    assert_eq!(
        stored(&history, &seeded.f).await["emailAddress"],
        REDIRECTED_EMAIL
    );
    history.fixture.finish().await;
}

/// A bound submitter's automatic Proposal cannot write what a condition
/// withholds from the submitter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automatic_proposal_of_a_bound_submitter_is_blocked() {
    let history = start().await;
    let seeded = seed(&history).await;
    let submitted = submit_as(
        &history,
        REGISTRAR,
        "correct-person-email",
        &seeded.f,
        REDIRECTED_EMAIL,
    )
    .await;
    let application = run_automatic(&history, &submitted).await;
    assert_eq!(application["state"], "blocked", "{application}");
    assert_eq!(application["reason"], "attempts-exhausted", "{application}");
    assert_eq!(application["recovery"], "correct-input", "{application}");
    assert_no_sentinel(&application.to_string());
    assert_unchanged(&history, &seeded).await;
    history.fixture.finish().await;
}

/// The emergency registrar is exempt from the contacts condition, not from the
/// history condition. Its automatic Proposal on `p` writes the contact, which
/// only the contacts condition withholds from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automatic_proposal_of_the_emergency_registrar_applies() {
    let history = start().await;
    let seeded = seed(&history).await;
    let submitted = submit_as(
        &history,
        EMERGENCY_REGISTRAR,
        "correct-person-email",
        &seeded.p,
        REDIRECTED_EMAIL,
    )
    .await;
    let application = run_automatic(&history, &submitted).await;
    assert_eq!(application["state"], "applied", "{application}");
    let p = stored(&history, &seeded.p).await;
    assert_eq!(p["emailAddress"], REDIRECTED_EMAIL);
    assert_eq!(p["historyProtected"], true);
    history.fixture.finish().await;
}

/// A bound profile may not tombstone a record that a `fields` or a `history`
/// condition marks. It still tombstones an unmarked record, and an exempt
/// profile tombstones a marked one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_profile_cannot_tombstone_a_marked_record() {
    let history = start().await;
    let seeded = seed(&history).await;
    // The registrar is bound by the contacts mark on `f`, the emergency
    // registrar only by the history mark on `p`.
    for (what, profile, id) in [
        ("fields mark", REGISTRAR, &seeded.f),
        ("history mark", EMERGENCY_REGISTRAR, &seeded.p),
    ] {
        let etag = etag_as(&history, profile, id).await;
        let reply = tombstone_as(&history, profile, "people", id, &etag).await;
        assert_refused(&reply, what);
    }
    assert_unchanged(&history, &seeded).await;

    let etag = etag_as(&history, REGISTRAR, &seeded.open).await;
    let reply = tombstone_as(&history, REGISTRAR, "people", &seeded.open, &etag).await;
    assert!(
        reply.status == 200 || reply.status == 204,
        "an unmarked record tombstones: {} {}",
        reply.status,
        reply.text()
    );
    let etag = etag_as(&history, PROTECTION_OFFICER, &seeded.f).await;
    let reply = tombstone_as(&history, PROTECTION_OFFICER, "people", &seeded.f, &etag).await;
    assert!(
        reply.status == 200 || reply.status == 204,
        "an exempt profile tombstones a marked record: {} {}",
        reply.status,
        reply.text()
    );
    for id in [&seeded.open, &seeded.f] {
        let gone = history.get(&person(id), PROTECTION_OFFICER).await;
        assert_eq!(gone.status, 404, "{}", gone.text());
    }
    history.fixture.finish().await;
}

/// A record a `record` condition withholds stays hidden from a bound
/// tombstone, which answers exactly as for an identifier that names nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_tombstone_of_a_withheld_record_answers_as_an_absent_one() {
    let history = start().await;
    let seeded = seed(&history).await;
    // The registrar cannot read `r`, so it sends the entity tag of a record
    // it can read.
    let etag = etag_as(&history, REGISTRAR, &seeded.open).await;
    let withheld = tombstone_as(&history, REGISTRAR, "residences", &seeded.r, &etag).await;
    let absent = tombstone_as(&history, REGISTRAR, "residences", ABSENT_ID, &etag).await;
    assert_ne!(withheld.status / 100, 2, "{}", withheld.text());
    assert_same_absence(&withheld.answer(), &absent.answer());
    assert_no_sentinel(&withheld.text());
    let kept = history
        .get(
            &format!("/v1/records/residences/{}", seeded.r),
            PROTECTION_OFFICER,
        )
        .await;
    assert_eq!(kept.status, 200, "{}", kept.text());
    history.fixture.finish().await;
}

/// A conflict on a constraint over a withheld field answers whether the hidden
/// value matches, so a bound Patch of a marked record may not change a field a
/// constraint ties to one. The exempt officer may, and so may anyone on a
/// record the condition does not match.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bound_patch_cannot_change_a_field_a_constraint_ties_to_a_withheld_field() {
    let history = start_with(tied_source()).await;
    let person_data = |level: &str, group: &str, email: &str, phone: &str| {
        json!({"familyName": "Tied", "protectionLevel": level, "historyProtected": false,
            "emailAddress": email, "phoneNumber": phone, "groupCode": group,
            "status": "inactive", "listedOn": "2020-01-01", "contactSince": "2021-01-01"})
    };
    let marked = history
        .create(
            "people",
            person_data("protected", "G1", SHIELDED_EMAIL, SHIELDED_PHONE),
        )
        .await;
    let unmarked = history
        .create(
            "people",
            person_data("none", "G2", "open@example.invalid", "555-0100"),
        )
        .await;
    let probes = [
        ("composite unique member", "groupCode", json!("G9")),
        ("partial unique when field", "status", json!("active")),
        ("compare side", "listedOn", json!("2020-06-01")),
    ];
    for (what, member, value) in &probes {
        let reply = patch_as(&history, REGISTRAR, &marked, replace(member, value.clone())).await;
        assert_refused(&reply, what);
    }
    let stored_marked = stored(&history, &marked).await;
    assert_eq!(stored_marked["groupCode"], "G1");
    assert_eq!(stored_marked["status"], "inactive");
    assert_eq!(stored_marked["listedOn"], "2020-01-01");

    for (what, member, value) in &probes {
        let reply = patch_as(
            &history,
            REGISTRAR,
            &unmarked,
            replace(member, value.clone()),
        )
        .await;
        assert_eq!(reply.status, 200, "unmarked {what}: {}", reply.text());
        let reply = patch_as(
            &history,
            PROTECTION_OFFICER,
            &marked,
            replace(member, value.clone()),
        )
        .await;
        assert_eq!(reply.status, 200, "officer {what}: {}", reply.text());
        assert_eq!(stored(&history, &marked).await[*member], *value, "{what}");
    }
    history.fixture.finish().await;
}
