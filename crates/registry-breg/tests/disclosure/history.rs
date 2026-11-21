// SPDX-License-Identifier: Apache-2.0

//! History canaries: snapshots and revisions.
//!
//! Every record is written through the real mutation routes, so each carries
//! the revisions the history surfaces read. The `writer` profile is exempt
//! from every condition and does the writing. The registrar is the profile a
//! canary must not leak to.

use std::collections::{BTreeMap, BTreeSet};

use reqwest::Method;
use serde_json::{json, Value};

use super::client_http::ClientFixture;
use super::fixture::{
    assert_has_sentinel, assert_no_sentinel, assert_same_absence, project_source, Answer,
    ABSENT_ID, CANARY_ADDRESS, CANARY_EMAIL, CANARY_OLD_NAME, CANARY_PHONE, EMERGENCY_REGISTRAR,
    PROTECTION_OFFICER, REGISTRAR,
};
use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::CompiledRegistry;
use registry_breg_client::{BRegActionInvocationRequest, BRegIdempotencyKey, BRegProposalState};

const WRITER: &str = "writer";
const PERSON_FIELDS: [&str; 5] = [
    "family-name",
    "protection-level",
    "history-protected",
    "email-address",
    "phone-number",
];

/// The shared fixture source with history operations on every profile, a
/// `writer` profile exempt from every condition, tombstones on `person` and
/// one immediate and one Proposal Action that patch a person.
fn history_source() -> Value {
    let mut source = project_source();
    let records = source["recordTypes"].as_array_mut().unwrap();
    for record in records.iter_mut() {
        if record["id"] == "person" {
            record["tombstone"] = json!(true);
            record["batch"] = json!({"maximumItems": 4, "maximumBytes": 8192});
        }
        for condition in record["disclosureConditions"].as_array_mut().unwrap() {
            condition["exemptProfiles"]
                .as_array_mut()
                .unwrap()
                .push(json!(WRITER));
        }
    }
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        for grant in profile["permissions"]["records"].as_array_mut().unwrap() {
            grant["operations"] = json!(["get", "list", "snapshot", "revisions"]);
            grant["revisionAccess"] = json!(true);
            grant["allowCount"] = json!(true);
            grant["provenanceFields"] = json!(["kind", "reasonText", "sourceReferences"]);
        }
    }
    let writable = |record_type: &str, fields: &[&str]| {
        let mut operations = vec!["create", "get", "list", "patch", "snapshot", "revisions"];
        if record_type == "person" {
            operations.push("tombstone");
            operations.push("batch");
        }
        json!({"recordType": record_type, "operations": operations,
            "revisionAccess": true, "provenanceFields": ["kind", "reasonText", "sourceReferences"], "allowCount": true, "rowBoundaries": "unrestricted",
            "readableFields": fields, "writableFields": fields})
    };
    let person_target = json!([{"recordType": "person", "rowBoundaries": "unrestricted"}]);
    source["accessProfiles"].as_array_mut().unwrap().push(json!({
        "id": WRITER, "principalClaim": "registry_principal", "requiredScopes": "unrestricted",
        "permissions": {
            "records": [
                writable("person", &PERSON_FIELDS),
                writable("residence", &["person-id", "protection-level", "address"]),
                writable("name-usage", &["person-id", "protection-level", "old-name", "closed-on"])],
            "actions": [
                {"action": "rename-person", "operations": ["invoke"],
                 "targets": person_target.clone(), "results": ["rename"]},
                {"action": "correct-person-name", "operations": ["start"],
                 "targets": person_target.clone()}],
            "proposals": [
                {"action": "correct-person-name", "ownership": "caller",
                 "operations": ["get", "list", "edit", "submit", "revise", "rebase", "retry", "cancel", "apply"],
                 "targets": person_target}]}}));
    source["actions"] = json!([
        {"id": "rename-person",
         "inputs": [
            {"id": "person", "apiName": "personId", "type": "reference", "target": "person",
             "required": true, "classification": "internal"},
            {"id": "name", "apiName": "name", "type": "string", "maximumLength": 64,
             "required": true, "classification": "internal"}],
         "execution": {"mode": "immediate"},
         "plan": {"type": "fixed", "effects": [
            {"id": "rename", "target": {"fromInput": "person"}, "operation": "patch",
             "set": {"family-name": {"fromInput": "name"}}}]}},
        {"id": "correct-person-name",
         "execution": {"mode": "proposal", "proposal": {
            "review": {"type": "none"},
            "application": {"mode": "automatic", "maximumAttempts": 3},
            "retention": {"mode": "operator-erase"}}},
         "inputs": [
            {"id": "person", "type": "reference", "target": "person", "required": true,
             "classification": "internal"},
            {"id": "name", "type": "string", "required": true, "maximumLength": 64,
             "classification": "internal"}],
         "commitGuards": {"targets": [{"input": "person", "revision": "unchanged"}]},
         "plan": {"type": "fixed", "effects": [
            {"id": "correct", "target": {"fromInput": "person"}, "operation": "patch",
             "set": {"family-name": {"fromInput": "name"}}}]}}]);
    source
}

fn history_registry() -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&history_source()).unwrap())
        .expect("history fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("history fixture compiles")
}

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "registry_principal",
        "history-principal",
        BTreeSet::new(),
        None,
        BTreeMap::<String, VerifiedClaimValue>::new(),
        registry_platform_oidc::ActorKind::Human,
    )
    .expect("history claims are valid")
}

/// A response: its status, parsed body and entity tag.
struct Reply {
    status: u16,
    body: Value,
    etag: Option<String>,
}

impl Reply {
    fn answer(&self) -> Answer {
        Answer {
            status: self.status,
            body: self.body.clone(),
        }
    }

    fn text(&self) -> String {
        self.body.to_string()
    }
}

struct History {
    fixture: ClientFixture,
    http: reqwest::Client,
    keys: std::cell::Cell<u32>,
}

impl History {
    async fn start() -> Self {
        Self {
            fixture: ClientFixture::start(history_registry(), claims()).await,
            http: reqwest::Client::new(),
            keys: std::cell::Cell::new(0),
        }
    }

    fn key(&self) -> String {
        self.keys.set(self.keys.get() + 1);
        format!("history-key-{}", self.keys.get())
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        profile: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, Vec<u8>)>,
    ) -> Reply {
        let separator = if path.contains('?') { '&' } else { '?' };
        let url = format!(
            "{}{path}{separator}accessProfile={profile}",
            self.fixture.http.base_url
        );
        let mut request = self.http.request(method, url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some((content_type, bytes)) = body {
            request = request.header("content-type", content_type).body(bytes);
        }
        let response = request.send().await.expect("request is answered");
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get("etag")
            .map(|value| value.to_str().unwrap().to_owned());
        let bytes = response.bytes().await.expect("body is read");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("body is JSON")
        };
        Reply { status, body, etag }
    }

    async fn get(&self, path: &str, profile: &str) -> Reply {
        self.send(Method::GET, path, profile, &[], None).await
    }

    /// Create a record as the writer and return its identifier.
    async fn create(&self, route: &str, data: Value) -> String {
        let key = self.key();
        let reply = self
            .send(
                Method::POST,
                &format!("/v1/records/{route}"),
                WRITER,
                &[("idempotency-key", &key)],
                Some((
                    "application/json",
                    serde_json::to_vec(&json!({ "data": data })).unwrap(),
                )),
            )
            .await;
        assert_eq!(reply.status, 201, "create {route}: {}", reply.text());
        reply.body["data"]["recordIdentifier"]
            .as_str()
            .expect("created record is named")
            .to_owned()
    }

    async fn etag(&self, route: &str, id: &str) -> String {
        let reply = self.get(&format!("/v1/records/{route}/{id}"), WRITER).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        reply.etag.expect("a read carries an entity tag")
    }

    /// Replace `/data/<member>` values on a person as the writer.
    async fn patch(&self, route: &str, id: &str, members: &[(&str, Value)]) {
        let etag = self.etag(route, id).await;
        let key = self.key();
        let operations: Vec<Value> = members
            .iter()
            .map(|(member, value)| {
                json!({"op": "replace", "path": format!("/data/{member}"), "value": value})
            })
            .collect();
        let reply = self
            .send(
                Method::PATCH,
                &format!("/v1/records/{route}/{id}"),
                WRITER,
                &[("idempotency-key", &key), ("if-match", &etag)],
                Some((
                    "application/json-patch+json",
                    serde_json::to_vec(&operations).unwrap(),
                )),
            )
            .await;
        assert_eq!(reply.status, 200, "patch {route}: {}", reply.text());
    }

    async fn tombstone(&self, route: &str, id: &str) {
        let etag = self.etag(route, id).await;
        let key = self.key();
        let reply = self
            .send(
                Method::DELETE,
                &format!("/v1/records/{route}/{id}"),
                WRITER,
                &[("idempotency-key", &key), ("if-match", &etag)],
                None,
            )
            .await;
        assert!(
            reply.status == 200 || reply.status == 204,
            "tombstone {route}: {} {}",
            reply.status,
            reply.text()
        );
    }

    async fn revisions(&self, route: &str, id: &str, profile: &str) -> Reply {
        self.get(&format!("/v1/records/{route}/{id}/revisions"), profile)
            .await
    }

    async fn revision(&self, route: &str, id: &str, revision: u32, profile: &str) -> Reply {
        self.get(
            &format!("/v1/records/{route}/{id}/revisions/{revision}"),
            profile,
        )
        .await
    }

    async fn snapshot(&self, route: &str, profile: &str) -> Reply {
        self.get(
            &format!("/v1/records/{route}:snapshot?$count=true&$top=100"),
            profile,
        )
        .await
    }

    /// The identifiers a snapshot lists.
    fn ids(reply: &Reply) -> BTreeSet<String> {
        assert_eq!(reply.status, 200, "{}", reply.text());
        reply.body["items"]
            .as_array()
            .expect("a snapshot lists items")
            .iter()
            .map(|item| item["recordIdentifier"].as_str().unwrap().to_owned())
            .collect()
    }
}

/// Seeded identifiers: the protected person `p` (flag and level set), its
/// residence `r` and closed name usage `n`, a person `f` whose level is
/// protected but whose history is not, and an open person `open`.
struct Seeded {
    p: String,
    r: String,
    n: String,
    f: String,
    open: String,
}

async fn seed(history: &History) -> Seeded {
    let p = history
        .create(
            "people",
            json!({"familyName": "Protected", "protectionLevel": "protected",
                "historyProtected": true, "emailAddress": CANARY_EMAIL,
                "phoneNumber": CANARY_PHONE}),
        )
        .await;
    let r = history
        .create(
            "residences",
            json!({"personId": p, "protectionLevel": "protected", "address": CANARY_ADDRESS}),
        )
        .await;
    let n = history
        .create(
            "name-usages",
            json!({"personId": p, "protectionLevel": "protected",
                "oldName": CANARY_OLD_NAME, "closedOn": "2020-01-01"}),
        )
        .await;
    let f = history
        .create(
            "people",
            json!({"familyName": "Shielded", "protectionLevel": "protected",
                "historyProtected": false, "emailAddress": "shielded@example.invalid",
                "phoneNumber": "555-0199"}),
        )
        .await;
    let open = history
        .create(
            "people",
            json!({"familyName": "Open", "protectionLevel": "none",
                "historyProtected": false, "emailAddress": "open@example.invalid",
                "phoneNumber": "555-0100"}),
        )
        .await;
    Seeded { p, r, n, f, open }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshots_withhold_flagged_records_and_match_a_random_identifier() {
    let history = History::start().await;
    let seeded = seed(&history).await;

    let people = history.snapshot("people", REGISTRAR).await;
    assert_eq!(
        History::ids(&people),
        BTreeSet::from([seeded.f.clone(), seeded.open.clone()]),
        "the history-flagged person is absent from the registrar snapshot"
    );
    assert_eq!(
        people.body["count"], 2,
        "the count excludes withheld records"
    );
    assert_no_sentinel(&people.text());
    assert_no_sentinel(&history.snapshot("residences", REGISTRAR).await.text());
    assert_no_sentinel(&history.snapshot("name-usages", REGISTRAR).await.text());
    assert!(History::ids(&history.snapshot("residences", REGISTRAR).await).is_empty());
    assert!(History::ids(&history.snapshot("name-usages", REGISTRAR).await).is_empty());
    assert_eq!(
        history.snapshot("residences", REGISTRAR).await.body["count"],
        0
    );

    // The fields condition drops contacts from the snapshot of a shielded person.
    let shielded = people.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["recordIdentifier"] == seeded.f.as_str())
        .unwrap();
    assert_eq!(
        shielded["domainData"].get("emailAddress"),
        Some(&Value::Null)
    );
    assert_eq!(
        shielded["domainData"].get("phoneNumber"),
        Some(&Value::Null)
    );
    assert_eq!(shielded["domainData"]["familyName"], "Shielded");
    let open = people.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["recordIdentifier"] == seeded.open.as_str())
        .unwrap();
    assert_eq!(open["domainData"]["emailAddress"], "open@example.invalid");

    // The protection officer reads every record, sentinels included.
    let officer = history.snapshot("people", PROTECTION_OFFICER).await;
    assert!(History::ids(&officer).contains(&seeded.p));
    assert_has_sentinel(&officer.text(), CANARY_EMAIL);
    assert_has_sentinel(&officer.text(), CANARY_PHONE);
    let officer_residences = history.snapshot("residences", PROTECTION_OFFICER).await;
    assert_has_sentinel(&officer_residences.text(), CANARY_ADDRESS);
    let officer_names = history.snapshot("name-usages", PROTECTION_OFFICER).await;
    assert_has_sentinel(&officer_names.text(), CANARY_OLD_NAME);

    // The emergency registrar is exempt from contacts and residence, not from history.
    let emergency = history.snapshot("people", EMERGENCY_REGISTRAR).await;
    assert!(!History::ids(&emergency).contains(&seeded.p));
    let emergency_residences = history.snapshot("residences", EMERGENCY_REGISTRAR).await;
    assert_has_sentinel(&emergency_residences.text(), CANARY_ADDRESS);
    assert!(
        !History::ids(&history.snapshot("name-usages", EMERGENCY_REGISTRAR).await)
            .contains(&seeded.n)
    );

    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revisions_of_withheld_records_answer_like_a_random_identifier() {
    let history = History::start().await;
    let seeded = seed(&history).await;
    // A second revision, so list and detail have more than one entry to hide.
    history
        .patch(
            "people",
            &seeded.p,
            &[("familyName", json!("Protected Two"))],
        )
        .await;

    for (route, id) in [
        ("people", &seeded.p),
        ("residences", &seeded.r),
        ("name-usages", &seeded.n),
    ] {
        let random_list = history.revisions(route, ABSENT_ID, REGISTRAR).await;
        let random_detail = history.revision(route, ABSENT_ID, 1, REGISTRAR).await;
        assert_eq!(random_list.status, 404, "{}", random_list.text());
        let list = history.revisions(route, id, REGISTRAR).await;
        let detail = history.revision(route, id, 1, REGISTRAR).await;
        assert_same_absence(&list.answer(), &random_list.answer());
        assert_same_absence(&detail.answer(), &random_detail.answer());
        assert_no_sentinel(&list.text());
        assert_no_sentinel(&detail.text());
    }

    // The protection officer reads them, sentinels included.
    let list = history
        .revisions("people", &seeded.p, PROTECTION_OFFICER)
        .await;
    assert_eq!(list.status, 200, "{}", list.text());
    assert_eq!(list.body["items"].as_array().unwrap().len(), 2);
    assert_has_sentinel(&list.text(), CANARY_EMAIL);
    let detail = history
        .revision("residences", &seeded.r, 1, PROTECTION_OFFICER)
        .await;
    assert_has_sentinel(&detail.text(), CANARY_ADDRESS);
    let detail = history
        .revision("name-usages", &seeded.n, 1, PROTECTION_OFFICER)
        .await;
    assert_has_sentinel(&detail.text(), CANARY_OLD_NAME);

    // The emergency registrar is not exempt from history on a person.
    let blocked = history
        .revisions("people", &seeded.p, EMERGENCY_REGISTRAR)
        .await;
    assert_eq!(blocked.status, 404, "{}", blocked.text());
    assert_no_sentinel(&blocked.text());

    // Contacts of a shielded person drop out of every revision, and the
    // protection officer still reads them.
    let shielded = history.revisions("people", &seeded.f, REGISTRAR).await;
    assert_eq!(shielded.status, 200, "{}", shielded.text());
    let items = shielded.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["domainData"].get("emailAddress"),
        Some(&Value::Null)
    );
    assert_eq!(
        items[0]["domainData"].get("phoneNumber"),
        Some(&Value::Null)
    );
    assert_eq!(items[0]["domainData"]["familyName"], "Shielded");
    let detail = history.revision("people", &seeded.f, 1, REGISTRAR).await;
    assert_eq!(detail.status, 200, "{}", detail.text());
    assert_eq!(
        detail.body["data"]["domainData"].get("emailAddress"),
        Some(&Value::Null)
    );
    let detail = history
        .revision("people", &seeded.f, 1, PROTECTION_OFFICER)
        .await;
    assert_eq!(
        detail.body["data"]["domainData"]["emailAddress"],
        "shielded@example.invalid"
    );

    // An open person reads in full.
    let open = history.revisions("people", &seeded.open, REGISTRAR).await;
    assert_eq!(
        open.body["items"][0]["domainData"]["emailAddress"],
        "open@example.invalid"
    );

    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn history_follows_the_current_state_of_the_record() {
    let history = History::start().await;
    let seeded = seed(&history).await;
    let withheld = || async {
        history
            .revisions("people", &seeded.p, REGISTRAR)
            .await
            .status
            == 404
    };
    assert!(withheld().await);

    // Un-flagging the person opens every revision, including the one written
    // while the flag was set.
    history
        .patch("people", &seeded.p, &[("historyProtected", json!(false))])
        .await;
    assert!(!withheld().await);
    assert!(History::ids(&history.snapshot("people", REGISTRAR).await).contains(&seeded.p));
    let list = history.revisions("people", &seeded.p, REGISTRAR).await;
    assert_eq!(list.body["items"].as_array().unwrap().len(), 2);
    // The protection level is still protected, so the contacts stay hidden.
    assert_no_sentinel(&list.text());

    // Flagging it again hides them all.
    history
        .patch("people", &seeded.p, &[("historyProtected", json!(true))])
        .await;
    assert!(withheld().await);
    assert!(!History::ids(&history.snapshot("people", REGISTRAR).await).contains(&seeded.p));

    history.fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_erased_latest_snapshot_is_withheld() {
    let history = History::start().await;
    let seeded = seed(&history).await;
    // Open the record, then erase its latest snapshot.
    history
        .patch("people", &seeded.open, &[("familyName", json!("Open Two"))])
        .await;
    assert_eq!(
        history
            .revisions("people", &seeded.open, REGISTRAR)
            .await
            .status,
        200
    );
    let changed = history
        .fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_revisions
                SET snapshot = NULL, erased_at = now()
              WHERE record_id = $1::text::uuid AND record_revision = 2",
            &[&seeded.open],
        )
        .await
        .expect("the fixture erases the latest snapshot");
    assert_eq!(changed, 1);
    let withheld = history.revisions("people", &seeded.open, REGISTRAR).await;
    assert_same_absence(
        &withheld.answer(),
        &history
            .revisions("people", ABSENT_ID, REGISTRAR)
            .await
            .answer(),
    );
    assert!(!History::ids(&history.snapshot("people", REGISTRAR).await).contains(&seeded.open));

    history.fixture.finish().await;
}

/// The latest revision snapshot carries what the current row holds, whichever
/// writer produced it. Disclosure conditions read the latest revision on the
/// history surfaces, so this equality is what keeps them consistent with the
/// condition evaluated on the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_latest_revision_equals_the_current_row_after_every_writer() {
    let history = History::start().await;
    let id = history
        .create(
            "people",
            json!({"familyName": "Created", "protectionLevel": "none",
                "historyProtected": false, "emailAddress": "w@example.invalid",
                "phoneNumber": "555-0001"}),
        )
        .await;
    let mut revision = 1_u32;
    assert_latest_equals_current(&history, &id, revision).await;

    // Patch.
    history
        .patch("people", &id, &[("familyName", json!("Patched"))])
        .await;
    revision += 1;
    assert_latest_equals_current(&history, &id, revision).await;

    // Immediate Action.
    let condition = history
        .send(
            Method::POST,
            "/v1/actions/rename-person/target-conditions",
            WRITER,
            &[],
            Some((
                "application/json",
                serde_json::to_vec(&json!({"input": {"personId": id}})).unwrap(),
            )),
        )
        .await;
    assert_eq!(condition.status, 200, "{}", condition.text());
    let key = history.key();
    let renamed = history
        .send(
            Method::POST,
            "/v1/actions/rename-person",
            WRITER,
            &[("idempotency-key", &key)],
            Some((
                "application/json",
                serde_json::to_vec(&json!({
                    "input": {"personId": id, "name": "Renamed"},
                    "preconditions": condition.body["preconditions"].clone()
                }))
                .unwrap(),
            )),
        )
        .await;
    assert_eq!(renamed.status, 200, "{}", renamed.text());
    revision += 1;
    assert_latest_equals_current(&history, &id, revision).await;

    // Proposal apply.
    let client = &history.fixture.http.client;
    let metadata = client.registry_contract(Some(WRITER)).await.unwrap();
    let action = metadata
        .value
        .select_action("correct-person-name", WRITER)
        .unwrap();
    let Value::Object(input) = json!({"person": id, "name": "Corrected"}) else {
        unreachable!()
    };
    let request = BRegActionInvocationRequest::new(&action, input, None).unwrap();
    let draft = client
        .start_proposal(
            &action,
            &request,
            &BRegIdempotencyKey::parse("history-proposal-start").unwrap(),
        )
        .await
        .unwrap()
        .value;
    let submit = client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &BRegIdempotencyKey::parse("history-proposal-submit").unwrap(),
        )
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    assert!(history
        .fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    revision += 1;
    assert_latest_equals_current(&history, &id, revision).await;

    // Tombstone: the tombstone revision keeps the row's data.
    let before = history
        .get(&format!("/v1/records/people/{id}"), WRITER)
        .await;
    history.tombstone("people", &id).await;
    revision += 1;
    let latest = history.revision("people", &id, revision, WRITER).await;
    assert_eq!(latest.status, 200, "{}", latest.text());
    assert_eq!(latest.body["data"]["lifecycle"], "tombstoned");
    assert_eq!(
        latest.body["data"]["domainData"], before.body["data"]["domainData"],
        "the tombstone revision holds the row data"
    );
    let lifecycle: String = history
        .fixture
        .database
        .admin
        .query_one(
            "SELECT lifecycle FROM (
                SELECT record_lifecycle AS lifecycle
                  FROM registry_internal.registry_revisions
                 WHERE record_id = $1::text::uuid
              ORDER BY record_revision DESC LIMIT 1) latest",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(lifecycle, "tombstoned");

    history.fixture.finish().await;
}

/// The newest revision (`revision`) of a live person holds exactly the data
/// the current read returns.
async fn assert_latest_equals_current(history: &History, id: &str, revision: u32) {
    let current = history
        .get(&format!("/v1/records/people/{id}"), WRITER)
        .await;
    assert_eq!(current.status, 200, "{}", current.text());
    let latest = history.revision("people", id, revision, WRITER).await;
    assert_eq!(latest.status, 200, "{}", latest.text());
    assert_eq!(
        latest.body["data"]["domainData"], current.body["data"]["domainData"],
        "revision {revision} equals the current row"
    );
    let list = history.revisions("people", id, WRITER).await;
    assert_eq!(
        list.body["items"][0]["revisionIdentifier"],
        revision.to_string(),
        "no revision is newer than {revision}"
    );
}

/// The change context a revision carries, wherever the response nests it.
fn change_context(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(members) => members
            .get("changeContext")
            .or_else(|| members.values().find_map(change_context)),
        Value::Array(items) => items.iter().find_map(change_context),
        _ => None,
    }
}

/// A snapshot reference taken before a record is marked must not read it.
/// Disclosure follows the latest retained revision of the record, not the
/// state at the reference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_snapshot_reference_does_not_read_a_record_marked_since() {
    let history = History::start().await;
    let open_person = |name: &str, email: &str, phone: &str| {
        json!({"familyName": name, "protectionLevel": "none", "historyProtected": false,
            "emailAddress": email, "phoneNumber": phone})
    };
    let p = history
        .create("people", open_person("Later", CANARY_EMAIL, CANARY_PHONE))
        .await;
    let f = history
        .create(
            "people",
            open_person("Shielded", "shielded@example.invalid", "555-0199"),
        )
        .await;
    let open = history
        .create(
            "people",
            open_person("Open", "open@example.invalid", "555-0100"),
        )
        .await;
    let r = history
        .create(
            "residences",
            json!({"personId": p, "protectionLevel": "none", "address": CANARY_ADDRESS}),
        )
        .await;
    let n = history
        .create(
            "name-usages",
            json!({"personId": p, "protectionLevel": "none",
                "oldName": CANARY_OLD_NAME, "closedOn": "2020-01-01"}),
        )
        .await;

    // Before marking, the reference reads every value: the canary is not vacuous.
    let people = history.snapshot("people", REGISTRAR).await;
    let reference = people.body["snapshot"]
        .as_str()
        .unwrap_or_else(|| panic!("a snapshot reference in {}", people.text()))
        .to_owned();
    assert_has_sentinel(&people.text(), CANARY_EMAIL);
    assert_has_sentinel(
        &history.snapshot("residences", REGISTRAR).await.text(),
        CANARY_ADDRESS,
    );
    assert_has_sentinel(
        &history.snapshot("name-usages", REGISTRAR).await.text(),
        CANARY_OLD_NAME,
    );

    // Mark P (record and history), F (contacts only), R and N.
    history
        .patch(
            "people",
            &p,
            &[
                ("protectionLevel", json!("protected")),
                ("historyProtected", json!(true)),
            ],
        )
        .await;
    history
        .patch("people", &f, &[("protectionLevel", json!("protected"))])
        .await;
    history
        .patch("residences", &r, &[("protectionLevel", json!("protected"))])
        .await;
    history
        .patch(
            "name-usages",
            &n,
            &[("protectionLevel", json!("protected"))],
        )
        .await;

    let at_reference = |route: &'static str| {
        let history = &history;
        let reference = reference.clone();
        async move {
            history
                .get(
                    &format!(
                        "/v1/records/{route}:snapshot?$count=true&$top=100&snapshot={reference}"
                    ),
                    REGISTRAR,
                )
                .await
        }
    };
    let people = at_reference("people").await;
    assert_eq!(people.status, 200, "{}", people.text());
    assert_no_sentinel(&people.text());
    let ids = History::ids(&people);
    assert!(!ids.contains(&p), "the marked person is absent");
    assert!(ids.contains(&open), "the open person is still read");
    assert_eq!(
        people.body["count"], 2,
        "the count excludes withheld records"
    );
    let shielded = people.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["recordIdentifier"] == f.as_str())
        .expect("the shielded person is listed");
    assert_eq!(
        shielded["domainData"].get("emailAddress"),
        Some(&Value::Null)
    );
    assert_eq!(shielded["domainData"]["familyName"], "Shielded");
    for route in ["residences", "name-usages"] {
        let reply = at_reference(route).await;
        assert_eq!(reply.status, 200, "{}", reply.text());
        assert_no_sentinel(&reply.text());
        assert!(History::ids(&reply).is_empty(), "{route}: {}", reply.text());
        assert_eq!(reply.body["count"], 0);
    }
    history.fixture.finish().await;
}

/// A commit shares one change context across its records. A marked record in
/// the commit must not lend that context to an unmarked one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_commit_context_shared_with_a_marked_record_is_withheld() {
    let history = History::start().await;
    let batch = |items: Value, key: &str| {
        let history = &history;
        let key = key.to_owned();
        async move {
            let reply = history
                .send(
                    Method::POST,
                    "/v1/records/people:batch",
                    WRITER,
                    &[("idempotency-key", &key)],
                    Some((
                        "application/json",
                        serde_json::to_vec(&json!({
                            "changeContext": {"kind": "correction", "reasonCode": "commit-context",
                                "reasonText": "COMMIT-CONTEXT-CANARY",
                                "sourceReferences": ["case-document:commit-context-canary"]},
                            "items": items
                        }))
                        .unwrap(),
                    )),
                )
                .await;
            assert_eq!(reply.status, 200, "batch: {}", reply.text());
            reply.body["results"]
                .as_array()
                .expect("a batch lists its results")
                .iter()
                .map(|item| item["recordIdentifier"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };
    let person = |name: &str, level: &str, flag: bool| {
        json!({"operation": "create", "data": {"familyName": name, "protectionLevel": level,
            "historyProtected": flag, "emailAddress": "mixed@example.invalid",
            "phoneNumber": "555-0123"}})
    };
    let mixed = batch(
        json!([
            person("Marked", "protected", true),
            person("Unmarked", "none", false)
        ]),
        "mixed-batch",
    )
    .await;
    let (marked, unmarked) = (&mixed[0], &mixed[1]);
    // A commit of two open records lends its context, so the control is not vacuous.
    let open = batch(
        json!([
            person("OpenOne", "none", false),
            person("OpenTwo", "none", false)
        ]),
        "open-batch",
    )
    .await;
    let control = history.revisions("people", &open[0], REGISTRAR).await;
    assert_eq!(control.status, 200, "{}", control.text());
    assert_has_sentinel(&control.text(), "COMMIT-CONTEXT-CANARY");

    let exempt = history
        .revisions("people", unmarked, PROTECTION_OFFICER)
        .await;
    assert_has_sentinel(&exempt.text(), "COMMIT-CONTEXT-CANARY");
    let reply = history.revisions("people", unmarked, REGISTRAR).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert!(
        change_context(&reply.body).is_none(),
        "the unmarked record carries the marked record's context: {}",
        reply.text()
    );
    let text = reply.text();
    assert!(!text.contains("COMMIT-CONTEXT-CANARY"), "{text}");
    assert!(!text.contains("commit-context-canary"), "{text}");
    assert!(!text.contains(marked.as_str()), "{text}");
    let detail = history.revision("people", unmarked, 1, REGISTRAR).await;
    assert_eq!(detail.status, 200, "{}", detail.text());
    assert!(change_context(&detail.body).is_none(), "{}", detail.text());
    history.fixture.finish().await;
}

#[path = "writes.rs"]
mod writes;
