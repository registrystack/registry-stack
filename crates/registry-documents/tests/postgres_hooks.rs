// SPDX-License-Identifier: Apache-2.0

//! Database-backed tests of the Document Store's after-commit observer
//! hooks: a verification verdict or a grant change captures exactly one
//! delivery per matching hook inside its own transaction, a transition that
//! rolls back captures nothing, delivery signs and sends the stored
//! canonical envelope, a returned proposal is refused, and a destination
//! that keeps failing is retried and then dead-lettered without ever
//! reaching the transition it reports.

mod support;

use std::sync::Arc;

use registry_documents::runtime::{prepare_with_verifier, Prepared, RuntimeError};
use registry_documents_core::{
    DOCUMENT_GRANT_CHANGED_EVENT_SCHEMA_ID, DOCUMENT_VERSION_READY_EVENT_SCHEMA_ID,
    DOCUMENT_VERSION_REJECTED_EVENT_SCHEMA_ID,
};
use registry_platform_hooks::delivery::DeliveryOutcome;
use serde_json::{json, Value};
use support::{
    pdf, reservation, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN, DATABASE_STORAGE,
    DISABLED_VERIFIER, READER, REJECT, STARTER_PROJECT, UNREACHABLE_HOOKS_URL,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PDF: &str = "application/pdf";
const SOURCE: &str = "urn:registrystack:documents:civil-registry-documents";

/// A second observer on `document-version.ready`, so one verdict must
/// capture one delivery for each.
const READY_MIRROR: &str = "
  - id: ready-mirror
    phase: after
    trigger: document-version.ready
    policies: [citizen-delivery]
    projection: [documentId]
    handler:
      type: url
      destinationId: owning-system-events
";

fn two_ready_observers() -> String {
    let project = STARTER_PROJECT.replacen("\nhooks:\n", &format!("\nhooks:{READY_MIRROR}"), 1);
    assert_ne!(
        project, STARTER_PROJECT,
        "the starter project declares hooks"
    );
    project
}

async fn deployment(project: &str) -> Deployment {
    let deployment = Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, project).await;
    deployment.migrate().await;
    deployment
}

async fn start(deployment: &Deployment, verifier: &Arc<FakeVerifier>) -> (Prepared, Api) {
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (prepared, api)
}

async fn upload(api: &Api, seed: u8) -> (String, String) {
    let content = pdf(512, seed);
    let reserved = api
        .reserve(APP, "citizen-delivery", CITIZEN.subject, &content, PDF)
        .await;
    let (document, version, path) = reservation(&reserved);
    let put = api
        .put(APP, &path, PDF, axum::body::Body::from(content))
        .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    (document, version)
}

/// Every captured event in capture order: its hook, its delivery count,
/// and its stored canonical envelope.
async fn captured(deployment: &Deployment) -> Vec<(String, i64, Value)> {
    let schema = &deployment.schema;
    let rows = deployment
        .admin
        .query(
            &format!(
                "SELECT o.event_type,
                        (SELECT count(*) FROM {schema}.registry_webhook_deliveries d
                          WHERE d.event_id = o.event_id),
                        o.payload
                   FROM {schema}.registry_outbox AS o ORDER BY o.created_at, o.event_type"
            ),
            &[],
        )
        .await
        .expect("read the captured events");
    rows.iter()
        .map(|row| {
            let payload: Vec<u8> = row.get(2);
            (
                row.get(0),
                row.get(1),
                serde_json::from_slice(&payload).expect("a canonical JSON envelope"),
            )
        })
        .collect()
}

async fn delivery_count(deployment: &Deployment) -> i64 {
    deployment
        .scalar("SELECT count(*) FROM registry_webhook_deliveries")
        .await
}

fn hook_delivery_entries(deployment: &Deployment) -> Vec<Value> {
    deployment
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["record"]["event"] == "documents.hook-delivery")
        .collect()
}

#[tokio::test]
async fn a_verdict_captures_one_delivery_per_matching_observer_with_the_closed_projection() {
    let deployment = deployment(&two_ready_observers()).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 3).await;
    assert!(
        captured(&deployment).await.is_empty(),
        "an upload alone reports nothing"
    );

    assert_eq!(prepared.verify_due().await, 1);
    let events = captured(&deployment).await;
    assert_eq!(events.len(), 2, "one event per matching observer");
    let by_hook = |hook: &str| {
        events
            .iter()
            .find(|(id, _, _)| id == hook)
            .unwrap_or_else(|| panic!("an event for {hook}"))
    };
    let (_, deliveries, ready) = by_hook("document-version-ready");
    assert_eq!(*deliveries, 1);
    assert_eq!(ready["type"], "document-version-ready");
    assert_eq!(ready["source"], SOURCE);
    assert_eq!(ready["dataschema"], DOCUMENT_VERSION_READY_EVENT_SCHEMA_ID);
    assert_eq!(
        ready["subject"],
        json!({
            "recordReference": format!("/v1/documents/{document}/versions/{version}"),
            // Reserved, finalized, then approved.
            "recordRevision": 3,
        })
    );
    let digest: String = deployment
        .scalar("SELECT verified_digest FROM documents_versions")
        .await;
    assert_eq!(
        ready["data"],
        json!({
            "documentId": document,
            "policyId": "citizen-delivery",
            "policyVersion": ready["data"]["policyVersion"],
            "versionDigest": digest,
            "versionId": version,
        })
    );
    assert!(ready["data"]["policyVersion"].is_string());
    let (_, deliveries, mirror) = by_hook("ready-mirror");
    assert_eq!(*deliveries, 1);
    assert_eq!(mirror["type"], "ready-mirror");
    assert_eq!(mirror["dataschema"], DOCUMENT_VERSION_READY_EVENT_SCHEMA_ID);
    assert_eq!(mirror["data"], json!({"documentId": document}));

    // The envelope never carries content, labels, media types, names, or
    // anyone's subject.
    for (_, _, envelope) in &events {
        let text = envelope.to_string();
        for forbidden in [PDF, CITIZEN.subject, APP.subject, "label", "mediaType"] {
            assert!(!text.contains(forbidden), "{forbidden} leaked into {text}");
        }
    }

    // Verifying the same version again changes nothing and reports nothing.
    deployment
        .execute(
            "UPDATE documents_verification_jobs
                SET state = 'pending', next_attempt_at = now(), delivered_at = NULL",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(delivery_count(&deployment).await, 2);
    let revision: i64 = deployment
        .scalar("SELECT revision FROM documents_versions")
        .await;
    assert_eq!(revision, 3, "a repeated approval is not a change");
}

#[tokio::test]
async fn a_version_approved_again_after_a_verifier_rebind_reports_ready_again() {
    let deployment = deployment(STARTER_PROJECT).await;
    let first = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &first).await;
    let (document, version) = upload(&api, 11).await;
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(delivery_count(&deployment).await, 1);
    drop((prepared, api));

    // A restart under another verifier binding suspends the version and
    // reports nothing until the new binding approves it.
    let second = FakeVerifier::new("binding-b", APPROVE);
    let (restarted, api) = start(&deployment, &second).await;
    assert_eq!(
        api.read(APP, &document).await.json()["version"]["status"],
        "suspended"
    );
    assert_eq!(delivery_count(&deployment).await, 1);
    deployment
        .execute(
            "UPDATE documents_verification_jobs SET next_attempt_at = now()
              WHERE state = 'pending'",
        )
        .await;
    restarted.verify_due().await;
    let events = captured(&deployment).await;
    assert_eq!(events.len(), 2, "ready once per transition into ready");
    for (hook, deliveries, envelope) in &events {
        assert_eq!(hook, "document-version-ready");
        assert_eq!(*deliveries, 1);
        assert_eq!(envelope["data"]["versionId"], version.as_str());
    }
    assert_ne!(events[0].2["id"], events[1].2["id"]);
    // Finalize, approve, suspend on rebind, approve again: each recorded
    // change advances the version's revision, so the second report names a
    // later revision than the first and a receiver can order them.
    let revision = |envelope: &Value| envelope["subject"]["recordRevision"].as_i64().unwrap();
    let (first, second) = (revision(&events[0].2), revision(&events[1].2));
    assert!(first > 1, "the approval advanced the version's revision");
    assert_eq!(second, first + 2, "a suspension and an approval later");
    let stored: i64 = deployment
        .scalar("SELECT revision FROM documents_versions")
        .await;
    assert_eq!(stored, second);
}

#[tokio::test]
async fn a_hook_hears_nothing_about_a_document_under_a_policy_it_does_not_name() {
    // Every starter hook names every starter policy; narrow them all to one
    // policy the citizen's upload is not held under.
    let all = "policies: [citizen-delivery, institutional-custody, named-share]";
    assert_eq!(STARTER_PROJECT.matches(all).count(), 3);
    let project = STARTER_PROJECT.replace(all, "policies: [institutional-custody]");
    let deployment = deployment(&project).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 14).await;
    let policy: String = deployment
        .scalar("SELECT policy_id FROM documents_documents")
        .await;
    assert_eq!(policy, "citizen-delivery");

    assert_eq!(prepared.verify_due().await, 1);
    let issued = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    assert_eq!(
        issued.status,
        201,
        "{}",
        String::from_utf8_lossy(&issued.body)
    );
    let grant = issued.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    assert!(
        captured(&deployment).await.is_empty(),
        "no transition under an unnamed policy captures a delivery"
    );
    assert_eq!(delivery_count(&deployment).await, 0);
}

#[tokio::test]
async fn a_rejection_captures_the_rejected_event_once() {
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", REJECT);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 4).await;
    assert_eq!(prepared.verify_due().await, 1);
    let events = captured(&deployment).await;
    assert_eq!(events.len(), 1);
    let (hook, deliveries, rejected) = &events[0];
    assert_eq!(hook, "document-version-rejected");
    assert_eq!(*deliveries, 1);
    assert_eq!(rejected["type"], "document-version-rejected");
    assert_eq!(
        rejected["dataschema"],
        DOCUMENT_VERSION_REJECTED_EVENT_SCHEMA_ID
    );
    assert_eq!(rejected["data"]["documentId"], document.as_str());
    assert_eq!(rejected["data"]["versionId"], version.as_str());
    assert_eq!(
        rejected["data"].as_object().unwrap().len(),
        4,
        "exactly the starter hook's projection"
    );

    deployment
        .execute(
            "UPDATE documents_verification_jobs
                SET state = 'pending', next_attempt_at = now(), delivered_at = NULL",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(
        delivery_count(&deployment).await,
        1,
        "a second rejection reports nothing"
    );
}

#[tokio::test]
async fn grant_issue_and_revoke_each_capture_one_event_and_repeats_capture_none() {
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 5).await;
    assert_eq!(prepared.verify_due().await, 1);
    let after_ready = delivery_count(&deployment).await;
    assert_eq!(after_ready, 1);

    let key = uuid::Uuid::new_v4().to_string();
    let issued = api
        .grant_with_key(APP, &key, &document, &version, READER.subject, None)
        .await;
    assert_eq!(
        issued.status,
        201,
        "{}",
        String::from_utf8_lossy(&issued.body)
    );
    let grant = issued.json()["id"].as_str().unwrap().to_owned();
    let expires_at = issued.json()["expiresAt"].clone();
    assert!(expires_at.is_string());
    let replayed = api
        .grant_with_key(APP, &key, &document, &version, READER.subject, None)
        .await;
    assert_eq!(replayed.json()["id"], grant.as_str());
    assert_eq!(
        delivery_count(&deployment).await,
        after_ready + 1,
        "a replayed issue reports nothing"
    );

    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    assert_eq!(api.revoke(APP, &grant).await.status, 200);
    assert_eq!(
        delivery_count(&deployment).await,
        after_ready + 2,
        "a repeated revocation reports nothing"
    );

    let events = captured(&deployment).await;
    let grant_events = events
        .iter()
        .filter(|(hook, _, _)| hook == "document-grant-changed")
        .map(|(_, deliveries, envelope)| {
            assert_eq!(*deliveries, 1);
            envelope
        })
        .collect::<Vec<_>>();
    assert_eq!(grant_events.len(), 2);
    for (envelope, change, revision) in [
        (grant_events[0], "issued", 1),
        (grant_events[1], "revoked", 2),
    ] {
        assert_eq!(envelope["type"], "document-grant-changed");
        assert_eq!(
            envelope["dataschema"],
            DOCUMENT_GRANT_CHANGED_EVENT_SCHEMA_ID
        );
        assert_eq!(
            envelope["subject"],
            json!({
                "recordReference": format!("/v1/document-grants/{grant}"),
                "recordRevision": revision,
            })
        );
        assert_eq!(
            envelope["data"],
            json!({
                "actorKind": "service",
                "change": change,
                "documentId": document,
                "expiresAt": expires_at,
                "grantId": grant,
                "versionId": version,
            })
        );
        let text = envelope.to_string();
        assert!(!text.contains(READER.subject), "the grantee never leaks");
        assert!(!text.contains(APP.subject), "the issuer never leaks");
        assert!(!text.contains(CITIZEN.subject), "the custodian never leaks");
    }
}

/// The revoked grant events captured so far, by grant id.
fn revoked_grant_events(events: &[(String, i64, Value)]) -> Vec<&Value> {
    events
        .iter()
        .filter(|(hook, _, envelope)| {
            hook == "document-grant-changed" && envelope["data"]["change"] == "revoked"
        })
        .map(|(_, deliveries, envelope)| {
            assert_eq!(*deliveries, 1);
            envelope
        })
        .collect()
}

#[tokio::test]
async fn a_removal_captures_one_revoked_event_per_grant_it_revokes_and_a_repeat_none() {
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 12).await;
    assert_eq!(prepared.verify_due().await, 1);
    let mut active = Vec::new();
    let mut expiries = std::collections::BTreeMap::new();
    for grantee in ["reader-one", "reader-two", "reader-three"] {
        let issued = api.grant(APP, &document, &version, grantee, None).await;
        assert_eq!(
            issued.status,
            201,
            "{}",
            String::from_utf8_lossy(&issued.body)
        );
        let grant = issued.json()["id"].as_str().unwrap().to_owned();
        expiries.insert(grant.clone(), issued.json()["expiresAt"].clone());
        active.push(grant);
    }
    let already = api
        .grant(APP, &document, &version, "reader-revoked", None)
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(api.revoke(APP, &already).await.status, 200);
    let before = captured(&deployment).await;
    assert_eq!(revoked_grant_events(&before).len(), 1);

    let removed = api.erase(CITIZEN, &document).await;
    assert_eq!(
        removed.status,
        200,
        "{}",
        String::from_utf8_lossy(&removed.body)
    );
    let after = captured(&deployment).await;
    assert_eq!(after.len(), before.len() + active.len());
    let revoked = revoked_grant_events(&after);
    let mut reported = revoked[1..]
        .iter()
        .map(|envelope| {
            let grant = envelope["data"]["grantId"].as_str().unwrap().to_owned();
            assert_eq!(
                envelope["data"],
                json!({
                    "actorKind": "human",
                    "change": "revoked",
                    "documentId": document,
                    "expiresAt": expiries[&grant],
                    "grantId": grant,
                    "versionId": version,
                })
            );
            assert_eq!(
                envelope["subject"],
                json!({
                    "recordReference": format!("/v1/document-grants/{grant}"),
                    "recordRevision": 2,
                })
            );
            grant
        })
        .collect::<Vec<_>>();
    reported.sort();
    active.sort();
    assert_eq!(reported, active, "one event per grant the removal revoked");

    assert_eq!(api.erase(CITIZEN, &document).await.status, 200);
    assert_eq!(
        captured(&deployment).await.len(),
        after.len(),
        "a repeated removal reports nothing"
    );
}

#[tokio::test]
async fn a_rolled_back_removal_captures_nothing() {
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 13).await;
    assert_eq!(prepared.verify_due().await, 1);
    for grantee in ["reader-one", "reader-two"] {
        assert_eq!(
            api.grant(APP, &document, &version, grantee, None)
                .await
                .status,
            201
        );
    }
    let before = captured(&deployment).await.len();

    fail_commits_on(&deployment, "documents_grants").await;
    assert_eq!(api.erase(CITIZEN, &document).await.status, 503);
    allow_commits_on(&deployment, "documents_grants").await;
    let active: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants WHERE revoked_at IS NULL")
        .await;
    assert_eq!(active, 2, "the removal rolled back");
    let removed: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents WHERE removal_requested_at IS NOT NULL")
        .await;
    assert_eq!(removed, 0);
    assert_eq!(captured(&deployment).await.len(), before);
}

/// Install a deferred constraint trigger that fails the commit of any
/// transaction touching `table`, after every statement in it, captures
/// included, has run.
async fn fail_commits_on(deployment: &Deployment, table: &str) {
    deployment
        .execute(&format!(
            "CREATE FUNCTION documents_test_refuse_commit() RETURNS trigger
                 LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'the test refuses this commit'; END $$;
             CREATE CONSTRAINT TRIGGER documents_test_refuse_commit
                 AFTER INSERT OR UPDATE ON {table}
                 DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW EXECUTE FUNCTION documents_test_refuse_commit();"
        ))
        .await;
}

async fn allow_commits_on(deployment: &Deployment, table: &str) {
    deployment
        .execute(&format!(
            "DROP TRIGGER documents_test_refuse_commit ON {table};
             DROP FUNCTION documents_test_refuse_commit();"
        ))
        .await;
}

#[tokio::test]
async fn a_rolled_back_transition_captures_nothing() {
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 6).await;

    // The verdict and its capture run; the commit is refused.
    fail_commits_on(&deployment, "documents_versions").await;
    prepared.verify_due().await;
    let state: String = deployment
        .scalar("SELECT verification_state FROM documents_versions")
        .await;
    assert_eq!(state, "pending", "the verdict rolled back");
    assert_eq!(delivery_count(&deployment).await, 0);
    assert!(captured(&deployment).await.is_empty());
    allow_commits_on(&deployment, "documents_versions").await;

    // The job is retried and its committed verdict captures exactly once.
    deployment
        .execute(
            "UPDATE documents_verification_jobs
                SET state = 'pending', next_attempt_at = now(), attempt_started_at = NULL,
                    lease_expires_at = NULL, lease_token = NULL",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(delivery_count(&deployment).await, 1);

    fail_commits_on(&deployment, "documents_grants").await;
    let refused = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    assert_eq!(refused.status, 503);
    let grants: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants")
        .await;
    assert_eq!(grants, 0);
    assert_eq!(
        delivery_count(&deployment).await,
        1,
        "a refused issue captures nothing"
    );
    allow_commits_on(&deployment, "documents_grants").await;
}

/// A capture that cannot commit takes its transition down with it: the
/// refusal is raised by the delivery row itself, after the transition's
/// own writes succeeded, and each transition is found as it was before.
#[tokio::test]
async fn a_capture_that_cannot_commit_rolls_its_transition_back() {
    const DELIVERIES: &str = "registry_webhook_deliveries";
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 15).await;

    fail_commits_on(&deployment, DELIVERIES).await;
    prepared.verify_due().await;
    allow_commits_on(&deployment, DELIVERIES).await;
    let state: String = deployment
        .scalar("SELECT verification_state FROM documents_versions")
        .await;
    assert_eq!(state, "pending", "the verdict rolled back with its capture");
    assert_eq!(delivery_count(&deployment).await, 0);
    deployment
        .execute(
            "UPDATE documents_verification_jobs
                SET state = 'pending', next_attempt_at = now(), attempt_started_at = NULL,
                    lease_expires_at = NULL, lease_token = NULL",
        )
        .await;
    prepared.verify_due().await;
    assert_eq!(delivery_count(&deployment).await, 1);

    fail_commits_on(&deployment, DELIVERIES).await;
    let refused = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    allow_commits_on(&deployment, DELIVERIES).await;
    assert_eq!(refused.status, 503);
    let grants: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants")
        .await;
    assert_eq!(grants, 0, "the issue rolled back with its capture");

    let issued = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    assert_eq!(issued.status, 201);
    let grant = issued.json()["id"].as_str().unwrap().to_owned();
    fail_commits_on(&deployment, DELIVERIES).await;
    let refused = api.revoke(APP, &grant).await;
    let removal = api.erase(CITIZEN, &document).await;
    allow_commits_on(&deployment, DELIVERIES).await;
    assert_eq!(refused.status, 503);
    assert_eq!(removal.status, 503);
    let active: i64 = deployment
        .scalar("SELECT count(*) FROM documents_grants WHERE revoked_at IS NULL")
        .await;
    assert_eq!(active, 1, "the revocation and the removal rolled back");
    let removed: i64 = deployment
        .scalar("SELECT count(*) FROM documents_documents WHERE removal_requested_at IS NOT NULL")
        .await;
    assert_eq!(removed, 0);
    assert_eq!(delivery_count(&deployment).await, 2);
}

#[tokio::test]
async fn delivery_sends_the_signed_envelope_and_refuses_a_returned_proposal() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/document-events"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"answer":"proposal","document":{"operation":"erase"}}"#,
            "application/json",
        ))
        .expect(1)
        .mount(&receiver)
        .await;
    let mut deployment = deployment(STARTER_PROJECT).await;
    deployment.bind_hooks(&format!("{}/document-events", receiver.uri()));
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, _) = upload(&api, 7).await;
    assert_eq!(prepared.verify_due().await, 1);
    let stored: Vec<u8> = deployment
        .scalar("SELECT payload FROM registry_outbox")
        .await;

    let outcome = prepared
        .deliver_hooks_once()
        .await
        .expect("the delivery completes");
    assert_eq!(outcome, DeliveryOutcome::Delivered);
    assert_eq!(
        prepared.deliver_hooks_once().await.expect("an idle pass"),
        DeliveryOutcome::Idle
    );

    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.body, stored, "the stored canonical bytes are sent");
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("missing valid {name} header"))
            .to_owned()
    };
    assert_eq!(header("ce-type"), "document-version-ready");
    assert_eq!(header("ce-source"), SOURCE);
    assert_eq!(
        header("ce-dataschema"),
        DOCUMENT_VERSION_READY_EVENT_SCHEMA_ID
    );
    assert!(header("x-registry-signature").starts_with("v1="));
    assert!(header("idempotency-key").starts_with("sha256:"));

    let state = deployment
        .admin
        .query_one(
            &format!(
                "SELECT state, attempt, proposal_disposition, proposal_code
                   FROM {}.registry_webhook_delivery_state",
                deployment.schema
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(state.get::<_, String>(0), "delivered");
    assert_eq!(state.get::<_, i16>(1), 1);
    assert_eq!(
        state.get::<_, Option<String>>(2).as_deref(),
        Some("refused")
    );
    assert_eq!(
        state.get::<_, Option<String>>(3).as_deref(),
        Some("documents.hook.proposal-unsupported")
    );

    // The proposal changed nothing about the document.
    let read = api.read(CITIZEN, &document).await;
    assert_eq!(read.json()["version"]["status"], "ready");

    let audit = hook_delivery_entries(&deployment);
    assert_eq!(audit.len(), 2, "an attempt entry and its terminal entry");
    assert_eq!(audit[0]["phase"], "request");
    assert_eq!(audit[1]["phase"], "response");
    assert_eq!(audit[1]["correlation"], audit[0]["correlation"]);
    assert_eq!(audit[1]["record"]["outcome"], "delivered");
}

#[tokio::test]
async fn a_failing_destination_is_retried_then_dead_lettered_without_touching_the_transition() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/document-events"))
        .respond_with(ResponseTemplate::new(503))
        .expect(2)
        .mount(&receiver)
        .await;
    let mut deployment = deployment(STARTER_PROJECT).await;
    deployment.bind_hooks(&format!("{}/document-events", receiver.uri()));
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, _) = upload(&api, 8).await;
    assert_eq!(prepared.verify_due().await, 1);

    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::RetryScheduled
    );
    let (state, attempt): (String, i16) = {
        let row = deployment
            .admin
            .query_one(
                &format!(
                    "SELECT state, attempt FROM {}.registry_webhook_delivery_state",
                    deployment.schema
                ),
                &[],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!((state.as_str(), attempt), ("pending", 1));
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::Idle,
        "the retry waits for its backoff"
    );

    deployment
        .execute("UPDATE registry_webhook_delivery_state SET next_attempt_at = now()")
        .await;
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::DeadLettered,
        "the deployed budget allows two attempts"
    );
    let state: String = deployment
        .scalar("SELECT state FROM registry_webhook_delivery_state")
        .await;
    assert_eq!(state, "dead-lettered");

    // The version the event reports stays ready throughout.
    let read = api.read(CITIZEN, &document).await;
    assert_eq!(read.json()["version"]["status"], "ready");
}

#[tokio::test]
async fn an_unreachable_destination_never_blocks_a_transition() {
    // The default binding points at a loopback port nothing listens on.
    let deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 9).await;
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::RetryScheduled
    );
    let issued = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    assert_eq!(issued.status, 201);
    assert_eq!(delivery_count(&deployment).await, 2);
}

#[tokio::test]
async fn startup_refuses_a_project_hook_whose_destination_is_not_bound() {
    let project = STARTER_PROJECT.replace(
        "destinationId: owning-system-events",
        "destinationId: unbound-events",
    );
    let deployment = deployment(&project).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let error = prepare_with_verifier(&deployment.runtime, verifier)
        .await
        .expect_err("an unbound hook destination refuses startup");
    let message = error.to_string();
    assert!(
        message.contains("documents.runtime.unbound-hook-destination"),
        "{message}"
    );
    // The refusal is the positioned report `documentsctl check --project`
    // gives for the same files: one diagnostic at `/destinations/hooks`, on
    // its line of the runtime document.
    let RuntimeError::ConfigurationRefused(report) = &error else {
        panic!("a positioned configuration refusal, not {message}");
    };
    let found: Vec<(&str, &str)> = report
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect();
    assert_eq!(
        found,
        [(
            "documents.runtime.unbound-hook-destination",
            "/destinations/hooks"
        )]
    );
    let source = report.diagnostics()[0]
        .source
        .as_ref()
        .expect("the diagnostic names its file");
    assert_eq!(source.file, deployment.runtime.display().to_string());
    assert!(source.line.is_some(), "{message}");
}

#[tokio::test]
async fn a_destination_changed_under_a_pending_delivery_refuses_startup_until_it_drains() {
    let mut deployment = deployment(STARTER_PROJECT).await;
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    upload(&api, 10).await;
    assert_eq!(prepared.verify_due().await, 1);
    assert_eq!(delivery_count(&deployment).await, 1);
    drop((prepared, api));

    // Changing the URL in place while the delivery is pending is refused.
    deployment.bind_hooks("https://moved.example.test/document-events");
    let error = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect_err("a pending delivery pins its destination binding");
    assert!(
        error.to_string().contains("retained hook delivery"),
        "{error}"
    );

    // Restored, the pending delivery runs out its attempts.
    deployment.bind_hooks(UNREACHABLE_HOOKS_URL);
    let (prepared, api) = start(&deployment, &verifier).await;
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::RetryScheduled
    );
    deployment
        .execute("UPDATE registry_webhook_delivery_state SET next_attempt_at = now()")
        .await;
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::DeadLettered
    );
    drop((prepared, api));

    // Once it has drained, the same change starts.
    deployment.bind_hooks("https://moved.example.test/document-events");
    prepare_with_verifier(&deployment.runtime, verifier)
        .await
        .expect("no retained delivery needs the old binding");
}

#[tokio::test]
async fn a_split_runtime_role_captures_and_delivers_under_its_own_grants() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/document-events"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&receiver)
        .await;
    let mut deployment =
        Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, STARTER_PROJECT).await;
    deployment.bind_hooks(&format!("{}/document-events", receiver.uri()));

    // A runtime login role with no authority of its own over the schema.
    let role = format!("wp6doc_runtime_{}", uuid::Uuid::new_v4().simple());
    deployment
        .admin
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'documents-test' NOSUPERUSER NOCREATEDB NOCREATEROLE"
        ))
        .await
        .unwrap();
    let mut limited = url::Url::parse(&support::database_url()).unwrap();
    limited.set_username(&role).unwrap();
    limited.set_password(Some("documents-test")).unwrap();
    limited
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={}", deployment.schema));
    deployment.secret("runtime-database-url", limited.as_str());
    let scoped = {
        let base = support::database_url();
        let separator = if base.contains('?') { '&' } else { '?' };
        format!(
            "{base}{separator}options=-csearch_path%3D{}",
            deployment.schema
        )
    };
    deployment.secret("migration-database-url", &scoped);
    let config = registry_documents::config::RuntimeConfig::load(&deployment.runtime)
        .expect("the test runtime document loads");
    let applied = registry_documents::runtime::apply_activation(
        &config,
        &registry_documents::activation::ApplyRequest::default(),
    )
    .await
    .expect("the migration credential applies");
    assert_eq!(
        applied.activation.role_mode,
        registry_platform_activation::RoleMode::Split
    );

    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (prepared, api) = start(&deployment, &verifier).await;
    let (document, version) = upload(&api, 10).await;
    assert_eq!(prepared.verify_due().await, 1);
    let issued = api
        .grant(APP, &document, &version, READER.subject, None)
        .await;
    assert_eq!(issued.status, 201);
    assert_eq!(delivery_count(&deployment).await, 2);
    assert_eq!(
        prepared.deliver_hooks_once().await.unwrap(),
        DeliveryOutcome::Delivered
    );
}
