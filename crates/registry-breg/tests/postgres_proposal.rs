// SPDX-License-Identifier: Apache-2.0
//! Durable Proposal journeys over the public client and PostgreSQL RLS.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposalQuery, BRegProposalState, BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claims(subject: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        subject,
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
async fn application_queue_age(fixture: &client_http::ClientFixture) -> f64 {
    use tower::util::ServiceExt;
    let router = registry_breg::metrics::metrics_app(std::sync::Arc::new(
        registry_breg::metrics::Metrics::with_pool_for_test(fixture.pool.clone()),
    ));
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let rendered = std::str::from_utf8(&bytes).unwrap();
    rendered
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "breg_queue_oldest_pending_age_seconds{queue=\"review-application\"} ",
            )
        })
        .expect("current Proposal tables produce the queue sample")
        .parse()
        .unwrap()
}
fn registry_source(automatic: bool) -> Value {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":if automatic{json!({"mode":"automatic","maximumAttempts":3})}else{json!({"mode":"manual"})},
            "retention":{"mode":"operator-erase"},"attachments":[{"id":"support","required":false,"maximumBytes":4096,
                "contentTypes":["text/plain"],"classification":"restricted"}]}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":["name","jurisdiction"],
                    "writableFields":["name","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
                "proposals":[{"action":"correct-name","operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller","readableAttachments":["support"],"writableAttachments":["support"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    source
}
fn compile(source: Value) -> registry_breg::CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("standalone Proposal compiles")
}
fn registry(automatic: bool) -> registry_breg::CompiledRegistry {
    compile(registry_source(automatic))
}

async fn proposal_state_lock_wait(fixture: &client_http::ClientFixture, minimum: i64) -> bool {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                 WHERE datname=current_database() AND wait_event_type='Lock'
                   AND query LIKE '%registry_proposal_state%'
                   AND (query LIKE '%FOR UPDATE%' OR query LIKE '%FOR SHARE%')",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting >= minimum {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coherent_observation_waits_for_automatic_application() {
    use std::time::Duration;
    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Coherent", "coherent-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("coherent-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let table = &fixture.registry.entities()["target"].physical_table;
    // Pause the actual automatic write after it owns the lifecycle row. The
    // advisory lock is only a deterministic fixture barrier, not a runtime hook.
    fixture.database.admin.batch_execute(&format!(
        "CREATE FUNCTION registry_data.pause_application() RETURNS trigger LANGUAGE plpgsql AS $body$
         BEGIN PERFORM pg_advisory_xact_lock(732995001); RETURN NEW; END $body$;
         CREATE TRIGGER pause_application BEFORE UPDATE ON registry_data.\"{table}\"
         FOR EACH ROW EXECUTE FUNCTION registry_data.pause_application()"
    )).await.unwrap();
    let (barrier, barrier_task) = fixture.database.connect_migration().await;
    barrier
        .execute("SELECT pg_advisory_lock(732995001)", &[])
        .await
        .unwrap();
    let mutations = fixture.mutations.clone();
    let applying =
        tokio::spawn(async move { mutations.run_automatic_proposal_once_for_test().await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = fixture
                .database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if waiting != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("automatic writer reached the fixture barrier while owning Proposal state");
    {
        let observation = client.read_proposal(&submitted);
        tokio::pin!(observation);
        let query = BRegProposalQuery::default();
        let listing = client.list_proposals(&collection, &query);
        tokio::pin!(listing);
        let waited = tokio::select! {
            _ = &mut observation => false,
            _ = &mut listing => false,
            waited = proposal_state_lock_wait(&fixture, 2) => waited,
        };
        // Always release the writer, including on the pre-fix failure path.
        barrier
            .execute("SELECT pg_advisory_unlock(732995001)", &[])
            .await
            .unwrap();
        assert!(applying.await.unwrap().unwrap());
        assert!(
            waited,
            "a composed observation must wait for the lifecycle writer"
        );
        let current = observation.await.unwrap().value;
        assert_eq!(current.state(), BRegProposalState::Applied);
        assert_eq!(
            current.application().unwrap().effect_digest.as_str(),
            submitted.effect_digest().unwrap()
        );
        let page = listing.await.unwrap().value;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].state(), BRegProposalState::Applied);
        assert_eq!(page.items[0].effect_digest(), submitted.effect_digest());
        drop(barrier);
        barrier_task.abort();
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coherent_observation_fences_review_approval_and_job_creation() {
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}", "b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reviewed coherent", "coherent-review-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("coherent-review-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions", &[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1", &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let result = review.result(&accepted);
    let (mut reader, reader_task) = fixture.database.connect_migration().await;
    let read = reader.transaction().await.unwrap();
    // A read may already have observed job absence. Approval plus job enqueue
    // must wait for that same lifecycle observation to finish.
    read.query_one("SELECT proposal_id FROM registry_internal.registry_proposal_state WHERE proposal_id=$1 FOR UPDATE", &[&uuid::Uuid::parse_str(submitted.id()).unwrap()]).await.unwrap();
    assert_eq!(
        read.query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_application_jobs",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let (mut writer, writer_task) = fixture.database.connect_migration().await;
    let write = writer.transaction().await.unwrap();
    let retained = {
        let reconciliation = registry_breg::review_store::reconcile_result(
            &write,
            "local-review",
            &accepted,
            &result,
        );
        tokio::pin!(reconciliation);
        let waited = tokio::select! {
            _ = &mut reconciliation => false,
            waited = proposal_state_lock_wait(&fixture, 1) => waited,
        };
        let retained: i64 = read
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_review_results",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        read.commit().await.unwrap();
        assert!(
            waited,
            "approval and automatic enqueue must take state before submission/job locks"
        );
        reconciliation.await.unwrap();
        retained
    };
    write.commit().await.unwrap();
    assert_eq!(retained, 0);
    let current = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    assert_eq!(
        serde_json::to_value(current).unwrap()["applicationStatus"]["state"],
        "pending"
    );
    assert_eq!(
        fixture
            .database
            .admin
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_proposal_application_jobs",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(reader);
    drop(writer);
    reader_task.abort();
    writer_task.abort();
    fixture.finish().await;
}

#[test]
fn proposal_input_disclosure_grants_require_declared_inputs_and_get_authority() {
    for (readable, operations) in [
        (json!(["missing"]), json!(["get"])),
        (json!(["value"]), json!(["list"])),
    ] {
        let mut source = registry_source(false);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] = readable;
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] = operations;
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] =
            json!([]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
            json!([]);
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let error = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
        assert!(format!("{error:?}").contains("breg.proposal.input-grant-invalid"));
    }
}

async fn start(
    fixture: &client_http::ClientFixture,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    start_action(fixture, "correct-name", value, key_name).await
}

async fn start_action(
    fixture: &client_http::ClientFixture,
    action_id: &str,
    value: &str,
    key_name: &str,
) -> registry_breg_client::BRegProposal {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key(&format!("{key_name}-record")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata.value.select_action(action_id, "clerk").unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":record.value.data.record_identifier,"value":value})),
        None,
    )
    .unwrap();
    client
        .start_proposal(&action, &input, &key(key_name))
        .await
        .unwrap()
        .value
}

#[tokio::test]
async fn known_proposal_http_authorization_refusals_are_value_free_and_audit_gated() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review-name","fields":{
            "currentName":{"type":"record","input":"target","field":"name"},
            "proposedName":{"type":"input","input":"value"}}});
    for id in [
        "reviewer",
        "missing-record-claim",
        "rebase-only",
        "no-bytes",
        "no-lifecycle",
    ] {
        let mut profile = source["accessProfiles"][0].clone();
        profile["id"] = json!(id);
        profile["default"] = json!(false);
        match id {
            "reviewer" | "missing-record-claim" => {
                profile["permissions"]["proposals"][0]["operations"] =
                    json!(["get", "get-review-context", "get-review-status"]);
                profile["permissions"]["proposals"][0]["readableContextFields"] =
                    json!(["currentName", "proposedName"]);
                profile["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
                if id == "missing-record-claim" {
                    profile["permissions"]["records"][0]["rowBoundaries"][0]["claim"] =
                        json!("recordZone");
                }
            }
            "rebase-only" => {
                profile["permissions"]["actions"] = json!([]);
            }
            "no-bytes" => {
                profile["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
                profile["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
            }
            "no-lifecycle" => {
                profile["permissions"]["proposals"] = json!([]);
            }
            _ => unreachable!(),
        }
        source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .push(profile);
    }
    let fixture = client_http::ClientFixture::start(
        compile(source),
        claims("audit-private-principal-canary", "zone-a"),
    )
    .await;
    let draft = start(
        &fixture,
        "audit-private-value-canary",
        "audit-refusal-start",
    )
    .await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"audit-private-attachment-canary",
            &key("audit-refusal-upload"),
        )
        .await
        .unwrap()
        .value;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("audit-refusal-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let id = submitted.id().to_owned();
    let cases = [
        (
            "GET",
            "review-context?accessProfile=clerk",
            "get-review-context",
        ),
        (
            "GET",
            "review-status?accessProfile=clerk",
            "get-review-status",
        ),
        (
            "GET",
            "review-context?accessProfile=missing-record-claim",
            "get-review-context",
        ),
        ("POST", "rebase?accessProfile=rebase-only", "rebase"),
        (
            "GET",
            "attachments/support?accessProfile=no-lifecycle&submissionVersion=1",
            "get",
        ),
        (
            "PATCH",
            "attachments/support?accessProfile=no-lifecycle",
            "edit",
        ),
        (
            "DELETE",
            "attachments/support?accessProfile=no-lifecycle",
            "edit",
        ),
        (
            "GET",
            "attachments/support?accessProfile=no-bytes&submissionVersion=1",
            "get",
        ),
        (
            "PATCH",
            "attachments/support?accessProfile=no-bytes",
            "edit",
        ),
        (
            "DELETE",
            "attachments/support?accessProfile=no-bytes",
            "edit",
        ),
    ];
    let mut unaudited = Vec::new();
    for (method, suffix, operation) in cases {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::Client::new()
            .request(
                method.parse().unwrap(),
                format!("{}/v1/proposals/{id}/{suffix}", fixture.http.base_url),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "{method} {suffix}"
        );
        assert!(response.headers().get("etag").is_none());
        let public = response.text().await.unwrap();
        let entries = fixture.audit_capture.entries();
        let refusals = entries[before..]
            .iter()
            .filter(|entry| entry["record"]["phase"] == "refusal")
            .collect::<Vec<_>>();
        if refusals.is_empty() {
            unaudited.push(format!("{method} {suffix}"));
            continue;
        }
        assert_eq!(refusals.len(), 1, "{method} {suffix}");
        let refusal = refusals[0];
        assert_eq!(refusal["record"]["actionId"], "correct-name");
        assert_eq!(
            refusal["record"]["operationId"],
            format!("proposals.correct-name.{operation}")
        );
        assert_eq!(refusal["record"]["method"], method);
        for canary in [
            "audit-private-principal-canary",
            "audit-private-value-canary",
            "audit-private-attachment-canary",
            id.as_str(),
        ] {
            assert!(
                !serde_json::to_string(&entries[before..])
                    .unwrap()
                    .contains(canary),
                "audit disclosed {canary}"
            );
            assert!(!public.contains(canary), "refusal disclosed {canary}");
        }
    }
    assert!(
        unaudited.is_empty(),
        "known Action refusals missed audit: {unaudited:?}"
    );
    for suffix in ["review-context", "review-status"] {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::get(format!(
            "{}/v1/proposals/{id}/{suffix}?accessProfile=reviewer",
            fixture.http.base_url
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{suffix}");
        let entries = fixture.audit_capture.entries();
        assert_eq!(
            entries[before..].len(),
            2,
            "permitted {suffix} pairs its audit"
        );
        assert_eq!(entries[before]["phase"], "request");
        assert_eq!(entries[before + 1]["phase"], "response");
        assert_eq!(
            entries[before]["correlation"],
            entries[before + 1]["correlation"]
        );
    }
    for suffix in [
        "review-context?accessProfile=clerk",
        "attachments/support?accessProfile=no-bytes&submissionVersion=1",
    ] {
        let before = fixture.audit_capture.entries().len();
        let response = reqwest::get(format!(
            "{}/v1/proposals/{}/{suffix}",
            fixture.http.base_url,
            uuid::Uuid::new_v4()
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            fixture.audit_capture.entries().len(),
            before,
            "unknown Proposal has no known Action attribution"
        );
    }
    fixture.audit_capture.fail_after(0);
    for (method, suffix, _) in cases {
        let response = reqwest::Client::new()
            .request(
                method.parse().unwrap(),
                format!("{}/v1/proposals/{id}/{suffix}", fixture.http.base_url),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{method} {suffix} must fail closed on audit loss"
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_review_reads_release_no_values_when_either_audit_append_fails() {
    for (suffix, accepted) in [
        ("review-context", 0),
        ("review-context", 1),
        ("review-status", 0),
        ("review-status", 1),
    ] {
        let mut source = registry_source(false);
        source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
            "id":"review-name","fields":{"proposedName":{"type":"input","input":"value"}}});
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
            json!(["get", "submit", "get-review-context", "get-review-status"]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
            json!(["proposedName"]);
        source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
            json!([]);
        let fixture =
            client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
        let draft = start(&fixture, "audit-gate-value-canary", "audit-gate-start").await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(&draft, "submit", json!({}), &key("audit-gate-submit"))
            .unwrap();
        let submitted = fixture
            .http
            .client
            .execute_proposal(&submit)
            .await
            .unwrap()
            .value;
        let before = fixture.audit_capture.entries().len();
        fixture.audit_capture.fail_after(accepted);
        let response = reqwest::get(format!(
            "{}/v1/proposals/{}/{suffix}?accessProfile=clerk",
            fixture.http.base_url,
            submitted.id()
        ))
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{suffix}, {accepted} accepted appends"
        );
        assert!(response.headers().get("etag").is_none());
        assert!(!response
            .text()
            .await
            .unwrap()
            .contains("audit-gate-value-canary"));
        let entries = fixture.audit_capture.entries();
        assert_eq!(entries.len(), before + accepted);
        if accepted == 1 {
            assert_eq!(entries[before]["phase"], "request");
            assert_eq!(entries[before]["record"]["phase"], "attempt");
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn proposal_list_pages_valid_large_inputs_without_losing_later_proposals() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"memo","type":"text","required":true,
            "maximumLength":320_000,"classification":"internal"}));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] = json!(["memo"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    // JSON encoding makes this legal text input nearly 2 MiB on the wire.
    let large_value = "\u{0001}".repeat(320_000);
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("large-list-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let mut created = BTreeSet::new();
    for index in 0..4 {
        let input = BRegActionInvocationRequest::new(
            &action,
            map(json!({"target":record.value.data.record_identifier,
                "value":"After","memo":large_value})),
            None,
        )
        .unwrap();
        let draft = client
            .start_proposal(&action, &input, &key(&format!("large-list-{index}")))
            .await
            .unwrap()
            .value;
        created.insert(draft.id().to_owned());
    }
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let mut seen = BTreeSet::new();
    let mut sizes = Vec::new();
    let mut cursor = None;
    loop {
        let page = client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    cursor,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .value;
        assert!(serde_json::to_vec(&page).unwrap().len() < 8 * 1024 * 1024);
        sizes.push(page.items.len());
        for item in page.items {
            assert_eq!(
                item.input().unwrap()["memo"].as_str(),
                Some(large_value.as_str())
            );
            assert!(seen.insert(item.id().to_owned()));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(sizes.len() < 4, "pagination must make progress");
    }
    assert_eq!(sizes, [2, 2]);
    assert_eq!(seen, created);
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_pages_by_limit_and_refuses_top_naming_limit() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("limit-list-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    for index in 0..2 {
        let input = BRegActionInvocationRequest::new(
            &action,
            map(json!({"target":record.value.data.record_identifier,"value":"After"})),
            None,
        )
        .unwrap();
        client
            .start_proposal(&action, &input, &key(&format!("limit-list-{index}")))
            .await
            .unwrap();
    }
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = client
        .list_proposals(
            &collection,
            &BRegProposalQuery {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .value;
    assert_eq!(page.items.len(), 1);
    assert!(page.next_cursor.is_some());
    let response = reqwest::get(format!(
        "{}/v1/proposals?accessProfile=clerk&top=1",
        fixture.http.base_url
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let problem: Value = response.json().await.unwrap();
    assert_eq!(problem["code"], "query.invalid", "{problem}");
    assert!(
        problem["detail"].as_str().unwrap().contains("`limit`"),
        "{problem}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn proposal_list_audit_counts_only_each_actions_returned_items() {
    let mut source = registry_source(false);
    for id in ["correct-alternate", "correct-empty"] {
        let mut action = source["actions"][0].clone();
        action["id"] = json!(id);
        source["actions"].as_array_mut().unwrap().push(action);
        for permission in ["actions", "proposals"] {
            let mut grant = source["accessProfiles"][0]["permissions"][permission][0].clone();
            grant["action"] = json!(id);
            source["accessProfiles"][0]["permissions"][permission]
                .as_array_mut()
                .unwrap()
                .push(grant);
        }
    }
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    start(&fixture, "First", "audit-list-first").await;
    start(&fixture, "Second", "audit-list-second").await;
    start_action(&fixture, "correct-alternate", "Other", "audit-list-other").await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    for (action, expected) in [
        (None, [2usize, 1, 0]),
        (Some("correct-name"), [2, 0, 0]),
        (Some("correct-empty"), [0, 0, 0]),
    ] {
        let before = fixture.audit_capture.entries().len();
        let page = client
            .list_proposals(
                &collection,
                &BRegProposalQuery {
                    action: action.map(str::to_owned),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.value.items.len(), expected.iter().sum::<usize>());
        let entries = fixture.audit_capture.entries();
        let terminal = entries[before..]
            .iter()
            .filter_map(|entry| {
                let record = &entry["record"];
                (record["phase"] == "terminal"
                    && record["operationId"]
                        .as_str()
                        .is_some_and(|id| id.ends_with(".list")))
                .then_some(record)
            })
            .collect::<Vec<_>>();
        assert_eq!(terminal.len(), 3);
        for (id, count) in ["correct-name", "correct-alternate", "correct-empty"]
            .into_iter()
            .zip(expected)
        {
            let record = terminal
                .iter()
                .find(|record| record["actionId"] == id)
                .unwrap();
            assert_eq!(record["resultCount"], count, "{action:?}/{id}");
            assert_eq!(
                record["outcome"],
                if count == 0 { "empty" } else { "returned" }
            );
        }
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn manual_no_review_attachments_cas_concealment_and_exact_receipt() {
    let fixture = client_http::ClientFixture::start(
        registry(false),
        claims("private-author-canary", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "After", "manual-start").await;
    assert_eq!(draft.state(), BRegProposalState::Draft);
    assert!(serde_json::to_value(&draft).unwrap().get("input").is_none());
    let uploaded = client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"synthetic-support",
            &key("manual-upload"),
        )
        .await
        .unwrap()
        .value;
    assert!(uploaded.revision() > draft.revision());
    assert_eq!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"synthetic-support"
    );
    let stale = client
        .prepare_proposal(&draft, "submit", json!({}), &key("manual-stale"))
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&stale)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let submit = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("manual-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    assert!(
        !submitted
            .link("retry")
            .unwrap()
            .availability()
            .unwrap()
            .available,
        "a manual no-review submission has no queued work to retry"
    );
    let provenance = fixture
        .database
        .admin
        .query_one(
            "SELECT submission.snapshot ->> 'originatingPackage', state.active_activation_id::text
         FROM registry_internal.registry_proposal_submissions AS submission
         CROSS JOIN registry_internal.registry_state AS state
         WHERE submission.proposal_id = $1 AND state.singleton",
            &[&uuid::Uuid::parse_str(submitted.id()).unwrap()],
        )
        .await
        .expect("native frozen submission retains its current activation provenance");
    let origin: String = provenance.get(0);
    assert_eq!(origin, provenance.get::<_, String>(1));
    assert!(!uuid::Uuid::parse_str(&origin).unwrap().is_nil());
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":submitted.submission_version(),
        "effectDigest":submitted.effect_digest().unwrap(),"reason":"proposal-reason-canary"}),
            &key("manual-apply"),
        )
        .unwrap();
    let first = client.execute_proposal(&apply).await.unwrap();
    let replay = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(
        serde_json::to_value(&first.value).unwrap(),
        serde_json::to_value(&replay.value).unwrap()
    );
    assert_eq!(first.value.state(), BRegProposalState::Applied);
    let public = serde_json::to_value(&first.value).unwrap();
    let serialized = serde_json::to_string(&public).unwrap();
    assert!(!serialized.contains("private-author-canary"));
    assert!(!serialized.contains("proposal-reason-canary"));
    for hidden in [
        "appliedBy",
        "appliedAt",
        "reason",
        "reasonPresent",
        "acceptedBinding",
        "result",
    ] {
        assert!(
            public["application"].get(hidden).is_none(),
            "internal application field {hidden}"
        );
    }
    let reason = fixture
        .database
        .admin
        .query_one(
            "SELECT reason FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(reason.get::<_, String>(0), "proposal-reason-canary");
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 1);
    let review_rows = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(review_rows.get::<_, i64>(0), 0);
    let observer = fixture.client_for(claims("other-author", "zone-a")).await;
    let hidden = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = hidden.value.select_proposals("clerk").unwrap();
    let page = observer
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert!(page.value.items.is_empty());
    drop(observer);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_binding_integrity_and_detail_erasure_preserve_record_history() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Retained record", "erase-start").await;
    let bytes = b"synthetic-support";
    let uploaded = client
        .upload_proposal_attachment(&draft, "support", "text/plain", bytes, &key("erase-upload"))
        .await
        .unwrap()
        .value;
    let mut corrupt = bytes.to_vec();
    corrupt[0] = b'X';
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET content=$1",
            &[&corrupt],
        )
        .await
        .unwrap();
    assert!(client
        .download_proposal_attachment(&uploaded, "support")
        .await
        .is_err());
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_attachment_blobs SET content=$1",
            &[&bytes.to_vec()],
        )
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_storage_binding SET verification_policy='different-policy'",&[]).await.unwrap();
    assert!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .is_err(),
        "a changed verification binding cannot release bytes"
    );
    let wrong = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("erase-wrong-binding"))
        .unwrap();
    assert!(client.execute_proposal(&wrong).await.is_err());
    fixture.database.admin.execute("UPDATE registry_internal.registry_attachment_storage_binding SET verification_policy='disabled'",&[]).await.unwrap();
    assert_eq!(
        client
            .download_proposal_attachment(&uploaded, "support")
            .await
            .unwrap()
            .value
            .as_bytes(),
        bytes
    );
    let submit = client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("erase-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap(),
        "reason":"erasure-reason-canary"}),
            &key("erase-apply"),
        )
        .unwrap();
    let applied = client.execute_proposal(&apply).await.unwrap().value;
    let before = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(before, 2);
    let (mut migration, task) = fixture.database.connect_migration().await;
    let erasure = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        registry_breg::proposal_retention::ProposalDetailErasureScope {
            action_id: "correct-name",
            proposal_id: uuid::Uuid::parse_str(applied.id()).unwrap(),
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(erasure.proposal_snapshots, 1);
    assert_eq!(erasure.attachment_references, 1);
    drop(migration);
    task.abort();
    assert!(
        client.execute_proposal(&apply).await.is_err(),
        "erased exact receipts retain spent-key refusal"
    );
    assert!(client
        .download_proposal_attachment(&applied, "support")
        .await
        .is_err());
    let current = client.read_proposal(&applied).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Applied);
    assert!(current.application().is_none());
    let row=fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_revisions),
        (SELECT count(*) FROM registry_internal.registry_attachment_blobs),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications WHERE reason IS NOT NULL)",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), before);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    fixture.finish().await;
}

/// Cancel closes the queued automatic application job in its own
/// transaction, so no inert queued work outlives the Proposal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_closes_the_queued_automatic_application_job() {
    let fixture = client_http::ClientFixture::start(
        compile(registry_source(true)),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Cancelled", "cancel-job-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("cancel-job-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let job_state = || async {
        fixture
            .database
            .admin
            .query_one(
                "SELECT state FROM registry_internal.registry_proposal_application_jobs",
                &[],
            )
            .await
            .unwrap()
            .get::<_, String>(0)
    };
    assert_eq!(job_state().await, "queued");
    let cancel = client
        .prepare_proposal(&submitted, "cancel", json!({}), &key("cancel-job-cancel"))
        .unwrap();
    let cancelled = client.execute_proposal(&cancel).await.unwrap().value;
    assert_eq!(cancelled.state(), BRegProposalState::Cancelled);
    assert_eq!(job_state().await, "cancelled");
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(job_state().await, "cancelled");
    fixture.finish().await;
}

/// Revise closes the superseded version's queued automatic application job,
/// which the worker could otherwise never claim again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revise_closes_the_superseded_versions_queued_automatic_application_job() {
    let fixture = client_http::ClientFixture::start(
        compile(registry_source(true)),
        claims("author", "zone-a"),
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Revised", "revise-job-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("revise-job-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let job_states = || async {
        fixture
            .database
            .admin
            .query(
                "SELECT submission_version, state
                 FROM registry_internal.registry_proposal_application_jobs
                 ORDER BY submission_version",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>()
    };
    assert_eq!(job_states().await, [(1, "queued".to_owned())]);
    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("revise-job-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(revised.state(), BRegProposalState::Draft);
    assert_eq!(job_states().await, [(1, "cancelled".to_owned())]);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_automatic_uses_current_builtin_grant_and_one_atomic_receipt() {
    let mut source = registry_source(true);
    source["actions"][0]["execution"]["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("application");
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Automatic", "automatic-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("automatic-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert_eq!(submitted.state(), BRegProposalState::Submitted);
    let pending = serde_json::to_value(&submitted).unwrap();
    assert_eq!(
        pending["applicationStatus"],
        json!({"state":"pending","mode":"automatic","automaticRetry":{"scheduled":true,"attempts":0,"maximumAttempts":3}})
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=transaction_timestamp()-interval '1 minute'",&[]).await.unwrap();
    assert!(application_queue_age(&fixture).await >= 60.0);
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let current = fixture
        .http
        .client
        .read_proposal(&submitted)
        .await
        .unwrap()
        .value;
    assert_eq!(current.state(), BRegProposalState::Applied);
    let applied = serde_json::to_value(&current).unwrap();
    assert_eq!(
        applied["applicationStatus"],
        json!({"state":"applied","mode":"automatic"})
    );
    assert_eq!(
        applied["application"]["submissionVersion"],
        pending["submissionVersion"]
    );
    assert_eq!(
        applied["application"]["effectDigest"],
        pending["effectDigest"]
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,maximum_attempts,executor,application_id IS NOT NULL
        FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, i32>(2), 3);
    assert_eq!(row.get::<_, String>(3), "builtin");
    assert!(row.get::<_, bool>(4));
    assert_eq!(application_queue_age(&fixture).await, 0.0);
    fixture.finish().await;
}

// Observe an actual row-lock wait, rather than guessing when the writer has
// reached the lifecycle boundary. Row locks wait on the owning transaction;
// its granted relation lock identifies the reader holding the Proposal row.
async fn proposal_lifecycle_writer_waits(admin: &tokio_postgres::Client, pid: Option<i32>) {
    loop {
        let waiting: bool = admin
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity writer
                    JOIN pg_locks pending ON pending.pid=writer.pid AND NOT pending.granted
                    WHERE writer.datname=current_database()
                      AND ($1::integer IS NULL OR writer.pid=$1)
                      AND writer.query LIKE '%registry_proposal_state%'
                      AND EXISTS (
                          SELECT 1 FROM pg_locks reader
                          WHERE reader.pid=ANY(pg_blocking_pids(writer.pid))
                            AND reader.relation='registry_internal.registry_proposal_state'::regclass
                            AND reader.mode='RowShareLock' AND reader.granted
                      )
                )",
                &[&pid],
            )
            .await
            .unwrap()
            .get(0);
        if waiting {
            return;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_get_remains_coherent_while_automatic_application_commits() {
    use registry_breg_client::BRegProposalApplicationState;
    use std::sync::Arc;
    use std::time::Duration;

    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let draft = start(&fixture, "Concurrent automatic", "observation-auto-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("observation-auto-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let loaded = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let observer = fixture
        .client_with_mutations(
            claims("author", "zone-a"),
            (*fixture.mutations)
                .clone()
                .with_proposal_read_barrier_for_test(loaded.clone(), resume.clone()),
        )
        .await;
    let metadata = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let (observation, (progress, application)) = tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.client.get_proposal(&get, submitted.id()),
            )
            .await
        },
        async {
            tokio::time::timeout(Duration::from_secs(1), loaded.notified())
                .await
                .expect("ordinary HTTP Get loaded its lifecycle header");
            let application = fixture.mutations.run_automatic_proposal_once_for_test();
            tokio::pin!(application);
            // Without the shared lifecycle lock, the worker commits here and
            // the one resumed Get deterministically composes Submitted with
            // an Applied job. Do not hide that refusal behind a retry.
            let progress = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut application => Some(result),
                    () = proposal_lifecycle_writer_waits(&fixture.database.admin, None) => None,
                }
            })
            .await;
            resume.notify_one();
            match progress {
                Ok(Some(result)) => (Ok(true), result),
                other => (
                    other.map(|_| false),
                    tokio::time::timeout(Duration::from_secs(3), application)
                        .await
                        .expect("automatic application completes after Get releases its row lock"),
                ),
            }
        }
    );
    let current = fixture.http.client.read_proposal(&submitted).await;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,application_id,
                    (SELECT count(*) FROM registry_internal.registry_proposal_applications)
               FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    let idle = fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await;
    drop(observer);
    fixture.finish().await;

    let observed = observation
        .expect("ordinary Get finishes within its deadline")
        .expect("an unchanged authorized caller must not receive a transient 404")
        .value;
    assert!(progress.is_ok(), "worker reached its lifecycle boundary");
    assert!(
        !progress.unwrap(),
        "Get holds the lifecycle lock until projection finishes"
    );
    assert!(application.unwrap());
    assert_eq!(observed.state(), BRegProposalState::Submitted);
    assert_eq!(observed.revision(), submitted.revision());
    assert_eq!(
        observed.submission_version(),
        submitted.submission_version()
    );
    assert_eq!(observed.effect_digest(), submitted.effect_digest());
    assert_eq!(
        observed.application_status().unwrap().state,
        BRegProposalApplicationState::Applying
    );
    assert!(observed.application().is_none());
    let applied = current.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(applied.submission_version(), submitted.submission_version());
    assert_eq!(applied.effect_digest(), submitted.effect_digest());
    assert_eq!(
        applied.application_status().unwrap().state,
        BRegProposalApplicationState::Applied
    );
    let receipt = applied.application().unwrap();
    assert_eq!(receipt.submission_version, submitted.submission_version());
    assert_eq!(
        Some(receipt.effect_digest.as_str()),
        submitted.effect_digest()
    );
    assert_eq!(
        receipt.application_id,
        row.get::<_, uuid::Uuid>(2).to_string()
    );
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, i64>(3), 1);
    assert!(
        !idle.unwrap(),
        "one frozen submission is applied exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_lease_expiring_during_a_write_rolls_back_and_recovers_within_its_budget() {
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(true),
        claims("author", "zone-a"),
        |mutations| {
            mutations
                .with_action_timeout_for_test(std::time::Duration::from_secs(2))
                .with_automatic_proposal_lease_for_test(std::time::Duration::from_millis(400))
        },
    )
    .await;
    let draft = start(&fixture, "Lease fenced", "lease-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("lease-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let table = &fixture.registry.entities()["target"].physical_table;
    // The sequence is deliberately nontransactional: it proves the write
    // trigger ran, even when the expired-lease transaction rolls back.
    fixture.database.admin.batch_execute(&format!("CREATE SEQUENCE registry_data.lease_probe;
        GRANT USAGE,SELECT ON SEQUENCE registry_data.lease_probe TO \"{}\";
        CREATE FUNCTION registry_data.expire_during_write() RETURNS trigger LANGUAGE plpgsql AS $body$
        BEGIN PERFORM nextval('registry_data.lease_probe'); PERFORM pg_sleep(0.65); RETURN NEW; END $body$;
        CREATE TRIGGER expire_lease BEFORE UPDATE ON registry_data.\"{}\" FOR EACH ROW EXECUTE FUNCTION registry_data.expire_during_write()",
        fixture.database.runtime_role.as_str(),table)).await.unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row = fixture
        .database
        .admin
        .query_one("SELECT is_called FROM registry_data.lease_probe", &[])
        .await
        .unwrap();
    assert!(
        row.get::<_, bool>(0),
        "the final fence is exercised after write execution began"
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state,attempt_count,last_error_code,
        (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_revisions)
        FROM registry_internal.registry_proposal_application_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(row.get::<_, String>(2), "lease-expired");
    assert_eq!(row.get::<_, i64>(3), 0);
    assert_eq!(row.get::<_, i64>(4), 1);
    assert_eq!(
        fixture
            .http
            .client
            .read_proposal(&submitted)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Submitted
    );
    fixture
        .database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER expire_lease ON registry_data.\"{}\"",
            table
        ))
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=clock_timestamp()",&[]).await.unwrap();
    // Only the first attempt deliberately expires inside its write. Recovery
    // retains the two-second action deadline, with lease headroom so ordinary
    // CI contention cannot turn this success check into a second expiry probe.
    let recovery_worker = fixture
        .mutations
        .as_ref()
        .clone()
        .with_automatic_proposal_lease_for_test(std::time::Duration::from_secs(5));
    assert!(recovery_worker
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let row=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications),last_error_code
        FROM registry_internal.registry_proposal_application_jobs",&[]).await.unwrap();
    assert_eq!(
        row.get::<_, String>(0),
        "applied",
        "recovery error: {:?}",
        row.get::<_, Option<String>>(3)
    );
    assert_eq!(row.get::<_, i32>(1), 2);
    assert_eq!(row.get::<_, i64>(2), 1);
    fixture.finish().await;
}

struct NoToken;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for NoToken {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        Err(registry_platform_httputil::TokenError::Unavailable)
    }
}
fn local_review_binding() -> std::sync::Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = std::sync::Arc::new(
        ReviewAuthorityClient::new(
            "local-review".into(),
            client,
            std::sync::Arc::new(NoToken),
            "producer".into(),
            "proposal-producer".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    std::sync::Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("local-review".into(), authority)])).unwrap(),
    )
}
struct LocalReview {
    calls: std::sync::atomic::AtomicUsize,
    mode: std::sync::atomic::AtomicUsize,
    result_id: uuid::Uuid,
}
impl LocalReview {
    fn result(
        &self,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> registry_review_client::ReviewResult {
        let now = chrono::Utc::now();
        let mode = self.mode.load(std::sync::atomic::Ordering::SeqCst);
        let mut result = registry_review_client::ReviewResult {
            result_id: self.result_id,
            request_id: accepted.request_id,
            subject: accepted.subject.clone(),
            policy: accepted.policy.clone(),
            submission_digest: accepted.submission_digest.clone(),
            status: registry_review_client::ReviewResultStatus::Approved,
            outcome: Some("approved".to_owned()),
            public_reason: None,
            result: None,
            completed_at: now - chrono::Duration::seconds(2),
            available_until: now + chrono::Duration::minutes(5),
        };
        if mode == 1 {
            result.policy.version = "different-policy".into();
        }
        if mode == 2 {
            result.available_until = now - chrono::Duration::seconds(1);
        }
        result
    }
}
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for LocalReview {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.mode.load(std::sync::atomic::Ordering::SeqCst) == 3 {
            return Err(registry_breg::mutation::MutationError::Unavailable);
        }
        registry_breg::review_integration::AcceptedReviewEvidence::from_protocol(
            authority,
            accepted,
            &self.result(accepted),
        )
        .map_err(|_| registry_breg::mutation::MutationError::PreconditionFailed)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_get_excludes_review_result_and_job_publication_until_observation_finishes() {
    use registry_breg_client::BRegProposalApplicationState;
    use std::sync::Arc;
    use std::time::Duration;

    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let draft = start(&fixture, "Concurrent approval", "observation-review-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            &draft,
            "submit",
            json!({}),
            &key("observation-review-submit"),
        )
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT create_request,expected_submission_digest,
                    (SELECT snapshot FROM registry_internal.registry_proposal_submissions)
               FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    let frozen: Value = row.get(2);
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute(
        "UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()],
    ).await.unwrap();
    let result = review.result(&accepted);
    let loaded = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let observer = fixture
        .client_with_mutations(
            claims("author", "zone-a"),
            (*fixture.mutations)
                .clone()
                .with_proposal_read_barrier_for_test(loaded.clone(), resume.clone()),
        )
        .await;
    let metadata = observer
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("clerk").unwrap();
    let (mut migration, connection) = fixture.database.connect_migration().await;
    let writer_pid: i32 = migration
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let (observation, (progress, before_release, reconciled)) = tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(5),
                observer.client.get_proposal(&get, submitted.id()),
            )
            .await
        },
        async {
            tokio::time::timeout(Duration::from_secs(1), loaded.notified())
                .await
                .expect("ordinary HTTP Get loaded its lifecycle header");
            let reconcile = async {
                let tx = migration.transaction().await.unwrap();
                registry_breg::review_store::reconcile_result(
                    &tx,
                    "local-review",
                    &accepted,
                    &result,
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|_| registry_breg::mutation::MutationError::Unavailable)
            };
            tokio::pin!(reconcile);
            // This proves writer exclusion at the lifecycle boundary. The
            // barrier is before projection, so it does not itself force the
            // narrower job-None then approved-result statement interleaving.
            let progress = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::select! {
                    result = &mut reconcile => Some(result),
                    () = proposal_lifecycle_writer_waits(&fixture.database.admin, Some(writer_pid)) => None,
                }
            })
            .await;
            let before_release = fixture
                .database
                .admin
                .query_one(
                    "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_results),
                            (SELECT count(*) FROM registry_internal.registry_proposal_application_jobs)",
                    &[],
                )
                .await
                .unwrap();
            resume.notify_one();
            let (progress, reconciled) = match progress {
                Ok(Some(result)) => (Ok(true), result),
                other => (
                    other.map(|_| false),
                    tokio::time::timeout(Duration::from_secs(3), reconcile)
                        .await
                        .expect(
                            "review publication finishes after the reader releases its row lock",
                        ),
                ),
            };
            (progress, before_release, reconciled)
        }
    );
    drop(migration);
    connection.abort();
    let current = fixture.http.client.read_proposal(&submitted).await;
    let published = fixture
        .database
        .admin
        .query_one(
            "SELECT r.result_id,r.result,r.status,j.result_id,j.proposal_digest,
                    j.submission_version,j.system_grant_revision,s.snapshot,
                    (SELECT count(*) FROM registry_internal.registry_proposal_review_results),
                    (SELECT count(*) FROM registry_internal.registry_proposal_application_jobs)
               FROM registry_internal.registry_proposal_review_results r
               JOIN registry_internal.registry_proposal_application_jobs j
                 USING(action_id,proposal_id,submission_version)
               JOIN registry_internal.registry_proposal_submissions s
                 USING(action_id,proposal_id,submission_version)",
            &[],
        )
        .await;
    drop(observer);
    fixture.finish().await;

    assert!(
        progress.is_ok(),
        "reconciler reached its lifecycle boundary"
    );
    assert!(
        !progress.unwrap(),
        "the no-job observer excludes review publication"
    );
    assert_eq!(before_release.get::<_, i64>(0), 0);
    assert_eq!(before_release.get::<_, i64>(1), 0);
    reconciled.unwrap();
    let observed = observation
        .expect("ordinary Get finishes within its deadline")
        .expect("an unchanged authorized caller can observe the pending review")
        .value;
    assert_eq!(observed.state(), BRegProposalState::Submitted);
    assert_eq!(observed.revision(), submitted.revision());
    assert_eq!(
        observed.submission_version(),
        submitted.submission_version()
    );
    assert_eq!(observed.effect_digest(), submitted.effect_digest());
    let status = observed.application_status().unwrap();
    assert_eq!(status.state, BRegProposalApplicationState::AwaitingReview);
    assert!(!status.automatic_retry.as_ref().unwrap().scheduled);
    let current = current.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Submitted);
    assert_eq!(current.revision(), submitted.revision());
    assert_eq!(current.submission_version(), submitted.submission_version());
    assert_eq!(current.effect_digest(), submitted.effect_digest());
    let status = current.application_status().unwrap();
    assert_eq!(status.state, BRegProposalApplicationState::Pending);
    assert!(status.automatic_retry.as_ref().unwrap().scheduled);
    assert!(current.application().is_none());
    let published = published.expect("approval and its application job are published together");
    assert_eq!(published.get::<_, uuid::Uuid>(0), result.result_id);
    assert_eq!(
        published.get::<_, Value>(1),
        serde_json::to_value(&result).unwrap()
    );
    assert_eq!(published.get::<_, String>(2), "approved");
    assert_eq!(published.get::<_, uuid::Uuid>(3), result.result_id);
    assert_eq!(
        Some(published.get::<_, String>(4).as_str()),
        submitted.effect_digest()
    );
    assert_eq!(
        published.get::<_, i64>(5),
        i64::from(submitted.submission_version())
    );
    assert_eq!(
        published.get::<_, String>(6),
        frozen["systemGrantRevision"].as_str().unwrap()
    );
    assert_eq!(published.get::<_, Value>(7), frozen);
    assert_eq!(published.get::<_, i64>(8), 1);
    assert_eq!(published.get::<_, i64>(9), 1);
    assert_eq!(review.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_apply_requires_fresh_exact_approval_and_receipt_recovery_is_local() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reviewed", "review-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("review-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let expected =
        registry_review_client::submission_digest("proposal-producer", "proposal-test", &create)
            .unwrap();
    assert_eq!(expected.as_str(), row.get::<_, String>(1));
    assert_eq!(create.subject.id, submitted.id());
    assert_eq!(
        create.subject.digest.as_str(),
        submitted.effect_digest().unwrap()
    );
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: expected,
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    registry_breg::review_store::verify_retained_bindings(&fixture.pool, &fixture.registry, None)
        .await
        .unwrap();
    registry_breg::review_store::verify_retained_bindings(
        &fixture.pool,
        &fixture.registry,
        Some(local_review_binding().as_ref()),
    )
    .await
    .unwrap();
    let result = review.result(&accepted);
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1,1,'local-review',$2,$3,'approved',$4,$5)",
        &[&uuid::Uuid::parse_str(submitted.id()).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();
    let current = client.read_proposal(&submitted).await.unwrap().value;
    review.mode.store(1, std::sync::atomic::Ordering::SeqCst);
    let wrong = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-wrong-policy"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&wrong)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    review.mode.store(2, std::sync::atomic::Ordering::SeqCst);
    let expired = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-expired"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&expired)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    review.mode.store(0, std::sync::atomic::Ordering::SeqCst);
    let apply = client
        .prepare_proposal(
            &current,
            "apply",
            json!({"submissionVersion":1,"effectDigest":current.effect_digest().unwrap()}),
            &key("review-valid"),
        )
        .unwrap();
    let applied = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(applied.value.state(), BRegProposalState::Applied);
    let calls = review.calls.load(std::sync::atomic::Ordering::SeqCst);
    review.mode.store(3, std::sync::atomic::Ordering::SeqCst);
    let recovered = client.execute_proposal(&apply).await.unwrap();
    assert_eq!(
        serde_json::to_value(applied.value).unwrap(),
        serde_json::to_value(recovered.value).unwrap()
    );
    assert_eq!(
        review.calls.load(std::sync::atomic::Ordering::SeqCst),
        calls
    );
    fixture.finish().await;
}

/// applicationStatus reports application progress only. A review outcome
/// reaches the caller through Apply availability, never as an application
/// refusal, in either application mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_outcomes_read_as_apply_availability_not_application_status() {
    for automatic in [false, true] {
        let mut source = registry_source(automatic);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
        let review = std::sync::Arc::new(LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        });
        let injected = review.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await;
        let client = &fixture.http.client;
        let draft = start(&fixture, "Reviewed", &format!("outcome-{automatic}-start")).await;
        let submit = client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("outcome-{automatic}-submit")),
            )
            .unwrap();
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
        let create: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(row.get(0)).unwrap();
        let accepted = registry_review_client::ReviewRequestAccepted {
            request_id: uuid::Uuid::new_v4(),
            subject: create.subject,
            policy: serde_json::from_value(policy).unwrap(),
            submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
        };
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
            &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
        let observe = || async {
            let current =
                serde_json::to_value(client.read_proposal(&submitted).await.unwrap().value)
                    .unwrap();
            (
                current["applicationStatus"].clone(),
                current["links"]["apply"]["availability"].clone(),
                current["links"]["revise"]["availability"]["available"].clone(),
            )
        };
        let (status, apply, _) = observe().await;
        assert_eq!(status["state"], "awaiting-review");
        assert!(status.get("reason").is_none() && status.get("recovery").is_none());
        assert_eq!(apply["reason"], "pending-review");
        assert_eq!(apply["recovery"], "refresh");
        let result = review.result(&accepted);
        fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
            (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
            VALUES ('correct-name',$1,1,'local-review',$2,$3,'rejected',$4,$5)",
            &[&uuid::Uuid::parse_str(submitted.id()).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();
        for (outcome, reason, recovery) in [
            ("rejected", "review-rejected", "revise"),
            ("changes-requested", "review-changes-requested", "revise"),
            ("cancelled", "review-ended", "revise"),
            ("superseded", "review-ended", "revise"),
            ("answered", "pending-review", "refresh"),
        ] {
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_results SET status=$1",
                    &[&outcome],
                )
                .await
                .unwrap();
            let (status, apply, revise) = observe().await;
            assert_eq!(status["state"], "awaiting-review", "{outcome}");
            assert!(
                status.get("reason").is_none() && status.get("recovery").is_none(),
                "{outcome} is a review outcome, not an application refusal"
            );
            assert_eq!(
                status["mode"],
                if automatic { "automatic" } else { "manual" }
            );
            assert_eq!(apply["available"], false, "{outcome}");
            assert_eq!(apply["reason"], reason, "{outcome}");
            assert_eq!(apply["recovery"], recovery, "{outcome}");
            assert_eq!(revise, true, "{outcome}");
        }
        if !automatic {
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_review_results SET status='approved'",
                    &[],
                )
                .await
                .unwrap();
            let (status, apply, _) = observe().await;
            assert_eq!(status["state"], "pending");
            assert_eq!(apply["available"], true);
        }
        fixture.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submission_read_reports_each_version_separately_and_is_gone_after_its_windows() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Historical", "history-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("history-submit-1"))
        .unwrap();
    let first = client.execute_proposal(&submit).await.unwrap().value;
    let first_digest = serde_json::to_value(&first).unwrap()["effectDigest"].clone();
    let id = first.id().to_owned();
    let read = |version: &str, profile: &str| {
        let url = format!(
            "{}/v1/proposals/{id}/submissions/{version}?accessProfile={profile}",
            fixture.http.base_url
        );
        async move {
            let response = reqwest::get(url).await.unwrap();
            let status = response.status();
            (
                status,
                response.json::<Value>().await.unwrap_or(Value::Null),
            )
        }
    };
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["id"], json!(id));
    assert_eq!(body["submissionVersion"], 1);
    assert_eq!(body["current"], true);
    assert_eq!(body["effectDigest"], first_digest);
    assert_eq!(body["review"], json!({"state":"pending"}));
    assert_eq!(body["application"]["state"], "awaiting-review");

    let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
        &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let result = review.result(&accepted);
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1,1,'local-review',$2,$3,'rejected',$4,$5)",
        &[&uuid::Uuid::parse_str(&id).unwrap(),&result.result_id,&serde_json::to_value(&result).unwrap(),&result.completed_at,&result.available_until]).await.unwrap();

    let current = client.read_proposal(&first).await.unwrap().value;
    let revise = client
        .prepare_proposal(&current, "revise", json!({}), &key("history-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    let submit = client
        .prepare_proposal(&revised, "submit", json!({}), &key("history-submit-2"))
        .unwrap();
    let second = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(second.submission_version(), 2);

    // The superseded version keeps its own review outcome and reports no
    // application progress, which belongs to the current version alone.
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["current"], false);
    assert_eq!(body["effectDigest"], first_digest);
    assert_eq!(body["review"]["state"], "rejected");
    assert_eq!(body["review"]["resultId"], json!(result.result_id));
    assert!(body["application"].is_null(), "{body}");
    let (status, body) = read("2", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["current"], true);
    assert_eq!(body["review"], json!({"state":"pending"}));
    assert_eq!(body["application"]["state"], "awaiting-review");

    // A version never submitted, a malformed version and a profile without
    // Get authority are all concealed alike.
    for (version, profile) in [
        ("3", "clerk"),
        ("0", "clerk"),
        ("01", "clerk"),
        ("1", "missing"),
    ] {
        let (status, _) = read(version, profile).await;
        assert_eq!(
            status,
            reqwest::StatusCode::NOT_FOUND,
            "{version} {profile}"
        );
    }

    // Once the superseded version's result window lapses it retains nothing
    // to report, and the read says so instead of concealing the version.
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results
             SET completed_at=transaction_timestamp()-interval '2 minutes',
                 available_until=transaction_timestamp()-interval '1 minute'
             WHERE submission_version=1",
            &[],
        )
        .await
        .unwrap();
    let (status, body) = read("1", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::GONE);
    assert_eq!(body["code"], "proposal.submission_expired");
    let (status, _) = read("2", "clerk").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submission_read_reports_the_application_receipt_without_the_applier() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Receipt", "receipt-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("receipt-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let body = json!({"submissionVersion":submitted.submission_version(),"effectDigest":submitted.effect_digest().unwrap()});
    let apply = client
        .prepare_proposal(&submitted, "apply", body, &key("receipt-apply"))
        .unwrap();
    let applied =
        serde_json::to_value(client.execute_proposal(&apply).await.unwrap().value).unwrap();
    let response = reqwest::get(format!(
        "{}/v1/proposals/{}/submissions/1?accessProfile=clerk",
        fixture.http.base_url,
        submitted.id()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let read = response.json::<Value>().await.unwrap();
    assert_eq!(read["current"], true);
    assert!(read["review"].is_null(), "{read}");
    assert_eq!(read["application"]["state"], "applied");
    assert_eq!(
        read["application"]["applicationId"],
        applied["application"]["applicationId"]
    );
    // Who applied and when stay private to the receipt (D24): no profile is
    // granted them by default.
    for hidden in ["appliedAt", "appliedBy", "author"] {
        assert!(!read.to_string().contains(hidden), "{read}");
    }
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_review_automatic_requires_fresh_exact_approval_even_with_a_cached_result() {
    for mode in [1, 2, 3, 0] {
        let mut source = registry_source(true);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
        let review = std::sync::Arc::new(LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        });
        let injected = review.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source),
            claims("author", "zone-a"),
            move |mutations| {
                mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
            },
        )
        .await;
        let draft = start(
            &fixture,
            "Reviewed automatic",
            &format!("review-auto-{mode}-start"),
        )
        .await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(
                &draft,
                "submit",
                json!({}),
                &key(&format!("review-auto-{mode}-submit")),
            )
            .unwrap();
        let submitted = fixture
            .http
            .client
            .execute_proposal(&submit)
            .await
            .unwrap()
            .value;
        let row=fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
        let create: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(row.get(0)).unwrap();
        let accepted = registry_review_client::ReviewRequestAccepted {
            request_id: uuid::Uuid::new_v4(),
            subject: create.subject,
            policy: serde_json::from_value(policy).unwrap(),
            submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
        };
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",
            &[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
        let (mut migration, task) = fixture.database.connect_migration().await;
        let tx = migration.transaction().await.unwrap();
        registry_breg::review_store::reconcile_result(
            &tx,
            "local-review",
            &accepted,
            &review.result(&accepted),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        drop(migration);
        task.abort();
        review.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap());
        assert_eq!(
            review.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an uncommitted attempt fetches fresh authority evidence"
        );
        let current = fixture
            .http
            .client
            .read_proposal(&submitted)
            .await
            .unwrap()
            .value;
        let row=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_application_jobs",&[]).await.unwrap();
        if mode == 0 {
            assert_eq!(current.state(), BRegProposalState::Applied);
            assert_eq!(row.get::<_, String>(0), "applied");
            assert_eq!(row.get::<_, i64>(2), 1);
            assert!(!fixture
                .mutations
                .run_automatic_proposal_once_for_test()
                .await
                .unwrap());
            assert_eq!(review.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        } else {
            assert_eq!(current.state(), BRegProposalState::Submitted);
            assert_eq!(
                row.get::<_, i64>(2),
                0,
                "cached approval cannot substitute for current authenticated evidence"
            );
            assert_eq!(
                row.get::<_, String>(0),
                if mode == 3 { "queued" } else { "blocked" }
            );
        }
        assert_eq!(row.get::<_, i32>(1), 1);
        fixture.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_inputs_require_an_explicit_selected_profile_allowlist() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"][0]["apiName"] = json!("accountRef");
    let mut reader = source["accessProfiles"][0].clone();
    reader["id"] = json!("input-reader");
    reader["default"] = json!(false);
    reader["permissions"]["actions"] = json!([]);
    reader["permissions"]["records"] = json!([]);
    reader["permissions"]["proposals"][0]["operations"] = json!(["get", "list"]);
    reader["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    reader["permissions"]["proposals"][0]["readableInputs"] = json!(["target"]);
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(reader);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let target = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("input-record"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap()
        .value
        .data
        .record_identifier;
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"accountRef":target,"value":"input-secret-canary"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("input-start"))
        .await
        .unwrap()
        .value;
    assert!(serde_json::to_value(&draft).unwrap().get("input").is_none());
    let metadata = client
        .registry_contract(Some("input-reader"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("input-reader").unwrap();
    let page = client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert_eq!(page.value.items.len(), 1);
    let value = serde_json::to_value(&page.value.items[0]).unwrap();
    assert_eq!(value["input"], json!({"accountRef":target}));
    assert!(!serde_json::to_string(&value)
        .unwrap()
        .contains("input-secret-canary"));
    fixture.finish().await;
}

// Pause only the first external observation, after its durable claim commits.
// The successor observes the same approval without sharing the fixture barrier.
struct PausedReview {
    review: LocalReview,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    observations: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl registry_breg::review_store::ReviewResultSource for PausedReview {
    async fn approved_evidence(
        &self,
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
    ) -> Result<
        registry_breg::review_integration::AcceptedReviewEvidence,
        registry_breg::mutation::MutationError,
    > {
        if self
            .observations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        registry_breg::review_store::ReviewResultSource::approved_evidence(
            &self.review,
            authority,
            accepted,
        )
        .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_automatic_worker_resumes_without_changing_successor_or_effects() {
    use std::time::Duration;
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":policy});
    let review = std::sync::Arc::new(PausedReview {
        review: LocalReview {
            calls: 0.into(),
            mode: 0.into(),
            result_id: uuid::Uuid::new_v4(),
        },
        entered: Default::default(),
        resume: Default::default(),
        observations: 0.into(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Reclaimed once", "replaced-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("replaced-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let row = fixture.database.admin.query_one("SELECT create_request,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions WHERE proposal_id=$1", &[&id]).await.unwrap();
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(row.get(0)).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: serde_json::from_value(json!(row.get::<_, String>(1))).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$2 WHERE proposal_id=$1", &[&id,&json!(accepted)]).await.unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    registry_breg::review_store::reconcile_result(
        &tx,
        "local-review",
        &accepted,
        &review.review.result(&accepted),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(migration);
    task.abort();
    let mutations = fixture.mutations.clone();
    let original =
        tokio::spawn(async move { mutations.run_automatic_proposal_once_for_test().await });
    tokio::time::timeout(Duration::from_secs(5), review.entered.notified())
        .await
        .expect("original worker reached external observation after claiming");
    let old_token: uuid::Uuid = fixture.database.admin.query_one("SELECT claim_token FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE proposal_id=$1", &[&id]).await.unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let job_sql = "SELECT to_jsonb(j) FROM registry_internal.registry_proposal_application_jobs j WHERE proposal_id=$1";
    let successor: Value = fixture
        .database
        .admin
        .query_one(job_sql, &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(successor["state"], "applied");
    assert_eq!(successor["attempt_count"], 2);
    assert!(successor["claim_token"].is_null());
    assert_ne!(successor["claim_token"], json!(old_token));
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    let receipt = serde_json::to_value(applied.application().unwrap()).unwrap();
    review.resume.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(5), original)
        .await
        .expect("replaced worker resumes")
        .unwrap()
        .unwrap());
    let after: Value = fixture
        .database
        .admin
        .query_one(job_sql, &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        after, successor,
        "stale worker cannot overwrite any successor job state"
    );
    let recovered = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(
        serde_json::to_value(recovered.application().unwrap()).unwrap(),
        receipt
    );
    let counts = fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),(SELECT count(*) FROM registry_internal.registry_revisions)",&[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1);
    assert_eq!(
        counts.get::<_, i64>(1),
        2,
        "one create and one applied revision"
    );
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn automatic_claim_pins_digest_grant_and_lease_before_any_effect() {
    let fixture =
        client_http::ClientFixture::start(registry(true), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Fenced", "fenced-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("fenced-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT proposal_digest,system_grant_revision
        FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    let digest: String = row.get(0);
    let grant: String = row.get(1);
    let wrong = format!("sha256:{}", "f".repeat(64));
    for column in ["proposal_digest", "system_grant_revision"] {
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),&[&id,&wrong]).await.unwrap();
        assert!(fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .is_err());
        let untouched=fixture.database.admin.query_one("SELECT state,attempt_count,(SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
        assert_eq!(untouched.get::<_, String>(0), "queued");
        assert_eq!(untouched.get::<_, i32>(1), 0);
        assert_eq!(untouched.get::<_, i64>(2), 0);
        fixture.database.admin.execute(&format!("UPDATE registry_internal.registry_proposal_application_jobs SET {column}=$2 WHERE proposal_id=$1"),
            &[&id,&if column=="proposal_digest"{&digest}else{&grant}]).await.unwrap();
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='blocked',attempt_count=1,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let tx = migration.transaction().await.unwrap();
    registry_breg::review_recovery::retry_application_for_test(
        &tx,
        registry_breg::review_recovery::ReviewRecoveryScope {
            action_id: "correct-name",
            proposal_id: id,
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let row=fixture.database.admin.query_one("SELECT state,attempt_count FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "queued");
    assert_eq!(
        row.get::<_, i32>(1),
        1,
        "operator recovery preserves consumed attempts"
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='blocked',attempt_count=maximum_attempts,last_error_code='dependency-outage' WHERE proposal_id=$1",&[&id]).await.unwrap();
    let tx = migration.transaction().await.unwrap();
    assert!(registry_breg::review_recovery::retry_application_for_test(
        &tx,
        registry_breg::review_recovery::ReviewRecoveryScope {
            action_id: "correct-name",
            proposal_id: id,
            submission_version: 1
        }
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    drop(migration);
    task.abort();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
        SET state='queued',attempt_count=0,last_error_code=NULL WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs
        SET state='applying',claim_token=$2,next_attempt_at=transaction_timestamp()+interval '1 minute'
        WHERE proposal_id=$1",&[&id,&uuid::Uuid::new_v4()]).await.unwrap();
    assert!(!fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
        SET next_attempt_at=transaction_timestamp()-interval '1 second' WHERE proposal_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let row=fixture.database.admin.query_one("SELECT state,attempt_count,claim_token FROM registry_internal.registry_proposal_application_jobs WHERE proposal_id=$1",&[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert!(row.get::<_, Option<uuid::Uuid>>(2).is_none());
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_submit_and_apply_each_commit_once_under_revision_fences() {
    let fixture =
        client_http::ClientFixture::start(registry(false), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Raced", "raced-start").await;
    let first = client
        .prepare_proposal(&draft, "submit", json!({}), &key("raced-submit-a"))
        .unwrap();
    let second = client
        .prepare_proposal(&draft, "submit", json!({}), &key("raced-submit-b"))
        .unwrap();
    let (a, b) = tokio::join!(
        client.execute_proposal(&first),
        client.execute_proposal(&second)
    );
    let submitted = match (a, b) {
        (Ok(value), Err(error)) | (Err(error), Ok(value)) => {
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::PreconditionFailed)
            );
            value.value
        }
        _ => panic!("exactly one submission must commit"),
    };
    let body = json!({"submissionVersion":submitted.submission_version(),"effectDigest":submitted.effect_digest().unwrap()});
    let first = client
        .prepare_proposal(&submitted, "apply", body.clone(), &key("raced-apply-a"))
        .unwrap();
    let second = client
        .prepare_proposal(&submitted, "apply", body, &key("raced-apply-b"))
        .unwrap();
    let (a, b) = tokio::join!(
        client.execute_proposal(&first),
        client.execute_proposal(&second)
    );
    match (a, b) {
        (Ok(value), Err(error)) | (Err(error), Ok(value)) => {
            assert_eq!(value.value.state(), BRegProposalState::Applied);
            assert_eq!(
                error.problem_code(),
                Some(BRegProblemCode::PreconditionFailed)
            );
        }
        _ => panic!("exactly one application must commit"),
    }
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_lifecycle_recovery_uses_current_authority_and_the_original_exact_condition() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Recover lifecycle", "recover-start").await;
    assert!(
        draft.input().is_none(),
        "mutation receipts retain no optional input disclosure"
    );
    let current = client.read_proposal(&draft).await.unwrap().value;
    let original_input = current.input().unwrap().clone();
    let submit = client
        .prepare_proposal(&current, "submit", json!({}), &key("recover-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let recovered = client.recover_proposal(&submitted, &submit).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&submitted).unwrap()
    );
    let revise = client
        .prepare_proposal(&submitted, "revise", json!({}), &key("recover-revise"))
        .unwrap();
    let revised = client.execute_proposal(&revise).await.unwrap().value;
    assert_eq!(
        revised.submission_version(),
        submitted.submission_version() + 1
    );
    let recovered = client.recover_proposal(&revised, &revise).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&revised).unwrap()
    );
    let rebase = client
        .prepare_proposal(
            &revised,
            "rebase",
            json!({"input":original_input}),
            &key("recover-rebase"),
        )
        .unwrap();
    let rebased = client.execute_proposal(&rebase).await.unwrap().value;
    assert_eq!(rebased.submission_version(), revised.submission_version());
    let recovered = client.recover_proposal(&rebased, &rebase).unwrap();
    assert_eq!(
        serde_json::to_value(client.execute_proposal(&recovered).await.unwrap().value).unwrap(),
        serde_json::to_value(&rebased).unwrap()
    );
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 1);
    assert_eq!(rows.get::<_, i64>(1), 0);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_only_targets_are_locked_and_readmitted_at_submit_and_apply() {
    let mut source = registry_source(false);
    source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"linked","type":"reference","target":"target","required":true,"classification":"internal"}));
    let mut fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let mut ids = Vec::new();
    for (name, key_name) in [
        ("Primary", "linked-primary"),
        ("Reference only", "linked-other"),
    ] {
        ids.push(
            client
                .create_record(
                    &create,
                    &BRegCreateRequest::new(map(json!({"name":name,"jurisdiction":"zone-a"})))
                        .unwrap(),
                    &key(key_name),
                    BRegRecordFormat::Json,
                )
                .await
                .unwrap()
                .value
                .data
                .record_identifier,
        );
    }
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":ids[0],"linked":ids[1],"value":"Changed"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("linked-start"))
        .await
        .unwrap()
        .value;
    let linked = uuid::Uuid::parse_str(&ids[1]).unwrap();
    let entity = &fixture.registry.entities()["target"];
    let change = format!(
        "UPDATE registry_data.\"{}\" SET \"{}\"=$2 WHERE record_id=$1",
        entity.physical_table, entity.fields["jurisdiction"].physical_name
    );
    let tx = fixture.database.admin.transaction().await.unwrap();
    tx.execute(&change, &[&linked, &"zone-b"]).await.unwrap();
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("linked-submit-denied"))
        .unwrap();
    let refused = {
        let waiting = client.execute_proposal(&submit);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(75), &mut waiting)
                .await
                .is_err(),
            "submit must wait for the reference-only row lock"
        );
        tx.commit().await.unwrap();
        waiting.await.unwrap_err()
    };
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    fixture
        .database
        .admin
        .execute(&change, &[&linked, &"zone-a"])
        .await
        .unwrap();
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("linked-submit-valid"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let tx = fixture.database.admin.transaction().await.unwrap();
    tx.execute(&change, &[&linked, &"zone-b"]).await.unwrap();
    let apply = client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("linked-apply-denied"),
        )
        .unwrap();
    let refused = {
        let waiting = client.execute_proposal(&apply);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(75), &mut waiting)
                .await
                .is_err(),
            "apply must wait for the reference-only row lock"
        );
        tx.commit().await.unwrap();
        waiting.await.unwrap_err()
    };
    assert_eq!(
        refused.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    let state = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(state.get::<_, String>(0), "submitted");
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_review_binding_preserves_unrelated_builtin_work_and_fails_review_closed() {
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let mut reviewed = source["actions"][0].clone();
    reviewed["id"] = json!("reviewed-name");
    reviewed["execution"]["proposal"]["application"] = json!({"mode":"manual"});
    reviewed["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    source["actions"].as_array_mut().unwrap().push(reviewed);
    for family in ["actions", "proposals"] {
        let mut grant = source["accessProfiles"][0]["permissions"][family][0].clone();
        grant["action"] = json!("reviewed-name");
        source["accessProfiles"][0]["permissions"][family]
            .as_array_mut()
            .unwrap()
            .push(grant);
    }
    let registry = compile(source);
    let runtime = registry_breg::runtime_config::parse_runtime_config(include_str!(
        "../../../products/breg/examples/minimal/runtime.example.yaml"
    ))
    .unwrap();
    assert!(
        runtime
            .activate_review_authorities(&registry)
            .unwrap()
            .is_none(),
        "an absent optional Review mapping must not disable the registry"
    );
    let fixture = client_http::ClientFixture::start(registry, claims("author", "zone-a")).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Independent", "independent-start").await;
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("independent-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    let record = applied.application().unwrap().result_links[0]
        .record_id
        .clone();
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let reviewed = metadata
        .value
        .select_action("reviewed-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &reviewed,
        map(json!({"target":record,"value":"Must remain unapplied"})),
        None,
    )
    .unwrap();
    let blocked = client
        .start_proposal(&reviewed, &input, &key("unavailable-review-start"))
        .await
        .unwrap()
        .value;
    let link = blocked
        .link("submit")
        .expect("unavailable transition is inspectable");
    assert!(!link.availability().unwrap().available);
    assert_eq!(
        link.availability().unwrap().reason,
        Some(registry_breg_client::BRegAvailabilityReason::DependencyOutage)
    );
    // Exercise refusal on the exact inert server link without promoting it in
    // the client or reconstructing a lifecycle route.
    let wire = serde_json::to_value(link).unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            fixture.http.base_url.trim_end_matches('/'),
            wire["path"].as_str().unwrap()
        ))
        .query(&[("accessProfile", wire["accessProfile"].as_str().unwrap())])
        .header("content-type", "application/json")
        .header("if-match", wire["ifMatch"].as_str().unwrap())
        .header("idempotency-key", "unavailable-review-submit")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let current = client.read_proposal(&blocked).await.unwrap().value;
    assert_eq!(current.state(), BRegProposalState::Draft);
    let cancel = client
        .prepare_proposal(
            &current,
            "cancel",
            json!({}),
            &key("unavailable-review-cancel"),
        )
        .unwrap();
    assert_eq!(
        client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let rows = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_review_submissions),
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows.get::<_, i64>(0), 0);
    assert_eq!(rows.get::<_, i64>(1), 1);
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[path = "support/proposal_activation.rs"]
mod proposal_activation;
#[cfg(feature = "tooling")]
#[path = "support/proposal_review_authority.rs"]
mod proposal_review_authority;
struct ActiveReady;
impl registry_breg::api::ReadinessProbe for ActiveReady {
    fn is_ready(&self) -> registry_breg::api::ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
#[cfg(feature = "tooling")]
async fn successor_client(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
) -> client_http::ClientHttp {
    client_with_audit_key(
        fixture,
        registry,
        identity,
        0x61,
        claims("author", "zone-a"),
    )
    .await
}
async fn client_with_audit_key(
    fixture: &client_http::ClientFixture,
    registry: registry_breg::CompiledRegistry,
    identity: registry_breg::postgres::ExpectedRegistryIdentity,
    audit_key: u8,
    caller: VerifiedRequestClaims,
) -> client_http::ClientHttp {
    use registry_breg::api::{HttpService, ReadRuntimeIdentity};
    use registry_breg::postgres::{
        PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey,
    };
    use std::sync::Arc;
    let registry = Arc::new(registry);
    let lock = RegistryLockKey::derive(registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(
            vec![audit_key; 32].into(),
        )
        .unwrap(),
    )
    .0;
    let cursors = Arc::new(
        registry_breg::cursor::CursorCodec::new(
            zeroize::Zeroizing::new(vec![0x62; 32]),
            std::time::Duration::from_secs(300),
        )
        .unwrap(),
    );
    let records = PostgresRecordReadService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        std::time::Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let mutations = PostgresRecordMutationService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity.clone(),
        "client-capability-test",
        lock,
        std::time::Duration::from_secs(2),
        audit,
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(records),
        Arc::new(ActiveReady),
        cursors,
    )
    .with_postgres_mutations(Arc::new(mutations));
    client_http::ClientHttp::start(registry_breg::api::router(Arc::new(service)), caller).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_key_rotation_preserves_stable_ownership_and_exact_replay_but_not_other_callers() {
    let mut source = registry_source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source), claims("author", "zone-a")).await;
    let applied_draft = start(&fixture, "Before rotation", "owner-applied-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(
            &applied_draft,
            "submit",
            json!({}),
            &key("owner-applied-submit"),
        )
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let apply = fixture
        .http
        .client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("owner-applied-apply"),
        )
        .unwrap();
    let applied = fixture
        .http
        .client
        .execute_proposal(&apply)
        .await
        .unwrap()
        .value;
    let draft = start(&fixture, "After rotation", "owner-draft-start").await;
    let saved: Value = serde_json::from_slice(apply.as_bytes()).unwrap();
    let rotated = client_with_audit_key(
        &fixture,
        (*fixture.registry).clone(),
        fixture.identity.clone(),
        0x72,
        claims("author", "zone-a"),
    )
    .await;
    let metadata = rotated
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = rotated
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value;
    assert_eq!(page.items.len(), 2);
    let owned = page
        .items
        .iter()
        .find(|proposal| proposal.id() == draft.id())
        .unwrap();
    let owned = rotated.client.read_proposal(owned).await.unwrap().value;
    let mut input = owned.input().unwrap().clone();
    input.insert("value".into(), json!("Edited after rotation"));
    let edit = rotated
        .client
        .prepare_proposal(&owned, "edit", json!({"input":input}), &key("owner-edit"))
        .unwrap();
    let edited = rotated.client.execute_proposal(&edit).await.unwrap().value;
    let submit = rotated
        .client
        .prepare_proposal(&edited, "submit", json!({}), &key("owner-submit"))
        .unwrap();
    let submitted = rotated
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let cancel = rotated
        .client
        .prepare_proposal(&submitted, "cancel", json!({}), &key("owner-cancel"))
        .unwrap();
    assert_eq!(
        rotated
            .client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            rotated.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        serde_json::to_value(applied).unwrap()
    );
    let other = client_with_audit_key(
        &fixture,
        (*fixture.registry).clone(),
        fixture.identity.clone(),
        0x72,
        claims("different-author", "zone-a"),
    )
    .await;
    let metadata = other.client.registry_contract(Some("clerk")).await.unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    assert!(other
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .is_empty());
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            other.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_ne!(response.status(), reqwest::StatusCode::OK);
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_applications",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    drop(other);
    drop(rotated);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn compatible_verified_activation_keeps_the_frozen_submission_applicable() {
    let source = registry_source(false);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "After compatible activation", "compatible-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("compatible-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["display"] = json!({"label":"Correct the name"});
    let candidate = compile(next.clone());
    assert_eq!(
        fixture.registry.actions().actions[0].definition_revision,
        candidate.actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    assert_ne!(identity.activation_id, fixture.identity.activation_id);
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let proposal = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    assert!(proposal.blocked_reason().is_none());
    assert_eq!(proposal.effect_digest(), submitted.effect_digest());
    let apply = current
        .client
        .prepare_proposal(
            &proposal,
            "apply",
            json!({"submissionVersion":1,"effectDigest":proposal.effect_digest().unwrap()}),
            &key("compatible-apply"),
        )
        .unwrap();
    assert_eq!(
        current
            .client
            .execute_proposal(&apply)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Applied
    );
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn narrowed_attachment_disclosure_refuses_the_old_exact_receipt_without_reexecution() {
    let source = registry_source(false);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "Disclosure narrowed", "narrow-start").await;
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            b"private-slot-canary",
            &key("narrow-upload"),
        )
        .await
        .unwrap()
        .value;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("narrow-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let apply = fixture
        .http
        .client
        .prepare_proposal(
            &submitted,
            "apply",
            json!({"submissionVersion":1,"effectDigest":submitted.effect_digest().unwrap()}),
            &key("narrow-apply"),
        )
        .unwrap();
    let applied = fixture
        .http
        .client
        .execute_proposal(&apply)
        .await
        .unwrap()
        .value;
    assert!(
        serde_json::to_value(&applied).unwrap()["attachments"]["support"]
            .get("value")
            .is_some()
    );
    let saved: Value = serde_json::from_slice(apply.as_bytes()).unwrap();
    let mut next = source;
    next["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
    assert_eq!(
        fixture.registry.actions().actions[0].definition_revision,
        compile(next.clone()).actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current = successor_client(&fixture, registry, identity).await;
    let response = reqwest::Client::new()
        .post(format!(
            "{}{}",
            current.base_url.trim_end_matches('/'),
            saved["link"]["path"].as_str().unwrap()
        ))
        .query(&[(
            "accessProfile",
            saved["link"]["accessProfile"].as_str().unwrap(),
        )])
        .header("content-type", "application/json")
        .header("if-match", saved["link"]["ifMatch"].as_str().unwrap())
        .header("idempotency-key", saved["key"].as_str().unwrap())
        .body(saved["body"].as_str().unwrap().to_owned())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let refused = response.text().await.unwrap();
    assert!(!refused.contains("private-slot-canary"));
    assert!(!refused.contains("sha256"));
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let page = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap();
    assert!(
        serde_json::to_value(&page.value.items[0]).unwrap()["attachments"]["support"]
            .get("value")
            .is_none()
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_revisions)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 2);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn review_context_refuses_active_action_mapping_for_a_retained_submission() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review-name","fields":{
            "proposedName":{"type":"input","input":"value"},
            "currentName":{"type":"record","input":"target","field":"name"},
            "changes":{"type":"changes","recordType":"target","fields":["name"]}
        }
    });
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .extend([json!("get-review-context"), json!("get-review-status")]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["proposedName", "currentName", "changes"]);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "frozen-name-canary", "mapping-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("mapping-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let path = format!(
        "/v1/proposals/{}/review-context?accessProfile=clerk",
        submitted.id()
    );
    let response = reqwest::get(format!("{}{path}", fixture.http.base_url))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let original: Value = response.json().await.unwrap();
    assert_eq!(
        original["actionRevision"],
        fixture.registry.actions().actions[0].definition_revision
    );
    assert_eq!(
        original["context"]["fields"]["proposedName"],
        "frozen-name-canary"
    );
    assert_eq!(
        original["context"]["fields"]["changes"][0]["after"]["name"],
        "frozen-name-canary"
    );

    let mut next = source;
    // The same public field now means a different frozen input. Even though both
    // values exist, the current mapping must not reinterpret the old submission.
    next["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["proposedName"] =
        json!({"type":"input","input":"target"});
    assert_ne!(
        fixture.registry.actions().actions[0].definition_revision,
        compile(next.clone()).actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current_schema = registry_breg::compiler::review_context::compile_schema(
        &registry,
        &registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let current = successor_client(&fixture, registry, identity).await;
    let response = reqwest::get(format!("{}{path}", current.base_url))
        .await
        .unwrap();
    let status = response.status();
    let refused = response.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "{refused}");
    for hidden in [
        "frozen-name-canary",
        "proposedName",
        "currentName",
        "sha256:",
    ] {
        assert!(!refused.contains(hidden), "refusal disclosed {hidden}");
    }
    let status = reqwest::get(format!(
        "{}/v1/proposals/{}/review-status?accessProfile=clerk",
        current.base_url,
        submitted.id(),
    ))
    .await
    .unwrap();
    assert_eq!(status.status(), reqwest::StatusCode::OK);
    let status: Value = status.json().await.unwrap();
    assert_eq!(status["actionRevision"], original["actionRevision"]);
    assert!(status["context"].get("fields").is_none());
    assert_eq!(
        status["context"]["contract"],
        json!({
            "id":current_schema.id,"revision":current_schema.revision,"schemaDigest":current_schema.digest,
        })
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
            (SELECT count(*) FROM registry_internal.registry_revisions),
            action_revision FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(
        row.get::<_, String>(2),
        original["actionRevision"].as_str().unwrap()
    );
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn retained_attachment_download_survives_tighter_current_upload_policy() {
    let mut source = registry_source(false);
    source["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({"id":"retained-document","fields":{"document":{"type":"document","slot":"support"}}});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-context"));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["document"]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableInputs"] =
        json!(["target", "value"]);
    let fixture =
        client_http::ClientFixture::start(compile(source.clone()), claims("author", "zone-a"))
            .await;
    let draft = start(&fixture, "Retained attachment", "retained-start").await;
    let bytes = b"historical-text-attachment-canary";
    let uploaded = fixture
        .http
        .client
        .upload_proposal_attachment(
            &draft,
            "support",
            "text/plain",
            bytes,
            &key("retained-upload"),
        )
        .await
        .unwrap()
        .value;
    let target = fixture
        .http
        .client
        .read_proposal(&uploaded)
        .await
        .unwrap()
        .value
        .input()
        .unwrap()["target"]
        .clone();
    let submit = fixture
        .http
        .client
        .prepare_proposal(&uploaded, "submit", json!({}), &key("retained-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let old_metadata = fixture
        .http
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap()
        .value;
    let old_binding = old_metadata
        .select_proposal_review_context("clerk", "correct-name")
        .unwrap();
    let old_context = fixture
        .http
        .client
        .read_proposal_review_by_id(&old_binding, submitted.id())
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["attachments"][0]["maximumBytes"] = json!(8);
    next["actions"][0]["execution"]["proposal"]["attachments"][0]["contentTypes"] =
        json!(["application/octet-stream"]);
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current_schema = registry_breg::compiler::review_context::compile_schema(
        &registry,
        &registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let listed = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    let retained = current.client.read_proposal(&listed).await.unwrap().value;
    let value = serde_json::to_value(&retained).unwrap();
    assert_eq!(value["attachments"]["support"]["maximumBytes"], 8);
    assert_eq!(
        value["attachments"]["support"]["contentTypes"],
        json!(["application/octet-stream"])
    );
    assert_eq!(
        value["attachments"]["support"]["value"]["byteSize"],
        bytes.len()
    );
    assert_eq!(
        value["attachments"]["support"]["value"]["contentType"],
        "text/plain"
    );
    let raw = reqwest::get(format!(
        "{}/v1/proposals/{}/attachments/support?accessProfile=clerk&submissionVersion=1",
        current.base_url,
        retained.id()
    ))
    .await
    .unwrap();
    assert_eq!(raw.status(), reqwest::StatusCode::OK);
    assert_eq!(raw.headers()["content-type"], "text/plain");
    assert_eq!(raw.bytes().await.unwrap().as_ref(), bytes);
    let binding = metadata
        .value
        .select_proposal_review_context("clerk", "correct-name")
        .unwrap();
    assert!(
        current
            .client
            .read_proposal_review_by_id(&binding, submitted.id())
            .await
            .is_err(),
        "a fresh context must not reinterpret the retained submission under a changed Action"
    );
    assert!(
        current
            .client
            .download_proposal_review_document(&binding, &old_context, "document")
            .await
            .is_err(),
        "a saved review link cannot release bytes after the Action revision changes"
    );

    let saved_path = old_context.context.fields.as_ref().unwrap()["document"]["download"]["path"]
        .as_str()
        .unwrap();
    let current_schema_path = saved_path.replace(
        &old_context
            .context
            .contract
            .as_ref()
            .unwrap()
            .schema_digest
            .replace(':', "%3A"),
        &current_schema.digest.replace(':', "%3A"),
    );
    for path in [saved_path, current_schema_path.as_str()] {
        let response = reqwest::get(format!("{}{path}&accessProfile=clerk", current.base_url))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "review bytes require the frozen Action even with today's context schema"
        );
        assert!(!response
            .text()
            .await
            .unwrap()
            .contains("historical-text-attachment-canary"));
    }

    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":target,"value":"Current draft"})),
        None,
    )
    .unwrap();
    let current_draft = current
        .client
        .start_proposal(&action, &input, &key("current-policy-start"))
        .await
        .unwrap()
        .value;
    for (content_type, upload, expected) in [
        (
            "application/octet-stream",
            bytes.as_slice(),
            reqwest::StatusCode::BAD_REQUEST,
        ),
        (
            "text/plain",
            b"ok".as_slice(),
            reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        assert!(current
            .client
            .upload_proposal_attachment(
                &current_draft,
                "support",
                content_type,
                upload,
                &key("current-policy-refused")
            )
            .await
            .is_err());
        let value = serde_json::to_value(&current_draft).unwrap();
        let response = reqwest::Client::new()
            .patch(format!(
                "{}/v1/proposals/{}/attachments/support?accessProfile=clerk",
                current.base_url,
                current_draft.id()
            ))
            .header("content-type", content_type)
            .header("idempotency-key", "current-policy-raw-refused")
            .header(
                "if-match",
                value["attachments"]["support"]["links"]["upload"]["ifMatch"]
                    .as_str()
                    .unwrap(),
            )
            .body(upload.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    current
        .client
        .upload_proposal_attachment(
            &current_draft,
            "support",
            "application/octet-stream",
            b"ok",
            &key("current-policy-accepted"),
        )
        .await
        .unwrap();
    assert_eq!(current.client.download_proposal_attachment(&retained, "support").await
        .expect("authorized retained content uses its stored size rather than today's upload ceiling").value.as_bytes(), bytes);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "tooling")]
async fn review_pin_only_verified_activation_blocks_apply_but_preserves_inspection_and_cancel() {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 3.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await;
    let draft = start(&fixture, "Must not apply old policy", "pin-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("pin-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let candidate = compile(next.clone());
    assert_ne!(
        fixture.registry.actions().actions[0].definition_revision,
        candidate.actions().actions[0].definition_revision
    );
    let (registry, identity) = proposal_activation::activate_successor(&fixture, &next).await;
    let current = successor_client(&fixture, registry, identity).await;
    let metadata = current
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let collection = metadata.value.select_proposals("clerk").unwrap();
    let proposal = current
        .client
        .list_proposals(&collection, &BRegProposalQuery::default())
        .await
        .unwrap()
        .value
        .items
        .into_iter()
        .find(|proposal| proposal.id() == submitted.id())
        .unwrap();
    assert_eq!(proposal.blocked_reason(), Some("package-changed"));
    assert_eq!(proposal.effect_digest(), submitted.effect_digest());
    let apply = proposal.link("apply").unwrap().availability().unwrap();
    assert!(!apply.available);
    assert_eq!(
        apply.reason,
        Some(registry_breg_client::BRegAvailabilityReason::ContractChanged)
    );
    let cancel = current
        .client
        .prepare_proposal(&proposal, "cancel", json!({}), &key("pin-cancel"))
        .unwrap();
    assert_eq!(
        current
            .client
            .execute_proposal(&cancel)
            .await
            .unwrap()
            .value
            .state(),
        BRegProposalState::Cancelled
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT count(*) FROM registry_internal.registry_migrations WHERE outcome='applied')",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 2);
    drop(current);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_receipt_replay_refuses_a_task_grant_expiring_at_the_idempotency_lock() {
    use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
    use registry_breg::task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker};
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use registry_platform_testing::{oidc_verifier_config, MockIdp};
    use std::{sync::Arc, time::Duration};
    struct Current;
    impl TaskGrantStatusChecker for Current {
        fn check<'a>(
            &'a self,
            _: &'a TaskGrantBinding,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(()) })
        }
    }
    let mut source = registry_source(false);
    let mut permission = source["accessProfiles"][0]["permissions"]["proposals"][0].clone();
    permission["operations"] = json!(["get", "apply"]);
    permission["readableAttachments"] = json!([]);
    permission["writableAttachments"] = json!([]);
    source["accessProfiles"].as_array_mut().unwrap().push(json!({"id":"task-applier","actorKind":"agent",
        "requesterClients":["agent-client"],"principalClaim":"sub","requiredScopes":["proposal:manage"],
        "requiredPurposes":["registry-administration"],"taskGrant":{"sourceIssuer":"https://casework.example"},
        "permissions":{"proposals":[permission]}}));
    let registry = compile(source);
    let idp = MockIdp::start().await;
    let mut verifier = oidc_verifier_config(idp.issuer(), vec!["urn:example:breg".into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
    )
    .unwrap();
    let human = json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client","registry_actor_kind":"human",
        "registry_purpose":"registry-administration","scope":"proposal:manage","jurisdiction":"zone-a"});
    let human = auth.authenticate(&idp.mint_token(human)).await.unwrap();
    let fixture = client_http::ClientFixture::start_with_mutations(registry, human, |mutations| {
        mutations
            .with_task_status(Arc::new(Current))
            .with_action_timeout_for_test(Duration::from_secs(8))
    })
    .await;
    let draft = start(&fixture, "One retained application", "expiry-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("expiry-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let token = json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client","registry_actor_kind":"agent",
        "registry_purpose":"registry-administration","scope":"proposal:manage",
        "registry_grant_id":"00000000-0000-4000-8000-000000000071","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":"urn:example:breg","registry_grant_exp":expiry,
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":format!("proposal:{}",submitted.id()),"operations":["get","apply"]}]},
        "identity":{"jurisdiction":"zone-a"},"jurisdiction":"zone-b"});
    let caller = auth.authenticate(&idp.mint_token(token)).await.unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let service = registry_breg::postgres::PostgresRecordMutationService::new(
        fixture.pool.clone(),
        fixture.registry.clone(),
        fixture.identity.clone(),
        "task-expiry",
        registry_breg::postgres::RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
        Duration::from_secs(10),
        audit,
    )
    .with_task_status(Arc::new(Current))
    .with_action_timeout_for_test(Duration::from_secs(8));
    let task = fixture.client_with_mutations(caller, service).await;
    let metadata = task
        .client
        .registry_contract(Some("task-applier"))
        .await
        .unwrap();
    let get = metadata.value.select_proposal_get("task-applier").unwrap();
    let proposal = task
        .client
        .get_proposal(&get, submitted.id())
        .await
        .unwrap()
        .value;
    let apply = task
        .client
        .prepare_proposal(
            &proposal,
            "apply",
            json!({"submissionVersion":proposal.submission_version(),
        "effectDigest":proposal.effect_digest().unwrap()}),
            &key("expiry-apply"),
        )
        .unwrap();
    task.client.execute_proposal(&apply).await.unwrap();
    let lock_ref:String=fixture.database.admin.query_one("SELECT key_reference FROM registry_internal.registry_idempotency WHERE idempotency_key='expiry-apply'",&[])
        .await.unwrap().get(0);
    fixture
        .database
        .admin
        .execute(
            "SELECT pg_advisory_lock(pg_catalog.hashtextextended($1,0))",
            &[&lock_ref],
        )
        .await
        .unwrap();
    let waiting = task.client.execute_proposal(&apply);
    let release = async {
        tokio::time::timeout(Duration::from_secs(1),async{loop{
            let blocked:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",&[]).await.unwrap().get(0);
            if blocked>0{break;}tokio::time::sleep(Duration::from_millis(10)).await;
        }}).await.expect("replay passed current admission and reached the idempotency lock");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        tokio::time::sleep(Duration::from_millis(
            (u128::from(expiry) * 1000).saturating_sub(now) as u64 + 30,
        ))
        .await;
        fixture
            .database
            .admin
            .execute(
                "SELECT pg_advisory_unlock(pg_catalog.hashtextextended($1,0))",
                &[&lock_ref],
            )
            .await
            .unwrap();
    };
    let (outcome, ()) = tokio::join!(waiting, release);
    assert_eq!(
        outcome.unwrap_err().problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    let row=fixture.database.admin.query_one("SELECT (SELECT count(*) FROM registry_internal.registry_proposal_applications),(SELECT count(*) FROM registry_internal.registry_idempotency WHERE idempotency_key='expiry-apply')",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(
        row.get::<_, i64>(1),
        1,
        "expired replay neither reexecutes nor replaces the receipt"
    );
    drop(task);
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compatible_old_review_closure_survives_successors_and_same_package_role_reactivation() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest,
    };
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let old_policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":old_policy});
    let authority = proposal_review_authority::LocalAuthority::start(
        serde_json::from_value(old_policy.clone()).unwrap(),
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| mutations.with_review_result_source(configured),
    )
    .await;
    let runtime = fixture.pool.get_for_test().await.unwrap();
    let _:i64=runtime.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap().get(0);
    for statement in [
        "INSERT INTO registry_internal.registry_proposal_activation_compatibility(action_id) SELECT 'synthetic' WHERE false",
        "UPDATE registry_internal.registry_proposal_activation_compatibility SET closure_digest=closure_digest WHERE false",
        "DELETE FROM registry_internal.registry_proposal_activation_compatibility WHERE false",
    ] {
        let error = runtime
            .execute(statement, &[])
            .await
            .expect_err("runtime compatibility authority is SELECT only");
        assert_eq!(error.code().map(|code| code.code()), Some("42501"));
    }
    drop(runtime);
    let draft = start(&fixture, "Retain original review closure", "closure-start").await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("closure-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_proposal_review_submissions",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "pending");
    // The ordinary durable handoff completes before proof preparation. The
    // activation factory performs GETs only and never sends creation payloads.
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry
        )
        .await
        .unwrap()
    );
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry
        )
        .await
        .unwrap()
    );
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_proposal_submissions",
            &[],
        )
        .await
        .unwrap();
    let original: Value = row.get(0);
    let mut next = source.clone();
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let (package_b, identity_b) = proposal_activation::activate_with_compatibility(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &next,
        Some(&authority.registry),
    )
    .await;
    let inspection =
        successor_client(&fixture, package_b.registry().clone(), identity_b.clone()).await;
    let contract = inspection
        .client
        .registry_contract(Some("clerk"))
        .await
        .unwrap();
    let get = contract.value.select_proposal_get("clerk").unwrap();
    let current = inspection
        .client
        .get_proposal(&get, submitted.id())
        .await
        .unwrap()
        .value;
    let revise = current.link("revise").unwrap();
    let availability = revise.availability().unwrap();
    assert!(
        !availability.available,
        "ordinary Revise never changes the frozen Action revision"
    );
    assert_eq!(
        availability.reason,
        Some(registry_breg_client::BRegAvailabilityReason::ContractChanged)
    );
    assert_eq!(
        availability.recovery,
        Some(registry_breg_client::BRegRecoveryHint::Refresh)
    );
    assert!(
        current
            .link("rebase")
            .unwrap()
            .availability()
            .unwrap()
            .available,
        "explicit Rebase remains available with current Start authority"
    );
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{}/revise?accessProfile=clerk",
            inspection.base_url,
            submitted.id()
        ))
        .header("idempotency-key", "compatible-cannot-revise-contract")
        .header(
            "if-match",
            serde_json::to_value(&current).unwrap()["links"]["revise"]["ifMatch"]
                .as_str()
                .unwrap(),
        )
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PRECONDITION_FAILED);
    drop(inspection);
    let mut third = next.clone();
    third["actions"][0]["display"] = json!({"label":"Current correction label"});
    let (package_c, identity_c) = proposal_activation::activate_with_compatibility(
        &fixture,
        package_b.registry(),
        &identity_b,
        &third,
        Some(&authority.registry),
    )
    .await;
    let inventory = registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
        &fixture.pool,
        &identity_c,
        &package_c,
        &authority.registry,
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    // A role-only same-package activation repairs a deliberately missing
    // runtime read grant. It appends proof under a new activation identity.
    fixture.database.admin.batch_execute(&format!("REVOKE SELECT ON registry_internal.registry_proposal_activation_compatibility FROM \"{}\"",
        fixture.database.runtime_role.as_str())).await.unwrap();
    let identity_d = apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &fixture.database.migration_config,
            &package_c,
            ActivationDeployment::new("local", "proposal-role-repair", &identity_c.database_id),
            ApplyPrecondition::RoleChange {
                current: &identity_c,
            },
            ApplyRoles::new(
                &fixture.database.migration_role,
                &fixture.database.runtime_role,
            ),
            ApplyTimeouts::new(
                std::time::Duration::from_secs(2),
                std::time::Duration::from_secs(10),
            )
            .unwrap(),
            fixture.database.activation_audit(),
        )
        .with_proposal_activation_compatibility(&inventory),
    )
    .await
    .unwrap();
    assert_eq!(identity_d.package_digest, identity_c.package_digest);
    assert_ne!(identity_d.activation_id, identity_c.activation_id);
    let row=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 3);
    let row = fixture
        .database
        .admin
        .query_one(
            "SELECT blocked_reason,action_revision FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<String>>(0).is_none());
    assert_eq!(
        row.get::<_, String>(1),
        fixture.registry.actions().actions[0].definition_revision
    );
    let before = authority.counts();
    assert_eq!(before.0, 1);
    assert_eq!(before.1, 3);
    let registry = std::sync::Arc::new(package_c.registry().clone());
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x61; 32].into())
            .unwrap(),
    )
    .0;
    let mutations = registry_breg::postgres::PostgresRecordMutationService::new(
        fixture.pool.clone(),
        registry.clone(),
        identity_d,
        "client-capability-test",
        registry_breg::postgres::RegistryLockKey::derive(registry.registry_id()).unwrap(),
        std::time::Duration::from_secs(2),
        audit,
    )
    .with_review_result_source(authority.registry.clone());
    assert!(mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        authority.counts().0,
        1,
        "activation never re-creates an old review under the new policy"
    );
    assert_eq!(
        authority.counts().2,
        before.2 + 1,
        "uncommitted automatic apply fetches fresh original approval"
    );
    let row=fixture.database.admin.query_one("SELECT s.snapshot,w.state,q.expected_policy,
        (SELECT count(*) FROM registry_internal.registry_proposal_applications)
        FROM registry_internal.registry_proposal_submissions s JOIN registry_internal.registry_proposal_state w USING(action_id,proposal_id,submission_version)
        JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
    assert_eq!(row.get::<_, Value>(0), original);
    assert_eq!(row.get::<_, String>(1), "applied");
    assert_eq!(row.get::<_, Value>(2), old_policy);
    assert_eq!(row.get::<_, i64>(3), 1);
    assert_eq!(submitted.submission_version(), 1);
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compatibility_inventory_refuses_rebound_frozen_review_subject_context_and_result() {
    use sha2::{Digest, Sha256};
    let mut source = registry_source(true);
    source["reviewAuthorities"] =
        json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
    let old_policy =
        json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":old_policy});
    let authority = proposal_review_authority::LocalAuthority::start(
        serde_json::from_value(old_policy).unwrap(),
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source.clone()),
        claims("author", "zone-a"),
        move |mutations| mutations.with_review_result_source(configured),
    )
    .await;
    let draft = start(
        &fixture,
        "Frozen closure tamper must refuse",
        "tamper-start",
    )
    .await;
    let submit = fixture
        .http
        .client
        .prepare_proposal(&draft, "submit", json!({}), &key("tamper-submit"))
        .unwrap();
    let submitted = fixture
        .http
        .client
        .execute_proposal(&submit)
        .await
        .unwrap()
        .value;
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry
        )
        .await
        .unwrap()
    );
    assert!(
        registry_breg::review_store::run_review_authority_once_for_test(
            &fixture.pool,
            &authority.registry
        )
        .await
        .unwrap()
    );
    let mut next = source;
    next["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "c".repeat(64)));
    let candidate = proposal_activation::verified_successor(
        &fixture,
        &fixture.registry,
        &fixture.identity,
        &next,
    )
    .await;
    let saved=fixture.database.admin.query_one("SELECT p.snapshot,q.create_request,q.expected_submission_digest,r.completed_at,q.accepted_binding,r.result
        FROM registry_internal.registry_proposal_submissions p JOIN registry_internal.registry_proposal_review_submissions q USING(action_id,proposal_id,submission_version)
        JOIN registry_internal.registry_proposal_review_results r USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
    let original: Value = saved.get(0);
    let create: Value = saved.get(1);
    let expected: String = saved.get(2);
    let completed: chrono::DateTime<chrono::Utc> = saved.get(3);
    let accepted_binding: Value = saved.get(4);
    let retained_result: Value = saved.get(5);
    let packet_key = registry_breg::proposal_workflow::ProposalKey::new(
        registry_breg::proposal_workflow::EntityId::new("correct-name").unwrap(),
        registry_breg::proposal_workflow::RecordId::new(submitted.id()).unwrap(),
    );
    // This packet has a valid recomputed digest and matching state/queued
    // digest. The independently authenticated old queued Review remains Required.
    let mut downgraded = original.clone();
    downgraded["reviewRequirement"] = json!({"type":"none"});
    let mut digest_input = json!({"schema":"breg.proposal/v1","inputs":downgraded["inputs"],"inputTargets":downgraded["inputTargets"],
        "proposal":packet_key,"submissionVersion":downgraded["submissionVersion"],"inputRevision":downgraded["inputRevision"],
        "contractFingerprint":downgraded["contractFingerprint"],"originatingPackage":downgraded["originatingPackage"],
        "review":downgraded["reviewRequirement"],"application":downgraded["applicationPolicy"],"systemGrantRevision":downgraded["systemGrantRevision"],
        "planningBinding":downgraded["planningBinding"],"effects":downgraded["effects"]});
    if let Some(value) = downgraded.get("applicationPreconditions") {
        digest_input["applicationPreconditions"] = value.clone();
    }
    if let Some(value) = downgraded.get("attachments") {
        digest_input["attachments"] = value.clone();
    }
    let bytes = registry_platform_canonical_json::canonicalize_json(&digest_input).unwrap();
    let digest = format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    downgraded["effectDigest"] = json!(digest);
    let frozen: registry_breg::proposal_workflow::ProposalSnapshot =
        serde_json::from_value(downgraded.clone()).unwrap();
    frozen
        .verify_digest(&packet_key)
        .expect("negative reaches closure validation after valid packet digest");
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_submissions SET snapshot=$1,effect_digest=$2",&[&downgraded,&digest]).await.unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$1",
            &[&digest],
        )
        .await
        .unwrap();
    let proof = registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
        &fixture.pool,
        &fixture.identity,
        &candidate,
        &authority.registry,
        std::time::Duration::from_secs(2),
    )
    .await;
    assert!(
        proof.is_err(),
        "frozen Review=None cannot reuse an authenticated Required closure"
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_submissions SET snapshot=$1,effect_digest=$2",&[&original,&submitted.effect_digest().unwrap()]).await.unwrap();
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_submissions SET proposal_digest=$1",
            &[&submitted.effect_digest().unwrap()],
        )
        .await
        .unwrap();
    for (field, value) in [
        (
            "subject",
            json!({"source":"another-source","type":"proposal","id":submitted.id(),"version":"1","digest":submitted.effect_digest().unwrap()}),
        ),
        (
            "context",
            json!({"mode":"current-source","binding":{"reference":"breg:wrong:correct-name:other:1"}}),
        ),
        ("policy-id", json!("other-policy")),
        ("policy-version", json!("2")),
        (
            "policy-digest",
            json!(registry_review_client::ContentDigest::for_bytes(
                b"other-policy"
            )),
        ),
    ] {
        let mut altered = create.clone();
        if let Some(policy_field) = field.strip_prefix("policy-") {
            altered["policy"][policy_field] = value;
        } else {
            altered[field] = value;
        }
        let request: registry_review_client::ReviewCreateRequest =
            serde_json::from_value(altered.clone()).unwrap();
        let recomputed = registry_review_client::submission_digest(
            "proposal-producer",
            "proposal-test",
            &request,
        )
        .unwrap();
        // Keep the local digest evidence internally consistent: the frozen
        // expected policy must independently reject the substituted request.
        let mut altered_binding = accepted_binding.clone();
        altered_binding["submissionDigest"] = json!(recomputed);
        let mut altered_result = retained_result.clone();
        altered_result["submissionDigest"] = json!(recomputed);
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET create_request=$1,expected_submission_digest=$2,accepted_binding=$3",
            &[&altered,&recomputed.as_str(),&altered_binding]).await.unwrap();
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_results SET result=$1",
                &[&altered_result],
            )
            .await
            .unwrap();
        let calls = authority.counts();
        assert!(
            registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
                &fixture.pool,
                &fixture.identity,
                &candidate,
                &authority.registry,
                std::time::Duration::from_secs(2)
            )
            .await
            .is_err(),
            "rebound {field} refuses"
        );
        assert_eq!(
            authority.counts(),
            calls,
            "reject {field} before remote proof"
        );
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET create_request=$1,expected_submission_digest=$2,accepted_binding=$3",&[&create,&expected,&accepted_binding]).await.unwrap();
        fixture
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_proposal_review_results SET result=$1",
                &[&retained_result],
            )
            .await
            .unwrap();
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_results SET completed_at=completed_at+interval '1 microsecond'",&[]).await.unwrap();
    assert!(
        registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
            &fixture.pool,
            &fixture.identity,
            &candidate,
            &authority.registry,
            std::time::Duration::from_secs(2)
        )
        .await
        .is_err(),
        "result column timestamp must equal immutable result"
    );
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results SET completed_at=$1",
            &[&completed],
        )
        .await
        .unwrap();
    let count:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_proposal_activation_compatibility",&[]).await.unwrap().get(0);
    assert_eq!(count, 0, "no negative proof persists compatibility");
    assert_eq!(
        authority.counts().1,
        0,
        "tampered closure refuses before HTTP proof reads"
    );
    fixture.finish().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incompatible_or_expired_inventory_cannot_activate_or_change_proposals_and_records() {
    use registry_breg::migration::{
        apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
        ApplyVerifiedPackageRequest,
    };
    use std::time::Duration;
    for expired in [false, true] {
        let mut source = registry_source(true);
        source["reviewAuthorities"] =
            json!([{"id":"local-review","protocol":"id.registrystack.org/protocols/review/v1"}]);
        let old_policy = json!({"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))});
        source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test","policy":old_policy});
        let authority = proposal_review_authority::LocalAuthority::start(
            serde_json::from_value(old_policy).unwrap(),
        )
        .await;
        let configured = authority.registry.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            compile(source.clone()),
            claims("author", "zone-a"),
            move |mutations| mutations.with_review_result_source(configured),
        )
        .await;
        let draft = start(
            &fixture,
            "Refused activation keeps original work",
            if expired {
                "expired-proof-start"
            } else {
                "wrong-proof-start"
            },
        )
        .await;
        let submit = fixture
            .http
            .client
            .prepare_proposal(&draft, "submit", json!({}), &key("rollback-submit"))
            .unwrap();
        fixture.http.client.execute_proposal(&submit).await.unwrap();
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry
            )
            .await
            .unwrap()
        );
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry
            )
            .await
            .unwrap()
        );
        let original: Value = fixture
            .database
            .admin
            .query_one(
                "SELECT snapshot FROM registry_internal.registry_proposal_submissions",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let before:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_migrations WHERE outcome='applied'",&[]).await.unwrap().get(0);
        let table = &fixture.registry.entities()["target"].physical_table;
        let before_records:Value=fixture.database.admin.query_one(&format!("SELECT jsonb_agg(to_jsonb(t) ORDER BY record_id) FROM registry_data.\"{table}\" t"),&[]).await.unwrap().get(0);
        source["actions"][0]["execution"]["proposal"]["review"]["policy"]["digest"] =
            json!(format!("sha256:{}", "c".repeat(64)));
        let candidate = proposal_activation::verified_successor(
            &fixture,
            &fixture.registry,
            &fixture.identity,
            &source,
        )
        .await;
        let inventory =
            registry_breg::proposal_retention::prepare_proposal_activation_compatibility(
                &fixture.pool,
                &fixture.identity,
                &candidate,
                &authority.registry,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(
            authority.counts().1,
            1,
            "genuine accepted closure was authenticated before the negative"
        );
        let other;
        let requested = if expired {
            // Validity is an engine-owned 30s bound. No editable/deserialized
            // proof or testing bypass controls its timestamp.
            tokio::time::sleep(Duration::from_secs(31)).await;
            &candidate
        } else {
            let mut unrelated = source.clone();
            unrelated["actions"][0]["display"] = json!({"label":"Different candidate package"});
            other = proposal_activation::verified_successor(
                &fixture,
                &fixture.registry,
                &fixture.identity,
                &unrelated,
            )
            .await;
            assert_ne!(candidate.package_digest(), other.package_digest());
            &other
        };
        let result = apply_verified_package(
            ApplyVerifiedPackageRequest::new(
                &fixture.database.migration_config,
                requested,
                ActivationDeployment::new(
                    "local",
                    "refused-compatibility-proof",
                    &fixture.identity.database_id,
                ),
                ApplyPrecondition::Successor {
                    current: &fixture.identity,
                },
                ApplyRoles::new(
                    &fixture.database.migration_role,
                    &fixture.database.runtime_role,
                ),
                ApplyTimeouts::new(Duration::from_secs(2), Duration::from_secs(10)).unwrap(),
                fixture.database.activation_audit(),
            )
            .with_proposal_activation_compatibility(&inventory),
        )
        .await;
        assert!(
            result.is_err(),
            "wrong or expired opaque proof cannot activate"
        );
        let state=fixture.database.admin.query_one("SELECT active_package_digest,active_activation_id::text,maintenance_status FROM registry_internal.registry_state WHERE singleton",&[]).await.unwrap();
        assert_eq!(state.get::<_, String>(0), fixture.identity.package_digest);
        assert_eq!(state.get::<_, String>(1), fixture.identity.activation_id);
        assert!(
            matches!(state.get::<_, String>(2).as_str(), "ready" | "failed"),
            "the attempted maintenance may record failure"
        );
        let after:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM registry_internal.registry_migrations WHERE outcome='applied'",&[]).await.unwrap().get(0);
        assert_eq!(after, before, "no successful activation ledger entry");
        let row=fixture.database.admin.query_one("SELECT p.snapshot,s.blocked_reason,
            (SELECT count(*) FROM registry_internal.registry_proposal_activation_compatibility),
            (SELECT count(*) FROM registry_internal.registry_proposal_applications)
            FROM registry_internal.registry_proposal_submissions p JOIN registry_internal.registry_proposal_state s USING(action_id,proposal_id,submission_version)",&[]).await.unwrap();
        assert_eq!(row.get::<_, Value>(0), original);
        assert!(row.get::<_, Option<String>>(1).is_none());
        assert_eq!(row.get::<_, i64>(2), 0);
        assert_eq!(row.get::<_, i64>(3), 0);
        let after_records:Value=fixture.database.admin.query_one(&format!("SELECT jsonb_agg(to_jsonb(t) ORDER BY record_id) FROM registry_data.\"{table}\" t"),&[]).await.unwrap().get(0);
        assert_eq!(
            after_records, before_records,
            "refused activation preserves exact Record rows"
        );
        fixture.finish().await;
    }
}

#[test]
fn automatic_recovery_grants_refuse_known_service_and_agent_profiles() {
    compile(registry_source(true));
    for actor in ["service", "agent"] {
        let mut source = registry_source(true);
        source["accessProfiles"][0]["actorKind"] = json!(actor);
        source["accessProfiles"][0]["requesterClients"] = json!(["synthetic-recovery-client"]);
        // Reach the recovery ceiling rather than the independent standing
        // agent ceiling on native Record writes.
        source["accessProfiles"][0]["permissions"]["records"][0]["operations"] =
            json!(["get", "list"]);
        source["accessProfiles"][0]["permissions"]["records"][0]["writableFields"] = json!([]);
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let error = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
        assert!(
            format!("{error:?}").contains("breg.proposal.automatic-recovery-requires-human"),
            "{error:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_application_status_exposes_bounded_block_and_human_recovery() {
    let mut source = registry_source(true);
    let mut service = source["accessProfiles"][0].clone();
    service["id"] = json!("status-service");
    service["default"] = json!(false);
    service["permissions"]["proposals"][0]["operations"] = json!(["get"]);
    service["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    service["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("actions");
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(service);
    let human_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap();
    let fixture = client_http::ClientFixture::start(compile(source), human_claims).await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Human recovery", "status-start").await;
    assert!(draft.application_status().is_none());
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("status-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let frozen = (
        submitted.submission_version(),
        submitted.effect_digest().unwrap().to_string(),
    );
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_application_jobs SET state='blocked',last_error_code='dependency-outage',attempt_count=1", &[]).await.unwrap();
    let blocked = client.read_proposal(&submitted).await.unwrap().value;
    let public = serde_json::to_value(&blocked).unwrap();
    assert_eq!(
        public["applicationStatus"],
        json!({"state":"blocked","mode":"automatic","reason":"dependency-outage","recovery":"retry","automaticRetry":{"scheduled":false,"attempts":1,"maximumAttempts":3}})
    );
    assert_eq!(blocked.submission_version(), frozen.0);
    assert_eq!(blocked.effect_digest(), Some(frozen.1.as_str()));
    assert!(blocked.application().is_none());
    let service_claims = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Service,
    )
    .unwrap();
    let service = fixture.client_for(service_claims).await;
    let metadata = service
        .client
        .registry_contract(Some("status-service"))
        .await
        .unwrap();
    let get = metadata
        .value
        .select_proposal_get("status-service")
        .unwrap();
    let ordinary = service
        .client
        .get_proposal(&get, blocked.id())
        .await
        .unwrap()
        .value;
    assert_eq!(ordinary.application_status(), blocked.application_status());
    assert!(ordinary.link("apply").is_none());
    assert!(ordinary.link("retry").is_none());
    for operation in ["apply", "retry"] {
        let body = if operation == "apply" {
            json!({"submissionVersion":blocked.submission_version(),"effectDigest":blocked.effect_digest().unwrap()})
        } else {
            json!({})
        };
        let prepared = client
            .prepare_proposal(
                &blocked,
                operation,
                body,
                &key(&format!("service-denied-{operation}")),
            )
            .unwrap();
        // The second fixture has a distinct HTTP origin. Prepared SDK attempts
        // are intentionally origin-bound, so send the owner's exact promoted
        // HTTP contract to exercise the runtime's verified service refusal.
        let wire: Value = serde_json::from_slice(prepared.as_bytes()).unwrap();
        let refused = reqwest::Client::new()
            .post(format!(
                "{}{}?accessProfile=clerk",
                service.base_url,
                wire["link"]["path"].as_str().unwrap()
            ))
            .header("if-match", wire["link"]["ifMatch"].as_str().unwrap())
            .header("idempotency-key", wire["key"].as_str().unwrap())
            .json(&serde_json::from_str::<Value>(wire["body"].as_str().unwrap()).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(
            refused.status(),
            reqwest::StatusCode::NOT_FOUND,
            "a service cannot reuse the explicit human recovery grant"
        );
    }
    let retry = client
        .prepare_proposal(&blocked, "retry", json!({}), &key("human-status-retry"))
        .unwrap();
    let retried = client.execute_proposal(&retry).await.unwrap().value;
    assert_eq!(
        retried.application_status().unwrap().state,
        registry_breg_client::BRegProposalApplicationState::Pending
    );
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let applied = client.read_proposal(&retried).await.unwrap().value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert_eq!(
        applied.application_status().unwrap().state,
        registry_breg_client::BRegProposalApplicationState::Applied
    );
    assert_eq!(applied.application().unwrap().effect_digest, frozen.1);
    drop(service);
    fixture.finish().await;
}
