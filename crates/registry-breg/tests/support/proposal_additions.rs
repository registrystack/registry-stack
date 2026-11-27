// SPDX-License-Identifier: Apache-2.0
use super::*;

fn addition_source() -> Value {
    let mut source = registry_source(false);
    source["reviewAuthorities"] =
        json!({"local-review":{"protocol":"id.registrystack.org/protocols/review/v1"}});
    let proposal = &mut source["actions"]["correct-name"]["execution"]["proposal"];
    proposal["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    proposal["additions"] = json!({"id":"other","maximumBytes":32,"maximumCount":2,"contentTypes":["text/plain"],"classification":"restricted"});
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
    grant["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("add"));
    grant["readableAttachments"]
        .as_array_mut()
        .unwrap()
        .push(json!("other"));
    grant["writableAttachments"]
        .as_array_mut()
        .unwrap()
        .push(json!("other"));
    source
}

async fn fixture() -> client_http::ClientFixture {
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    client_http::ClientFixture::start_with_mutations(
        compile(addition_source()),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await
}

async fn add(
    fixture: &client_http::ClientFixture,
    id: &str,
    etag: &str,
    key: &str,
    content_type: &str,
    bytes: &[u8],
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!(
            "{}/v1/proposals/{id}/additions/other?accessProfile=clerk",
            fixture.http.base_url
        ))
        .header("if-match", etag)
        .header("idempotency-key", key)
        .header("content-type", content_type)
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn additions_keep_the_submission_and_digest_but_fence_tabs_and_replay() {
    let fixture = fixture().await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "After", "add-start").await;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("add-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let before = serde_json::to_value(&submitted).unwrap();
    let etag = before["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .expect("add link");
    let first = add(
        &fixture,
        submitted.id(),
        etag,
        "addition-one",
        "text/plain",
        b"first",
    )
    .await;
    assert_eq!(first.status(), 200);
    let new_etag = first.headers()["etag"].to_str().unwrap().to_owned();
    let first_bytes = first.bytes().await.unwrap();
    let added: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(added["state"], "submitted");
    assert_eq!(added["submissionVersion"], before["submissionVersion"]);
    assert_eq!(added["effectDigest"], before["effectDigest"]);
    assert_ne!(new_etag, etag);
    assert!(added["revision"].as_u64().unwrap() > before["revision"].as_u64().unwrap());
    let replay = add(
        &fixture,
        submitted.id(),
        etag,
        "addition-one",
        "text/plain",
        b"first",
    )
    .await;
    assert_eq!(replay.status(), 200);
    assert_eq!(replay.bytes().await.unwrap(), first_bytes);
    assert_eq!(
        add(
            &fixture,
            submitted.id(),
            etag,
            "addition-one",
            "text/plain",
            b"changed"
        )
        .await
        .status(),
        409
    );
    assert_eq!(
        add(
            &fixture,
            submitted.id(),
            etag,
            "addition-stale",
            "text/plain",
            b"second"
        )
        .await
        .status(),
        412
    );
    for (kind, bytes, status, code) in [
        (
            "application/pdf",
            b"file".as_slice(),
            415,
            "attachment.content-type",
        ),
        (
            "text/plain",
            b"012345678901234567890123456789012",
            413,
            "attachment.too-large",
        ),
        ("text/plain", b"", 400, "request.invalid"),
    ] {
        let refusal = add(
            &fixture,
            submitted.id(),
            &new_etag,
            "addition-refused",
            kind,
            bytes,
        )
        .await;
        assert_eq!(refusal.status(), status);
        assert_eq!(refusal.json::<Value>().await.unwrap()["code"], code);
    }
    let download = &added["additions"]["other"]["items"][0]["links"]["download"];
    let response = reqwest::get(format!(
        "{}{}&accessProfile=clerk",
        fixture.http.base_url,
        download["path"].as_str().unwrap()
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.bytes().await.unwrap(), b"first".as_slice());
    let second = add(
        &fixture,
        submitted.id(),
        &new_etag,
        "addition-two",
        "text/plain",
        b"second",
    )
    .await;
    assert_eq!(second.status(), 200);
    let etag = second.headers()["etag"].to_str().unwrap().to_owned();
    let second: Value = second.json().await.unwrap();
    assert_eq!(
        second["additions"]["other"]["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        second["additions"]["other"]["links"]["add"]["availability"]["reason"],
        "limit-reached"
    );
    let limited = add(
        &fixture,
        submitted.id(),
        &etag,
        "addition-three",
        "text/plain",
        b"third",
    )
    .await;
    assert_eq!(limited.status(), 409);
    assert_eq!(
        limited.json::<Value>().await.unwrap()["code"],
        "attachment.limit-reached"
    );
    let rows = fixture.database.admin.query("SELECT payload FROM registry_internal.registry_outbox WHERE event_type='proposal.added'", &[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_keep_shared_blobs_live_until_their_retention_erases_them() {
    let fixture = fixture().await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "After", "retained-add-start").await;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("retained-add-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let before = serde_json::to_value(&submitted).unwrap();
    let etag = before["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap();
    let added = add(
        &fixture,
        submitted.id(),
        etag,
        "retained-add-one",
        "text/plain",
        b"shared",
    )
    .await;
    assert_eq!(added.status(), 200);
    let added: Value = added.json().await.unwrap();
    let other = start(&fixture, "Other", "other-add-start").await;
    let uploaded = client
        .upload_proposal_attachment(
            &other,
            "support",
            "text/plain",
            b"shared",
            &key("shared-upload"),
        )
        .await
        .unwrap()
        .value;
    client
        .delete_proposal_attachment(&uploaded, "support", &key("shared-remove"))
        .await
        .unwrap();
    let path = added["additions"]["other"]["items"][0]["links"]["download"]["path"]
        .as_str()
        .unwrap();
    let response = reqwest::get(format!(
        "{}{}&accessProfile=clerk",
        fixture.http.base_url, path
    ))
    .await
    .unwrap();
    assert_eq!(
        response.status(),
        200,
        "removing the draft file must keep the addition's bytes"
    );
    assert_eq!(response.bytes().await.unwrap(), b"shared".as_slice());
    let current = client.read_proposal(&submitted).await.unwrap().value;
    client
        .execute_proposal(
            &client
                .prepare_proposal(&current, "cancel", json!({}), &key("retained-add-cancel"))
                .unwrap(),
        )
        .await
        .unwrap();
    let (mut migration, task) = fixture.database.connect_migration().await;
    let erased = registry_breg::proposal_retention::erase_proposal_detail(
        &mut migration,
        &fixture.registry,
        registry_breg::proposal_retention::ProposalDetailErasureScope {
            action_id: "correct-name",
            proposal_id: uuid::Uuid::parse_str(submitted.id()).unwrap(),
            submission_version: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(erased.attachment_references, 1);
    let row = fixture.database.admin.query_one("SELECT
        (SELECT count(*) FROM registry_internal.registry_proposal_additions WHERE erased_at IS NULL),
        (SELECT count(*) FROM registry_internal.registry_attachment_blobs)", &[]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
    assert_eq!(row.get::<_, i64>(1), 0);
    drop(migration);
    task.abort();
    fixture.finish().await;
}

#[tokio::test]
async fn additions_reviewer_reads_live_files_under_the_exact_context_binding() {
    let mut source = addition_source();
    source["actions"]["correct-name"]["execution"]["proposal"]["reviewContext"] = json!({"id":"supporting-review",
        "fields":{"otherDocuments":{"type":"additions","slot":"other"}}});
    let mut reviewer = source["accessProfiles"]["clerk"].clone();
    reviewer["default"] = json!(false);
    reviewer["permissions"]["actions"] = json!([]);
    reviewer["permissions"]["records"] = json!([]);
    let grant = &mut reviewer["permissions"]["proposals"][0];
    grant["operations"] = json!(["get-review-context"]);
    grant.as_object_mut().unwrap().remove("ownership");
    grant["readableInputs"] = json!([]);
    grant["readableAttachments"] = json!([]);
    grant["writableAttachments"] = json!([]);
    grant["readableContextFields"] = json!(["otherDocuments"]);
    source["accessProfiles"]["reviewer"] = reviewer;
    let mut hidden = source["accessProfiles"]["clerk"].clone();
    hidden["default"] = json!(false);
    hidden["permissions"]["actions"] = json!([]);
    hidden["permissions"]["proposals"][0]["operations"] = json!(["get"]);
    hidden["permissions"]["proposals"][0]["readableAttachments"] = json!([]);
    hidden["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    source["accessProfiles"]["no-files"] = hidden;
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await;
    let reviewer_http = client_http::ClientHttp::start(
        registry_breg::api::router(fixture.service()),
        claims("reviewer", "zone-a"),
    )
    .await;
    let draft = start(&fixture, "Reviewed", "review-add-start").await;
    let client = &fixture.http.client;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("review-add-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let value = serde_json::to_value(&submitted).unwrap();
    let etag = value["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap();
    let added = add(
        &fixture,
        submitted.id(),
        etag,
        "review-add-one",
        "text/plain",
        b"review-file",
    )
    .await;
    assert_eq!(added.status(), 200);
    let added: Value = added.json().await.unwrap();
    let context = reqwest::get(format!(
        "{}/v1/proposals/{}/review-context?accessProfile=reviewer",
        reviewer_http.base_url,
        submitted.id()
    ))
    .await
    .unwrap();
    assert_eq!(context.status(), 200);
    let context: Value = context.json().await.unwrap();
    assert_eq!(context["effectDigest"], added["effectDigest"]);
    let documents = context["context"]["fields"]["otherDocuments"]
        .as_array()
        .unwrap();
    assert_eq!(documents.len(), 1);
    let path = documents[0]["download"]["path"].as_str().unwrap();
    assert!(path.contains("/additions/"));
    let downloaded = reqwest::get(format!(
        "{}{}&accessProfile=reviewer",
        reviewer_http.base_url, path
    ))
    .await
    .unwrap();
    assert_eq!(downloaded.status(), 200);
    assert_eq!(downloaded.bytes().await.unwrap(), b"review-file".as_slice());
    let wrong = path.replace("submissionVersion=1", "submissionVersion=2");
    assert_eq!(
        reqwest::get(format!(
            "{}{}&accessProfile=reviewer",
            reviewer_http.base_url, wrong
        ))
        .await
        .unwrap()
        .status(),
        404
    );
    let wrong = path.replace(
        "reviewContextField=otherDocuments",
        "reviewContextField=missing",
    );
    assert_eq!(
        reqwest::get(format!(
            "{}{}&accessProfile=reviewer",
            reviewer_http.base_url, wrong
        ))
        .await
        .unwrap()
        .status(),
        404
    );
    for digest in [
        context["effectDigest"].as_str().unwrap(),
        context["context"]["contract"]["schemaDigest"]
            .as_str()
            .unwrap(),
    ] {
        let wrong = path.replace(
            &digest.replace(':', "%3A"),
            &format!("sha256%3A{}", "f".repeat(64)),
        );
        assert_eq!(
            reqwest::get(format!(
                "{}{}&accessProfile=reviewer",
                reviewer_http.base_url, wrong
            ))
            .await
            .unwrap()
            .status(),
            404
        );
    }
    let hidden = reqwest::get(format!(
        "{}/v1/proposals/{}?accessProfile=no-files",
        fixture.http.base_url,
        submitted.id()
    ))
    .await
    .unwrap();
    assert_eq!(hidden.status(), 200);
    assert!(hidden
        .json::<Value>()
        .await
        .unwrap()
        .get("additions")
        .is_none());
    let download = added["additions"]["other"]["items"][0]["links"]["download"]["path"]
        .as_str()
        .unwrap();
    assert_eq!(
        reqwest::get(format!(
            "{}{}&accessProfile=no-files",
            fixture.http.base_url, download
        ))
        .await
        .unwrap()
        .status(),
        404
    );
    let current = client.read_proposal(&submitted).await.unwrap().value;
    let revised = client
        .execute_proposal(
            &client
                .prepare_proposal(&current, "revise", json!({}), &key("review-add-revise"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let revised = serde_json::to_value(&revised).unwrap();
    assert_eq!(revised["submissionVersion"], 2);
    assert!(revised["additions"]["other"]["items"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        reqwest::get(format!(
            "{}{}&accessProfile=reviewer",
            reviewer_http.base_url, path
        ))
        .await
        .unwrap()
        .status(),
        404
    );
    drop(reviewer_http);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_leave_the_frozen_manifest_unchanged_and_apply_still_succeeds() {
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let injected = review.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(addition_source()),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), injected)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Applied", "apply-add-start").await;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("apply-add-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let id = uuid::Uuid::parse_str(submitted.id()).unwrap();
    let snapshot: Value = fixture.database.admin.query_one("SELECT snapshot FROM registry_internal.registry_proposal_submissions WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    let value = serde_json::to_value(&submitted).unwrap();
    let etag = value["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap();
    assert_eq!(
        add(
            &fixture,
            submitted.id(),
            etag,
            "apply-add-one",
            "text/plain",
            b"support"
        )
        .await
        .status(),
        200
    );
    let after: Value = fixture.database.admin.query_one("SELECT snapshot FROM registry_internal.registry_proposal_submissions WHERE proposal_id=$1", &[&id]).await.unwrap().get(0);
    assert_eq!(after, snapshot);
    retain_queue_review(
        &fixture,
        &submitted,
        &review,
        registry_review_client::ReviewResultStatus::Approved,
        false,
        true,
    )
    .await;
    let current = client.read_proposal(&submitted).await.unwrap().value;
    let current_value = serde_json::to_value(&current).unwrap();
    let closed = current_value["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap();
    assert_eq!(
        add(
            &fixture,
            current.id(),
            closed,
            "approved-add",
            "text/plain",
            b"too late"
        )
        .await
        .status(),
        412
    );
    let applied = client
        .execute_proposal(
            &client
                .prepare_proposal(
                    &current,
                    "apply",
                    json!({"submissionVersion":current.submission_version(),
        "effectDigest":current.effect_digest().unwrap()}),
                    &key("apply-after-addition"),
                )
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(applied.state(), BRegProposalState::Applied);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_emit_a_value_free_event_and_enqueue_the_selected_hook() {
    let mut source = addition_source();
    source["actions"]["correct-name"]["execution"]["proposal"]["hooks"] = json!([{"id":"on-add","transitions":["added"],
        "handler":{"type":"rhai","script":"hooks/on-add.rhai","abi":"registry.hook-handler/v1"}}]);
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let registry = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "hooks/on-add.rhai".into(),
            bytes: b"fn handle(ctx) { #{answer: \"none\"} }".to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap();
    let review = std::sync::Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry,
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await;
    let client = &fixture.http.client;
    let draft = start(&fixture, "Event", "event-add-start").await;
    let submitted = client
        .execute_proposal(
            &client
                .prepare_proposal(&draft, "submit", json!({}), &key("event-add-submit"))
                .unwrap(),
        )
        .await
        .unwrap()
        .value;
    let value = serde_json::to_value(&submitted).unwrap();
    let etag = value["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap();
    assert_eq!(
        add(
            &fixture,
            submitted.id(),
            etag,
            "event-add-one",
            "text/plain",
            b"addition-private-bytes-canary"
        )
        .await
        .status(),
        200
    );
    let row = fixture.database.admin.query_one("SELECT payload FROM registry_internal.registry_outbox WHERE event_type='proposal.added'",&[]).await.unwrap();
    let bytes: Vec<u8> = row.get(0);
    assert!(!String::from_utf8_lossy(&bytes).contains("addition-private-bytes-canary"));
    let envelope = registry_platform_hooks::HookEnvelope::from_canonical_bytes(
        &bytes,
        &registry_platform_hooks::EnvelopeLimits::default(),
    )
    .unwrap();
    assert_eq!(envelope.data["transition"], "added");
    assert_eq!(envelope.data["state"], "submitted");
    assert_eq!(envelope.data["fromState"], "submitted");
    let hooks:i64 = fixture.database.admin.query_one("SELECT count(*) FROM registry_internal.registry_webhook_deliveries d
        JOIN registry_internal.registry_outbox e USING (event_id) WHERE e.event_type='proposal.added'",&[]).await.unwrap().get(0);
    assert_eq!(hooks, 1);
    let audit = serde_json::to_string(&fixture.audit_capture.entries()).unwrap();
    assert!(!audit.contains("addition-private-bytes-canary"));
    let row = fixture.database.admin.query_one("SELECT added_by,added_at IS NOT NULL FROM registry_internal.registry_proposal_additions",&[]).await.unwrap();
    assert!(row.get::<_, String>(0).starts_with("hmac-sha256:"));
    assert!(row.get::<_, bool>(1));
    fixture.finish().await;
}

#[tokio::test]
async fn additions_refuse_draft_approved_rejected_cancelled_and_revised_work() {
    for state in ["draft", "approved", "rejected", "cancelled", "revised"] {
        let source = addition_source();
        let policy =
            source["actions"]["correct-name"]["execution"]["proposal"]["review"]["policy"].clone();
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
        let draft = start(&fixture, "Closed", &format!("{state}-add-start")).await;
        let mut current = if state == "draft" {
            draft
        } else {
            client
                .execute_proposal(
                    &client
                        .prepare_proposal(
                            &draft,
                            "submit",
                            json!({}),
                            &key(&format!("{state}-add-submit")),
                        )
                        .unwrap(),
                )
                .await
                .unwrap()
                .value
        };
        match state {
            "approved" => {
                retain_queue_review(
                    &fixture,
                    &current,
                    &review,
                    registry_review_client::ReviewResultStatus::Approved,
                    false,
                    true,
                )
                .await
            }
            "rejected" => inject_review_decision(&fixture, &review, policy, "rejected").await,
            "cancelled" | "revised" => {
                let operation = if state == "cancelled" {
                    "cancel"
                } else {
                    "revise"
                };
                current = client
                    .execute_proposal(
                        &client
                            .prepare_proposal(
                                &current,
                                operation,
                                json!({}),
                                &key(&format!("{state}-add-close")),
                            )
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .value;
            }
            _ => {}
        }
        let current = client.read_proposal(&current).await.unwrap().value;
        let value = serde_json::to_value(&current).unwrap();
        let link = &value["additions"]["other"]["links"]["add"];
        assert_eq!(link["availability"]["available"], false, "{state}");
        let refusal = add(
            &fixture,
            current.id(),
            link["ifMatch"].as_str().unwrap(),
            &format!("{state}-add-refused"),
            "text/plain",
            b"closed",
        )
        .await;
        assert_eq!(
            refusal.status(),
            if state == "rejected" { 409 } else { 412 },
            "{state}"
        );
        if state == "rejected" {
            assert_eq!(
                refusal.json::<Value>().await.unwrap()["code"],
                "proposal.rejected"
            );
        }
        fixture.finish().await;
    }
}
