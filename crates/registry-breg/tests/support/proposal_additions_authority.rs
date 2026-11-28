// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

async fn with_source(source: Value) -> client_http::ClientFixture {
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    client_http::ClientFixture::start_with_mutations(
        compile(source),
        claims("author", "zone-a"),
        move |mutations| {
            mutations.with_proposal_review_substitute_for_test(local_review_binding(), review)
        },
    )
    .await
}

async fn request(base: &str, profile: &str, id: &str, etag: &str, key: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!(
            "{base}/v1/proposals/{id}/additions/other?accessProfile={profile}"
        ))
        .header("if-match", etag)
        .header("idempotency-key", key)
        .header("content-type", "text/plain")
        .body("supporting-file")
        .send()
        .await
        .unwrap()
}

fn etag(proposal: &registry_breg_client::BRegProposal) -> String {
    serde_json::to_value(proposal).unwrap()["additions"]["other"]["links"]["add"]["ifMatch"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn count(fixture: &client_http::ClientFixture) -> i64 {
    fixture
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_proposal_additions",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn additions_require_add_even_when_the_caller_holds_edit_or_get() {
    let mut source = addition_source();
    for (profile, operation) in [("get-and-edit", "edit"), ("get-only", "get")] {
        let mut restricted = source["accessProfiles"]["clerk"].clone();
        restricted["default"] = json!(false);
        restricted["permissions"]["actions"] = json!([]);
        let grant = &mut restricted["permissions"]["proposals"][0];
        grant["operations"] = if operation == "edit" {
            json!(["get", "edit"])
        } else {
            json!(["get"])
        };
        grant["readableAttachments"] = if operation == "get" {
            json!(["other"])
        } else {
            json!([])
        };
        grant["writableAttachments"] = json!([]);
        source["accessProfiles"][profile] = restricted;
    }
    let fixture = with_source(source).await;
    let proposal = submitted_addition_proposal(&fixture, "operation-grant").await;
    for profile in ["get-and-edit", "get-only"] {
        let refused = request(
            &fixture.http.base_url,
            profile,
            proposal.id(),
            &etag(&proposal),
            profile,
        )
        .await;
        assert_eq!(refused.status(), 404, "{profile}");
        assert_eq!(
            refused.json::<Value>().await.unwrap()["code"],
            "resource.not_found"
        );
    }
    assert_eq!(count(&fixture).await, 0);
    assert_eq!(
        add(
            &fixture,
            proposal.id(),
            &etag(&proposal),
            "operation-allowed",
            "text/plain",
            b"allowed"
        )
        .await
        .status(),
        200
    );
    fixture.finish().await;
}

#[tokio::test]
async fn additions_refuse_a_non_owner() {
    let fixture = fixture().await;
    let proposal = submitted_addition_proposal(&fixture, "non-owner").await;
    let other = fixture.client_for(claims("other-author", "zone-a")).await;
    let refused = request(
        &other.base_url,
        "clerk",
        proposal.id(),
        &etag(&proposal),
        "non-owner-add",
    )
    .await;
    assert_eq!(refused.status(), 404);
    assert_eq!(count(&fixture).await, 0);
    drop(other);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_refuse_an_owner_outside_the_row_boundary() {
    let fixture = fixture().await;
    let proposal = submitted_addition_proposal(&fixture, "outside-row").await;
    let target =
        uuid::Uuid::parse_str(proposal.input().unwrap()["target"].as_str().unwrap()).unwrap();
    let entity = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"=$2 WHERE record_id=$1",
                entity.physical_table, entity.fields["jurisdiction"].physical_name
            ),
            &[&target, &"zone-b"],
        )
        .await
        .unwrap();
    let refused = request(
        &fixture.http.base_url,
        "clerk",
        proposal.id(),
        &etag(&proposal),
        "outside-row-add",
    )
    .await;
    assert_eq!(refused.status(), 412);
    assert_eq!(count(&fixture).await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_refuse_a_standing_agent() {
    let fixture = fixture().await;
    let proposal = submitted_addition_proposal(&fixture, "standing-agent").await;
    let agent = VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Agent,
    )
    .unwrap();
    let agent = fixture.client_for(agent).await;
    let refused = request(
        &agent.base_url,
        "clerk",
        proposal.id(),
        &etag(&proposal),
        "standing-agent-add",
    )
    .await;
    assert_eq!(refused.status(), 404);
    assert_eq!(count(&fixture).await, 0);
    drop(agent);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_recheck_a_stale_task_grant_before_writing() {
    use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
    use registry_breg::task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker};
    use registry_platform_httputil::FetchUrlPolicy;
    use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
    use registry_platform_testing::{oidc_verifier_config, MockIdp};
    struct Current(Arc<AtomicBool>);
    impl TaskGrantStatusChecker for Current {
        fn check<'a>(
            &'a self,
            _: &'a TaskGrantBinding,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>,
        > {
            Box::pin(async move {
                if self.0.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(TaskGrantError::Refused)
                }
            })
        }
    }
    let mut source = addition_source();
    let mut permission = source["accessProfiles"]["clerk"]["permissions"]["proposals"][0].clone();
    permission["operations"] = json!(["get", "add"]);
    permission["readableAttachments"] = json!(["other"]);
    permission["writableAttachments"] = json!(["other"]);
    source["accessProfiles"]["task-adder"] = json!({"actorKind":"agent","requesterClients":["agent-client"],
        "principalClaim":"sub","requiredScopes":["proposal:manage"],"requiredPurposes":["registry-administration"],
        "taskGrant":{"sourceIssuer":"https://casework.example"},"permissions":{"proposals":[permission]}});
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
            FetchUrlPolicy::https_or_loopback(),
        )),
        AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
    )
    .unwrap();
    let human=auth.authenticate(&idp.mint_token(json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client",
        "registry_actor_kind":"human","registry_purpose":"registry-administration","scope":"proposal:manage","jurisdiction":"zone-a"}))).await.unwrap();
    let current = Arc::new(AtomicBool::new(true));
    let check = current.clone();
    let review = Arc::new(LocalReview {
        calls: 0.into(),
        mode: 0.into(),
        result_id: uuid::Uuid::new_v4(),
    });
    let fixture =
        client_http::ClientFixture::start_with_mutations(registry, human, move |mutations| {
            mutations
                .with_task_status(Arc::new(Current(check)))
                .with_proposal_review_substitute_for_test(local_review_binding(), review)
        })
        .await;
    let proposal = submitted_addition_proposal(&fixture, "stale-grant").await;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let caller=auth.authenticate(&idp.mint_token(json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client",
        "registry_actor_kind":"agent","registry_purpose":"registry-administration","scope":"proposal:manage",
        "registry_grant_id":"00000000-0000-4000-8000-000000000071","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":"urn:example:breg","registry_grant_exp":expiry,"exp":expiry,
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":format!("proposal:{}",proposal.id()),"operations":["get","add"]}]},
        "identity":{"jurisdiction":"zone-a"},"jurisdiction":"zone-b"}))).await.unwrap();
    let agent = fixture.client_for(caller).await;
    let contract = agent
        .client
        .registry_contract(Some("task-adder"))
        .await
        .unwrap()
        .value;
    let proposal = agent
        .client
        .get_proposal(
            &contract.select_proposal_get("task-adder").unwrap(),
            proposal.id(),
        )
        .await
        .unwrap()
        .value;
    let added = agent
        .client
        .add_proposal_addition(
            &proposal,
            "other",
            "text/plain",
            b"allowed",
            &key("live-grant-add"),
        )
        .await
        .unwrap()
        .value;
    assert_eq!(count(&fixture).await, 1);
    current.store(false, Ordering::SeqCst);
    let refused = request(
        &agent.base_url,
        "task-adder",
        added.id(),
        &etag(&added),
        "stale-grant-add",
    )
    .await;
    assert_eq!(refused.status(), 412);
    assert_eq!(count(&fixture).await, 1);
    drop(agent);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_refuse_blocked_applied_and_changes_requested_proposals() {
    for state in ["blocked", "applied", "changes-requested"] {
        let review = Arc::new(LocalReview {
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
        let mut proposal = submitted_addition_proposal(&fixture, state).await;
        if state == "blocked" {
            fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_state SET blocked_reason='package-changed'",&[]).await.unwrap();
        } else {
            let status = if state == "applied" {
                registry_review_client::ReviewResultStatus::Approved
            } else {
                registry_review_client::ReviewResultStatus::ChangesRequested
            };
            retain_queue_review(&fixture, &proposal, &review, status, false, true).await;
            proposal = fixture
                .http
                .client
                .read_proposal(&proposal)
                .await
                .unwrap()
                .value;
            if state == "applied" {
                proposal=fixture.http.client.execute_proposal(&fixture.http.client.prepare_proposal(&proposal,"apply",
                    json!({"submissionVersion":proposal.submission_version(),"effectDigest":proposal.effect_digest().unwrap()}),
                    &key("applied-before-add")).unwrap()).await.unwrap().value;
            }
        }
        proposal = fixture
            .http
            .client
            .read_proposal(&proposal)
            .await
            .unwrap()
            .value;
        let value = serde_json::to_value(&proposal).unwrap();
        assert_eq!(
            value["additions"]["other"]["links"]["add"]["availability"]["available"], false,
            "{state}"
        );
        assert_eq!(
            request(
                &fixture.http.base_url,
                "clerk",
                proposal.id(),
                &etag(&proposal),
                &format!("{state}-refused")
            )
            .await
            .status(),
            412,
            "{state}"
        );
        assert_eq!(count(&fixture).await, 0);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn additions_racing_for_the_last_place_commit_exactly_one_file() {
    let fixture = fixture().await;
    let proposal = submitted_addition_proposal(&fixture, "last-place").await;
    let proposal = fixture
        .http
        .client
        .add_proposal_addition(
            &proposal,
            "other",
            "text/plain",
            b"first",
            &key("last-place-first"),
        )
        .await
        .unwrap()
        .value;
    let condition = etag(&proposal);
    let (left, right) = tokio::join!(
        add(
            &fixture,
            proposal.id(),
            &condition,
            "last-place-left",
            "text/plain",
            b"left"
        ),
        add(
            &fixture,
            proposal.id(),
            &condition,
            "last-place-right",
            "text/plain",
            b"right"
        )
    );
    let mut success = 0;
    for response in [left, right] {
        match response.status().as_u16() {
            200 => success += 1,
            412 => {}
            409 => assert_eq!(
                response.json::<Value>().await.unwrap()["code"],
                "attachment.limit-reached"
            ),
            status => panic!("unexpected addition race status {status}"),
        }
    }
    assert_eq!(success, 1);
    assert_eq!(count(&fixture).await, 2);
    fixture.finish().await;
}

#[tokio::test]
async fn additions_reviewer_cannot_download_a_file_missing_from_the_live_context() {
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
    let fixture = with_source(source).await;
    let first = submitted_addition_proposal(&fixture, "context-first").await;
    let first = fixture
        .http
        .client
        .add_proposal_addition(
            &first,
            "other",
            "text/plain",
            b"first",
            &key("context-first-add"),
        )
        .await
        .unwrap()
        .value;
    let second = submitted_addition_proposal(&fixture, "context-second").await;
    let second = fixture
        .http
        .client
        .add_proposal_addition(
            &second,
            "other",
            "text/plain",
            b"second",
            &key("context-second-add"),
        )
        .await
        .unwrap()
        .value;
    let other_file = second.addition_slot("other").unwrap().items()[0].id();
    assert_eq!(
        fixture
            .http
            .client
            .download_proposal_addition(&second, other_file)
            .await
            .unwrap()
            .value
            .as_bytes(),
        b"second"
    );
    let reviewer = fixture.client_for(claims("reviewer", "zone-a")).await;
    let context: Value = reqwest::get(format!(
        "{}/v1/proposals/{}/review-context?accessProfile=reviewer",
        reviewer.base_url,
        first.id()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let documents = context["context"]["fields"]["otherDocuments"]
        .as_array()
        .unwrap();
    assert_eq!(documents.len(), 1);
    let path = documents[0]["download"]["path"].as_str().unwrap();
    let first_file = first.addition_slot("other").unwrap().items()[0].id();
    assert!(!path.contains(other_file));
    let forged = path.replace(first_file, other_file);
    let refused = reqwest::get(format!(
        "{}{forged}&accessProfile=reviewer",
        reviewer.base_url
    ))
    .await
    .unwrap();
    assert_eq!(refused.status(), 404);
    drop(reviewer);
    fixture.finish().await;
}
