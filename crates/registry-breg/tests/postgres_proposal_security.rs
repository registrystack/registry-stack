// SPDX-License-Identifier: Apache-2.0
//! Signed Proposal grants preserve receipt identity and current Record disclosure.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/consent_fixture.rs"]
#[allow(dead_code)]
mod consent_fixture;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    auth::{AuthorityClaimConfig, RegistryAuthenticator},
    compiler::{compile_project, CompileProfile},
    contract::parse_project_json,
    task_grant::{TaskGrantBinding, TaskGrantError, TaskGrantStatusChecker},
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

fn source(membership: bool) -> Value {
    let boundary = json!([{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]);
    let targets = json!([{"recordType":"target","rowBoundaries":boundary}]);
    let mut reader = json!({"recordType":"target","operations":["get","list"],"readableFields":["name"],
        "rowBoundaries":[{"field":"jurisdiction","claim":"recordJurisdiction","operator":"equals"}]});
    if membership {
        reader["membershipBoundaries"] = json!([{"field":"organization","membershipRecordType":"membership",
            "membershipKeyField":"organization","principalField":"principal","activeField":"active"}]);
    }
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-security","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://proposal.example.test"},
        "datasets":[{"id":"directory"}],"recordTypes":[
            {"id":"organization","primaryDataset":"directory","route":"organizations","mutationMode":"mutable",
                "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"}]},
            {"id":"membership","primaryDataset":"directory","route":"memberships","mutationMode":"mutable","fields":[
                {"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"},
                {"id":"principal","type":"string","required":true,"maximumLength":64,"classification":"restricted"},
                {"id":"active","type":"boolean","required":true,"classification":"internal"}]},
            {"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
                "mutationPolicy":{"patch":"proposal-required"},"fields":[
                    {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"organization","type":"reference","target":"organization","required":true,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},
            "reviewContext":{"id":"review-name","fields":{"currentName":{"type":"record","input":"target","field":"name"},"proposedName":{"type":"input","input":"value"}}},
            "application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
            "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"registry_principal","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{"records":[
                {"recordType":"organization","operations":["create","get"],"readableFields":["name"],"writableFields":["name"],"rowBoundaries":"unrestricted"},
                {"recordType":"membership","operations":["create","get","patch"],"readableFields":["organization","principal","active"],
                    "writableFields":["organization","principal","active"],"rowBoundaries":"unrestricted"},
                {"recordType":"target","operations":["create","get"],"readableFields":["name","jurisdiction","organization"],
                    "writableFields":["name","jurisdiction","organization"],"rowBoundaries":boundary}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":targets}],
                "proposals":[{"action":"correct-name","operations":["get","edit","submit","cancel"],"ownership":"caller","targets":targets}]}},
            {"id":"task-reviewer","principalClaim":"registry_principal","actorKind":"agent","requesterClients":["agent-client"],
                "requiredScopes":["proposal:manage"],"requiredPurposes":["registry-administration"],
                "taskGrant":{"sourceIssuer":"https://casework.example"},"permissions":{"records":[reader],
                    "actions":[{"action":"correct-name","operations":["start"],"targets":targets}],
                    "proposals":[{"action":"correct-name","operations":["get","edit","submit","get-review-context"],
                        "ownership":"caller","readableContextFields":["currentName","proposedName"],"targets":targets}]}}]});
    source
}

fn compile(source: Value) -> registry_breg::CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn registry(membership: bool) -> registry_breg::CompiledRegistry {
    compile(source(membership))
}

fn clerk() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap()
}

struct Status {
    active: AtomicBool,
    calls: AtomicUsize,
}
impl TaskGrantStatusChecker for Status {
    fn check<'a>(
        &'a self,
        _: &'a TaskGrantBinding,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TaskGrantError>> + Send + 'a>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.active.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(TaskGrantError::Refused)
            }
        })
    }
}

async fn authenticator(
    registry: &registry_breg::CompiledRegistry,
    idp: &MockIdp,
) -> RegistryAuthenticator {
    let mut verifier = oidc_verifier_config(idp.issuer(), vec!["urn:example:breg".into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    RegistryAuthenticator::new(
        registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into())),
    )
    .unwrap()
}

fn token(grant: u64, permissions: Value) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({"aud":"urn:example:breg","sub":"author","azp":"agent-client","registry_principal":"author",
        "registry_actor_kind":"agent","registry_purpose":"registry-administration","scope":"proposal:manage",
        "registry_grant_id":format!("00000000-0000-4000-8000-{grant:012x}"),"registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":"urn:example:breg","registry_grant_exp":now+600,
        "registry_grant_bounds":{"type":"breg","permissions":permissions},
        "identity":{"jurisdiction":"zone-a","recordJurisdiction":"zone-a"},"jurisdiction":"zone-b","recordJurisdiction":"zone-b"})
}

async fn send(
    http: &client_http::ClientHttp,
    method: Method,
    path: &str,
    body: Value,
    key: Option<&str>,
    etag: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{}{path}", http.base_url))
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    if let Some(etag) = etag {
        request = request.header("if-match", etag);
    }
    if !body.is_null() {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned());
    (status, response.json().await.unwrap(), etag)
}

async fn create(http: &client_http::ClientHttp, route: &str, data: Value, key: &str) -> String {
    let (status, value, _) = send(
        http,
        Method::POST,
        &format!("/v1/records/{route}?accessProfile=clerk"),
        json!({"data":data}),
        Some(key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn seed(fixture: &client_http::ClientFixture) -> (String, String) {
    let organization = create(
        &fixture.http,
        "organizations",
        json!({"name":"Unit"}),
        "organization",
    )
    .await;
    let target = create(
        &fixture.http,
        "targets",
        json!({"name":"current-name-canary","jurisdiction":"zone-a","organization":organization}),
        "target",
    )
    .await;
    (organization, target)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_proposal_start_and_lifecycle_receipts_reject_sibling_grants() {
    let status = Arc::new(Status {
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let checker = status.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry(false),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let (_, target) = seed(&fixture).await;
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let start_bounds = json!([{"collection":"action:correct-name","operations":["start"]}]);
    let first = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(1, start_bounds.clone())))
                .await
                .unwrap(),
        )
        .await;
    let sibling = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(2, start_bounds)))
                .await
                .unwrap(),
        )
        .await;
    let path = "/v1/actions/correct-name/proposals?accessProfile=task-reviewer";
    let body = json!({"input":{"target":target,"value":"After"}});
    let (code, draft, etag) = send(
        &first,
        Method::POST,
        path,
        body.clone(),
        Some("same-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let (code, replay, _) = send(
        &first,
        Method::POST,
        path,
        body.clone(),
        Some("same-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{replay}");
    assert_eq!(draft, replay);
    let (code, error, _) = send(&sibling, Method::POST, path, body, Some("same-start"), None).await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "sibling Start grant recovered receipt: {error}"
    );
    let id = draft["id"].as_str().unwrap();
    let lifecycle_bounds = json!([{"collection":format!("proposal:{id}"),"operations":["get","edit","submit","get-review-context"]}]);
    let lifecycle = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(3, lifecycle_bounds.clone())))
                .await
                .unwrap(),
        )
        .await;
    let sibling_lifecycle = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(4, lifecycle_bounds)))
                .await
                .unwrap(),
        )
        .await;
    let path = format!("/v1/proposals/{id}/edit?accessProfile=task-reviewer");
    let body = json!({"input":{"target":target,"value":"Edited"}});
    let (code, edited, _) = send(
        &lifecycle,
        Method::POST,
        &path,
        body.clone(),
        Some("same-edit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{edited}");
    let (code, replay, _) = send(
        &lifecycle,
        Method::POST,
        &path,
        body.clone(),
        Some("same-edit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{replay}");
    assert_eq!(edited, replay);
    let (code, error, _) = send(
        &sibling_lifecycle,
        Method::POST,
        &path,
        body,
        Some("same-edit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(
        code,
        StatusCode::CONFLICT,
        "sibling lifecycle grant recovered receipt: {error}"
    );
    let count: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    let revision: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT workflow_revision FROM registry_internal.registry_proposal_state",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(revision, 2, "siblings cause no transition");
    status.active.store(false, Ordering::SeqCst);
    let (code, _, _) = send(
        &first,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=task-reviewer",
        json!({"input":{"target":target,"value":"After"}}),
        Some("same-start"),
        None,
    )
    .await;
    assert_eq!(
        code,
        StatusCode::PRECONDITION_FAILED,
        "replay checks current grant status"
    );
    assert!(status.calls.load(Ordering::SeqCst) >= 7);
    drop(first);
    drop(sibling);
    drop(lifecycle);
    drop(sibling_lifecycle);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_context_requires_record_grant_and_current_membership() {
    let status = Arc::new(Status {
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let checker = status.clone();
    let mut source = source(true);
    source["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["changes"] =
        json!({"type":"changes","recordType":"target","fields":["name"]});
    source["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("changes"));
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
        json!(["get", "list", "edit", "submit", "cancel"]);
    source["actions"][0]["execution"]["proposal"]["attachments"] = json!([
        {"id":"support","required":false,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"},
        {"id":"absent","required":false,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"},
        {"id":"private","required":false,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"}
    ]);
    source["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["document"] =
        json!({"type":"document","slot":"support"});
    source["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["optionalDocument"] =
        json!({"type":"document","slot":"absent"});
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] =
        json!(["support"]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
        json!(["support"]);
    source["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get-review-context"]);
    source["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"]
        .as_array_mut()
        .unwrap()
        .extend([json!("document"), json!("optionalDocument")]);
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let (organization, target) = seed(&fixture).await;
    let (code, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"Proposed"}}),
        Some("review-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let upload = reqwest::Client::new()
        .patch(format!(
            "{}/v1/proposals/{id}/attachments/support?accessProfile=clerk",
            fixture.http.base_url
        ))
        .header("if-match", etag.as_deref().unwrap())
        .header("idempotency-key", "review-document-upload")
        .header("content-type", "text/plain")
        .body("frozen-review-document")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let etag = upload.headers()["etag"].to_str().unwrap().to_owned();
    let (code, value, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("review-submit"),
        Some(&etag),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{value}");
    for path in [
        format!("/v1/proposals/{id}?accessProfile=clerk"),
        "/v1/proposals?accessProfile=clerk".to_owned(),
    ] {
        let (code, public, _) =
            send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(code, StatusCode::OK, "{public}");
        let serialized = public.to_string();
        for hidden in [
            "current-name-canary",
            "currentName",
            "proposedName",
            "acceptedBinding",
            "\"result\"",
            "uploadedBy",
            "submitterReference",
            "applierReference",
        ] {
            assert!(
                !serialized.contains(hidden),
                "ordinary Proposal read disclosed {hidden}"
            );
        }
    }
    for suffix in ["review-context", "review-status"] {
        let (code, public, _) = send(
            &fixture.http,
            Method::GET,
            &format!("/v1/proposals/{id}/{suffix}?accessProfile=clerk"),
            Value::Null,
            None,
            None,
        )
        .await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "ordinary reader gained {suffix}: {public}"
        );
    }
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let proposal_bound =
        json!({"collection":format!("proposal:{id}"),"operations":["get","get-review-context"]});
    let record_bound = json!({"collection":"targets","operations":["get","list"]});
    let composed = token(5, json!([proposal_bound, record_bound]));
    let reader = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(composed.clone()))
                .await
                .unwrap(),
        )
        .await;
    let path = format!("/v1/proposals/{id}/review-context?accessProfile=task-reviewer");
    let record_path = format!("/v1/records/targets/{target}?accessProfile=task-reviewer");
    assert_eq!(
        send(&reader, Method::GET, &record_path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (code, value, _) = send(&reader, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "absent membership released current Record: {value}"
    );
    assert!(!value.to_string().contains("current-name-canary"));
    let membership = create(
        &fixture.http,
        "memberships",
        json!({"organization":organization,"principal":"author","active":true}),
        "membership",
    )
    .await;
    assert_eq!(
        send(&reader, Method::GET, &record_path, Value::Null, None, None)
            .await
            .0,
        StatusCode::OK
    );
    let (code, value, _) = send(&reader, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "composed static Record and Proposal bounds: {value}"
    );
    assert_eq!(
        value["context"]["fields"]["currentName"],
        "current-name-canary"
    );
    assert_review_contract(&fixture.registry, &value);
    assert_eq!(
        value["context"]["fields"]["changes"],
        json!([{
            "recordId":target,"operation":"patch","before":{"name":"current-name-canary"},"after":{"name":"Proposed"}
        }])
    );
    let document = &value["context"]["fields"]["document"];
    assert_eq!(document["type"], "document");
    assert_eq!(document["byteSize"], "frozen-review-document".len());
    assert!(value["context"]["fields"]["optionalDocument"].is_null());
    let saved_download = format!(
        "{}&accessProfile=task-reviewer",
        document["download"]["path"].as_str().unwrap()
    );
    let response = reqwest::Client::new()
        .get(format!("{}{}", reader.base_url, saved_download))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/plain");
    assert_eq!(response.headers()["content-disposition"], "attachment");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        b"frozen-review-document"
    );
    let wrong_digest = format!("sha256%3A{}", "f".repeat(64));
    for refused in [
        format!("/v1/proposals/{id}?accessProfile=task-reviewer"),
        format!("/v1/proposals/{id}/attachments/support?submissionVersion=1&accessProfile=task-reviewer"),
        saved_download.replace("attachments/support", "attachments/private"),
        saved_download.replace("reviewContextField=document", "reviewContextField=optionalDocument"),
        saved_download.replace("submissionVersion=1", "submissionVersion=2"),
        saved_download.replace(value["effectDigest"].as_str().unwrap().replace(':', "%3A").as_str(), &wrong_digest),
        saved_download.replace(value["context"]["contract"]["schemaDigest"].as_str().unwrap().replace(':', "%3A").as_str(), &wrong_digest),
        saved_download.replace("accessProfile=task-reviewer", "accessProfile=clerk"),
    ] {
        let response = reqwest::Client::new().get(format!("{}{}", reader.base_url, refused)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{refused}");
    }
    for method in [Method::PATCH, Method::DELETE, Method::POST] {
        let denied_path = if method == Method::POST {
            format!("/v1/proposals/{id}/submit?accessProfile=task-reviewer")
        } else {
            saved_download.clone()
        };
        let response = reqwest::Client::new()
            .request(method, format!("{}{}", reader.base_url, denied_path))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let (code, concealed, _) = send(
        &reader,
        Method::GET,
        &format!("/v1/proposals/{id}/review-status?accessProfile=task-reviewer"),
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "context authority gained status: {concealed}"
    );
    for permissions in [
        json!([proposal_bound]),
        json!([proposal_bound,{"collection":"targets","operations":["get"]}]),
    ] {
        let caller = fixture
            .client_for(
                auth.authenticate(&idp.mint_token(token(6, permissions)))
                    .await
                    .unwrap(),
            )
            .await;
        let (code, value, _) = send(&caller, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "missing static Record permission disclosed context: {value}"
        );
        assert_eq!(
            reqwest::Client::new()
                .get(format!("{}{}", caller.base_url, saved_download))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    for (claim, value) in [
        (
            "registry_grant_source_issuer",
            json!("https://other.example"),
        ),
        (
            "identity",
            json!({"jurisdiction":"zone-a","recordJurisdiction":"zone-b"}),
        ),
    ] {
        let mut wrong = composed.clone();
        wrong[claim] = value;
        let caller = fixture
            .client_for(auth.authenticate(&idp.mint_token(wrong)).await.unwrap())
            .await;
        let (code, value, _) = send(&caller, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "mismatched source or row bound disclosed context: {value}"
        );
    }
    let entity = &fixture.registry.entities()["membership"];
    let column = &entity.fields["active"].physical_name;
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{column}\"=false WHERE record_id=$1::text::uuid",
                entity.physical_table
            ),
            &[&membership],
        )
        .await
        .unwrap();
    assert_eq!(
        send(&reader, Method::GET, &record_path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (code, value, _) = send(&reader, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "committed membership revocation disclosed context: {value}"
    );
    assert!(!value.to_string().contains("current-name-canary"));
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}{}", reader.base_url, saved_download))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "a saved document link must rerun current membership"
    );
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{column}\"=true WHERE record_id=$1::text::uuid",
                entity.physical_table
            ),
            &[&membership],
        )
        .await
        .unwrap();
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}{}", reader.base_url, saved_download))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    status.active.store(false, Ordering::SeqCst);
    assert_eq!(
        send(&reader, Method::GET, &path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}{}", reader.base_url, saved_download))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "a saved document link must check task-grant status"
    );
    status.active.store(true, Ordering::SeqCst);
    fixture.audit_capture.fail_after(1);
    let failed_audit = reqwest::Client::new()
        .get(format!("{}{}", reader.base_url, saved_download))
        .send()
        .await
        .unwrap();
    assert_eq!(
        failed_audit.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "terminal audit failure withholds exact document bytes"
    );
    assert!(!failed_audit
        .text()
        .await
        .unwrap()
        .contains("frozen-review-document"));
    drop(reader);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saved_review_document_requires_current_subject_consent() {
    let mut project = source(false);
    let consent = consent_fixture::source();
    let mut decision = consent["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == "consent-decision")
        .unwrap()
        .clone();
    decision["primaryDataset"] = json!("directory");
    decision["fields"][0]["target"] = json!("target");
    project["recordTypes"]
        .as_array_mut()
        .unwrap()
        .push(decision);
    let mut record_consent = consent["actions"][0].clone();
    record_consent["inputs"][0]["target"] = json!("target");
    project["actions"]
        .as_array_mut()
        .unwrap()
        .push(record_consent);
    project["recipients"] = json!({"organizations":[{"id":"review-org","name":"Review organization","contact":"privacy@example.test","clients":["agent-client"]}]});
    project["vocabularies"] = json!([
        {"id":"data-use-purpose","values":["registry-administration"]},
        {"id":"consent-decision","values":["given","withdrawn","refused","invalidated"]}
    ]);
    project["actions"][0]["execution"]["proposal"]["attachments"] = json!([
        {"id":"support","required":true,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"}
    ]);
    project["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["document"] =
        json!({"type":"document","slot":"support"});
    project["accessProfiles"][0]["permissions"]["proposals"][0]["readableAttachments"] =
        json!(["support"]);
    project["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
        json!(["support"]);
    project["accessProfiles"][0]["permissions"]["actions"].as_array_mut().unwrap().push(json!({"action":"record-consent","operations":["invoke"],
        "targets":[{"recordType":"target","rowBoundaries":"unrestricted"},{"recordType":"consent-decision","rowBoundaries":"unrestricted"}],"results":["decision"]}));
    project["accessProfiles"][1]["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("actions");
    project["accessProfiles"][1]["permissions"]["records"][0]["requireConsent"] =
        json!([{"record":"consent-decision","on":"id"}]);
    project["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get-review-context"]);
    project["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["currentName", "proposedName", "document"]);
    let status = Arc::new(Status {
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(project),
        clerk(),
        move |service| service.with_task_status(status),
    )
    .await;
    let (_, target) = seed(&fixture).await;
    let (code, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"Consented proposed name"}}),
        Some("consent-document-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let upload = reqwest::Client::new()
        .patch(format!(
            "{}/v1/proposals/{id}/attachments/support?accessProfile=clerk",
            fixture.http.base_url
        ))
        .header("if-match", etag.unwrap())
        .header("idempotency-key", "consent-document-upload")
        .header("content-type", "text/plain")
        .body("consent-bound-document-bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let etag = upload.headers()["etag"].to_str().unwrap().to_owned();
    let (code, submitted, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("consent-document-submit"),
        Some(&etag),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{submitted}");
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let reader = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(
                90,
                json!([
                    {"collection":format!("proposal:{id}"),"operations":["get-review-context"]},
                    {"collection":"targets","operations":["get","list"]}
                ]),
            )))
            .await
            .unwrap(),
        )
        .await;
    let context_path = format!("/v1/proposals/{id}/review-context?accessProfile=task-reviewer");
    assert_eq!(
        send(&reader, Method::GET, &context_path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND,
        "no current consent"
    );
    let consent_input = |decision: &str| {
        json!({"input":{"subject":target,"recipient":"review-org","purpose":"registry-administration",
        "scope":"task-reviewer","decision":decision,"effectiveAt":chrono::Utc::now().to_rfc3339(),"expiresAt":(chrono::Utc::now()+chrono::Duration::days(1)).to_rfc3339()}})
    };
    let (code, given, _) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/record-consent?accessProfile=clerk",
        consent_input("given"),
        Some("consent-document-given"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{given}");
    let (code, context, _) =
        send(&reader, Method::GET, &context_path, Value::Null, None, None).await;
    assert_eq!(code, StatusCode::OK, "{context}");
    assert_review_contract(&fixture.registry, &context);
    let path = format!(
        "{}&accessProfile=task-reviewer",
        context["context"]["fields"]["document"]["download"]["path"]
            .as_str()
            .unwrap()
    );
    let download = reqwest::Client::new()
        .get(format!("{}{}", reader.base_url, path))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        download.bytes().await.unwrap().as_ref(),
        b"consent-bound-document-bytes"
    );
    let (code, revoked, _) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/record-consent?accessProfile=clerk",
        consent_input("withdrawn"),
        Some("consent-document-withdrawn"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{revoked}");
    assert_eq!(
        send(&reader, Method::GET, &context_path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}{}", reader.base_url, path))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND,
        "cached document metadata cannot bypass current subject consent"
    );
    drop(reader);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_service_assessment_preserves_scope_actor_target_and_record_disclosure() {
    let mut project = source(false);
    let mut service = project["accessProfiles"][1].clone();
    service["id"] = json!("assessment");
    service["actorKind"] = json!("service");
    service["requiredScopes"] = json!(["proposal:assess"]);
    service["requiredPurposes"] = json!(["automatic-assessment"]);
    service.as_object_mut().unwrap().remove("taskGrant");
    service["permissions"]
        .as_object_mut()
        .unwrap()
        .remove("actions");
    service["permissions"]["proposals"][0]["operations"] = json!(["get-review-context"]);
    service["permissions"]["proposals"][0]
        .as_object_mut()
        .unwrap()
        .remove("ownership");
    let mut human = service.clone();
    human["id"] = json!("human-review");
    human["actorKind"] = json!("human");
    let mut narrow = service.clone();
    narrow["id"] = json!("narrow-assessment");
    narrow["permissions"]["proposals"][0]["readableContextFields"] = json!(["proposedName"]);
    project["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .extend([service, human, narrow]);
    let fixture = client_http::ClientFixture::start(compile(project), clerk()).await;
    let (_, target) = seed(&fixture).await;
    let (code, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"Frozen requested name"}}),
        Some("assessment-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let (code, submitted, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("assessment-submit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{submitted}");
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let claims = |scope: &str, purpose: &str, target_zone: &str, record_zone: &str| {
        json!({"aud":"urn:example:breg","sub":"assessor","azp":"agent-client",
            "registry_principal":"assessor","registry_actor_kind":"service",
            "registry_purpose":purpose,"scope":scope,
            "jurisdiction":target_zone,"recordJurisdiction":record_zone})
    };
    let caller = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(claims(
                "proposal:assess",
                "automatic-assessment",
                "zone-a",
                "zone-a",
            )))
            .await
            .unwrap(),
        )
        .await;
    let path = format!("/v1/proposals/{id}/review-context?accessProfile=assessment");
    let (code, context, _) = send(&caller, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(code, StatusCode::OK, "{context}");
    assert_eq!(context["submissionVersion"], submitted["submissionVersion"]);
    assert_eq!(context["effectDigest"], submitted["effectDigest"]);
    assert_eq!(
        context["context"]["fields"],
        json!({"currentName":"current-name-canary","proposedName":"Frozen requested name"})
    );
    assert_review_contract(&fixture.registry, &context);
    for suffix in [
        "review-context?accessProfile=human-review",
        "review-context?accessProfile=narrow-assessment",
        "review-context?accessProfile=clerk",
        "review-status?accessProfile=assessment",
    ] {
        let (code, concealed, _) = send(
            &caller,
            Method::GET,
            &format!("/v1/proposals/{id}/{suffix}"),
            Value::Null,
            None,
            None,
        )
        .await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "wrong purpose/profile disclosed context: {concealed}"
        );
        assert!(!concealed.to_string().contains("current-name-canary"));
    }
    for authority in [
        claims(
            "proposal:manage",
            "automatic-assessment",
            "zone-a",
            "zone-a",
        ),
        claims(
            "proposal:assess",
            "registry-administration",
            "zone-a",
            "zone-a",
        ),
        claims(
            "proposal:assess",
            "automatic-assessment",
            "zone-b",
            "zone-a",
        ),
        claims(
            "proposal:assess",
            "automatic-assessment",
            "zone-a",
            "zone-b",
        ),
    ] {
        let refused = fixture
            .client_for(auth.authenticate(&idp.mint_token(authority)).await.unwrap())
            .await;
        let (code, concealed, _) =
            send(&refused, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "assessment widened current authority: {concealed}"
        );
        assert!(!concealed.to_string().contains("current-name-canary"));
    }
    drop(caller);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_disclosures_refuse_a_signed_grant_expiring_during_terminal_audit() {
    use registry_breg::{
        audit::RegistryAudit,
        postgres::{PostgresRecordMutationService, RegistryLockKey},
    };
    use registry_platform_audit::{AuditProfile, AuditWriter};
    use std::{
        io::{self, Write},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    struct DelayedTerminal {
        expiry: u64,
        reached: Arc<AtomicBool>,
        was_current: Arc<AtomicBool>,
        entries: Arc<std::sync::Mutex<Vec<Value>>>,
    }
    impl Write for DelayedTerminal {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let returned = bytes
                .split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                .any(|entry| {
                    entry["record"]["phase"] == "terminal"
                        && entry["record"]["outcome"] == "returned"
                });
            if returned && !self.reached.swap(true, Ordering::SeqCst) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                self.was_current
                    .store(now.as_secs() < self.expiry, Ordering::SeqCst);
                // The real AuditWriter waits for this ordinary stream sink on
                // its writer thread. Its successful terminal append crosses
                // grant expiry, within the existing five-second write bound.
                let remaining = Duration::from_secs(self.expiry).saturating_sub(now);
                std::thread::sleep(remaining + Duration::from_millis(30));
            }
            self.entries.lock().unwrap().extend(
                bytes
                    .split(|byte| *byte == b'\n')
                    .filter_map(|line| serde_json::from_slice::<Value>(line).ok()),
            );
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let status = Arc::new(Status {
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let checker = status.clone();
    let mut source = source(false);
    source["actions"][0]["execution"]["proposal"]["attachments"] = json!([
        {"id":"support","required":false,"maximumBytes":4096,"contentTypes":["text/plain"],"classification":"restricted"}
    ]);
    source["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"]["document"] =
        json!({"type":"document","slot":"support"});
    source["accessProfiles"][1]["permissions"]["proposals"][0]["readableContextFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("document"));
    for profile in [0, 1] {
        source["accessProfiles"][profile]["permissions"]["proposals"][0]["readableAttachments"] =
            json!(["support"]);
    }
    source["accessProfiles"][0]["permissions"]["proposals"][0]["writableAttachments"] =
        json!(["support"]);
    source["accessProfiles"][1]["permissions"]["proposals"][0]["operations"] =
        json!(["get", "list", "edit", "submit", "get-review-context"]);
    let fixture = client_http::ClientFixture::start_with_mutations(
        compile(source),
        clerk(),
        move |service| service.with_task_status(checker),
    )
    .await;
    let (_, target) = seed(&fixture).await;
    let (code, draft, _) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"proposed-name-canary"}}),
        Some("audit-expiry-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let upload = reqwest::Client::new()
        .patch(format!(
            "{}/v1/proposals/{id}/attachments/support?accessProfile=clerk",
            fixture.http.base_url
        ))
        .header(
            "if-match",
            draft["attachments"]["support"]["links"]["upload"]["ifMatch"]
                .as_str()
                .unwrap(),
        )
        .header("idempotency-key", "audit-expiry-upload")
        .header("content-type", "text/plain")
        .body("attachment-disclosure-canary")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let uploaded: Value = upload.json().await.unwrap();
    let attachment = &uploaded["attachments"]["support"]["value"];
    assert_eq!(attachment["contentType"], "text/plain");
    assert_eq!(attachment["byteSize"], "attachment-disclosure-canary".len());
    assert!(attachment["sha256"].as_str().is_some());
    assert!(attachment.get("uploadedBy").is_none());
    let etag = uploaded["links"]["submit"]["ifMatch"].as_str().unwrap();
    let (code, submitted, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("audit-expiry-submit"),
        Some(etag),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{submitted}");
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let bounds = json!([
        {"collection":format!("proposal:{id}"),"operations":["get","list","get-review-context"]},
        {"collection":"targets","operations":["get","list"]}
    ]);
    let current = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token(80, bounds.clone())))
                .await
                .unwrap(),
        )
        .await;
    let (code, displayed, _) = send(
        &current,
        Method::GET,
        &format!("/v1/proposals/{id}/review-context?accessProfile=task-reviewer"),
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{displayed}");
    let review_download = format!(
        "{}&accessProfile=task-reviewer",
        displayed["context"]["fields"]["document"]["download"]["path"]
            .as_str()
            .unwrap()
    );
    for (index, path) in [
        format!("/v1/proposals/{id}?accessProfile=task-reviewer"),
        format!("/v1/proposals/{id}/review-context?accessProfile=task-reviewer"),
        "/v1/proposals?accessProfile=task-reviewer".to_owned(),
        format!(
            "/v1/proposals/{id}/attachments/support?accessProfile=task-reviewer&submissionVersion=1"
        ),
        review_download,
    ]
    .into_iter()
    .enumerate()
    {
        let positive = reqwest::Client::new()
            .get(format!("{}{path}", current.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(
            positive.status(),
            StatusCode::OK,
            "current authority admits {path}"
        );
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3;
        let mut short = token(81 + index as u64, bounds.clone());
        short["registry_grant_exp"] = json!(expiry);
        let caller = auth.authenticate(&idp.mint_token(short)).await.unwrap();
        let reached = Arc::new(AtomicBool::new(false));
        let was_current = Arc::new(AtomicBool::new(false));
        let entries = Arc::new(std::sync::Mutex::new(Vec::new()));
        let audit = RegistryAudit::new(
            AuditProfile::production_from_secret_bytes(vec![0x61; 32].into()).unwrap(),
            AuditWriter::from_line_sink(Box::new(DelayedTerminal {
                expiry,
                reached: reached.clone(),
                was_current: was_current.clone(),
                entries: entries.clone(),
            })),
        );
        let service = PostgresRecordMutationService::new(
            fixture.pool.clone(),
            fixture.registry.clone(),
            fixture.identity.clone(),
            "client-capability-test",
            RegistryLockKey::derive(fixture.registry.registry_id()).unwrap(),
            Duration::from_secs(2),
            audit,
        )
        .with_task_status(status.clone())
        .with_action_timeout_for_test(Duration::from_secs(8));
        let task = fixture.client_with_mutations(caller, service).await;
        let response = reqwest::Client::new()
            .get(format!("{}{path}", task.base_url))
            .send()
            .await
            .unwrap();
        let code = response.status();
        let body = response.text().await.unwrap();
        assert!(
            reached.load(Ordering::SeqCst),
            "{path} reached successful terminal audit"
        );
        assert!(
            was_current.load(Ordering::SeqCst),
            "{path} had current grant at terminal audit admission"
        );
        let expected = if index == 2 {
            StatusCode::PRECONDITION_FAILED
        } else {
            StatusCode::NOT_FOUND
        };
        assert_eq!(code, expected, "expired grant released {path}: {body}");
        for canary in [
            "current-name-canary",
            "proposed-name-canary",
            "attachment-disclosure-canary",
        ] {
            assert!(!body.contains(canary), "expired grant disclosed {canary}");
        }
        {
            let entries = entries.lock().unwrap();
            let phases = entries
                .iter()
                .map(|entry| {
                    (
                        entry["phase"].as_str().unwrap(),
                        entry["record"]["phase"].as_str().unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                phases,
                [
                    ("request", "attempt"),
                    ("response", "terminal"),
                    ("response", "refusal")
                ],
                "{path}: assembled outcome is audited before expired authority withholds release"
            );
            assert!(entries
                .iter()
                .all(|entry| entry["correlation"] == entries[0]["correlation"]));
            for canary in [
                "current-name-canary",
                "proposed-name-canary",
                "attachment-disclosure-canary",
            ] {
                assert!(!serde_json::to_string(&*entries).unwrap().contains(canary));
            }
        }
        drop(task);
    }
    let counts = fixture
        .database
        .admin
        .query_one(
            "SELECT
        (SELECT count(*) FROM registry_internal.registry_proposal_applications),
        (SELECT workflow_revision FROM registry_internal.registry_proposal_state)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(
        counts.get::<_, i64>(1),
        3,
        "expiry refusal causes no Proposal transition"
    );
    drop(current);
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

fn review_binding() -> Arc<registry_breg::review_store::ReviewAuthorityRegistry> {
    use registry_breg::review_store::{ReviewAuthorityClient, ReviewAuthorityRegistry};
    let client = registry_review_client::ReviewClient::new(
        registry_review_client::ReviewClientConfig::new("http://127.0.0.1:9/".parse().unwrap()),
    )
    .unwrap();
    let authority = Arc::new(
        ReviewAuthorityClient::new(
            "casework".into(),
            client,
            Arc::new(NoToken),
            "producer".into(),
            "proposal-producer".into(),
            7,
            None,
            None,
        )
        .unwrap(),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework".into(), authority)])).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_status_service_reads_only_its_exact_frozen_review_binding() {
    let mut source = source(false);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] = json!([
        "get",
        "edit",
        "submit",
        "cancel",
        "get-review-status",
        "get-review-context"
    ]);
    source["accessProfiles"][0]["permissions"]["proposals"][0]["readableContextFields"] =
        json!(["currentName", "proposedName"]);
    source["reviewAuthorities"] =
        json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]);
    source["actions"][0]["execution"]["proposal"]["review"] = json!({"type":"required","authority":"casework","source":"proposal-security",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    source["accessProfiles"].as_array_mut().unwrap().push(json!({"id":"review-status","principalClaim":"registry_principal",
        "actorKind":"service","requesterClients":["agent-client"],"requiredScopes":["proposal:review-status"],
        "requiredPurposes":["registry-administration"],"permissions":{"proposals":[{"action":"correct-name",
            "reviewAuthority":"casework","operations":["get-review-status"]}]}}));
    let fixture =
        client_http::ClientFixture::start_with_mutations(compile(source), clerk(), |service| {
            service.with_review_result_source(review_binding())
        })
        .await;
    let (_, target) = seed(&fixture).await;
    let (code, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"Proposed"}}),
        Some("status-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let (code, value, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("status-submit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{value}");
    let idp = MockIdp::start().await;
    let auth = authenticator(&fixture.registry, &idp).await;
    let token = json!({"aud":"urn:example:breg","sub":"review-service","azp":"agent-client","registry_principal":"review-service",
        "registry_actor_kind":"service","registry_purpose":"registry-administration","scope":"proposal:review-status"});
    let service = fixture
        .client_for(
            auth.authenticate(&idp.mint_token(token.clone()))
                .await
                .unwrap(),
        )
        .await;
    let path = format!("/v1/proposals/{id}/review-status?accessProfile=review-status");
    let (code, value, _) = send(&service, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::OK,
        "target-free service status read: {value}"
    );
    assert_eq!(value["authority"], "casework");
    assert_eq!(value["subject"]["id"], id);
    assert_eq!(value["result"]["state"], "pending");
    assert!(
        value.get("requestId").is_none(),
        "no correlation before acceptance"
    );
    assert_review_contract(&fixture.registry, &value);
    assert!(value["context"].get("fields").is_none());
    assert!(!value.to_string().contains("current-name-canary"));
    let metadata = service
        .client
        .registry_contract(Some("review-status"))
        .await
        .unwrap()
        .value;
    let binding = metadata
        .select_proposal_review_status("review-status", "correct-name")
        .unwrap();
    let purpose_read = service
        .client
        .read_proposal_review_by_id(&binding, id)
        .await
        .unwrap()
        .value;
    assert_eq!(purpose_read.subject.id, id);
    assert!(purpose_read.context.fields.is_none());
    assert_eq!(purpose_read.result.unwrap().state, "pending");
    for suffix in ["", "/review-context"] {
        let (code, value, _) = send(
            &service,
            Method::GET,
            &format!("/v1/proposals/{id}{suffix}?accessProfile=review-status"),
            Value::Null,
            None,
            None,
        )
        .await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "status service gained another surface: {value}"
        );
    }
    let mut human = token;
    human["registry_actor_kind"] = json!("human");
    let human = fixture
        .client_for(auth.authenticate(&idp.mint_token(human)).await.unwrap())
        .await;
    assert_eq!(
        send(&human, Method::GET, &path, Value::Null, None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let row=fixture.database.admin.query_one("SELECT create_request,expected_policy,expected_submission_digest FROM registry_internal.registry_proposal_review_submissions",&[]).await.unwrap();
    let stored: Value = row.get(0);
    let policy: Value = row.get(1);
    let digest: String = row.get(2);
    for field in [
        "authority",
        "subject",
        "context",
        "policy",
        "policy-id",
        "policy-version",
        "policy-digest",
    ] {
        match field {
            "authority" => {
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET authority='other-review'",&[]).await.unwrap();
            }
            "policy" => {
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET expected_policy=jsonb_set(expected_policy,'{version}','\"different\"')",&[]).await.unwrap();
            }
            _ => {
                let mut changed = stored.clone();
                if field == "subject" {
                    changed["subject"]["id"] = json!(uuid::Uuid::new_v4());
                } else if let Some(policy_field) = field.strip_prefix("policy-") {
                    changed["policy"][policy_field] = match policy_field {
                        "id" => json!("other-policy"),
                        "version" => json!("2"),
                        "digest" => json!(registry_review_client::ContentDigest::for_bytes(
                            b"other-policy"
                        )),
                        _ => unreachable!(),
                    };
                } else {
                    changed["context"]["binding"]["reference"] = json!("breg:different:context");
                }
                let request: registry_review_client::ReviewCreateRequest =
                    serde_json::from_value(changed.clone()).unwrap();
                let recomputed = registry_review_client::submission_digest(
                    "proposal-producer",
                    "proposal-security",
                    &request,
                )
                .unwrap();
                fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET create_request=$1,expected_submission_digest=$2",&[&changed,&recomputed.as_str()]).await.unwrap();
            }
        }
        let (code, value, _) = send(&service, Method::GET, &path, Value::Null, None, None).await;
        assert_eq!(
            code,
            StatusCode::NOT_FOUND,
            "substituted {field} disclosed status: {value}"
        );
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET authority='casework',create_request=$1,expected_policy=$2,expected_submission_digest=$3",
            &[&stored,&policy,&digest]).await.unwrap();
    }
    let create: registry_review_client::ReviewCreateRequest =
        serde_json::from_value(stored).unwrap();
    let accepted = registry_review_client::ReviewRequestAccepted {
        request_id: uuid::Uuid::new_v4(),
        subject: create.subject,
        policy: serde_json::from_value(policy).unwrap(),
        submission_digest: registry_review_client::SubmissionDigest::parse(&digest).unwrap(),
    };
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',accepted_binding=$1",&[&serde_json::to_value(&accepted).unwrap()]).await.unwrap();
    let accepted_value = serde_json::to_value(&accepted).unwrap();
    for state in ["accepted", "cancelling", "cancelled"] {
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state=$1,withdrawn=($1<>'accepted')", &[&state]).await.unwrap();
        for (http, selected) in [(&service, "review-status"), (&fixture.http, "clerk")] {
            let (code, value, _) = send(
                http,
                Method::GET,
                &format!("/v1/proposals/{id}/review-status?accessProfile={selected}"),
                Value::Null,
                None,
                None,
            )
            .await;
            assert_eq!(code, StatusCode::OK, "{state} correlation: {value}");
            assert_eq!(value["requestId"], accepted.request_id.to_string());
        }
        let purpose_read = service
            .client
            .read_proposal_review_by_id(&binding, id)
            .await
            .unwrap()
            .value;
        assert_eq!(
            purpose_read.request_id.as_deref(),
            Some(accepted.request_id.to_string().as_str())
        );
    }
    let (code, context, _) = send(
        &fixture.http,
        Method::GET,
        &format!("/v1/proposals/{id}/review-context?accessProfile=clerk"),
        Value::Null,
        None,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{context}");
    assert!(
        context.get("requestId").is_none(),
        "context does not expose status correlation"
    );
    let (code, denied, _) = send(&human, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(!denied
        .to_string()
        .contains(&accepted.request_id.to_string()));
    for field in ["id", "version", "digest", "submissionDigest", "requestId"] {
        let mut changed = accepted_value.clone();
        match field {
            "id" => changed["subject"][field] = json!(uuid::Uuid::new_v4()),
            "version" => changed["subject"][field] = json!("2"),
            "digest" => changed["subject"][field] = json!(format!("sha256:{}", "f".repeat(64))),
            "submissionDigest" => changed[field] = json!(format!("sha256:{}", "f".repeat(64))),
            "requestId" => changed[field] = json!(uuid::Uuid::nil()),
            _ => unreachable!(),
        }
        fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET accepted_binding=$1", &[&changed]).await.unwrap();
        for (http, selected) in [(&service, "review-status"), (&fixture.http, "clerk")] {
            let (code, value, _) = send(
                http,
                Method::GET,
                &format!("/v1/proposals/{id}/review-status?accessProfile={selected}"),
                Value::Null,
                None,
                None,
            )
            .await;
            assert_eq!(
                code,
                StatusCode::NOT_FOUND,
                "substituted accepted {field}: {value}"
            );
            assert!(value.get("requestId").is_none());
        }
    }
    fixture.database.admin.execute("UPDATE registry_internal.registry_proposal_review_submissions SET state='accepted',withdrawn=false,accepted_binding=$1", &[&accepted_value]).await.unwrap();
    let now = chrono::Utc::now();
    let result = registry_review_client::ReviewResult {
        result_id: uuid::Uuid::new_v4(),
        request_id: accepted.request_id,
        subject: accepted.subject,
        policy: accepted.policy,
        submission_digest: accepted.submission_digest,
        status: registry_review_client::ReviewResultStatus::Approved,
        outcome: None,
        result: None,
        completed_at: now - chrono::Duration::seconds(1),
        available_until: now + chrono::Duration::minutes(5),
    };
    let result = serde_json::to_value(result).unwrap();
    let parsed: registry_review_client::ReviewResult =
        serde_json::from_value(result.clone()).unwrap();
    fixture.database.admin.execute("INSERT INTO registry_internal.registry_proposal_review_results
        (action_id,proposal_id,submission_version,authority,result_id,result,status,completed_at,available_until)
        VALUES ('correct-name',$1::text::uuid,1,'casework',$2,$3,'approved',$4,$5)",
        &[&id,&parsed.result_id,&result,&parsed.completed_at,&parsed.available_until]).await.unwrap();
    let (code, value, _) = send(&service, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(code, StatusCode::OK, "{value}");
    assert_eq!(value["result"]["state"], "approved");
    assert_eq!(value["requestId"], parsed.request_id.to_string());
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_proposal_review_results SET status='cancelled'",
            &[],
        )
        .await
        .unwrap();
    let (code, value, _) = send(&service, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "substituted status column disclosed a result: {value}"
    );
    drop(service);
    drop(human);
    fixture.finish().await;
}

fn assert_review_contract(registry: &registry_breg::CompiledRegistry, value: &Value) {
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-name")
        .unwrap();
    let exported = registry_breg::compiler::review_context::compile_schema(registry, action)
        .unwrap()
        .unwrap();
    assert_eq!(
        value["context"]["contract"],
        json!({"id":exported.id,"revision":exported.revision,"schemaDigest":exported.digest})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frozen_changes_inspection_covers_patch_and_create_without_applying_or_rerunning_plan() {
    let mut project = source(false);
    project["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    project["recordTypes"].as_array_mut().unwrap().push(json!({
        "id":"notice","primaryDataset":"directory","route":"notices","mutationMode":"mutable",
        "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
            {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]
    }));
    project["actions"][0]["execution"]["proposal"]["reviewContext"]["fields"] = json!({
        "changes":{"type":"changes","recordType":"target","fields":["name"]},
        "notices":{"type":"changes","recordType":"notice","fields":["name"]}
    });
    project["actions"][0]["plan"]["effects"][0]["set"]["name"] =
        json!({"value":"Computed frozen patch"});
    project["actions"][0]["plan"]["effects"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"notice","target":{"recordType":"notice"},"operation":"create",
            "set":{"name":{"value":"Computed frozen notice"},"jurisdiction":{"value":"zone-a"}}
        }));
    let permissions = &mut project["accessProfiles"][0]["permissions"];
    permissions["records"].as_array_mut().unwrap().push(json!({"recordType":"notice","operations":["get"],
        "readableFields":["name"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}));
    let target = json!({"recordType":"notice","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]});
    permissions["actions"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(target.clone());
    permissions["proposals"][0]["targets"]
        .as_array_mut()
        .unwrap()
        .push(target);
    permissions["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!("get-review-context"));
    permissions["proposals"][0]["readableContextFields"] = json!(["changes", "notices"]);
    let fixture = client_http::ClientFixture::start(compile(project), clerk()).await;
    let (_, target) = seed(&fixture).await;
    let (code, draft, etag) = send(
        &fixture.http,
        Method::POST,
        "/v1/actions/correct-name/proposals?accessProfile=clerk",
        json!({"input":{"target":target,"value":"Unprocessed input"}}),
        Some("inspect-start"),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{draft}");
    let id = draft["id"].as_str().unwrap();
    let (code, submitted, _) = send(
        &fixture.http,
        Method::POST,
        &format!("/v1/proposals/{id}/submit?accessProfile=clerk"),
        json!({}),
        Some("inspect-submit"),
        etag.as_deref(),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{submitted}");
    let path = format!("/v1/proposals/{id}/review-context?accessProfile=clerk");
    let (code, context, _) = send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(code, StatusCode::OK, "{context}");
    assert_eq!(context["effectDigest"], submitted["effectDigest"]);
    assert_eq!(context["submissionVersion"], submitted["submissionVersion"]);
    assert_review_contract(&fixture.registry, &context);
    assert_eq!(
        context["context"]["fields"]["changes"],
        json!([{
            "recordId":target,"operation":"patch","before":{"name":"current-name-canary"},"after":{"name":"Computed frozen patch"}
        }])
    );
    let notice = &context["context"]["fields"]["notices"][0];
    assert!(uuid::Uuid::parse_str(notice["recordId"].as_str().unwrap()).is_ok());
    assert_eq!(notice["operation"], "create");
    assert!(notice["before"].is_null());
    assert_eq!(notice["after"], json!({"name":"Computed frozen notice"}));
    for hidden in ["Unprocessed input", "jurisdiction", "organization"] {
        assert!(!context["context"]["fields"].to_string().contains(hidden));
    }
    let notice_record = &fixture.registry.entities()["notice"];
    let count: i64 = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.\"{}\"",
                notice_record.physical_table
            ),
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "inspection does not apply the proposed create");
    let (_, replay, _) = send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        replay, context,
        "inspection reads the stored submission unchanged"
    );
    let record = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\"='zone-b' WHERE record_id=$1::text::uuid",
                record.physical_table, record.fields["jurisdiction"].physical_name
            ),
            &[&target],
        )
        .await
        .unwrap();
    let (code, concealed, _) =
        send(&fixture.http, Method::GET, &path, Value::Null, None, None).await;
    assert_eq!(
        code,
        StatusCode::NOT_FOUND,
        "current row disclosure still governs the frozen projection: {concealed}"
    );
    assert!(!concealed.to_string().contains("Computed frozen"));
    fixture.finish().await;
}
