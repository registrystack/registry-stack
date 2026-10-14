// SPDX-License-Identifier: Apache-2.0
//! Signed task authority through the client, Action router, and PostgreSQL RLS.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
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
use registry_breg_client::{BRegActionInvocationRequest, BRegIdempotencyKey, BRegProblemCode};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn registry() -> registry_breg::CompiledRegistry {
    let mut source: Value = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../products/breg/examples/refactor/minimal/registry.yaml"
        ))
        .expect("canonical fixture uses the supported YAML subset")
        .expect("canonical fixture is nonempty")
        .to_json_value();
    source["actions"] = json!([{"id":"create-contact","execution":{"mode":"immediate"},"inputs":[
        {"id":"name","type":"string","required":true,"minimumLength":1,"maximumLength":160,"classification":"internal"},
        {"id":"email","type":"string","required":true,"minimumLength":1,"maximumLength":254,"classification":"internal"},
        {"id":"jurisdiction","type":"string","required":true,"minimumLength":1,"maximumLength":40,"classification":"internal"}],
        "plan":{"type":"fixed","effects":[{"id":"contact","target":{"recordType":"contact"},"operation":"create",
            "set":{"name":{"fromInput":"name"},"email":{"fromInput":"email"},"jurisdiction":{"fromInput":"jurisdiction"}}}]}}]);
    source["accessProfiles"].as_array_mut().unwrap().push(json!({"id":"task-creator","actorKind":"agent",
        "requesterClients":["agent-client"],"principalClaim":"registry_principal","requiredScopes":["contact:create"],
        "requiredPurposes":["directory-administration"],"taskGrant":{"sourceIssuer":"https://casework.example"},
        "permissions":{"actions":[{"action":"create-contact","operations":["invoke"],"targets":[{"recordType":"contact",
            "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],"results":["contact"]}]}}));
    source["accessProfiles"].as_array_mut().unwrap().push(json!({"id":"agent-reader","actorKind":"agent",
        "requesterClients":["agent-client"],"principalClaim":"registry_principal","requiredScopes":["contact:create"],
        "requiredPurposes":["directory-administration"],"permissions":{"records":[{"recordType":"contact","operations":["get"],
            "readableFields":["name","email","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}}));
    source["accessProfiles"][1]["permissions"]["records"] = json!([{"recordType":"contact","operations":["get"],
        "readableFields":["name","email","jurisdiction"],"rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]);
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
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
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn task_action_scope_subjects_replay_and_fresh_revocation_are_enforced() {
    let registry = registry();
    let idp = MockIdp::start().await;
    let audience = "urn:example:breg";
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![audience.into()]);
    verifier.allowed_clients = vec!["agent-client".into()];
    let auth = RegistryAuthenticator::new(
        &registry,
        verifier,
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        AuthorityClaimConfig::new("registry_principal", Some("registry_purpose".into()))
            .with_contextual_claims(
                registry_platform_oidc::ClaimNames::default(),
                BTreeMap::from([(
                    "agent-client".into(),
                    "00000000-0000-4000-8000-0000000000aa".into(),
                )]),
            ),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = json!({"aud":audience,"sub":"author","azp":"agent-client","registry_principal":"author",
        "registry_actor_kind":"agent","registry_purpose":"directory-administration","scope":"contact:create",
        "registry_grant_id":"00000000-0000-4000-8000-000000000001","registry_approver":"h:approver",
        "registry_grant_source_issuer":"https://casework.example","registry_grant_client":"agent-client",
        "registry_grant_resource":audience,"registry_grant_exp":now+600,
        "registry_grant_bounds":{"type":"breg","permissions":[{"collection":"action:create-contact","operations":["invoke"]},{"collection":"contacts","operations":["get"]}]},
        "identity":{"jurisdiction":"zone-a"},"jurisdiction":"zone-b"});
    let caller = auth
        .authenticate(&idp.mint_token(token.clone()))
        .await
        .unwrap();
    let editor = VerifiedRequestClaims::authenticated(
        "registry_principal",
        "editor",
        BTreeSet::from(["registry:directory:write".into()]),
        Some("directory-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
    )
    .unwrap();
    let status = Arc::new(Status {
        active: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let checker = status.clone();
    let fixture =
        client_http::ClientFixture::start_with_mutations(registry, editor, move |mutations| {
            mutations.with_task_status(checker)
        })
        .await;
    let task = fixture.client_for(caller).await;
    let metadata = task
        .client
        .registry_contract(Some("task-creator"))
        .await
        .unwrap();
    let binding = metadata
        .value
        .select_action("create-contact", "task-creator")
        .unwrap();
    let input = |zone: &str| {
        json!({"name":"Institution","email":"directory@example.test","jurisdiction":zone})
            .as_object()
            .unwrap()
            .clone()
    };
    let request = BRegActionInvocationRequest::new(&binding, input("zone-a"), None).unwrap();
    let first = task
        .client
        .invoke_action(&binding, &request, &key("task-create"))
        .await
        .unwrap();
    let replay = task
        .client
        .invoke_action(&binding, &request, &key("task-create"))
        .await
        .unwrap();
    assert_eq!(first.value, replay.value);
    assert_eq!(
        status.calls.load(Ordering::SeqCst),
        2,
        "replays perform a fresh authority check"
    );
    let table = &fixture.registry.entities()["contact"].physical_table;
    let count = || async {
        fixture
            .database
            .admin
            .query_one(
                &format!("SELECT count(*)::bigint FROM registry_data.\"{table}\""),
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
    };
    assert_eq!(count().await, 1);
    let outside = BRegActionInvocationRequest::new(&binding, input("zone-b"), None).unwrap();
    assert!(
        task.client
            .invoke_action(&binding, &outside, &key("outside-grant"))
            .await
            .is_err(),
        "top-level claim cannot widen frozen subjects"
    );
    assert_eq!(count().await, 1);
    let id = first.value.results()["contact"]
        .record_identifier()
        .to_string();
    let options = registry_breg_client::BRegRecordOptions::default()
        .access_profile("task-creator")
        .unwrap();
    task.client
        .get_record("contacts", &id, &options)
        .await
        .unwrap();
    let mut delegated = token.clone();
    delegated
        .as_object_mut()
        .unwrap()
        .retain(|name, _| !name.starts_with("registry_grant_") && name != "registry_approver");
    delegated["act"] = json!({"sub":"00000000-0000-4000-8000-0000000000aa","iss":idp.issuer()});
    delegated["jurisdiction"] = json!("zone-a");
    let delegated = fixture
        .client_for(auth.authenticate(&idp.mint_token(delegated)).await.unwrap())
        .await;
    let options = registry_breg_client::BRegRecordOptions::default()
        .access_profile("agent-reader")
        .unwrap();
    let read = delegated
        .client
        .get_record("contacts", &id, &options)
        .await
        .unwrap();
    assert!(!serde_json::to_string(&read.value)
        .unwrap()
        .contains("00000000-0000-4000-8000-0000000000aa"));
    let refused = reqwest::Client::new()
        .post(format!(
            "{}{}?accessProfile=task-creator",
            delegated.base_url,
            binding.invoke_path()
        ))
        .header("idempotency-key", "actor-no-task")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        reqwest::StatusCode::NOT_FOUND,
        "the router refuses standing actor Invoke before body parsing"
    );
    let entries = fixture.audit_capture.entries();
    let records = entries
        .iter()
        .filter_map(|entry| entry.get("record"))
        .collect::<Vec<_>>();
    for operation in ["actions.create-contact.invoke", "records.contact.get"] {
        assert!(
            records
                .iter()
                .any(|record| record["operationId"] == operation
                    && record["authorization"]["grantPseudonym"].is_string()),
            "task audit {operation}: {records:?}"
        );
    }
    assert!(
        records
            .iter()
            .any(|record| record["operationId"] == "records.contact.get"
                && record["authorization"]["actorPseudonym"].is_string()),
        "trusted actor read audit"
    );
    assert!(
        records.iter().any(
            |record| record["authorization"]["actorPseudonym"].is_string()
                && record["authorization"]["outcome"] == "denied"
        ),
        "trusted actor Action refusal audit"
    );
    let wire = serde_json::to_string(&entries).unwrap();
    for raw in [
        "00000000-0000-4000-8000-0000000000aa",
        "00000000-0000-4000-8000-000000000001",
        "h:approver",
    ] {
        assert!(!wire.contains(raw));
    }
    drop(delegated);
    let mut sibling = token.clone();
    sibling["registry_grant_id"] = json!("00000000-0000-4000-8000-000000000002");
    let sibling = fixture
        .client_for(auth.authenticate(&idp.mint_token(sibling)).await.unwrap())
        .await;
    let sibling_contract = sibling
        .client
        .registry_contract(Some("task-creator"))
        .await
        .unwrap();
    let sibling_binding = sibling_contract
        .value
        .select_action("create-contact", "task-creator")
        .unwrap();
    let sibling_request =
        BRegActionInvocationRequest::new(&sibling_binding, input("zone-a"), None).unwrap();
    let error = sibling
        .client
        .invoke_action(&sibling_binding, &sibling_request, &key("task-create"))
        .await
        .unwrap_err();
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::IdempotencyConflict),
        "{error:?}"
    );
    assert_eq!(count().await, 1);
    let mut short_token = token;
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    short_token["registry_grant_id"] = json!("00000000-0000-4000-8000-000000000003");
    short_token["registry_grant_exp"] = json!(expiry);
    let short_claims = auth
        .authenticate(&idp.mint_token(short_token))
        .await
        .unwrap();
    let lock =
        registry_breg::postgres::RegistryLockKey::derive(fixture.registry.registry_id()).unwrap();
    let audit = registry_breg::audit::test_support::capturing(
        registry_platform_audit::AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
            .unwrap(),
    )
    .0;
    let waiting_service = registry_breg::postgres::PostgresRecordMutationService::new(
        fixture.pool.clone(),
        fixture.registry.clone(),
        fixture.identity.clone(),
        "task-expiry",
        lock,
        Duration::from_secs(10),
        audit,
    )
    .with_task_status(status.clone());
    let short = fixture
        .client_with_mutations(short_claims, waiting_service)
        .await;
    let short_contract = short
        .client
        .registry_contract(Some("task-creator"))
        .await
        .unwrap();
    let short_binding = short_contract
        .value
        .select_action("create-contact", "task-creator")
        .unwrap();
    let short_request =
        BRegActionInvocationRequest::new(&short_binding, input("zone-a"), None).unwrap();
    let receipts_before: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    fixture
        .database
        .admin
        .execute("SELECT pg_advisory_lock($1)", &[&lock.get()])
        .await
        .unwrap();
    let expiry_key = key("task-expired-at-lock");
    let waiting = short
        .client
        .invoke_action(&short_binding, &short_request, &expiry_key);
    let release = async {
        tokio::time::timeout(Duration::from_secs(1),async {
            loop {
                let blocked:i64=fixture.database.admin.query_one("SELECT count(*)::bigint FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",&[]).await.unwrap().get(0);
                if blocked>0 {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("the Action passed fresh status and waits on the registry transaction lock");
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
            .execute("SELECT pg_advisory_unlock($1)", &[&lock.get()])
            .await
            .unwrap();
    };
    let (expired, ()) = tokio::join!(waiting, release);
    assert_eq!(
        expired.unwrap_err().problem_code(),
        Some(BRegProblemCode::PreconditionFailed),
        "expiry while waiting cannot commit or release a result"
    );
    assert_eq!(count().await, 1);
    let receipts_after: i64 = fixture
        .database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_idempotency",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        receipts_before, receipts_after,
        "expired authority spends no receipt"
    );
    drop(short);
    status.active.store(false, Ordering::SeqCst);
    // Even a saturated pool cannot delay revocation admission into SQL work.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(fixture.pool.get_for_test().await.unwrap());
    }
    let refusal = tokio::time::timeout(
        Duration::from_secs(1),
        task.client
            .invoke_action(&binding, &request, &key("task-create")),
    )
    .await
    .expect("revoked authority is checked before waiting for PostgreSQL")
    .unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    drop(held);
    assert_eq!(count().await, 1);
    drop(task);
    drop(sibling);
    fixture.finish().await;
}
