// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    authenticated_router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
};
use registry_breg::auth::{AuthorityClaimConfig, RegistryAuthenticator};
use registry_breg::cursor::CursorCodec;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    PostgresSnapshotReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_breg::{compile_project, parse_project_json, CompileProfile, CompiledRegistry};
use registry_platform_audit::AuditProfile;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;
use zeroize::Zeroizing;

const RECORD_A: &str = "00000000-0000-4000-8000-000000000001";
const RECORD_B: &str = "00000000-0000-4000-8000-000000000002";
const CASE_A: &str = "00000000-0000-4000-8000-000000000003";
const CASE_PERSON_A: &str = "00000000-0000-4000-8000-000000000004";
const SUBJECT: &str = "subject-private-canary";
const PURPOSE: &str = "service-purpose-canary";
const PACKAGE: &str = "subject-access-test";
const AUDIENCE: &str = "urn:breg:subject-access-test";

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn compiled() -> CompiledRegistry {
    let permission = json!({"entity":"entry", "operations":["get","list","lookup"],
        "readableFields":["label"], "lookups":[{"selector":"by-subject","valueOrigin":"request"}],
        "rowBoundaries":"unrestricted"});
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "entities":[{"id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"restricted",
            "fields":[{"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
            "selectorProfiles":[{"id":"by-subject","fields":["subject"]}],
            "accessLog":{"subjectField":"subject","trustedIntermediaries":["evidence-service"],
                "exemptions":{"investigator":{"reason":"investigation-policy-canary","delayDays":7}}}}],
        "accessProfiles":[
            {"id":"reader","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{"entities":[permission.clone()]}},
            {"id":"investigator","principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{"entities":[permission]}}
        ]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn compiled_relationships() -> CompiledRegistry {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "entities":[
            {"id":"case","primaryDataset":"records","route":"cases","mutationMode":"mutable","classification":"restricted",
                "fields":[{"id":"case-code","type":"string","maximumLength":64,"required":true,"classification":"restricted"}],
                "readPaths":[{"id":"people","through":"case-person","to":"person","route":"people"}]},
            {"id":"case-person","primaryDataset":"records","route":"case-people","mutationMode":"mutable","classification":"restricted",
                "fields":[
                    {"id":"case","type":"reference","target":"case","required":true,"classification":"restricted"},
                    {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}]},
            {"id":"person","primaryDataset":"records","route":"people","mutationMode":"mutable","classification":"restricted",
                "fields":[
                    {"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                    {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
                "accessLog":{"subjectField":"subject","exemptions":{
                    "investigator":{"reason":"target-local-policy-canary","delayDays":7},
                    "relationship-investigator":{"sourceEntity":"case","reason":"relationship-policy-canary","delayDays":7}}}}
        ],
        "accessProfiles":[
            {"id":"reader","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "entities":[
                    {"entity":"person","operations":["get"],"readableFields":["label"],"rowBoundaries":"unrestricted"}
                ]
            }},
            {"id":"investigator","principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{
                "entities":[
                    {"entity":"case","operations":["get"],"readableFields":["case-code"],"rowBoundaries":"unrestricted",
                        "readPaths":[{"path":"people","readableFields":["label"]}]},
                    {"entity":"person","operations":["get"],"readableFields":["label"],"rowBoundaries":"unrestricted"}
                ]
            }},
            {"id":"relationship-investigator","principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{
                "entities":[
                    {"entity":"case","operations":["get"],"readableFields":["case-code"],"rowBoundaries":"unrestricted",
                        "readPaths":[{"path":"people","readableFields":["label"]}]}
                ]
            }}
        ]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

async fn setup_relationships() -> (TestDatabase, Router, MockIdp) {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(compiled_relationships());
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "relationship-access-database",
            label: "relationship-access-package-1",
        },
    )
    .await
    .unwrap();
    let person = &registry.entities()["person"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\"
                    (record_id,record_revision,record_lifecycle,active_package_revision,\"{}\",\"{}\")
                 VALUES ($1::text::uuid,1,'active',$4,$2,$3)",
                person.physical_table,
                person.fields["subject"].physical_name,
                person.fields["label"].physical_name,
            ),
            &[&RECORD_A, &SUBJECT, &"protected-label", &identity.activation_id],
        )
        .await
        .unwrap();
    let case = &registry.entities()["case"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\"
                    (record_id,record_revision,record_lifecycle,active_package_revision,\"{}\")
                 VALUES ($1::text::uuid,1,'active',$3,$2)",
                case.physical_table, case.fields["case-code"].physical_name,
            ),
            &[&CASE_A, &"CASE-1763", &identity.activation_id],
        )
        .await
        .unwrap();
    let link = &registry.entities()["case-person"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.\"{}\"
                    (record_id,record_revision,record_lifecycle,active_package_revision,\"{}\",\"{}\")
                 VALUES ($1::text::uuid,1,'active',$4,$2::text::uuid,$3::text::uuid)",
                link.physical_table,
                link.fields["case"].physical_name,
                link.fields["person"].physical_name,
            ),
            &[&CASE_PERSON_A, &CASE_A, &RECORD_A, &identity.activation_id],
        )
        .await
        .unwrap();
    drop(migration);
    task.abort();

    let idp = MockIdp::start().await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
    verifier.allowed_clients = vec!["portal".into(), "agency".into()];
    let auth = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            verifier,
            keys,
            AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
        )
        .unwrap(),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = PostgresRecordReadService::new(
        database.runtime_config.build_pool().unwrap(),
        registry.clone(),
        identity.clone(),
        RegistryLockKey::derive(PACKAGE).unwrap(),
        Duration::from_secs(2),
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).unwrap()),
        cursors.clone(),
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(reads),
        Arc::new(Ready),
        cursors,
    );
    (database, authenticated_router(Arc::new(service), auth), idp)
}

async fn setup() -> (TestDatabase, Router, MockIdp) {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(compiled());
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "access-database",
            label: "access-package-1",
        },
    )
    .await
    .unwrap();
    let entity = &registry.entities()["entry"];
    for (id, subject) in [(RECORD_A, SUBJECT), (RECORD_B, "other-subject")] {
        database.admin.execute(&format!("INSERT INTO registry_data.\"{}\" (record_id,record_revision,record_lifecycle,active_package_revision,\"{}\",\"{}\") VALUES ($1::text::uuid,1,'active',$3,$2,'protected-label')",
            entity.physical_table, entity.fields["subject"].physical_name, entity.fields["label"].physical_name), &[&id,&subject,&identity.activation_id]).await.unwrap();
    }
    drop(migration);
    task.abort();
    let idp = MockIdp::start().await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
    verifier.allowed_clients = vec!["portal".into(), "agency".into(), "evidence-service".into()];
    let auth = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            verifier,
            keys,
            AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
        )
        .unwrap(),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = PostgresRecordReadService::new(
        database.runtime_config.build_pool().unwrap(),
        registry.clone(),
        identity.clone(),
        RegistryLockKey::derive(PACKAGE).unwrap(),
        Duration::from_secs(2),
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).unwrap()),
        cursors.clone(),
    );
    let service = HttpService::new(
        registry,
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(reads),
        Arc::new(Ready),
        cursors,
    );
    (database, authenticated_router(Arc::new(service), auth), idp)
}

fn token(idp: &MockIdp, client: &str, subject: &str) -> String {
    idp.mint_token(json!({"aud":AUDIENCE,"sub":subject,"client_id":client,"scope":"registry.read","registry_actor_kind":"service","registry_purpose":PURPOSE}))
}

async fn send(
    app: &Router,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
    attribution: Option<(&str, &str)>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if let Some((requester, purpose)) = attribution {
        request = request
            .header(
                "Registry-Access-Requester",
                URL_SAFE_NO_PAD.encode(requester),
            )
            .header("Registry-Access-Purpose", URL_SAFE_NO_PAD.encode(purpose));
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&body).unwrap())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    if status == StatusCode::OK {
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn history(app: &Router, token: &str, record: &str, query: &str) -> (StatusCode, Value) {
    send(
        app,
        token,
        Method::GET,
        &format!("/v1/records/entries/{record}/access-log{query}"),
        None,
        None,
    )
    .await
}

#[tokio::test]
async fn subject_access_log_requires_current_record_ownership_and_records_each_read_hit() {
    let (db, app, idp) = setup().await;
    let agency = token(&idp, "agency", "officer");
    let owner = token(&idp, "portal", SUBJECT);
    assert_eq!(
        send(
            &app,
            &agency,
            Method::GET,
            &format!("/v1/records/entries/{RECORD_A}"),
            None,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            &agency,
            Method::GET,
            "/v1/records/entries?$top=1",
            None,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &app,
            &agency,
            Method::POST,
            "/v1/records/entries:lookup",
            Some(json!({"selector":"by-subject","values":{"subject":SUBJECT}})),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, page) = history(&app, &owner, RECORD_A, "?limit=2").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["events"].as_array().unwrap().len(), 2);
    for event in page["events"].as_array().unwrap() {
        assert_eq!(event["requester"], "agency");
        assert_eq!(event["purpose"], PURPOSE);
        assert!(event["serviceClient"].is_null());
    }
    let next = page["nextCursor"].as_str().unwrap();
    let (_, second) = history(&app, &owner, RECORD_A, &format!("?cursor={next}")).await;
    assert_eq!(second["events"].as_array().unwrap().len(), 1);
    let (_, again) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(
        again["events"].as_array().unwrap().len(),
        3,
        "reading the history does not recursively log a record read"
    );
    assert_eq!(
        history(&app, &agency, RECORD_A, "").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        history(&app, &owner, RECORD_B, "").await.0,
        StatusCode::NOT_FOUND
    );
    let (_, other) = history(&app, &token(&idp, "portal", "other-subject"), RECORD_B, "").await;
    assert_eq!(
        other["events"].as_array().unwrap().len(),
        0,
        "list lookahead never becomes a hit"
    );
    assert_eq!(
        send(
            &app,
            &agency,
            Method::GET,
            "/v1/records/entries?$top=2",
            None,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, first_subject) = history(&app, &owner, RECORD_A, "").await;
    let (_, second_subject) =
        history(&app, &token(&idp, "portal", "other-subject"), RECORD_B, "").await;
    assert_eq!(first_subject["events"].as_array().unwrap().len(), 4);
    assert_eq!(
        second_subject["events"].as_array().unwrap().len(),
        1,
        "a returned page records a separate access for each subject"
    );
    let audit = db
        .audit_entries()
        .into_iter()
        .map(|entry| entry.to_string())
        .collect::<String>();
    for secret in [SUBJECT, PURPOSE, "officer", RECORD_A, "protected-label"] {
        assert!(!audit.contains(secret));
    }
    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn forwarded_access_attribution_requires_a_verified_trusted_client_and_never_grants_subject_access(
) {
    let (db, app, idp) = setup().await;
    let route = format!("/v1/records/entries/{RECORD_A}");
    let forwarding = ("requesting-agency-éducation", "requesting-purpose-canary");
    let agency = token(&idp, "agency", "officer");
    let intermediary = token(&idp, "evidence-service", "source-account");
    assert_eq!(
        send(&app, &agency, Method::GET, &route, None, Some(forwarding))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            &intermediary,
            Method::POST,
            "/v1/records/entries:lookup",
            Some(json!({"selector":"by-subject","values":{"subject":SUBJECT}})),
            Some(forwarding)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        history(&app, &intermediary, RECORD_A, "").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(
            &app,
            &intermediary,
            Method::GET,
            &format!("{route}/access-log"),
            None,
            Some((SUBJECT, PURPOSE))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, log) = history(&app, &token(&idp, "portal", SUBJECT), RECORD_A, "").await;
    let entries = log["events"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["requester"], forwarding.0);
    assert_eq!(entries[0]["purpose"], forwarding.1);
    assert_eq!(entries[0]["serviceClient"], "evidence-service");
    let audit = db
        .audit_entries()
        .into_iter()
        .map(|entry| entry.to_string())
        .collect::<String>();
    assert!(!audit.contains(forwarding.0));
    assert!(!audit.contains(forwarding.1));
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn access_log_exemptions_are_delayed_audited_and_expire_without_runtime_delete_authority() {
    let (db, app, idp) = setup().await;
    let agency = token(&idp, "agency", "investigator");
    let owner = token(&idp, "portal", SUBJECT);
    assert_eq!(
        send(
            &app,
            &agency,
            Method::GET,
            &format!("/v1/records/entries/{RECORD_A}?accessProfile=investigator"),
            None,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, hidden) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(hidden["events"].as_array().unwrap().len(), 0);
    assert!(db
        .audit_entries()
        .iter()
        .any(|entry| entry["schema"] == "breg-access-log/v1"
            && entry["record"]["operation"] == "visibility-delay"));
    db.admin.execute("UPDATE registry_internal.registry_subject_access_log SET accessed_at=accessed_at-interval '8 days',visible_after=visible_after-interval '8 days',expires_at=expires_at-interval '8 days'",&[]).await.unwrap();
    let (_, visible) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(
        visible["events"][0]["exemptionReason"],
        "investigation-policy-canary"
    );
    db.admin.execute("UPDATE registry_internal.registry_subject_access_log SET accessed_at=accessed_at-interval '90 days',visible_after=visible_after-interval '90 days',expires_at=expires_at-interval '90 days'",&[]).await.unwrap();
    let (_, expired) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(expired["events"].as_array().unwrap().len(), 0);
    let pool = db.runtime_config.build_pool().unwrap();
    let client = pool.get_for_test().await.unwrap();
    assert!(client
        .execute(
            "DELETE FROM registry_internal.registry_subject_access_log",
            &[]
        )
        .await
        .is_err());
    assert!(client
        .execute(
            "UPDATE registry_internal.registry_subject_access_log SET purpose='spoof'",
            &[]
        )
        .await
        .is_err());
    let removed: i64 = client
        .query_one("SELECT registry_internal.expire_subject_access_log()", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(removed, 1);
    db.assert_every_audit_request_answered_once();
    drop(client);
    drop(pool);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn relationship_exemptions_bind_the_source_entity_without_profile_name_collisions() {
    let (db, app, idp) = setup_relationships().await;
    let agency = token(&idp, "agency", "officer");
    let owner = token(&idp, "portal", SUBJECT);
    let relationship = format!("/v1/records/cases/{CASE_A}/people");

    let (status, same_name) = send(
        &app,
        &agency,
        Method::GET,
        &format!("{relationship}?accessProfile=investigator"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{same_name}");
    assert_eq!(same_name["items"].as_array().map(Vec::len), Some(1));

    let (status, source_scoped) = send(
        &app,
        &agency,
        Method::GET,
        &format!("{relationship}?accessProfile=relationship-investigator"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{source_scoped}");
    assert_eq!(source_scoped["items"].as_array().map(Vec::len), Some(1));

    let rows = db
        .admin
        .query(
            "SELECT access_profile, authority_entity, exemption_reason,
                    visible_after = accessed_at, visible_after > transaction_timestamp()
               FROM registry_internal.registry_subject_access_log
              WHERE entity_id='person' AND record_id=$1::text::uuid
              ORDER BY access_profile",
            &[&RECORD_A],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>(0), "investigator");
    assert_eq!(rows[0].get::<_, String>(1), "case");
    assert!(rows[0].get::<_, Option<String>>(2).is_none());
    assert!(rows[0].get::<_, bool>(3));
    assert_eq!(rows[1].get::<_, String>(0), "relationship-investigator");
    assert_eq!(rows[1].get::<_, String>(1), "case");
    assert_eq!(
        rows[1].get::<_, Option<String>>(2).as_deref(),
        Some("relationship-policy-canary")
    );
    assert!(!rows[1].get::<_, bool>(3));
    assert!(rows[1].get::<_, bool>(4));

    let (status, before_delay) = send(
        &app,
        &owner,
        Method::GET,
        &format!("/v1/records/people/{RECORD_A}/access-log?accessProfile=reader"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{before_delay}");
    let events = before_delay["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "the source-scoped exemption stays hidden");
    assert!(events[0]["exemptionReason"].is_null());

    let exemption_audits = db
        .audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["schema"] == "breg-access-log/v1"
                && entry["phase"] == "request"
                && entry["record"]["operation"] == "visibility-delay"
        })
        .collect::<Vec<_>>();
    assert_eq!(exemption_audits.len(), 1);
    assert_eq!(exemption_audits[0]["record"]["entityId"], "person");
    assert_eq!(exemption_audits[0]["record"]["authorityEntity"], "case");
    assert_eq!(
        exemption_audits[0]["record"]["selectedAccessProfile"],
        "relationship-investigator"
    );
    assert!(!exemption_audits[0]
        .to_string()
        .contains("relationship-policy-canary"));

    db.admin
        .execute(
            "UPDATE registry_internal.registry_subject_access_log
                SET accessed_at=accessed_at-interval '8 days',
                    visible_after=visible_after-interval '8 days',
                    expires_at=expires_at-interval '8 days'
              WHERE access_profile='relationship-investigator'",
            &[],
        )
        .await
        .unwrap();
    let (_, after_delay) = send(
        &app,
        &owner,
        Method::GET,
        &format!("/v1/records/people/{RECORD_A}/access-log?accessProfile=reader"),
        None,
        None,
    )
    .await;
    let events = after_delay["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .any(|event| event["exemptionReason"] == "relationship-policy-canary"));

    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_failed_subject_access_log_insert_prevents_record_release() {
    let (db, app, idp) = setup().await;
    db.admin
        .batch_execute(&format!(
            "REVOKE INSERT ON registry_internal.registry_subject_access_log FROM \"{}\"",
            db.runtime_role.as_str()
        ))
        .await
        .unwrap();
    let (status, body) = send(
        &app,
        &token(&idp, "agency", "officer"),
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body.to_string().contains("protected-label"));
    let count: i64 = db
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_subject_access_log",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

async fn seed_access_log_rows(db: &TestDatabase, rows: i32, expired: bool) {
    let expires_at = if expired {
        "transaction_timestamp() - interval '1 day'"
    } else {
        "transaction_timestamp() + interval '1 day'"
    };
    db.admin
        .execute(
            &format!(
                "INSERT INTO registry_internal.registry_subject_access_log
                    (event_id, entity_id, record_id, requester, operation_id, authority_entity,
                     access_profile, package_revision, request_id, accessed_at, visible_after,
                     expires_at)
                 SELECT gen_random_uuid(), 'entry', $1::text::uuid, 'agency', 'seeded-read',
                        'entry', 'reader', 'seeded-package', gen_random_uuid(),
                        transaction_timestamp() - interval '100 days',
                        transaction_timestamp() - interval '100 days', {expires_at}
                   FROM generate_series(1, $2)"
            ),
            &[&RECORD_A, &rows],
        )
        .await
        .unwrap();
}

async fn access_log_rows(db: &TestDatabase) -> i64 {
    db.admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_subject_access_log",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn one_retention_tick_erases_every_expired_batch_and_reports_a_bounded_backlog() {
    let (db, app, idp) = setup().await;
    // More expired rows than one erasure batch, plus a live row that must stay.
    seed_access_log_rows(&db, 2_500, true).await;
    seed_access_log_rows(&db, 1, false).await;
    let pool = db.runtime_config.build_pool().unwrap();

    let (erased, bound_reached) = registry_breg::expire_subject_access_log_for_test(&pool, Some(1))
        .await
        .unwrap();
    assert_eq!(erased, 1_000);
    assert!(
        bound_reached,
        "a tick that stops at its bound reports the backlog"
    );
    assert_eq!(access_log_rows(&db).await, 1_501);

    let (erased, bound_reached) = registry_breg::expire_subject_access_log_for_test(&pool, None)
        .await
        .unwrap();
    assert_eq!(erased, 1_500, "one tick keeps erasing until a short batch");
    assert!(!bound_reached);
    assert_eq!(access_log_rows(&db).await, 1, "the live entry is retained");

    drop(pool);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retention_tick_without_failure_records_its_last_success() {
    let (db, app, idp) = setup().await;
    let pool = db.runtime_config.build_pool().unwrap();
    let last_success = Arc::new(registry_breg::metrics::LastSuccess::default());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let retention = tokio::spawn(registry_breg::run_subject_access_log_retention_for_test(
        pool.clone(),
        Arc::clone(&last_success),
        shutdown_rx,
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while last_success.age().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a retention tick without failure was never recorded as a success"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    shutdown_tx.send(true).unwrap();
    retention.await.unwrap();

    drop(pool);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

fn compiled_with_history() -> CompiledRegistry {
    let source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "entities":[{"id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"restricted",
            "fields":[{"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
            "accessLog":{"subjectField":"subject"}}],
        "accessProfiles":[
            {"id":"reader","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "entities":[
                    {"entity":"entry","operations":["get","snapshot","revisions"],"readableFields":["label"],
                        "revisionAccess":true,"rowBoundaries":"unrestricted"}
                ]
            }},
            {"id":"steward","principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "entities":[
                    {"entity":"entry","operations":["create"],"readableFields":["subject","label"],
                        "writableFields":["subject","label"],"rowBoundaries":"unrestricted"}
                ]
            }}
        ]
    });
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

/// Serves record, snapshot, revision, and mutation routes, so a record gets
/// its revision history through the ordinary create path.
async fn setup_with_history() -> (TestDatabase, Router, MockIdp, Arc<CompiledRegistry>) {
    let database = TestDatabase::create(4).await;
    let registry = Arc::new(compiled_with_history());
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            database_id: "history-access-database",
            label: "history-access-package-1",
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    let idp = MockIdp::start().await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        idp.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let mut verifier = oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]);
    verifier.allowed_clients = vec!["portal".into(), "agency".into()];
    let auth = Arc::new(
        RegistryAuthenticator::new(
            &registry,
            verifier,
            keys,
            AuthorityClaimConfig::new("sub", Some("registry_purpose".into())),
        )
        .unwrap(),
    );
    let pool = database.runtime_config.build_pool().unwrap();
    let lock_key = RegistryLockKey::derive(PACKAGE).unwrap();
    let audit =
        database.audit(AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).unwrap());
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let records = PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let revisions = PostgresRevisionReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    );
    let snapshots = PostgresSnapshotReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    );
    let mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        "history-access-instance",
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    let service = HttpService::new(
        registry.clone(),
        ReadRuntimeIdentity {
            package_revision: identity.activation_id,
            schema_fingerprint: identity.schema_fingerprint,
        },
        Arc::new(records),
        Arc::new(Ready),
        cursors,
    )
    .with_postgres_revisions(Arc::new(revisions))
    .with_snapshots(Arc::new(snapshots))
    .with_postgres_mutations(Arc::new(mutations));
    (
        database,
        authenticated_router(Arc::new(service), auth),
        idp,
        registry,
    )
}

fn route_operation(
    registry: &CompiledRegistry,
    operation: registry_breg::contract::Operation,
) -> String {
    registry
        .routes()
        .routes
        .iter()
        .find(|route| route.entity_id == "entry" && route.operation == operation)
        .unwrap()
        .id
        .clone()
}

async fn logged_operations(db: &TestDatabase, record: &str) -> Vec<String> {
    db.admin
        .query(
            "SELECT operation_id FROM registry_internal.registry_subject_access_log
              WHERE entity_id='entry' AND record_id=$1::text::uuid ORDER BY accessed_at, operation_id",
            &[&record],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn snapshot_and_revision_reads_write_subject_access_log_entries() {
    let (db, app, idp, registry) = setup_with_history().await;
    let steward = token(&idp, "agency", "steward");
    let reader = token(&idp, "agency", "officer");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/records/entries?accessProfile=steward")
        .header("authorization", format!("Bearer {steward}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "history-access-create")
        .body(Body::from(
            serde_json::to_vec(&json!({"data":{"subject":SUBJECT,"label":"protected-label"}}))
                .unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let record = created["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        logged_operations(&db, &record).await.is_empty(),
        "a write is not a logged read"
    );

    let (status, revisions) = send(
        &app,
        &reader,
        Method::GET,
        &format!("/v1/records/entries/{record}/revisions"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revisions}");
    assert_eq!(revisions["items"].as_array().map(Vec::len), Some(1));
    let revision_operation =
        route_operation(&registry, registry_breg::contract::Operation::Revisions);
    assert_eq!(
        logged_operations(&db, &record).await,
        [revision_operation.as_str()]
    );

    let (status, snapshot) = send(
        &app,
        &reader,
        Method::GET,
        "/v1/records/entries:snapshot",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{snapshot}");
    assert_eq!(snapshot["items"].as_array().map(Vec::len), Some(1));
    let mut logged = logged_operations(&db, &record).await;
    logged.sort();
    let mut expected = vec![
        revision_operation,
        route_operation(&registry, registry_breg::contract::Operation::Snapshot),
    ];
    expected.sort();
    assert_eq!(logged, expected);

    let (status, log) = history(&app, &token(&idp, "portal", SUBJECT), &record, "").await;
    assert_eq!(status, StatusCode::OK, "{log}");
    let events = log["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event["requester"] == "agency"));

    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

/// Sends a request whose response body need not be JSON, as a HEAD answer
/// never is.
async fn send_raw(app: &Router, token: &str, method: Method, uri: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// HEAD on a governed read takes the concealed path of any method the route
/// does not accept: the same status as PUT, no read performed, nothing
/// journaled under the route's GET identity, and no subject access logged.
async fn assert_head_is_refused_like_an_unaccepted_method(
    db: &TestDatabase,
    app: &Router,
    token: &str,
    uri: &str,
) {
    let journal_before = db.audit_entries().len();
    let access_before = access_log_rows(db).await;
    let (unaccepted, _) = send_raw(app, token, Method::PUT, uri).await;
    let (head, body) = send_raw(app, token, Method::HEAD, uri).await;
    assert_eq!(head, StatusCode::NOT_FOUND, "{uri}");
    assert_eq!(head, unaccepted, "{uri} refuses HEAD as it refuses PUT");
    assert!(body.is_empty(), "{uri}");
    let journal = db.audit_entries();
    assert_eq!(
        journal.len(),
        journal_before,
        "{uri} refuses before any journaled read: {:#?}",
        &journal[journal_before..]
    );
    assert_eq!(
        access_log_rows(db).await,
        access_before,
        "{uri} logs no subject access"
    );
}

#[tokio::test]
async fn head_on_record_reads_is_refused_without_a_journaled_read() {
    let (db, app, idp) = setup().await;
    let agency = token(&idp, "agency", "officer");
    for uri in [
        format!("/v1/records/entries/{RECORD_A}"),
        "/v1/records/entries?$top=1".to_owned(),
    ] {
        assert_head_is_refused_like_an_unaccepted_method(&db, &app, &agency, &uri).await;
    }
    let (status, _) = send_raw(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the same read is served to GET");
    assert_eq!(access_log_rows(&db).await, 1);
    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn head_on_subject_access_log_reads_is_refused_without_a_journaled_read() {
    let (db, app, idp) = setup().await;
    let agency = token(&idp, "agency", "officer");
    let owner = token(&idp, "portal", SUBJECT);
    let (status, _) = send_raw(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let uri = format!("/v1/records/entries/{RECORD_A}/access-log");
    assert_head_is_refused_like_an_unaccepted_method(&db, &app, &owner, &uri).await;
    let (status, log) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same read is served to GET: {log}"
    );
    assert_eq!(log["events"].as_array().map(Vec::len), Some(1));
    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn head_on_history_reads_is_refused_without_a_journaled_read() {
    let (db, app, idp, _) = setup_with_history().await;
    let steward = token(&idp, "agency", "steward");
    let reader = token(&idp, "agency", "officer");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/records/entries?accessProfile=steward")
        .header("authorization", format!("Bearer {steward}"))
        .header("content-type", "application/json")
        .header("idempotency-key", "history-head-create")
        .body(Body::from(
            serde_json::to_vec(&json!({"data":{"subject":SUBJECT,"label":"protected-label"}}))
                .unwrap(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    let record = created["data"]["recordIdentifier"]
        .as_str()
        .unwrap()
        .to_owned();
    for uri in [
        format!("/v1/records/entries/{record}/revisions"),
        "/v1/records/entries:snapshot".to_owned(),
    ] {
        assert_head_is_refused_like_an_unaccepted_method(&db, &app, &reader, &uri).await;
    }
    assert!(logged_operations(&db, &record).await.is_empty());
    let (status, _) = send_raw(
        &app,
        &reader,
        Method::GET,
        &format!("/v1/records/entries/{record}/revisions"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the same read is served to GET");
    assert_eq!(logged_operations(&db, &record).await.len(), 1);
    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}
