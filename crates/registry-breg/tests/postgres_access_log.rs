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
use registry_breg::mutation::MutationFaultPoint;
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
    compiled_with_profiles(false)
}

/// The same registry plus a non-default `reasoned` profile that requires an
/// access reason on every request.
fn compiled_with_access_reason() -> CompiledRegistry {
    compiled_with_profiles(true)
}

fn compiled_with_profiles(with_reasoned: bool) -> CompiledRegistry {
    compile_access_source(access_source(with_reasoned))
}

/// The same registry as `compiled_with_access_reason`, with a read-triggered
/// hook that alerts on every read under the `reasoned` profile.
fn compiled_with_read_alert() -> CompiledRegistry {
    let mut source = access_source(true);
    source["recordTypes"]["entry"]["hooks"] = json!([
        {"id":"reasoned-read","phase":"after","trigger":"read","profiles":["reasoned"],"projection":[]}
    ]);
    compile_access_source(source)
}

fn compile_access_source(source: Value) -> CompiledRegistry {
    compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn access_source(with_reasoned: bool) -> Value {
    let permission = json!({"recordType":"entry", "operations":["get","list","lookup"],
        "readableFields":["label"], "lookups":[{"selector":"by-subject","valueOrigin":"request"}],
        "rowBoundaries":"unrestricted"});
    let mut source = json!({"datasets":{"records": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "recordTypes":{"entry": {"primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"restricted",
            "fields":[{"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
            "selectorProfiles":[{"id":"by-subject","fields":["subject"]}],
            "accessLog":{"subjectField":"subject","trustedIntermediaries":["evidence-service"],
                "exemptions":{"investigator":{"reason":"investigation-policy-canary","delayDays":7}}}}},
        "accessProfiles":{
            "reader": {"default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{"records":[permission.clone()]}},
            "investigator": {"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{"records":[permission.clone()]}}
        }
    });
    if with_reasoned {
        source["accessProfiles"].as_object_mut().unwrap().insert(
            "reasoned".to_owned(),
            json!({"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"requireAccessReason":true,"permissions":{"records":[permission]}}),
        );
    }
    source
}

fn compiled_relationships() -> CompiledRegistry {
    let source = json!({"datasets":{"records": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "recordTypes":{
            "case": {"primaryDataset":"records","route":"cases","mutationMode":"mutable","classification":"restricted",
                "fields":[{"id":"case-code","type":"string","maximumLength":64,"required":true,"classification":"restricted"}],
                "readPaths":[{"id":"people","through":"case-person","to":"person","route":"people"}]},
            "case-person": {"primaryDataset":"records","route":"case-people","mutationMode":"mutable","classification":"restricted",
                "fields":[
                    {"id":"case","type":"reference","target":"case","required":true,"classification":"restricted"},
                    {"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}]},
            "person": {"primaryDataset":"records","route":"people","mutationMode":"mutable","classification":"restricted",
                "fields":[
                    {"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                    {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
                "accessLog":{"subjectField":"subject","exemptions":{
                    "investigator":{"reason":"target-local-policy-canary","delayDays":7},
                    "relationship-investigator":{"sourceRecordType":"case","reason":"relationship-policy-canary","delayDays":7}}}}
        },
        "accessProfiles":{
            "reader": {"default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "records":[
                    {"recordType":"person","operations":["get"],"readableFields":["label"],"rowBoundaries":"unrestricted"}
                ]
            }},
            "investigator": {"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{
                "records":[
                    {"recordType":"case","operations":["get"],"readableFields":["case-code"],"rowBoundaries":"unrestricted",
                        "readPaths":[{"path":"people","readableFields":["label"]}]},
                    {"recordType":"person","operations":["get"],"readableFields":["label"],"rowBoundaries":"unrestricted"}
                ]
            }},
            "relationship-investigator": {"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"actorKind":"service","requesterClients":["agency"],"permissions":{
                "records":[
                    {"recordType":"case","operations":["get"],"readableFields":["case-code"],"rowBoundaries":"unrestricted",
                        "readPaths":[{"path":"people","readableFields":["label"]}]}
                ]
            }}
        }
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
    )
    .with_event_destinations(None, "access-instance");
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
    setup_registry(compiled()).await
}

async fn setup_registry(registry: CompiledRegistry) -> (TestDatabase, Router, MockIdp) {
    let database = TestDatabase::create(2).await;
    let registry = Arc::new(registry);
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
    // The seeded records carry a retained revision, as every written record does.
    for id in [RECORD_A, RECORD_B] {
        database.admin.execute("INSERT INTO registry_internal.registry_revisions
                (entity_id,record_id,record_reference,record_revision,record_lifecycle,package_revision,
                 operation_id,mutation_kind,principal_reference,request_reference,erased_at)
             VALUES ('entry',$1::text::uuid,$2,1,'active',$3,'seed','create','principal','request',now())",
            &[&id, &format!("reference-{id}"), &identity.activation_id]).await.unwrap();
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
    )
    .with_event_destinations(None, "access-instance");
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
async fn direct_client_is_distinguished_in_allowed_and_refused_request_audit() {
    let (db, app, idp) = setup().await;
    let portal = token(&idp, "portal", SUBJECT);
    let agency = token(&idp, "agency", SUBJECT);
    let uri = format!("/v1/records/entries/{RECORD_A}");
    for bearer in [&portal, &agency] {
        assert_eq!(
            send(&app, bearer, Method::GET, &uri, None, None).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        send(
            &app,
            &portal,
            Method::GET,
            &format!("{uri}?$select=subject"),
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let records = db.audit_records();
    assert_eq!(records.len(), 5);
    let profile = AuditProfile::production_from_secret_bytes(vec![0x52; 32].into()).unwrap();
    for (record, phase, client) in [
        (&records[0], "attempt", "portal"),
        (&records[1], "terminal", "portal"),
        (&records[2], "attempt", "agency"),
        (&records[3], "terminal", "agency"),
        (&records[4], "refusal", "portal"),
    ] {
        let activation = record["activationId"].as_str().unwrap();
        let client_reference = profile
            .key_hasher()
            .audit_reference_hash("breg-client-v1", activation, client)
            .unwrap();
        assert_eq!(record["phase"], phase);
        assert_eq!(record["clientReference"], client_reference);
        assert_eq!(
            record["principalReference"],
            records[0]["principalReference"]
        );
        assert!(record.get("authorization").is_none());
    }
    let rendered = json!(records).to_string();
    for raw in [
        SUBJECT,
        PURPOSE,
        "\"portal\"",
        "\"agency\"",
        &portal,
        &agency,
    ] {
        assert!(!rendered.contains(raw));
    }
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
        .any(|entry| entry["schema"] == "breg-access-log/v2"
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
            entry["schema"] == "breg-access-log/v2"
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
    let source = json!({"datasets":{"records": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "recordTypes":{"entry": {"primaryDataset":"records","route":"entries","mutationMode":"mutable","classification":"restricted",
            "fields":[{"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
                {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}],
            "accessLog":{"subjectField":"subject"}}},
        "accessProfiles":{
            "reader": {"default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "records":[
                    {"recordType":"entry","operations":["get","snapshot","revisions"],"readableFields":["label"],
                        "revisionAccess":true,"rowBoundaries":"unrestricted"}
                ]
            }},
            "steward": {"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],"permissions":{
                "records":[
                    {"recordType":"entry","operations":["create"],"readableFields":["subject","label"],
                        "writableFields":["subject","label"],"rowBoundaries":"unrestricted"}
                ]
            }}
        }
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
    setup_with_mutations(compiled_with_history(), None).await
}

/// The same routes over `registry`, with the mutation service failing at
/// `fault` when one is given.
async fn setup_with_mutations(
    registry: CompiledRegistry,
    fault: Option<MutationFaultPoint>,
) -> (TestDatabase, Router, MockIdp, Arc<CompiledRegistry>) {
    let database = TestDatabase::create(4).await;
    let registry = Arc::new(registry);
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
    )
    .with_event_destinations(None, "access-instance");
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
    let mut mutations = PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        "history-access-instance",
        lock_key,
        Duration::from_secs(2),
        audit,
    );
    if let Some(fault) = fault {
        mutations = mutations.with_fault_for_test(fault);
    }
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

/// A request under the `reasoned` profile. `reason` is the raw header value, so
/// a test can send a malformed one; `None` sends no header.
async fn send_reasoned(
    app: &Router,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
    reason: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    if let Some(reason) = reason {
        request = request.header("Registry-Access-Reason", reason);
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
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn reason_header(reason: &str) -> String {
    URL_SAFE_NO_PAD.encode(reason)
}

#[tokio::test]
async fn a_request_without_its_required_access_reason_is_refused_before_any_record_is_read() {
    let (db, app, idp) = setup_registry(compiled_with_access_reason()).await;
    let agency = token(&idp, "agency", "officer");
    let record = format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned");
    let (status, problem) = send_reasoned(&app, &agency, Method::GET, &record, None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    assert_eq!(problem["code"], "request.access_reason_required");
    let (status, problem) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        "/v1/records/entries?accessProfile=reasoned&$top=1",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    assert_eq!(problem["code"], "request.access_reason_required");
    let (status, problem) = send_reasoned(
        &app,
        &agency,
        Method::POST,
        "/v1/records/entries:lookup?accessProfile=reasoned",
        Some(json!({"selector":"by-subject","values":{"subject":SUBJECT}})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    assert_eq!(problem["code"], "request.access_reason_required");
    assert_eq!(access_log_rows(&db).await, 0);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn an_invalid_access_reason_is_refused_like_a_missing_one() {
    let (db, app, idp) = setup_registry(compiled_with_access_reason()).await;
    let agency = token(&idp, "agency", "officer");
    let record = format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned");
    let too_long = reason_header(&"r".repeat(513));
    let control = reason_header("reason\nwith control");
    let blank = reason_header("   ");
    let padded = format!("{}=", reason_header("padded"));
    let doubled = format!("{0}, {0}", reason_header("twice"));
    for invalid in [
        "not base64url!",
        "",
        padded.as_str(),
        too_long.as_str(),
        control.as_str(),
        blank.as_str(),
        doubled.as_str(),
    ] {
        let (status, problem) =
            send_reasoned(&app, &agency, Method::GET, &record, None, Some(invalid)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid:?}: {problem}");
        assert_eq!(problem["code"], "request.access_reason_required");
    }
    assert_eq!(access_log_rows(&db).await, 0);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_valid_access_reason_is_stored_and_returned_by_the_access_log_route() {
    let (db, app, idp) = setup_registry(compiled_with_access_reason()).await;
    let agency = token(&idp, "agency", "officer");
    let owner = token(&idp, "portal", SUBJECT);
    let reason = "welfare check, case 42 é";
    let (status, record) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned"),
        None,
        Some(&reason_header(reason)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{record}");
    let (status, page) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["accessReason"], reason);
    assert_eq!(events[0]["accessKind"], "read");
    let stored: Option<String> = db
        .admin
        .query_one(
            "SELECT access_reason FROM registry_internal.registry_subject_access_log",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored.as_deref(), Some(reason));
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn the_access_log_route_requires_the_reason_under_a_profile_that_requires_one() {
    let (db, app, idp) = setup_registry(compiled_with_access_reason()).await;
    let owner = token(&idp, "portal", SUBJECT);
    let uri = format!("/v1/records/entries/{RECORD_A}/access-log?accessProfile=reasoned");
    let (status, problem) = send_reasoned(&app, &owner, Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    assert_eq!(problem["code"], "request.access_reason_required");
    let (status, page) = send_reasoned(
        &app,
        &owner,
        Method::GET,
        &uri,
        None,
        Some(&reason_header("subject reviews their own history")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_profile_without_the_flag_needs_no_reason_and_logs_none() {
    let (db, app, idp) = setup_registry(compiled_with_access_reason()).await;
    let agency = token(&idp, "agency", "officer");
    let owner = token(&idp, "portal", SUBJECT);
    let (status, _) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, page) = history(&app, &owner, RECORD_A, "").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0]["accessReason"].is_null());
    drop(app);
    drop(idp);
    db.cleanup().await;
}

/// Every outbox row a read alert captured, as `(event type, envelope)`.
async fn read_alerts(db: &TestDatabase) -> Vec<(String, Value)> {
    db.admin
        .query(
            "SELECT event_type, convert_from(payload, 'UTF8') FROM registry_internal.registry_outbox
              WHERE trigger = 'read' ORDER BY created_at, event_id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            let payload: String = row.get(1);
            (row.get(0), serde_json::from_str(&payload).unwrap())
        })
        .collect()
}

async fn logged_event_ids(db: &TestDatabase) -> Vec<String> {
    db.admin
        .query(
            "SELECT event_id::text FROM registry_internal.registry_subject_access_log ORDER BY event_id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn a_read_under_an_alerting_profile_emits_one_event_per_access_log_entry() {
    let (db, app, idp) = setup_registry(compiled_with_read_alert()).await;
    let agency = token(&idp, "agency", "officer");
    let reason = "welfare check, case 42";
    let (status, _) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned"),
        None,
        Some(&reason_header(reason)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alerts = read_alerts(&db).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    let (event_type, envelope) = &alerts[0];
    assert_eq!(event_type, "reasoned-read");
    let data = &envelope["data"];
    assert_eq!(data["recordType"], "entry");
    assert_eq!(data["recordId"], RECORD_A);
    assert_eq!(data["revision"], 1);
    assert_eq!(data["trigger"], "read");
    assert_eq!(data["values"], json!({}));
    let logged = logged_event_ids(&db).await;
    assert_eq!(logged.len(), 1);
    assert_eq!(
        data["access"],
        json!({
            "accessProfile": "reasoned",
            "operationId": data["access"]["operationId"],
            "requester": "agency",
            "purpose": PURPOSE,
            "accessReason": reason,
            "accessLogEventId": logged[0],
        })
    );
    assert!(data["access"]["operationId"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));

    let (status, _) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        "/v1/records/entries?accessProfile=reasoned&$top=2",
        None,
        Some(&reason_header(reason)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let alerts = read_alerts(&db).await;
    assert_eq!(alerts.len(), 3, "a list of two records adds two events");
    let mut alerted = alerts
        .iter()
        .map(|(_, envelope)| {
            envelope["data"]["access"]["accessLogEventId"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    alerted.sort();
    assert_eq!(alerted, logged_event_ids(&db).await);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_read_alert_carries_no_record_values() {
    let (db, app, idp) = setup_registry(compiled_with_read_alert()).await;
    let agency = token(&idp, "agency", "officer");
    let (status, record) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned"),
        None,
        Some(&reason_header("welfare check")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{record}");
    let rendered = json!(read_alerts(&db).await).to_string();
    for value in ["protected-label", SUBJECT] {
        assert!(!rendered.contains(value), "{value} leaked into {rendered}");
    }
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_read_under_a_profile_the_hook_does_not_name_emits_none() {
    let (db, app, idp) = setup_registry(compiled_with_read_alert()).await;
    let agency = token(&idp, "agency", "officer");
    for uri in [
        format!("/v1/records/entries/{RECORD_A}"),
        "/v1/records/entries?$top=2".to_owned(),
    ] {
        let (status, _) = send_reasoned(&app, &agency, Method::GET, &uri, None, None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(access_log_rows(&db).await, 3, "the reads were logged");
    assert!(read_alerts(&db).await.is_empty());
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_failed_read_emits_no_alert() {
    let (db, app, idp) = setup_registry(compiled_with_read_alert()).await;
    let agency = token(&idp, "agency", "officer");
    let (status, _) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        &format!("/v1/records/entries/{RECORD_A}?accessProfile=reasoned"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no reason");
    let (status, _) = send_reasoned(
        &app,
        &agency,
        Method::GET,
        "/v1/records/entries/00000000-0000-4000-8000-0000000000ff?accessProfile=reasoned",
        None,
        Some(&reason_header("welfare check")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such record");
    assert!(read_alerts(&db).await.is_empty());
    assert_eq!(access_log_rows(&db).await, 0);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

/// An `entry` type with `accessLog` and a `note` type without one. The `clerk`
/// and `investigator` profiles require an access reason; the `steward` does
/// not. Entries by the `investigator` are delayed seven days, and a read hook
/// alerts on every `clerk` read of an entry.
fn compiled_with_writes() -> CompiledRegistry {
    let fields = json!([
        {"id":"subject","type":"string","minimumLength":1,"maximumLength":128,"required":true,"classification":"restricted"},
        {"id":"label","type":"string","maximumLength":128,"required":true,"classification":"restricted"}
    ]);
    let writer = |record_type: &str, operations: Value| {
        json!({"recordType":record_type,"operations":operations,
            "readableFields":["subject","label"],"writableFields":["subject","label"],
            "rowBoundaries":"unrestricted"})
    };
    let entry_writes = json!(["get", "create", "patch", "batch", "tombstone"]);
    let profile = |reason: bool, records: Value| {
        json!({"principalClaim":"sub","requiredScopes":"unrestricted",
            "requiredPurposes":[PURPOSE],"requireAccessReason":reason,
            "permissions":{"records":records}})
    };
    let source = json!({"datasets":{"records": {}},
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1", "kind":"BRegProject",
        "project":{"id":PACKAGE,"version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
        "recordTypes":{
            "entry": {"primaryDataset":"records","route":"entries","mutationMode":"mutable",
                "tombstone":true,"batch":{"maximumItems":10,"maximumBytes":65536},
                "classification":"restricted","fields":fields.clone(),
                "accessLog":{"subjectField":"subject","retentionDays":30,
                    "exemptions":{"investigator":{"reason":"investigation-policy-canary","delayDays":7}}},
                "hooks":[{"id":"clerk-read","phase":"after","trigger":"read","profiles":["clerk"],"projection":[]}]},
            "note": {"primaryDataset":"records","route":"notes","mutationMode":"mutable",
                "classification":"restricted","fields":fields}},
        "accessProfiles":{
            "reader": {"default":true,"principalClaim":"sub","requiredScopes":"unrestricted","requiredPurposes":[PURPOSE],
                "permissions":{"records":[{"recordType":"entry","operations":["get"],"readableFields":["label"],"rowBoundaries":"unrestricted"}]}},
            "clerk": profile(true, json!([writer("entry", entry_writes.clone()), writer("note", json!(["create"]))])),
            "investigator": profile(true, json!([writer("entry", json!(["get", "create"]))])),
            "steward": profile(false, json!([writer("entry", entry_writes)]))
        }
    });
    compile_access_source(source)
}

/// One write under `profile`. `reason` is sent as the access reason header
/// when given. Answers the status, the body, and the response ETag.
#[allow(clippy::too_many_arguments)]
async fn write_as(
    app: &Router,
    token: &str,
    profile: &str,
    method: Method,
    path: &str,
    body: Option<(&str, Value)>,
    if_match: Option<&str>,
    reason: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{path}{separator}accessProfile={profile}"))
        .header("authorization", format!("Bearer {token}"))
        .header("idempotency-key", uuid::Uuid::new_v4().to_string());
    if let Some(etag) = if_match {
        request = request.header("if-match", etag);
    }
    if let Some(reason) = reason {
        request = request.header("Registry-Access-Reason", reason_header(reason));
    }
    let body = match body {
        Some((content_type, value)) => {
            request = request.header("content-type", content_type);
            Body::from(serde_json::to_vec(&value).unwrap())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body, etag)
}

/// Create one `entry` for `SUBJECT` as `profile`, and answer its id and ETag.
async fn create_entry(
    app: &Router,
    token: &str,
    profile: &str,
    reason: Option<&str>,
) -> (String, String) {
    let (status, body, etag) = write_as(
        app,
        token,
        profile,
        Method::POST,
        "/v1/records/entries",
        Some((
            "application/json",
            json!({"data":{"subject":SUBJECT,"label":"first-label"}}),
        )),
        None,
        reason,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        body["data"]["recordIdentifier"]
            .as_str()
            .unwrap()
            .to_owned(),
        etag.expect("a created record carries an ETag"),
    )
}

/// Every stored entry as `(record, kind, operation, reason)`, in write order.
async fn logged_entries(db: &TestDatabase) -> Vec<(String, String, String, Option<String>)> {
    db.admin
        .query(
            "SELECT record_id::text, access_kind, operation_id, access_reason
               FROM registry_internal.registry_subject_access_log
              ORDER BY accessed_at, event_id",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect()
}

#[tokio::test]
async fn each_direct_write_under_a_reasoned_profile_logs_one_write_entry_with_its_reason() {
    let (db, app, idp, registry) = setup_with_mutations(compiled_with_writes(), None).await;
    let clerk = token(&idp, "agency", "clerk");
    let (first, etag) = create_entry(&app, &clerk, "clerk", Some("create reason")).await;

    let (status, body, etag) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::PATCH,
        &format!("/v1/records/entries/{first}"),
        Some((
            "application/json-patch+json",
            json!([{"op":"replace","path":"/data/label","value":"second-label"}]),
        )),
        Some(&etag),
        Some("patch reason"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let etag = etag.expect("a patched record carries an ETag");

    let (status, body, _) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::POST,
        "/v1/records/entries:batch",
        Some((
            "application/json",
            json!({"items":[
                {"operation":"create","data":{"subject":SUBJECT,"label":"batch-label"}},
                {"operation":"patch","recordIdentifier":first,"ifMatch":etag,
                    "patch":[{"op":"replace","path":"/data/label","value":"third-label"}]}
            ]}),
        )),
        None,
        Some("batch reason"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = body["results"][0]["recordIdentifier"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned();
    let second_etag = body["results"][0]["etag"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"))
        .to_owned();

    let (status, body, _) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::DELETE,
        &format!("/v1/records/entries/{second}"),
        None,
        Some(&second_etag),
        Some("tombstone reason"),
    )
    .await;
    assert!(status.is_success(), "{status}: {body}");

    let operation = |operation| route_operation(&registry, operation);
    use registry_breg::contract::Operation;
    let write = |record: &str, operation: String, reason: &str| {
        (
            record.to_owned(),
            "write".to_owned(),
            operation,
            Some(reason.to_owned()),
        )
    };
    let mut logged = logged_entries(&db).await;
    let mut expected = vec![
        write(&first, operation(Operation::Create), "create reason"),
        write(&first, operation(Operation::Patch), "patch reason"),
        write(&second, operation(Operation::Batch), "batch reason"),
        write(&first, operation(Operation::Batch), "batch reason"),
        write(&second, operation(Operation::Tombstone), "tombstone reason"),
    ];
    logged.sort();
    expected.sort();
    assert_eq!(logged, expected);

    let (status, page) = history(&app, &token(&idp, "portal", SUBJECT), &first, "").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 3, "{page}");
    assert!(events.iter().all(|event| event["accessKind"] == "write"
        && event["requester"] == "agency"
        && event["serviceClient"].is_null()));
    let mut reasons = events
        .iter()
        .map(|event| event["accessReason"].as_str().unwrap())
        .collect::<Vec<_>>();
    reasons.sort_unstable();
    assert_eq!(reasons, ["batch reason", "create reason", "patch reason"]);
    db.assert_every_audit_request_answered_once();
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_write_under_a_profile_without_the_flag_logs_no_write_entry() {
    let (db, app, idp, _) = setup_with_mutations(compiled_with_writes(), None).await;
    let steward = token(&idp, "agency", "steward");
    let (record, etag) = create_entry(&app, &steward, "steward", None).await;
    let (status, body, _) = write_as(
        &app,
        &steward,
        "steward",
        Method::PATCH,
        &format!("/v1/records/entries/{record}"),
        Some((
            "application/json-patch+json",
            json!([{"op":"replace","path":"/data/label","value":"second-label"}]),
        )),
        Some(&etag),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(logged_entries(&db).await, []);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_type_without_an_access_log_requires_the_reason_and_stores_nothing() {
    let (db, app, idp, _) = setup_with_mutations(compiled_with_writes(), None).await;
    let clerk = token(&idp, "agency", "clerk");
    let note = || {
        Some((
            "application/json",
            json!({"data":{"subject":SUBJECT,"label":"note-label"}}),
        ))
    };
    let (status, problem, _) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::POST,
        "/v1/records/notes",
        note(),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    assert_eq!(problem["code"], "request.access_reason_required");
    let (status, body, _) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::POST,
        "/v1/records/notes",
        note(),
        None,
        Some("note reason"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(logged_entries(&db).await, []);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_rolled_back_write_leaves_no_write_entry() {
    let (db, app, idp, _) = setup_with_mutations(
        compiled_with_writes(),
        Some(MutationFaultPoint::BeforeCommit),
    )
    .await;
    let clerk = token(&idp, "agency", "clerk");
    let (status, body, _) = write_as(
        &app,
        &clerk,
        "clerk",
        Method::POST,
        "/v1/records/entries",
        Some((
            "application/json",
            json!({"data":{"subject":SUBJECT,"label":"first-label"}}),
        )),
        None,
        Some("create reason"),
    )
    .await;
    assert!(!status.is_success(), "{status}: {body}");
    assert_eq!(logged_entries(&db).await, []);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn a_write_entry_raises_no_read_alert() {
    let (db, app, idp, _) = setup_with_mutations(compiled_with_writes(), None).await;
    let clerk = token(&idp, "agency", "clerk");
    let (record, _) = create_entry(&app, &clerk, "clerk", Some("create reason")).await;
    assert_eq!(logged_entries(&db).await.len(), 1);
    assert_eq!(read_alerts(&db).await, []);
    // The hook is live: a read under the same profile alerts.
    let (status, body) = send_reasoned(
        &app,
        &clerk,
        Method::GET,
        &format!("/v1/records/entries/{record}?accessProfile=clerk"),
        None,
        Some(&reason_header("read reason")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(read_alerts(&db).await.len(), 1);
    drop(app);
    drop(idp);
    db.cleanup().await;
}

#[tokio::test]
async fn write_entries_keep_the_retention_and_exemption_delay_of_read_entries() {
    let (db, app, idp, _) = setup_with_mutations(compiled_with_writes(), None).await;
    let clerk = token(&idp, "agency", "clerk");
    let investigator = token(&idp, "agency", "investigator");
    let (prompt, _) = create_entry(&app, &clerk, "clerk", Some("create reason")).await;
    let (delayed, _) =
        create_entry(&app, &investigator, "investigator", Some("investigation")).await;
    let timing = |record: String| {
        let db = &db;
        async move {
            let row = db
                .admin
                .query_one(
                    "SELECT extract(day FROM visible_after - accessed_at)::int,
                            extract(day FROM expires_at - accessed_at)::int, exemption_reason
                       FROM registry_internal.registry_subject_access_log
                      WHERE record_id = $1::text::uuid",
                    &[&record],
                )
                .await
                .unwrap();
            (
                row.get::<_, i32>(0),
                row.get::<_, i32>(1),
                row.get::<_, Option<String>>(2),
            )
        }
    };
    assert_eq!(timing(prompt.clone()).await, (0, 30, None));
    assert_eq!(
        timing(delayed.clone()).await,
        (7, 30, Some("investigation-policy-canary".to_owned()))
    );
    let owner = token(&idp, "portal", SUBJECT);
    let (_, page) = history(&app, &owner, &delayed, "").await;
    assert_eq!(page["events"].as_array().unwrap().len(), 0, "{page}");

    db.admin
        .execute(
            "UPDATE registry_internal.registry_subject_access_log
                SET accessed_at = accessed_at - interval '31 days',
                    visible_after = visible_after - interval '31 days',
                    expires_at = expires_at - interval '31 days'",
            &[],
        )
        .await
        .unwrap();
    let (_, page) = history(&app, &owner, &prompt, "").await;
    assert_eq!(page["events"].as_array().unwrap().len(), 0, "{page}");
    let pool = db.runtime_config.build_pool().unwrap();
    let (erased, _) = registry_breg::expire_subject_access_log_for_test(&pool, None)
        .await
        .unwrap();
    assert_eq!(erased, 2);
    assert_eq!(logged_entries(&db).await, []);
    drop(pool);
    drop(app);
    drop(idp);
    db.cleanup().await;
}
