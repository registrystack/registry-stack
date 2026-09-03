// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_yaml;
use registry_breg::cursor::CursorCodec;
use registry_breg::metrics::{self, Metrics};
use registry_breg::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema, ExpectedManagedCatalog,
    PostgresRecordReadService, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_breg::startup::with_request_timeout_and_metrics_for_test;
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use tower::util::ServiceExt as _;
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "anonymous-refusal-registry";
const INSTANCE_ID: &str = "anonymous-refusal-instance";
const DATABASE_ID: &str = "anonymous-refusal-database";
const PACKAGE_REVISION: &str = "package-anonymous-refusal-1";
const PRINCIPAL_CANARY: &str = "principal-value-must-not-enter-anonymous-refusal-metrics";

const PROJECT: &str = r#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: anonymous-refusal-registry
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
entities:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    tombstone: true
    classification: public
    fields:
      - {id: label, type: string, required: true, maxLength: 100, classification: public}
      - {id: jurisdiction, type: string, required: true, maxLength: 32, classification: internal}
accessProfiles:
  - id: public
    default: true
    anonymous: true
    grants:
      - entity: case
        operations: [get, list]
        readableFields: [label]
        filterableFields: [label]
        sortableFields: [label]
  - id: caseworker
    principalClaim: registry_principal
    requiredScopes: [registry.read]
    requiredPurposes: [case-management]
    grants:
      - entity: case
        operations: [get, list]
        readableFields: [label, jurisdiction]
        filterableFields: [label, jurisdiction]
        sortableFields: [label]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdictions, operator: in}
"#;

/// An unauthenticated caller must not be able to append to the hash-chained
/// journal. Anonymous pre-admission refusals are counted on the operator
/// metrics listener instead, while a refusal that carries a principal is
/// journaled exactly as before and the chain stays contiguous across the mix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_refusals_are_counted_while_principal_refusals_stay_chained() {
    let database = TestDatabase::create(8).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = Arc::new(compiled_registry());
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("migration installs the complete compiled PostgreSQL schema");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: PACKAGE_REVISION,
            package_sequence: 1,
        },
    )
    .await
    .expect("migration initializes durable Registry identity");
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock identity is bounded");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x3c; 32].into())
        .expect("test owns a strongly keyed audit profile");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x3d; 32]), Duration::from_secs(300))
            .expect("test cursor key is valid"),
    );
    let records = PostgresRecordReadService::new(
        pool,
        Arc::clone(&registry),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit_profile.clone(),
        Arc::clone(&cursors),
    );
    let service = Arc::new(HttpService::new(
        Arc::clone(&registry),
        ReadRuntimeIdentity {
            package_revision: identity.package_revision.clone(),
            schema_fingerprint: identity.schema_fingerprint.clone(),
        },
        Arc::new(records),
        Arc::new(AlwaysReady),
        cursors,
    ));
    let metrics = Arc::new(Metrics::without_pool_for_test());
    let app = with_request_timeout_and_metrics_for_test(
        router(service),
        Duration::from_secs(10),
        Some(Arc::clone(&metrics)),
    );

    // An admitted anonymous read still brackets its release in the journal:
    // this change only stops journaling refusals that name no principal.
    let admitted = send(&app, "/v1/records/cases", None).await;
    assert_eq!(admitted.status(), StatusCode::OK);
    let admitted_rows = audit_count(&database).await;
    assert_eq!(
        admitted_rows, 2,
        "an admitted anonymous read keeps its attempt and terminal records"
    );

    // Anonymous pre-admission refusals: a profile the caller cannot hold, an
    // unknown profile, and an invalid query on a route it can otherwise reach.
    for uri in [
        "/v1/records/cases?accessProfile=caseworker",
        "/v1/records/cases?accessProfile=unknown",
        "/v1/records/cases?$select=jurisdiction",
        "/v1/records/cases?pageSize=not-a-number",
    ] {
        let response = send(&app, uri, None).await;
        assert!(
            response.status().is_client_error(),
            "{uri} is refused before admission"
        );
    }
    assert_eq!(
        audit_count(&database).await,
        admitted_rows,
        "anonymous pre-admission refusals append no chained journal record"
    );

    // The same refusals from an authenticated principal stay journaled.
    let refusals = [
        "/v1/records/cases?accessProfile=unknown",
        "/v1/records/cases?pageSize=not-a-number",
    ];
    for uri in refusals {
        let response = send(&app, uri, Some(caseworker_claims(["zone-a"]))).await;
        assert!(
            response.status().is_client_error(),
            "{uri} is refused for the authenticated caller too"
        );
    }
    let after_principal_refusals = audit_count(&database).await;
    assert_eq!(
        after_principal_refusals,
        admitted_rows + refusals.len() as i64,
        "a refusal that names a principal still appends one chained record"
    );

    // Mixed traffic afterwards: the chain remains contiguous and verifies
    // under the keyed platform chain hasher.
    let served = send(
        &app,
        "/v1/records/cases?accessProfile=caseworker",
        Some(caseworker_claims(["zone-a"])),
    )
    .await;
    assert_eq!(served.status(), StatusCode::OK);
    let anonymous = send(&app, "/v1/records/cases?accessProfile=caseworker", None).await;
    assert_eq!(anonymous.status(), StatusCode::NOT_FOUND);

    let envelopes = ordered_audit_envelopes(&database, &audit_profile).await;
    assert_eq!(
        envelopes.len() as i64,
        after_principal_refusals + 2,
        "only the admitted authenticated read extends the chain after the mix"
    );
    let phases = envelopes
        .iter()
        .map(|envelope| {
            envelope.record["phase"]
                .as_str()
                .expect("phase is recorded")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec!["attempt", "terminal", "refusal", "refusal", "attempt", "terminal"],
        "the journal holds the admitted reads and the principal refusals only"
    );
    let audit_text = envelopes
        .iter()
        .map(|envelope| envelope.record.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!audit_text.contains(PRINCIPAL_CANARY));

    // The operational signal the journal no longer carries: one bounded
    // counter series per route, method, and refusal reason.
    let body = scrape(&metrics).await;
    assert!(
        body.contains("# TYPE breg_anonymous_refusals_total counter\n"),
        "the anonymous refusal counter is exposed: {body}"
    );
    assert!(
        body.contains(
            "breg_anonymous_refusals_total{route=\"/v1/records/cases\",method=\"GET\",reason=\"read_concealed\"} 3\n"
        ),
        "concealed anonymous reads are counted under the matched template: {body}"
    );
    assert!(
        body.contains(
            "breg_anonymous_refusals_total{route=\"/v1/records/cases\",method=\"GET\",reason=\"read_request_invalid\"} 1\n"
        ),
        "an unparsable anonymous query is counted under its own reason: {body}"
    );
    assert!(
        body.contains(
            "breg_anonymous_refusals_total{route=\"/v1/records/cases\",method=\"GET\",reason=\"read_refused\"} 1\n"
        ),
        "an admitted-surface anonymous refusal is counted under its own reason: {body}"
    );
    assert!(
        !body.contains(PRINCIPAL_CANARY),
        "no request value reaches a counter label"
    );
    assert!(
        !body.contains("accessProfile"),
        "no query value reaches a counter label: {body}"
    );

    database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_yaml(PROJECT.as_bytes()).expect("anonymous refusal fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("anonymous refusal fixture compiles")
}

fn caseworker_claims<const N: usize>(jurisdictions: [&str; N]) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        PRINCIPAL_CANARY,
        BTreeSet::from(["registry.read".to_owned()]),
        Some("case-management".to_owned()),
        BTreeMap::from([(
            "jurisdictions".to_owned(),
            VerifiedClaimValue::direct_string_set(jurisdictions)
                .expect("jurisdictions are direct verified strings"),
        )]),
    )
    .expect("caseworker claims are verified")
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

async fn send(
    app: &axum::Router,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns a response")
}

async fn scrape(metrics: &Arc<Metrics>) -> String {
    let response = metrics::metrics_app(Arc::clone(metrics))
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .expect("scrape request builds"),
        )
        .await
        .expect("scrape request responds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("scrape body reads");
    String::from_utf8(body.to_vec()).expect("scrape body is UTF-8")
}

async fn audit_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit count")
        .get(0)
}

async fn ordered_audit_envelopes(
    database: &TestDatabase,
    profile: &AuditProfile,
) -> Vec<AuditEnvelope> {
    let rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit envelopes");
    let mut envelopes = rows
        .iter()
        .map(|row| {
            serde_json::from_slice::<AuditEnvelope>(&row.get::<_, Vec<u8>>(0))
                .expect("audit envelope is canonical platform JSON")
        })
        .collect::<Vec<_>>();
    let mut ordered = Vec::with_capacity(envelopes.len());
    let mut predecessor = None;
    while !envelopes.is_empty() {
        let position = envelopes
            .iter()
            .position(|envelope| envelope.prev_hash == predecessor)
            .expect("database audit chain has one next envelope");
        let envelope = envelopes.remove(position);
        predecessor = Some(envelope.record_hash);
        ordered.push(envelope);
    }
    let audit_lines = ordered
        .iter()
        .map(|envelope| serde_json::to_string(envelope).expect("audit envelope serializes"))
        .collect::<Vec<_>>();
    verify_jsonl_lines_with_hasher(audit_lines.iter(), &profile.chain_hasher())
        .expect("database audit envelopes form one keyed platform chain");
    ordered
}
