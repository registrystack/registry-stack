// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/action_evidence_provider.rs"]
#[allow(dead_code)]
mod action_evidence_provider;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

#[path = "support/real_action_evidence_provider.rs"]
#[allow(dead_code)]
mod real_action_evidence_provider;

use action_evidence_provider::EvidenceProvider;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use postgres_harness::TestDatabase;
use registry_breg as breg;
use registry_breg::{
    action_evidence::ActionEvidenceEvaluator,
    api::{
        router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture,
        VerifiedRequestClaims,
    },
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    cursor::CursorCodec,
    mutation::MutationFaultPoint,
    postgres::{
        initialize_registry_state_for_catalog_test, install_compiled_schema,
        ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresRecordMutationService,
        PostgresRecordReadService, RegistryLockKey, RegistryStateTestIdentity, RuntimePool,
    },
};
use registry_platform_audit::AuditProfile;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};
use tower::Service as _;
use zeroize::Zeroizing;

const PACKAGE: &str = "farmer-landholding-evidence";
const ACTION: &str = "/v1/actions/register-landholding";

async fn setup(
    source: Option<&str>,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    setup_with_age(source, 60).await
}

async fn setup_with_age(
    source: Option<&str>,
    maximum_age: u64,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    setup_with_contracts(source, maximum_age, None).await
}

async fn setup_with_contracts(
    source: Option<&str>,
    maximum_age: u64,
    contracts: Option<&[u8]>,
) -> (
    TestDatabase,
    Arc<registry_breg::CompiledRegistry>,
    ExpectedRegistryIdentity,
) {
    let database = TestDatabase::create(1).await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/farmer-landholding-evidence");
    let mut project =
        parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    for action in &mut project.actions {
        for capability in &mut action.evidence {
            capability.maximum_observation_age_seconds = maximum_age;
        }
    }
    let assets = [
        "scripts/register-landholding.rhai",
        "scripts/check-procedure.rhai",
        "evidence/farmer-contracts.json",
    ]
    .map(|path| ModuleAssetSource {
        module: None,
        path: path.into(),
        bytes: if path == "scripts/register-landholding.rhai" {
            source.map_or_else(
                || std::fs::read(root.join(path)).unwrap(),
                |s| s.as_bytes().to_vec(),
            )
        } else if path == "evidence/farmer-contracts.json" {
            contracts.map_or_else(
                || std::fs::read(root.join(path)).unwrap(),
                |bytes| bytes.to_vec(),
            )
        } else {
            std::fs::read(root.join(path)).unwrap()
        },
    });
    let registry = Arc::new(
        compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap(),
    );
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .unwrap();
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: "evidence-test",
            database_id: "evidence-test",
            package_revision: "evidence-1",
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(migration);
    task.abort();
    (database, registry, identity)
}

struct Ready;
impl ReadinessProbe for Ready {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}

fn app(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    provider: &EvidenceProvider,
    fault: Option<MutationFaultPoint>,
) -> (axum::Router, RuntimePool) {
    app_with_client(database, registry, identity, provider.client(), fault)
}

fn app_with_client(
    database: &TestDatabase,
    registry: Arc<registry_breg::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
    client: Arc<registry_breg::action_evidence_client::EvidenceActionClient>,
    fault: Option<MutationFaultPoint>,
) -> (axum::Router, RuntimePool) {
    let pool = database.runtime_config.build_pool().unwrap();
    let audit = AuditProfile::production_from_secret_bytes(vec![0x42; 32].into()).unwrap();
    let lock = RegistryLockKey::derive(PACKAGE).unwrap();
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x63; 32]), Duration::from_secs(300)).unwrap(),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock,
        Duration::from_secs(5),
        audit.clone(),
        cursors.clone(),
    ));
    let read_identity = ReadRuntimeIdentity {
        package_revision: identity.package_revision.clone(),
        schema_fingerprint: identity.schema_fingerprint.clone(),
    };
    let mutations = PostgresRecordMutationService::new(
        pool.clone(),
        registry.clone(),
        identity,
        lock,
        Duration::from_secs(5),
        audit,
    )
    .with_evidence_evaluator(Arc::new(ActionEvidenceEvaluator::new(client)));
    let mutations = match fault {
        Some(fault) => mutations.with_fault_for_test(fault),
        None => mutations,
    };
    (
        router(Arc::new(
            HttpService::new(registry, read_identity, reads, Arc::new(Ready), cursors)
                .with_postgres_mutations(Arc::new(mutations)),
        )),
        pool,
    )
}

async fn send(
    mut app: axum::Router,
    path: &str,
    key: &str,
    input: Value,
    authorized: bool,
) -> (StatusCode, Value) {
    let claims = VerifiedRequestClaims::authenticated(
        "registry_principal",
        "synthetic-registrar",
        BTreeSet::from([if authorized {
            "registry:landholding:register"
        } else {
            "registry:unrelated"
        }
        .into()]),
        Some("land-registration".into()),
        BTreeMap::new(),
    )
    .unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(Body::from(serde_json::to_vec(&input).unwrap()))
        .unwrap();
    request.extensions_mut().insert(claims);
    let response = app.call(request).await.unwrap();
    let status = response.status();
    let value =
        serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap();
    (status, value)
}
fn input(parcel: &str, category: bool) -> Value {
    json!({"input":{"farmerPrefix":"  FR ", "farmerNumber":"  12345  ", "parcelCode":parcel, "includeCategory":category}})
}
fn q(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
async fn counts(database: &TestDatabase, registry: &registry_breg::CompiledRegistry) -> Vec<i64> {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
        (SELECT count(*) FROM registry_data.{}),
        (SELECT count(*) FROM registry_data.{}),
        (SELECT count(*) FROM registry_internal.registry_revisions),
        (SELECT count(*) FROM registry_internal.registry_idempotency),
        (SELECT count(*) FROM registry_internal.registry_immediate_action_applications),
        (SELECT count(*) FROM registry_internal.registry_action_evidence_uses)",
                q(&registry.entities()["landholding"].physical_table),
                q(&registry.entities()["procedure-check"].physical_table)
            ),
            &[],
        )
        .await
        .unwrap();
    (0..6).map(|index| row.get(index)).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn signed_evidence_actions_release_postgres_and_commit_atomic_transcripts() {
    let provider = EvidenceProvider::start().await;
    let (database, registry, identity) = setup(None).await;
    let (app, pool) = app(
        &database,
        registry.clone(),
        identity.clone(),
        &provider,
        None,
    );
    let before = counts(&database, &registry).await;
    let denied = send(app.clone(), ACTION, "denied", input("denied", true), false).await;
    assert_eq!(denied.0, StatusCode::NOT_FOUND);
    let mut blank = input("blank", false);
    blank["input"]["farmerNumber"] = json!(" ");
    let refused = send(app.clone(), ACTION, "blank", blank, true).await;
    assert_eq!(refused.0, StatusCode::UNPROCESSABLE_ENTITY, "{}", refused.1);
    assert_eq!(provider.calls(), 0);
    assert_eq!(counts(&database, &registry).await, before);
    // Direct CRUD cannot bypass the only granted landholding write procedure.
    let bypass = send(
        app.clone(),
        "/v1/records/landholdings",
        "bypass",
        json!({"data":{"farmerNumber":"FR-12345","parcelCode":"bypass"}}),
        true,
    )
    .await;
    assert!(!bypass.0.is_success());
    assert_eq!(provider.calls(), 0);
    let zero = send(
        app.clone(),
        "/v1/actions/check-procedure",
        "zero",
        input("zero", false),
        true,
    )
    .await;
    assert_eq!(zero.0, StatusCode::OK, "{}", zero.1);
    assert_eq!(provider.calls(), 0);
    provider.pause();
    let invoke = send(app.clone(), ACTION, "one", input("one", false), true);
    let inspect = async {
        provider.wait_for_calls(1).await;
        assert_eq!(
            pool.status().available,
            pool.status().size,
            "remote work returns the pooled connection"
        );
        tokio::time::timeout(Duration::from_millis(500), pool.startup_probe())
            .await
            .unwrap()
            .unwrap();
        let row = database.admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND xact_start IS NOT NULL", &[&database.runtime_role.as_str()]).await.unwrap();
        assert_eq!(
            row.get::<_, i64>(0),
            0,
            "no runtime transaction during remote wait"
        );
        let locks = database.admin.query_one("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND a.usename=$1 AND l.locktype IN ('advisory', 'tuple', 'transactionid')", &[&database.runtime_role.as_str()]).await.unwrap();
        assert_eq!(locks.get::<_, i64>(0), 0);
        provider.resume();
    };
    let (one, ()) = tokio::join!(invoke, inspect);
    assert_eq!(one.0, StatusCode::OK, "{}", one.1);
    assert_eq!(provider.calls(), 1);
    assert_eq!(
        send(app.clone(), ACTION, "one", input("one", false), true).await,
        one
    );
    assert_eq!(provider.calls(), 1, "receipt replay makes no remote calls");
    let two = send(app.clone(), ACTION, "two", input("two", true), true).await;
    assert_eq!(two.0, StatusCode::OK, "{}", two.1);
    assert_eq!(provider.calls(), 3);
    assert_eq!(counts(&database, &registry).await, vec![2, 1, 3, 3, 3, 3]);
    let entity = &registry.entities()["landholding"];
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT {}, {} FROM registry_data.{} WHERE {}='two'",
                q(&entity.fields["farmer-number"].physical_name),
                q(&entity.fields["farmer-category"].physical_name),
                q(&entity.physical_table),
                q(&entity.fields["parcel-code"].physical_name)
            ),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "FR-12345");
    assert_eq!(row.get::<_, String>(1), "smallholder");
    for request in provider.requests() {
        assert_eq!(
            request["subjects"][0]["selector"]["values"]["farmer-number"],
            "FR-12345"
        );
    }
    let retained = database
        .admin
        .query(
            "SELECT retained FROM registry_internal.registry_action_evidence_uses ORDER BY ordinal",
            &[],
        )
        .await
        .unwrap();
    for row in retained {
        let retained: Value = row.get(0);
        assert!(retained["signedResponse"]
            .as_str()
            .unwrap()
            .contains("signature"));
        assert!(retained["verification"].is_object());
        let verification: registry_evidence_client::RetainedEvidenceVerification =
            serde_json::from_value(retained["verification"].clone()).unwrap();
        verification
            .verify(retained["signedResponse"].as_str().unwrap().as_bytes())
            .unwrap();
        assert!(!retained.to_string().contains("synthetic-test-token"));
        assert!(!retained.to_string().contains("FR-12345"));
        assert_eq!(
            retained["subjectResolution"],
            "trusted-provider-exact-selector"
        );
    }
    let runtime = pool.get_for_test().await.unwrap();
    assert!(
        runtime
            .query(
                "SELECT retained FROM registry_internal.registry_action_evidence_uses",
                &[]
            )
            .await
            .is_err(),
        "runtime cannot read the protected assertion archive"
    );
    assert!(
        runtime
            .execute(
                "DELETE FROM registry_internal.registry_action_evidence_uses",
                &[]
            )
            .await
            .is_err(),
        "runtime cannot erase the protected assertion archive"
    );
    drop(runtime);
    let committed = counts(&database, &registry).await;
    let (fault_app, _) = self::app(
        &database,
        registry.clone(),
        identity,
        &provider,
        Some(MutationFaultPoint::BeforeTerminalAudit),
    );
    let failed = send(
        fault_app,
        ACTION,
        "audit-failure",
        input("audit-failure", true),
        true,
    )
    .await;
    assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE, "{}", failed.1);
    assert_eq!(counts(&database, &registry).await, committed);
    provider.mode("inactive");
    let calls = provider.calls();
    let inactive = send(
        app.clone(),
        ACTION,
        "inactive",
        input("inactive", true),
        true,
    )
    .await;
    assert_eq!(
        inactive.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        inactive.1
    );
    assert_eq!(
        provider.calls(),
        calls + 1,
        "inactive status skips optional category"
    );
    assert_eq!(counts(&database, &registry).await, committed);
    for mode in ["nonce", "expired"] {
        provider.mode(mode);
        let failed = send(app.clone(), ACTION, mode, input(mode, true), true).await;
        assert!(!failed.0.is_success(), "{}", failed.1);
        assert_eq!(counts(&database, &registry).await, committed);
    }
    provider.mode("");
    provider.pause();
    let calls = provider.calls();
    let first = send(
        app.clone(),
        ACTION,
        "concurrent",
        input("concurrent", false),
        true,
    );
    let second = send(
        app.clone(),
        ACTION,
        "concurrent",
        input("concurrent", false),
        true,
    );
    let release = async {
        provider.wait_for_calls(calls + 2).await;
        provider.resume();
    };
    let (first, second, ()) = tokio::join!(first, second, release);
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(
        first, second,
        "competing finalizations return the same committed receipt"
    );
    assert_eq!(counts(&database, &registry).await, vec![3, 1, 4, 4, 4, 4]);
    // Sequence state survives rollback and proves a real serialization retry
    // uses the same create identity, handler outcome and verified transcript.
    database.admin.batch_execute(&format!(
        "CREATE SEQUENCE registry_internal.evidence_retry_attempt;
         CREATE SEQUENCE registry_internal.evidence_retry_identity MINVALUE 0;
         GRANT USAGE, SELECT, UPDATE ON SEQUENCE registry_internal.evidence_retry_attempt, registry_internal.evidence_retry_identity TO {};
         CREATE FUNCTION registry_internal.evidence_retry_probe() RETURNS trigger LANGUAGE plpgsql AS $body$
         DECLARE attempt bigint; identity_digest bigint; BEGIN
           attempt := nextval('registry_internal.evidence_retry_attempt');
           identity_digest := ('x' || substr(md5(NEW.record_id::text), 1, 15))::bit(60)::bigint;
           IF attempt = 1 THEN
             PERFORM setval('registry_internal.evidence_retry_identity', identity_digest, true);
             RAISE EXCEPTION 'synthetic confirmed abort' USING ERRCODE = '40001';
           END IF;
           IF identity_digest <> (SELECT last_value FROM registry_internal.evidence_retry_identity) THEN RAISE EXCEPTION 'reserved identity changed'; END IF;
           RETURN NEW; END $body$;
         CREATE TRIGGER evidence_retry_probe BEFORE INSERT ON registry_data.{} FOR EACH ROW EXECUTE FUNCTION registry_internal.evidence_retry_probe()",
        q(database.runtime_role.as_str()), q(&entity.physical_table))).await.unwrap();
    let calls = provider.calls();
    let retried = send(
        app.clone(),
        ACTION,
        "sql-retry",
        input("sql-retry", true),
        true,
    )
    .await;
    assert_eq!(retried.0, StatusCode::OK, "{}", retried.1);
    assert_eq!(
        provider.calls(),
        calls + 2,
        "SQL retry cannot rerun acquisition"
    );
    let attempts: i64 = database
        .admin
        .query_one(
            "SELECT last_value FROM registry_internal.evidence_retry_attempt",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(attempts, 2);
    assert_eq!(counts(&database, &registry).await, vec![4, 1, 5, 5, 5, 6]);
    database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER evidence_retry_probe ON registry_data.{}",
            q(&entity.physical_table)
        ))
        .await
        .unwrap();
    let committed = counts(&database, &registry).await;
    database
        .admin
        .batch_execute(&format!(
            "REVOKE INSERT ON registry_internal.registry_action_evidence_uses FROM {}",
            q(database.runtime_role.as_str())
        ))
        .await
        .unwrap();
    let calls = provider.calls();
    let failed = send(
        app,
        ACTION,
        "retention-failure",
        input("retention-failure", true),
        true,
    )
    .await;
    assert!(!failed.0.is_success(), "{}", failed.1);
    assert_eq!(
        provider.calls(),
        calls + 2,
        "retention failure occurs after verified acquisition"
    );
    assert_eq!(
        counts(&database, &registry).await,
        committed,
        "retention failure rolls back all operation material"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn caught_failed_helper_cannot_commit_or_make_another_disclosure() {
    let source = r#"fn handle(ctx) {
        let subjects = #{farmer: #{"farmer-number": "FR-12345"}};
        try { evidence::resolve("farmer-status", subjects); } catch (error) {}
        try { evidence::resolve("farmer-category", subjects); } catch (error) {}
        #{effects: [#{id: "landholding", set: #{
            "farmer-number": "FR-12345", "parcel-code": ctx.inputs["parcel-code"]
        }}]}
    }"#;
    let provider = EvidenceProvider::start().await;
    provider.mode("nonce");
    let (database, registry, identity) = setup(Some(source)).await;
    let (app, _) = app(&database, registry.clone(), identity, &provider, None);
    let failed = send(app, ACTION, "caught", input("caught", true), true).await;
    assert!(!failed.0.is_success(), "{}", failed.1);
    assert_eq!(
        provider.calls(),
        1,
        "host poison blocks the caught second helper"
    );
    assert_eq!(counts(&database, &registry).await, vec![0, 0, 0, 0, 0, 0]);
    assert!(!failed.1.to_string().contains("FR-12345"));
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_receipt_overrides_failed_acquisition_and_recovers_ambiguous_commit() {
    let successful = EvidenceProvider::start().await;
    let failed = EvidenceProvider::start().await;
    failed.mode("nonce");
    failed.pause();
    let (database, registry, identity) = setup(None).await;
    let (good_app, _) = app(
        &database,
        registry.clone(),
        identity.clone(),
        &successful,
        None,
    );
    let (bad_app, _) = app(&database, registry.clone(), identity.clone(), &failed, None);
    let loser = send(
        bad_app,
        ACTION,
        "competing",
        input("competing", false),
        true,
    );
    let winner = async {
        failed.wait_for_calls(1).await;
        let result = send(
            good_app.clone(),
            ACTION,
            "competing",
            input("competing", false),
            true,
        )
        .await;
        assert_eq!(result.0, StatusCode::OK, "{}", result.1);
        failed.resume();
        result
    };
    let (loser, winner) = tokio::join!(loser, winner);
    assert_eq!(
        loser, winner,
        "authoritative receipt takes precedence over this attempt's poisoned result"
    );
    assert_eq!(counts(&database, &registry).await, vec![1, 0, 1, 1, 1, 1]);
    assert_eq!(successful.calls(), 1);
    assert_eq!(failed.calls(), 1);
    let (ambiguous_app, _) = app(
        &database,
        registry.clone(),
        identity,
        &successful,
        Some(MutationFaultPoint::AfterCommitBeforeResponseRelease),
    );
    let ambiguous = send(
        ambiguous_app,
        ACTION,
        "ambiguous",
        input("ambiguous", true),
        true,
    )
    .await;
    assert_eq!(
        ambiguous.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        ambiguous.1
    );
    let committed = counts(&database, &registry).await;
    assert_eq!(committed, vec![2, 0, 2, 2, 2, 3]);
    assert_eq!(successful.calls(), 3);
    let recovered = send(
        good_app,
        ACTION,
        "ambiguous",
        input("ambiguous", true),
        true,
    )
    .await;
    assert_eq!(recovered.0, StatusCode::OK, "{}", recovered.1);
    assert_eq!(
        successful.calls(),
        3,
        "ambiguous commit recovery uses retained receipt"
    );
    assert_eq!(counts(&database, &registry).await, committed);
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn verified_acquisition_expiring_during_sql_wait_cannot_commit() {
    let provider = EvidenceProvider::start().await;
    provider.pause();
    let (database, registry, identity) = setup_with_age(None, 2).await;
    let (app, _) = app(&database, registry.clone(), identity, &provider, None);
    let invocation = send(
        app.clone(),
        ACTION,
        "expires-in-sql",
        input("expiry", false),
        true,
    );
    let interfere = async {
        provider.wait_for_calls(1).await;
        let (migration, task) = database.connect_migration().await;
        migration
            .batch_execute(&format!(
                "BEGIN; LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
                q(&registry.entities()["landholding"].physical_table)
            ))
            .await
            .unwrap();
        provider.resume();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let row = database.admin.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock'", &[&database.runtime_role.as_str()]).await.unwrap();
                if row.get::<_, i64>(0) > 0 { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("finalization reaches a real PostgreSQL lock wait");
        tokio::time::sleep(Duration::from_millis(2200)).await;
        migration.batch_execute("COMMIT").await.unwrap();
        drop(migration);
        task.abort();
    };
    let (expired, ()) = tokio::join!(invocation, interfere);
    assert_eq!(expired.0, StatusCode::SERVICE_UNAVAILABLE, "{}", expired.1);
    assert_eq!(expired.1["code"], "action.evidence_failed");
    assert_eq!(expired.1["fieldPath"], "/evidence/farmer-status");
    assert_eq!(provider.calls(), 1);
    assert_eq!(counts(&database, &registry).await, vec![0, 0, 0, 0, 0, 0]);
    let fresh = send(app, ACTION, "expires-in-sql", input("expiry", false), true).await;
    assert_eq!(fresh.0, StatusCode::OK, "{}", fresh.1);
    assert_eq!(
        provider.calls(),
        2,
        "only a later caller attempt obtains fresh evidence"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn real_evidence_service_resolves_exact_selector_and_commits_verified_postgres_result() {
    let input = |parcel: &str, category: bool| {
        let mut body = input(parcel, category);
        body["input"]["farmerPrefix"] = json!(" TH ");
        body["input"]["farmerNumber"] = json!(" 00042 ");
        body
    };
    let provider = real_action_evidence_provider::RealEvidenceProvider::start().await;
    let contracts = provider.contracts();
    let (database, registry, identity) = setup_with_contracts(None, 60, Some(&contracts)).await;
    let (app, _) = app_with_client(
        &database,
        registry.clone(),
        identity.clone(),
        provider.client(),
        None,
    );
    let (unauthorized, _) = app_with_client(
        &database,
        registry.clone(),
        identity,
        provider.unauthorized_client(),
        None,
    );
    let denied = send(
        unauthorized,
        ACTION,
        "real-provider-denied",
        input("denied", true),
        true,
    )
    .await;
    assert!(!denied.0.is_success(), "{}", denied.1);
    assert!(
        provider.requests().is_empty(),
        "Evidence denies requester authority before source access"
    );
    assert_eq!(counts(&database, &registry).await, vec![0, 0, 0, 0, 0, 0]);
    let zero = send(
        app.clone(),
        "/v1/actions/check-procedure",
        "real-zero",
        input("real-zero", false),
        true,
    )
    .await;
    assert_eq!(zero.0, StatusCode::OK, "{}", zero.1);
    assert!(provider.requests().is_empty());
    let one = send(
        app.clone(),
        ACTION,
        "real-one",
        input("real-one", false),
        true,
    )
    .await;
    assert_eq!(one.0, StatusCode::OK, "{}", one.1);
    assert_eq!(provider.requests().len(), 1);
    let two = send(
        app.clone(),
        ACTION,
        "real-two",
        input("real-two", true),
        true,
    )
    .await;
    assert_eq!(two.0, StatusCode::OK, "{}", two.1);
    assert_eq!(provider.requests().len(), 3);
    assert_eq!(
        send(
            app.clone(),
            ACTION,
            "real-two",
            input("real-two", true),
            true
        )
        .await,
        two
    );
    assert_eq!(provider.requests().len(), 3);
    assert_eq!(counts(&database, &registry).await, vec![2, 1, 3, 3, 3, 3]);
    let entity = &registry.entities()["landholding"];
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT {} FROM registry_data.{}",
                q(&entity.fields["farmer-number"].physical_name),
                q(&entity.physical_table)
            ),
            &[],
        )
        .await
        .unwrap();
    for row in rows {
        assert_eq!(row.get::<_, String>(0), "TH-00042");
    }
    for request in provider.requests() {
        assert_eq!(request["reference"], "TH-00042");
    }
    let rows = database
        .admin
        .query(
            "SELECT retained FROM registry_internal.registry_action_evidence_uses",
            &[],
        )
        .await
        .unwrap();
    for row in rows {
        let retained: Value = row.get(0);
        let verification: registry_evidence_client::RetainedEvidenceVerification =
            serde_json::from_value(retained["verification"].clone()).unwrap();
        verification
            .verify(retained["signedResponse"].as_str().unwrap().as_bytes())
            .unwrap();
    }
    let committed = counts(&database, &registry).await;
    for mode in ["mismatch", "ambiguous", "missing"] {
        provider.control(&json!({"mode":mode,"active":true,"category":"smallholder"}));
        let failed = send(app.clone(), ACTION, mode, input(mode, true), true).await;
        assert!(!failed.0.is_success(), "{}", failed.1);
        assert_eq!(counts(&database, &registry).await, committed);
    }
    provider.control(&json!({"mode":"match","active":false,"category":"smallholder"}));
    let calls = provider.requests().len();
    let inactive = send(
        app.clone(),
        ACTION,
        "real-inactive",
        input("real-inactive", true),
        true,
    )
    .await;
    assert_eq!(
        inactive.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        inactive.1
    );
    assert_eq!(provider.requests().len(), calls + 1);
    assert_eq!(counts(&database, &registry).await, committed);
    database.cleanup().await;
}
