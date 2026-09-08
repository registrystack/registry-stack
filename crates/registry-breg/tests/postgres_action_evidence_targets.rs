// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/action_evidence_provider.rs"]
#[allow(dead_code)]
mod action_evidence_provider;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

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
        VerifiedClaimValue, VerifiedRequestClaims,
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
    let database = TestDatabase::create(1).await;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/farmer-landholding-evidence");
    let mut project =
        parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    let mut document = serde_json::to_value(&project).unwrap();
    document["entities"].as_array_mut().unwrap().push(json!({
        "id":"local-register", "route":"local-registers", "primaryDataset":"farmer-landholding-evidence", "mutationMode":"mutable",
        "fields":[
            {"id":"zone", "type":"string", "maxLength":32,"required":true,"classification":"restricted"},
            {"id":"active", "type":"boolean", "required":true,"classification":"restricted"},
            {"id":"checked", "type":"boolean", "required":true,"classification":"restricted"}
        ]
    }));
    document["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({
        "id":"local-register", "apiName":"localRegister", "type":"reference", "target":"local-register", "required":true,"classification":"restricted"
    }));
    document["actions"][0]["requires"] =
        json!([{"input":"local-register","field":"active","equals":true}]);
    document["actions"][0]["handler"]["writes"].as_array_mut().unwrap().push(json!({
        "id":"local-register", "target":{"fromField":"local-register"},"operation":"patch","fields":["checked"]
    }));
    document["accessProfiles"][0]["grants"][0]["targets"].as_array_mut().unwrap().push(json!({
        "entity":"local-register", "rowBoundaries":[{"field":"zone","claim":"zone","operator":"equals"}]
    }));
    project = parse_project_yaml(&serde_json::to_vec(&document).unwrap()).unwrap();
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
    .with_evidence_evaluator(Arc::new(ActionEvidenceEvaluator::new(provider.client())));
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
        BTreeMap::from([(
            "zone".into(),
            VerifiedClaimValue::direct_string("permitted").unwrap(),
        )]),
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

const TARGET: &str = "7431a75f-8e07-4859-b946-a8479bca089d";

#[tokio::test(flavor = "current_thread")]
async fn final_local_target_checks_refuse_changes_during_external_wait_even_for_omitted_slots() {
    for loss in ["unchanged", "authority", "condition", "requirement"] {
        let provider = EvidenceProvider::start().await;
        let (database, registry, identity) = setup(None).await;
        let entity = &registry.entities()["local-register"];
        let table = q(&entity.physical_table);
        let zone = q(&entity.fields["zone"].physical_name);
        let active = q(&entity.fields["active"].physical_name);
        let checked = q(&entity.fields["checked"].physical_name);
        database.admin.execute(&format!(
            "INSERT INTO registry_data.{table} (record_id, record_revision, record_lifecycle, active_package_revision, {zone}, {active}, {checked}) VALUES ($1, 1, 'active', $2, 'permitted', true, false)"
        ), &[&uuid::Uuid::parse_str(TARGET).unwrap(), &identity.package_revision]).await.unwrap();
        let (app, _pool) = app(&database, registry.clone(), identity, &provider, None);
        let condition = send(
            app.clone(),
            &format!("{ACTION}/target-conditions"),
            "condition",
            json!({"input":{"localRegister":TARGET}}),
            true,
        )
        .await;
        assert_eq!(condition.0, StatusCode::OK, "{loss}: {}", condition.1);
        assert_eq!(
            provider.calls(),
            0,
            "local target condition acquisition does not disclose to Evidence"
        );
        let mut body = input(loss, false);
        body["input"]["localRegister"] = json!(TARGET);
        body["preconditions"] = condition.1["preconditions"].clone();
        let before = counts(&database, &registry).await;
        provider.pause();
        let invoke = send(app.clone(), ACTION, loss, body, true);
        let change = async {
            provider.wait_for_calls(1).await;
            // Controlled owner-side updates isolate each final check. The
            // authority/requirement probes preserve revision so a stale token
            // cannot accidentally stand in for the boundary being exercised.
            let assignment = match loss {
                "authority" => Some(format!("{zone}='withdrawn'")),
                "condition" => Some("record_revision=record_revision+1".to_owned()),
                "requirement" => Some(format!("{active}=false")),
                _ => None,
            };
            if let Some(assignment) = assignment {
                tokio::time::timeout(
                    Duration::from_secs(1),
                    database.admin.execute(
                        &format!(
                            "UPDATE registry_data.{table} SET {assignment} WHERE record_id=$1"
                        ),
                        &[&uuid::Uuid::parse_str(TARGET).unwrap()],
                    ),
                )
                .await
                .expect("remote wait holds no target lock")
                .unwrap();
            }
            provider.resume();
        };
        let (response, ()) = tokio::join!(invoke, change);
        assert_eq!(provider.calls(), 1, "{loss}");
        if loss == "unchanged" {
            assert_eq!(response.0, StatusCode::OK, "{}", response.1);
            assert_ne!(counts(&database, &registry).await, before);
        } else {
            assert_eq!(
                response.0,
                StatusCode::PRECONDITION_FAILED,
                "{loss}: {}",
                response.1
            );
            assert_eq!(counts(&database, &registry).await, before,
                "{loss}: final denial leaves no business write revision receipt idempotency result or retained Evidence");
        }
        let row = database
            .admin
            .query_one(
                &format!("SELECT {checked} FROM registry_data.{table} WHERE record_id=$1"),
                &[&uuid::Uuid::parse_str(TARGET).unwrap()],
            )
            .await
            .unwrap();
        assert!(
            !row.get::<_, bool>(0),
            "the script omitted the declared patch slot"
        );
        database.cleanup().await;
    }
}
