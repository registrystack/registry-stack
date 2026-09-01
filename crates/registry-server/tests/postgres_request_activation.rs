// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "runtime", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, MigrationError,
};
use registry_server::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageSourceFile, SignaturePolicy, VerifiedPackage,
};
use registry_server::postgres::{
    managed_schema_fingerprint, reconcile_compiled_runtime_acl_for_test, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, PostgresRecordMutationService, PostgresRecordReadService,
    PostgresRevisionReadService, RegistryLockKey,
};
use registry_server::request_retention::{
    RequestDetailErasureScope, RequestRetentionOperatorService,
};
use registry_server::startup::prepare_startup;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "change-request-activation-registry";
const INSTANCE_ID: &str = "change-request-activation-instance";
const DATABASE_ID: &str = "change-request-activation-database";
const SOURCE_REVISION: &str = "change-request-activation-source";
const TENANT: &str = "tenant-a";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: activation-request-list
    steps:
      - id: list-correction-requests
        entity: correction-request
        accessProfile: submitter
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_package_activation_preserves_pending_request_application() {
    load_postgres_env();
    let database = TestDatabase::create(8).await;
    let base = Arc::new(compiled_registry(Variant::Base, 1));
    let initial = prepare_initial_package(&database, &base).await;
    let active = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial package activates");
    assert_eq!(active.package_sequence, 1);

    let app = change_request_router(&database, base.clone(), active.clone());
    let steward = claims("steward", "unrelated-steward", None);
    let submitter = claims("submitter", "unrelated-submitter", None);
    let reviewer = claims("reviewer", "unrelated-reviewer", Some("review"));
    let applier = claims("applier", "unrelated-applier", Some("apply"));
    let approved = create_approved_correction(
        &app,
        steward.clone(),
        submitter.clone(),
        reviewer,
        "unrelated",
    )
    .await;

    let unrelated = Arc::new(compiled_registry(Variant::UnrelatedOptionalField, 2));
    assert_eq!(
        request_contract_fingerprint(&base),
        request_contract_fingerprint(&unrelated),
        "the unrelated successor must not reinterpret the frozen request proposal"
    );
    let successor = prepare_successor_package(&database, &base, &active, &unrelated).await;
    let successor_active = apply_package(
        &database,
        &successor.package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("unrelated additive successor activates with an approved request present");
    assert_eq!(successor_active.package_sequence, 2);

    let successor_app =
        change_request_router(&database, unrelated.clone(), successor_active.clone());
    let before_apply = get_record(
        &successor_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            approved.request_id
        ),
        applier.clone(),
    )
    .await;
    assert_eq!(before_apply.body["request"]["serverState"], "approved");
    let apply = action(&before_apply.body, "apply_request", None);
    assert_eq!(apply.proposal_version, Some(1));
    assert_eq!(
        apply.effect_digest.as_deref(),
        Some(approved.effect_digest.as_str())
    );

    let applied = send_action(
        &successor_app,
        &apply,
        "unrelated-apply-after-activation",
        applier.clone(),
        json!({
            "proposalVersion": apply.proposal_version,
            "effectDigest": apply.effect_digest
        }),
    )
    .await;
    assert_eq!(
        applied.status,
        StatusCode::OK,
        "unchanged request contract must remain applicable after unrelated activation, body {}",
        applied.body
    );
    assert_eq!(applied.body["request"]["serverState"], "applied");

    let changed_placement = get_record(
        &successor_app,
        &format!(
            "/v1/records/placements/{}?accessProfile=steward",
            approved.placement_id
        ),
        steward,
    )
    .await;
    assert_eq!(changed_placement.body["revision"], 2);
    assert_eq!(changed_placement.body["data"]["site"], approved.new_site_id);
    assert_eq!(
        active_package_revision(&database).await,
        successor_active.package_revision
    );

    let retention = RequestRetentionOperatorService::new_for_test(
        unrelated.as_ref().clone(),
        successor_active.clone(),
        ExpectedManagedCatalog::compiled(&unrelated),
        RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        AuditProfile::production_from_secret_bytes(vec![0x8d; 32].into())
            .expect("test audit profile is keyed"),
    );
    let erasure_scope = RequestDetailErasureScope {
        request_entity_id: "correction-request",
        request_id: Uuid::parse_str(&approved.request_id).expect("request id parses"),
        proposal_version: 1,
    };
    let dry_run = retention
        .dry_run(erasure_scope.clone())
        .await
        .expect("applied request is eligible for operator erasure");
    assert_eq!(dry_run.request_state, "applied");
    assert_eq!(dry_run.retention_mode, "operator_erase");
    assert!(dry_run.eligible_for_erasure);
    assert!(!dry_run.detail_erased);
    let erased = retention
        .erase(erasure_scope)
        .await
        .expect("applied request detail erases through the verified operator boundary");
    assert_eq!(erased.request_state, "applied");
    assert_eq!(erased.retention_mode, "operator_erase");

    let erased_request = get_record(
        &successor_app,
        &format!(
            "/v1/records/correction-requests/{}?accessProfile=applier",
            approved.request_id
        ),
        applier,
    )
    .await;
    assert_eq!(erased_request.body["request"]["serverState"], "applied");
    assert_eq!(erased_request.body["request"]["proposalVersion"], 1);
    assert_eq!(erased_request.body["request"]["detailErased"], true);
    assert_eq!(erased_request.body["data"], json!({}));
    assert_eq!(
        erased_request.body["request"]["effectDigest"],
        approved.effect_digest
    );
    assert_eq!(
        erased_request.body["request"]["application"]["proposalVersion"],
        1
    );
    assert!(
        erased_request.body["request"]["application"]["applicationId"]
            .as_str()
            .is_some(),
        "operator erasure preserves terminal application provenance"
    );
    let retained = &erased_request.body["request"]["history"]["proposals"][0];
    assert_eq!(retained["serverState"], "applied");
    assert_eq!(retained["proposalVersion"], 1);
    assert_eq!(retained["current"], true);
    assert_eq!(retained["detailErased"], true);
    assert_eq!(retained["effectDigest"], approved.effect_digest);
    assert_eq!(
        retained["contractFingerprint"],
        request_contract_fingerprint(&unrelated)
    );
    assert_eq!(
        retained["applicationId"],
        erased_request.body["request"]["application"]["applicationId"]
    );

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let startup_context = package_context(PackageIntent::Startup {
        active_revision: &successor_active.package_revision,
        active_sequence: 2,
    });
    prepare_startup(
        &successor.package_root,
        &startup_context,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect(
        "unrelated successor catalog identity remains startup-ready after applying the proposal",
    );
    drop(runtime);
    drop(successor);
    drop(initial);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relevant_package_activation_waits_for_explicit_cancellation_then_starts() {
    load_postgres_env();
    let database = TestDatabase::create(8).await;
    let base = Arc::new(compiled_registry(Variant::Base, 1));
    let initial = prepare_initial_package(&database, &base).await;
    let active = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("initial package activates");

    let app = change_request_router(&database, base.clone(), active.clone());
    let steward = claims("steward", "relevant-steward", None);
    let submitter = claims("submitter", "relevant-submitter", None);
    let reviewer = claims("reviewer", "relevant-reviewer", Some("review"));
    let approved =
        create_approved_correction(&app, steward, submitter.clone(), reviewer, "relevant").await;

    let relevant = Arc::new(compiled_registry(Variant::RelevantOptionalRequestSchema, 2));
    assert_ne!(
        request_contract_fingerprint(&base),
        request_contract_fingerprint(&relevant),
        "the relevant successor changes the request mapping/schema fingerprint"
    );
    let successor = prepare_successor_package(&database, &base, &active, &relevant).await;
    let before_refusal = active_package_revision(&database).await;
    let refused = apply_package(
        &database,
        &successor.package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_eq!(
        refused.err(),
        Some(MigrationError::ActiveRequestProposals),
        "approved proposals must block activation of a package that changes the relevant request contract"
    );
    assert_eq!(
        active_package_revision(&database).await,
        before_refusal,
        "the retention guard must run before installed package identity changes"
    );
    assert!(
        !column_exists(
            &database,
            &relevant.entities()["correction-request"].physical_table,
            &relevant.entities()["correction-request"].fields["note"].physical_name,
        )
        .await,
        "the refused activation must not install candidate request-schema data columns"
    );
    assert_eq!(
        application_result_count(&database).await,
        0,
        "the refused activation must not apply pending proposals"
    );

    let canceled = run_action(
        &app,
        &approved.request_id,
        "correction-requests",
        "submitter",
        submitter,
        "relevant-cancel-approved-request",
        "cancel_request",
        None,
        |_| json!({}),
    )
    .await;
    assert_eq!(canceled["request"]["serverState"], "canceled");

    let successor_active = apply_package(
        &database,
        &successor.package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("explicit cancellation permits the exact relevant successor activation");
    assert_eq!(
        active_package_revision(&database).await,
        successor_active.package_revision
    );
    assert!(
        column_exists(
            &database,
            &relevant.entities()["correction-request"].physical_table,
            &relevant.entities()["correction-request"].fields["note"].physical_name,
        )
        .await,
        "the candidate request-schema column appears only after permitted activation"
    );

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let startup_context = package_context(PackageIntent::Startup {
        active_revision: &successor_active.package_revision,
        active_sequence: 2,
    });
    let startup = prepare_startup(
        &successor.package_root,
        &startup_context,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("successor activation preserves catalog identity and startup readiness");
    assert_eq!(
        startup.expected_identity().package_revision,
        successor_active.package_revision
    );
    drop(runtime);
    drop(successor);
    drop(initial);
    database.cleanup().await;
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    UnrelatedOptionalField,
    RelevantOptionalRequestSchema,
}

struct PublishedPackage {
    _root: TempDir,
    package_root: std::path::PathBuf,
    package: VerifiedPackage,
}

struct ApprovedCorrection {
    request_id: String,
    placement_id: String,
    new_site_id: String,
    effect_digest: String,
}

#[derive(Debug)]
struct RequestAction {
    href: String,
    if_match: String,
    proposal_version: Option<u64>,
    effect_digest: Option<String>,
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
}

async fn create_approved_correction(
    app: &axum::Router,
    steward: VerifiedRequestClaims,
    submitter: VerifiedRequestClaims,
    reviewer: VerifiedRequestClaims,
    key_prefix: &str,
) -> ApprovedCorrection {
    let old_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        &format!("{key_prefix}-old-site"),
        json!({"tenant": TENANT, "name": format!("{key_prefix}-old")}),
    )
    .await;
    let new_site = create_record(
        app,
        "/v1/records/sites?accessProfile=steward",
        steward.clone(),
        &format!("{key_prefix}-new-site"),
        json!({"tenant": TENANT, "name": format!("{key_prefix}-new")}),
    )
    .await;
    let placement = create_record(
        app,
        "/v1/records/placements?accessProfile=steward",
        steward,
        &format!("{key_prefix}-placement"),
        json!({"tenant": TENANT, "site": old_site.id}),
    )
    .await;
    let request = create_record(
        app,
        "/v1/records/correction-requests?accessProfile=submitter",
        submitter.clone(),
        &format!("{key_prefix}-request"),
        json!({
            "tenant": TENANT,
            "placement": placement.id,
            "proposedSite": new_site.id,
            "reason": format!("{key_prefix} activation proof")
        }),
    )
    .await;
    let submitted = run_action(
        app,
        &request.id,
        "correction-requests",
        "submitter",
        submitter,
        &format!("{key_prefix}-submit"),
        "submit_request",
        None,
        |_| json!({}),
    )
    .await;
    let effect_digest = submitted["request"]["effectDigest"]
        .as_str()
        .expect("submission freezes an effect digest")
        .to_owned();
    run_action(
        app,
        &request.id,
        "correction-requests",
        "reviewer",
        reviewer,
        &format!("{key_prefix}-approve"),
        "approve_request",
        Some("review"),
        |_| json!({"proposalVersion": 1, "effectDigest": effect_digest}),
    )
    .await;
    ApprovedCorrection {
        request_id: request.id,
        placement_id: placement.id,
        new_site_id: new_site.id,
        effect_digest,
    }
}

async fn prepare_initial_package(
    database: &TestDatabase,
    registry: &Arc<registry_server::CompiledRegistry>,
) -> PublishedPackage {
    let fingerprint = initial_schema_fingerprint(database, registry).await;
    publish_and_load(
        build_request(
            registry,
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(PackageIntent::InitialActivation),
    )
}

async fn prepare_successor_package(
    database: &TestDatabase,
    prior: &Arc<registry_server::CompiledRegistry>,
    active: &ExpectedRegistryIdentity,
    candidate: &Arc<registry_server::CompiledRegistry>,
) -> PublishedPackage {
    let provisional = publish_and_load(
        build_request(
            candidate,
            active.package_sequence as u64 + 1,
            Some(active.package_revision.as_str()),
            &active.schema_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new((**prior).clone()),
            },
        ),
        package_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: active.package_sequence as u64,
        }),
    );
    let target_fingerprint = successor_schema_fingerprint(database, &provisional.package).await;
    drop(provisional);
    publish_and_load(
        build_request(
            candidate,
            active.package_sequence as u64 + 1,
            Some(active.package_revision.as_str()),
            &target_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new((**prior).clone()),
            },
        ),
        package_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: active.package_sequence as u64,
        }),
    )
}

fn publish_and_load(
    request: PackageBuildRequest,
    context: PackageLoadContext<'_>,
) -> PublishedPackage {
    let prepared = prepare_package(request).expect("package prepares");
    let root = tempfile::Builder::new()
        .prefix("registry-request-activation-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package tempdir creates");
    let package_root = root.path().join("package");
    prepared
        .publish_to_directory(&package_root, Vec::new())
        .expect("package publishes");
    let package = load_package(&package_root, &context).expect("published package loads");
    PublishedPackage {
        _root: root,
        package_root,
        package,
    }
}

fn build_request(
    registry: &registry_server::CompiledRegistry,
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.json".to_owned(),
            bytes: project_bytes(sequence, registry),
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

async fn initial_schema_fingerprint(
    database: &TestDatabase,
    registry: &registry_server::CompiledRegistry,
) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    registry_server::postgres::install_compiled_schema(
        &transaction,
        registry,
        &database.runtime_role,
    )
    .await
    .expect("initial schema rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("initial fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("initial fingerprint transaction rolls back");
    task.abort();
    fingerprint
}

async fn successor_schema_fingerprint(
    database: &TestDatabase,
    package: &VerifiedPackage,
) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("successor fingerprint transaction starts");
    for statement in &package.manifest().migration_plan.statements {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("successor additive DDL rehearses");
    }
    reconcile_compiled_runtime_acl_for_test(
        &transaction,
        package.registry(),
        &database.runtime_role,
    )
    .await
    .expect("successor fingerprint reconciles the production runtime ACL");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(package.registry()),
    )
    .await
    .expect("successor fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("successor fingerprint transaction rolls back");
    task.abort();
    fingerprint
}

async fn apply_package(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    ))
    .await
}

fn package_context(intent: PackageIntent<'_>) -> PackageLoadContext<'_> {
    PackageLoadContext {
        environment: "local",
        instance_id: INSTANCE_ID,
        database_id: DATABASE_ID,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

fn change_request_router(
    database: &TestDatabase,
    registry: Arc<registry_server::CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = AuditProfile::production_from_secret_bytes(vec![0x8d; 32].into())
        .expect("test audit profile is keyed");
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let revisions = Arc::new(PostgresRevisionReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
    ));
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.package_revision,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_revisions(revisions)
        .with_postgres_mutations(mutations),
    ))
}

async fn create_record(
    app: &axum::Router,
    uri: &str,
    claims: VerifiedRequestClaims,
    key: &str,
    data: Value,
) -> CreatedRecord {
    let response = response_parts(
        send(
            app,
            Method::POST,
            uri,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({ "data": data })).expect("create body serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "create {uri} failed with body {}",
        response.body
    );
    CreatedRecord {
        id: response.body["id"]
            .as_str()
            .expect("created response includes id")
            .to_owned(),
    }
}

struct CreatedRecord {
    id: String,
}

async fn get_record(app: &axum::Router, uri: &str, claims: VerifiedRequestClaims) -> ResponseParts {
    let response =
        response_parts(send(app, Method::GET, uri, Some(claims), &[], Vec::new()).await).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "GET {uri} failed with body {}",
        response.body
    );
    response
}

#[allow(clippy::too_many_arguments)] // The route, actor, state, and expected transition are independent test inputs.
async fn run_action(
    app: &axum::Router,
    record_id: &str,
    route: &str,
    profile: &str,
    claims: VerifiedRequestClaims,
    key: &str,
    operation: &str,
    stage: Option<&str>,
    body: impl FnOnce(&RequestAction) -> Value,
) -> Value {
    let before = get_record(
        app,
        &format!("/v1/records/{route}/{record_id}?accessProfile={profile}"),
        claims.clone(),
    )
    .await;
    let action = action(&before.body, operation, stage);
    let response = send_action(app, &action, key, claims, body(&action)).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "action {operation} failed with body {}",
        response.body
    );
    response.body
}

async fn send_action(
    app: &axum::Router,
    action: &RequestAction,
    key: &str,
    claims: VerifiedRequestClaims,
    body: Value,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            &action.href,
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
                ("if-match", &action.if_match),
            ],
            serde_json::to_vec(&body).expect("action body serializes"),
        )
        .await,
    )
    .await
}

fn action(body: &Value, operation: &str, stage: Option<&str>) -> RequestAction {
    let actions = body["request"]["actions"]
        .as_array()
        .expect("request read exposes action links");
    let action = actions
        .iter()
        .find(|action| {
            action["operation"] == operation
                && stage.map_or(action.get("stage").is_none(), |stage| {
                    action["stage"] == stage
                })
        })
        .unwrap_or_else(|| panic!("missing {operation} action in {actions:?}"));
    RequestAction {
        href: action["href"].as_str().expect("action has href").to_owned(),
        if_match: action["ifMatch"]
            .as_str()
            .expect("action has precondition")
            .to_owned(),
        proposal_version: action["proposalVersion"].as_u64(),
        effect_digest: action["effectDigest"].as_str().map(str::to_owned),
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns response")
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    ResponseParts {
        status,
        body: serde_json::from_slice(&bytes).expect("response body is JSON"),
    }
}

fn claims(profile: &str, principal: &str, purpose: Option<&str>) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        principal,
        BTreeSet::new(),
        purpose.map(str::to_owned),
        BTreeMap::from([(
            "tenant_claim".to_owned(),
            VerifiedClaimValue::direct_string(TENANT).expect("tenant claim is a direct string"),
        )]),
    )
    .unwrap_or_else(|_| panic!("{profile} claims are verified"))
}

async fn active_package_revision(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT active_package_revision FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("registry state reads")
        .get(0)
}

async fn application_result_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_request_results",
            &[],
        )
        .await
        .expect("application results read")
        .get(0)
}

async fn column_exists(database: &TestDatabase, table: &str, column: &str) -> bool {
    database
        .admin
        .query_one(
            "SELECT count(*) > 0
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND column_name = $2",
            &[&table, &column],
        )
        .await
        .expect("column inventory reads")
        .get(0)
}

fn request_contract_fingerprint(registry: &registry_server::CompiledRegistry) -> String {
    registry.entities()["correction-request"]
        .change_request
        .as_ref()
        .expect("correction request has a compiled plan")
        .contract_fingerprint
        .clone()
}

fn compiled_registry(variant: Variant, sequence: u64) -> registry_server::CompiledRegistry {
    let project = parse_project_json(&project_bytes_for_variant(variant, sequence))
        .expect("activation fixture parses");
    compile_project(&project, &[], CompileProfile::Production).expect("activation fixture compiles")
}

fn project_bytes(sequence: u64, registry: &registry_server::CompiledRegistry) -> Vec<u8> {
    let variant = if registry.entities()["correction-request"]
        .fields
        .contains_key("note")
    {
        Variant::RelevantOptionalRequestSchema
    } else if registry.entities()["asset-site"]
        .fields
        .contains_key("display-code")
    {
        Variant::UnrelatedOptionalField
    } else {
        Variant::Base
    };
    project_bytes_for_variant(variant, sequence)
}

fn project_bytes_for_variant(variant: Variant, sequence: u64) -> Vec<u8> {
    let site_extra_field = if matches!(variant, Variant::UnrelatedOptionalField) {
        r#",{"id":"display-code","type":"string","maxLength":32,"classification":"internal"}"#
    } else {
        ""
    };
    let request_extra_field = if matches!(variant, Variant::RelevantOptionalRequestSchema) {
        r#",{"id":"note","type":"text","maxLength":1000,"classification":"internal"}"#
    } else {
        ""
    };
    let request_extra_read_write = "";
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"{PACKAGE_ID}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "package":{{"environment":"local","instanceId":"{INSTANCE_ID}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},
          "entities":[
            {{
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"create_only","classification":"internal",
              "fields":[
                {{"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}},
                {{"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}}{site_extra_field}
              ]
            }},
            {{
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable","classification":"internal",
              "changeControl":{{"requiredFor":["patch"]}},
              "fields":[
                {{"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}},
                {{"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}}
              ]
            }},
            {{
              "id":"correction-request","primaryDataset":"test-dataset","route":"correction-requests","mutationMode":"mutable","classification":"internal",
              "fields":[
                {{"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}},
                {{"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"}},
                {{"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"}},
                {{"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}}{request_extra_field}
              ],
              "changeRequest":{{
                "retention":{{"mode":"operator_erase"}},
                "effects":[{{"target":{{"fromField":"placement"}},"operation":"patch","set":{{"site":{{"fromField":"proposed-site"}}}}}}],
                "review":{{"stages":[{{"id":"review","approvals":1,"excludeSubmitter":true}}]}}
              }}
            }}
          ],
          "accessProfiles":[
            {{
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{{
                "entity":"asset-site",
                "operations":["create","get","list"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}]
              }},{{
                "entity":"asset-placement",
                "operations":["create","get","list","revisions"],
                "revisionAccess":true,
                "readableFields":["tenant","site"],
                "writableFields":["tenant","site"],
                "rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}],
                "requestPresence":[{{"requestType":"correction-request","rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}]}}]
              }}]
            }},
            {{
              "id":"submitter","default":true,"principalClaim":"registry_principal",
              "grants":[{{
                "entity":"correction-request",
                "operations":["create","get","list","revisions","patch","submit_request","revise_request","cancel_request"],
                "revisionAccess":true,
                "readableFields":["tenant","placement","proposed-site","reason"{request_extra_read_write}],
                "writableFields":["tenant","placement","proposed-site","reason"{request_extra_read_write}],
                "rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}]
              }}]
            }},
            {{
              "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{{
                "entity":"correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"{request_extra_read_write}],
                "rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}],
                "reviewStages":[{{"stage":"review","targets":[{{"entity":"asset-placement","readableFields":["site"],"rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}]}}]}}]
              }}]
            }},
            {{
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{{
                "entity":"correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"{request_extra_read_write}],
                "rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}],
                "applyTargets":[{{"entity":"asset-placement","rowBoundaries":[{{"field":"tenant","claim":"tenant_claim","operator":"equals"}}]}}]
              }}]
            }}
          ]
        }}"#
    )
    .into_bytes()
}

fn load_postgres_env() {
    if env::var_os("REGISTRY_SERVER_TEST_DATABASE_URL").is_some() {
        return;
    }
    let Ok(contents) = std::fs::read_to_string("/private/tmp/registry-cr-plain-gqgr39oa/test.env")
    else {
        return;
    };
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "REGISTRY_SERVER_TEST_DATABASE_URL" {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or(value);
        env::set_var("REGISTRY_SERVER_TEST_DATABASE_URL", value);
    }
}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
