// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "runtime", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_server::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::cursor::CursorCodec;
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest,
};
use registry_server::migration_plan::{
    MigrationRehearsalReceipt, RehearsalProofs, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
};
use registry_server::package::{
    compiled_registry_change_set, load_package, prepare_package, PackageBuildRequest,
    PackageIntent, PackageLoadContext, PackageMigrationPlanInput, PackageSignature,
    PackageSourceFile, PackageTrustAnchor, SignaturePolicy, TrustAnchorKey, VerifiedPackage,
    FIXTURE_JOURNEYS_PATH, TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    managed_schema_fingerprint, ExpectedManagedCatalog, ExpectedRegistryIdentity,
    PostgresRecordMutationService, PostgresRecordReadService, RegistryLockKey, SqlIdentifier,
};
use registry_server::startup::prepare_startup;
use registry_server::CompiledRegistry;
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_postgres::GenericClient;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "immediate-action-activation-registry";
const INSTANCE_ID: &str = "immediate-action-activation-instance";
const DATABASE_ID: &str = "immediate-action-activation-database";
const ENVIRONMENT: &str = "production";
const SOURCE_REVISION: &str = "immediate-action-activation-source";
const HOUSEHOLD_ID: &str = "00000000-0000-4000-8000-000000000100";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys: []
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_activation_updates_immediate_action_policies_and_consumed_keys() {
    let database = TestDatabase::create(8).await;
    let signer = TestSigner::new();

    let initial_registry = Arc::new(compiled_registry(Variant::NoAction, 1));
    let initial = prepare_initial_package(&database, &signer, &initial_registry).await;
    let active_initial = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;
    seed_household(&database, &initial_registry, &active_initial).await;

    let action_registry = Arc::new(compiled_registry(Variant::ActionV1, 2));
    let action_package = prepare_reviewed_successor_package(
        &database,
        &signer,
        &initial_registry,
        &active_initial,
        &action_registry,
        2,
    )
    .await;
    assert!(
        action_package
            .package
            .manifest()
            .migration_plan
            .statements
            .iter()
            .any(|statement| statement.sql.starts_with("CREATE POLICY ")),
        "reviewed action-add activation must carry compiler-owned policy creates"
    );
    let active_action = apply_package(
        &database,
        &action_package.package,
        ApplyPrecondition::Successor {
            current: &active_initial,
        },
    )
    .await;
    assert_exact_catalog(&database, &action_registry, &active_action).await;

    let action_app = action_router(&database, action_registry.clone(), active_action.clone());
    let claims_v1 = action_claims("registry:contact:register");
    let condition = condition_for(&action_app, claims_v1.clone()).await;
    let first = invoke_action(
        &action_app,
        claims_v1,
        "upgrade-stable-key",
        "Alex Example",
        &condition,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(entity_count(&database, &action_registry, "person").await, 1);
    assert_eq!(
        entity_count(&database, &action_registry, "group-membership").await,
        1
    );
    assert_eq!(receipt_count(&database).await, 1);

    let changed_registry = Arc::new(compiled_registry(Variant::ActionV2, 3));
    let changed_package = prepare_reviewed_successor_package(
        &database,
        &signer,
        &action_registry,
        &active_action,
        &changed_registry,
        3,
    )
    .await;
    let changed_sql = changed_package
        .package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect::<Vec<_>>();
    assert!(changed_sql
        .iter()
        .any(|sql| sql.starts_with("DROP POLICY ")));
    assert!(changed_sql
        .iter()
        .any(|sql| sql.starts_with("CREATE POLICY ")));
    let active_changed = apply_package(
        &database,
        &changed_package.package,
        ApplyPrecondition::Successor {
            current: &active_action,
        },
    )
    .await;
    assert_exact_catalog(&database, &changed_registry, &active_changed).await;

    let stale_old_app = invoke_action(
        &action_app,
        action_claims("registry:contact:register"),
        "old-package-after-upgrade",
        "Old Runtime",
        &condition,
    )
    .await;
    assert_eq!(
        stale_old_app.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "old runtime identity must be unavailable after successor activation"
    );

    let changed_app = action_router(&database, changed_registry.clone(), active_changed.clone());
    let same_key_after_contract_change = invoke_action(
        &changed_app,
        action_claims("registry:contact:register.v2"),
        "upgrade-stable-key",
        "Changed Contract",
        &condition,
    )
    .await;
    assert_eq!(
        same_key_after_contract_change.status,
        StatusCode::CONFLICT,
        "a consumed immediate-action key must not replay across a changed action contract"
    );
    assert_eq!(
        entity_count(&database, &changed_registry, "person").await,
        1
    );
    assert_eq!(
        entity_count(&database, &changed_registry, "group-membership").await,
        1
    );
    assert_eq!(receipt_count(&database).await, 1);

    let removed_registry = Arc::new(compiled_registry(Variant::NoAction, 4));
    let removed_package = prepare_reviewed_successor_package(
        &database,
        &signer,
        &changed_registry,
        &active_changed,
        &removed_registry,
        4,
    )
    .await;
    let removed_sql = removed_package
        .package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect::<Vec<_>>();
    assert!(removed_sql
        .iter()
        .any(|sql| sql.starts_with("DROP POLICY ")));
    assert!(!removed_sql
        .iter()
        .any(|sql| sql.starts_with("CREATE POLICY ")));
    let active_removed = apply_package(
        &database,
        &removed_package.package,
        ApplyPrecondition::Successor {
            current: &active_changed,
        },
    )
    .await;
    assert_exact_catalog(&database, &removed_registry, &active_removed).await;
    prepare_startup_for(&database, &removed_package, &active_removed)
        .await
        .expect("removed-action package starts against the exact candidate catalog");

    drop(removed_package);
    drop(changed_package);
    drop(action_package);
    drop(initial);
    database.cleanup().await;
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    NoAction,
    ActionV1,
    ActionV2,
}

struct PublishedPackage {
    _root: TempDir,
    package_root: PathBuf,
    anchor_path: PathBuf,
    package: VerifiedPackage,
}

struct TestSigner {
    key: PrivateJwk,
    key_id: String,
}

impl TestSigner {
    fn new() -> Self {
        let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("package signing key generates");
        let key_id = key.public().kid.expect("generated key has a key id");
        Self { key, key_id }
    }
}

async fn prepare_initial_package(
    database: &TestDatabase,
    signer: &TestSigner,
    registry: &Arc<CompiledRegistry>,
) -> PublishedPackage {
    let fingerprint = initial_schema_fingerprint(database, registry).await;
    publish_and_load(
        signer,
        build_request(
            Variant::NoAction,
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(PackageIntent::InitialActivation),
    )
}

async fn prepare_reviewed_successor_package(
    database: &TestDatabase,
    signer: &TestSigner,
    prior: &Arc<CompiledRegistry>,
    active: &ExpectedRegistryIdentity,
    candidate: &Arc<CompiledRegistry>,
    sequence: u64,
) -> PublishedPackage {
    let variant = variant_for(candidate);
    let provisional = publish_and_load(
        signer,
        build_request(
            variant,
            sequence,
            Some(active.package_revision.as_str()),
            &active.schema_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new((**prior).clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: vec![metadata_only_source(
                    prior,
                    candidate,
                    &active.package_revision,
                    &active.schema_fingerprint,
                    &active.schema_fingerprint,
                )],
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
        signer,
        build_request(
            variant,
            sequence,
            Some(active.package_revision.as_str()),
            &target_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new((**prior).clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: vec![metadata_only_source(
                    prior,
                    candidate,
                    &active.package_revision,
                    &active.schema_fingerprint,
                    &target_fingerprint,
                )],
            },
        ),
        package_context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: active.package_sequence as u64,
        }),
    )
}

fn build_request(
    variant: Variant,
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        environment: ENVIRONMENT.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 1,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "registry.json".to_owned(),
            bytes: project_bytes(variant, sequence),
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

fn publish_and_load(
    signer: &TestSigner,
    mut request: PackageBuildRequest,
    context: PackageLoadContext<'_>,
) -> PublishedPackage {
    request.signature_policy.key_ids = vec![signer.key_id.clone()];
    let prepared = prepare_package(request).expect("package prepares");
    let root = tempfile::Builder::new()
        .prefix("registry-immediate-action-activation-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package tempdir creates");
    let package_root = root.path().join("package");
    let signature =
        sign(prepared.canonical_signed_bytes(), &signer.key).expect("package bytes sign");
    prepared
        .publish_to_directory(
            &package_root,
            vec![PackageSignature {
                key_id: signer.key_id.clone(),
                signature_hex: hex(&signature),
            }],
        )
        .expect("package publishes");
    let anchor_path = root.path().join("trust-anchor.json");
    write_json(
        &anchor_path,
        &PackageTrustAnchor {
            api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
            environment: ENVIRONMENT.to_owned(),
            instance_id: INSTANCE_ID.to_owned(),
            database_id: DATABASE_ID.to_owned(),
            threshold: 1,
            keys: vec![TrustAnchorKey {
                key_id: signer.key_id.clone(),
                jwk: serde_json::to_value(signer.key.public()).expect("public JWK serializes"),
            }],
        },
    );
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            trust_anchor: Some(&anchor_path),
            ..context
        },
    )
    .expect("signed package loads and verifies");
    PublishedPackage {
        _root: root,
        package_root,
        anchor_path,
        package,
    }
}

async fn apply_package(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> ExpectedRegistryIdentity {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
    ))
    .await
    .expect("verified package applies")
}

async fn initial_schema_fingerprint(
    database: &TestDatabase,
    registry: &CompiledRegistry,
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
            .expect("successor DDL rehearses");
    }
    reconcile_runtime_acl_for_fingerprint(&transaction, package.registry(), &database.runtime_role)
        .await;
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

async fn assert_exact_catalog(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
) {
    let (migration, task) = database.connect_migration().await;
    let fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("activated schema matches the exact candidate catalog");
    assert_eq!(fingerprint, identity.schema_fingerprint);
    task.abort();
}

async fn reconcile_runtime_acl_for_fingerprint(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) {
    client
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA registry_data, registry_source, registry_derived, registry_context FROM PUBLIC, {};
             GRANT USAGE ON SCHEMA registry_data, registry_source, registry_derived, registry_context TO {};",
            quote(runtime_role.as_str()),
            quote(runtime_role.as_str()),
        ))
        .await
        .expect("schema privileges rehearse");
    for table in &registry.ddl().tables {
        client
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE registry_data.{} FROM PUBLIC, {};",
                quote(&table.physical_name),
                quote(runtime_role.as_str()),
            ))
            .await
            .expect("table privileges revoke");
        if !table.runtime_privileges.is_empty() {
            let privileges = table
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            client
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE registry_data.{} TO {};",
                    quote(&table.physical_name),
                    quote(runtime_role.as_str()),
                ))
                .await
                .expect("table privileges grant");
        }
    }
    for view in &registry.ddl().views {
        client
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {}.{} FROM PUBLIC, {};",
                quote(&view.schema),
                quote(&view.name),
                quote(runtime_role.as_str()),
            ))
            .await
            .expect("view privileges revoke");
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            client
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {}.{} TO {};",
                    quote(&view.schema),
                    quote(&view.name),
                    quote(runtime_role.as_str()),
                ))
                .await
                .expect("view privileges grant");
        }
    }
    for function in &registry.ddl().functions {
        client
            .batch_execute(&format!(
                "REVOKE ALL ON FUNCTION {}.{}({}) FROM PUBLIC, {};",
                quote(&function.schema),
                quote(&function.name),
                function.arguments,
                quote(runtime_role.as_str()),
            ))
            .await
            .expect("function privileges revoke");
        if function.runtime_execute {
            client
                .batch_execute(&format!(
                    "GRANT EXECUTE ON FUNCTION {}.{}({}) TO {};",
                    quote(&function.schema),
                    quote(&function.name),
                    function.arguments,
                    quote(runtime_role.as_str()),
                ))
                .await
                .expect("function privileges grant");
        }
    }
}

fn metadata_only_source(
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    prior_revision: &str,
    prior_schema_fingerprint: &str,
    final_schema_fingerprint: &str,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(prior, candidate, prior_revision);
    let mut covers = change_set
        .changes
        .iter()
        .filter(|change| {
            change.class
                != registry_server::package::CompiledRegistryChangeClass::CompatibleAdditive
        })
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    let base = "modules/core/migrations/action-policy";
    let descriptor = ReviewedMigrationDescriptor {
        id: "action-policy".to_owned(),
        change_class:
            registry_server::package::CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_revision: prior_revision.to_owned(),
        prior_schema_fingerprint: prior_schema_fingerprint.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_schema_fingerprint.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: false,
        },
    };
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path,
            bytes: canonical(&receipt),
        }],
    }
}

async fn prepare_startup_for(
    database: &TestDatabase,
    package: &PublishedPackage,
    active: &ExpectedRegistryIdentity,
) -> registry_server::startup::Result<registry_server::startup::VerifiedStartup> {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let mut context = package_context(PackageIntent::Startup {
        active_revision: &active.package_revision,
        active_sequence: active.package_sequence as u64,
    });
    context.trust_anchor = Some(&package.anchor_path);
    prepare_startup(
        &package.package_root,
        &context,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
}

fn package_context(intent: PackageIntent<'_>) -> PackageLoadContext<'_> {
    PackageLoadContext {
        environment: ENVIRONMENT,
        instance_id: INSTANCE_ID,
        database_id: DATABASE_ID,
        database_initialization_environment: ENVIRONMENT,
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

fn action_router(
    database: &TestDatabase,
    registry: Arc<CompiledRegistry>,
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
        .with_postgres_mutations(mutations),
    ))
}

async fn condition_for(app: &axum::Router, claims: VerifiedRequestClaims) -> Value {
    let response = response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input": {"householdId": HOUSEHOLD_ID}}))
                .expect("condition request serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    response.body["preconditions"].clone()
}

async fn invoke_action(
    app: &axum::Router,
    claims: VerifiedRequestClaims,
    key: &str,
    legal_name: &str,
    preconditions: &Value,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-001",
                    "legalName": legal_name,
                    "jurisdiction": "zone-a"
                },
                "preconditions": preconditions
            }))
            .expect("action request serializes"),
        )
        .await,
    )
    .await
}

async fn seed_household(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
) {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let code = &household.fields["household-code"].physical_name;
    let jurisdiction = &household.fields["jurisdiction"].physical_name;
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                    (record_id, record_revision, record_lifecycle, active_package_revision, {code}, {jurisdiction})
                 VALUES ($1, 1, 'active', $2, 'H-001', 'zone-a')",
                table = quote(table),
                code = quote(code),
                jurisdiction = quote(jurisdiction),
            ),
            &[
                &Uuid::parse_str(HOUSEHOLD_ID).expect("household UUID"),
                &identity.package_revision,
            ],
        )
        .await
        .expect("administrator seeds an existing household target");
}

async fn entity_count(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    entity_id: &str,
) -> i64 {
    let entity = &registry.entities()[entity_id];
    database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{}",
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("administrator counts entity rows")
        .get(0)
}

async fn receipt_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency
              WHERE result_kind = 'immediate_action'",
            &[],
        )
        .await
        .expect("administrator counts immediate-action receipts")
        .get(0)
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

struct ResponseParts {
    status: StatusCode,
    body: Value,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    let body = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).expect("response body is JSON")
    };
    ResponseParts { status, body }
}

fn action_claims(scope: &str) -> VerifiedRequestClaims {
    let mut direct_claims = BTreeMap::new();
    direct_claims.insert(
        "jurisdiction".to_owned(),
        VerifiedClaimValue::direct_string("zone-a").expect("direct claim"),
    );
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar-principal",
        BTreeSet::from([scope.to_owned()]),
        Some("contact-registration".to_owned()),
        direct_claims,
    )
    .expect("authenticated action claims are valid")
}

fn compiled_registry(variant: Variant, sequence: u64) -> CompiledRegistry {
    let project =
        parse_project_json(&project_bytes(variant, sequence)).expect("activation project parses");
    compile_project(&project, &[], CompileProfile::Production).expect("activation project compiles")
}

fn variant_for(registry: &CompiledRegistry) -> Variant {
    match registry
        .actions()
        .actions
        .first()
        .and_then(|action| action.grants.first())
        .and_then(|grant| grant.required_scopes.iter().next())
        .map(String::as_str)
    {
        Some("registry:contact:register") => Variant::ActionV1,
        Some("registry:contact:register.v2") => Variant::ActionV2,
        _ => Variant::NoAction,
    }
}

fn project_bytes(variant: Variant, sequence: u64) -> Vec<u8> {
    let required_scope = match variant {
        Variant::ActionV1 => Some("registry:contact:register"),
        Variant::ActionV2 => Some("registry:contact:register.v2"),
        Variant::NoAction => None,
    };
    let actions = if required_scope.is_some() {
        r#""actions":[{
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"person":{"fromEffect":"person"},"household":{"fromField":"household"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"household","target":{"fromField":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]
          }],"#
            .to_owned()
    } else {
        String::new()
    };
    let access_profiles = required_scope.map_or_else(
        || r#""accessProfiles":[]"#.to_owned(),
        |scope| {
            format!(
                r#""accessProfiles":[{{
                  "id":"contact-registrar",
                  "default":true,
                  "principalClaim":"registry_principal",
                  "requiredScopes":["{scope}"],
                  "requiredPurposes":["contact-registration"],
                  "grants":[{{
                    "action":"register-household-contact",
                    "operations":["invoke"],
                    "targets":[
                      {{"entity":"household","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}},
                      {{"entity":"person","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}},
                      {{"entity":"group-membership","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}}
                    ],
                    "results":["person","membership","household"]
                  }}]
                }}]"#
            )
        },
    );
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"{PACKAGE_ID}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "package":{{"environment":"{ENVIRONMENT}","instanceId":"{INSTANCE_ID}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},
          "entities":[{{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "constraints":[{{"kind":"unique","fields":["person-code"]}}],
            "fields":[
              {{"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}}
            ]
          }},{{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {{"id":"household-code","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}}
            ]
          }},{{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable",
            "fields":[
              {{"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}},
              {{"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}}
            ]
          }}],
          {actions}
          {access_profiles}
        }}"#
    )
    .into_bytes()
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex(&digest))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn write_json<T: Serialize>(path: &std::path::Path, value: &T) {
    fs::write(path, canonical(value)).expect("canonical JSON writes");
    set_private_permissions(path);
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private package file permissions set");
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) {}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
