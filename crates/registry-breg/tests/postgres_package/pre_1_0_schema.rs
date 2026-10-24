// SPDX-License-Identifier: Apache-2.0

use super::*;

/// A fresh, empty database plans and applies the initial activation as
/// before: the pre-1.0 attachment verification check finds no verdict table
/// to judge. Once the database carries the shape a v0.43.0 release
/// installed, the recorded state read and the activation coordinator name the
/// pre-1.0 schema before any other database outcome, including the
/// already-active report the same package would otherwise meet, and write
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plan_and_apply_name_the_v0_43_0_attachment_verification_shape() {
    let database = TestDatabase::create(1).await;
    let (mut migration, task) = database.connect_migration().await;
    let registry = compile_fixture_registry(PlanChoice::Schema);
    let transaction = migration.transaction().await.unwrap();
    install_compiled_schema(&transaction, &registry, &database.runtime_role)
        .await
        .unwrap();
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
    )
    .await
    .unwrap();
    transaction.rollback().await.unwrap();
    task.abort();

    let fixture = PackageFixture::build(None, fingerprint, PlanChoice::Schema);
    let package = load_package(fixture.root.path(), &fixture.context()).unwrap();
    let package_id = package.manifest().package_id.clone();
    let timeouts = ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
        .expect("test timeouts are bounded");
    let plan = |precondition| {
        plan_verified_package(ApplyVerifiedPackageRequest::plan(
            &database.migration_config,
            &package,
            ActivationDeployment::new("local", INSTANCE, DATABASE),
            precondition,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            timeouts,
        ))
    };

    assert_eq!(
        read_recorded_registry_state(
            &database.migration_config,
            &package_id,
            &database.migration_role,
            timeouts,
        )
        .await,
        Ok(None),
        "a fresh database records no registry state"
    );
    let fresh_plan = plan(ApplyPrecondition::InitialActivation)
        .await
        .expect("a fresh database plans the initial activation");
    assert_eq!(fresh_plan.activation, PlannedActivation::Initial);
    apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("a fresh database applies the initial activation");

    install_v0_43_0_attachment_verification(&database.admin).await;
    let before = (
        registry_state_snapshot(&database.admin).await,
        migration_ledger_snapshot(&database.admin).await,
    );

    assert_eq!(
        read_recorded_registry_state(
            &database.migration_config,
            &package_id,
            &database.migration_role,
            timeouts,
        )
        .await,
        Err(MigrationError::Pre1_0Schema)
    );
    // A successor or role-change plan or apply binds to this recorded state
    // first, so the refusal above is the one it meets. An initial activation
    // reads no recorded state beforehand, so the coordinator refuses it too.
    assert_eq!(
        plan(ApplyPrecondition::InitialActivation).await.err(),
        Some(MigrationError::Pre1_0Schema),
        "the plan names the pre-1.0 schema"
    );
    assert_eq!(
        apply_package(
            &database,
            &package,
            ApplyPrecondition::InitialActivation,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .err(),
        Some(MigrationError::Pre1_0Schema),
        "apply names the pre-1.0 schema before any other refusal"
    );
    assert_eq!(
        (
            registry_state_snapshot(&database.admin).await,
            migration_ledger_snapshot(&database.admin).await,
        ),
        before,
        "a refused plan or apply writes nothing"
    );
    database.cleanup().await;
}

/// The attachment verification shape v0.43.0 installed: the verdict table
/// carried its own lease and attempt columns and its pending index, and no
/// verification job table existed.
async fn install_v0_43_0_attachment_verification(admin: &impl GenericClient) {
    admin
        .batch_execute(
            "DROP TABLE registry_internal.registry_attachment_verification_jobs;
             ALTER TABLE registry_internal.registry_attachment_verification
                 DROP COLUMN verification_id,
                 ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 ADD COLUMN lease_id uuid,
                 ADD COLUMN lease_expires_at timestamptz,
                 ADD COLUMN attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                 ADD CHECK ((lease_id IS NULL) = (lease_expires_at IS NULL));
             CREATE INDEX registry_attachment_verification_pending
                 ON registry_internal.registry_attachment_verification
                     (policy_digest,next_attempt_at,sha256,content_type) WHERE verdict='pending'",
        )
        .await
        .expect("administrator installs the v0.43.0 verification shape");
}
