// SPDX-License-Identifier: Apache-2.0

use registry_platform_activation::{
    activation_history, activation_recorded, active_activation, append_activation,
    check_active_package, database_id_check, grant_runtime_role, observe_role, stray_authority,
    ActivePackageError, DatabaseIdCheck, Layout, NewActivation, PlanKind, RoleMode,
};
use tokio_postgres::NoTls;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("ACTIVATION_TEST_DATABASE_URL")
        .expect("ACTIVATION_TEST_DATABASE_URL must name a disposable PostgreSQL database")
}

fn layout() -> Layout {
    Layout::new(
        "fixture",
        "fixture_activations",
        "fixture_schema_migrations",
        &[],
        false,
    )
    .expect("static fixture layout")
}

#[tokio::test]
async fn ledger_identity_and_split_role_share_one_postgres_boundary() {
    let (mut client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let suffix = Uuid::new_v4().simple().to_string();
    let schema = format!("activation_{suffix}");
    let runtime_role = format!("activation_runtime_{suffix}");
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema};
             CREATE ROLE {runtime_role} NOLOGIN;
             SET search_path TO {schema};
             CREATE TABLE fixture_schema_migrations(
               version bigint PRIMARY KEY,
               applied_at timestamptz NOT NULL DEFAULT now()
             );
             CREATE TABLE fixture_records(
               record_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
               document text NOT NULL
             );
             CREATE TABLE fixture_activations(
               activation_id uuid PRIMARY KEY,
               apply_order bigint NOT NULL UNIQUE,
               package_digest text NOT NULL,
               predecessor_package_digest text,
               database_id text NOT NULL,
               plan_kind text NOT NULL CHECK(plan_kind IN ('initial','successor')),
               applied_at timestamptz NOT NULL,
               operator_reference_hash text,
               backup_references text[] NOT NULL,
               role_mode text NOT NULL CHECK(role_mode IN ('single','split'))
             );"
        ))
        .await
        .expect("create isolated activation fixture");

    let transaction = client.transaction().await.expect("start transaction");
    assert!(active_activation(&transaction, &layout())
        .await
        .expect("read empty ledger")
        .is_none());

    grant_runtime_role(&transaction, &layout(), &runtime_role, &[])
        .await
        .expect("grant split runtime role");
    let role = observe_role(&transaction, &layout(), Some(&runtime_role), &[])
        .await
        .expect("observe split role")
        .expect("ledger exists");
    assert_eq!(role.mode, RoleMode::Split);
    assert!(role.grants_current);

    let activation_id = Uuid::new_v4();
    let activation = append_activation(
        &transaction,
        &layout(),
        &NewActivation {
            activation_id,
            package_digest: "sha256:fixture",
            database_id: "fixture-database",
            operator_reference_hash: None,
            backup_references: &[],
            role_mode: role.mode,
            runtime_role: None,
        },
    )
    .await
    .expect("append activation");
    assert_eq!(activation.plan_kind, PlanKind::Initial);
    assert_eq!(
        database_id_check(Some(&activation), "fixture-database"),
        DatabaseIdCheck::Matches
    );
    assert_eq!(
        database_id_check(Some(&activation), "another-database"),
        DatabaseIdCheck::Differs
    );
    assert!(activation_recorded(&transaction, &layout(), activation_id)
        .await
        .expect("read activation id"));
    assert_eq!(
        activation_history(&transaction, &layout())
            .await
            .expect("read activation history"),
        vec![activation.clone()]
    );
    check_active_package(
        &transaction,
        &layout(),
        "fixture-database",
        "sha256:fixture",
    )
    .await
    .expect("accept exact active package");
    assert!(matches!(
        check_active_package(
            &transaction,
            &layout(),
            "another-database",
            "sha256:fixture"
        )
        .await,
        Err(ActivePackageError::DatabaseIdMismatch)
    ));

    transaction
        .batch_execute(&format!(
            "REVOKE INSERT ON TABLE {schema}.fixture_records FROM {runtime_role}"
        ))
        .await
        .expect("remove one required runtime grant");
    let role = observe_role(&transaction, &layout(), Some(&runtime_role), &[])
        .await
        .expect("observe incomplete split grants")
        .expect("ledger exists");
    assert_eq!(role.mode, RoleMode::Split);
    assert!(!role.grants_current);

    transaction
        .batch_execute(&format!(
            "GRANT CREATE ON SCHEMA {schema} TO {runtime_role}"
        ))
        .await
        .expect("weaken split role");
    let fixes = stray_authority(&transaction, &layout(), Some(&runtime_role))
        .await
        .expect("identify stray authority");
    assert_eq!(
        fixes,
        vec![format!(
            "REVOKE CREATE ON SCHEMA {schema} FROM {runtime_role}"
        )]
    );
    transaction
        .rollback()
        .await
        .expect("roll back fixture state");

    client
        .batch_execute(&format!(
            "RESET search_path; DROP SCHEMA {schema} CASCADE; DROP ROLE {runtime_role};"
        ))
        .await
        .expect("remove isolated activation fixture");
    drop(client);
    connection_task
        .await
        .expect("join PostgreSQL connection")
        .expect("PostgreSQL connection completes");
}

#[tokio::test]
async fn postgres_version_floor_precedes_missing_ledger_observation() {
    let (client, connection) = tokio_postgres::connect(&database_url(), NoTls)
        .await
        .expect("connect to disposable PostgreSQL");
    let connection_task = tokio::spawn(connection);
    let version: i32 = client
        .query_one("SELECT current_setting('server_version_num')::integer", &[])
        .await
        .expect("server version")
        .get(0);
    let missing = format!("missing_{}", Uuid::new_v4().simple());
    let result = registry_platform_activation::relation_exists(&client, &missing).await;
    if version < 170_000 {
        assert!(matches!(
            result,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
        assert!(matches!(
            active_activation(&client, &layout()).await,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
        assert!(matches!(
            registry_platform_activation::schema_state(&client, &layout(), &[1]).await,
            Err(registry_platform_activation::Error::UnsupportedPostgres)
        ));
    } else {
        assert!(!result.expect("supported server"));
    }
    drop(client);
    connection_task
        .await
        .expect("connection task")
        .expect("connection closes");
}
