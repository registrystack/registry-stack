// SPDX-License-Identifier: Apache-2.0

//! Installation of the compiler-owned PostgreSQL data surface.

#[cfg(not(all(feature = "runtime", feature = "tooling")))]
use tokio_postgres::GenericClient;
#[cfg(all(feature = "runtime", feature = "tooling", feature = "postgres-test"))]
use tokio_postgres::NoTls;
#[cfg(all(feature = "runtime", feature = "tooling"))]
use tokio_postgres::{Client, GenericClient};

use crate::generated_ddl::DdlStatementKind;
#[cfg(any(feature = "tooling", feature = "postgres-test"))]
use crate::history_commit::install_empty_history_baseline;
use crate::history_store::install_history_schema_store;
use crate::model::CompiledRegistry;
use crate::mutation::install_mutation_schema;

#[cfg(all(feature = "runtime", feature = "tooling"))]
use super::config::ConnectionTls;
use super::{
    catalog::install_registry_state_schema, verify_btree_gist, PostgresKernelError, Result,
    SqlIdentifier,
};
#[cfg(all(feature = "runtime", feature = "tooling"))]
use super::{
    catalog::{
        managed_schema_fingerprint, verify_catalog_identity_for_catalog, ExpectedManagedCatalog,
        ExpectedRegistryIdentity,
    },
    verify_migration_role, ConnectionConfig, RegistryLockKey, RuntimePool,
};
#[cfg(any(feature = "tooling", feature = "postgres-test"))]
use crate::history_store::retain_descriptor;

/// Installs one exact compiled Registry data inventory and its closed runtime
/// privilege set. The caller must already be the verified migration role and
/// must own every managed schema.
pub async fn install_compiled_schema(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    verify_postgres_15_or_newer(migration).await?;
    if registry.ddl().requires_btree_gist {
        verify_btree_gist(migration).await?;
    }

    install_registry_state_schema(migration, runtime_role).await?;
    install_mutation_schema(migration, runtime_role)
        .await
        .map_err(|_| PostgresKernelError::Connection)?;
    install_history_schema_store(migration, runtime_role)
        .await
        .map_err(|_| PostgresKernelError::Connection)?;

    for statement in &registry.ddl().statements {
        if statement.kind == DdlStatementKind::Schema {
            continue;
        }
        migration.batch_execute(&statement.sql).await?;
    }

    reconcile_compiled_runtime_acl(migration, registry, runtime_role).await
}

pub(crate) async fn reconcile_compiled_runtime_acl(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    client
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA registry_data, registry_source, registry_derived, registry_context FROM PUBLIC, {};
             GRANT USAGE ON SCHEMA registry_data, registry_source, registry_derived, registry_context TO {};",
            runtime_role.quoted(),
            runtime_role.quoted(),
        ))
        .await?;

    for table in &registry.ddl().tables {
        let table_name = quote_compiled_identifier(&table.physical_name);
        client
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE registry_data.{table_name} FROM PUBLIC, {};",
                runtime_role.quoted(),
            ))
            .await?;
        if !table.runtime_privileges.is_empty() {
            let privileges = table
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            client
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE registry_data.{table_name} TO {};",
                    runtime_role.quoted(),
                ))
                .await?;
        }
    }
    for view in &registry.ddl().views {
        let schema = quote_compiled_identifier(&view.schema);
        let view_name = quote_compiled_identifier(&view.name);
        client
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {schema}.{view_name} FROM PUBLIC, {};",
                runtime_role.quoted(),
            ))
            .await?;
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            client
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {schema}.{view_name} TO {};",
                    runtime_role.quoted(),
                ))
                .await?;
        }
    }
    for function in &registry.ddl().functions {
        let schema = quote_compiled_identifier(&function.schema);
        let name = quote_compiled_identifier(&function.name);
        client
            .batch_execute(&format!(
                "REVOKE ALL ON FUNCTION {schema}.{name}({}) FROM PUBLIC, {};",
                function.arguments,
                runtime_role.quoted(),
            ))
            .await?;
        if function.runtime_execute {
            client
                .batch_execute(&format!(
                    "GRANT EXECUTE ON FUNCTION {schema}.{name}({}) TO {};",
                    function.arguments,
                    runtime_role.quoted(),
                ))
                .await?;
        }
    }
    Ok(())
}

#[cfg(any(feature = "tooling", feature = "postgres-test"))]
pub(crate) async fn install_empty_history_baseline_for_compiled_registry(
    client: &impl GenericClient,
    registry: &CompiledRegistry,
    package_revision: &str,
) -> Result<()> {
    for table in &registry.ddl().tables {
        let table_name = quote_compiled_identifier(&table.physical_name);
        let row = client
            .query_one(
                &format!("SELECT count(*)::bigint FROM registry_data.{table_name}"),
                &[],
            )
            .await?;
        if row.get::<_, i64>(0) != 0 {
            return Err(PostgresKernelError::CatalogInvariant(
                "empty history baseline requires empty live data tables",
            ));
        }
    }
    let revision_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_revisions",
            &[],
        )
        .await?
        .get(0);
    if revision_count != 0 {
        return Err(PostgresKernelError::CatalogInvariant(
            "empty history baseline requires empty revision journal",
        ));
    }
    let existing_head = client
        .query_opt(
            "SELECT 1 FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await?;
    if existing_head.is_some() {
        return Err(PostgresKernelError::CatalogInvariant(
            "empty history baseline requires absent history head",
        ));
    }
    retain_descriptor(client, registry, package_revision)
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    install_empty_history_baseline(client, package_revision)
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    Ok(())
}

pub(crate) async fn verify_postgres_15_or_newer(client: &impl GenericClient) -> Result<()> {
    let version_num: String = client
        .query_one("SELECT current_setting('server_version_num')", &[])
        .await?
        .get(0);
    let version_num = version_num
        .parse::<u32>()
        .map_err(|_| PostgresKernelError::Configuration("PostgreSQL 15 or newer is required"))?;
    if version_num < 150_000 {
        return Err(PostgresKernelError::Configuration(
            "PostgreSQL 15 or newer is required",
        ));
    }
    Ok(())
}

/// Candidate identity installed into a clean schema-test database.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub struct SchemaTestDatabaseIdentity<'a> {
    pub environment: &'a str,
    pub instance_id: &'a str,
    pub database_id: &'a str,
    pub active_package_revision: &'a str,
    pub active_sequence: u64,
}

/// Opaque capability for the production pre-sign schema-test executor.
///
/// It is intentionally not a prepared server: callers cannot obtain a pool,
/// client, router, listener, or response from it. The fixture executor consumes
/// it inside the crate and dispatches only validated journey requests.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub struct PreparedSchemaTestDatabase {
    pool: RuntimePool,
    migration_connection: ConnectionConfig,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_key: RegistryLockKey,
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
#[derive(Clone)]
pub(crate) struct PreparedSchemaTestCatalogVerifier {
    migration_connection: ConnectionConfig,
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_key: RegistryLockKey,
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
impl PreparedSchemaTestDatabase {
    pub(crate) fn pool(&self) -> RuntimePool {
        self.pool.clone()
    }

    pub(crate) fn expected(&self) -> &ExpectedRegistryIdentity {
        &self.expected
    }

    pub(crate) fn lock_key(&self) -> RegistryLockKey {
        self.lock_key
    }

    pub(crate) fn catalog_verifier(&self) -> PreparedSchemaTestCatalogVerifier {
        PreparedSchemaTestCatalogVerifier {
            migration_connection: self.migration_connection.clone(),
            expected: self.expected.clone(),
            expected_catalog: self.expected_catalog.clone(),
            migration_role: self.migration_role.clone(),
            runtime_role: self.runtime_role.clone(),
            lock_key: self.lock_key,
        }
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
impl PreparedSchemaTestCatalogVerifier {
    pub(crate) async fn verify(&self) -> Result<()> {
        let (mut client, connection_task) = connect_schema_test(&self.migration_connection).await?;
        verify_migration_role(&client, &self.migration_role).await?;
        let transaction = client.transaction().await?;
        transaction
            .batch_execute("SET LOCAL lock_timeout = '5s'")
            .await?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await?;
        transaction.commit().await?;
        connection_task.abort();
        Ok(())
    }
}

/// Prepare a clean, pre-provisioned PostgreSQL target for a pre-sign schema
/// test. The caller supplies the explicit migration and runtime connection
/// configurations resolved from trusted runtime configuration.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub async fn prepare_schema_test_database_with_connections(
    migration_connection: &ConnectionConfig,
    runtime_connection: &ConnectionConfig,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    registry: &CompiledRegistry,
    identity: SchemaTestDatabaseIdentity<'_>,
) -> Result<PreparedSchemaTestDatabase> {
    let (mut migration, migration_task) = connect_schema_test(migration_connection).await?;
    verify_migration_role(&migration, migration_role).await?;
    let transaction = migration.transaction().await?;
    refuse_existing_managed_objects(&transaction).await?;
    install_compiled_schema(&transaction, registry, runtime_role).await?;
    retain_descriptor(&transaction, registry, identity.active_package_revision)
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    install_empty_history_baseline_for_compiled_registry(
        &transaction,
        registry,
        identity.active_package_revision,
    )
    .await?;

    let expected_catalog = ExpectedManagedCatalog::compiled(registry);
    let schema_fingerprint =
        managed_schema_fingerprint(&transaction, runtime_role, &expected_catalog).await?;
    let package_sequence = i64::try_from(identity.active_sequence).map_err(|_| {
        PostgresKernelError::Configuration("schema-test package sequence is out of range")
    })?;
    let expected = ExpectedRegistryIdentity {
        package_id: registry.registry_id().to_owned(),
        environment: identity.environment.to_owned(),
        instance_id: identity.instance_id.to_owned(),
        database_id: identity.database_id.to_owned(),
        package_revision: identity.active_package_revision.to_owned(),
        schema_fingerprint,
        package_sequence,
    };
    let inserted = transaction
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, environment, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status
             ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')",
            &[
                &expected.package_id,
                &expected.environment,
                &expected.instance_id,
                &expected.database_id,
                &expected.package_revision,
                &expected.schema_fingerprint,
                &expected.package_sequence,
            ],
        )
        .await?;
    if inserted != 1 {
        return Err(PostgresKernelError::CatalogInvariant(
            "schema-test registry state was not installed exactly once",
        ));
    }
    verify_catalog_identity_for_catalog(
        &transaction,
        &expected,
        &expected_catalog,
        migration_role,
        runtime_role,
    )
    .await?;
    transaction.commit().await?;
    migration_task.abort();

    let pool = runtime_connection.build_pool()?;
    let (runtime, runtime_task) = connect_schema_test(runtime_connection).await?;
    verify_schema_test_runtime_role(&runtime, migration_role, runtime_role).await?;
    verify_catalog_identity_for_catalog(
        &runtime,
        &expected,
        &expected_catalog,
        migration_role,
        runtime_role,
    )
    .await?;
    runtime_task.abort();

    let lock_key = RegistryLockKey::derive(&expected.package_id)?;
    Ok(PreparedSchemaTestDatabase {
        pool,
        migration_connection: migration_connection.clone(),
        expected,
        expected_catalog,
        migration_role: migration_role.clone(),
        runtime_role: runtime_role.clone(),
        lock_key,
    })
}

/// Install one compiled Registry into an empty disposable database transaction,
/// verify the exact managed catalog, roll the transaction back, and return only
/// its schema fingerprint. This is a measurement path only: it never writes
/// active package identity and it never returns a pool, client, database id,
/// role, URL, or SQL.
#[cfg(all(feature = "runtime", feature = "tooling"))]
pub(crate) async fn rehearse_schema_fingerprint_with_connection(
    migration_connection: &ConnectionConfig,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
    registry: &CompiledRegistry,
) -> Result<String> {
    let (mut migration, migration_task) = connect_schema_test(migration_connection).await?;
    let migration_result: Result<String> = async {
        verify_migration_role(&migration, migration_role).await?;
        let transaction = migration.transaction().await?;
        transaction
            .batch_execute("SET LOCAL lock_timeout = '5s'")
            .await?;
        refuse_existing_managed_objects(&transaction).await?;
        install_compiled_schema(&transaction, registry, runtime_role).await?;
        let expected_catalog = ExpectedManagedCatalog::compiled(registry);
        let fingerprint =
            managed_schema_fingerprint(&transaction, runtime_role, &expected_catalog).await?;
        transaction.rollback().await?;
        Ok(fingerprint)
    }
    .await;
    migration_task.abort();
    migration_result
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn connect_schema_test(
    config: &ConnectionConfig,
) -> Result<(Client, tokio::task::JoinHandle<()>)> {
    match config.tls_connector() {
        ConnectionTls::Rustls(connector) => {
            let (client, connection) = config.postgres().connect(connector).await?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, task))
        }
        #[cfg(feature = "postgres-test")]
        ConnectionTls::TestOnlyPlaintext => {
            let (client, connection) = config.postgres().connect(NoTls).await?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, task))
        }
    }
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn refuse_existing_managed_objects(client: &impl GenericClient) -> Result<()> {
    client
        .batch_execute("SAVEPOINT registry_empty_schema_probe")
        .await?;
    let empty = client
        .batch_execute(
            "DROP SCHEMA registry_internal RESTRICT;
             DROP SCHEMA registry_data RESTRICT;
             DROP SCHEMA registry_source RESTRICT;
             DROP SCHEMA registry_derived RESTRICT;
             DROP SCHEMA registry_context RESTRICT",
        )
        .await
        .is_ok();
    client
        .batch_execute(
            "ROLLBACK TO SAVEPOINT registry_empty_schema_probe;
             RELEASE SAVEPOINT registry_empty_schema_probe",
        )
        .await?;
    if !empty {
        return Err(PostgresKernelError::CatalogInvariant(
            "schema-test database is not clean",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "runtime", feature = "tooling"))]
async fn verify_schema_test_runtime_role(
    client: &impl GenericClient,
    migration_role: &SqlIdentifier,
    runtime_role: &SqlIdentifier,
) -> Result<()> {
    let row = client
        .query_one(
            "SELECT current_user,
                    rolsuper,
                    rolbypassrls,
                    rolcreatedb,
                    rolcreaterole,
                    current_user = $1,
                    pg_has_role(current_user, $1, 'MEMBER'),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'registry_internal', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_data', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_source', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_derived', 'CREATE'),
                    has_schema_privilege(current_user, 'registry_context', 'CREATE'),
                    EXISTS (
                        SELECT 1
                          FROM pg_catalog.pg_class c
                          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname IN (
                             'registry_internal',
                             'registry_data',
                             'registry_source',
                             'registry_derived',
                             'registry_context'
                         )
                           AND c.relowner = (
                               SELECT oid
                                 FROM pg_catalog.pg_roles
                                WHERE rolname = current_user
                           )
                    )
               FROM pg_catalog.pg_roles
              WHERE rolname = current_user",
            &[&migration_role.as_str()],
        )
        .await?;
    if row.get::<_, String>(0) != runtime_role.as_str()
        || (1..=13).any(|index| row.get::<_, bool>(index))
    {
        return Err(PostgresKernelError::RoleInvariant(
            "schema-test runtime connection uses unexpected authority",
        ));
    }
    Ok(())
}

fn quote_compiled_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
