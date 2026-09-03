// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use registry_breg::postgres::{
    provision_managed_schemas, ConnectionConfig, PoolBounds, SqlIdentifier,
};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, NoTls};

pub struct TestDatabase {
    admin_root: Config,
    pub admin: Client,
    admin_task: JoinHandle<()>,
    pub migration_config: ConnectionConfig,
    pub runtime_config: ConnectionConfig,
    pub tls_runtime_config: ConnectionConfig,
    pub migration_role: SqlIdentifier,
    pub runtime_role: SqlIdentifier,
    pub intruder_role: SqlIdentifier,
    database: SqlIdentifier,
    migration_raw: Config,
}

impl TestDatabase {
    pub async fn create(pool_size: usize) -> Self {
        let url = env::var("BREG_TEST_DATABASE_URL")
            .expect("BREG_TEST_DATABASE_URL is required for the real PostgreSQL kernel test");
        let admin_root =
            Config::from_str(&url).expect("BREG_TEST_DATABASE_URL must be a valid PostgreSQL URL");
        let suffix = unique_suffix();
        let database = SqlIdentifier::parse(&format!("breg_test_{suffix}"))
            .expect("generated database identifier is valid");
        let migration_role = SqlIdentifier::parse(&format!("breg_migration_{suffix}"))
            .expect("generated migration role identifier is valid");
        let runtime_role = SqlIdentifier::parse(&format!("breg_runtime_{suffix}"))
            .expect("generated runtime role identifier is valid");
        let intruder_role = SqlIdentifier::parse(&format!("breg_intruder_{suffix}"))
            .expect("generated intruder role identifier is valid");
        let password = format!("rs{suffix}password");

        let (root, root_task) = connect(admin_root.clone()).await;
        root.batch_execute(&format!(
            "CREATE ROLE \"{}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}';\n\
             CREATE ROLE \"{}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}';\n\
             CREATE ROLE \"{}\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;",
            migration_role.as_str(),
            password,
            runtime_role.as_str(),
            password,
            intruder_role.as_str(),
        ))
        .await
        .expect("test administrator can create isolated roles");
        root.batch_execute(&format!("CREATE DATABASE \"{}\";", database.as_str()))
            .await
            .expect("test administrator can create an isolated database");
        root_task.abort();

        let mut database_admin_config = admin_root.clone();
        database_admin_config.dbname(database.as_str());
        let (admin, admin_task) = connect(database_admin_config).await;
        admin
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE \"{}\" FROM PUBLIC;\n\
                 GRANT CONNECT ON DATABASE \"{}\" TO \"{}\", \"{}\";",
                database.as_str(),
                database.as_str(),
                migration_role.as_str(),
                runtime_role.as_str(),
            ))
            .await
            .expect("test administrator can constrain database privileges");
        provision_managed_schemas(&admin, &migration_role)
            .await
            .expect("test administrator can provision managed schemas");

        let bounds = PoolBounds::new(
            pool_size,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .expect("test pool bounds are valid");
        let migration_raw = role_config(&admin_root, &database, &migration_role, &password);
        let migration_config = ConnectionConfig::from_test_config(migration_raw.clone(), bounds)
            .expect("migration test configuration is valid");
        let runtime_raw = role_config(&admin_root, &database, &runtime_role, &password);
        let runtime_config = ConnectionConfig::from_test_config(runtime_raw.clone(), bounds)
            .expect("runtime test configuration is valid");
        let tls_runtime_config = ConnectionConfig::require_tls_config(runtime_raw, bounds)
            .expect("TLS runtime test configuration is valid");
        Self {
            admin_root,
            admin,
            admin_task,
            migration_config,
            runtime_config,
            tls_runtime_config,
            migration_role,
            runtime_role,
            intruder_role,
            database,
            migration_raw,
        }
    }

    pub async fn connect_migration(&self) -> (Client, JoinHandle<()>) {
        connect(self.migration_raw.clone()).await
    }

    pub async fn cleanup(self) {
        self.admin_task.abort();
        let (root, root_task) = connect(self.admin_root).await;
        root.batch_execute(&format!(
            "DROP DATABASE \"{}\" WITH (FORCE);",
            self.database.as_str(),
        ))
        .await
        .expect("isolated PostgreSQL test database can be removed");
        root.batch_execute(&format!(
            "DROP ROLE \"{}\"; DROP ROLE \"{}\"; DROP ROLE \"{}\";",
            self.intruder_role.as_str(),
            self.runtime_role.as_str(),
            self.migration_role.as_str(),
        ))
        .await
        .expect("isolated PostgreSQL test roles can be removed");
        root_task.abort();
    }
}

fn role_config(
    admin: &Config,
    database: &SqlIdentifier,
    role: &SqlIdentifier,
    password: &str,
) -> Config {
    let mut config = admin.clone();
    config.dbname(database.as_str());
    config.user(role.as_str());
    config.password(password);
    config
}

async fn connect(config: Config) -> (Client, JoinHandle<()>) {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("real PostgreSQL test connection succeeds");
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, task)
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}_{nanos}_{counter}", std::process::id())
}
