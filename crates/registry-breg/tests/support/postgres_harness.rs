// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use registry_breg::audit::{test_support::AuditCapture, RegistryAudit};
use registry_breg::postgres::{
    provision_managed_schemas, ConnectionConfig, PoolBounds, SqlIdentifier,
};
use registry_platform_audit::AuditProfile;
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, NoTls};

pub struct TestDatabase {
    admin_root: Config,
    pub admin: Client,
    admin_task: JoinHandle<()>,
    #[allow(dead_code)] // Individual integration targets use different fixture identities.
    pub migration_config: ConnectionConfig,
    pub runtime_config: ConnectionConfig,
    #[allow(dead_code)] // Only the TLS-specific integration target uses this configuration.
    pub tls_runtime_config: ConnectionConfig,
    pub migration_role: SqlIdentifier,
    pub runtime_role: SqlIdentifier,
    pub intruder_role: SqlIdentifier,
    database: SqlIdentifier,
    migration_raw: Config,
    audit: AuditCapture,
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
                 GRANT CONNECT, TEMPORARY ON DATABASE \"{}\" TO \"{}\";
                 GRANT CONNECT ON DATABASE \"{}\" TO \"{}\";",
                database.as_str(),
                database.as_str(),
                migration_role.as_str(),
                database.as_str(),
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
            audit: AuditCapture::default(),
        }
    }

    /// An audit handle whose entries land in this database's capture. Every
    /// handle a test builds shares the one capture, so entries from several
    /// services read back in append order.
    #[allow(dead_code)] // Not every integration target builds services directly.
    pub fn audit(&self, profile: AuditProfile) -> RegistryAudit {
        self.audit.audit(profile)
    }

    /// The capture behind [`Self::audit`], for failure injection.
    #[allow(dead_code)] // Only the audit failure tests inject refusals.
    pub fn audit_capture(&self) -> &AuditCapture {
        &self.audit
    }

    /// Every audit entry accepted so far, as whole envelopes.
    #[allow(dead_code)] // Not every integration target reads audit entries.
    pub fn audit_entries(&self) -> Vec<Value> {
        self.audit.entries()
    }

    /// Assert that every audit request accepted so far has exactly one
    /// response, written after it under the same schema and correlation.
    /// The only response allowed without a request is a refusal for a
    /// correlation that never opened one: a request refused before its
    /// attempt was recorded.
    #[allow(dead_code)] // Not every integration target reads audit entries.
    pub fn assert_every_audit_request_answered_once(&self) {
        let entries = self.audit.entries();
        let mut open = std::collections::BTreeMap::<(String, String), usize>::new();
        for entry in &entries {
            let key = (
                entry["schema"].as_str().unwrap_or_default().to_owned(),
                entry["correlation"].as_str().unwrap_or_default().to_owned(),
            );
            match entry["phase"].as_str() {
                Some("request") => *open.entry(key).or_default() += 1,
                Some("response") => match open.get_mut(&key) {
                    Some(pending) if *pending > 0 => *pending -= 1,
                    None if entry["record"]["phase"] == "refusal" => {}
                    _ => panic!("a response answers no open request: {entry}\n{entries:#?}"),
                },
                other => panic!("an audit entry has no pairing phase {other:?}: {entry}"),
            }
        }
        let unanswered: Vec<_> = open.iter().filter(|(_, pending)| **pending > 0).collect();
        assert!(
            unanswered.is_empty(),
            "audit requests without a response: {unanswered:?}\n{entries:#?}"
        );
    }

    /// The record of every audit entry accepted so far.
    #[allow(dead_code)] // Not every integration target reads audit entries.
    pub fn audit_records(&self) -> Vec<Value> {
        self.audit
            .entries()
            .into_iter()
            .map(|mut entry| entry["record"].take())
            .collect()
    }

    #[allow(dead_code)] // Not every integration target needs a migration-role session.
    pub async fn connect_migration(&self) -> (Client, JoinHandle<()>) {
        connect(self.migration_raw.clone()).await
    }

    #[allow(dead_code)]
    pub async fn connect_admin(&self) -> (Client, JoinHandle<()>) {
        let mut config = self.admin_root.clone();
        config.dbname(self.database.as_str());
        connect(config).await
    }

    /// Reuse the exact fixture migration credentials against another disposable
    /// database, for proving endpoint/identity separation with identical roles.
    #[allow(dead_code)] // Only binding tests use this shared-harness helper.
    pub async fn connect_migration_to(&self, database: &str) -> (Client, JoinHandle<()>) {
        let mut config = self.migration_raw.clone();
        config.dbname(database);
        connect(config).await
    }

    #[allow(dead_code)] // Only binding tests use this shared-harness helper.
    pub fn migration_config_for_database(&self, database: &str) -> ConnectionConfig {
        let mut config = self.migration_raw.clone();
        config.dbname(database);
        ConnectionConfig::from_test_config(
            config,
            PoolBounds::new(
                1,
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .unwrap(),
        )
        .unwrap()
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
