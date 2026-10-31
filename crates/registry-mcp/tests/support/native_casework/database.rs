// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, str::FromStr as _};
use url::Url;

use super::process::private_file;

pub struct NativeDatabases {
    admin_url: String,
    breg_databases: [String; 2],
    breg_roles: [String; 2],
    casework_schema: String,
    pub breg_rehearsal_migration: String,
    pub breg_rehearsal_runtime: String,
    pub breg_live_migration: String,
    pub breg_live_runtime: String,
    pub casework: String,
}

impl NativeDatabases {
    pub fn breg_roles(&self) -> &[String; 2] {
        &self.breg_roles
    }

    pub async fn create(secret_root: &Path) -> Self {
        let admin_url = std::env::var("CASEWORK_MCP_TEST_DATABASE_URL")
            .expect("CASEWORK_MCP_TEST_DATABASE_URL names an owned disposable PostgreSQL server");
        Url::parse(&admin_url).expect("disposable PostgreSQL URL parses");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let breg_databases = [
            format!("mcp_staff_test_{suffix}"),
            format!("mcp_staff_live_{suffix}"),
        ];
        let breg_roles = [
            format!("mcp_staff_migrate_{suffix}"),
            format!("mcp_staff_runtime_{suffix}"),
        ];
        let casework_schema = format!("mcp_staff_casework_{suffix}");
        let password = uuid::Uuid::new_v4().simple().to_string();
        let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
            .await
            .expect("connect disposable PostgreSQL administrator");
        let root_connection = tokio::spawn(connection);
        for role in &breg_roles {
            admin
                .batch_execute(&format!(
                    "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}'"
                ))
                .await
                .expect("create fixture-owned BReg role");
        }
        let mut breg_urls = Vec::new();
        for database in &breg_databases {
            admin
                .batch_execute(&format!("CREATE DATABASE {database}"))
                .await
                .expect("create fixture-owned BReg database");
            let mut owner_url = Url::parse(&admin_url).expect("PostgreSQL administrator URL");
            owner_url.set_path(&format!("/{database}"));
            let (owner, connection) =
                tokio_postgres::connect(owner_url.as_str(), tokio_postgres::NoTls)
                    .await
                    .expect("connect fixture-owned BReg database");
            let database_connection = tokio::spawn(connection);
            owner
                .batch_execute(&format!(
                    "REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE {database} TO {}; GRANT CONNECT ON DATABASE {database} TO {}",
                    breg_roles[0], breg_roles[1]
                ))
                .await
                .expect("provision fixture-owned BReg database grants");
            for schema in [
                "registry_internal",
                "registry_data",
                "registry_source",
                "registry_derived",
                "registry_context",
            ] {
                owner
                    .batch_execute(&format!(
                        "CREATE SCHEMA {schema} AUTHORIZATION {}; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC",
                        breg_roles[0]
                    ))
                    .await
                    .expect("provision fixture-owned BReg schema");
            }
            database_connection.abort();
            let mut role_urls = Vec::new();
            for role in &breg_roles {
                let mut role_url = owner_url.clone();
                role_url
                    .set_username(role)
                    .expect("fixture-owned PostgreSQL role is URL-safe");
                role_url
                    .set_password(Some(&password))
                    .expect("fixture-owned PostgreSQL password is URL-safe");
                role_urls.push(role_url.to_string());
            }
            breg_urls.push(role_urls);
        }
        admin
            .batch_execute(&format!("CREATE SCHEMA {casework_schema}"))
            .await
            .expect("create fixture-owned Casework schema");
        root_connection.abort();

        let separator = if admin_url.contains('?') { '&' } else { '?' };
        let casework = format!("{admin_url}{separator}options=-csearch_path%3D{casework_schema}");
        tokio_postgres::Config::from_str(&casework)
            .expect("fixture-owned Casework PostgreSQL URL parses");
        let result = Self {
            admin_url,
            breg_databases,
            breg_roles,
            casework_schema,
            breg_rehearsal_migration: breg_urls[0][0].clone(),
            breg_rehearsal_runtime: breg_urls[0][1].clone(),
            breg_live_migration: breg_urls[1][0].clone(),
            breg_live_runtime: breg_urls[1][1].clone(),
            casework,
        };
        result.write_secrets(secret_root);
        result
    }

    fn write_secrets(&self, root: &Path) {
        for (name, value) in [
            ("breg-test-migration-url", &self.breg_rehearsal_migration),
            ("breg-test-runtime-url", &self.breg_rehearsal_runtime),
            ("breg-live-migration-url", &self.breg_live_migration),
            ("breg-live-runtime-url", &self.breg_live_runtime),
            ("casework-database-url", &self.casework),
        ] {
            private_file(&root.join(name), value.as_bytes());
        }
    }

    async fn cleanup(&self) -> Result<(), tokio_postgres::Error> {
        let (admin, connection) =
            tokio_postgres::connect(&self.admin_url, tokio_postgres::NoTls).await?;
        let task = tokio::spawn(connection);
        admin
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {} CASCADE",
                self.casework_schema
            ))
            .await?;
        for database in &self.breg_databases {
            admin
                .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
                .await?;
        }
        for role in &self.breg_roles {
            admin
                .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                .await?;
        }
        task.abort();
        Ok(())
    }

    pub async fn finish(self) {
        self.cleanup()
            .await
            .expect("remove only fixture-owned PostgreSQL objects");
        std::mem::forget(self);
    }
}

impl Drop for NativeDatabases {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let databases = self.breg_databases.clone();
        let roles = self.breg_roles.clone();
        let schema = self.casework_schema.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("cleanup runtime")
                .block_on(async move {
                    let (admin, connection) =
                        tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
                    let task = tokio::spawn(connection);
                    admin
                        .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                        .await?;
                    for database in databases {
                        admin
                            .batch_execute(&format!(
                                "DROP DATABASE IF EXISTS {database} WITH (FORCE)"
                            ))
                            .await?;
                    }
                    for role in roles {
                        admin
                            .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                            .await?;
                    }
                    task.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned PostgreSQL cleanup failed");
        }
    }
}
