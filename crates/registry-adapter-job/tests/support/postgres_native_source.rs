// SPDX-License-Identifier: Apache-2.0

//! Shared real-PostgreSQL source setup for the two native destination proofs.
//! The source uses its own schema and file-backed credential. The Adapter item
//! store and each native destination keep their existing isolated state.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use deadpool_postgres::Pool;
use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::{config::Host, Config, NoTls};

const DIRECT_MAPPING: &str = r#"fn map_proposal(exchange) {
    #{
        startInput: #{
            input: #{
                targetId: exchange.body.target,
                label: exchange.body.label
            }
        },
        submitBody: #{}
    }
}
"#;

/// The household route's reviewed shaping script. A PostgreSQL row is flat,
/// so the route groups the size column under `household`, where the
/// projection's dotted path `household.household_size` reads it, the same
/// value shape the Kobo pack gives a grouped answer.
const HOUSEHOLD_SCRIPT: &str = r#"fn group_household(exchange) {
    let page = exchange.body;
    let items = [];
    for item in page.items {
        let value = item.value;
        let size = value.remove("household_size");
        value.household = #{household_size: size};
        item.value = value;
        items.push(item);
    }
    page.items = items;
    page
}
"#;

pub struct PostgresNativeSource {
    base_url: String,
    schema: String,
    secret_root: PathBuf,
}

impl PostgresNativeSource {
    pub async fn install(
        pack_path: &Path,
        job_path: &Path,
        runtime_path: &Path,
        direct_mapping: bool,
        target: &str,
    ) -> Self {
        Self::install_with_shape(
            pack_path,
            job_path,
            runtime_path,
            direct_mapping,
            target,
            false,
        )
        .await
    }

    pub async fn install_household(pack_path: &Path, job_path: &Path, runtime_path: &Path) -> Self {
        Self::install_with_shape(pack_path, job_path, runtime_path, false, "unused", true).await
    }

    async fn install_with_shape(
        pack_path: &Path,
        job_path: &Path,
        runtime_path: &Path,
        direct_mapping: bool,
        target: &str,
        household_shape: bool,
    ) -> Self {
        let base_url = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("ADAPTER_TEST_DATABASE_URL names an owned disposable PostgreSQL server");
        let config = Config::from_str(&base_url).expect("the disposable PostgreSQL URL parses");
        let host = match config.get_hosts().first() {
            Some(Host::Tcp(host)) if host == "localhost" => "127.0.0.1".to_owned(),
            Some(Host::Tcp(host)) => host.clone(),
            _ => panic!("the native PostgreSQL source uses a TCP host"),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        let database = config
            .get_dbname()
            .expect("the native PostgreSQL URL names a database")
            .to_owned();
        let user = config
            .get_user()
            .expect("the native PostgreSQL URL names a user")
            .to_owned();
        let password = config
            .get_password()
            .expect("the native PostgreSQL URL names a password");
        let schema = format!("adapter_native_source_{}", uuid::Uuid::new_v4().simple());
        let (admin, connection) = tokio_postgres::connect(&base_url, NoTls)
            .await
            .expect("connect the isolated native source");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the native source connection failed: {error}");
            }
        });
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; \
                 CREATE TABLE {schema}.submissions (\
                   external_id text PRIMARY KEY, label text NOT NULL, target text NOT NULL\
                 )"
            ))
            .await
            .expect("create the isolated native PostgreSQL source");
        admin
            .execute(
                &format!(
                    "INSERT INTO {schema}.submissions (external_id, label, target) \
                     VALUES ('a', '045', $1)"
                ),
                &[&target],
            )
            .await
            .expect("seed the isolated native PostgreSQL source");

        let root = pack_path
            .parent()
            .expect("the pack has an artifact directory")
            .to_path_buf();
        let query_directory = root.join("queries");
        std::fs::create_dir_all(&query_directory).expect("create the native query directory");
        let query = if household_shape {
            format!(
                "SELECT external_id AS id, external_id AS \"_id\", \
                 label AS respondent_name, 4::bigint AS household_size \
                 FROM {schema}.submissions ORDER BY external_id"
            )
        } else {
            format!(
                "SELECT external_id AS id, label, target \
                 FROM {schema}.submissions ORDER BY external_id"
            )
        };
        std::fs::write(query_directory.join("source.sql"), &query)
            .expect("write the reviewed native source query");
        let (shaping_step, shaping_scripts) = if household_shape {
            let script_directory = root.join("scripts");
            std::fs::create_dir_all(&script_directory).expect("create the native script directory");
            std::fs::write(script_directory.join("household.rhai"), HOUSEHOLD_SCRIPT)
                .expect("write the reviewed household shaping script");
            (
                "      - setBody:\n          rhai:\n            file: scripts/household.rhai\n            entrypoint: group_household\n"
                    .to_owned(),
                format!(
                    "scripts:\n  - path: scripts/household.rhai\n    digest: {}\n",
                    sha256_uri(HOUSEHOLD_SCRIPT.as_bytes())
                ),
            )
        } else {
            (String::new(), String::new())
        };
        let old_pack = std::fs::read(pack_path).expect("read the existing native fixture pack");
        let old_pack_digest = sha256_uri(&old_pack);
        let pack = format!(
            r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions: []
endpoints:
  - id: submissions
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 3000
    maximumResponseBytes: 65536
    queryFile: queries/source.sql
    keyColumn: id
queryFiles:
  - path: queries/source.sql
    digest: {}
sourceRoutes:
  - id: submissions-page
    scan: finite
    nextRecovery: key-deduplicated
    edits: rescan
    rescanDelaySeconds: 60
    steps:
      - to:
          uri: postgres:submissions
          parameters:
            queryParameters: {{}}
{shaping_step}{shaping_scripts}capabilities: {{}}
"#,
            sha256_uri(query.as_bytes())
        );
        std::fs::write(pack_path, &pack).expect("write the native PostgreSQL pack");
        let pack_digest = sha256_uri(pack.as_bytes());

        let mut job = std::fs::read_to_string(job_path).expect("read the native fixture job");
        job = job.replace(&old_pack_digest, &pack_digest);
        if !household_shape {
            job = job.replace("    - answers.age", "    - label");
            job = job.replace("    - answers.target", "    - target");
        }
        if direct_mapping {
            let mapping_path = root.join("mappings/direct-breg.rhai");
            let old_mapping = std::fs::read(&mapping_path).expect("read the native BReg mapping");
            let old_mapping_digest = sha256_uri(&old_mapping);
            std::fs::write(&mapping_path, DIRECT_MAPPING)
                .expect("write the native PostgreSQL BReg mapping");
            job = job.replace(&old_mapping_digest, &sha256_uri(DIRECT_MAPPING.as_bytes()));
        }
        std::fs::write(job_path, job).expect("write the native PostgreSQL job");

        let project_path = root.join("project.yaml");
        let project = std::fs::read_to_string(&project_path)
            .expect("read the native fixture project")
            .replace(&old_pack_digest, &pack_digest);
        std::fs::write(project_path, project).expect("write the native PostgreSQL project pin");

        let password_path = root.join("postgres-source-password");
        private_file(&password_path, password);
        let runtime = json!({
            "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
            "kind": "AdapterJobRuntimeConfig",
            "id": "native-postgres-destination",
            "endpoints": [],
            "sources": {"postgres": {"submissions": {
                "host": host,
                "port": port,
                "database": database,
                "user": user,
                "passwordRef": "secret:file/postgres-source-password",
                "namespace": "native-source",
                "tls": {"type": "plaintext"}
            }}},
            "secretProviders": {"file": {"root": root.display().to_string()}},
            "allowedPrivateCidrs": ["127.0.0.0/8"]
        });
        std::fs::write(
            runtime_path,
            serde_json::to_vec_pretty(&runtime).expect("render the native source runtime"),
        )
        .expect("write the native source runtime");

        Self {
            base_url,
            schema,
            secret_root: root,
        }
    }

    pub fn resolver(&self) -> SecretResolver {
        SecretResolver::new([SecretProvider::File], &self.secret_root)
            .expect("start the file-backed native source resolver")
    }

    pub async fn revise_label(&self) {
        let (client, connection) = tokio_postgres::connect(&self.base_url, NoTls)
            .await
            .expect("connect the isolated source for its reviewed edit");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the native source edit connection failed: {error}");
            }
        });
        client
            .execute(
                &format!(
                    "UPDATE {}.submissions SET label = '046' WHERE external_id = 'a'",
                    self.schema
                ),
                &[],
            )
            .await
            .expect("revise the isolated source row");
    }
}

pub async fn only_item_key(pool: &Pool) -> String {
    let client = pool.get().await.expect("an Adapter item-store client");
    client
        .query_one(
            "SELECT item_key FROM adapter_job_items WHERE job_id = 'case-daily'",
            &[],
        )
        .await
        .expect("read the one native source item key")
        .get(0)
}

pub async fn assert_no_payload_columns(pool: &Pool) {
    let client = pool.get().await.expect("an Adapter item-store client");
    let payload_columns: i64 = client
        .query_one(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'adapter_job_items' \
             AND data_type IN ('json', 'jsonb')",
            &[],
        )
        .await
        .expect("read the native item-table shape")
        .get(0);
    assert_eq!(payload_columns, 0, "the item store retains no payload");
}

fn private_file(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, contents).expect("write a private native fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("set private native fixture permissions");
}
