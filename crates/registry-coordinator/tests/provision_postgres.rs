// SPDX-License-Identifier: Apache-2.0
//! `coordinatorctl provision` against a real server, then `apply` and the
//! service on what it created.
//!
//! `PROVISION_TEST_DATABASE_URL` names a disposable superuser URL
//! with `sslmode=verify-full` and `PROVISION_TEST_DATABASE_CA` the
//! PEM file the server certificate chains to: provisioning always uses
//! verified TLS, so the suite's plaintext database cannot serve it.
#![cfg(feature = "postgres-test")]
use chrono::Utc;
use registry_coordinator::{
    adapters::HttpAdapters,
    deployment,
    http::{self, HttpState},
    project,
    runtime::RuntimeConfig,
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_provision::test_support::{connect_verified, provision_test_env};
use registry_platform_testing::{TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command, sync::Arc};
use uuid::Uuid;

const DELAYED: &str = "delayed-follow-up";
const ADMIN_URL_VARIABLE: &str = "COORDINATOR_PROVISION_ADMIN_URL";

fn private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn yaml_value(text: &str, api_version: &str, kind: &str) -> Value {
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
    let versions = [ApiVersion::current(api_version)];
    let format = FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &versions,
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    Reader::new("fixture.yaml")
        .read(text.as_bytes(), &Expect::one(&format))
        .unwrap()
        .to_json_value()
}

fn ctl(runtime: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "--runtime-config"])
        .arg(runtime)
        .args(args)
        .output()
        .unwrap()
}

fn provision(runtime: &Path, admin_url: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "provision", "--runtime-config"])
        .arg(runtime)
        .args(["--admin-url-env", ADMIN_URL_VARIABLE])
        .env(ADMIN_URL_VARIABLE, admin_url)
        .output()
        .unwrap()
}

struct Names {
    migration: String,
    runtime: String,
    owner: String,
    database: String,
    namespace: String,
}

async fn drop_everything(admin: &tokio_postgres::Client, names: &Names) {
    for statement in [
        format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", names.database),
        format!("DROP ROLE IF EXISTS {}", names.runtime),
        format!("DROP ROLE IF EXISTS {}", names.migration),
        format!("DROP ROLE IF EXISTS {}", names.owner),
    ] {
        admin.batch_execute(&statement).await.unwrap();
    }
}

/// The administrator is a role that can only create roles and databases, the
/// way a managed server's admin is, never the server's superuser.
#[tokio::test]
async fn provision_then_apply_then_serve_with_a_namespace_schema() {
    let (superuser_url, ca_pem) = provision_test_env();
    let superuser = connect_verified(&superuser_url, &ca_pem, None).await;
    let suffix = Uuid::new_v4().simple().to_string()[..12].to_owned();
    let names = Names {
        migration: format!("coord_mig_{suffix}"),
        runtime: format!("coord_run_{suffix}"),
        owner: format!("coord_own_{suffix}"),
        database: format!("coord_db_{suffix}"),
        namespace: format!("coordinator_{suffix}"),
    };
    let owner_password = Uuid::new_v4().simple().to_string();
    superuser
        .batch_execute(&format!(
            "CREATE ROLE {} LOGIN CREATEROLE CREATEDB NOSUPERUSER PASSWORD '{owner_password}'",
            names.owner
        ))
        .await
        .unwrap();
    let outcome = tokio::spawn(run(
        superuser_url.clone(),
        ca_pem.clone(),
        owner_password,
        Names {
            migration: names.migration.clone(),
            runtime: names.runtime.clone(),
            owner: names.owner.clone(),
            database: names.database.clone(),
            namespace: names.namespace.clone(),
        },
    ))
    .await;
    drop_everything(&superuser, &names).await;
    outcome.unwrap();
}

async fn run(superuser_url: String, ca_pem: Vec<u8>, owner_password: String, names: Names) {
    let mut endpoint = url::Url::parse(&superuser_url).unwrap();
    let (host, port) = (
        endpoint.host_str().unwrap().to_owned(),
        endpoint.port().unwrap(),
    );
    endpoint.set_username(&names.owner).unwrap();
    endpoint.set_password(Some(&owner_password)).unwrap();
    let admin_url = endpoint.to_string();

    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project_path = root_path.join("project");
    project::init(&project_path, Some(DELAYED)).unwrap();
    let package_path = root_path.join("package");
    let digest = deployment::package(&project_path, &package_path).unwrap();
    let (migration_password, runtime_password) = (
        Uuid::new_v4().simple().to_string(),
        Uuid::new_v4().simple().to_string(),
    );
    private(
        &root_path.join("migration-url"),
        format!(
            "postgres://{}:{migration_password}@{host}:{port}/{}?sslmode=require",
            names.migration, names.database
        )
        .as_bytes(),
    );
    private(
        &root_path.join("runtime-url"),
        format!(
            "postgres://{}:{runtime_password}@{host}:{port}/{}?sslmode=require",
            names.runtime, names.database
        )
        .as_bytes(),
    );
    private(&root_path.join("ca.pem"), &ca_pem);
    for (name, byte) in [("state-key", 71), ("admission-key", 72), ("audit-key", 73)] {
        private(&root_path.join(name), &[byte; 32]);
    }
    for name in ["reader-jwk", "notices-jwk"] {
        private(
            &root_path.join(name),
            registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
        );
    }
    let issuer = TestAuthorizationServer::builder()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(TestClient::new("producer"))
        .start()
        .await;
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
    let mut doc = yaml_value(
        template,
        registry_coordinator::runtime::API_VERSION,
        registry_coordinator::runtime::KIND,
    );
    doc["namespace"] = json!(names.namespace);
    doc["secretProviders"]["file"]["root"] = json!(&root_path);
    doc["database"]["runtimeUrlRef"] = json!("secret:file/runtime-url");
    doc["database"]["migrationUrlRef"] = json!("secret:file/migration-url");
    doc["database"]["caBundleRef"] = json!("secret:file/ca.pem");
    let d = &mut doc["deployment"];
    d["databaseId"] = json!("provision-test");
    d["runtimeRole"] = json!(names.runtime);
    d["packages"] = json!([{"root":package_path,"expectedDigest":digest}]);
    d["listener"] = json!({"bind":"127.0.0.1:0","tlsTermination":"loopback-plaintext"});
    d["auditFile"] = json!(root_path.join("audit.jsonl"));
    d["stateKeys"] = json!({"1":{"keyRef":"secret:file/state-key"}});
    d["admissionKeyRef"] = json!("secret:file/admission-key");
    d["auditKeyRef"] = json!("secret:file/audit-key");
    d["authentication"] = json!({"issuer":issuer.issuer(),"audience":"urn:coordinator:test","scopeClaim":"scope","jwksSource":{"type":"uri","uri":issuer.jwks_uri()},"policies":{"producer":{"subjects":["owner-a"],"requiredScopes":["coordinator:start"],"workflows":[DELAYED],"actions":["start","status"]}}});
    let path = root_path.join("runtime.yaml");
    fs::write(&path, serde_norway::to_string(&doc).unwrap()).unwrap();

    // The first run creates both roles, the database and the grant that lets
    // `apply` create the namespace schema.
    let output = provision(&path, &admin_url);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}{stderr}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    let outcome = |report: &Value, step: &str| {
        report["statements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["step"] == step)
            .map(|s| s["outcome"].clone())
    };
    assert_eq!(outcome(&report, "role.migration"), Some("created".into()));
    assert_eq!(outcome(&report, "role.runtime"), Some("created".into()));
    assert_eq!(outcome(&report, "database.create"), Some("created".into()));
    assert!(
        outcome(&report, "database.grant-create").is_some(),
        "{stdout}"
    );
    assert_eq!(report["executed"], true);
    for secret in [
        migration_password.as_str(),
        runtime_password.as_str(),
        owner_password.as_str(),
        "postgres://",
    ] {
        assert!(
            !stdout.contains(secret) && !stderr.contains(secret),
            "the output leaked a secret"
        );
    }

    // A second run finds everything present.
    let output = provision(&path, &admin_url);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(outcome(&report, "database.create"), Some("present".into()));
    assert_eq!(outcome(&report, "role.runtime"), Some("present".into()));

    // `apply` creates the namespace schema as the migration role.
    let output = ctl(&path, &["apply"]);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The runtime role holds CONNECT on the database and nothing else there.
    let database_admin = connect_verified(&superuser_url, &ca_pem, Some(&names.database)).await;
    let schema_owner: String = database_admin
        .query_one(
            "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1",
            &[&names.namespace],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(schema_owner, names.migration);
    let (connect_privilege, create_privilege): (bool, bool) = {
        let row = database_admin
            .query_one(
                "SELECT has_database_privilege($1, $2, 'CONNECT'), has_database_privilege($1, $2, 'CREATE')",
                &[&names.runtime, &names.database],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert!(connect_privilege);
    assert!(!create_privilege);

    // The service runs as the runtime role and answers a route.
    let runtime = Arc::new(RuntimeConfig::load(&path).unwrap());
    let workflows =
        Arc::new(deployment::load_workflows(deployment::config(&runtime).unwrap()).unwrap());
    let store = deployment::open(&runtime, false).await.unwrap();
    // The serving check the service runs at startup and on every `/ready`.
    deployment::check_serving(&store, &runtime, workflows.digest())
        .await
        .unwrap();
    let authenticator = Arc::new(
        deployment::config(&runtime)
            .unwrap()
            .authentication
            .authenticator(&runtime.secret_providers)
            .await
            .unwrap(),
    );
    let state = HttpState {
        recovery_only: false,
        store,
        runtime: runtime.clone(),
        workflows,
        authenticator,
        adapters: Arc::new(HttpAdapters::new(&runtime).unwrap()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, http::router(state)).await.unwrap();
    });
    let token = issuer.issue_access_token(
        "producer",
        "owner-a",
        "urn:coordinator:test",
        "coordinator:start",
        Utc::now().timestamp() + 300,
    );
    let response = reqwest::Client::new()
        .get(format!("{origin}/v1/workflows/{DELAYED}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let contract: Value = response.json().await.unwrap();
    assert!(contract["workflowRevision"].is_string());
    server.abort();
}
