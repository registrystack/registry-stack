// SPDX-License-Identifier: Apache-2.0
//! `caseworkctl provision`: print mode, usage refusals, and, with a disposable
//! server, provisioning as a non-superuser owner then apply then serve.

#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests write only their own synthetic project and secrets"
)]

use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const MIGRATION_PASSWORD: &str = "migration-password-canary-0123456789";
const RUNTIME_PASSWORD: &str = "runtime-password-canary-0123456789";

fn ctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .args(arguments)
        .env_remove("RSTACK_GENERATION_DIR")
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .expect("caseworkctl starts")
}

fn ctl_ok(arguments: &[&str]) -> Value {
    let output = ctl(&[&["--format", "json"], arguments].concat());
    assert!(
        output.status.success(),
        "caseworkctl {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("a typed JSON report")
}

fn secret(path: &Path, value: &str) {
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// One synthetic deployment: an authored project, its package, a secret root
/// and a runtime file whose two database URLs name the given roles.
struct Deployment {
    _root: tempfile::TempDir,
    #[cfg_attr(not(feature = "postgres-test"), allow(dead_code))]
    root: PathBuf,
    runtime: PathBuf,
}

struct DatabaseUrls<'a> {
    migration: &'a str,
    runtime: &'a str,
    ca_pem: Option<&'a Path>,
    plaintext: bool,
    bind: &'a str,
}

fn deployment(urls: &DatabaseUrls<'_>) -> Deployment {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let project = root.join("project");
    ctl_ok(&[
        "init",
        project.to_str().unwrap(),
        "--template",
        "standalone-decision",
    ]);
    let package = root.join("package");
    ctl_ok(&[
        "package",
        project.to_str().unwrap(),
        "--output",
        package.to_str().unwrap(),
    ]);
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700)).unwrap();
    secret(&secrets.join("migration-url"), urls.migration);
    secret(&secrets.join("runtime-url"), urls.runtime);
    secret(
        &secrets.join("audit-key"),
        "provision-test-audit-key-canary-0123456789",
    );
    // The issuer's public key is read from a secret, so serving needs no network.
    secret(
        &secrets.join("jwks"),
        r#"{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"provision-test","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#,
    );
    let mut database = json!({
        "runtimeUrlRef":"secret:file/runtime-url",
        "migrationUrlRef":"secret:file/migration-url",
    });
    if let Some(ca) = urls.ca_pem {
        secret(&secrets.join("ca"), &fs::read_to_string(ca).unwrap());
        database["caBundleRef"] = json!("secret:file/ca");
    }
    if urls.plaintext {
        database["testOnlyPlaintext"] = json!(true);
    }
    let config = json!({
        "apiVersion":registry_casework::RUNTIME_CONFIG_API_VERSION,"kind":registry_casework::RUNTIME_CONFIG_KIND,
        "identity":{"databaseId":"provision-test"},"package":{"root":package},
        "listener":{"bind":urls.bind,"tlsTermination":"loopback-plaintext","networkExposure":"private-address"},
        "secretProviders":{"file":{"root":secrets}},
        "database":database,
        "authentication":{"oidc":{"issuers":{"main":{"issuer":"https://identity.example.test","audience":"urn:example:casework",
            "jwksSource":{"type":"static","documentRef":"secret:file/jwks"},
            "allowedClients":["provision-test"]}}}},
        "audit":{"path":root.join("audit.ndjson"),"hashKeyRef":"secret:file/audit-key"}
    });
    let runtime = root.join("runtime.yaml");
    fs::write(&runtime, serde_norway::to_string(&config).unwrap()).unwrap();
    Deployment {
        _root: temporary,
        root,
        runtime,
    }
}

fn offline_urls() -> (String, String) {
    (
        format!("postgresql://cw_migration:{MIGRATION_PASSWORD}@db.example.test:5432/casework_db"),
        format!("postgresql://cw_runtime:{RUNTIME_PASSWORD}@db.example.test:5432/casework_db"),
    )
}

#[test]
fn print_sql_connects_to_nothing_and_prints_no_password() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    let output = ctl(&[
        "provision",
        "--runtime-config",
        deployment.runtime.to_str().unwrap(),
        "--print-sql",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let script = String::from_utf8(output.stdout).unwrap();
    for expected in ["cw_migration", "cw_runtime", "casework_db", "CREATE ROLE"] {
        assert!(script.contains(expected), "script lacks {expected}");
    }
    for private in [
        MIGRATION_PASSWORD,
        RUNTIME_PASSWORD,
        "db.example.test",
        "postgresql://",
    ] {
        assert!(!script.contains(private), "script leaks {private}");
    }
    assert!(!String::from_utf8_lossy(&output.stderr).contains(MIGRATION_PASSWORD));
}

#[test]
fn print_sql_with_a_global_json_format_reports_without_executing() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        deployment.runtime.to_str().unwrap(),
        "--print-sql",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    let report: Value = serde_json::from_str(&text).expect("a JSON report on stdout");
    assert_eq!(report["command"], "provision");
    assert_eq!(report["product"], "casework");
    assert_eq!(report["executed"], false);
    assert_eq!(report["migrationRole"], "cw_migration");
    assert_eq!(report["runtimeRole"], "cw_runtime");
    assert!(!text.contains(MIGRATION_PASSWORD) && !text.contains(RUNTIME_PASSWORD));
}

/// Runs `provision --print-sql` with a JSON report and returns the exit code,
/// the report, and everything the command wrote, for a leak check.
fn refused_print(runtime: &Path) -> (Option<i32>, Value, String) {
    let output = ctl(&[
        "--format",
        "json",
        "provision",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "--print-sql",
    ]);
    let written = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("a JSON report on stdout: {written}"));
    (output.status.code(), report, written)
}

fn assert_loader_refusal(
    (code, report, written): &(Option<i32>, Value, String),
    diagnostic_code: &str,
    pointer: &str,
) {
    assert_eq!(*code, Some(1), "{written}");
    assert_eq!(report["ok"], false, "{written}");
    assert_eq!(
        report["diagnostics"][0]["code"], diagnostic_code,
        "{written}"
    );
    let location = report["diagnostics"][0]["path"]
        .as_str()
        .unwrap_or_default();
    assert!(location.ends_with(pointer), "{location} in {written}");
    for private in [MIGRATION_PASSWORD, RUNTIME_PASSWORD, "postgresql://"] {
        assert!(!written.contains(private), "the refusal leaks {private}");
    }
}

#[test]
fn a_missing_runtime_url_secret_is_refused_without_printing_a_password() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    fs::remove_file(deployment.root.join("secrets/runtime-url")).unwrap();
    assert_loader_refusal(
        &refused_print(&deployment.runtime),
        "casework.runtime.secret-unavailable",
        "/database/runtimeUrlRef",
    );
}

#[test]
fn a_missing_migration_url_secret_is_refused_without_printing_a_password() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    fs::remove_file(deployment.root.join("secrets/migration-url")).unwrap();
    assert_loader_refusal(
        &refused_print(&deployment.runtime),
        "casework.runtime.secret-unavailable",
        "/database/migrationUrlRef",
    );
}

#[test]
fn a_runtime_url_secret_that_is_not_text_is_refused() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    let file = deployment.root.join("secrets/runtime-url");
    fs::write(&file, [0xff, 0xfe, 0xfd]).unwrap();
    assert_loader_refusal(
        &refused_print(&deployment.runtime),
        "casework.runtime.secret-unavailable",
        "/database/runtimeUrlRef",
    );
}

#[test]
fn a_missing_ca_bundle_secret_is_refused() {
    let (migration, runtime) = offline_urls();
    let ca = tempfile::NamedTempFile::new().unwrap();
    fs::write(ca.path(), "not a bundle, never parsed here").unwrap();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: Some(ca.path()),
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    fs::remove_file(deployment.root.join("secrets/ca")).unwrap();
    assert_loader_refusal(
        &refused_print(&deployment.runtime),
        "casework.runtime.secret-unavailable",
        "/database/caBundleRef",
    );
}

#[test]
fn a_runtime_file_that_does_not_load_is_refused_with_its_own_code() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    fs::write(&deployment.runtime, "kind: NotARuntimeConfig\n").unwrap();
    let (code, report, written) = refused_print(&deployment.runtime);
    assert_eq!(code, Some(1), "{written}");
    assert_eq!(report["ok"], false, "{written}");
    assert_eq!(
        report["diagnostics"][0]["code"], "config.missing-envelope",
        "{written}"
    );
}

#[test]
fn both_administrator_flags_are_a_usage_error() {
    let output = ctl(&[
        "provision",
        "--runtime-config",
        "/nonexistent/runtime.yaml",
        "--admin-url-file",
        "/nonexistent/admin-url",
        "--admin-url-env",
        "UNUSED_ADMIN_URL",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let output = ctl(&[
        "provision",
        "--runtime-config",
        "/nonexistent/runtime.yaml",
        "--print-sql",
        "--admin-url-env",
        "UNUSED_ADMIN_URL",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let output = ctl(&["provision", "--runtime-config", "/nonexistent/runtime.yaml"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an administrator flag is required unless --print-sql is given"
    );
}

#[cfg(feature = "postgres-test")]
mod served {
    use super::*;
    use registry_platform_provision::test_support::{connect_verified, provision_test_env};
    use std::io::{Read as _, Write as _};
    use uuid::Uuid;

    fn required(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("the postgres-test feature needs {name}"))
    }

    fn hex(length: usize) -> String {
        Uuid::new_v4().simple().to_string()[..length].to_owned()
    }

    /// Drops the database and roles a test created, even after a failure.
    struct Cleanup {
        superuser_url: String,
        ca_pem: Vec<u8>,
        database: String,
        roles: Vec<String>,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let (url, ca_pem, database, roles) = (
                self.superuser_url.clone(),
                self.ca_pem.clone(),
                self.database.clone(),
                self.roles.clone(),
            );
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let client = connect_verified(&url, &ca_pem, None).await;
                        client
                            .batch_execute(&format!(
                                "DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"
                            ))
                            .await
                            .expect("drop database");
                        for role in roles {
                            client
                                .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                                .await
                                .expect("drop role");
                        }
                    });
            })
            .join()
            .expect("cleanup thread");
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn get_status(address: &str, path: &str) -> std::io::Result<String> {
        let mut stream = std::net::TcpStream::connect(address)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response.lines().next().unwrap_or_default().to_owned())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn provision_then_apply_then_serve_with_split_roles() {
        let (superuser_url, ca_pem) = provision_test_env();
        let ca_path = PathBuf::from(required("PROVISION_TEST_DATABASE_CA"));
        let server = registry_platform_provision::admin_config(&superuser_url, Some(&ca_pem))
            .expect("PROVISION_TEST_DATABASE_URL is a valid administrator URL");
        let (host, port) = (server.host().to_owned(), server.port());

        let suffix = hex(12);
        let (owner, migration, runtime, database) = (
            format!("cw_owner_{suffix}"),
            format!("cw_mig_{suffix}"),
            format!("cw_run_{suffix}"),
            format!("cw_db_{suffix}"),
        );
        let owner_password = hex(24);
        let _cleanup = Cleanup {
            superuser_url: superuser_url.clone(),
            ca_pem: ca_pem.clone(),
            database: database.clone(),
            roles: vec![runtime.clone(), migration.clone(), owner.clone()],
        };
        let admin = connect_verified(&superuser_url, &ca_pem, None).await;
        admin
            .batch_execute(&format!(
                "CREATE ROLE \"{owner}\" LOGIN CREATEROLE CREATEDB NOSUPERUSER PASSWORD '{owner_password}'"
            ))
            .await
            .unwrap();

        let bind = format!("127.0.0.1:{}", free_port());
        let endpoint = format!("{host}:{port}/{database}");
        let migration_url = format!("postgresql://{migration}:{MIGRATION_PASSWORD}@{endpoint}");
        let runtime_url = format!("postgresql://{runtime}:{RUNTIME_PASSWORD}@{endpoint}");
        let deployment = deployment(&DatabaseUrls {
            migration: &migration_url,
            runtime: &runtime_url,
            ca_pem: Some(&ca_path),
            plaintext: false,
            bind: &bind,
        });
        let admin_file = deployment.root.join("admin-url");
        secret(
            &admin_file,
            &format!(
                "postgresql://{owner}:{owner_password}@{host}:{port}/postgres?sslmode=verify-full"
            ),
        );
        let runtime_file = deployment.runtime.to_str().unwrap();

        let provisioned = Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
            .args(["--format", "json", "provision", "--runtime-config"])
            .arg(runtime_file)
            .arg("--admin-url-file")
            .arg(&admin_file)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&provisioned.stdout).into_owned();
        assert_eq!(
            provisioned.status.code(),
            Some(0),
            "provision refused: {text} {}",
            String::from_utf8_lossy(&provisioned.stderr)
        );
        let report: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["status"], "complete");
        assert_eq!(report["roleMode"], "split");
        for private in [
            MIGRATION_PASSWORD,
            RUNTIME_PASSWORD,
            owner_password.as_str(),
        ] {
            assert!(!text.contains(private), "the report leaks a password");
        }

        // Apply records single-role mode and still succeeds, so only these
        // fields show that provisioning left the two roles split.
        let applied = ctl_ok(&["apply", "--runtime-config", runtime_file]);
        assert_eq!(applied["ok"], true, "{applied}");
        assert!(
            applied["singleRoleStatement"].is_null(),
            "apply recorded single-role mode: {applied}"
        );
        assert_eq!(applied["activation"]["roleMode"], "split", "{applied}");
        let status = ctl_ok(&["status", "--runtime-config", runtime_file]);
        assert_eq!(status["ok"], true, "{status}");
        assert!(
            status["singleRoleStatement"].is_null(),
            "status reports single-role mode: {status}"
        );
        assert_eq!(status["activation"]["roleMode"], "split", "{status}");

        // A second provision finds everything present and creates nothing.
        let again = ctl_ok(&[
            "provision",
            "--runtime-config",
            runtime_file,
            "--admin-url-file",
            admin_file.to_str().unwrap(),
        ]);
        assert_eq!(again["status"], "complete");
        assert!(
            again["statements"]
                .as_array()
                .unwrap()
                .iter()
                .all(|statement| statement["outcome"] != "created"),
            "{again}"
        );

        let server_task = tokio::spawn({
            let runtime = deployment.runtime.clone();
            async move {
                registry_casework::serve_from_path(
                    runtime,
                    registry_platform_config::DeclaredPosture {
                        posture: registry_platform_config::Posture::Production,
                        source: registry_platform_config::PostureSource::Flag,
                    },
                )
                .await
            }
        });
        let mut answer = String::new();
        for _ in 0..100 {
            assert!(
                !server_task.is_finished(),
                "the runtime stopped: {:?}",
                server_task.await
            );
            let probe_address = bind.clone();
            answer = tokio::task::spawn_blocking(move || get_status(&probe_address, "/ready"))
                .await
                .unwrap()
                .unwrap_or_default();
            if answer.contains("200") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        server_task.abort();
        assert!(
            answer.contains("200"),
            "the runtime role serves /ready after provision and apply: {answer:?}"
        );
    }
}

#[test]
fn print_sql_requires_development_for_unrestricted_clients() {
    let (migration, runtime) = offline_urls();
    let deployment = deployment(&DatabaseUrls {
        migration: &migration,
        runtime: &runtime,
        ca_pem: None,
        plaintext: false,
        bind: "127.0.0.1:8100",
    });
    let contents = fs::read_to_string(&deployment.runtime).unwrap();
    let contents: Value = registry_platform_yaml::Reader::new("runtime.yaml")
        .scan(contents.as_bytes())
        .unwrap()
        .unwrap()
        .to_json_value();
    let mut contents = contents;
    contents["authentication"]["oidc"]["issuers"]["main"]["allowedClients"] = json!("unrestricted");
    fs::write(
        &deployment.runtime,
        serde_norway::to_string(&contents).unwrap(),
    )
    .unwrap();
    let (exit, report, _) = refused_print(&deployment.runtime);
    assert_eq!(exit, Some(1));
    assert_eq!(
        report["diagnostics"][0]["code"],
        "casework.posture.unrestricted-clients"
    );
    let output = ctl(&[
        "provision",
        "--runtime-config",
        deployment.runtime.to_str().unwrap(),
        "--print-sql",
        "--posture",
        "development",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
