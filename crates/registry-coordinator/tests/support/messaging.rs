// SPDX-License-Identifier: Apache-2.0
//! An independently built Messaging service reached through its public HTTP
//! contract, with disposable PostgreSQL and a synthetic template. No delivery
//! claim is made; only authoritative acceptance and receipts are observed.

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use registry_platform_testing::TestAuthorizationServer;
use serde_json::json;

fn binary(variable: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| {
        panic!("{variable} must point to the independently built executable; run products/coordinator/scripts/test-postgres.sh")
    }));
    assert!(
        path.is_file(),
        "{variable} must name an existing executable"
    );
    path
}

fn operator(binary: &Path, arguments: &[&std::ffi::OsStr], log: &Path) {
    let output = Command::new(binary).args(arguments).output().unwrap();
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    super::private_file(log, &bytes);
    assert!(
        output.status.success(),
        "independent Messaging operator failed; inspect {}",
        log.display()
    );
}

pub struct Messaging {
    _root: tempfile::TempDir,
    pub base_url: String,
    pub admin: Arc<tokio_postgres::Client>,
    schema: String,
    child: Option<Child>,
}

impl Messaging {
    pub async fn start(issuer: &TestAuthorizationServer) -> Self {
        let ctl = binary("COORDINATOR_MESSAGINGCTL_BIN");
        let runtime_binary = binary("COORDINATOR_MESSAGING_BIN");
        let base = std::env::var("COORDINATOR_MESSAGING_TEST_DATABASE_URL").expect(
            "COORDINATOR_MESSAGING_TEST_DATABASE_URL must name a separate disposable database",
        );
        let schema = format!("poc_messaging_{}", uuid::Uuid::new_v4().simple());
        let mut database = url::Url::parse(&base).expect("disposable database URL");
        database
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let (admin, connection) = tokio_postgres::connect(database.as_str(), tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move {
            connection.await.unwrap();
        });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let project = root.path().join("project");
        let template = project.join("templates/application-follow-up/1");
        std::fs::create_dir_all(template.join("en")).unwrap();
        std::fs::write(project.join("messaging.yaml"), serde_norway::to_string(&json!({
            "apiVersion":"id.registrystack.org/formats/messaging/project/v1alpha1", "kind":"MessagingProject",
            "project":{"id":"coordinator-messaging", "version":"1"},
            "providers":[{"id":"mail-relay", "type":"smtp"}],
            "senderProfiles":[{"id":"transactional", "channel":"email", "provider":"mail-relay", "sender":"notices@example.invalid"}],
            "templates":[{"id":"application-follow-up", "version":"1"}],
            "accessProfiles":[{"id":"case-notices", "principalClaim":"sub", "requiredScopes":["messaging:send"],
                "requesterClients":["case-system"], "actorKind":"service", "role":"sender", "senderProfiles":["transactional"],
                "templates":["application-follow-up"], "requestsPerMinute":600, "burst":100}]
        })).unwrap()).unwrap();
        std::fs::write(
            template.join("template.yaml"),
            "apiVersion: id.registrystack.org/formats/messaging/template/v1alpha1\nkind: MessagingTemplate\nchannel: email\nlocales: [en]\nparts: [subject, text]\n",
        )
        .unwrap();
        std::fs::write(template.join("schema.json"), json!({"type":"object", "additionalProperties":false,
            "required":["applicationReference"], "properties":{"applicationReference":{"type":"string"}}}).to_string()).unwrap();
        std::fs::write(
            template.join("sample.json"),
            json!({"applicationReference":super::RECORD}).to_string(),
        )
        .unwrap();
        std::fs::write(template.join("en/subject.j2"), "Application follow-up").unwrap();
        std::fs::write(
            template.join("en/text.j2"),
            "Application {{ applicationReference }}",
        )
        .unwrap();
        let package = root.path().join("package");
        operator(
            &ctl,
            &[
                "package".as_ref(),
                project.as_os_str(),
                "--output".as_ref(),
                package.as_os_str(),
            ],
            &root.path().join("package.log"),
        );
        let jwks = reqwest::get(issuer.jwks_uri())
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        super::private_file(&root.path().join("jwks"), &jwks);
        super::private_file(&root.path().join("database"), database.as_str().as_bytes());
        super::private_file(
            &root.path().join("audit-key"),
            b"synthetic-audit-key-of-at-least-32-bytes",
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let path = root.path().join("messaging-runtime.yaml");
        std::fs::write(&path, serde_norway::to_string(&json!({
            "apiVersion":"id.registrystack.org/formats/messaging/runtime/v1alpha1", "kind":"MessagingRuntimeConfig",
            "identity":{"databaseId":"coordinator-messaging"}, "package":{"root":package},
            "listener":{"bind":address.to_string(), "tlsTermination":"development-loopback"},
            "secretProviders":{"file":{"root":root.path()}},
            "database":{"runtimeUrlRef":"secret:file/database", "migrationUrlRef":"secret:file/database", "testOnlyPlaintext":true},
            "authentication":{"oidc":{"issuer":issuer.issuer(), "audience":"urn:example:messaging",
                "jwksSource":{"kind":"static", "documentRef":"secret:file/jwks"}, "scopeClaim":"scope", "allowedClients":["case-system"]}},
            "audit":{"destination":"file", "path":root.path().join("audit/messaging.ndjson"), "hashKeyRef":"secret:file/audit-key"}
        })).unwrap()).unwrap();
        drop(listener);
        operator(
            &ctl,
            &[
                "apply".as_ref(),
                "--runtime-config".as_ref(),
                path.as_os_str(),
            ],
            &root.path().join("apply.log"),
        );
        let log_path = root.path().join("service.log");
        super::private_file(&log_path, b"");
        let log = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        let child = Command::new(runtime_binary)
            .arg("--runtime-config")
            .arg(&path)
            .arg("serve")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut service = Self {
            _root: root,
            base_url: format!("http://{address}"),
            admin: Arc::new(admin),
            schema,
            child: Some(child),
        };
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let stop = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                service
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "independent Messaging service exited; inspect {}",
                log_path.display()
            );
            if http
                .get(format!("{}/ready", service.base_url))
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .is_ok_and(|response| response.status() == reqwest::StatusCode::OK)
            {
                break;
            }
            assert!(
                Instant::now() < stop,
                "independent Messaging service did not become ready; inspect {}",
                log_path.display()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        service
    }

    pub async fn count(&self) -> i64 {
        self.admin
            .query_one("SELECT count(*) FROM messaging_messages", &[])
            .await
            .unwrap()
            .get(0)
    }

    pub async fn stop(mut self) {
        self.stop_child();
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

impl Messaging {
    fn stop_child(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Messaging {
    fn drop(&mut self) {
        self.stop_child();
    }
}
