// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

#[cfg(feature = "postgres-test")]
pub mod messaging;

use std::{collections::BTreeMap, path::Path};

use registry_coordinator::adapters::{
    AuthorizationConfig, ConnectionConfig, Product, RuntimeConfig,
};
use registry_platform_config::{
    EnvironmentSecretProviderConfig, FileSecretProviderConfig, SecretProvidersConfig,
    SecretReference,
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
use registry_platform_testing::{fixtures, TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use url::Url;

pub const RECORD: &str = "00000000-0000-4000-8000-000000000001";
pub const MESSAGE: &str = "00000000-0000-4000-8000-000000000002";
pub const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

pub async fn issuer() -> TestAuthorizationServer {
    let (_, public) = fixtures::ed25519_pair();
    TestAuthorizationServer::builder()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(
            TestClient::new("case-system")
                .with_public_jwk(public.clone())
                .with_resource("urn:example:messaging")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject("poc-sender"),
        )
        .client(
            TestClient::new("application-reader")
                .with_public_jwk(public)
                .with_resource("urn:example:applications")
                .with_actor_kind(TestActorKind::Service)
                .with_service_subject("poc-reader"),
        )
        .start()
        .await
}

pub fn private_file(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

pub fn config(
    root: &Path,
    issuer: &TestAuthorizationServer,
    breg: &str,
    messaging: &str,
) -> RuntimeConfig {
    private_file(
        &root.join("client-key"),
        fixtures::ED25519_PRIVATE_JWK.as_bytes(),
    );
    let authorization = |client: &str, resource: &str, scope: &str| AuthorizationConfig {
        token_endpoint: Url::parse(&issuer.token_endpoint()).unwrap(),
        client_assertion_audience: None,
        task_authority: None,
        client_id: client.to_owned(),
        signing_key_ref: SecretReference::parse("secret:file/client-key").unwrap(),
        resource: resource.to_owned(),
        scopes: vec![scope.to_owned()],
    };
    RuntimeConfig {
        deployment: None,
        secret_providers: SecretProvidersConfig {
            file: Some(FileSecretProviderConfig {
                root: root.to_path_buf(),
            }),
            environment: Some(EnvironmentSecretProviderConfig {}),
        },
        database: registry_platform_config::DatabaseConfig {
            runtime_url_ref: "secret:env/COORDINATOR_TEST_DATABASE_URL".into(),
            migration_url_ref: "secret:env/COORDINATOR_TEST_DATABASE_URL".into(),
            trusted_root_certificate_ref: None,
            test_only_plaintext: false,
        },
        namespace: format!("coordinator_{}", uuid::Uuid::new_v4().simple()),
        connections: BTreeMap::from([
            (
                "applications".to_owned(),
                ConnectionConfig {
                    observation_authorization: None,
                    product: Product::Breg,
                    base_url: Url::parse(breg).unwrap(),
                    authorization: authorization(
                        "application-reader",
                        "urn:example:applications",
                        "applications:read",
                    ),
                    profile: Some("follow-up-reader".to_owned()),
                },
            ),
            (
                "notices".to_owned(),
                ConnectionConfig {
                    observation_authorization: None,
                    product: Product::Messaging,
                    base_url: Url::parse(messaging).unwrap(),
                    authorization: authorization(
                        "case-system",
                        "urn:example:messaging",
                        "messaging:send",
                    ),
                    profile: None,
                },
            ),
        ]),
    }
}

pub fn write_runtime(path: &Path, config: &RuntimeConfig) {
    let value = config.document().unwrap();
    private_file(path, serde_norway::to_string(&value).unwrap().as_bytes());
}

pub fn record(allowed: bool, email: &str) -> Value {
    json!({"data": {"recordIdentifier": RECORD, "revisionIdentifier": "1",
        "domainData": {"noticeAllowed": allowed, "email": email}},
        "meta": {"registryIdentifier": "applications-registry", "datasetIdentifier": "applications", "entityTypeIdentifier": "application"}})
}

pub fn submission() -> Value {
    json!({"senderProfile":"transactional", "to":{"email":"person@example.invalid"},
        "template":{"id":"application-follow-up", "version":"1"}, "locale":"en",
        "data":{"applicationReference":RECORD}})
}

pub fn receipt() -> Value {
    json!({"id": MESSAGE, "status":"queued", "links":{"self":format!("/v1/messages/{MESSAGE}"), "cancel":format!("/v1/messages/{MESSAGE}/cancel")}})
}

pub fn project() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples/delayed-follow-up")
}
