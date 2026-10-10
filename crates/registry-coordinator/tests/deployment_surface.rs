// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use jsonwebtoken::Algorithm;
use registry_coordinator::{
    access::{Action, Authenticator, ClientPolicy},
    definition::Definition,
    deployment, project,
    runtime::RuntimeConfig,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    access_token_typ_set, JwksFetcher, JwksFetcherConfig, TokenVerifierConfig,
};
use registry_platform_testing::{TestAuthorizationServerBuilder, TestClient};
use std::{fs, sync::Arc};

#[test]
fn immutable_package_closure_tamper_and_abi_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project_path = root_path.join("project");
    project::init(&project_path).unwrap();
    let package_path = root_path.join("package");
    let digest = deployment::package(&project_path, &package_path).unwrap();
    assert!(deployment::package(&project_path, &package_path).is_err());
    let runtime = root_path.join("runtime.yaml");
    let template = include_str!("../../../products/coordinator/examples/pilot-runtime.yaml")
        .replace(
            "/opt/registry-coordinator/package",
            package_path.to_str().unwrap(),
        )
        .replace(&format!("sha256:{}", "0".repeat(64)), &digest);
    fs::write(&runtime, template).unwrap();
    let config = RuntimeConfig::load(&runtime).unwrap();
    let d = deployment::config(&config).unwrap();
    let loaded = deployment::load_package(d).unwrap();
    assert_eq!(loaded.digest, digest);
    fs::write(package_path.join("extra"), "secret-canary").unwrap();
    let error = deployment::load_package(d).err().unwrap();
    assert!(!error.to_string().contains("secret-canary"));
    fs::remove_file(package_path.join("extra")).unwrap();
    fs::write(package_path.join("definition.json"), "{}").unwrap();
    assert!(deployment::load_package(d).is_err());
}
#[test]
fn unrelated_connection_and_signing_rotation_preserve_workflow_binding() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let dir = root_path.join("flow");
    project::init(&dir).unwrap();
    let definition = Definition::load(&dir).unwrap();
    let mut runtime = RuntimeConfig::load(&dir.join("runtime.yaml")).unwrap();
    let original = runtime.binding_digest_for(&definition.workflow).unwrap();
    runtime
        .connections
        .insert("unrelated".into(), runtime.connections["notices"].clone());
    assert_eq!(
        original,
        runtime.binding_digest_for(&definition.workflow).unwrap()
    );
    runtime
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .signing_key_ref =
        registry_platform_config::SecretReference::parse("secret:file/rotated-key").unwrap();
    assert_eq!(
        original,
        runtime.binding_digest_for(&definition.workflow).unwrap()
    );
    runtime
        .connections
        .get_mut("notices")
        .unwrap()
        .authorization
        .client_id = "changed-identity".into();
    assert_ne!(
        original,
        runtime.binding_digest_for(&definition.workflow).unwrap()
    );
}
#[tokio::test]
async fn verified_subject_owns_runs_and_exact_policy_restricts_flow_action() {
    let issuer = TestAuthorizationServerBuilder::default()
        .client(TestClient::new("producer"))
        .client(TestClient::new("stranger"))
        .start()
        .await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::dev(),
    ));
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec!["urn:coordinator:test".into()],
        vec![Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["producer".into()]);
    let policy = ClientPolicy {
        client_id: "producer".into(),
        required_scopes: vec!["coordinator:start".into()],
        flows: vec!["follow-up".into()],
        actions: Vec::from([Action::Start, Action::Status]),
        operator: false,
    };
    let auth = Authenticator::new(verifier, keys, vec![policy], false);
    let token = issuer.issue_access_token(
        "producer",
        "actual-subject",
        "urn:coordinator:test",
        "coordinator:start",
        Utc::now().timestamp() + 300,
    );
    let caller = auth.authenticate(&token).await.unwrap();
    assert_eq!(caller.actor.issuer, issuer.issuer());
    assert_eq!(caller.actor.subject, "actual-subject");
    assert!(!caller.actor.operator);
    caller.authorize(Action::Start, Some("follow-up")).unwrap();
    assert!(caller.authorize(Action::Start, Some("other-flow")).is_err());
    assert!(caller
        .authorize(Action::RetrySame, Some("follow-up"))
        .is_err());
    for (client, resource, scope) in [
        ("stranger", "urn:coordinator:test", "coordinator:start"),
        ("producer", "urn:other", "coordinator:start"),
        ("producer", "urn:coordinator:test", "wrong-scope"),
    ] {
        let token = issuer.issue_access_token(
            client,
            "actual-subject",
            resource,
            scope,
            Utc::now().timestamp() + 300,
        );
        assert!(auth.authenticate(&token).await.is_err());
    }
    issuer.stop().await;
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

fn packaged_config(path: &std::path::Path, digest: &str) -> deployment::DeploymentConfig {
    let template = include_str!("../../../products/coordinator/examples/pilot-runtime.yaml")
        .replace(
            "/opt/registry-coordinator/package",
            path.canonicalize().unwrap().to_str().unwrap(),
        )
        .replace(&format!("sha256:{}", "0".repeat(64)), digest);
    let runtime_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(runtime_file.path(), template).unwrap();
    let config = RuntimeConfig::load(&runtime_file.path().canonicalize().unwrap()).unwrap();
    deployment::config(&config).unwrap().clone()
}

#[test]
fn oversized_authored_snapshot_cannot_write_a_successful_unloadable_package() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND + 1);
    let output = root.path().join("package");
    let result = deployment::package(&project, &output);
    if let Ok(digest) = &result {
        let snapshot = fs::read_to_string(output.join("definition.json")).unwrap();
        assert_eq!(snapshot.len(), snapshot_boundary::SNAPSHOT_BOUND + 1);
        assert_eq!(
            Definition::from_snapshot(&snapshot).err().unwrap().code,
            "coordinator.definition.snapshot-limit"
        );
        assert_eq!(
            deployment::load_package(&packaged_config(&output, digest))
                .err()
                .unwrap()
                .code,
            "coordinator.definition.snapshot-limit"
        );
        panic!("package succeeded but its exact immutable snapshot cannot be loaded");
    }
    assert_eq!(result.unwrap_err().code, "coordinator.definition.snapshot-limit");
    assert!(
        !output.exists(),
        "refused package must not leave an artifact"
    );
}

#[test]
fn exact_snapshot_boundary_package_roundtrips_with_shared_integrity_verification() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND);
    let definition = Definition::load(&project).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let output = root.path().join("package");
    let digest = deployment::package(&project, &output).unwrap();
    assert_eq!(
        fs::read_to_string(output.join("definition.json")).unwrap(),
        snapshot
    );
    let loaded = deployment::load_package(&packaged_config(&output, &digest)).unwrap();
    assert_eq!(loaded.digest, digest);
    assert_eq!(loaded.definition.digest, definition.digest);
    assert_eq!(loaded.definition.snapshot().unwrap(), snapshot);
    assert_eq!(
        loaded
            .definition
            .evaluate("select", &serde_json::Value::Null, &Default::default())
            .unwrap(),
        "one"
    );
}
