// SPDX-License-Identifier: Apache-2.0
use chrono::Utc;
use jsonwebtoken::Algorithm;
use registry_coordinator::{
    access::{Action, Authenticator, ClientPolicy},
    definition::Definition,
    deployment, project,
    runtime::RuntimeConfig,
};
use registry_platform_audit::FileDestination;
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    access_token_typ_set, DeclaredKinds, IssuerEntry, JwksFetcher, JwksFetcherConfig,
    TokenVerifier, TokenVerifierConfig,
};
use registry_platform_testing::{TestAuthorizationServerBuilder, TestClient};
use std::{fs, sync::Arc};

fn authenticator(
    profile: TokenVerifierConfig,
    keys: Arc<JwksFetcher>,
    policies: std::collections::BTreeMap<String, ClientPolicy>,
    assertion_issuers: bool,
) -> Authenticator {
    let scope_claim = profile.scope_claim.clone();
    let entry = IssuerEntry::new(
        "main",
        TokenVerifier::new(profile, keys),
        DeclaredKinds::None,
    );
    Authenticator::new(vec![(entry, scope_claim, assertion_issuers)], policies).unwrap()
}

#[test]
fn immutable_package_closure_tamper_and_abi_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let project_path = root_path.join("project");
    project::init(&project_path, Some("delayed-follow-up")).unwrap();
    let package_path = root_path.join("package");
    let digest = deployment::package(&project_path, &package_path).unwrap();
    assert!(deployment::package(&project_path, &package_path).is_err());
    let runtime = root_path.join("runtime.yaml");
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml")
        .replace(
            "/opt/registry-coordinator/package",
            package_path.to_str().unwrap(),
        )
        .replace(&format!("sha256:{}", "0".repeat(64)), &digest);
    fs::write(&runtime, template).unwrap();
    let config = RuntimeConfig::load(&runtime).unwrap();
    let d = deployment::config(&config).unwrap();
    let loaded = deployment::load_package(&d.packages[0]).unwrap();
    assert_eq!(loaded.digest, digest);
    fs::write(package_path.join("extra"), "secret-canary").unwrap();
    let error = deployment::load_package(&d.packages[0]).err().unwrap();
    assert!(!error.to_string().contains("secret-canary"));
    fs::remove_file(package_path.join("extra")).unwrap();
    fs::write(package_path.join("definition.json"), "{}").unwrap();
    assert!(deployment::load_package(&d.packages[0]).is_err());
}

#[test]
fn runtime_reads_the_explicit_http_issuer_opt_in_only_in_development() {
    let runtime_file = tempfile::NamedTempFile::new().unwrap();
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml")
        .replace(
            "issuer: https://issuer.example.org",
            "issuer: http://issuer.example.org\n        allowInsecureHttp: true",
        );
    assert_ne!(
        template,
        include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml")
    );
    fs::write(runtime_file.path(), template).unwrap();
    let path = runtime_file.path().canonicalize().unwrap();
    let error = RuntimeConfig::load(&path)
        .err()
        .expect("production refuses the opt-in");
    assert_eq!(error.code, "platform.posture.insecure-issuer-http");
    let development = registry_platform_config::declared_from(Some("development"), None).unwrap();
    let runtime = RuntimeConfig::load_with_posture(&path, development).unwrap();
    let authentication = runtime.deployment.unwrap().authentication;
    assert!(
        authentication
            .issuers
            .iter()
            .next()
            .unwrap()
            .1
            .core
            .provider
            .allow_insecure_http
    );
    assert!(serde_norway::to_string(&authentication)
        .unwrap()
        .contains("allowInsecureHttp: true"));
}

#[test]
fn a_remote_http_issuer_is_refused_without_the_opt_in() {
    let runtime_file = tempfile::NamedTempFile::new().unwrap();
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml")
        .replace(
            "issuer: https://issuer.example.org",
            "issuer: http://issuer.example.org",
        );
    fs::write(runtime_file.path(), template).unwrap();
    let error = RuntimeConfig::load(&runtime_file.path().canonicalize().unwrap())
        .err()
        .unwrap();
    assert_eq!(error.code, "coordinator.access.configuration");
    assert_eq!(
        error.field.as_deref(),
        Some("/deployment/authentication/issuers/main/issuer")
    );
    assert!(error
        .suggested_action
        .as_deref()
        .is_some_and(|action| action.contains("allowInsecureHttp: true")));
}
#[test]
fn unrelated_connection_and_signing_rotation_preserve_workflow_binding() {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let dir = root_path.join("flow");
    project::init(&dir, None).unwrap();
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
        .authorization_mut()
        .unwrap()
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
        .authorization_mut()
        .unwrap()
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
        FetchUrlPolicy::https_or_loopback(),
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
        subjects: vec!["actual-subject".into()],
        required_scopes: vec!["coordinator:start".into()],
        workflows: vec!["follow-up".into()],
        actions: Vec::from([Action::Start, Action::Status]),
        operator: false,
    };
    let auth = authenticator(verifier, keys, [("producer".into(), policy)].into(), false);
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
        let refusal = auth.authenticate(&token).await.err().unwrap();
        // Only a scope refusal declares values, and they come from the
        // configuration, never from the token.
        match refusal.declared_scope() {
            Some(declared) => {
                assert_eq!(scope, "wrong-scope");
                assert_eq!(declared.scope_claim(), "scope");
                assert_eq!(declared.required_scope(), Some("coordinator:start"));
                assert_eq!(declared.access_profile(), None);
            }
            None => assert_ne!(scope, "wrong-scope"),
        }
    }
    issuer.stop().await;
}

/// A policy admits only the exact token subjects it lists. A listed client
/// presenting a token for anyone else is refused like a scope mismatch, and
/// operator policies are pinned the same way.
#[tokio::test]
async fn a_policy_admits_only_the_subjects_it_lists() {
    let issuer = TestAuthorizationServerBuilder::default()
        .client(TestClient::new("producer"))
        .client(TestClient::new("operator"))
        .start()
        .await;
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::https_or_loopback(),
    ));
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec!["urn:coordinator:test".into()],
        vec![Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["producer".into(), "operator".into()]);
    let producer = ClientPolicy {
        subjects: vec!["producer-service-account".into()],
        required_scopes: vec!["coordinator:start".into()],
        workflows: vec!["follow-up".into()],
        actions: Vec::from([Action::Start, Action::Status]),
        operator: false,
    };
    let operator = ClientPolicy {
        subjects: vec!["operations-lead".into(), "on-call-operator".into()],
        required_scopes: vec!["coordinator:operate".into()],
        workflows: vec!["follow-up".into()],
        actions: Vec::from([Action::Status, Action::Inspect]),
        operator: true,
    };
    let auth = authenticator(
        verifier,
        keys,
        [("producer".into(), producer), ("operator".into(), operator)].into(),
        false,
    );
    for (client, subject, scope, admitted) in [
        (
            "producer",
            "producer-service-account",
            "coordinator:start",
            true,
        ),
        ("producer", "a-person", "coordinator:start", false),
        (
            "producer",
            "Producer-Service-Account",
            "coordinator:start",
            false,
        ),
        ("producer", "operations-lead", "coordinator:start", false),
        ("operator", "operations-lead", "coordinator:operate", true),
        ("operator", "a-person", "coordinator:operate", false),
        (
            "operator",
            "producer-service-account",
            "coordinator:operate",
            false,
        ),
    ] {
        let token = issuer.issue_access_token(
            client,
            subject,
            "urn:coordinator:test",
            scope,
            Utc::now().timestamp() + 300,
        );
        match auth.authenticate(&token).await {
            Ok(caller) => {
                assert!(admitted, "{client} / {subject} must be refused");
                assert_eq!(caller.actor.client_id, client);
                assert_eq!(caller.actor.subject, subject);
            }
            Err(error) => {
                assert!(!admitted, "{client} / {subject} must be admitted: {error}");
                assert_eq!(error.code, "access.denied", "{client} / {subject}");
            }
        }
    }
    issuer.stop().await;
}

/// A client assertion signed by hand, so the test can drive the token
/// endpoint's client credentials and token exchange grants directly. It names
/// the issuer identifier as its audience and carries the explicit type, as
/// RFC 10070 section 4 requires.
fn client_assertion(
    key: &registry_platform_crypto::PrivateJwk,
    client: &str,
    issuer: &str,
    jti: &str,
) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let now = Utc::now().timestamp();
    let header = serde_json::json!({
        "alg": key.algorithm().unwrap().jwa_name(), "kid": key.kid,
        "typ": "client-authentication+jwt"
    });
    let claims = serde_json::json!({
        "iss": client, "sub": client, "aud": issuer, "iat": now, "exp": now + 60, "jti": jti
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = registry_platform_crypto::sign(input.as_bytes(), key).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

async fn granted_access_token(endpoint: &str, form: &[(&str, &str)]) -> String {
    let response = reqwest::Client::new()
        .post(endpoint)
        .form(form)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

fn token_claims(token: &str) -> serde_json::Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// A delegated token names a person in `sub` and the exchanging service in
/// `act`. Admission refuses any token carrying `act`, even when its client,
/// scopes, assertion issuer and subject would all be admitted. A token
/// exchange without an actor keeps the service's own subject and no `act`,
/// so it is admitted like the service's own token.
#[tokio::test]
async fn a_token_carrying_act_is_refused_and_an_exchange_without_one_is_not() {
    use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
    const AUDIENCE: &str = "urn:coordinator:test";
    const SERVICE: &str = "producer-service-account";
    const PERSON: &str = "a-person";
    const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
    const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
    const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    let issuer = TestAuthorizationServerBuilder::default()
        .client(
            TestClient::new("producer")
                .with_public_jwk(key.public())
                .with_resource(AUDIENCE)
                .with_service_subject(SERVICE),
        )
        .start()
        .await;
    let endpoint = issuer.token_endpoint();
    let assertion_audience = issuer.issuer();
    let keys = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        issuer.jwks_uri(),
        JwksFetcherConfig::defaults(),
        FetchUrlPolicy::https_or_loopback(),
    ));
    let verifier = TokenVerifierConfig::access_token_profile(
        issuer.issuer(),
        vec![AUDIENCE.into()],
        vec![Algorithm::EdDSA],
        access_token_typ_set("at+jwt"),
    )
    .with_scope_claim("scope")
    .with_allowed_clients(vec!["producer".into()])
    .with_assertion_issuers([("producer".into(), vec![issuer.issuer()])].into());
    // The policy lists both subjects, so only `act` decides the refusal.
    let policy = ClientPolicy {
        subjects: vec![SERVICE.into(), PERSON.into()],
        required_scopes: vec!["coordinator:start".into()],
        workflows: vec!["follow-up".into()],
        actions: Vec::from([Action::Start, Action::Status]),
        operator: false,
    };
    let auth = authenticator(verifier, keys, [("producer".into(), policy)].into(), true);

    let own = client_assertion(&key, "producer", &assertion_audience, "own");
    let service = granted_access_token(
        &endpoint,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "producer"),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", &own),
            ("resource", AUDIENCE),
            ("scope", "coordinator:start"),
        ],
    )
    .await;
    assert_eq!(token_claims(&service)["sub"], SERVICE);
    let caller = auth.authenticate(&service).await.unwrap();
    assert_eq!(caller.actor.subject, SERVICE);

    let exchange = |subject_token: String, jti: &'static str, actor: Option<String>| {
        let assertion = client_assertion(&key, "producer", &assertion_audience, jti);
        let endpoint = endpoint.clone();
        async move {
            let mut form = vec![
                ("grant_type", TOKEN_EXCHANGE.to_owned()),
                ("client_id", "producer".to_owned()),
                ("client_assertion_type", JWT_BEARER.to_owned()),
                ("client_assertion", assertion),
                ("subject_token", subject_token),
                ("subject_token_type", ACCESS_TOKEN.to_owned()),
                ("resource", AUDIENCE.to_owned()),
            ];
            if let Some(actor) = actor {
                form.push(("actor_token", actor));
                form.push(("actor_token_type", ACCESS_TOKEN.to_owned()));
            }
            let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            granted_access_token(&endpoint, &form).await
        }
    };
    let expires = Utc::now().timestamp() + 300;

    // Delegated: the person is `sub`, the service is `act.sub`.
    let person =
        issuer.issue_access_token("producer", PERSON, AUDIENCE, "coordinator:start", expires);
    let delegated = exchange(person, "delegated", Some(service.clone())).await;
    let claims = token_claims(&delegated);
    assert_eq!(claims["sub"], PERSON);
    assert_eq!(claims["act"], serde_json::json!({"sub": SERVICE}));
    let error = auth
        .authenticate(&delegated)
        .await
        .err()
        .expect("a token carrying act is refused");
    assert_eq!(error.code, "access.denied");

    // Without an actor the exchanged token keeps the service subject.
    let subject =
        issuer.issue_access_token("producer", SERVICE, AUDIENCE, "coordinator:start", expires);
    let exchanged = exchange(subject, "service", None).await;
    let claims = token_claims(&exchanged);
    assert!(claims.get("act").is_none());
    assert_eq!(claims["registry_assertion_issuer"], issuer.issuer());
    let caller = auth.authenticate(&exchanged).await.unwrap();
    assert_eq!(caller.actor.subject, SERVICE);
    issuer.stop().await;
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

fn packaged_config(path: &std::path::Path, digest: &str) -> deployment::DeploymentConfig {
    let template = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml")
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
fn audit_file_offline_validation_matches_the_writer_path_contract() {
    let runtime_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        runtime_file.path(),
        include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml"),
    )
    .unwrap();
    let runtime = RuntimeConfig::load(&runtime_file.path().canonicalize().unwrap()).unwrap();
    let mut deployment = deployment::config(&runtime).unwrap().clone();

    for path in [
        "/var/lib/registry-coordinator/events.lock".into(),
        "/var/lib/registry-coordinator/events.seq".into(),
        "/var/lib/registry-coordinator/events.seq.tmp".into(),
        "/var/lib/registry-coordinator/events.torn".into(),
        "/var/lib/registry-coordinator/events.00000001".into(),
        format!("/var/lib/registry-coordinator/{}", "a".repeat(247)),
    ] {
        assert!(
            FileDestination::new(&path).is_err(),
            "writer accepted {path}"
        );
        deployment.audit_path = path.into();
        let error = deployment
            .validate(&runtime.secret_providers)
            .expect_err("offline validation must refuse every path the writer refuses");
        assert_eq!(error.field.as_deref(), Some("/deployment/auditFile"));
    }

    for path in [
        "/var/lib/registry-coordinator/events.jsonl",
        "/var/lib/registry-coordinator/events.locks",
        "/var/lib/registry-coordinator/.lock.jsonl",
    ] {
        FileDestination::new(path).expect("writer accepts ordinary file name");
        deployment.audit_path = path.into();
        deployment
            .validate(&runtime.secret_providers)
            .expect("offline validation accepts every permitted example");
    }
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
            deployment::load_package(&packaged_config(&output, digest).packages[0])
                .err()
                .unwrap()
                .code,
            "coordinator.definition.snapshot-limit"
        );
        panic!("package succeeded but its exact immutable snapshot cannot be loaded");
    }
    assert_eq!(
        result.unwrap_err().code,
        "coordinator.definition.snapshot-limit"
    );
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
    let loaded = deployment::load_package(&packaged_config(&output, &digest).packages[0]).unwrap();
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

#[test]
fn flows_are_keyed_by_workflow_id_with_an_order_independent_set_digest() {
    use registry_platform_config::PackageConfig;
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/coordinator/examples");
    let pin = |project: &std::path::Path, output: &str| {
        let path = root_path.join(output);
        let digest = deployment::package(project, &path).unwrap();
        PackageConfig {
            root: path,
            expected_digest: Some(digest),
        }
    };
    let delayed = pin(&examples.join("delayed-follow-up"), "delayed");
    let governed = pin(&examples.join("governed-action-follow-up"), "governed");
    let variant_project = root_path.join("variant");
    fs::create_dir(&variant_project).unwrap();
    for entry in fs::read_dir(examples.join("delayed-follow-up")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), variant_project.join(entry.file_name())).unwrap();
        }
    }
    let source = variant_project.join("functions.rhai");
    let text = fs::read_to_string(&source).unwrap();
    fs::write(
        &source,
        format!("{text}\n// a second package of the same flow\n"),
    )
    .unwrap();
    let variant = pin(&variant_project, "variant-package");

    let mut config = packaged_config(&delayed.root, delayed.expected_digest.as_deref().unwrap());
    config.packages = vec![delayed.clone(), governed.clone()];
    let flows = deployment::load_workflows(&config).unwrap();
    assert_eq!(flows.len(), 2);
    let ids: Vec<_> = flows.iter().map(|(flow, _)| flow.as_str()).collect();
    assert_eq!(ids, ["delayed-follow-up", "governed-action-follow-up"]);
    let package = flows.get("governed-action-follow-up").unwrap();
    assert_eq!(Some(&package.digest), governed.expected_digest.as_ref());
    assert_eq!(package.definition.workflow.id, "governed-action-follow-up");
    assert!(flows.get("unknown-flow").is_none());
    assert_eq!(
        flows.package_digests(),
        std::collections::BTreeMap::from([
            (
                "delayed-follow-up".to_owned(),
                delayed.expected_digest.clone().unwrap()
            ),
            (
                "governed-action-follow-up".to_owned(),
                governed.expected_digest.clone().unwrap()
            ),
        ])
    );
    assert_eq!(
        flows.digest(),
        deployment::workflows_digest(&config).unwrap()
    );

    config.packages = vec![governed.clone(), delayed.clone()];
    let reordered = deployment::load_workflows(&config).unwrap();
    assert_eq!(reordered.digest(), flows.digest());
    config.packages = vec![delayed.clone()];
    let single = deployment::load_workflows(&config).unwrap();
    assert_ne!(single.digest(), flows.digest());

    config.packages = vec![delayed, governed, variant];
    let error = deployment::load_workflows(&config).err().unwrap();
    assert_eq!(error.code, "coordinator.deployment.configuration");
    assert_eq!(error.field.as_deref(), Some("/deployment/packages/2"));
    assert!(error
        .suggested_action
        .as_deref()
        .unwrap()
        .contains("delayed-follow-up"));
}

#[tokio::test]
async fn runtime_authenticator_derives_exact_admission_from_policy_keys() {
    use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm};
    let issuer = TestAuthorizationServerBuilder::default()
        .with_signing_key(generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap())
        .client(TestClient::new("urn:client:producer.v1"))
        .client(TestClient::new("display-label"))
        .client(TestClient::new("urn:client:Producer.v1"))
        .start()
        .await;
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut document = registry_platform_yaml::Reader::new("runtime.yaml")
        .scan(include_bytes!(
            "../../../products/coordinator/examples/single-flow-runtime.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value();
    document["deployment"]["authentication"]["issuers"]["main"] = serde_json::json!({
        "issuer": issuer.issuer(),
        "audience": "urn:coordinator:test",
        "jwksSource": {"type":"uri", "uri":issuer.jwks_uri()},
        "allowedClients": "from-policies",
        "scopeClaim": "scope",
    });
    fs::write(file.path(), document.to_string()).unwrap();
    let mut runtime = RuntimeConfig::load(&file.path().canonicalize().unwrap()).unwrap();
    let access = &mut runtime.deployment.as_mut().unwrap().authentication;
    let mut policy = access.policies.remove("institution-producer").unwrap();
    policy.workflows = vec!["follow-up".into()];
    policy.subjects = vec!["actual-subject".into()];
    access.policies = [("urn:client:producer.v1".into(), policy)].into();
    let auth = access
        .authenticator(&runtime.secret_providers)
        .await
        .unwrap();
    for (client, scopes, permitted) in [
        ("urn:client:producer.v1", "coordinator:start", true),
        ("display-label", "coordinator:start", false),
        ("urn:client:Producer.v1", "coordinator:start", false),
        ("urn:client:producer.v1", "coordinator:operate", false),
    ] {
        let token = issuer.issue_access_token(
            client,
            "actual-subject",
            "urn:coordinator:test",
            scopes,
            Utc::now().timestamp() + 300,
        );
        let caller = auth.authenticate(&token).await;
        assert_eq!(caller.is_ok(), permitted, "{client} / {scopes}");
        if let Ok(caller) = caller {
            assert_eq!(caller.actor.client_id, "urn:client:producer.v1");
            caller.authorize(Action::Start, Some("follow-up")).unwrap();
            assert!(caller
                .authorize(Action::Start, Some("concealed-workflow"))
                .is_err());
            assert!(caller
                .authorize(Action::Inspect, Some("follow-up"))
                .is_err());
        }
    }
    issuer.stop().await;
}

#[test]
fn check_production_refuses_development_settings_and_conflicting_declarations() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("runtime.yaml");
    let contents = include_str!("../../../products/coordinator/examples/single-flow-runtime.yaml");
    let contents = contents.replace(
        "database:\n",
        "database:\n  transport: private-network-plaintext\n",
    );
    std::fs::write(&config, contents).unwrap();
    for (flags, environment, exit, code) in [
        (
            &["--posture", "development"][..],
            None,
            2,
            "platform.posture.conflict",
        ),
        (&[][..], Some("development"), 2, "platform.posture.conflict"),
        (
            &[][..],
            None,
            1,
            "platform.posture.database-private-plaintext",
        ),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_coordinatorctl"));
        command.env_remove("REGISTRY_STACK_POSTURE");
        if let Some(value) = environment {
            command.env("REGISTRY_STACK_POSTURE", value);
        }
        let output = command
            .args([
                "--format",
                "json",
                "check",
                "--production",
                "--runtime-config",
            ])
            .arg(&config)
            .args(flags)
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(exit), "{report}");
        assert!(
            report["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == code),
            "{report}"
        );
    }
}

#[test]
fn conflict_with_environment_names_the_production_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["--format", "json", "check", "--production"])
        .env("REGISTRY_STACK_POSTURE", "development")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["code"], "platform.posture.conflict",
        "{report}"
    );
    assert_eq!(
        report["diagnostics"][0]["message"],
        "--production and REGISTRY_STACK_POSTURE declare different postures",
        "{report}"
    );
}
