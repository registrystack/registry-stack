// SPDX-License-Identifier: Apache-2.0
//! Production caller refusals through the Coordinator router.
//! Set REGISTRY_COORDINATOR_WRITE_GOLDEN=1 to write the observed answers.
#![cfg(feature = "postgres-test")]

use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use registry_coordinator::{
    deployment,
    http::{self, HttpState},
    protocol::{AdapterSet, CallOutcome, CallRequest},
    runtime::RuntimeConfig,
    store::Store,
};
use registry_platform_oidc::ASSERTION_ISSUER_CLAIM;
use registry_platform_testing::{Binding, ClaimValue, FixtureHeader, TokenCorpus, TokenSigner};
use serde_json::{json, Map, Value};
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "urn:coordinator:refusal";
const CLIENT: &str = "institution-producer";
const SUBJECT: &str = "institution-producer-service-account";

struct NoAdapters;

#[async_trait::async_trait]
impl AdapterSet for NoAdapters {
    fn binding_digest(&self) -> &str {
        "refusal-golden"
    }

    async fn call(&self, _: &CallRequest) -> CallOutcome {
        panic!("a refused request must not call an adapter");
    }
}

async fn router(root: &Path, database: &str, signer: &TokenSigner) -> Router {
    let mut public_keys = signer.public_key_set();
    public_keys["keys"]
        .as_array_mut()
        .unwrap()
        .retain(|key| key["kty"] != "OKP");
    let key_file = root.join("keys.json");
    fs::write(&key_file, public_keys.to_string()).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();

    let examples =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/coordinator/examples");
    let package = root.join("package");
    let digest = deployment::package(&examples.join("delayed-follow-up"), &package).unwrap();
    let mut document = registry_platform_yaml::Reader::new("runtime.yaml")
        .scan(&fs::read(examples.join("single-flow-runtime.yaml")).unwrap())
        .unwrap()
        .unwrap()
        .to_json_value();
    document["secretProviders"]["file"]["root"] = json!(root);
    let deployment = &mut document["deployment"];
    deployment["packages"] = json!([{"root": package, "expectedDigest": digest}]);
    let auth = &mut deployment["authentication"];
    auth.as_object_mut()
        .unwrap()
        .retain(|key, _| key == "policies");
    auth["issuers"] = json!({"main": {
        "issuer": ISSUER, "audience": AUDIENCE,
        "jwksSource": {"type":"static", "documentRef":"secret:file/keys.json"},
        "allowedClients": "from-policies", "scopeClaim": "scope",
    }});
    auth["policies"][CLIENT]["actions"] = json!(["status"]);

    let runtime_file = root.join("runtime.yaml");
    fs::write(&runtime_file, document.to_string()).unwrap();
    let runtime = RuntimeConfig::load(&runtime_file).unwrap();
    let config = deployment::config(&runtime).unwrap();
    let workflows = deployment::load_workflows(config).unwrap();
    let authenticator = config
        .authentication
        .authenticator(&runtime.secret_providers)
        .await
        .unwrap();
    let store = Store::connect(database, "coordinator_refusal_golden")
        .await
        .unwrap();
    http::router(HttpState {
        store: Arc::new(store),
        recovery_only: false,
        workflows: Arc::new(workflows),
        authenticator: Arc::new(authenticator),
        adapters: Arc::new(NoAdapters),
        runtime: Arc::new(runtime),
    })
}

async fn answer(app: &Router, credential: Option<&str>, expected_status: StatusCode) -> Value {
    let mut request = Request::post("/v1/runs")
        .header("content-type", "application/json")
        .header(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        );
    if let Some(value) = credential {
        request = request.header("authorization", value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    assert_eq!(parts.status, expected_status);
    let headers: Map<String, Value> = parts
        .headers
        .iter()
        .filter(|(name, _)| name.as_str() != "traceparent")
        .map(|(name, value)| (name.to_string(), json!(value.to_str().unwrap())))
        .collect();
    let mut body: Value = serde_json::from_slice(&to_bytes(body, 65_536).await.unwrap()).unwrap();
    assert!(body.as_object_mut().unwrap().remove("traceId").is_some());
    json!({"status": parts.status.as_u16(), "headers": headers, "body": body})
}

#[tokio::test]
async fn production_caller_refusals_match_the_golden() {
    let database = std::env::var("COORDINATOR_TEST_DATABASE_URL")
        .expect("set COORDINATOR_TEST_DATABASE_URL to a disposable PostgreSQL 17 database");
    let root = tempfile::tempdir().unwrap();
    let signer = TokenSigner::new();
    let other_signer = TokenSigner::new();
    let app = router(root.path(), &database, &signer).await;

    let corpus = TokenCorpus::load().unwrap();
    let mut fixture = corpus
        .fixture("keycloak-client-credentials")
        .unwrap()
        .clone();
    fixture.header = Some(FixtureHeader {
        alg: "RS256".into(),
        typ: Some("at+jwt".into()),
    });
    for (claim, value) in [
        ("azp", json!(CLIENT)),
        ("client_id", json!(CLIENT)),
        ("sub", json!(SUBJECT)),
        ("scope", json!("coordinator:start")),
    ] {
        fixture
            .claims
            .insert(claim.into(), ClaimValue::Literal(value));
    }

    let binding = Binding {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
    };
    let sign = |name, change| {
        let mut fixture = fixture.clone();
        fixture.claims.insert(name, change);
        signer.sign(&fixture, &binding).unwrap()
    };
    let literal = |value| ClaimValue::Literal(value);
    let good = signer.sign(&fixture, &binding).unwrap();
    let (prefix, signature) = good.expose().rsplit_once('.').unwrap();
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    let bad_signature = format!("{prefix}.{first}{}", &signature[1..]);
    let unknown_key = other_signer.sign(&fixture, &binding).unwrap();
    let mut jwt_fixture = fixture.clone();
    jwt_fixture.header.as_mut().unwrap().typ = Some("JWT".into());
    let wrong_type = signer.sign(&jwt_fixture, &binding).unwrap();
    let wrong_issuer = sign("iss".into(), literal(json!("https://other.example.test")));
    let wrong_audience = sign("aud".into(), literal(json!("urn:other")));
    let mut expired_fixture = fixture.clone();
    for (claim, offset) in [("exp", -300), ("iat", -600)] {
        expired_fixture
            .claims
            .insert(claim.into(), ClaimValue::OffsetSeconds(offset));
    }
    let expired = signer.sign(&expired_fixture, &binding).unwrap();
    let assertion = sign(
        ASSERTION_ISSUER_CLAIM.into(),
        literal(json!("https://assertions.example.test")),
    );
    let mut unknown_client_fixture = fixture.clone();
    for claim in ["azp", "client_id"] {
        unknown_client_fixture
            .claims
            .insert(claim.into(), literal(json!("unlisted-client")));
    }
    let unknown_client = signer.sign(&unknown_client_fixture, &binding).unwrap();
    let wrong_subject = sign("sub".into(), literal(json!("another-subject")));
    let act = sign("act".into(), literal(json!({"sub":"acting-subject"})));
    let missing_scope = sign("scope".into(), literal(json!("coordinator:status")));

    let unauthorized = StatusCode::UNAUTHORIZED;
    let forbidden = StatusCode::FORBIDDEN;
    let mut answers = Map::new();
    for (name, credential) in [
        ("no-credential", None),
        ("non-bearer-credential", Some("Basic opaque")),
        ("malformed-compact-token", Some("Bearer a.b.c")),
    ] {
        answers.insert(name.into(), answer(&app, credential, unauthorized).await);
    }
    for (name, token, status) in [
        ("bad-signature", bad_signature.as_str(), unauthorized),
        ("wrong-issuer", wrong_issuer.expose(), unauthorized),
        ("wrong-audience", wrong_audience.expose(), unauthorized),
        ("expired", expired.expose(), unauthorized),
        ("wrong-type", wrong_type.expose(), unauthorized),
        ("unknown-key", unknown_key.expose(), unauthorized),
        (
            "undeclared-assertion-issuer",
            assertion.expose(),
            unauthorized,
        ),
        (
            "client-without-policy",
            unknown_client.expose(),
            unauthorized,
        ),
        ("subject-without-policy", wrong_subject.expose(), forbidden),
        ("delegated-token", act.expose(), forbidden),
        ("missing-scope", missing_scope.expose(), forbidden),
        ("action-without-policy", good.expose(), forbidden),
    ] {
        let credential = format!("Bearer {token}");
        answers.insert(name.into(), answer(&app, Some(&credential), status).await);
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/refusal_answers.json");
    let observed = serde_json::to_string_pretty(&Value::Object(answers)).unwrap() + "\n";
    if std::env::var("REGISTRY_COORDINATOR_WRITE_GOLDEN").as_deref() == Ok("1") {
        fs::write(&path, &observed).unwrap();
    }
    assert_eq!(observed, fs::read_to_string(path).unwrap());
}
