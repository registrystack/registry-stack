// SPDX-License-Identifier: Apache-2.0

//! The refusals of the Document Store, driven over the served router with
//! real tokens, in two checks.
//!
//! The first freezes what a caller is answered: the status, the headers that
//! matter to a client, and the body without its trace, for every refusal of
//! authentication or authority, against `tests/golden/refusals.json`. The
//! file records the answers the runtime gave before refusals were counted by
//! the check they failed. It must not change when the recording changes.
//!
//! The second proves the operator's side of the same refusals: each one adds
//! one to `documents_request_refusals_total` under the fixed check it failed,
//! writes one `request refused` line carrying that check and nothing a caller
//! sent, and answers the same bytes as the first.
//!
//! `DOCUMENTS_UPDATE_GOLDEN=1` rewrites the golden file from the current
//! answers. The database is named by `DOCUMENTS_TEST_DATABASE_URL`.

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Method, Request};
use registry_documents::runtime::{prepare_with_verifier, Prepared};
use registry_platform_authcommon::FailedCheck;
use serde_json::{json, Value};
use support::{
    pdf, request, reservation, token, token_with, Answer, Api, Deployment, FakeVerifier, Principal,
    APP, APPROVE, CITIZEN, DATABASE_STORAGE, DISABLED_VERIFIER, OTHER_APP, PARTNER_SERVICE, READER,
    STRANGER, TEST_AUDIENCE, TEST_ISSUER,
};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

/// The headers a client reads on a refusal.
const HEADERS: [&str; 4] = [
    "content-type",
    "www-authenticate",
    "retry-after",
    "cache-control",
];

/// How a fixture presents its credential.
enum Credential {
    Absent,
    Header(&'static str),
    Token(String),
}

/// One refusal: its name in the golden file, the check it must be recorded
/// under, and the request that trips it.
struct Fixture {
    name: &'static str,
    check: FailedCheck,
    method: Method,
    path: String,
    credential: Credential,
    body: Option<Value>,
}

impl Fixture {
    fn new(
        name: &'static str,
        check: FailedCheck,
        method: Method,
        path: &str,
        credential: Credential,
    ) -> Self {
        Self {
            name,
            check,
            method,
            path: path.to_owned(),
            credential,
            body: None,
        }
    }

    fn get(name: &'static str, check: FailedCheck, path: &str, credential: Credential) -> Self {
        Self::new(name, check, Method::GET, path, credential)
    }

    fn as_principal(
        name: &'static str,
        check: FailedCheck,
        method: Method,
        path: &str,
        principal: Principal,
    ) -> Self {
        Self::new(
            name,
            check,
            method,
            path,
            Credential::Token(token(principal)),
        )
    }

    fn with_body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    fn request(&self) -> Request<Body> {
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(&self.path);
        match &self.credential {
            Credential::Absent => {}
            Credential::Header(value) => builder = builder.header("authorization", *value),
            Credential::Token(token) => {
                builder = builder.header("authorization", format!("Bearer {token}"));
            }
        }
        match &self.body {
            Some(body) => builder
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(body.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }
}

/// The deployment, one document held for the citizen, and its ids.
struct World {
    deployment: Deployment,
    prepared: Prepared,
    api: Api,
    document: String,
    version: String,
    upload_path: String,
    missing: String,
}

async fn world() -> World {
    world_with_project(support::STARTER_PROJECT).await
}

async fn world_with_project(project: &str) -> World {
    let mut deployment =
        Deployment::with_project(DATABASE_STORAGE, DISABLED_VERIFIER, project).await;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    deployment.configure(&format!("metricsListener:\n  bind: 127.0.0.1:{port}\n"));
    deployment.migrate().await;
    let prepared = prepare_with_verifier(
        &deployment.runtime,
        FakeVerifier::new("refusal-golden", APPROVE),
    )
    .await
    .expect("the runtime prepares");
    let api = Api::new(&prepared);
    let content = pdf(256, 7);
    let reserved = api
        .reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &content,
            "application/pdf",
        )
        .await;
    let (document, version, upload_path) = reservation(&reserved);
    World {
        deployment,
        prepared,
        api,
        document,
        version,
        upload_path,
        missing: Uuid::new_v4().to_string(),
    }
}

fn claims(name: &str, value: Value) -> Value {
    json!({ name: value })
}

fn fixtures(world: &World) -> Vec<Fixture> {
    let document = &world.document;
    let version = &world.version;
    let missing = world.missing.clone();
    let reserve = |policy: &str, custodian: &str| {
        support::reservation_body(
            policy,
            custodian,
            &support::sha256(&pdf(256, 7)),
            256,
            "application/pdf",
        )
    };
    let signed = |claims: Value| Credential::Token(token_with(CITIZEN, claims));
    let mut forged = token(CITIZEN);
    let signature_at = forged.rfind('.').unwrap() + 1;
    forged.replace_range(signature_at.., &"A".repeat(86));
    vec![
        // The credential.
        Fixture::get(
            "no-authorization-header",
            FailedCheck::CredentialMissing,
            "/v1/documents",
            Credential::Absent,
        ),
        Fixture::get(
            "another-scheme",
            FailedCheck::CredentialMissing,
            "/v1/documents",
            Credential::Header("Basic dXNlcjpwYXNz"),
        ),
        Fixture::get(
            "empty-bearer",
            FailedCheck::CredentialMalformed,
            "/v1/documents",
            Credential::Header("Bearer"),
        ),
        Fixture::get(
            "not-a-compact-token",
            FailedCheck::CredentialMalformed,
            "/v1/documents",
            Credential::Token("not-a-token".to_owned()),
        ),
        // The token.
        Fixture::get(
            "forged-signature",
            FailedCheck::TokenSignature,
            "/v1/documents",
            Credential::Token(forged),
        ),
        Fixture::get(
            "foreign-issuer",
            FailedCheck::TokenIssuer,
            "/v1/documents",
            signed(claims("iss", json!("https://other.example.test"))),
        ),
        Fixture::get(
            "foreign-audience",
            FailedCheck::TokenAudience,
            "/v1/documents",
            signed(claims("aud", json!("urn:example:elsewhere"))),
        ),
        Fixture::get(
            "expired",
            FailedCheck::TokenTime,
            "/v1/documents",
            signed(claims("exp", json!(1_600_000_000))),
        ),
        Fixture::get(
            "unadmitted-client",
            FailedCheck::TokenClient,
            "/v1/documents",
            signed(json!({"azp": "unlisted-client", "client_id": "unlisted-client"})),
        ),
        Fixture::get(
            "exchanged-token",
            FailedCheck::TokenAssertionIssuer,
            "/v1/documents",
            signed(claims(
                registry_platform_oidc::ASSERTION_ISSUER_CLAIM,
                json!("https://partner.example.test"),
            )),
        ),
        // The profile the token resolves to.
        Fixture::get(
            "missing-scope",
            FailedCheck::Scope,
            "/v1/documents",
            signed(claims("scope", json!("documents:read"))),
        ),
        // The verifier admits this client and no access profile of the
        // starter project lists it.
        Fixture::as_principal(
            "client-no-profile-lists",
            FailedCheck::AccessProfile,
            Method::GET,
            "/v1/documents",
            PARTNER_SERVICE,
        ),
        Fixture::get(
            "another-actor-kind",
            FailedCheck::ActorKind,
            "/v1/documents",
            signed(claims("registry_actor_kind", json!("service"))),
        ),
        Fixture::get(
            "agent-actor-kind",
            FailedCheck::ActorKind,
            "/v1/documents",
            signed(claims("registry_actor_kind", json!("agent"))),
        ),
        Fixture::get(
            "malformed-actor-kind",
            FailedCheck::ActorKind,
            "/v1/documents",
            signed(claims("registry_actor_kind", json!(7))),
        ),
        Fixture::get(
            "principal-outside-its-grammar",
            FailedCheck::TokenClaims,
            "/v1/documents",
            signed(claims("sub", json!("a principal\u{7}with a control"))),
        ),
        // A document the caller may not see, or not act on.
        Fixture::as_principal(
            "read-by-a-stranger",
            FailedCheck::Visibility,
            Method::GET,
            &format!("/v1/documents/{document}"),
            STRANGER,
        ),
        Fixture::as_principal(
            "read-of-an-absent-document",
            FailedCheck::Visibility,
            Method::GET,
            &format!("/v1/documents/{missing}"),
            CITIZEN,
        ),
        Fixture::as_principal(
            "read-of-a-malformed-id",
            FailedCheck::Visibility,
            Method::GET,
            "/v1/documents/not-a-uuid",
            CITIZEN,
        ),
        Fixture::as_principal(
            "download-by-a-stranger",
            FailedCheck::Visibility,
            Method::GET,
            &format!("/v1/documents/{document}/versions/{version}/content"),
            STRANGER,
        ),
        Fixture::as_principal(
            "download-by-the-reserving-system",
            FailedCheck::Ownership,
            Method::GET,
            &format!("/v1/documents/{document}/versions/{version}/content"),
            APP,
        ),
        Fixture::as_principal(
            "grants-listed-by-a-stranger",
            FailedCheck::Visibility,
            Method::GET,
            &format!("/v1/documents/{document}/grants"),
            STRANGER,
        ),
        Fixture::as_principal(
            "grants-listed-by-the-reserving-system",
            FailedCheck::Ownership,
            Method::GET,
            &format!("/v1/documents/{document}/grants"),
            APP,
        ),
        Fixture::as_principal(
            "grant-issued-by-a-stranger",
            FailedCheck::Visibility,
            Method::POST,
            &format!("/v1/documents/{document}/grants"),
            STRANGER,
        )
        .with_body(
            json!({"versionId": version, "grantee": {"subject": "reader-1", "kind": "human"}}),
        ),
        Fixture::as_principal(
            "grant-issued-by-the-reserving-system",
            FailedCheck::Ownership,
            Method::POST,
            &format!("/v1/documents/{document}/grants"),
            APP,
        )
        .with_body(
            json!({"versionId": version, "grantee": {"subject": "reader-1", "kind": "human"}}),
        ),
        Fixture::as_principal(
            "grant-on-another-version",
            FailedCheck::Visibility,
            Method::POST,
            &format!("/v1/documents/{document}/grants"),
            CITIZEN,
        )
        .with_body(
            json!({"versionId": missing, "grantee": {"subject": "reader-1", "kind": "human"}}),
        ),
        Fixture::as_principal(
            "revoke-of-an-absent-grant",
            FailedCheck::Visibility,
            Method::DELETE,
            &format!("/v1/document-grants/{missing}"),
            CITIZEN,
        ),
        Fixture::as_principal(
            "erasure-by-a-stranger",
            FailedCheck::Visibility,
            Method::POST,
            &format!("/v1/documents/{document}/erasure"),
            STRANGER,
        ),
        Fixture::as_principal(
            "erasure-by-the-reserving-system",
            FailedCheck::Ownership,
            Method::POST,
            &format!("/v1/documents/{document}/erasure"),
            APP,
        ),
        // An upload the caller did not reserve.
        Fixture::as_principal(
            "upload-to-an-absent-reservation",
            FailedCheck::Visibility,
            Method::PUT,
            &format!("/v1/uploads/{missing}/content"),
            APP,
        ),
        Fixture::as_principal(
            "upload-by-another-caller",
            FailedCheck::Visibility,
            Method::PUT,
            &world.upload_path,
            OTHER_APP,
        ),
        // Custody the caller's profile may not place.
        Fixture::as_principal(
            "reservation-by-a-recipient-profile",
            FailedCheck::Operation,
            Method::POST,
            "/v1/documents",
            READER,
        )
        .with_body(reserve("citizen-delivery", "citizen-1")),
        Fixture::as_principal(
            "reservation-outside-the-custody-profiles",
            FailedCheck::Operation,
            Method::POST,
            "/v1/documents",
            CITIZEN,
        )
        .with_body(reserve("citizen-delivery", "citizen-1")),
        Fixture::as_principal(
            "reservation-for-another-custodian-by-a-person",
            FailedCheck::Operation,
            Method::POST,
            "/v1/documents",
            CITIZEN,
        )
        .with_body(reserve("named-share", "citizen-2")),
    ]
}

/// The answer to `fixture` and what a client can read of it: the status, the
/// headers in [`HEADERS`], and the problem body without its trace.
async fn observe(api: &Api, fixture: &Fixture) -> (Answer, Value) {
    let answer = api.call(fixture.request()).await;
    let mut body: Value = serde_json::from_slice(&answer.body).unwrap_or_else(|_| {
        panic!(
            "{}: a problem body, got {}",
            fixture.name,
            String::from_utf8_lossy(&answer.body)
        )
    });
    assert!(
        body.as_object_mut().unwrap().remove("traceId").is_some(),
        "{}: the answer carries a trace",
        fixture.name
    );
    let headers: BTreeMap<&str, &str> = HEADERS
        .iter()
        .filter_map(|name| {
            answer
                .headers
                .get(*name)
                .map(|value| (*name, value.to_str().unwrap()))
        })
        .collect();
    let observed = json!({
        "status": answer.status,
        "headers": headers,
        "body": body,
    });
    (answer, observed)
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/refusals.json")
}

#[tokio::test]
async fn every_refusal_answers_the_bytes_the_golden_file_holds() {
    let world = world().await;
    let mut observed = BTreeMap::new();
    for fixture in fixtures(&world) {
        let (_, answer) = observe(&world.api, &fixture).await;
        assert!(
            matches!(answer["status"].as_u64(), Some(401 | 403 | 404)),
            "{}: {answer}",
            fixture.name
        );
        observed.insert(fixture.name, answer);
    }
    let observed = serde_json::to_value(&observed).unwrap();
    if std::env::var_os("DOCUMENTS_UPDATE_GOLDEN").is_some() {
        let text = serde_json::to_string_pretty(&observed).unwrap() + "\n";
        std::fs::create_dir_all(golden_path().parent().unwrap()).unwrap();
        std::fs::write(golden_path(), text).unwrap();
        return;
    }
    let golden: Value = serde_json::from_slice(
        &std::fs::read(golden_path()).expect("tests/golden/refusals.json exists"),
    )
    .unwrap();
    assert_eq!(
        observed,
        golden,
        "a refusal answers differently than the golden file holds:\n{}",
        serde_json::to_string_pretty(&observed).unwrap()
    );
}

/// The count `documents_request_refusals_total` holds for `check`.
async fn counted(prepared: &Prepared, check: FailedCheck) -> u64 {
    let response = prepared
        .metrics_app()
        .expect("a metrics listener is configured")
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let prefix = format!(
        "documents_request_refusals_total{{check=\"{}\"}} ",
        check.as_str()
    );
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("no series for {}\n{text}", check.as_str()))
        .parse()
        .unwrap()
}

#[tokio::test]
async fn every_refusal_is_counted_and_logged_under_the_check_it_failed() {
    let world = world().await;
    let logs = registry_platform_testing::CapturedDiagnosticLogs::default();
    let mut logged: BTreeMap<&str, usize> = BTreeMap::new();
    let mut seen: BTreeMap<&str, u64> = BTreeMap::new();
    for fixture in fixtures(&world) {
        let before = counted(&world.prepared, fixture.check).await;
        let lines_before = logs.text().lines().count();
        let (_, _) = observe(&world.api, &fixture)
            .with_subscriber(logs.subscriber())
            .await;
        let after = counted(&world.prepared, fixture.check).await;
        assert_eq!(after, before + 1, "{}: counted once", fixture.name);
        let occurrences = seen.entry(fixture.check.as_str()).or_default();
        *occurrences += 1;
        let text = logs.text();
        let written: Vec<&str> = text
            .lines()
            .skip(lines_before)
            .filter(|line| line.contains("request refused"))
            .collect();
        // The limiter admits the first lines of each check in a window.
        if *occurrences <= 5 {
            assert_eq!(written.len(), 1, "{}: one line\n{text}", fixture.name);
            let line: Value = serde_json::from_str(written[0]).unwrap();
            let fields = &line["fields"];
            assert_eq!(fields["decision"], "refused", "{}", fixture.name);
            assert_eq!(
                fields["failed_check"],
                fixture.check.as_str(),
                "{}",
                fixture.name
            );
            *logged.entry(fixture.check.as_str()).or_default() += 1;
        }
    }
    let text = logs.text();
    // Nothing a caller sent reaches the log.
    for canary in [
        "unlisted-client",
        "a principal",
        "other.example.test",
        "urn:example:elsewhere",
        "partner.example.test",
        TEST_ISSUER,
        TEST_AUDIENCE,
        "citizen-portal",
        "reader-1",
        "someone-else",
        "not-a-token",
        "partner-service",
        CITIZEN.subject,
        &world.document,
        &world.version,
        &world.missing,
    ] {
        assert!(!text.contains(canary), "{canary} reached the log\n{text}");
    }
    assert!(!logged.is_empty());
}

/// The sum of every series of `documents_request_refusals_total`.
async fn counted_in_total(prepared: &Prepared) -> u64 {
    let mut total = 0;
    for check in FailedCheck::ALL {
        total += counted(prepared, check).await;
    }
    total
}

#[tokio::test]
async fn a_request_that_is_not_refused_is_not_counted() {
    let world = world().await;
    let before = counted_in_total(&world.prepared).await;
    let read = world.api.read(CITIZEN, &world.document).await;
    assert_eq!(read.status, 200);
    let listed = world.api.get(CITIZEN, "/v1/documents").await;
    assert_eq!(listed.status, 200);
    let missing_route = world.api.get(CITIZEN, "/v1/nothing-here").await;
    assert_eq!(missing_route.status, 404);
    let unsupported = world
        .api
        .call(
            request(CITIZEN, Method::POST, "/v1/documents")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(unsupported.status >= 400);
    assert_eq!(counted_in_total(&world.prepared).await, before);
    drop(world.deployment);
}

/// A custodian whose profile has no grant authority is refused under
/// `operation`, not `ownership`, with the answer the reserving system gets.
/// Under `citizen-delivery` with represented-principal grants refused, the
/// citizen holds the document and may not issue a grant on it.
#[tokio::test]
async fn a_custodian_without_grant_authority_is_counted_under_operation() {
    let project = support::STARTER_PROJECT.replacen(
        "representedPrincipalGrants: permitted",
        "representedPrincipalGrants: refused",
        1,
    );
    assert_ne!(
        project,
        support::STARTER_PROJECT,
        "the starter changed shape"
    );
    let world = world_with_project(&project).await;
    let fixture = Fixture::as_principal(
        "grant-issued-by-a-custodian-without-grant-authority",
        FailedCheck::Operation,
        Method::POST,
        &format!("/v1/documents/{}/grants", world.document),
        CITIZEN,
    )
    .with_body(
        json!({"versionId": world.version, "grantee": {"subject": "reader-1", "kind": "human"}}),
    );
    let operation_before = counted(&world.prepared, FailedCheck::Operation).await;
    let ownership_before = counted(&world.prepared, FailedCheck::Ownership).await;
    let (_, answer) = observe(&world.api, &fixture).await;
    assert_eq!(
        counted(&world.prepared, FailedCheck::Operation).await,
        operation_before + 1
    );
    assert_eq!(
        counted(&world.prepared, FailedCheck::Ownership).await,
        ownership_before
    );
    let golden: Value = serde_json::from_slice(&std::fs::read(golden_path()).unwrap()).unwrap();
    assert_eq!(answer, golden["grant-issued-by-the-reserving-system"]);
    drop(world.deployment);
}

/// A scope refusal's line names what the deployment declared, the scope
/// claim, the scope the profile requires and the profile, and nothing the
/// token carried in its own scope.
#[tokio::test]
async fn a_scope_refusal_line_names_the_declared_values_and_none_of_the_tokens() {
    let world = world().await;
    let logs = registry_platform_testing::CapturedDiagnosticLogs::default();
    let canary = "canary-scope-from-the-token";
    let fixture = Fixture::get(
        "listing-with-another-scope",
        FailedCheck::Scope,
        "/v1/documents",
        Credential::Token(token_with(CITIZEN, claims("scope", json!(canary)))),
    );
    let (answer, _) = observe(&world.api, &fixture)
        .with_subscriber(logs.subscriber())
        .await;
    assert_eq!(answer.status, 403);
    let text = logs.text();
    assert!(
        !text.contains(canary),
        "the token's scope reached the log\n{text}"
    );
    let line: Value = text
        .lines()
        .filter(|line| line.contains("request refused"))
        .map(|line| serde_json::from_str(line).unwrap())
        .next()
        .unwrap_or_else(|| panic!("no refusal line\n{text}"));
    let fields = &line["fields"];
    assert_eq!(fields["failed_check"], "scope");
    assert_eq!(fields["scope_claim"], "scope");
    assert_eq!(fields["required_scope"], "documents:own");
    assert_eq!(fields["access_profile"], "citizen");
    assert!(fields["remedy"].as_str().unwrap().contains("scopeClaim"));
    drop(world.deployment);
}
