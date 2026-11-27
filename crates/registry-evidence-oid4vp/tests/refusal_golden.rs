//! The refusals a caller can provoke, answered through the whole router and
//! frozen in `tests/golden/refusals.json`. Each answer is its status, the
//! headers a caller or proxy acts on, and the body without its per-request
//! trace id. Run with `REGISTRY_OID4VP_WRITE_GOLDEN=1` to rewrite the file.

mod common;

use std::path::Path;

use axum_test::{TestResponse, TestServer};
use common::{bearer, Harness, Options};
use serde_json::{json, Map, Value};

const HEADERS: [&str; 5] = [
    "content-type",
    "www-authenticate",
    "cache-control",
    "retry-after",
    "x-content-type-options",
];

/// The answer as the golden freezes it. A `retry-after` on a 429 is the
/// bucket's remaining wait, which moves with the clock, so only its presence
/// is frozen there.
fn frozen(response: &TestResponse) -> Value {
    let status = response.status_code().as_u16();
    let mut headers = Map::new();
    for name in HEADERS {
        if let Some(value) = response.maybe_header(name) {
            let text = value.to_str().expect("ASCII header").to_owned();
            let text = if name == "retry-after" && status == 429 {
                "<seconds>".to_owned()
            } else {
                text
            };
            headers.insert(name.to_owned(), text.into());
        }
    }
    let mut body: Value = serde_json::from_slice(response.as_bytes()).expect("a JSON body");
    if let Some(object) = body.as_object_mut() {
        object.remove("traceId");
    }
    json!({"status": status, "headers": headers, "body": body})
}

async fn create(server: &TestServer, authorization: Option<&str>) -> TestResponse {
    let mut request = server.post("/v1/sessions");
    if let Some(value) = authorization {
        request = request.add_header("authorization", value.to_owned());
    }
    request.json(&json!({"policy": "national-id"})).await
}

async fn status_of(
    server: &TestServer,
    reference: &str,
    authorization: Option<&str>,
) -> TestResponse {
    let mut request = server.get(&format!("/v1/sessions/{reference}"));
    if let Some(value) = authorization {
        request = request.add_header("authorization", value.to_owned());
    }
    request.await
}

async fn read(
    server: &TestServer,
    authorization: Option<&str>,
    reference: &str,
    issuer: &str,
    subject: &str,
) -> TestResponse {
    let mut request = server.post("/v1/presentations/read");
    if let Some(value) = authorization {
        request = request.add_header("authorization", value.to_owned());
    }
    request
        .json(&json!({
            "reference": reference,
            "principal": {"issuer": issuer, "subject": subject},
        }))
        .await
}

/// Every refusal case, in a fixed order, answered by a fresh deployment where
/// the case needs a spent budget.
async fn answers() -> Value {
    let mut answers = Map::new();
    let mut put = |name: &str, response: &TestResponse| {
        answers.insert(name.to_owned(), frozen(response));
    };

    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let issuer = harness.idp.issuer().to_string();
    let creator = harness.applicant_token("portal", "user-1");
    let created: Value = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&creator))
        .json(&json!({"policy": "national-id"}))
        .await
        .json();
    let reference = created["reference"].as_str().expect("reference").to_owned();

    put("create-no-header", &create(&server, None).await);
    put(
        "create-non-bearer-scheme",
        &create(&server, Some("Basic dXNlcjpwYXNz")).await,
    );
    put(
        "create-garbage-token",
        &create(&server, Some("Bearer not-a-token")).await,
    );
    let unscoped = harness.token("portal", "user-1", "something:else");
    put(
        "create-wrong-scope",
        &create(&server, Some(&bearer(&unscoped))).await,
    );

    put(
        "status-no-header",
        &status_of(&server, &reference, None).await,
    );
    put(
        "status-unknown-reference",
        &status_of(&server, &"A".repeat(43), Some(&bearer(&creator))).await,
    );
    let other = harness.applicant_token("portal", "user-2");
    put(
        "status-another-principal",
        &status_of(&server, &reference, Some(&bearer(&other))).await,
    );

    put(
        "read-no-header",
        &read(&server, None, &reference, &issuer, "user-1").await,
    );
    put(
        "read-garbage-token",
        &read(
            &server,
            Some("Bearer not-a-token"),
            &reference,
            &issuer,
            "user-1",
        )
        .await,
    );
    let applicant_as_reader = harness.token("portal", "user-1", "oid4vp:read-result");
    put(
        "read-client-not-allowed",
        &read(
            &server,
            Some(&bearer(&applicant_as_reader)),
            &reference,
            &issuer,
            "user-1",
        )
        .await,
    );
    let reader_wrong_scope = harness.token("evidence", "evidence-service", "something:else");
    put(
        "read-wrong-scope",
        &read(
            &server,
            Some(&bearer(&reader_wrong_scope)),
            &reference,
            &issuer,
            "user-1",
        )
        .await,
    );
    let reader = harness.evidence_token();
    put(
        "read-another-principal",
        &read(
            &server,
            Some(&bearer(&reader)),
            &reference,
            &issuer,
            "user-2",
        )
        .await,
    );
    put(
        "read-unknown-reference",
        &read(
            &server,
            Some(&bearer(&reader)),
            &"B".repeat(43),
            &issuer,
            "user-1",
        )
        .await,
    );

    // Spent budgets, each in a deployment whose burst is one.
    let limited = Harness::new(&Options {
        session_creation_burst: 1,
        wallet_request_burst: 1,
        wallet_response_burst: 1,
        evidence_read_burst: 1,
        ..Options::default()
    })
    .await;
    let (server, _) = limited.server().await;
    let token = limited.applicant_token("portal", "user-1");
    let first = create(&server, Some(&bearer(&token))).await;
    assert_eq!(first.status_code().as_u16(), 201);
    put(
        "create-rate-limited",
        &create(&server, Some(&bearer(&token))).await,
    );
    let first = server.get("/v1/requests/unknown").await;
    assert_eq!(first.status_code().as_u16(), 404);
    put(
        "request-rate-limited",
        &server.get("/v1/requests/unknown").await,
    );
    let issuer = limited.idp.issuer().to_string();
    let reader = limited.evidence_token();
    let first = read(
        &server,
        Some(&bearer(&reader)),
        &"C".repeat(43),
        &issuer,
        "user-1",
    )
    .await;
    assert_eq!(first.status_code().as_u16(), 404);
    put(
        "read-rate-limited",
        &read(
            &server,
            Some(&bearer(&reader)),
            &"C".repeat(43),
            &issuer,
            "user-1",
        )
        .await,
    );
    let form = |server: &TestServer| {
        server
            .post("/v1/responses/unknown")
            .content_type("application/x-www-form-urlencoded")
            .text("response=x")
    };
    let first = form(&server).await;
    assert_eq!(first.status_code().as_u16(), 400);
    put("response-rate-limited", &form(&server).await);

    Value::Object(answers)
}

#[tokio::test]
async fn refusal_answers_match_the_golden() {
    let actual = answers().await;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/refusals.json");
    if std::env::var_os("REGISTRY_OID4VP_WRITE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("golden directory");
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&actual).expect("json")),
        )
        .expect("write golden");
    }
    let expected: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("golden file")).expect("golden json");
    assert_eq!(actual, expected);
}
