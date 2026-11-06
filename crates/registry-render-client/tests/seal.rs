// SPDX-License-Identifier: Apache-2.0
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::Engine as _;
use registry_render_client::{
    BearerToken, RenderClient, RenderClientConfig, RenderClientError, SealLevel,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TRACE: &str = "1234567890abcdef1234567890abcdef";
const FIRST_REVISION: &[u8] = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n";
const UPDATE: &[u8] = b"2 0 obj<</Type/Sig>>endobj\ntrailer<<>>\n%%EOF\n";

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn digest_of(hex_digit: &str) -> String {
    format!("sha256:{}", hex_digit.repeat(64))
}
fn signed_file() -> Vec<u8> {
    [FIRST_REVISION, UPDATE].concat()
}
fn sealed_body(level: &str) -> Value {
    let pdf = signed_file();
    let mut seal = json!({"id":"agency","level":level,"certificateDigest":digest_of("c")});
    if level == "B-T" {
        seal["timestampedAt"] = json!("2026-10-23T00:00:01Z");
    }
    json!({
        "pdfBase64": base64::engine::general_purpose::STANDARD.encode(&pdf),
        "documentDigest": sha(FIRST_REVISION),
        "signedFileDigest": sha(&pdf),
        "dataDigest": digest_of("0"),
        "documentVersion": "receipt v1",
        "packageDigest": digest_of("b"),
        "warnings": ["w"],
        "seal": seal,
    })
}
fn problem(slug: &str, status: u16) -> Value {
    json!({"type":format!("https://render.registrystack.org/problems/{slug}"),"title":slug,"status":status,"detail":"refused","code":format!("render.{slug}"),"traceId":TRACE,"pointers":[]})
}

#[derive(Clone)]
struct Stub {
    status: u16,
    body: Vec<u8>,
    echo: Option<String>,
}
async fn handler(State(stub): State<Stub>, headers: HeaderMap, input: String) -> Response {
    assert_eq!(headers["authorization"], "Bearer canary-render-token");
    assert_eq!(headers["accept"], "application/json");
    assert_eq!(
        serde_json::from_str::<Value>(&input).unwrap()["issuedAt"],
        "2026-10-23T00:00:00Z"
    );
    let mut response = (
        StatusCode::from_u16(stub.status).unwrap(),
        Body::from(stub.body),
    )
        .into_response();
    let h = response.headers_mut();
    h.insert(
        "content-type",
        if stub.status == 200 {
            "application/json"
        } else {
            "application/problem+json"
        }
        .parse()
        .unwrap(),
    );
    h.insert(
        "traceparent",
        format!("00-{TRACE}-1234567890abcdef-01").parse().unwrap(),
    );
    if let Some(echo) = stub.echo {
        h.insert("idempotency-key", echo.parse().unwrap());
    }
    response
}
async fn serve(
    path: &str,
    status: u16,
    body: Value,
    echo: Option<&str>,
    config: impl FnOnce(&mut RenderClientConfig),
) -> (RenderClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(path, post(handler)).with_state(Stub {
        status,
        body: serde_json::to_vec(&body).unwrap(),
        echo: echo.map(str::to_owned),
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut cfg = RenderClientConfig::new(base);
    config(&mut cfg);
    (RenderClient::new(cfg).unwrap(), task)
}
async fn seal_with(
    status: u16,
    body: Value,
    key: Option<&str>,
    echo: Option<&str>,
) -> Result<registry_render_client::SealedDocument, RenderClientError> {
    let (client, task) = serve("/v1/seal/receipt", status, body, echo, |_| {}).await;
    let result = client
        .seal(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{"number":"R-1"}}),
            key,
        )
        .await;
    task.abort();
    result
}

/// The language bindings return a sealed document as JSON: the names the
/// server sends, with the PDF as `pdfBase64`.
#[tokio::test]
async fn a_sealed_document_serializes_with_the_wire_names() {
    for (level, test_only) in [("B-T", false), ("B-B", true)] {
        let mut body = sealed_body(level);
        if test_only {
            body["seal"]["testOnly"] = json!(true);
        }
        let sealed = seal_with(200, body.clone(), None, None).await.unwrap();
        assert_eq!(serde_json::to_value(&sealed).unwrap(), body, "{level}");
    }
}

#[test]
fn a_correlation_key_is_validated_without_an_exchange() {
    for key in [None, Some("k"), Some("~!"), Some(&*"k".repeat(128))] {
        assert!(
            RenderClient::validate_correlation_key(key).is_ok(),
            "{key:?}"
        );
    }
    for key in ["", "has space", "caf\u{e9}", &"k".repeat(129)] {
        let error = RenderClient::validate_correlation_key(Some(key)).unwrap_err();
        assert_eq!(error.kind, "invalid-request", "{key:?}");
    }
}

#[tokio::test]
async fn timestamped_seal_returns_typed_facts() {
    let sealed = seal_with(200, sealed_body("B-T"), None, None)
        .await
        .unwrap();
    assert_eq!(sealed.pdf, signed_file());
    assert_eq!(sealed.document_digest, sha(FIRST_REVISION));
    assert_eq!(sealed.signed_file_digest, sha(&signed_file()));
    assert_eq!(sealed.data_digest, digest_of("0"));
    assert_eq!(sealed.document_version, "receipt v1");
    assert_eq!(sealed.package_digest, digest_of("b"));
    assert_eq!(sealed.seal.certificate_digest, digest_of("c"));
    assert_eq!(sealed.warnings, ["w"]);
    assert_eq!(sealed.seal.id, "agency");
    assert!(!sealed.seal.test_only);
    assert_eq!(sealed.seal.level, SealLevel::BaselineT);
    assert_eq!(sealed.seal.level.as_str(), "B-T");
    assert_eq!(
        sealed.seal.timestamped_at.as_deref(),
        Some("2026-10-23T00:00:01Z")
    );
}

#[tokio::test]
async fn basic_seal_has_no_timestamp() {
    let sealed = seal_with(200, sealed_body("B-B"), None, None)
        .await
        .unwrap();
    assert_eq!(sealed.seal.level, SealLevel::BaselineB);
    assert_eq!(sealed.seal.timestamped_at, None);
}

#[tokio::test]
async fn level_and_timestamp_must_agree() {
    let mut body = sealed_body("B-B");
    body["seal"]["timestampedAt"] = json!("2026-10-23T00:00:01Z");
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    let mut body = sealed_body("B-T");
    body["seal"]
        .as_object_mut()
        .unwrap()
        .remove("timestampedAt");
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    // An unknown level, and a known one in another spelling, are refused:
    // the level names are ETSI's, compared exactly.
    for level in ["b-lt", "B-LT", "b-t"] {
        let mut body = sealed_body("B-T");
        body["seal"]["level"] = json!(level);
        assert_eq!(
            seal_with(200, body, None, None).await.unwrap_err().kind,
            "protocol",
            "{level}"
        );
    }
}

#[tokio::test]
async fn hash_mismatches_are_refused() {
    let mut body = sealed_body("B-T");
    body["signedFileDigest"] = json!(digest_of("f"));
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    // A document hash that is no %%EOF prefix of the file.
    let mut body = sealed_body("B-T");
    body["documentDigest"] = json!(digest_of("f"));
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    // The whole file is not a first revision.
    let mut body = sealed_body("B-T");
    body["documentDigest"] = json!(sha(&signed_file()));
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    // A pdfDigest or pdfSha256 member is not part of the sealed contract.
    for member in ["pdfDigest", "pdfSha256"] {
        let mut body = sealed_body("B-T");
        body[member] = json!(sha(&signed_file()));
        assert_eq!(
            seal_with(200, body, None, None).await.unwrap_err().kind,
            "protocol",
            "{member}"
        );
    }
}

#[tokio::test]
async fn every_digest_is_labelled() {
    let unlabelled = |digest: &Value| json!(digest.as_str().unwrap().trim_start_matches("sha256:"));
    for pointer in [
        "/documentDigest",
        "/signedFileDigest",
        "/dataDigest",
        "/packageDigest",
        "/seal/certificateDigest",
    ] {
        let mut body = sealed_body("B-T");
        let bare = unlabelled(body.pointer(pointer).unwrap());
        *body.pointer_mut(pointer).unwrap() = bare;
        assert_eq!(
            seal_with(200, body, None, None).await.unwrap_err().kind,
            "protocol",
            "{pointer}"
        );
        let mut body = sealed_body("B-T");
        let upper = json!(body
            .pointer(pointer)
            .unwrap()
            .as_str()
            .unwrap()
            .replace("sha256:", "SHA256:"));
        *body.pointer_mut(pointer).unwrap() = upper;
        assert_eq!(
            seal_with(200, body, None, None).await.unwrap_err().kind,
            "protocol",
            "{pointer}"
        );
    }
}

#[tokio::test]
async fn unknown_members_are_tolerated_and_a_test_seal_is_named() {
    let mut body = sealed_body("B-T");
    body["laterMember"] = json!({"any": "shape"});
    body["seal"]["laterFact"] = json!(1);
    body["seal"]["testOnly"] = json!(true);
    let sealed = seal_with(200, body, None, None).await.unwrap();
    assert!(sealed.seal.test_only);
    assert_eq!(sealed.seal.level, SealLevel::BaselineT);
}

#[tokio::test]
async fn the_package_digest_is_required_and_checked() {
    let mut body = sealed_body("B-B");
    body.as_object_mut().unwrap().remove("packageDigest");
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
    let mut body = sealed_body("B-B");
    body["packageDigest"] = json!("not-a-digest");
    assert_eq!(
        seal_with(200, body, None, None).await.unwrap_err().kind,
        "protocol"
    );
}

#[tokio::test]
async fn first_revision_hash_may_exclude_the_line_ending() {
    let mut body = sealed_body("B-B");
    body["documentDigest"] = json!(sha(&FIRST_REVISION[..FIRST_REVISION.len() - 1]));
    assert!(seal_with(200, body, None, None).await.is_ok());
}

#[tokio::test]
async fn each_seal_problem_is_decoded() {
    for (slug, status) in [
        ("signing-unavailable", 503),
        ("seal-certificate-invalid", 503),
        ("timestamp-failed", 502),
        ("document-not-sealable", 400),
        ("seal-client-not-allowed", 403),
    ] {
        let error = seal_with(status, problem(slug, status), None, None)
            .await
            .unwrap_err();
        assert_eq!(error.kind, "problem", "{slug}");
        assert_eq!(error.status, Some(status));
        assert_eq!(
            error.code.as_deref(),
            Some(format!("render.{slug}").as_str())
        );
        assert!(!error.is_outcome_unknown());
    }
    // A known kind with the wrong status stays a protocol failure.
    let error = seal_with(400, problem("timestamp-failed", 400), None, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, "protocol");
}

/// A package without its SHA256SUMS is `package-checksums-missing`; the
/// retired `bundle-unsealed` code is no longer a Render problem.
#[tokio::test]
async fn a_package_without_checksums_is_decoded_by_its_current_code() {
    let error = seal_with(400, problem("package-checksums-missing", 400), None, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, "problem");
    assert_eq!(
        error.code.as_deref(),
        Some("render.package-checksums-missing")
    );
    let error = seal_with(400, problem("bundle-unsealed", 400), None, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, "protocol");
}

#[tokio::test]
async fn seal_problems_are_not_render_problems() {
    let (client, task) = serve(
        "/v1/render/receipt",
        502,
        problem("timestamp-failed", 502),
        None,
        |_| {},
    )
    .await;
    let error = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{}}),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "protocol");
    task.abort();
}

#[tokio::test]
async fn absent_route_is_a_not_found_problem() {
    // The stub mounts only /v1/render, as a server without seals does; the
    // client's request reaches no handler and the router answers 404.
    let (client, task) = serve("/v1/render/receipt", 200, json!({}), None, |_| {}).await;
    let error = client
        .seal(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{}}),
            None,
        )
        .await
        .unwrap_err();
    // An empty router 404 carries no problem media type: refused as protocol.
    assert_eq!(error.kind, "protocol");
    task.abort();
    // A server that does answer with its problem document is decoded.
    let error = seal_with(404, problem("not-found", 404), None, None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, "problem");
    assert_eq!(error.status, Some(404));
    assert_eq!(error.code.as_deref(), Some("render.not-found"));
}

#[tokio::test]
async fn oversize_body_is_bounded() {
    // A body that would otherwise be valid but is larger than the limit.
    let mut body = sealed_body("B-T");
    body["warnings"] = json!(vec!["w".repeat(100); 20]);
    assert!(serde_json::to_vec(&body).unwrap().len() > 1024);
    let (client, task) = serve("/v1/seal/receipt", 200, body, None, |cfg| {
        cfg.maximum_response_bytes = 1024;
    })
    .await;
    let error = client
        .seal(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{"number":"R-1"}}),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "transport");
    task.abort();
}

#[tokio::test]
async fn correlation_key_is_sent_and_must_be_echoed() {
    let sealed = seal_with(200, sealed_body("B-T"), Some("key-1"), Some("key-1")).await;
    assert!(sealed.is_ok());
    for echo in [None, Some("other")] {
        let error = seal_with(200, sealed_body("B-T"), Some("key-1"), echo)
            .await
            .unwrap_err();
        assert_eq!(error.kind, "protocol");
    }
    for key in ["", "has space", &"k".repeat(129)] {
        let client = RenderClient::new(RenderClientConfig::new("http://127.0.0.1:1")).unwrap();
        let error = client
            .seal(
                &BearerToken::new("canary-render-token").unwrap(),
                "receipt",
                &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{}}),
                Some(key),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind, "invalid-request");
    }
}

/// `render` takes the same optional correlation key as `seal`: it is sent as
/// `Idempotency-Key`, must come back exactly, and is checked before any
/// exchange.
#[tokio::test]
async fn render_takes_the_same_correlation_key() {
    type Received = std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>>;
    async fn echoing(State(received): State<Received>, headers: HeaderMap) -> Response {
        let pdf = b"%PDF-fixture";
        let body = json!({"pdfBase64":base64::engine::general_purpose::STANDARD.encode(pdf),"pdfDigest":sha(pdf),"dataDigest":digest_of("0"),"pdfSha256":sha(pdf).trim_start_matches("sha256:"),"dataSha256":"0".repeat(64),"documentVersion":"receipt v1","warnings":[]});
        let mut response = (
            StatusCode::OK,
            Body::from(serde_json::to_vec(&body).unwrap()),
        )
            .into_response();
        let h = response.headers_mut();
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert(
            "traceparent",
            format!("00-{TRACE}-1234567890abcdef-01").parse().unwrap(),
        );
        let key = headers.get("idempotency-key");
        received
            .lock()
            .unwrap()
            .push(key.map(|key| key.to_str().unwrap().to_owned()));
        if let Some(key) = key {
            h.insert("idempotency-key", key.clone());
        }
        response
    }
    let received = Received::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/v1/render/receipt", post(echoing))
        .with_state(received.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = RenderClient::new(RenderClientConfig::new(base)).unwrap();
    let token = BearerToken::new("canary-render-token").unwrap();
    let request = json!({"issuedAt":"2026-10-23T00:00:00Z","data":{}});
    for key in [Some("key-1"), None] {
        let rendered = client.render(&token, "receipt", &request, key).await;
        assert!(rendered.is_ok(), "{key:?}: {rendered:?}");
    }
    task.abort();
    assert_eq!(*received.lock().unwrap(), [Some("key-1".to_owned()), None]);
    for key in ["", "has space", &"k".repeat(129)] {
        let client = RenderClient::new(RenderClientConfig::new("http://127.0.0.1:1")).unwrap();
        let error = client
            .render(&token, "receipt", &request, Some(key))
            .await
            .unwrap_err();
        assert_eq!(error.kind, "invalid-request");
    }
}

#[tokio::test]
async fn a_broken_exchange_is_not_resent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let mut bytes = [0; 4096];
            let _ = socket.read(&mut bytes).await;
            let _ = socket
                .write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\ntraceparent: 00-{TRACE}-1234567890abcdef-01\r\nConnection: close\r\n\r\n{{}}").as_bytes())
                .await;
        }
    });
    let client = RenderClient::new(RenderClientConfig::new(origin)).unwrap();
    let error = client
        .seal(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &json!({"issuedAt":"2026-10-23T00:00:00Z","data":{}}),
            Some("key-1"),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "transport");
    assert!(error.is_outcome_unknown());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    task.abort();
}
