// SPDX-License-Identifier: Apache-2.0

//! The golden journey of the first slice, end to end over a real socket:
//! an owning system renders a document with the built `registry-render`
//! binary, reserves it with the digest Registry Render reported, and
//! uploads it into a citizen's custody; the verifier approves it; the
//! citizen names one recipient in a document grant; the recipient
//! downloads the exact version and its bytes match the digest; the grant
//! expires; and the cleanup sweep erases nothing the citizen still holds.
//!
//! Registry Render is composed through its public CLI, never through a
//! crate dependency: the binary is named by `REGISTRY_RENDER_BIN`. Every
//! token is signed by the suite's test issuer, whose issuer, audience, and
//! key id are fixed and whose public key set the runtime reads as a static
//! secret, the IdP fixture every Document Store database suite uses.
//!
//! The database is named by `DOCUMENTS_TEST_DATABASE_URL` and the binary by
//! `REGISTRY_RENDER_BIN`. Without either the test fails on the spot: a
//! journey that skipped is not a journey that ran.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use registry_documents::runtime::prepare_with_verifier;
use registry_documents_core::ProblemCode;
use support::{
    reservation_body, sha256, token, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN,
    DATABASE_STORAGE, DISABLED_VERIFIER, READER, STRANGER,
};

const PDF: &str = "application/pdf";
const ISSUED_AT: &str = "2026-01-01T00:00:00Z";

fn render_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var_os("REGISTRY_RENDER_BIN").expect(
        "REGISTRY_RENDER_BIN names a built registry-render binary \
         (cargo build --locked -p registry-render)",
    ));
    assert!(
        path.is_file(),
        "REGISTRY_RENDER_BIN is not a file: {}",
        path.display()
    );
    path
}

fn run(command: &mut Command) -> Vec<u8> {
    let output = command.output().expect("registry-render starts");
    assert!(
        output.status.success(),
        "registry-render failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Scaffold the Registry Render starter bundle under `root` and render its
/// letter at a fixed issuance time; return the PDF bytes and the
/// `sha256:<hex>` digest Registry Render reported for them.
fn render(binary: &Path, root: &Path) -> (Vec<u8>, String) {
    let bundle = root.join("bundle");
    let out = root.join("letter.pdf");
    run(Command::new(binary).arg("init").arg(&bundle));
    let report = run(Command::new(binary)
        .arg("compile")
        .arg("--bundle")
        .arg(&bundle)
        .args(["--type", "letter", "--issued-at", ISSUED_AT, "--json"])
        .arg("--data")
        .arg(bundle.join("fixtures/data.json"))
        .arg("--out")
        .arg(&out));
    let report: serde_json::Value = serde_json::from_slice(&report).expect("a JSON report");
    let digest = format!(
        "sha256:{}",
        report["pdfSha256"].as_str().expect("a reported PDF digest")
    );
    let bytes = std::fs::read(&out).expect("the rendered PDF");
    assert!(bytes.starts_with(b"%PDF-"), "Registry Render wrote a PDF");
    (bytes, digest)
}

async fn json(response: reqwest::Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| panic!("a JSON body: {}", String::from_utf8_lossy(&body)));
    (status, value)
}

#[tokio::test]
async fn a_rendered_document_reaches_a_named_recipient_and_outlives_its_share() {
    let binary = render_binary();
    let deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    deployment.migrate().await;
    let (content, digest) = render(&binary, deployment.path());
    assert_eq!(
        digest,
        sha256(&content),
        "Registry Render reported its bytes"
    );

    let verifier = FakeVerifier::new("journey-binding", APPROVE);
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let base = url::Url::parse(&format!("http://{}/v1/", prepared.local_addr().unwrap())).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async {
        stopped.await.ok();
    }));
    let http = reqwest::Client::new();

    // The owning system reserves the rendered letter for the citizen under
    // the digest Registry Render reported.
    let (status, reserved) = json(
        http.post(base.join("documents").unwrap())
            .bearer_auth(token(APP))
            .header("idempotency-key", "journey-reservation")
            .json(&reservation_body(
                "named-share",
                CITIZEN.subject,
                &digest,
                content.len() as u64,
                PDF,
            ))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 201, "{reserved}");
    let document = reserved["document"]["id"].as_str().unwrap().to_owned();
    let version = reserved["document"]["version"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(reserved["document"]["version"]["expectedDigest"], digest);
    let upload = base.join(reserved["uploadPath"].as_str().unwrap()).unwrap();

    // Bytes other than the rendered ones are refused and nothing is kept.
    let mut altered = content.clone();
    *altered.last_mut().unwrap() ^= 1;
    let (status, problem) = json(
        http.put(upload.clone())
            .bearer_auth(token(APP))
            .header("content-type", PDF)
            .body(altered)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 422, "{problem}");
    assert_eq!(problem["code"], ProblemCode::UploadDigestMismatch.code());
    let (status, uploaded) = json(
        http.put(upload)
            .bearer_auth(token(APP))
            .header("content-type", PDF)
            .body(content.clone())
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{uploaded}");

    // The served verification worker approves it; the citizen holds it.
    let document_url = base.join(&format!("documents/{document}")).unwrap();
    let mut ready = false;
    for _ in 0..100 {
        let (status, view) = json(
            http.get(document_url.clone())
                .bearer_auth(token(CITIZEN))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, 200, "{view}");
        if view["version"]["status"] == "ready" {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "the served verifier approved the rendered letter");
    assert_eq!(verifier.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // The citizen names one recipient for this exact version.
    let (status, grant) = json(
        http.post(base.join(&format!("documents/{document}/grants")).unwrap())
            .bearer_auth(token(CITIZEN))
            .header("idempotency-key", "journey-share")
            .json(&serde_json::json!({
                "versionId": version,
                "grantee": {"subject": READER.subject, "kind": "human"},
                "expiryHours": 1,
            }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 201, "{grant}");
    let grant = grant["id"].as_str().unwrap().to_owned();
    let (status, naming) = json(
        http.get(base.join("document-grants").unwrap())
            .bearer_auth(token(READER))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, 200, "{naming}");
    assert_eq!(naming["items"].as_array().unwrap().len(), 1);
    assert_eq!(naming["items"][0]["id"], grant);
    assert_eq!(naming["items"][0]["versionId"], version);

    // The recipient downloads exactly the rendered bytes.
    let content_url = base
        .join(&format!("documents/{document}/versions/{version}/content"))
        .unwrap();
    let downloaded = http
        .get(content_url.clone())
        .bearer_auth(token(READER))
        .send()
        .await
        .unwrap();
    assert_eq!(downloaded.status(), reqwest::StatusCode::OK);
    assert_eq!(downloaded.headers()["content-type"], PDF);
    let bytes = downloaded.bytes().await.unwrap();
    assert_eq!(sha256(&bytes), digest);
    assert_eq!(bytes.as_ref(), content.as_slice());
    // A recipient-profile holder the grant does not name gets nothing.
    let refused = http
        .get(content_url)
        .bearer_auth(token(STRANGER))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::NOT_FOUND);

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();

    // The share runs out: its issue and expiry move into the past, as an
    // hour passing would.
    deployment
        .execute(&format!(
            "UPDATE documents_grants
                SET issued_at = now() - interval '2 hours',
                    expires_at = now() - interval '1 hour'
              WHERE grant_id = '{grant}'"
        ))
        .await;
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares again");
    let api = Api::new(&prepared);
    api.download(READER, &document, &version)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    api.read(READER, &document)
        .await
        .assert_problem(ProblemCode::ResourceNotFound);
    let naming = api.get(READER, "/v1/document-grants").await;
    assert_eq!(naming.status, 200);
    assert!(naming.json()["items"].as_array().unwrap().is_empty());

    // The sweep erases nothing the citizen still holds; the expired grant
    // stays on record.
    prepared.sweep_due().await;
    prepared.sweep_due().await;
    let held: i64 = deployment
        .scalar("SELECT count(*) FROM documents_contents")
        .await;
    assert_eq!(held, 1, "the citizen's bytes are kept");
    let view = api.read(CITIZEN, &document).await;
    assert_eq!(view.status, 200);
    assert_eq!(view.json()["version"]["status"], "ready");
    let kept = api.download(CITIZEN, &document, &version).await;
    assert_eq!(kept.status, 200);
    assert_eq!(kept.body, content);
    let grants = api
        .get(CITIZEN, &format!("/v1/documents/{document}/grants"))
        .await;
    assert_eq!(
        grants.status,
        200,
        "{}",
        String::from_utf8_lossy(&grants.body)
    );
    let grants = grants.json();
    assert_eq!(grants["items"].as_array().unwrap().len(), 1);
    assert_eq!(grants["items"][0]["id"], grant);
    assert_eq!(grants["items"][0]["state"], "expired");
}
