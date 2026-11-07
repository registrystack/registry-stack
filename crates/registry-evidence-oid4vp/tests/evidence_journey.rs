#![cfg(unix)]

//! The composed wallet journey over real processes and real HTTP on loopback:
//! a portal creates an OpenID4VP session, a simulated wallet presents an SD-JWT
//! VC through `direct_post.jwt`, and Evidence reads the presentation from the
//! verifier service, verifies the credential and signs an assertion that a
//! relying party verifies with the Evidence client.
//!
//! The ordinary test proves the committed example deployment stays
//! well-formed. The ignored gate starts the real `evidence-oid4vp` and
//! `evidence` binaries and needs `EVIDENCE_BIN` and `EVIDENCECTL_BIN`.
//!
//! Every key in this file is a test-only fixture. The trusted issuer's key is
//! derived from the constants below; its public half is the key the example's
//! protocol configurations pin.

mod common;
#[path = "common/journey.rs"]
mod journey;

use std::{fs, process::Command};

use common::{canonical_tempdir, HOST};
use journey::{
    example_dir, hex, read_example, Deployment, Setup, APPLICANT, CREDENTIAL_TYPE, IDENTITY,
    ISSUER, ISSUER_KEY_ID, ISSUER_TEST_PUBLIC, POSSESSION,
};
use registry_evidence_client::{
    ChannelKind, EvidenceClientError, SubjectLinkMode, VerifiedEvidence,
};
use registry_platform_crypto::{
    generate_private_jwk, sign, verify, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

/// The seed of the synthetic trusted issuer the example pins. TEST-ONLY key
/// material; the public half is `journey::ISSUER_TEST_PUBLIC`.
const ISSUER_TEST_SEED: &str = "Mr7ZLwp5g1UDka9z0wECc3gRaShMvA78EZMiualp3yI";

/// The values the simulated wallet discloses. Neither may appear in an
/// assertion or in a possession journey's held presentation (that journey's
/// wallet discloses nothing); the name is chosen so the exact comparison needs the reviewed
/// normalisation to match the expected spelling.
const PRESENTED_CATEGORY: &str = "category-canary-4417";
const PRESENTED_NAME: &str = "Zoë Ångström-Nyström";
const MATCHING_EXPECTED_NAME: &str = "zoe angstrom nystrom";
const OTHER_EXPECTED_NAME: &str = "Someone Else";

const OTHER_APPLICANT: &str = "applicant-2";

fn issuer_key() -> PrivateJwk {
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": ISSUER_KEY_ID,
        "x": ISSUER_TEST_PUBLIC,
        "d": ISSUER_TEST_SEED,
    }))
    .expect("the test issuer key parses")
}

// ---------------------------------------------------------------------------
// The ordinary test: the committed example stays well-formed.
// ---------------------------------------------------------------------------

#[test]
fn the_example_deployment_is_well_formed() {
    use registry_evidence_authoring::{
        project::read_project,
        target::{read_authority, read_target},
    };

    // The verifier runtime file passes `evidence-oid4vp check`.
    let root = canonical_tempdir();
    let runtime = root.path().join("runtime.yaml");
    fs::write(&runtime, read_example("oid4vp-runtime.yaml")).expect("the runtime file is written");
    let output = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .args([
            "check",
            "--format",
            "json",
            "--deny-warnings",
            "--runtime-config",
        ])
        .arg(&runtime)
        .env_remove("EVIDENCE_OID4VP_CONFIG")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .output()
        .expect("the verifier binary runs");
    let report: Value = serde_json::from_slice(&output.stdout).expect("check prints one report");
    assert_eq!(output.status.code(), Some(0), "{report}");
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["diagnostics"], json!([]), "{report}");

    // The Evidence project, target and authority pass the authoring checks.
    let project_bytes = read_example("evidence.yaml");
    let project = read_project("evidence.yaml", project_bytes.as_bytes())
        .unwrap_or_else(|report| panic!("the project is refused: {report:?}"));
    let target = read_example("wallet-target.yaml");
    if let Err(report) = read_target("wallet-target.yaml", target.as_bytes()) {
        panic!("the target is refused: {report:?}");
    }
    let authority = read_example("wallet-authority.yaml");
    if let Err(report) = read_authority(
        "wallet-authority.yaml",
        authority.as_bytes(),
        &project.value,
    ) {
        panic!("the authority is refused: {report:?}");
    }

    // Every artifact the pack pins matches its declared digest, and the issuer
    // key the protocol configurations pin is the test issuer's.
    let pack_root = example_dir().join("adapter-packs/wallet-session");
    let pack: Value = serde_json::from_str(&read_example("adapter-packs/wallet-session/pack.yaml"))
        .expect("the pack is JSON");
    let mut pinned = Vec::new();
    collect_digests(&pack, &mut pinned);
    assert_eq!(pinned.len(), 7, "{pinned:?}");
    for (path, digest) in pinned {
        let bytes = fs::read(pack_root.join(&path))
            .unwrap_or_else(|error| panic!("the pack artifact {path} is readable: {error}"));
        assert_eq!(
            digest,
            format!("sha256:{}", hex(&Sha256::digest(&bytes))),
            "{path}"
        );
    }
    for protocol in ["credential-possession", "identity-match"] {
        let config: Value = serde_json::from_str(&read_example(&format!(
            "adapter-packs/wallet-session/protocols/{protocol}.json"
        )))
        .expect("the protocol configuration is JSON");
        assert_eq!(config["policyId"], protocol);
        assert_eq!(config["clientId"], format!("x509_san_dns:{HOST}"));
        let key = &config["trust"][0]["keys"]["jwks"][0];
        assert_eq!(key["x"], ISSUER_TEST_PUBLIC);
        assert_eq!(key["kid"], ISSUER_KEY_ID);
    }
    // The seed signs for the public key the configurations pin.
    let pinned: PublicJwk = serde_json::from_str::<Value>(&read_example(
        "adapter-packs/wallet-session/protocols/credential-possession.json",
    ))
    .map(|config| config["trust"][0]["keys"]["jwks"][0].clone())
    .and_then(serde_json::from_value)
    .expect("the pinned key parses");
    let signature = sign(b"test-only", &issuer_key()).expect("the test seed signs");
    verify(b"test-only", &signature, &pinned).expect("the pinned key verifies the test seed");
}

/// Every `{path, digest}` pair under `value`.
fn collect_digests(value: &Value, found: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(path)), Some(Value::String(digest))) =
                (map.get("path"), map.get("digest"))
            {
                found.push((path.clone(), digest.clone()));
            }
            map.values().for_each(|inner| collect_digests(inner, found));
        }
        Value::Array(items) => items.iter().for_each(|inner| collect_digests(inner, found)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

/// The one boolean output of a verified assertion.
fn boolean_output(verified: &VerifiedEvidence) -> bool {
    journey::boolean_output(verified).expect("a single boolean output")
}

/// The assertion states the channel and credential, never what was disclosed.
fn assert_holder_presented(verified: &VerifiedEvidence, link: SubjectLinkMode) {
    assert_eq!(verified.channel(), ChannelKind::HolderPresented);
    let credential = verified
        .presented_credential()
        .expect("a holder-presented assertion carries its credential");
    assert_eq!(credential.trust_entry, "example-issuer");
    assert_eq!(credential.issuer, ISSUER);
    assert_eq!(credential.credential_type, CREDENTIAL_TYPE);
    assert_eq!(credential.subject_link, link);
    let text = serde_json::to_string(verified.evidence()).expect("the assertion encodes");
    for canary in [PRESENTED_CATEGORY, PRESENTED_NAME, MATCHING_EXPECTED_NAME] {
        assert!(!text.contains(canary), "{canary} reached the assertion");
    }
}

/// The refusal is a dependency failure that released no assertion.
fn assert_dependency_failure(result: Result<VerifiedEvidence, EvidenceClientError>, what: &str) {
    match result {
        Err(EvidenceClientError::Unavailable { status: 503, .. }) => {}
        other => panic!("{what}: expected a dependency failure, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "exact gate: starts the real evidence-oid4vp and evidence binaries on loopback; needs EVIDENCE_BIN and EVIDENCECTL_BIN"]
async fn a_presented_credential_becomes_a_verified_assertion() {
    let deployment = Deployment::start(Setup::example()).await;
    let issuer = issuer_key();

    // Possession only: the assertion says a trusted credential was presented.
    let session = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    assert_eq!(deployment.status(&session).await, "pending");
    deployment.present(&session, &issuer, &[]).await;
    deployment.wait_until_received(&session).await;
    let possession = deployment
        .request(POSSESSION, &session, APPLICANT, None)
        .await
        .expect("the possession assertion verifies");
    assert_holder_presented(&possession, SubjectLinkMode::Possession);
    assert!(boolean_output(&possession));
    // Evidence's read consumed the presentation: it yields one assertion.
    assert_eq!(deployment.read_status(&session).await, 404);

    // The read response holds the issuer-signed JWT and the key binding JWT
    // and no disclosure, so it holds no claim value.
    let session = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    deployment.present(&session, &issuer, &[]).await;
    deployment.wait_until_received(&session).await;
    let read = deployment.read_presentation(&session).await;
    let held = read["presentation"]["credential"][0]
        .as_str()
        .expect("the held presentation is a string");
    assert_eq!(held.split('~').count(), 2, "a disclosure was held");
    assert!(
        !read.to_string().contains(PRESENTED_CATEGORY),
        "a claim value was held"
    );

    // Identity match: one exact comparison after the reviewed normalisation.
    let session = deployment.create_session(APPLICANT, "identity-match").await;
    deployment
        .present(&session, &issuer, &[("name", PRESENTED_NAME)])
        .await;
    deployment.wait_until_received(&session).await;
    let matching = deployment
        .request(IDENTITY, &session, APPLICANT, Some(MATCHING_EXPECTED_NAME))
        .await
        .expect("the matching identity assertion verifies");
    assert_holder_presented(&matching, SubjectLinkMode::AttributeMatch);
    assert!(boolean_output(&matching));
    // A second name against the same presentation is refused: the result was
    // consumed, so one presentation cannot be used to search for a name.
    assert_eq!(deployment.read_status(&session).await, 404);
    assert!(deployment
        .request(IDENTITY, &session, APPLICANT, Some(OTHER_EXPECTED_NAME))
        .await
        .is_err());
    // A second presentation answers a request whose expected name does not
    // match with a verified assertion that says false.
    let session = deployment.create_session(APPLICANT, "identity-match").await;
    deployment
        .present(&session, &issuer, &[("name", PRESENTED_NAME)])
        .await;
    deployment.wait_until_received(&session).await;
    let mismatch = deployment
        .request(IDENTITY, &session, APPLICANT, Some(OTHER_EXPECTED_NAME))
        .await
        .expect("the mismatching identity assertion verifies");
    assert_holder_presented(&mismatch, SubjectLinkMode::AttributeMatch);
    assert!(!boolean_output(&mismatch));

    // A credential from an issuer the example does not trust.
    let session = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    let untrusted = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("an issuer key");
    let untrusted: PrivateJwk = serde_json::from_value(json!({
        "kty": untrusted.kty, "crv": untrusted.crv, "alg": untrusted.alg,
        "kid": ISSUER_KEY_ID, "x": untrusted.x, "d": untrusted.d,
    }))
    .expect("the untrusted key parses");
    deployment.present(&session, &untrusted, &[]).await;
    deployment.wait_until_received(&session).await;
    assert_dependency_failure(
        deployment
            .request(POSSESSION, &session, APPLICANT, None)
            .await,
        "a credential from an untrusted issuer",
    );

    // Another principal than the one that created the session.
    let session = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    deployment.present(&session, &issuer, &[]).await;
    deployment.wait_until_received(&session).await;
    assert_dependency_failure(
        deployment
            .request(POSSESSION, &session, OTHER_APPLICANT, None)
            .await,
        "another principal",
    );

    // Evidence called before the wallet posted.
    let session = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    assert_dependency_failure(
        deployment
            .request(POSSESSION, &session, APPLICANT, None)
            .await,
        "a request before the wallet posted",
    );

    // The service is still serving after the refusals.
    let session_after = deployment
        .create_session(APPLICANT, "credential-possession")
        .await;
    deployment.present(&session_after, &issuer, &[]).await;
    deployment.wait_until_received(&session_after).await;
    deployment
        .request(POSSESSION, &session_after, APPLICANT, None)
        .await
        .expect("a later presentation still verifies");
}
