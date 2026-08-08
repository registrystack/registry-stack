//! Live round trip through the real Python-facing surface.
//!
//! Every call here goes through genuine PyO3 dispatch: a `PyModule` is built
//! directly from this crate's own `#[pymodule]` entry point (the same
//! registration a real `import registry_evidence_client` performs), then
//! every object is built and driven with `getattr`/`call1`/`call_method1`,
//! exactly as a Python caller would. Nothing here reaches into a pyclass's
//! Rust fields directly, and `pyo3::append_to_inittab!` is deliberately not
//! used: its own doc comment asks callers to leave the `auto-initialize`
//! feature off, which this crate's `[dev-dependencies]` already turns on for
//! the panic-boundary unit test in `src/lib.rs`. Building the module directly
//! exercises the same `#[pyclass]`/`#[pymethods]` marshaling without needing
//! that sequencing at all.
//!
//! `prepare()` mints a fresh nonce on every call with no injection seam, so
//! the stub deployment can only sign its answer once the live nonce is
//! known: every test here calls `prepare` first (synchronous, no network),
//! reads the resulting nonce back through the real `request_nonce` getter,
//! signs a matching response, and only then mounts it on the stub. This
//! mirrors `crates/registry-evidence-client-node/__test__/happy-path.test.js`,
//! which does the same thing for the Node binding.
//!
//! The client's own internal tokio runtime is a second, independent
//! `tokio::runtime::Runtime` the pyclass builds and blocks on for every
//! network call (see `EvidenceClient::new` in `src/lib.rs`). Blocking on it
//! while already inside another runtime's `block_on` frame on the same
//! thread panics ("Cannot start a runtime from within a runtime"), so every
//! test here drives the stub server's own async setup (starting the server,
//! mounting a responder) through a `block_on` call that always returns
//! before any Python method call happens. By the time `EvidenceClient::send`
//! builds and blocks on its own runtime, this thread is not inside anyone
//! else's `block_on` frame.

use std::{fs, path::Path};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use evidence_client_sdk::{
    AssuranceProfile, Evidence, EvidenceObjectType, JwksDocument, PublicValue, SubjectBinding,
    SubjectBindingMode, SupportedValue,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::rand_core::OsRng,
};
use pyo3::prelude::*;
use registry_evidence_verifier::{
    EVIDENCE_JWS_CTY, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_JWS_TYP, EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::PublicJwk;
use wiremock::{
    matchers::{method, path as path_matcher},
    Mock, MockServer, ResponseTemplate,
};

/// The instant the golden fixture is signed for, restated from
/// `tests/golden_fixture.rs` rather than shared with it: every file under
/// `tests/` compiles as its own crate.
const FIXTURE_ISSUED_AT: &str = "2026-08-01T00:00:00Z";

/// The specification every send/verify test in this file prepares against,
/// as the plain Python-facing (snake_case) shape `spec_from_json` expects.
/// `subject_expectations` is `"accept_first_use"`, so verification pins
/// whatever binding the response asserts rather than checking it against a
/// value chosen ahead of time.
fn request_spec_json() -> serde_json::Value {
    serde_json::json!({
        "response_format": "signed-jws",
        "requirement": "urn:example:requirement:v1",
        "purpose": "example-purpose",
        "audience": "urn:example:audience",
        "evidence_type": "urn:example:evidence-type:v1",
        "issued_by": "urn:example:issuer",
        "provided_by": "urn:example:provider",
        "configuration_revision": format!("sha256:{}", "0".repeat(64)),
        "expected_assurance_profile": "local",
        "subjects": [
            { "role": "subject", "selector_profile": "national-id" }
        ],
        "expected_outputs": [
            { "concept": "urn:example:concept:status-holds", "form": "boolean" }
        ],
        "maximum_assertion_lifetime_seconds": 300,
        "clock_skew_seconds": 60,
        "subject_expectations": "accept_first_use",
    })
}

/// A fresh P-256 key, generated and discarded within one test. Distinct
/// from the golden fixture's committed key: these tests need to sign a
/// response for a nonce that does not exist until `prepare()` runs, so they
/// cannot use a response signed ahead of time.
fn fresh_signing_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

fn public_jwk(signing_key: &SigningKey) -> PublicJwk {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let mut key = PublicJwk {
        kty: "EC".to_owned(),
        kid: None,
        alg: Some("ES256".to_owned()),
        crv: Some("P-256".to_owned()),
        x: point.x().map(|value| URL_SAFE_NO_PAD.encode(value)),
        y: point.y().map(|value| URL_SAFE_NO_PAD.encode(value)),
        n: None,
        e: None,
    };
    key.kid = Some(key.jkt().expect("the thumbprint computes"));
    key
}

fn trusted_jwks_json(signing_key: &SigningKey) -> serde_json::Value {
    let jwks = JwksDocument {
        keys: vec![
            serde_json::to_value(public_jwk(signing_key)).expect("the public key serializes")
        ],
    };
    serde_json::to_value(jwks).expect("the key set serializes")
}

/// Build the `Evidence` payload matching [`request_spec_json`], for the
/// given live nonce and subject binding.
fn evidence_for(request_nonce: &str, subject_binding: &str) -> Evidence {
    let issued_at = Utc::now();
    let valid_until = issued_at + ChronoDuration::seconds(120);
    Evidence {
        schema: EVIDENCE_SCHEMA_V1.to_owned(),
        assurance_profile: AssuranceProfile::Local,
        subject_binding: SubjectBindingMode::AudienceScoped,
        request_nonce: Some(request_nonce.to_owned()),
        id: "urn:example:evidence:python-live".to_owned(),
        evidence_type_name: EvidenceObjectType::Evidence,
        supports_requirement: "urn:example:requirement:v1".to_owned(),
        is_conformant_to: "urn:example:evidence-type:v1".to_owned(),
        issued_by: "urn:example:issuer".to_owned(),
        provided_by: "urn:example:provider".to_owned(),
        issued_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        observed_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        valid_until: valid_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        purpose: "example-purpose".to_owned(),
        audience: Some("urn:example:audience".to_owned()),
        configuration_revision: format!("sha256:{}", "0".repeat(64)),
        subjects: vec![SubjectBinding {
            role: "subject".to_owned(),
            binding: subject_binding.to_owned(),
        }],
        supported_values: vec![SupportedValue {
            provides_value_for: "urn:example:concept:status-holds".to_owned(),
            value: PublicValue::Boolean(true),
        }],
    }
}

#[derive(serde::Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
    cty: &'static str,
}

#[derive(serde::Serialize)]
struct FlattenedJwsBody {
    protected: String,
    payload: String,
    signature: String,
}

/// Sign synchronously with the raw key, unlike the golden fixture's own
/// signer: mounting has to happen after `prepare()` names a nonce, and by
/// then this test is past the one async setup step it allows itself (see the
/// module doc comment), so the signature is computed with `p256`
/// directly rather than through the async `SigningProvider` trait.
fn sign(evidence: &Evidence, signing_key: &SigningKey) -> Vec<u8> {
    let payload = serde_json::to_vec(evidence).expect("evidence serializes");
    let key_id = public_jwk(signing_key)
        .kid
        .expect("the key identifier is derived");
    let protected = serde_json::to_vec(&ProtectedHeader {
        alg: "ES256",
        kid: &key_id,
        typ: EVIDENCE_JWS_TYP,
        cty: EVIDENCE_JWS_CTY,
    })
    .expect("protected header serializes");

    let protected = URL_SAFE_NO_PAD.encode(protected);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{payload}");
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    serde_json::to_vec(&FlattenedJwsBody {
        protected,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .expect("the flattened JWS serializes")
}

/// Parse `value` into a genuine Python object via the stdlib `json` module,
/// the same as a real caller loading a specification or a key set from a
/// file would. Kept independent of this crate's own `convert::json_to_python`
/// helper on purpose: that function lives in a private module, unreachable
/// from an integration test, and a real caller has no access to it either.
fn python_json<'py>(py: Python<'py>, value: &serde_json::Value) -> Bound<'py, PyAny> {
    let text = serde_json::to_string(value).expect("the value serializes");
    py.import("json")
        .expect("the json module is available")
        .call_method1("loads", (text,))
        .expect("the value parses back")
}

/// Build the extension module directly from its own `#[pymodule]` entry
/// point, the same registration a real `import registry_evidence_client`
/// performs. See the module doc comment for why this is used instead of
/// `pyo3::append_to_inittab!` plus an embedded interpreter.
fn evidence_client_module(py: Python<'_>) -> Bound<'_, PyModule> {
    let module = PyModule::new(py, "registry_evidence_client").expect("the module object builds");
    registry_evidence_client::registry_evidence_client(&module)
        .expect("the module registers its classes and exceptions");
    module
}

/// Because `auto-initialize` links this binary against libpython, it has to
/// find that library at process startup, before any test below runs. Without
/// the rpath `build.rs` records for the embedding build, that lookup falls to
/// `DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`, and the whole binary aborts under a
/// `mise`-, `pyenv`- or virtualenv-managed interpreter: not as a failing test,
/// but as a dynamic-linker error that also stops `cargo test --workspace` at
/// this crate and skips every suite ordered after it. Re-running this same
/// binary with those variables cleared asserts the startup path stands on its
/// own. Unix only: rpath has no Windows equivalent, where the loader searches
/// `PATH` instead.
#[cfg(unix)]
#[test]
fn the_binary_starts_without_a_library_path_variable() {
    let binary = std::env::current_exe().expect("the running test binary has a path");
    // `--list` starts the process, and the interpreter with it, without
    // running any test a second time.
    let started = std::process::Command::new(&binary)
        .arg("--list")
        .env_remove("DYLD_LIBRARY_PATH")
        .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .expect("the test binary can be re-executed");
    assert!(
        started.status.success(),
        "{} did not start without a library path variable: {}{}",
        binary.display(),
        String::from_utf8_lossy(&started.stderr),
        String::from_utf8_lossy(&started.stdout),
    );
}

#[test]
fn round_trip_through_send_and_verify() {
    let signing_key = fresh_signing_key();
    let trusted_jwks = trusted_jwks_json(&signing_key);
    let subject_binding = format!("urn:evidence:subject:v1_{}", "A".repeat(43));

    let runtime = tokio::runtime::Runtime::new().expect("the stub's runtime starts");
    let server = runtime.block_on(MockServer::start());
    let base_url = server.uri();

    Python::attach(|py| {
        let module = evidence_client_module(py);
        let client_class = module.getattr("EvidenceClient").expect("the class exists");
        let client = client_class
            .call1((
                base_url.as_str(),
                python_json(py, &trusted_jwks),
                Vec::<String>::new(),
                "test-token",
            ))
            .expect("the client is constructed");

        let prepared = client
            .call_method1("prepare", (python_json(py, &request_spec_json()),))
            .expect("the specification is accepted");
        let nonce: String = prepared
            .getattr("request_nonce")
            .expect("the nonce getter exists")
            .extract()
            .expect("the nonce is a string");

        let body = sign(&evidence_for(&nonce, &subject_binding), &signing_key);
        runtime.block_on(
            Mock::given(method("POST"))
                .and(path_matcher("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(body, EVIDENCE_JWS_MEDIA_TYPE),
                )
                .expect(1)
                .mount(&server),
        );

        let response = client
            .call_method1("send", (&prepared,))
            .expect("the stub answers the one send this request allows");
        let verified = client
            .call_method1("verify", (&prepared, &response))
            .expect("the response verifies");

        let verified_evidence = verified.getattr("evidence").expect("evidence is exposed");
        let verified_nonce: String = verified_evidence
            .get_item("requestNonce")
            .expect("requestNonce is present")
            .extract()
            .expect("requestNonce is a string");
        assert_eq!(verified_nonce, nonce);

        let operation: Option<String> = verified
            .getattr("operation")
            .expect("operation is exposed")
            .extract()
            .expect("operation is a string or None");
        assert_eq!(operation, None);

        let pinned = verified
            .getattr("pinned_subject_expectations")
            .expect("pinned_subject_expectations is exposed");
        assert_eq!(pinned.len().expect("it supports len()"), 1);
        let first = pinned.get_item(0).expect("one entry exists");
        let role: String = first.get_item("role").unwrap().extract().unwrap();
        let binding: String = first.get_item("binding").unwrap().extract().unwrap();
        assert_eq!(role, "subject");
        assert_eq!(binding, subject_binding);
    });
}

#[test]
fn request_and_verify_performs_the_same_round_trip() {
    let signing_key = fresh_signing_key();
    let trusted_jwks = trusted_jwks_json(&signing_key);
    let subject_binding = format!("urn:evidence:subject:v1_{}", "B".repeat(43));

    let runtime = tokio::runtime::Runtime::new().expect("the stub's runtime starts");
    let server = runtime.block_on(MockServer::start());
    let base_url = server.uri();

    Python::attach(|py| {
        let module = evidence_client_module(py);
        let client_class = module.getattr("EvidenceClient").expect("the class exists");
        let client = client_class
            .call1((
                base_url.as_str(),
                python_json(py, &trusted_jwks),
                Vec::<String>::new(),
                "test-token",
            ))
            .expect("the client is constructed");

        let prepared = client
            .call_method1("prepare", (python_json(py, &request_spec_json()),))
            .expect("the specification is accepted");
        let nonce: String = prepared
            .getattr("request_nonce")
            .expect("the nonce getter exists")
            .extract()
            .expect("the nonce is a string");

        let body = sign(&evidence_for(&nonce, &subject_binding), &signing_key);
        runtime.block_on(
            Mock::given(method("POST"))
                .and(path_matcher("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(body, EVIDENCE_JWS_MEDIA_TYPE),
                )
                .expect(1)
                .mount(&server),
        );

        let verified = client
            .call_method1("request_and_verify", (&prepared,))
            .expect("the one-call round trip succeeds");

        let verified_evidence = verified.getattr("evidence").expect("evidence is exposed");
        let verified_nonce: String = verified_evidence
            .get_item("requestNonce")
            .expect("requestNonce is present")
            .extract()
            .expect("requestNonce is a string");
        assert_eq!(verified_nonce, nonce);
    });
}

#[test]
fn a_second_send_is_refused_without_reaching_the_deployment() {
    let signing_key = fresh_signing_key();
    let trusted_jwks = trusted_jwks_json(&signing_key);
    let subject_binding = format!("urn:evidence:subject:v1_{}", "C".repeat(43));

    let runtime = tokio::runtime::Runtime::new().expect("the stub's runtime starts");
    let server = runtime.block_on(MockServer::start());
    let base_url = server.uri();

    Python::attach(|py| {
        let module = evidence_client_module(py);
        let client_class = module.getattr("EvidenceClient").expect("the class exists");
        let client = client_class
            .call1((
                base_url.as_str(),
                python_json(py, &trusted_jwks),
                Vec::<String>::new(),
                "test-token",
            ))
            .expect("the client is constructed");

        let prepared = client
            .call_method1("prepare", (python_json(py, &request_spec_json()),))
            .expect("the specification is accepted");
        let nonce: String = prepared
            .getattr("request_nonce")
            .expect("the nonce getter exists")
            .extract()
            .expect("the nonce is a string");

        let body = sign(&evidence_for(&nonce, &subject_binding), &signing_key);
        // `.expect(1)`: if the second, rejected `send` below reached the
        // network after all, the stub would see a second request and the
        // mock's own cardinality check would fail when `server` drops.
        runtime.block_on(
            Mock::given(method("POST"))
                .and(path_matcher("/v1/evidence"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(body, EVIDENCE_JWS_MEDIA_TYPE),
                )
                .expect(1)
                .mount(&server),
        );

        client
            .call_method1("send", (&prepared,))
            .expect("the first send happens");

        let error = client
            .call_method1("send", (&prepared,))
            .expect_err("a second send with the same prepared request is refused locally");
        let kind: String = error
            .value(py)
            .getattr("kind")
            .expect("the exception carries a kind")
            .extract()
            .expect("kind is a string");
        assert_eq!(kind, "configuration");
    });
}

/// The companion negative case for the golden fixture: signed with a fixed,
/// canonical nonce, so checking it against a freshly prepared request (whose
/// nonce is different on every run) has to fail verification, not just
/// happen to succeed by construction.
///
/// Verified through `verify_as_of` at an instant inside the fixture's own
/// validity window, so the nonce mismatch stays the reason it fails. Against
/// the wall clock, the fixture would eventually expire and this case would go
/// on passing for a reason it was never written to prove.
#[test]
fn a_stale_fixture_response_fails_verification_against_a_live_prepared_request() {
    let fixtures_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"));
    let trusted_jwks: serde_json::Value = serde_json::from_slice(
        &fs::read(fixtures_dir.join("jwks.json")).expect("the JWKS fixture exists"),
    )
    .expect("the JWKS fixture parses");
    let stale_response_body =
        fs::read(fixtures_dir.join("response.jws.json")).expect("the response fixture exists");

    let runtime = tokio::runtime::Runtime::new().expect("the stub's runtime starts");
    let server = runtime.block_on(MockServer::start());
    let base_url = server.uri();
    runtime.block_on(
        Mock::given(method("POST"))
            .and(path_matcher("/v1/evidence"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(stale_response_body, EVIDENCE_JWS_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server),
    );

    // Mirrors the golden fixture's own policy document (see
    // `tests/golden_fixture.rs`) in every field except the nonce, which
    // `prepare()` mints fresh below: the fixture's response was signed for
    // its own canonical, fixed nonce, never this one.
    let spec_json = serde_json::json!({
        "response_format": "signed-jws",
        "requirement": "urn:example:requirement:v1",
        "purpose": "example-purpose",
        "audience": "urn:example:audience",
        "evidence_type": "urn:example:evidence-type:v1",
        "issued_by": "urn:example:issuer",
        "provided_by": "urn:example:provider",
        "configuration_revision": format!("sha256:{}", "0".repeat(64)),
        "expected_assurance_profile": "local",
        "subjects": [
            { "role": "subject", "selector_profile": "national-id" }
        ],
        "expected_outputs": [
            { "concept": "urn:example:concept:status-holds", "form": "boolean" }
        ],
        "maximum_assertion_lifetime_seconds": 30 * 24 * 60 * 60_i64,
        "clock_skew_seconds": 30,
        "subject_expectations": "accept_first_use",
    });

    Python::attach(|py| {
        let module = evidence_client_module(py);
        let client_class = module.getattr("EvidenceClient").expect("the class exists");
        let client = client_class
            .call1((
                base_url.as_str(),
                python_json(py, &trusted_jwks),
                Vec::<String>::new(),
                "test-token",
            ))
            .expect("the client is constructed");

        let prepared = client
            .call_method1("prepare", (python_json(py, &spec_json),))
            .expect("the specification is accepted");
        let response = client
            .call_method1("send", (&prepared,))
            .expect("the stub answers, with its stale fixture body");

        let as_of = FIXTURE_ISSUED_AT
            .parse::<DateTime<Utc>>()
            .expect("the fixture instant parses")
            + ChronoDuration::days(1);
        let error = client
            .call_method1(
                "verify_as_of",
                (&prepared, &response, as_of.timestamp() as f64),
            )
            .expect_err("a response signed for a different nonce fails verification");
        let kind: String = error
            .value(py)
            .getattr("kind")
            .expect("the exception carries a kind")
            .extract()
            .expect("kind is a string");
        assert_eq!(kind, "verification");
        let code: String = error
            .value(py)
            .getattr("code")
            .expect("the exception carries a code")
            .extract()
            .expect("code is a string");
        // The one generic class every failed policy comparison reports, the
        // expected nonce included. `time` here would mean the fixture expired
        // instead, which is the outcome the pinned instant rules out.
        assert_eq!(code, "policy");
    });
}
