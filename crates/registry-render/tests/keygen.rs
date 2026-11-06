// SPDX-License-Identifier: Apache-2.0

//! `registry-render keygen` writes a seal key and its certificate request,
//! checked with `openssl`, the tool a certificate authority's operator uses.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use registry_platform_crypto::document_signature::test_support::{
    pem_block, TestPki, TestSeal, TestTransit,
};
use registry_platform_crypto::SigningAlgorithm;

/// A passphrase for the encrypted test keys this file generates.
const TEST_PASSPHRASE: &str = "pass:test-only-passphrase";

fn registry_render() -> Command {
    Command::new(env!("CARGO_BIN_EXE_registry-render"))
}

fn fresh_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let home = dir.path().canonicalize().expect("canonical home");
    (dir, home)
}

fn openssl(args: &[&str], paths: &[&Path]) -> Output {
    let mut command = Command::new("openssl");
    let mut paths = paths.iter();
    for arg in args {
        if *arg == "{}" {
            command.arg(paths.next().expect("a path for each placeholder"));
        } else {
            command.arg(arg);
        }
    }
    let output = command.output().expect("openssl starts");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn keygen(home: &Path, extra: &[&str]) -> Output {
    registry_render()
        .arg("keygen")
        .arg("--key")
        .arg(home.join("seal.jwk"))
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .args(extra)
        .output()
        .expect("run registry-render keygen")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The private JWK the key file holds.
fn key_file(home: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(home.join("seal.jwk")).expect("the key file reads"))
        .expect("the key file is JSON")
}

/// Assert that `output` printed nothing of the private key in `jwk`.
fn printed_no_key_material(output: &Output, jwk: &serde_json::Value) {
    let printed = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(!printed.contains("\"d\""), "{printed}");
    for member in ["d", "p", "q", "dp", "dq", "qi"] {
        if let Some(value) = jwk[member].as_str() {
            assert!(!printed.contains(value), "{member} printed: {printed}");
        }
    }
}

/// `openssl req -verify` over the request, and its subject in RFC 2253 order.
fn verified_subject(csr: &Path) -> String {
    let output = openssl(
        &[
            "req", "-in", "{}", "-noout", "-verify", "-subject", "-nameopt", "RFC2253",
        ],
        &[csr],
    );
    let all = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(all.contains("verify OK"), "{all}");
    text(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("subject="))
        .expect("openssl prints the subject")
        .trim()
        .to_owned()
}

/// The PEM public key `openssl` reads from a request or a private key.
fn public_key_of(args: &[&str], path: &Path) -> String {
    text(&openssl(args, &[path]).stdout)
}

#[test]
fn keygen_writes_an_owner_only_key_and_a_request_openssl_verifies() {
    let (_dir, home) = fresh_home();
    let output = keygen(
        &home,
        &["--organization", "Ministry of Health", "--country", "FR"],
    );
    assert!(output.status.success(), "{}", text(&output.stderr));

    let mode = std::fs::metadata(home.join("seal.jwk"))
        .expect("the key file exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the key file is owner-only");
    let jwk = key_file(&home);
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert_eq!(jwk["alg"], "ES256");
    assert!(jwk["d"].is_string(), "the file holds the private key");
    printed_no_key_material(&output, &jwk);

    let stdout = text(&output.stdout);
    assert!(
        stdout.contains(&home.join("seal.jwk").display().to_string()),
        "{stdout}"
    );
    assert!(
        stdout.contains(&home.join("seal.csr").display().to_string()),
        "{stdout}"
    );
    assert!(
        stdout.contains("CA:FALSE"),
        "the next step names the leaf it needs: {stdout}"
    );

    assert_eq!(
        verified_subject(&home.join("seal.csr")),
        "CN=Civil Registry Seal,O=Ministry of Health,C=FR"
    );
}

#[test]
fn keygen_writes_each_seal_algorithm() {
    for (algorithm, kty, alg) in [
        ("es384", "EC", "ES384"),
        ("rs256", "RSA", "RS256"),
        ("rs384", "RSA", "RS384"),
    ] {
        let (_dir, home) = fresh_home();
        let output = keygen(&home, &["--algorithm", algorithm]);
        assert!(
            output.status.success(),
            "{algorithm}: {}",
            text(&output.stderr)
        );
        let jwk = key_file(&home);
        assert_eq!(
            (jwk["kty"].as_str(), jwk["alg"].as_str()),
            (Some(kty), Some(alg))
        );
        printed_no_key_material(&output, &jwk);
        assert_eq!(
            verified_subject(&home.join("seal.csr")),
            "CN=Civil Registry Seal"
        );
    }
}

#[test]
fn keygen_never_overwrites_and_leaves_no_half_pair() {
    let (_dir, home) = fresh_home();
    std::fs::write(home.join("seal.jwk"), "an existing key\n").unwrap();
    let output = keygen(&home, &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("already exists"),
        "{}",
        text(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(home.join("seal.jwk")).unwrap(),
        "an existing key\n"
    );
    assert!(!home.join("seal.csr").exists());

    let (_dir, home) = fresh_home();
    std::fs::write(home.join("seal.csr"), "an existing request\n").unwrap();
    let output = keygen(&home, &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("already exists"),
        "{}",
        text(&output.stderr)
    );
    assert!(
        !home.join("seal.jwk").exists(),
        "no key without its request"
    );
    assert_eq!(
        std::fs::read_to_string(home.join("seal.csr")).unwrap(),
        "an existing request\n"
    );

    let (_dir, home) = fresh_home();
    let output = registry_render()
        .arg("keygen")
        .arg("--key")
        .arg(home.join("seal.jwk"))
        .arg("--csr")
        .arg(home.join("seal.jwk"))
        .args(["--common-name", "Civil Registry Seal"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("same file"),
        "{}",
        text(&output.stderr)
    );
    assert!(!home.join("seal.jwk").exists());
}

#[test]
fn keygen_refuses_a_bad_subject_before_writing_anything() {
    for extra in [
        &["--country", "fr"][..],
        &["--country", "FRA"][..],
        &["--organization", ""][..],
    ] {
        let (_dir, home) = fresh_home();
        let output = keygen(&home, extra);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{extra:?}: {}",
            text(&output.stderr)
        );
        assert!(!home.join("seal.jwk").exists(), "{extra:?}");
        assert!(!home.join("seal.csr").exists(), "{extra:?}");
    }
}

#[test]
fn keygen_imports_an_unencrypted_pkcs8_key_and_requests_a_certificate_for_it() {
    for (genpkey, algorithm, kty, alg) in [
        (
            &["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"][..],
            None,
            "EC",
            "ES384",
        ),
        (
            &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"][..],
            None,
            "RSA",
            "RS256",
        ),
        (
            &["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"][..],
            Some("rs384"),
            "RSA",
            "RS384",
        ),
    ] {
        let (_dir, home) = fresh_home();
        let pem = home.join("existing-key.pem");
        let mut args = vec!["genpkey"];
        args.extend_from_slice(genpkey);
        args.extend_from_slice(&["-out", "{}"]);
        openssl(&args, &[&pem]);
        let mut extra = vec!["--from-pem", pem.to_str().unwrap()];
        if let Some(algorithm) = algorithm {
            extra.extend_from_slice(&["--algorithm", algorithm]);
        }
        let output = keygen(&home, &extra);
        assert!(output.status.success(), "{alg}: {}", text(&output.stderr));
        let jwk = key_file(&home);
        assert_eq!(
            (jwk["kty"].as_str(), jwk["alg"].as_str()),
            (Some(kty), Some(alg))
        );
        printed_no_key_material(&output, &jwk);
        verified_subject(&home.join("seal.csr"));
        assert_eq!(
            public_key_of(
                &["req", "-in", "{}", "-noout", "-pubkey"],
                &home.join("seal.csr")
            ),
            public_key_of(&["pkey", "-in", "{}", "-pubout"], &pem),
            "the request certifies the imported key"
        );
    }
}

#[test]
fn keygen_refuses_an_algorithm_the_imported_key_cannot_sign() {
    let (_dir, home) = fresh_home();
    let pem = home.join("existing-key.pem");
    openssl(
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "{}",
        ],
        &[&pem],
    );
    let output = keygen(
        &home,
        &["--from-pem", pem.to_str().unwrap(), "--algorithm", "rs256"],
    );
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    assert!(
        text(&output.stderr).contains("P-256"),
        "{}",
        text(&output.stderr)
    );
    assert!(!home.join("seal.jwk").exists());
    assert!(!home.join("seal.csr").exists());
}

/// Run `keygen --from-pem` on `pem`, expect a refusal naming `conversion`,
/// then run that conversion as printed (with the test passphrase) and import
/// what it writes.
fn refused_then_converted(home: &Path, pem: &Path, conversion: &str) {
    let output = keygen(home, &["--from-pem", pem.to_str().unwrap()]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let printed = format!("{conversion} -in {} ", pem.display());
    assert!(stderr.contains(&printed), "{stderr}");
    assert!(stderr.contains("-out seal-key.pem"), "{stderr}");
    assert!(!stderr.contains("BEGIN"), "{stderr}");
    assert!(!home.join("seal.jwk").exists());
    assert!(!home.join("seal.csr").exists());

    let converted = home.join("seal-key.pem");
    let mut args: Vec<&str> = conversion.split(' ').skip(1).collect();
    args.extend_from_slice(&["-in", "{}", "-passin", TEST_PASSPHRASE, "-out", "{}"]);
    if conversion.contains("pkcs12") {
        args.extend_from_slice(&["-nocerts", "-nodes"]);
    }
    openssl(&args, &[pem, &converted]);
    let output = keygen(home, &["--from-pem", converted.to_str().unwrap()]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    verified_subject(&home.join("seal.csr"));
}

#[test]
fn keygen_refuses_encrypted_legacy_and_pkcs12_keys_with_the_conversion_that_fixes_them() {
    let (_dir, home) = fresh_home();
    let encrypted = home.join("encrypted.pem");
    openssl(
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-aes-256-cbc",
            "-pass",
            TEST_PASSPHRASE,
            "-out",
            "{}",
        ],
        &[&encrypted],
    );
    assert!(std::fs::read_to_string(&encrypted)
        .unwrap()
        .contains("ENCRYPTED PRIVATE KEY"));
    refused_then_converted(&home, &encrypted, "openssl pkey");

    let (_dir, home) = fresh_home();
    let legacy = home.join("sec1.pem");
    openssl(
        &[
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
            "{}",
        ],
        &[&legacy],
    );
    assert!(std::fs::read_to_string(&legacy)
        .unwrap()
        .contains("EC PRIVATE KEY"));
    refused_then_converted(&home, &legacy, "openssl pkey");

    let (_dir, home) = fresh_home();
    let key = home.join("p12-key.pem");
    let certificate = home.join("p12-certificate.pem");
    let bundle = home.join("seal.p12");
    openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=PKCS 12 test",
            "-keyout",
            "{}",
            "-out",
            "{}",
        ],
        &[&key, &certificate],
    );
    openssl(
        &[
            "pkcs12",
            "-export",
            "-inkey",
            "{}",
            "-in",
            "{}",
            "-passout",
            TEST_PASSPHRASE,
            "-out",
            "{}",
        ],
        &[&key, &certificate, &bundle],
    );
    refused_then_converted(&home, &bundle, "openssl pkcs12");
}

// ----- A Transit-held seal key -----

/// The Transit key the proxy serves and keygen names.
const TRANSIT_MOUNT: &str = "transit";
const TRANSIT_KEY: &str = "render-seal";
const TRANSIT_KEY_VERSION: u32 = 3;

/// A seal whose key a Transit proxy at `home/transit.sock` would hold.
fn transit_seal() -> TestSeal {
    TestPki::generate()
        .expect("test pki")
        .issue_seal(SigningAlgorithm::Es256)
        .expect("test seal")
}

fn start_transit(home: &Path, seal: &TestSeal) -> TestTransit {
    TestTransit::start(
        &home.join("transit.sock"),
        TRANSIT_MOUNT,
        TRANSIT_KEY,
        TRANSIT_KEY_VERSION,
        seal.private_jwk(),
    )
    .expect("test Transit proxy")
}

/// `keygen` for the Transit key at `home/transit.sock`, writing only the
/// request.
fn transit_keygen(home: &Path, extra: &[&str]) -> Output {
    registry_render()
        .arg("keygen")
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .arg("--transit-unix-socket-path")
        .arg(home.join("transit.sock"))
        .args(["--transit-mount", TRANSIT_MOUNT])
        .args(["--transit-key-name", TRANSIT_KEY])
        .args(["--transit-key-version", &TRANSIT_KEY_VERSION.to_string()])
        .args(extra)
        .output()
        .expect("run registry-render keygen")
}

#[test]
fn keygen_requests_a_certificate_for_a_transit_key_and_writes_no_key_file() {
    let (_dir, home) = fresh_home();
    let seal = transit_seal();
    let transit = start_transit(&home, &seal);
    let output = transit_keygen(&home, &["--organization", "Ministry of Health"]);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(
        transit.signatures(),
        2,
        "a self-test signature and the request's"
    );

    let csr = home.join("seal.csr");
    assert_eq!(
        verified_subject(&csr),
        "CN=Civil Registry Seal,O=Ministry of Health"
    );
    let certificate = home.join("seal.pem");
    std::fs::write(
        &certificate,
        pem_block("CERTIFICATE", seal.certificate_der()),
    )
    .unwrap();
    assert_eq!(
        public_key_of(&["req", "-in", "{}", "-noout", "-pubkey"], &csr),
        public_key_of(&["x509", "-in", "{}", "-noout", "-pubkey"], &certificate),
        "the request certifies the Transit key"
    );
    let mut entries: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        ["seal.csr", "seal.pem", "transit.sock"],
        "no key file"
    );

    let stdout = text(&output.stdout);
    for expected in [
        "transit/render-seal version 3",
        "signer.type: transit",
        "trust: production",
    ] {
        assert!(stdout.contains(expected), "{expected}: {stdout}");
    }
    printed_no_key_material(&output, &serde_json::json!({"d": seal.private_jwk().d}));
}

#[test]
fn keygen_refuses_a_transit_key_it_cannot_use_before_writing_anything() {
    let (_dir, home) = fresh_home();
    let seal = transit_seal();
    let exportable = TestTransit::start_with(
        &home.join("transit.sock"),
        TRANSIT_MOUNT,
        TRANSIT_KEY,
        TRANSIT_KEY_VERSION,
        seal.private_jwk(),
        |metadata| metadata["data"]["exportable"] = serde_json::Value::Bool(true),
    )
    .expect("test Transit proxy");
    let output = transit_keygen(&home, &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("--transit-key-name"), "{stderr}");
    assert_eq!(exportable.signatures(), 0);
    assert!(!home.join("seal.csr").exists());
    drop(exportable);

    // A version the key does not have names the version flag.
    let transit = TestTransit::start(
        &home.join("other.sock"),
        TRANSIT_MOUNT,
        TRANSIT_KEY,
        TRANSIT_KEY_VERSION - 1,
        seal.private_jwk(),
    )
    .expect("test Transit proxy");
    let output = registry_render()
        .arg("keygen")
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .arg("--transit-unix-socket-path")
        .arg(transit.socket_path())
        .args(["--transit-mount", TRANSIT_MOUNT])
        .args(["--transit-key-name", TRANSIT_KEY])
        .args(["--transit-key-version", &TRANSIT_KEY_VERSION.to_string()])
        .output()
        .expect("run registry-render keygen");
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("--transit-key-version"), "{stderr}");
    assert!(!home.join("seal.csr").exists());
}

#[test]
fn keygen_names_the_socket_flag_when_no_transit_proxy_answers() {
    let (_dir, home) = fresh_home();
    let output = transit_keygen(&home, &[]);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("did not answer"), "{stderr}");
    assert!(stderr.contains("--transit-unix-socket-path"), "{stderr}");
    assert!(!home.join("seal.csr").exists());
}

#[test]
fn keygen_takes_either_a_key_file_or_a_transit_key() {
    let (_dir, home) = fresh_home();
    for (label, extra) in [
        ("a key file too", &["--key", "seal.jwk"][..]),
        ("an algorithm", &["--algorithm", "es384"][..]),
        ("a PEM key", &["--from-pem", "seal.pem"][..]),
    ] {
        let output = transit_keygen(&home, extra);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{label}: {}",
            text(&output.stderr)
        );
        assert!(
            text(&output.stderr).contains("cannot be used with"),
            "{label}: {}",
            text(&output.stderr)
        );
    }
    let without_key = registry_render()
        .arg("keygen")
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .output()
        .unwrap();
    assert_eq!(without_key.status.code(), Some(2));
    assert!(
        text(&without_key.stderr).contains("--key"),
        "{}",
        text(&without_key.stderr)
    );
    let partial = registry_render()
        .arg("keygen")
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .arg("--transit-unix-socket-path")
        .arg(home.join("transit.sock"))
        .output()
        .unwrap();
    assert_eq!(partial.status.code(), Some(2));
    assert!(
        text(&partial.stderr).contains("--transit-mount"),
        "{}",
        text(&partial.stderr)
    );
    let nested = registry_render()
        .arg("keygen")
        .arg("--csr")
        .arg(home.join("seal.csr"))
        .args(["--common-name", "Civil Registry Seal"])
        .arg("--transit-unix-socket-path")
        .arg(home.join("transit.sock"))
        .args(["--transit-mount", "transit/render"])
        .args(["--transit-key-name", TRANSIT_KEY])
        .args(["--transit-key-version", "1"])
        .output()
        .unwrap();
    assert_eq!(nested.status.code(), Some(2));
    assert!(
        text(&nested.stderr).contains("local id"),
        "the mount is a local id, as in the runtime file: {}",
        text(&nested.stderr)
    );
    assert!(!home.join("seal.csr").exists());
}
