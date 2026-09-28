#![cfg(unix)]

//! `evidencectl jwk from-pem` converts one PEM public key into the exact public
//! JWK the runtime and `jwks` accept. Every key below is generated inside the
//! test, by the same crypto crate the runtime validates JWKs with, so the
//! expected JWK is that crate's own public half rather than a hand-written
//! fixture.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output, Stdio},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use pkcs8::{
    der::{
        asn1::{BitString, UintRef},
        pem::LineEnding,
        Any, Encode as _,
    },
    spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned},
};
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

fn decode(member: Option<&str>) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(member.expect("member present"))
        .expect("base64url member")
}

fn pem(label: &str, der: &[u8]) -> String {
    pkcs8::der::pem::encode_string(label, LineEnding::LF, der).expect("PEM encodes")
}

fn spki_pem(algorithm: AlgorithmIdentifierOwned, key: &[u8]) -> String {
    let spki = SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: BitString::from_bytes(key).expect("bit string"),
    };
    pem("PUBLIC KEY", &spki.to_der().expect("SPKI encodes"))
}

/// The SubjectPublicKeyInfo PEM a Transit key export carries for an EC key.
fn ec_public_pem(jwk: &PrivateJwk, curve: ObjectIdentifier) -> String {
    let mut point = vec![0x04];
    point.extend(decode(jwk.x.as_deref()));
    point.extend(decode(jwk.y.as_deref()));
    spki_pem(
        AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&curve).expect("curve parameter")),
        },
        &point,
    )
}

fn rsa_public_der(jwk: &PrivateJwk) -> Vec<u8> {
    let n = decode(jwk.n.as_deref());
    let e = decode(jwk.e.as_deref());
    pkcs1::RsaPublicKey {
        modulus: UintRef::new(&n).expect("modulus"),
        public_exponent: UintRef::new(&e).expect("exponent"),
    }
    .to_der()
    .expect("PKCS#1 public key encodes")
}

fn rsa_public_pem(jwk: &PrivateJwk) -> String {
    spki_pem(
        AlgorithmIdentifierOwned {
            oid: RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        &rsa_public_der(jwk),
    )
}

fn rsa_private_der(jwk: &PrivateJwk) -> Vec<u8> {
    let members: Vec<Vec<u8>> = [
        &jwk.n, &jwk.e, &jwk.d, &jwk.p, &jwk.q, &jwk.dp, &jwk.dq, &jwk.qi,
    ]
    .iter()
    .map(|member| decode(member.as_deref()))
    .collect();
    let uint = |index: usize| UintRef::new(&members[index]).expect("RSA member");
    pkcs1::RsaPrivateKey {
        modulus: uint(0),
        public_exponent: uint(1),
        private_exponent: uint(2),
        prime1: uint(3),
        prime2: uint(4),
        exponent1: uint(5),
        exponent2: uint(6),
        coefficient: uint(7),
        other_prime_infos: None,
    }
    .to_der()
    .expect("PKCS#1 private key encodes")
}

/// The generated key's public half, with the `kid` its generator assigned
/// (the RFC 7638 thumbprint), as the JSON value `from-pem` must reproduce.
fn expected_public(jwk: &PrivateJwk, alg: &str) -> serde_json::Value {
    let mut public = serde_json::to_value(jwk.public()).expect("public JWK serializes");
    public["alg"] = serde_json::Value::String(alg.to_owned());
    public
}

fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).expect("write input");
    path
}

fn from_pem(arguments: &[&str], input: &Path) -> Output {
    evidencectl()
        .args(["jwk", "from-pem"])
        .args(arguments)
        .arg(input)
        .output()
        .expect("run evidencectl jwk from-pem")
}

#[test]
fn converts_an_ec_p256_public_key_to_the_exact_es256_jwk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("P-256 key");
    let input = write(dir.path(), "signing.pem", &ec_public_pem(&key, PRIME256V1));

    let output = from_pem(&[], &input);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let jwk: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("JWK on stdout");
    assert_eq!(jwk, expected_public(&key, "ES256"));
    let members: Vec<&str> = jwk
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        members.len(),
        6,
        "exactly kty, crv, x, y, alg, kid: {members:?}"
    );
    assert_eq!(jwk["kid"].as_str().expect("kid").len(), 43);
}

#[test]
fn writes_the_jwk_under_its_thumbprint_into_an_output_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("P-256 key");
    let input = write(dir.path(), "signing.pem", &ec_public_pem(&key, PRIME256V1));
    let out_dir = dir.path().join("public-keys");
    fs::create_dir(&out_dir).expect("output directory");

    let output = evidencectl()
        .args(["--format", "json", "jwk", "from-pem", "--output-dir"])
        .arg(&out_dir)
        .arg(&input)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let kid = key.kid.clone().expect("generated kid");
    let written = out_dir.join(format!("{kid}.jwk.json"));
    let report: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("JSON report");
    assert_eq!(report["kid"], kid.as_str());
    assert_eq!(report["alg"], "ES256");
    assert_eq!(report["files"][0], written.display().to_string());

    let contents = fs::read_to_string(&written).expect("written JWK");
    assert!(contents.ends_with('\n'));
    let jwk: serde_json::Value = serde_json::from_str(&contents).expect("JWK file");
    assert_eq!(jwk, expected_public(&key, "ES256"));
    assert_eq!(
        fs::metadata(&written).expect("stat").permissions().mode() & 0o777,
        0o644
    );

    // A second run refuses to replace it silently, and --force replaces it.
    let refused = evidencectl()
        .args(["jwk", "from-pem", "--output-dir"])
        .arg(&out_dir)
        .arg(&input)
        .output()
        .expect("run evidencectl");
    assert!(!refused.status.success());
    assert!(
        stderr_of(&refused).contains("--force"),
        "{}",
        stderr_of(&refused)
    );
    let forced = evidencectl()
        .args(["jwk", "from-pem", "--force", "--output-dir"])
        .arg(&out_dir)
        .arg(&input)
        .output()
        .expect("run evidencectl");
    assert!(forced.status.success(), "{}", stderr_of(&forced));
}

#[test]
fn reads_the_pem_from_standard_input() {
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("P-256 key");
    let mut child = evidencectl()
        .args(["jwk", "from-pem", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn evidencectl");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(ec_public_pem(&key, PRIME256V1).as_bytes())
        .expect("write PEM");
    let output = child.wait_with_output().expect("evidencectl exits");
    assert!(output.status.success(), "{}", stderr_of(&output));
    let jwk: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("JWK");
    assert_eq!(jwk, expected_public(&key, "ES256"));
}

#[test]
fn converts_an_ec_p384_public_key_to_an_es384_jwk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("P-384 key");
    let input = write(dir.path(), "assertion.pem", &ec_public_pem(&key, SECP384R1));

    let output = from_pem(&[], &input);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let jwk: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("JWK");
    assert_eq!(jwk, expected_public(&key, "ES384"));
}

#[test]
fn converts_an_rsa_public_key_with_the_named_algorithm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Rs384).expect("RSA key");
    let spki = write(dir.path(), "rsa.pem", &rsa_public_pem(&key));
    let pkcs1 = write(
        dir.path(),
        "rsa-pkcs1.pem",
        &pem("RSA PUBLIC KEY", &rsa_public_der(&key)),
    );

    for (input, alg) in [(&spki, "RS384"), (&pkcs1, "RS256")] {
        let output = from_pem(&["--alg", &alg.to_ascii_lowercase()], input);
        assert!(output.status.success(), "{}", stderr_of(&output));
        let jwk: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("JWK");
        assert_eq!(jwk, expected_public(&key, alg), "{}", input.display());
    }
}

#[test]
fn an_rsa_key_needs_an_explicit_algorithm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Rs384).expect("RSA key");
    let input = write(dir.path(), "rsa.pem", &rsa_public_pem(&key));

    let output = from_pem(&[], &input);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--alg rs256") && stderr.contains("rs384"),
        "{stderr}"
    );
}

#[test]
fn refuses_an_algorithm_the_key_type_cannot_carry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("P-256 key");
    let input = write(dir.path(), "signing.pem", &ec_public_pem(&key, PRIME256V1));

    let output = from_pem(&["--alg", "rs256"], &input);
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("EC P-256") && stderr.contains("es256"),
        "{stderr}"
    );
}

#[test]
fn refuses_private_keys_without_printing_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Rs384).expect("RSA key");
    let pkcs1_der = rsa_private_der(&key);
    let pkcs8_der = pkcs8::PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: RSA_ENCRYPTION,
            parameters: None,
        },
        private_key: &pkcs1_der,
        public_key: None,
    }
    .to_der()
    .expect("PKCS#8 encodes");
    let pkcs1_pem = pem("RSA PRIVATE KEY", &pkcs1_der);
    let pkcs8_pem = pem("PRIVATE KEY", &pkcs8_der);
    // A private key pasted after a public one is refused too, not skipped.
    let public_then_private = format!("{}{pkcs8_pem}", rsa_public_pem(&key));

    for (name, contents) in [
        ("pkcs1.pem", &pkcs1_pem),
        ("pkcs8.pem", &pkcs8_pem),
        ("both.pem", &public_then_private),
    ] {
        let input = write(dir.path(), name, contents);
        let output = from_pem(&["--alg", "rs384"], &input);
        assert!(!output.status.success(), "{name} was accepted");
        assert!(output.stdout.is_empty(), "{name} wrote to stdout");
        let stderr = stderr_of(&output);
        assert!(stderr.contains("private key"), "{name}: {stderr}");
        let body_line = pkcs8_pem.lines().nth(1).expect("PEM body line");
        let pkcs1_body_line = pkcs1_pem.lines().nth(1).expect("PEM body line");
        assert!(
            !stderr.contains(body_line) && !stderr.contains(pkcs1_body_line),
            "{name}: the error echoed key material"
        );
    }
}

#[test]
fn refuses_unsupported_key_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A P-521 point is well-formed SPKI the platform has no JWK algorithm for.
    let mut p521_point = vec![0x04];
    p521_point.extend([0x01; 132]);
    let p521 = spki_pem(
        AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&SECP521R1).expect("curve parameter")),
        },
        &p521_point,
    );
    // Ed25519 is a JWK type the platform knows, but no Evidence public key
    // file carries one, so the converter does not offer it.
    let ed25519 = spki_pem(
        AlgorithmIdentifierOwned {
            oid: ED25519,
            parameters: None,
        },
        &[0x11; 32],
    );
    let certificate = pem("CERTIFICATE", &[0x30, 0x00]);

    for (name, contents, expected) in [
        ("p521.pem", p521.as_str(), "unsupported EC curve"),
        ("ed25519.pem", ed25519.as_str(), "unsupported key type"),
        ("certificate.pem", certificate.as_str(), "CERTIFICATE"),
    ] {
        let input = write(dir.path(), name, contents);
        let output = from_pem(&[], &input);
        assert!(!output.status.success(), "{name} was accepted");
        assert!(output.stdout.is_empty(), "{name} wrote to stdout");
        let stderr = stderr_of(&output);
        assert!(stderr.contains(expected), "{name}: {stderr}");
    }
}

#[test]
fn refuses_input_that_is_not_a_pem_public_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("P-256 key");
    let valid = ec_public_pem(&key, PRIME256V1);
    let mut body: Vec<&str> = valid.lines().collect();
    body[1] = "not base64 at all!";
    let corrupted = body.join("\n");
    // An off-curve point decodes as SPKI but is not a usable key.
    let mut off_curve = vec![0x04];
    off_curve.extend([0x01; 64]);
    let off_curve = spki_pem(
        AlgorithmIdentifierOwned {
            oid: EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&PRIME256V1).expect("curve parameter")),
        },
        &off_curve,
    );

    for (name, contents, expected) in [
        ("garbage.pem", "this is not a key\n", "not a PEM"),
        ("empty.pem", "", "not a PEM"),
        (
            "jwk.json",
            &serde_json::to_string(&key.public()).expect("JWK"),
            "not a PEM",
        ),
        ("corrupted.pem", &corrupted, "not a valid PEM"),
        (
            "off-curve.pem",
            &off_curve,
            "not a valid EC P-256 public key",
        ),
    ] {
        let input = write(dir.path(), name, contents);
        let output = from_pem(&[], &input);
        assert!(!output.status.success(), "{name} was accepted");
        assert!(output.stdout.is_empty(), "{name} wrote to stdout");
        let stderr = stderr_of(&output);
        assert!(stderr.contains(expected), "{name}: {stderr}");
    }
}
