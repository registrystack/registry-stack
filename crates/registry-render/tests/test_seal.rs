// SPDX-License-Identifier: Apache-2.0
//! The local test-signing command returns a signed PDF and its public trust root together.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

#[path = "common/signed_pdf.rs"]
mod signed_pdf;
use signed_pdf::{read_signed_file, SignedFile};

fn bundle() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sealed-notice")
}

fn run(bundle: &Path, document: &str, data: &Path, output: &Path) -> Output {
    run_with_posture(
        bundle,
        document,
        data,
        output,
        &["--posture", "development"],
    )
}

fn run_with_posture(
    bundle: &Path,
    document: &str,
    data: &Path,
    output: &Path,
    flags: &[&str],
) -> Output {
    seal_command(bundle, document, data, output)
        .args(flags)
        .output()
        .expect("run registry-render")
}

fn seal_command(bundle: &Path, document: &str, data: &Path, output: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-render"));
    command
        .env_remove("REGISTRY_STACK_POSTURE")
        .arg("test-seal")
        .arg("--bundle")
        .arg(bundle)
        .args(["--type", document])
        .arg("--data")
        .arg(data)
        .arg("--output")
        .arg(output)
        .args(["--issued-at", "2026-11-24T09:00:00Z", "--format", "json"]);
    command
}

#[test]
fn test_seal_accepts_development_from_environment() {
    let (dir, data) = example();
    let destination = dir.path().join("specimen");
    let result = seal_command(&bundle(), "notice", &data, &destination)
        .env("REGISTRY_STACK_POSTURE", "development")
        .output()
        .unwrap();
    let sealed = report(&result);
    assert!(result.status.success(), "{sealed}");
    assert_eq!(sealed["seal"]["testOnly"], true);
    assert!(destination.join("document.pdf").is_file());
}

#[test]
fn test_seal_refuses_production_without_writing_output() {
    let (dir, data) = example();
    let destination = dir.path().join("specimen");
    for flags in [&[][..], &["--posture", "production"][..]] {
        let result = run_with_posture(&bundle(), "notice", &data, &destination, flags);
        let refused = report(&result);
        assert_eq!(result.status.code(), Some(20), "{refused}");
        assert_eq!(
            refused["diagnostics"][0]["code"], "render.posture.test-signing",
            "{refused}"
        );
        assert!(
            refused
                .to_string()
                .contains("REGISTRY_STACK_POSTURE=development"),
            "{refused}"
        );
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

fn example() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("record.json");
    fs::write(
        &data,
        r#"{"reference":"TEST-0041","body":"Fictional record."}"#,
    )
    .unwrap();
    (dir, data)
}

fn report(result: &Output) -> Value {
    assert!(
        result.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).expect("one JSON report")
}

/// Verify the detached CMS through OpenSSL, independently of Render's signer.
fn verify_with_openssl(
    scratch: &Path,
    name: &str,
    signed: &SignedFile,
    trust_root: &Path,
    verification_time: Option<i64>,
) -> Output {
    let content = scratch.join(format!("{name}-signed-content.bin"));
    let cms = scratch.join(format!("{name}-signature.der"));
    let verified = scratch.join(format!("{name}-verified-content.bin"));
    let mut bytes = signed.signed_parts[0].clone();
    bytes.extend_from_slice(&signed.signed_parts[1]);
    fs::write(&content, bytes).unwrap();
    fs::write(&cms, &signed.cms_der).unwrap();
    let mut command = Command::new("openssl");
    command.env_remove("REGISTRY_STACK_POSTURE").arg("cms");
    if let Some(time) = verification_time {
        command.arg("-attime").arg(time.to_string());
    }
    command
        .args(["-verify", "-binary", "-inform", "DER"])
        .arg("-in")
        .arg(cms)
        .arg("-content")
        .arg(content)
        .arg("-CAfile")
        .arg(trust_root)
        .args(["-purpose", "any"])
        .arg("-out")
        .arg(verified)
        .output()
        .expect("run openssl cms verifier")
}

#[test]
fn generates_a_real_test_signature_and_a_fresh_public_root() {
    let (dir, data) = example();
    let destination = dir.path().join("specimen");
    let result = run(&bundle(), "notice", &data, &destination);
    let status = report(&result);
    assert!(result.status.success(), "{status}");
    assert_eq!(status["seal"]["testOnly"], true);
    assert_eq!(status["seal"]["level"], "B-B");
    assert_eq!(status["documentVersion"], "notice v2");
    assert!(status["seal"].get("timestampedAt").is_none());
    assert!(status.get("pdfBase64").is_none());
    let pdf = fs::read(destination.join("document.pdf")).unwrap();
    assert!(pdf
        .windows(b"/ByteRange [".len())
        .any(|p| p == b"/ByteRange ["));
    assert!(pdf
        .windows(b"ETSI.CAdES.detached".len())
        .any(|p| p == b"ETSI.CAdES.detached"));
    assert_eq!(
        status["signedFileDigest"],
        registry_render::hash::sha256_digest(&pdf)
    );
    let root = fs::read_to_string(destination.join("test-root.pem")).unwrap();
    assert_eq!(root.matches("-----BEGIN CERTIFICATE-----").count(), 1);
    assert!(!root.contains("PRIVATE KEY"));
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 2);
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let signed = read_signed_file(&pdf, 0);
    let reason = b"/Reason (Registry Stack test seal: not an official document)";
    assert!(signed.signed_parts[0]
        .windows(reason.len())
        .any(|field| field == reason));
    assert!(signed.reserved >= signed.cms_der.len());
    let verified = verify_with_openssl(
        dir.path(),
        "matching-root",
        &signed,
        &destination.join("test-root.pem"),
        None,
    );
    assert!(
        verified.status.success(),
        "OpenSSL refused the emitted PDF and root:\n{}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );

    let other = dir.path().join("second");
    let result = run(&bundle(), "notice", &data, &other);
    assert!(result.status.success(), "{}", report(&result));
    assert_ne!(
        fs::read_to_string(other.join("test-root.pem")).unwrap(),
        root
    );
    let wrong_root = verify_with_openssl(
        dir.path(),
        "wrong-root",
        &signed,
        &other.join("test-root.pem"),
        None,
    );
    assert!(
        !wrong_root.status.success(),
        "OpenSSL trusted a different specimen's root"
    );

    let mut tampered = signed;
    tampered.signed_parts[0][0] ^= 1;
    let tampered_result = verify_with_openssl(
        dir.path(),
        "tampered-content",
        &tampered,
        &destination.join("test-root.pem"),
        None,
    );
    assert!(
        !tampered_result.status.success(),
        "OpenSSL accepted changed signed content"
    );
}

#[test]
fn each_published_specimen_matches_its_public_test_root_at_issuance() {
    let issued = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/site/public/examples/population-extract/issued");
    let scratch = tempfile::tempdir().unwrap();
    let specimens: Vec<_> = fs::read_dir(issued)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        !specimens.is_empty(),
        "expected a published test-signed specimen"
    );
    for specimen in specimens {
        let dir = specimen.path();
        let receipt: Value =
            serde_json::from_slice(&fs::read(dir.join("receipt.json")).unwrap()).unwrap();
        let issued_at =
            chrono::DateTime::parse_from_rfc3339(receipt["issuedAt"].as_str().unwrap()).unwrap();
        let pdf = fs::read(dir.join("document.pdf")).unwrap();
        // The historical fixture must stay paired with its test root after that root expires.
        let verification = verify_with_openssl(
            scratch.path(),
            "published",
            &read_signed_file(&pdf, 0),
            &dir.join("test-root.pem"),
            Some(issued_at.timestamp()),
        );
        assert!(
            verification.status.success(),
            "{}: {}",
            dir.display(),
            String::from_utf8_lossy(&verification.stderr)
        );
    }
}

#[test]
fn refuses_unsigned_documents_and_invalid_records_without_publishing_output() {
    let (dir, data) = example();
    let destination = dir.path().join("specimen");
    let unsigned = run(&bundle(), "letter", &data, &destination);
    assert!(!unsigned.status.success());
    assert_eq!(report(&unsigned)["title"], "document-not-sealable");
    assert!(!destination.exists());
    fs::write(&data, "{}").unwrap();
    let invalid = run(&bundle(), "notice", &data, &destination);
    assert!(!invalid.status.success());
    assert_eq!(report(&invalid)["title"], "data-invalid");
    assert!(!destination.exists());
}

#[test]
fn preserves_an_existing_destination() {
    let (dir, data) = example();
    let destination = dir.path().join("specimen");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("document.pdf"), "existing contents").unwrap();
    let result = run(&bundle(), "notice", &data, &destination);
    assert!(!result.status.success());
    assert_eq!(report(&result)["title"], "invalid-argument");
    assert_eq!(
        fs::read(destination.join("document.pdf")).unwrap(),
        b"existing contents"
    );
    assert!(!destination.join("test-root.pem").exists());
}

#[test]
fn refuses_oversized_record_input_before_parsing_it() {
    let (dir, data) = example();
    fs::File::create(&data)
        .unwrap()
        .set_len(9 * 1024 * 1024)
        .unwrap();
    let destination = dir.path().join("specimen");
    let result = run(&bundle(), "notice", &data, &destination);
    assert!(!result.status.success());
    assert_eq!(report(&result)["title"], "body-too-large");
    assert!(!destination.exists());
}

#[test]
fn refuses_request_when_json_framing_crosses_the_limit() {
    const REQUEST_LIMIT: usize = 8 * 1024 * 1024;
    const PREFIX: &[u8] = br#"{"reference":"TEST-0041","body":""#;
    const SUFFIX: &[u8] = br#""}"#;

    let (dir, data) = example();
    let mut record = Vec::with_capacity(REQUEST_LIMIT);
    record.extend_from_slice(PREFIX);
    record.resize(REQUEST_LIMIT - SUFFIX.len(), b'x');
    record.extend_from_slice(SUFFIX);
    assert_eq!(record.len(), REQUEST_LIMIT);
    fs::write(&data, record).unwrap();

    let destination = dir.path().join("specimen");
    let result = run(&bundle(), "notice", &data, &destination);
    assert!(!result.status.success());
    assert_eq!(report(&result)["title"], "body-too-large");
    assert!(!destination.exists());
}

#[test]
fn preserves_package_identity_and_refuses_changed_package_bytes() {
    let (dir, data) = example();
    let physical = dir.path().canonicalize().expect("physical temp directory");
    let package = physical.join("package");
    let result = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .arg("package")
        .arg("--bundle")
        .arg(bundle())
        .arg("--output")
        .arg(&package)
        .args(["--revision", "specimen-fixture"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = run(&package, "notice", &data, &physical.join("specimen"));
    let sealed = report(&result);
    assert!(result.status.success(), "{sealed}");
    assert_eq!(
        sealed["packageDigest"],
        registry_render::hash::sha256_digest(&fs::read(package.join("SHA256SUMS")).unwrap())
    );

    fs::write(package.join("templates/notice.typ"), "changed test fixture").unwrap();
    let refused = physical.join("refused");
    let result = run(&package, "notice", &data, &refused);
    assert!(!result.status.success());
    assert_eq!(report(&result)["title"], "bundle-tampered");
    assert!(!refused.exists());
}

#[test]
fn runtime_check_requires_declared_development_for_local_assurance() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime.yaml");
    let config = |profile| {
        format!(
        "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\nlistener: {{bind: '127.0.0.1:8080'}}\npackage: {{root: /srv/render/package}}\nsecretProviders: {{file: {{root: /srv/render/secrets}}}}\nauthentication: {{apiKeyRef: 'secret:file/api.key'}}\naudit: {{destination: stdout}}\nassuranceProfile: {profile}\n"
    )
    };
    fs::write(&runtime, config("local")).unwrap();
    let check = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_registry-render"))
            .env_remove("REGISTRY_STACK_POSTURE")
            .args(["check", "--runtime-config"])
            .arg(runtime.canonicalize().unwrap())
            .args(["--format", "json"])
            .args(flags)
            .output()
            .unwrap()
    };
    for flags in [&[][..], &["--posture", "production"][..]] {
        let result = check(flags);
        let report = report(&result);
        assert_eq!(result.status.code(), Some(1), "{report}");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "render.posture.local-assurance"
        );
        let action = report["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap();
        assert!(action.contains("rstack dev"), "{action}");
        assert!(
            action.contains("REGISTRY_STACK_POSTURE=development"),
            "{action}"
        );
    }
    let result = check(&["--posture", "development"]);
    let accepted = report(&result);
    assert!(result.status.success(), "{accepted}");
    assert_eq!(accepted["posture"]["value"], "development");
    assert_eq!(
        accepted["diagnostics"][0]["code"],
        "render.posture.local-assurance"
    );

    fs::write(&runtime, config("production")).unwrap();
    let result = check(&["--posture", "development"]);
    let refused = report(&result);
    assert_eq!(result.status.code(), Some(1), "{refused}");
    assert_eq!(
        refused["diagnostics"][0]["code"],
        "render.posture.assurance-profile-conflict"
    );
}
