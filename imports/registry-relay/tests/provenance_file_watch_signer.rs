// SPDX-License-Identifier: Apache-2.0
//! Tests for the local file-watch provenance signer.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_platform_crypto::KeyReadiness;
use registry_relay::config::{FileWatchSignerConfig, ProvenanceAlgorithm};
use registry_relay::provenance::signers::file_watch::FileWatchSigner;
use registry_relay::provenance::{Signer, SigningAlgorithm};
use serde_json::json;
use tempfile::TempDir;

fn jwk_from_keypair(sk: &SigningKey, kid: &str) -> String {
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    serde_json::to_string(&json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(d_bytes),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
        "kid": kid,
    }))
    .expect("jwk serializes")
}

fn sign_and_verify(signer: &dyn Signer, vk: VerifyingKey) {
    let header = json!({
        "alg": "EdDSA",
        "typ": "vc+jwt",
        "kid": signer.verification_method_id(),
    });
    let payload = json!({
        "iss": "did:web:example",
        "sub": "did:web:example:entity:file-watch",
        "iat": 1_700_000_000,
    });
    let jws = signer.sign(header, payload).expect("sign");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies");
}

fn file_mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .expect("key metadata")
        .modified()
        .expect("key mtime")
}

fn set_file_mtime(path: &Path, mtime: SystemTime) {
    fs::File::open(path)
        .expect("open key file for mtime")
        .set_modified(mtime)
        .expect("set key mtime");
}

fn bump_file_mtime(path: &Path) {
    let mtime = file_mtime(path)
        .checked_add(Duration::from_secs(2))
        .expect("mtime bump");
    set_file_mtime(path, mtime);
}

#[test]
fn file_watch_signer_loads_initial_key_and_signs() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("active.jwk");
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    fs::write(&key_path, jwk_from_keypair(&sk, "did:web:example#fw-a")).expect("write key");
    let signer = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path,
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect("file-watch signer builds");

    assert_eq!(signer.algorithm(), SigningAlgorithm::EdDSA);
    assert_eq!(signer.readiness(), KeyReadiness::Ready);
    sign_and_verify(&signer, vk);
}

#[test]
fn file_watch_signer_uses_replaced_key_without_restart() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("active.jwk");
    let first = SigningKey::generate(&mut OsRng);
    let first_jwk = jwk_from_keypair(&first, "did:web:example#fw-a");
    let first_vk = first.verifying_key();
    fs::write(&key_path, &first_jwk).expect("write key");
    let signer = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path.clone(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect("file-watch signer builds");

    fs::write(&key_path, first_jwk).expect("refresh key");
    bump_file_mtime(&key_path);

    assert_eq!(signer.readiness(), KeyReadiness::Ready);
    sign_and_verify(&signer, first_vk);
}

#[test]
fn file_watch_signer_rejects_different_public_key_under_same_method_id() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("active.jwk");
    let first = SigningKey::generate(&mut OsRng);
    let first_vk = first.verifying_key();
    fs::write(&key_path, jwk_from_keypair(&first, "did:web:example#fw-a")).expect("write key");
    let signer = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path.clone(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect("file-watch signer builds");

    let second = SigningKey::generate(&mut OsRng);
    fs::write(&key_path, jwk_from_keypair(&second, "did:web:example#fw-a"))
        .expect("write wrong-key replacement");
    bump_file_mtime(&key_path);

    assert_eq!(signer.readiness(), KeyReadiness::Degraded);
    sign_and_verify(&signer, first_vk);
}

#[test]
fn file_watch_signer_missing_initial_file_fails_without_path_leak() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("missing-active.jwk");

    let err = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path.clone(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect_err("missing initial key file fails");

    let err = err.to_string();
    assert!(err.contains("file_watch key file could not be read"));
    let key_path = key_path.to_string_lossy();
    assert!(!err.contains(key_path.as_ref() as &str));
}

#[test]
fn file_watch_signer_keeps_last_good_key_when_replacement_is_corrupt() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("active.jwk");
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    fs::write(&key_path, jwk_from_keypair(&sk, "did:web:example#fw-a")).expect("write key");
    let signer = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path.clone(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect("file-watch signer builds");

    let initial_mtime = file_mtime(&key_path);
    fs::write(&key_path, "{not valid jwk").expect("write corrupt replacement");
    set_file_mtime(&key_path, initial_mtime);

    assert_eq!(signer.readiness(), KeyReadiness::Ready);
    sign_and_verify(&signer, vk);

    bump_file_mtime(&key_path);

    assert_eq!(signer.readiness(), KeyReadiness::Degraded);
    sign_and_verify(&signer, vk);
    let debug = format!("{signer:?}");
    let key_path = key_path.to_string_lossy();
    let key_path: &str = key_path.as_ref();
    assert!(!debug.contains("not valid jwk"), "{debug}");
    assert!(!debug.contains(key_path), "{debug}");

    fs::remove_file(key_path).expect("remove replacement");
    assert_eq!(signer.readiness(), KeyReadiness::Degraded);
    sign_and_verify(&signer, vk);
}

#[test]
fn file_watch_signer_retries_after_transient_read_failure_at_same_mtime() {
    let tmp = TempDir::new().expect("tempdir");
    let key_path = tmp.path().join("active.jwk");
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let jwk = jwk_from_keypair(&sk, "did:web:example#fw-a");
    fs::write(&key_path, &jwk).expect("write key");
    let signer = FileWatchSigner::from_config(
        &FileWatchSignerConfig {
            path: key_path.clone(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:example#fw-a".to_string(),
    )
    .expect("file-watch signer builds");

    fs::remove_file(&key_path).expect("remove key file");
    fs::create_dir(&key_path).expect("replace key file with unreadable directory");
    let unreadable_mtime = file_mtime(&key_path);

    assert_eq!(signer.readiness(), KeyReadiness::Degraded);
    sign_and_verify(&signer, vk);

    fs::remove_dir(&key_path).expect("remove unreadable directory");
    fs::write(&key_path, jwk).expect("restore key file");
    set_file_mtime(&key_path, unreadable_mtime);

    assert_eq!(signer.readiness(), KeyReadiness::Ready);
    sign_and_verify(&signer, vk);
}
