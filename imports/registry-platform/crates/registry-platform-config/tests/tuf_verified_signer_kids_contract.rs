//! Regression coverage for Registry signer IDs derived from TUF targets
//! metadata. Only cryptographically valid targets-role signatures may be
//! exposed to Registry authorization.
//!
//! Threat model: an attacker who can produce TUF metadata meeting the *TUF*
//! targets-role threshold (here 1) and who holds the (typically online)
//! snapshot+timestamp keys appends extra signature objects carrying distinct,
//! Registry-trusted keyids with garbage signature bytes. `tough` verifies the
//! one real targets signature, ignores the forged ones for its threshold, but
//! leaves them in the `signatures` array. The platform verifier must not
//! forward those unverified key IDs into `RegistryTrustRoot::authorize`, because
//! that would let multi-sig authorization pass with a single real signer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use chrono::{TimeDelta, Utc};
use registry_platform_config::{
    sha256_uri, LocalTufRepositoryInput, RegistryAcceptedTrustRoots, RegistryTrustRoot,
    TrustRootRole, TrustRootSigner, TufConfigVerifier,
};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::{PathExists, SignedRole};
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::{KeyHolder, RoleKeys, RoleType, Root, Signed, Snapshot, Timestamp};

#[derive(Clone, Copy, Debug)]
enum SigningAlgorithm {
    Rsa,
    Ed25519,
    EcdsaP256,
}

impl SigningAlgorithm {
    const ALL: [Self; 3] = [Self::Rsa, Self::Ed25519, Self::EcdsaP256];

    fn label(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }
}

fn tough_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tough-data")
}

fn find_metadata_file(dir: &Path, suffix: &str) -> PathBuf {
    std::fs::read_dir(dir)
        .expect("metadata dir reads")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(suffix))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("metadata file ending in {suffix} exists"))
}

fn hex_digest(bytes: &[u8]) -> String {
    sha256_uri(bytes)
        .strip_prefix("sha256:")
        .expect("sha256 uri prefix")
        .to_string()
}

async fn generate_signed_repo_with_key(
    repo: &TempDir,
    data: &Path,
    target_name: &str,
    root_path: &Path,
    key_path: &Path,
) -> PathBuf {
    let target_path = data.join("targets").join(target_name);
    let metadata_dir = repo.path().join("metadata");
    let targets_dir = repo.path().join("targets");
    let expiry = Utc::now()
        .checked_add_signed(TimeDelta::try_days(30).expect("duration"))
        .expect("future expiration");
    let version = NonZeroU64::new(1).expect("non-zero version");

    let mut editor = RepositoryEditor::new(root_path)
        .await
        .expect("editor loads fixture root");
    editor.targets_expires(expiry).expect("targets expiration");
    editor.targets_version(version).expect("targets version");
    editor.snapshot_expires(expiry);
    editor.snapshot_version(version);
    editor.timestamp_expires(expiry);
    editor.timestamp_version(version);
    editor
        .add_target_paths(vec![target_path])
        .await
        .expect("target path");
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: key_path.to_path_buf(),
    })];
    let signed = editor.sign(&keys).await.expect("repository signs");
    signed.write(&metadata_dir).await.expect("metadata writes");
    signed
        .link_targets(data.join("targets"), &targets_dir, PathExists::Skip)
        .await
        .expect("targets link");

    metadata_dir
}

async fn generated_key_pair(
    repo: &TempDir,
    _data: &Path,
    algorithm: SigningAlgorithm,
) -> (PathBuf, PathBuf) {
    let key_dir = repo.path().join("keys").join(algorithm.label());
    std::fs::create_dir_all(&key_dir).expect("key directory exists");
    match algorithm {
        SigningAlgorithm::Rsa => {
            let primary = key_dir.join("snakeoil.pem");
            let secondary = key_dir.join("snakeoil_2.pem");
            write_generated_rsa_key(&primary);
            write_generated_rsa_key(&secondary);
            (primary, secondary)
        }
        SigningAlgorithm::Ed25519 => {
            let rng = SystemRandom::new();
            let primary = key_dir.join("primary-ed25519.pkcs8");
            let secondary = key_dir.join("secondary-ed25519.pkcs8");
            let primary_key =
                Ed25519KeyPair::generate_pkcs8(&rng).expect("primary Ed25519 key generates");
            let secondary_key =
                Ed25519KeyPair::generate_pkcs8(&rng).expect("secondary Ed25519 key generates");
            std::fs::write(&primary, primary_key.as_ref()).expect("primary Ed25519 key writes");
            std::fs::write(&secondary, secondary_key.as_ref())
                .expect("secondary Ed25519 key writes");
            (primary, secondary)
        }
        SigningAlgorithm::EcdsaP256 => {
            let rng = SystemRandom::new();
            let primary = key_dir.join("primary-ecdsa-p256.pkcs8");
            let secondary = key_dir.join("secondary-ecdsa-p256.pkcs8");
            let primary_key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("primary ECDSA key generates");
            let secondary_key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("secondary ECDSA key generates");
            std::fs::write(&primary, primary_key.as_ref()).expect("primary ECDSA key writes");
            std::fs::write(&secondary, secondary_key.as_ref()).expect("secondary ECDSA key writes");
            (primary, secondary)
        }
    }
}

fn write_generated_rsa_key(path: &Path) {
    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generates");
    let pem = key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("RSA key encodes as PKCS#1 PEM");
    std::fs::write(path, pem.as_bytes()).expect("RSA key writes");
}

async fn key_id_and_tuf_key(key_path: &Path) -> (Vec<u8>, tough::schema::key::Key) {
    let source = LocalKeySource {
        path: key_path.to_path_buf(),
    };
    let signer = source.as_sign().await.expect("key source loads signer");
    let key = signer.tuf_key();
    let key_id = key.key_id().expect("key id calculates").to_vec();
    (key_id, key)
}

async fn write_root_for_algorithm(
    repo: &TempDir,
    primary_key_path: &Path,
    secondary_targets_key_path: &Path,
    algorithm: SigningAlgorithm,
) -> (PathBuf, String, String) {
    let (primary_key_id, primary_key) = key_id_and_tuf_key(primary_key_path).await;
    let (secondary_key_id, secondary_key) = key_id_and_tuf_key(secondary_targets_key_path).await;
    let root_dir = repo.path().join("roots").join(algorithm.label());
    std::fs::create_dir_all(&root_dir).expect("root directory exists");
    let expiry = Utc::now()
        .checked_add_signed(TimeDelta::try_days(30).expect("duration"))
        .expect("future root expiration");
    let primary_role = RoleKeys {
        keyids: vec![primary_key_id.clone().into()],
        threshold: NonZeroU64::new(1).expect("non-zero threshold"),
        _extra: HashMap::new(),
    };
    let targets_role = RoleKeys {
        keyids: vec![
            primary_key_id.clone().into(),
            secondary_key_id.clone().into(),
        ],
        threshold: NonZeroU64::new(1).expect("non-zero threshold"),
        _extra: HashMap::new(),
    };
    let root = Root {
        spec_version: "1.0.0".to_string(),
        consistent_snapshot: true,
        version: NonZeroU64::new(1).expect("non-zero root version"),
        expires: expiry,
        keys: HashMap::from([
            (primary_key_id.clone().into(), primary_key),
            (secondary_key_id.clone().into(), secondary_key),
        ]),
        roles: HashMap::from([
            (RoleType::Root, primary_role.clone()),
            (RoleType::Snapshot, primary_role.clone()),
            (RoleType::Timestamp, primary_role),
            (RoleType::Targets, targets_role),
        ]),
        _extra: HashMap::new(),
    };
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: primary_key_path.to_path_buf(),
    })];
    let signed_root = SignedRole::new(
        root.clone(),
        &KeyHolder::Root(root),
        &keys,
        &SystemRandom::new(),
    )
    .await
    .expect("algorithm root signs");
    signed_root
        .write(&root_dir, true)
        .await
        .expect("algorithm root writes");
    (
        root_dir.join("1.root.json"),
        hex_lower(&primary_key_id),
        hex_lower(&secondary_key_id),
    )
}

/// Append an invalid signature entry for a trusted targets-role key. Returns
/// the real signer keyid (the one tough actually verified).
fn forge_extra_targets_signature(metadata_dir: &Path, forged_keyid: &str) -> String {
    let targets_path = find_metadata_file(metadata_dir, "targets.json");
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(&targets_path).expect("targets reads"))
            .expect("targets parses");
    let signatures = value["signatures"]
        .as_array_mut()
        .expect("signatures is an array");
    let real_keyid = signatures[0]["keyid"]
        .as_str()
        .expect("real keyid is a string")
        .to_string();
    assert_ne!(real_keyid, forged_keyid, "forged keyid must be distinct");
    signatures.push(json!({
        "keyid": forged_keyid,
        // Garbage signature bytes: this keyid is in the TUF targets role, but
        // it did not sign this metadata. tough keeps the entry while counting
        // only the valid primary signature toward the role threshold.
        "sig": "abababababababababababababababababababababababababababababababab"
    }));
    std::fs::write(
        &targets_path,
        serde_json::to_vec_pretty(&value).expect("targets serializes"),
    )
    .expect("targets rewrites");
    real_keyid
}

fn set_meta(signed_value: &mut Value, suffix: &str, length: u64, hash_hex: &str) {
    let meta = signed_value["signed"]["meta"]
        .as_object_mut()
        .expect("meta object");
    let key = meta
        .keys()
        .find(|key| key.ends_with(suffix))
        .cloned()
        .unwrap_or_else(|| panic!("snapshot/timestamp meta entry for {suffix} exists"));
    let entry = meta
        .get_mut(&key)
        .and_then(Value::as_object_mut)
        .expect("meta entry object");
    entry.insert("length".to_string(), json!(length));
    entry.insert("hashes".to_string(), json!({ "sha256": hash_hex }));
}

/// Re-sign snapshot+timestamp so the modified targets.json passes tough's
/// length/hash pinning. Models an attacker holding the online snapshot+timestamp
/// keys.
async fn reseal_snapshot_and_timestamp(metadata_dir: &Path, root_path: &Path, key_path: &Path) {
    let root: Signed<Root> = serde_json::from_slice(&std::fs::read(root_path).expect("root reads"))
        .expect("root parses");
    let key_holder = KeyHolder::Root(root.signed.clone());
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: key_path.to_path_buf(),
    })];
    let rng = SystemRandom::new();

    let targets_bytes = std::fs::read(find_metadata_file(metadata_dir, "targets.json")).unwrap();
    let mut snapshot_value: Value = serde_json::from_slice(
        &std::fs::read(find_metadata_file(metadata_dir, "snapshot.json")).unwrap(),
    )
    .expect("snapshot parses");
    set_meta(
        &mut snapshot_value,
        "targets.json",
        targets_bytes.len() as u64,
        &hex_digest(&targets_bytes),
    );
    let snapshot: Snapshot =
        serde_json::from_value(snapshot_value["signed"].clone()).expect("snapshot deserializes");
    SignedRole::new(snapshot, &key_holder, &keys, &rng)
        .await
        .expect("snapshot re-signs")
        .write(metadata_dir, true)
        .await
        .expect("snapshot writes");

    let snapshot_bytes = std::fs::read(find_metadata_file(metadata_dir, "snapshot.json")).unwrap();
    let mut timestamp_value: Value = serde_json::from_slice(
        &std::fs::read(find_metadata_file(metadata_dir, "timestamp.json")).unwrap(),
    )
    .expect("timestamp parses");
    set_meta(
        &mut timestamp_value,
        "snapshot.json",
        snapshot_bytes.len() as u64,
        &hex_digest(&snapshot_bytes),
    );
    let timestamp: Timestamp =
        serde_json::from_value(timestamp_value["signed"].clone()).expect("timestamp deserializes");
    SignedRole::new(timestamp, &key_holder, &keys, &rng)
        .await
        .expect("timestamp re-signs")
        .write(metadata_dir, true)
        .await
        .expect("timestamp writes");
}

async fn assert_forged_extra_targets_signature_does_not_authorize_multisig_role(
    algorithm: SigningAlgorithm,
) {
    let data = tough_data_dir();
    let repo = TempDir::new().expect("repo tempdir");
    let datastore = TempDir::new().expect("datastore tempdir");
    let target_name = "file4.txt";

    let (primary_key_path, secondary_key_path) = generated_key_pair(&repo, &data, algorithm).await;
    let (root_path, primary_keyid, secondary_keyid) =
        write_root_for_algorithm(&repo, &primary_key_path, &secondary_key_path, algorithm).await;
    let metadata_dir =
        generate_signed_repo_with_key(&repo, &data, target_name, &root_path, &primary_key_path)
            .await;
    let real_keyid = forge_extra_targets_signature(&metadata_dir, &secondary_keyid);
    reseal_snapshot_and_timestamp(&metadata_dir, &root_path, &primary_key_path).await;

    assert_eq!(real_keyid, primary_keyid);

    let input = LocalTufRepositoryInput {
        root_path,
        metadata_dir,
        targets_dir: repo.path().join("targets"),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: target_name.to_string(),
    };

    let target = TufConfigVerifier::verify_local_target(&input)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "repo with a forged extra {algorithm:?} signature still verifies in tough: {err}"
            )
        });

    assert!(
        target.signer_kids.contains(&real_keyid),
        "sanity: the real {algorithm:?} signer is present"
    );

    // Build a 2-of-N high-risk PRODUCTION role over [real, forged].
    let change_class = "rotate_signing_key".to_string();
    let change_classes = BTreeSet::from([change_class.clone()]);
    let signers = [real_keyid.clone(), secondary_keyid.clone()]
        .into_iter()
        .map(|kid| {
            (
                kid.clone(),
                TrustRootSigner {
                    kid: kid.clone(),
                    enabled: true,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let accepted = RegistryAcceptedTrustRoots {
        accepted_roots: vec![RegistryTrustRoot {
            root_id: "prod-root".to_string(),
            production: true,
            tuf_root_sha256: target.root_sha256.clone(),
            valid_from_unix_seconds: None,
            valid_until_unix_seconds: None,
            high_risk_change_classes: BTreeSet::from([change_class.clone()]),
            signers,
            roles: vec![TrustRootRole {
                name: "high-risk-operator".to_string(),
                threshold: 2,
                signer_kids: vec![real_keyid.clone(), secondary_keyid.clone()],
                allowed_change_classes: BTreeSet::from([change_class]),
            }],
        }],
    };

    let forged_present = target.signer_kids.contains(&secondary_keyid);
    let authorized = accepted
        .authorize_at(
            &change_classes,
            &target.signer_kids,
            &target.root_sha256,
            1_000,
        )
        .is_ok();

    eprintln!(
        "algorithm={algorithm:?}, forged_kid_in_signer_kids={forged_present}, multisig_authorized={authorized}, \
         signer_kids={:?}",
        target.signer_kids
    );

    assert!(
        !forged_present,
        "forged keyid leaked into signer_kids despite never verifying"
    );
    assert!(
        !authorized,
        "a 2-of-2 high-risk production role was authorized with one real \
         signer plus one forged keyid (multi-sig bypass)"
    );
}

#[tokio::test]
async fn forged_extra_targets_signature_does_not_authorize_multisig_role() {
    assert_forged_extra_targets_signature_does_not_authorize_multisig_role(SigningAlgorithm::Rsa)
        .await;
}

#[tokio::test]
async fn signer_identity_recovery_rejects_forged_signature_algorithm_matrix() {
    for algorithm in SigningAlgorithm::ALL {
        assert_forged_extra_targets_signature_does_not_authorize_multisig_role(algorithm).await;
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
