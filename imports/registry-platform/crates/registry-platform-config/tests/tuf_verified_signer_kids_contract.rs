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

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use chrono::{TimeDelta, Utc};
use registry_platform_config::{
    sha256_uri, LocalTufRepositoryInput, RegistryAcceptedTrustRoots, RegistryTrustRoot,
    TrustRootRole, TrustRootSigner, TufConfigVerifier,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::{PathExists, SignedRole};
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::{KeyHolder, Root, Signed, Snapshot, Timestamp};

/// A distinct, well-formed keyid that is NOT one of the TUF root's targets
/// keys, so `tough` skips it for threshold counting but keeps it in the array.
const FORGED_KID: &str = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

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

async fn generate_signed_repo(repo: &TempDir, data: &Path, target_name: &str) -> PathBuf {
    let root_path = data.join("simple-rsa").join("root.json");
    let key_path = data.join("snakeoil.pem");
    let target_path = data.join("targets").join(target_name);
    let metadata_dir = repo.path().join("metadata");
    let targets_dir = repo.path().join("targets");
    let expiry = Utc::now()
        .checked_add_signed(TimeDelta::try_days(30).expect("duration"))
        .expect("future expiration");
    let version = NonZeroU64::new(1).expect("non-zero version");

    let mut editor = RepositoryEditor::new(&root_path)
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
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
    let signed = editor.sign(&keys).await.expect("repository signs");
    signed.write(&metadata_dir).await.expect("metadata writes");
    signed
        .link_targets(data.join("targets"), &targets_dir, PathExists::Skip)
        .await
        .expect("targets link");

    metadata_dir
}

/// Append a forged signature entry to the written `*targets.json`. Returns the
/// real signer keyid (the one tough actually verified).
fn forge_extra_targets_signature(metadata_dir: &Path) -> String {
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
    assert_ne!(real_keyid, FORGED_KID, "forged keyid must be distinct");
    signatures.push(json!({
        "keyid": FORGED_KID,
        // Garbage signature bytes: this keyid is not in the TUF targets role,
        // so tough never verifies it; it only needs to be valid hex.
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
/// keys (here all roles share the snakeoil key).
async fn reseal_snapshot_and_timestamp(metadata_dir: &Path, data: &Path) {
    let root: Signed<Root> =
        serde_json::from_slice(&std::fs::read(data.join("simple-rsa").join("root.json")).unwrap())
            .expect("root parses");
    let key_holder = KeyHolder::Root(root.signed.clone());
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
        path: data.join("snakeoil.pem"),
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

#[tokio::test]
async fn forged_extra_targets_signature_does_not_authorize_multisig_role() {
    let data = tough_data_dir();
    let repo = TempDir::new().expect("repo tempdir");
    let datastore = TempDir::new().expect("datastore tempdir");
    let target_name = "file4.txt";

    let metadata_dir = generate_signed_repo(&repo, &data, target_name).await;
    let real_keyid = forge_extra_targets_signature(&metadata_dir);
    reseal_snapshot_and_timestamp(&metadata_dir, &data).await;

    let input = LocalTufRepositoryInput {
        root_path: data.join("simple-rsa").join("root.json"),
        metadata_dir,
        targets_dir: repo.path().join("targets"),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: target_name.to_string(),
    };

    // tough still loads the repo: the one real targets signature meets the
    // threshold of 1; the forged keyid is distinct (no duplicate-keyid error).
    let target = TufConfigVerifier::verify_local_target(&input)
        .await
        .expect("repo with a forged extra signature still verifies in tough");

    assert!(
        target.signer_kids.contains(&real_keyid),
        "sanity: the real signer is present"
    );

    // Build a 2-of-N high-risk PRODUCTION role over [real, forged].
    let change_class = "rotate_signing_key".to_string();
    let change_classes = BTreeSet::from([change_class.clone()]);
    let signers = [real_keyid.clone(), FORGED_KID.to_string()]
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
                signer_kids: vec![real_keyid.clone(), FORGED_KID.to_string()],
                allowed_change_classes: BTreeSet::from([change_class]),
            }],
        }],
    };

    let forged_present = target.signer_kids.contains(&FORGED_KID.to_string());
    let authorized = accepted
        .authorize_at(
            &change_classes,
            &target.signer_kids,
            &target.root_sha256,
            1_000,
        )
        .is_ok();

    eprintln!(
        "forged_kid_in_signer_kids={forged_present}, multisig_authorized={authorized}, \
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
