use registry_rstack::assets::{checksum_for, AssetProvider};
use registry_rstack::Asset;
use std::fs;

fn asset(name: &str, bytes: &[u8]) -> Asset {
    use sha2::{Digest, Sha256};
    Asset {
        name: name.to_owned(),
        size: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

#[test]
fn checksum_lookup_requires_one_exact_lowercase_entry() {
    let expected = "a".repeat(64);
    let checksums = format!("{expected}  rstack-v0.44.0-linux-amd64\n");
    assert_eq!(
        checksum_for(checksums.as_bytes(), "rstack-v0.44.0-linux-amd64").unwrap(),
        expected
    );
    assert!(checksum_for(
        format!("{checksums}{checksums}").as_bytes(),
        "rstack-v0.44.0-linux-amd64"
    )
    .is_err());
    assert!(checksum_for(
        format!("{}  rstack-v0.44.0-linux-amd64\n", "A".repeat(64)).as_bytes(),
        "rstack-v0.44.0-linux-amd64"
    )
    .is_err());
    assert!(checksum_for(checksums.as_bytes(), "rstack-v0.44.0-linux-arm64").is_err());
}

#[test]
fn offline_assets_are_verified_before_they_are_staged() {
    let directory = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let payload = b"one verified executable";
    let name = "rstack-v0.44.0-linux-amd64";
    fs::write(directory.path().join(name), payload).unwrap();
    let provider = AssetProvider::new("v0.44.0", Some(directory.path().to_path_buf())).unwrap();
    provider
        .fetch(&asset(name, payload), &output.path().join(name))
        .unwrap();
    assert_eq!(fs::read(output.path().join(name)).unwrap(), payload);

    let wrong_size = Asset {
        size: 1,
        ..asset(name, payload)
    };
    assert!(provider
        .fetch(&wrong_size, &output.path().join("wrong-size"))
        .is_err());
    assert!(!output.path().join("wrong-size").exists());

    fs::write(directory.path().join(name), b"tampered executable!!!").unwrap();
    assert!(provider
        .fetch(&asset(name, payload), &output.path().join("wrong-hash"))
        .is_err());
    assert!(!output.path().join("wrong-hash").exists());
}

#[test]
fn offline_asset_symlinks_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let name = "rstack-v0.44.0-linux-amd64";
    fs::write(directory.path().join("real"), b"binary").unwrap();
    std::os::unix::fs::symlink("real", directory.path().join(name)).unwrap();
    let provider = AssetProvider::new("v0.44.0", Some(directory.path().to_path_buf())).unwrap();
    assert!(provider
        .fetch(&asset(name, b"binary"), &output.path().join(name))
        .is_err());
}
