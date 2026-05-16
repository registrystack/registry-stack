// SPDX-License-Identifier: Apache-2.0
//! Pinned-byte invariant for provenance resources.
//!
//! `resources/MANIFEST.toml` records the sha256 of every JSON-LD
//! context and JSON Schema the gateway serves. This test re-hashes
//! both the on-disk file and the compiled-in byte slice and asserts
//! equality with the pinned value. An unreviewed edit to any resource
//! file would change one or both hashes and fail CI before any tampered
//! bytes can be deployed.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Manifest {
    resource: Vec<ResourceEntry>,
}

#[derive(Debug, Deserialize)]
struct ResourceEntry {
    path: String,
    sha256: String,
    #[allow(dead_code)]
    served_as: String,
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("resources")
        .join("MANIFEST.toml")
}

fn resources_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[test]
fn every_on_disk_resource_matches_pinned_sha256() {
    let manifest_bytes = fs::read(manifest_path()).expect("manifest readable");
    let manifest: Manifest =
        toml::from_str(std::str::from_utf8(&manifest_bytes).expect("manifest utf-8"))
            .expect("manifest parses");
    for entry in &manifest.resource {
        let path = resources_root().join(&entry.path);
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("resource {} unreadable: {err}", entry.path));
        let hash = sha256_hex(&bytes);
        assert_eq!(
            hash, entry.sha256,
            "sha256 mismatch for {}: file hashes to {hash}, manifest declares {}",
            entry.path, entry.sha256
        );
    }
}

#[test]
fn compiled_in_resources_match_pinned_sha256() {
    // The library re-exports each resource as a &'static [u8] via
    // `include_bytes!`. We hash those slices to prove the compiled
    // binary carries the same bytes as the on-disk file (the previous
    // test asserts the on-disk bytes match the manifest).
    let mut compiled: HashMap<&'static str, &'static [u8]> = HashMap::new();
    compiled.insert(
        "jsonld/provenance/v1/context.jsonld",
        data_gate::provenance::resources::PROVENANCE_CONTEXT_V1,
    );
    compiled.insert(
        "jsonld/vc/v2/credentials.jsonld",
        data_gate::provenance::resources::VC_V2_CONTEXT,
    );
    compiled.insert(
        "schemas/verify-result/v1.json",
        data_gate::provenance::resources::VERIFY_RESULT_V1,
    );
    compiled.insert(
        "schemas/aggregate-result/v1.json",
        data_gate::provenance::resources::AGGREGATE_RESULT_V1,
    );
    compiled.insert(
        "schemas/entity-record/v1.json",
        data_gate::provenance::resources::ENTITY_RECORD_V1,
    );
    compiled.insert(
        "scalar/api-reference.js",
        data_gate::api::docs::SCALAR_BUNDLE,
    );

    let manifest_bytes = fs::read(manifest_path()).expect("manifest readable");
    let manifest: Manifest =
        toml::from_str(std::str::from_utf8(&manifest_bytes).expect("manifest utf-8"))
            .expect("manifest parses");
    for entry in &manifest.resource {
        let bytes = compiled
            .get(entry.path.as_str())
            .unwrap_or_else(|| panic!("no compiled-in bytes registered for {}", entry.path));
        let hash = sha256_hex(bytes);
        assert_eq!(
            hash, entry.sha256,
            "compiled-in bytes for {} hash to {hash}; manifest declares {}",
            entry.path, entry.sha256
        );
    }
}
