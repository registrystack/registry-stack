use registry_rstack::ReleaseManifest;

fn document() -> serde_json::Value {
    serde_json::json!({
        "schema_version":"registry-stack.release-candidate.v2",
        "repository":"registrystack/registry-stack",
        "release":{"tag":"v0.44.0","version":"0.44.0","source_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","release_id":"beta-56"},
        "payloads":[
            {"name":"rstack-v0.44.0-linux-amd64","kind":"binary","size":8,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {"name":"bregctl-v0.44.0-linux-amd64","kind":"binary","size":11,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
        ],
        "components":{
            "schema_version":"registry-stack.components.v1",
            "release":"v0.44.0",
            "launcher":{"linux-amd64":{"name":"rstack-v0.44.0-linux-amd64","size":8,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
            "components":{"breg":{"entrypoint":"bregctl","dependencies":[],"platforms":{"linux-amd64":{"assets":[{"name":"bregctl-v0.44.0-linux-amd64","size":11,"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"capabilities":{"tooling":true,"runtime":false}}}}}
        }
    })
}

fn stack_v3_document() -> serde_json::Value {
    let mut value = document();
    value["schema_version"] = serde_json::json!("registry-stack.release-candidate.v3");
    value["workflow"] = serde_json::json!({
        "path": ".github/workflows/release-candidate.yml",
        "revision": "b".repeat(40),
        "run_id": 123,
        "run_attempt": 1
    });
    value["validity"] = serde_json::json!({
        "created_at": "2026-10-23T00:00:00Z",
        "expires_at": "2026-10-24T00:00:00Z"
    });
    value["payloads"].as_array_mut().unwrap().extend([
        serde_json::json!({"name": "docs.tar.gz", "kind": "docs", "size": 1, "sha256": "d".repeat(64)}),
        serde_json::json!({"name": "sbom.json", "kind": "sbom", "size": 1, "sha256": "e".repeat(64)}),
        serde_json::json!({"name": "security-evidence.tar.gz", "kind": "security-evidence", "size": 1, "sha256": "f".repeat(64)}),
        serde_json::json!({"name": "distribution.json", "kind": "distribution", "size": 1, "sha256": "1".repeat(64)}),
    ]);
    value["images"] = serde_json::json!([{
        "name": "breg",
        "candidate_ref": format!("ghcr.io/registrystack/breg-candidate@sha256:{}", "5".repeat(64)),
        "digest": format!("sha256:{}", "5".repeat(64)),
        "final_ref": "ghcr.io/registrystack/breg:v0.44.0"
    }]);
    value["docs"] = serde_json::json!({"name": "docs.tar.gz", "sha256": "d".repeat(64)});
    value["sbom"] = serde_json::json!({"name": "sbom.json", "sha256": "e".repeat(64)});
    value["scans"] = serde_json::json!([{
        "image": "breg",
        "name": "breg.grype.json",
        "sha256": "6".repeat(64),
        "status": "passed"
    }]);
    value["advisory"] = serde_json::json!({
        "name": "advisory.json",
        "sha256": "f".repeat(64),
        "verdict": "passed"
    });
    value["bundle"] = serde_json::json!({
        "name": "candidate.tar.gz",
        "size": 1,
        "sha256": "1".repeat(64)
    });
    value["distribution_components"] = serde_json::json!([{
        "unit": "discovery",
        "version": "1.2.3",
        "release_tag": "discovery/v1.2.3",
        "source_sha": "2".repeat(40),
        "manifest": {"name": "discovery-manifest.json", "sha256": "3".repeat(64)},
        "payloads": [{
            "name": "injected-v1.2.3-linux-amd64",
            "kind": "binary",
            "size": 99,
            "sha256": "4".repeat(64)
        }],
        "images": []
    }]);
    value
}

#[test]
fn release_manifest_binds_component_assets_to_published_digests() {
    let valid = serde_json::to_vec(&document()).unwrap();
    assert_eq!(
        ReleaseManifest::parse(&valid).unwrap().release.tag,
        "v0.44.0"
    );

    let mut tampered = document();
    tampered["components"]["components"]["breg"]["platforms"]["linux-amd64"]["assets"][0]
        ["sha256"] = serde_json::json!("d".repeat(64));
    let error = ReleaseManifest::parse(&serde_json::to_vec(&tampered).unwrap()).unwrap_err();
    assert!(error.contains("payload"));

    let mut mismatched_release = document();
    mismatched_release["components"]["release"] = serde_json::json!("v0.45.0");
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&mismatched_release).unwrap()).is_err());
}

#[test]
fn stack_v3_uses_only_embedded_installer_components() {
    let manifest = ReleaseManifest::parse(&serde_json::to_vec(&stack_v3_document()).unwrap())
        .expect("Stack v3 release candidate should retain rstack compatibility");

    assert_eq!(manifest.release.tag, "v0.44.0");
    assert_eq!(
        manifest
            .components
            .components
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["breg"]
    );
    assert_eq!(
        manifest
            .components
            .select(
                "linux-amd64",
                registry_rstack::Selection::Names(vec!["breg".into()])
            )
            .unwrap()
            .download_bytes,
        19
    );
}

#[test]
fn independent_discovery_v3_manifest_is_rejected() {
    let mut value = stack_v3_document();
    value["release"]["unit"] = serde_json::json!("discovery");
    value["release"]["tag"] = serde_json::json!("discovery/v0.44.0");

    let error = ReleaseManifest::parse(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert!(error.contains("unit"), "unexpected error: {error}");
}

#[test]
fn stack_v3_preserves_repository_and_release_identity_checks() {
    let mut wrong_repository = stack_v3_document();
    wrong_repository["repository"] = serde_json::json!("registrystack/other");
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&wrong_repository).unwrap()).is_err());

    let mut mismatched_release = stack_v3_document();
    mismatched_release["components"]["release"] = serde_json::json!("v0.45.0");
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&mismatched_release).unwrap()).is_err());
}

#[test]
fn duplicate_payload_name_is_rejected() {
    let mut value = document();
    let duplicate = value["payloads"][0].clone();
    value["payloads"].as_array_mut().unwrap().push(duplicate);
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn duplicate_component_document_member_is_rejected() {
    let raw = serde_json::to_string(&document()).unwrap();
    let needle = "\"launcher\":{\"linux-amd64\":";
    assert!(raw.contains(needle));
    let ambiguous = raw.replacen(
        needle,
        "\"launcher\":{\"linux-amd64\":null,\"linux-amd64\":",
        1,
    );
    assert!(ReleaseManifest::parse(ambiguous.as_bytes()).is_err());
}

#[test]
fn release_identity_must_use_canonical_version_text() {
    let mut value = document();
    value["release"]["tag"] = serde_json::json!("v00.44.0");
    value["release"]["version"] = serde_json::json!("00.44.0");
    value["components"]["release"] = serde_json::json!("v00.44.0");
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn plain_macos_binary_is_limited_to_registry_manifest() {
    let mut value = document();
    let asset = serde_json::json!({
        "name":"registry-manifest-v0.44.0-macos-arm64",
        "kind":"binary",
        "size":19,
        "sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    });
    value["payloads"]
        .as_array_mut()
        .unwrap()
        .push(asset.clone());
    value["components"]["components"]["manifest"] = serde_json::json!({
        "entrypoint":"registry-manifest",
        "dependencies":[],
        "platforms":{
            "macos-arm64":{
                "assets":[{
                    "name":asset["name"],
                    "size":asset["size"],
                    "sha256":asset["sha256"]
                }],
                "capabilities":{"tooling":true,"runtime":false}
            }
        }
    });
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&value).unwrap()).is_ok());

    value["payloads"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()["name"] = serde_json::json!("bregctl-v0.44.0-macos-arm64");
    value["components"]["components"]["manifest"]["entrypoint"] = serde_json::json!("bregctl");
    value["components"]["components"]["manifest"]["platforms"]["macos-arm64"]["assets"][0]
        ["name"] = serde_json::json!("bregctl-v0.44.0-macos-arm64");
    assert!(ReleaseManifest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
