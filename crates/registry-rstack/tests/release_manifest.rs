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
