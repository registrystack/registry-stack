// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_registry-manifest")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("registry-manifest-{name}-{nonce}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn help_flags_exit_zero_and_print_usage_to_stdout() {
    for flag in &["--help", "-h", "help"] {
        let output = Command::new(bin())
            .arg(flag)
            .output()
            .unwrap_or_else(|e| panic!("run cli with {flag}: {e}"));

        assert!(
            output.status.success(),
            "{flag} must exit 0, got {:?}",
            output.status.code()
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
        assert!(
            stdout.contains("usage:"),
            "{flag} stdout must contain usage text; got: {stdout}"
        );
        assert!(
            output.stderr.is_empty(),
            "{flag} must produce no stderr; got: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn render_rejects_undeclared_dcat_profile() {
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "dcat",
            "--profile",
            "bregdcat-ap",
        ])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.unsupported_application_profile"));
}

#[test]
fn validate_reports_stable_manifest_error_codes() {
    let dir = temp_dir("validate-errors");
    let unsupported = dir.join("unsupported.yaml");
    fs::write(
        &unsupported,
        r#"
schema_version: registry-manifest/v0
catalog:
  id: demo
  base_url: https://metadata.example.test/
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write unsupported manifest");
    let output = Command::new(bin())
        .args(["validate", unsupported.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.version_unsupported"));

    let invalid = dir.join("invalid.yaml");
    fs::write(
        &invalid,
        r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write invalid manifest");
    let output = Command::new(bin())
        .args(["validate", invalid.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.validation_failed"));
    assert!(stderr.contains("catalog.base_url"));
}

#[test]
fn publish_writes_every_indexed_artifact_without_undeclared_profiles() {
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let out = temp_dir("publish-example-person-schema");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out.join("dcat.bregdcat-ap.jsonld").exists());

    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index reads"))
            .expect("index json");
    assert_eq!(index["schema_version"], "registry-manifest-index/v1");
    assert_eq!(index["dcat_profiles"], serde_json::json!([]));
    assert_eq!(index["evidence_offering_documents"], serde_json::json!([]));
    assert_eq!(
        index["policy_documents"]
            .as_array()
            .expect("policies")
            .len(),
        1
    );
    assert_index_urls_exist(&out, &index);
    assert_well_known_discovery_matches_index(&out, &index);
    assert_api_catalog_points_at_index_and_catalogs(&out, &index);
}

#[test]
fn render_and_publish_cpsv_ap_service_catalogue() {
    let manifest =
        workspace_root().join("fixtures/cpsv-ap/health-linked-child-support.metadata.yaml");
    let output = Command::new(bin())
        .args(["render", manifest.to_str().unwrap(), "--format", "cpsv-ap"])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cpsv: serde_json::Value = serde_json::from_slice(&output.stdout).expect("cpsv json");
    assert_eq!(
        cpsv["@id"],
        "https://child-support.example.gov/metadata/cpsv-ap"
    );
    assert!(cpsv["@graph"]
        .as_array()
        .expect("@graph")
        .iter()
        .any(|node| {
            node["@type"] == "cpsv:PublicService"
                && node["cv:holdsRequirement"][0]["@id"]
                    == "https://child-support.example.gov/requirements/child-health-coverage"
        }));
    assert!(!String::from_utf8(output.stdout)
        .expect("stdout utf8")
        .contains("cv:hasInputType"));

    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "form-json-schema",
            "--form",
            "child-support-review-form",
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let form_schema: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("form schema json");
    assert_eq!(form_schema["properties"]["children"]["type"], "array");

    let out = temp_dir("publish-cpsv-ap");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.join("cpsv-ap").exists());
    assert!(out.join("cpsv-ap.jsonld").exists());
    assert!(out
        .join("forms")
        .join("child-support-review-form")
        .join("schema.json")
        .exists());
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index reads"))
            .expect("index json");
    assert_eq!(
        index["service_catalogues"][0]["url"],
        "/metadata/cpsv-ap.jsonld"
    );
    assert_eq!(
        index["service_catalogues"][0]["aliases"][0],
        "/metadata/cpsv-ap"
    );
    assert_eq!(
        index["service_catalogues"][0]["media_type"],
        "application/ld+json"
    );
    assert_eq!(
        index["form_schemas"][0]["url"],
        "/metadata/forms/child-support-review-form/schema.json"
    );
    assert_index_urls_exist(&out, &index);
    assert_well_known_discovery_matches_index(&out, &index);
    assert_api_catalog_points_at_index_and_catalogs(&out, &index);
}

#[test]
fn render_outputs_evidence_offerings_and_policy_artifacts() {
    let dir = temp_dir("render-evidence-and-policy");
    let manifest = dir.join("metadata.yaml");
    fs::write(
        &manifest,
        r#"
schema_version: registry-manifest/v1
catalog:
  id: evidence-and-policy
  base_url: https://metadata.example.test
  title: Evidence and Policy
  publisher:
    name: Publisher
requirements:
  - id: requirement
    iri: https://metadata.example.test/requirements/example
    title: Requirement
evidence_types:
  - id: evidence
    iri: https://metadata.example.test/evidence-types/example
    title: Evidence
    proves: [requirement]
datasets:
  - id: vital-events
    title: Vital Events
    entities:
      - name: person
        fields:
          - name: person_id
            type: string
    evidence_offerings:
      - id: person_evidence
        title: Person evidence
        evidence_type: evidence
        issuing_authority:
          id: authority
          name: Authority
        entity: person
        lookup_keys: [person_id]
        access:
          kind: partner-api
          ruleset: exact
"#,
    )
    .expect("write manifest");
    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "evidence-offerings",
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let offerings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("evidence offerings json");
    assert_eq!(offerings["evidence_offerings"][0]["id"], "person_evidence");

    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "policy",
            "--dataset",
            "vital-events",
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let policy: serde_json::Value = serde_json::from_slice(&output.stdout).expect("policy json");
    assert_eq!(policy["@type"], "odrl:Offer");
    assert_eq!(policy["@id"], "#policy-vital-events-offer");

    let out = dir.join("public");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index reads"))
            .expect("index json");
    assert_eq!(
        index["evidence_offering_documents"][0]["url"],
        "/metadata/evidence-offerings/person_evidence.json"
    );
    assert_eq!(
        index["policy_documents"][0]["url"],
        "/metadata/policies/vital-events.jsonld"
    );
    assert_index_urls_exist(&out, &index);
}

#[test]
fn validate_profiles_checks_descriptors_and_fixtures() {
    let profiles = workspace_root().join("profiles");
    let output = Command::new(bin())
        .args(["validate-profiles", profiles.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("validated 4 profile descriptors and fixtures"));
}

#[test]
fn validate_profiles_allows_empty_unsupported_mappings() {
    let root = temp_dir("empty-unsupported-mappings");
    let profile_dir = root.join("empty-unsupported");
    let fixtures_dir = profile_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("fixtures dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: empty-unsupported
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
unsupported_mappings: []
conformance_checks:
  - id: empty-unsupported.check
fixtures:
  - path: fixtures/metadata.yaml
"#,
    )
    .expect("write profile");
    fs::write(
        fixtures_dir.join("metadata.yaml"),
        r#"
schema_version: registry-manifest/v1
catalog:
  id: empty-unsupported
  base_url: https://metadata.example.test
  title: Empty Unsupported
  publisher:
    name: Publisher
profiles:
  - id: empty-unsupported
    version: "1"
datasets: []
"#,
    )
    .expect("write fixture");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_profiles_rejects_legacy_relay_schema_version() {
    let root = temp_dir("legacy-profile-schema");
    let profile_dir = root.join("legacy");
    fs::create_dir_all(&profile_dir).expect("profile dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-relay-profile/v1
profile:
  id: legacy
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
unsupported_mappings:
  - source: runtime source
conformance_checks:
  - id: legacy.check
fixtures:
  - path: fixtures/metadata.yaml
"#,
    )
    .expect("write profile");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.version_unsupported"));
}

fn assert_index_urls_exist(out: &Path, index: &serde_json::Value) {
    for key in [
        "manifest",
        "catalog",
        "evidence_offerings",
        "policies",
        "dcat",
        "shacl",
    ] {
        assert_url_exists(out, index[key].as_str().expect("url"));
    }
    for entry in index["evidence_offering_documents"]
        .as_array()
        .expect("evidence offerings")
    {
        assert_url_exists(out, entry["url"].as_str().expect("evidence offering url"));
    }
    for entry in index["policy_documents"].as_array().expect("policies") {
        assert_url_exists(out, entry["url"].as_str().expect("policy url"));
    }
    for entry in index["schemas"].as_array().expect("schemas") {
        assert_url_exists(out, entry["url"].as_str().expect("schema url"));
    }
    for entry in index["form_schemas"].as_array().expect("form schemas") {
        assert_url_exists(out, entry["url"].as_str().expect("form schema url"));
    }
    for entry in index["profiles"].as_array().expect("profiles") {
        assert_url_exists(out, entry["url"].as_str().expect("profile url"));
    }
    for entry in index["dcat_profiles"].as_array().expect("dcat profiles") {
        assert_url_exists(out, entry["url"].as_str().expect("profile url"));
    }
    for entry in index["service_catalogues"]
        .as_array()
        .expect("service catalogues")
    {
        assert_url_exists(out, entry["url"].as_str().expect("service catalogue url"));
    }
}

fn assert_well_known_discovery_matches_index(out: &Path, index: &serde_json::Value) {
    let discovery_path = out
        .parent()
        .expect("metadata out has parent")
        .join(".well-known")
        .join("registry-manifest.json");
    let discovery: serde_json::Value =
        serde_json::from_slice(&fs::read(discovery_path).expect("well-known reads"))
            .expect("well-known json");
    assert_eq!(
        discovery["schema_version"],
        "registry-manifest-discovery/v1"
    );
    assert_eq!(discovery["metadata_index"], "/metadata/index.json");
    assert_eq!(discovery["service_catalogues"], index["service_catalogues"]);
    assert_eq!(
        discovery["application_profiles"],
        index["application_profiles"]
    );
}

fn assert_api_catalog_points_at_index_and_catalogs(out: &Path, index: &serde_json::Value) {
    let api_catalog_path = out
        .parent()
        .expect("metadata out has parent")
        .join(".well-known")
        .join("api-catalog");
    let api_catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(api_catalog_path).expect("api-catalog reads"))
            .expect("api-catalog json");
    let linkset = api_catalog["linkset"].as_array().expect("linkset");
    assert_eq!(linkset[0]["anchor"], "/.well-known/api-catalog");
    assert_eq!(linkset[0]["describedby"][0]["href"], "/metadata/index.json");
    let item_hrefs = linkset[0]["item"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["href"].as_str().expect("item href"))
        .collect::<Vec<_>>();
    assert!(item_hrefs.contains(&index["catalog"].as_str().expect("catalog url")));
    assert!(item_hrefs.contains(&index["dcat"].as_str().expect("dcat url")));
    for entry in index["service_catalogues"]
        .as_array()
        .expect("service catalogues")
    {
        assert!(item_hrefs.contains(&entry["url"].as_str().expect("service catalogue url")));
    }
}

fn assert_url_exists(out: &Path, url: &str) {
    let relative = url
        .strip_prefix("/metadata/")
        .unwrap_or_else(|| panic!("unexpected metadata URL: {url}"));
    assert!(
        out.join(relative).exists(),
        "missing indexed artifact: {url}"
    );
}
