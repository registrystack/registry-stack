// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

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

fn manifest_product_root() -> PathBuf {
    workspace_root().join("products/manifest")
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

fn write_minimal_manifest(path: &Path, body: &str) {
    fs::write(
        path,
        format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
{body}
"#
        ),
    )
    .expect("write manifest");
}

fn output_with_timeout(command: &mut Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn command");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("poll command").is_some() {
            return child.wait_with_output().expect("collect output");
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect killed output");
            panic!(
                "command timed out after {timeout:?}; stdout: {}; stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
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
fn version_reports_the_shared_build_identity() {
    let output = Command::new(bin())
        .arg("--version")
        .output()
        .expect("run cli with --version");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout utf8"),
        format!(
            "registry-manifest {}\n",
            registry_platform_buildinfo::DISPLAY_VERSION
        )
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn no_command_keeps_the_existing_usage_error() {
    let output = Command::new(bin())
        .output()
        .expect("run cli without a command");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .expect("stderr utf8")
        .contains("usage: registry-manifest validate"));
}

#[test]
fn render_rejects_undeclared_dcat_profile() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
fn validate_and_render_multi_dataset_distribution_fixture() {
    let manifest =
        manifest_product_root().join("profiles/example-multi-dataset/fixtures/metadata.yaml");
    let validate = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("validate multi-dataset fixture");
    assert!(
        validate.status.success(),
        "validation failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let render = Command::new(bin())
        .args(["render", manifest.to_str().unwrap(), "--format", "dcat"])
        .output()
        .expect("render multi-dataset fixture");
    assert!(
        render.status.success(),
        "render failed: {}",
        String::from_utf8_lossy(&render.stderr)
    );
    let dcat: serde_json::Value =
        serde_json::from_slice(&render.stdout).expect("rendered DCAT JSON");
    let datasets = dcat["dcat:dataset"].as_array().unwrap();
    assert_eq!(datasets.len(), 2);
    let legal_entities = datasets
        .iter()
        .find(|dataset| dataset["dcterms:identifier"] == "legal-entities")
        .expect("legal-entities dataset");
    assert_eq!(
        legal_entities["dcat:distribution"][0]["@type"],
        "dcat:Distribution"
    );
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
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.metadata.unsupported-version]"));
    assert!(stderr.contains("unsupported.yaml:2:17 /schema_version"));

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
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.metadata.invalid-url]"));
    assert!(stderr.contains("invalid.yaml:5:13 /catalog/base_url"));
    assert!(
        !stderr.contains("metadata.example.test"),
        "a diagnostic must not repeat the refused value: {stderr}"
    );
}

#[test]
fn validate_prints_source_digest_and_rejects_runtime_only_keys() {
    let dir = temp_dir("validate-digest");
    let valid = dir.join("valid.yaml");
    write_minimal_manifest(&valid, "datasets: []\n");

    let output = Command::new(bin())
        .arg("validate")
        .arg(&valid)
        .output()
        .expect("run cli");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("source_manifest_digest: sha256:"));

    let endpoints = dir.join("endpoints.yaml");
    write_minimal_manifest(
        &endpoints,
        r#"
data_services:
  - id: person_api
    title: Person API
    endpoint_url: https://registry.example.test/v1/person
    serves_datasets: [people]
datasets:
  - id: people
    title: People
"#,
    );
    let output = Command::new(bin())
        .arg("validate")
        .arg(&endpoints)
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "a declared endpoint URL should be source metadata, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let invalid = dir.join("runtime-only.yaml");
    write_minimal_manifest(
        &invalid,
        r#"
datasets:
  - id: ds
    title: Dataset
    entities:
      - name: person
        title: Person
        source: people_table
"#,
    );
    let output = Command::new(bin())
        .arg("validate")
        .arg(&invalid)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.metadata.runtime-only-key]"));
    assert!(stderr.contains("/datasets/0/entities/0/source"));
}

#[test]
fn publish_writes_every_indexed_artifact_without_undeclared_profiles() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
    let ogc_records_path = out.join("ogc-records").join("items.json");
    assert!(ogc_records_path.exists());
    assert_eq!(
        index["ogc_records_items"],
        "/metadata/ogc-records/items.json"
    );
    let ogc_records: serde_json::Value =
        serde_json::from_slice(&fs::read(&ogc_records_path).expect("ogc records reads"))
            .expect("ogc records json");
    assert_eq!(
        ogc_records["schema_version"],
        "registry-manifest-ogc-records/v1"
    );
    assert_eq!(ogc_records["type"], "FeatureCollection");
    assert_index_urls_exist(&out, &index);
    assert_well_known_discovery_matches_index(&out, &index);
    assert_api_catalog_points_at_index_and_catalogs(&out, &index);
}

#[test]
fn publish_writes_stable_package_digest_and_artifact_digests() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let first = temp_dir("publish-digest-first");
    let second = temp_dir("publish-digest-second");

    for out in [&first, &second] {
        let site_root = out.join("site");
        let output = Command::new(bin())
            .args([
                "publish",
                manifest.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--site-root",
                site_root.to_str().unwrap(),
            ])
            .output()
            .expect("run cli");
        assert!(
            output.status.success(),
            "publish failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let first_index: serde_json::Value =
        serde_json::from_slice(&fs::read(first.join("index.json")).expect("index reads"))
            .expect("index parses");
    let second_index: serde_json::Value =
        serde_json::from_slice(&fs::read(second.join("index.json")).expect("index reads"))
            .expect("index parses");

    let source_digest = first_index["source_manifest_digest"]
        .as_str()
        .expect("source digest");
    assert!(source_digest.starts_with("sha256:"));
    assert_eq!(source_digest.len(), "sha256:".len() + 64);
    assert_eq!(
        first_index["source_manifest_digest"],
        second_index["source_manifest_digest"]
    );
    assert_eq!(
        first_index["package_digest"],
        second_index["package_digest"]
    );

    let artifacts = first_index["artifacts"].as_array().expect("artifacts");
    assert!(artifacts.iter().any(|artifact| {
        artifact["path"] == "metadata.yaml"
            && artifact["sha256"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:"))
    }));
    assert!(artifacts.iter().any(|artifact| {
        artifact["path"] == "ogc-records/items.json"
            && artifact["media_type"] == "application/geo+json"
            && artifact["sha256"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:"))
    }));
    assert!(!artifacts.iter().any(|artifact| artifact["path"]
        .as_str()
        .is_some_and(|path| path.starts_with(".well-known/"))));
}

#[derive(Debug, Deserialize)]
struct BetaPublishIndexReader {
    schema_version: String,
    artifacts: Vec<BetaArtifactReader>,
    manifest: String,
    catalog: String,
    evidence_offerings: String,
    policies: String,
    dcat: String,
    shacl: String,
}

#[derive(Debug, Deserialize)]
struct BetaArtifactReader {
    path: String,
    media_type: String,
    sha256: String,
}

#[test]
fn publish_bundle_readers_tolerate_additive_artifacts() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let out = temp_dir("publish-additive-artifact");
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
        "publish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fs::write(
        out.join("provenance.jsonld"),
        br#"{"@context": {}, "@graph": []}"#,
    )
    .expect("write additive artifact");
    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index reads"))
            .expect("index parses");
    index["artifacts"]
        .as_array_mut()
        .expect("artifacts")
        .push(serde_json::json!({
            "path": "provenance.jsonld",
            "media_type": "application/ld+json",
            "sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "profile": "https://www.w3.org/TR/prov-o/"
        }));
    index["provenance"] = serde_json::json!("/metadata/provenance.jsonld");

    let parsed: BetaPublishIndexReader =
        serde_json::from_value(index.clone()).expect("beta reader parses additive bundle index");
    assert_eq!(parsed.schema_version, "registry-manifest-index/v1");
    assert_eq!(parsed.manifest, "/metadata/metadata.yaml");
    assert_eq!(parsed.catalog, "/metadata/catalog.json");
    assert_eq!(
        parsed.evidence_offerings,
        "/metadata/evidence-offerings.json"
    );
    assert_eq!(parsed.policies, "/metadata/policies.jsonld");
    assert_eq!(parsed.dcat, "/metadata/dcat.jsonld");
    assert_eq!(parsed.shacl, "/metadata/shacl.jsonld");
    assert!(parsed.artifacts.iter().any(|artifact| {
        artifact.path == "provenance.jsonld"
            && artifact.media_type == "application/ld+json"
            && artifact.sha256.starts_with("sha256:")
    }));
    assert_index_urls_exist(&out, &index);
}

#[test]
fn render_and_publish_cpsv_ap_service_catalogue() {
    let manifest =
        manifest_product_root().join("fixtures/cpsv-ap/health-linked-child-support.metadata.yaml");
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
fn validate_profiles_checks_canonical_examples_without_relay_copies() {
    let profiles = manifest_product_root().join("profiles");
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
    assert!(stdout.contains("validated 5 profile descriptors and fixtures"));

    for profile in [
        "example-benefits-sync",
        "example-civil-registration",
        "example-multi-dataset",
        "example-person-schema",
        "example-social-benefits",
    ] {
        let profile_root = profiles.join(profile);
        assert!(
            profile_root.join("profile.yaml").is_file(),
            "missing canonical descriptor for {profile}"
        );
        assert!(
            profile_root.join("fixtures/metadata.yaml").is_file(),
            "missing canonical fixture for {profile}"
        );
    }
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

fn assert_index_urls_exist(out: &Path, index: &serde_json::Value) {
    for key in [
        "manifest",
        "catalog",
        "evidence_offerings",
        "policies",
        "dcat",
        "shacl",
        "ogc_records_items",
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
    let discovery_path = out.join(".well-known").join("registry-manifest.json");
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
    let api_catalog_path = out.join(".well-known").join("api-catalog");
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
    assert!(item_hrefs.contains(
        &index["ogc_records_items"]
            .as_str()
            .expect("ogc records url")
    ));
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

fn collect_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if !root.exists() {
        return paths;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            paths.push(path);
        }
    }
    paths
}

#[test]
fn publish_default_writes_only_inside_out() {
    let parent = temp_dir("publish-contained-parent");
    let out = parent.join("metadata");
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let status = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .status()
        .expect("run cli");
    assert!(status.success(), "publish must succeed");

    let stray = collect_paths(&parent)
        .into_iter()
        .filter(|path| !path.starts_with(&out))
        .collect::<Vec<_>>();
    assert!(
        stray.is_empty(),
        "publish wrote files outside --out: {stray:?}"
    );

    assert!(out.join(".well-known").join("api-catalog").exists());
    assert!(out
        .join(".well-known")
        .join("registry-manifest.json")
        .exists());
}

#[test]
fn publish_with_site_root_writes_well_known_under_site_root_only() {
    let parent = temp_dir("publish-site-root-parent");
    let out = parent.join("metadata");
    let site_root = parent.join("site");
    fs::create_dir_all(&site_root).expect("site root");

    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let status = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--site-root",
            site_root.to_str().unwrap(),
        ])
        .status()
        .expect("run cli");
    assert!(status.success(), "publish must succeed");

    assert!(site_root.join(".well-known").join("api-catalog").exists());
    assert!(site_root
        .join(".well-known")
        .join("registry-manifest.json")
        .exists());
    assert!(!out.join(".well-known").exists(),);
    assert!(out.join("catalog.json").exists());
    assert!(out.join("index.json").exists());

    let stray = collect_paths(&parent)
        .into_iter()
        .filter(|path| !path.starts_with(&out) && !path.starts_with(&site_root))
        .collect::<Vec<_>>();
    assert!(
        stray.is_empty(),
        "publish wrote files outside --out ∪ --site-root: {stray:?}"
    );
}

#[cfg(unix)]
#[test]
fn publish_rejects_preexisting_symlink_directories_under_out() {
    use std::os::unix::fs::symlink;

    let parent = temp_dir("publish-symlink-out");
    let out = parent.join("metadata");
    let outside = parent.join("outside");
    fs::create_dir_all(&out).expect("out dir");
    fs::create_dir_all(&outside).expect("outside dir");
    symlink(&outside, out.join("schema")).expect("schema symlink");

    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");

    assert!(!output.status.success(), "publish must reject symlink path");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("metadata.publish.path_escape"),
        "stderr missing path escape error: {stderr}"
    );
    assert!(
        collect_paths(&outside).is_empty(),
        "publish wrote through pre-existing symlink"
    );
}

#[test]
fn publish_fails_closed_on_malformed_manifest() {
    let dir = temp_dir("publish-malformed");
    let manifest = dir.join("metadata.yaml");
    fs::write(
        &manifest,
        r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: not-a-url
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write malformed manifest");
    let out = dir.join("out");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");
    assert_eq!(
        output.status.code(),
        Some(1),
        "publish must refuse the manifest"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.metadata.invalid-url]"));
}

#[test]
fn publish_fails_closed_when_out_cannot_be_created() {
    let dir = temp_dir("publish-bad-out");
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let blocker = dir.join("blocker");
    fs::write(&blocker, b"not a directory").expect("write blocker");
    let out = blocker.join("nested");
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
        !output.status.success(),
        "publish must exit non-zero when --out cannot be created"
    );
}

#[test]
fn publish_rejects_profile_id_path_escapes_without_writing_outside_out() {
    let dir = temp_dir("publish-profile-escape");
    let out = dir.join("out");
    let outside = dir.join("outside");
    fs::create_dir_all(&outside).expect("outside dir");

    let absolute_profile_id = outside
        .join("absolute-escape")
        .to_str()
        .expect("utf8 path")
        .to_string();
    let cases = [
        ("relative", "../../outside/relative-escape".to_string()),
        ("absolute", absolute_profile_id),
    ];

    for (name, profile_id) in cases {
        let manifest = dir.join(format!("{name}.yaml"));
        write_minimal_manifest(
            &manifest,
            &format!(
                r#"
profiles:
  - id: "{profile_id}"
    version: "1"
datasets: []
"#
            ),
        );

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
            !output.status.success(),
            "{name} profile id escape must fail closed"
        );
        assert!(
            !outside.join(format!("{name}-escape.json")).exists(),
            "{name} profile id escape wrote outside --out"
        );
    }
}

#[test]
fn render_reports_required_flag_errors() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");

    for (format, expected) in &[
        (
            "evidence-offering",
            "evidence-offering render requires --offering <id>",
        ),
        ("policy", "policy render requires --dataset <id>"),
        (
            "form-json-schema",
            "form-json-schema render requires --form <id>",
        ),
        (
            "json-schema",
            "json-schema render requires --dataset <id> and --entity <name>",
        ),
    ] {
        let output = Command::new(bin())
            .args(["render", manifest.to_str().unwrap(), "--format", format])
            .output()
            .expect("run cli");
        assert!(!output.status.success(), "format {format} must fail closed");
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            stderr.contains(expected),
            "stderr {stderr:?} missing {expected:?}"
        );
    }
}

#[test]
fn render_reports_lookup_errors_and_unsupported_format() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");

    let cases: &[(&[&str], &str)] = &[
        (
            &["render", "--format", "policy", "--dataset", "missing"],
            "dataset not found: missing",
        ),
        (
            &[
                "render",
                "--format",
                "json-schema",
                "--dataset",
                "missing",
                "--entity",
                "person",
            ],
            "entity not found: missing/person",
        ),
        (
            &[
                "render",
                "--format",
                "form-json-schema",
                "--form",
                "missing",
            ],
            "form not found: missing",
        ),
        (
            &[
                "render",
                "--format",
                "evidence-offering",
                "--offering",
                "missing",
            ],
            "evidence offering not found: missing",
        ),
        (
            &["render", "--format", "unicorn-schema"],
            "unsupported render format: unicorn-schema",
        ),
    ];

    for (args, expected) in cases {
        let mut full = vec!["render", manifest.to_str().unwrap()];
        full.extend_from_slice(&args[1..]);
        let output = Command::new(bin()).args(&full).output().expect("run cli");
        assert!(!output.status.success(), "{args:?} must fail closed");
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            stderr.contains(expected),
            "stderr {stderr:?} missing {expected:?}"
        );
    }
}

#[test]
fn render_dcat_with_unsupported_profile_fails_closed() {
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "dcat",
            "--profile",
            "not-a-real-profile",
        ])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.unsupported_application_profile"));
}

#[test]
fn validate_reports_missing_manifest_file() {
    let output = Command::new(bin())
        .args(["validate", "/this/path/does/not/exist.yaml"])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.metadata.missing-file]"));
}

#[test]
fn validate_reports_yaml_parse_failure() {
    let dir = temp_dir("validate-yaml-parse");
    let manifest = dir.join("broken.yaml");
    fs::write(&manifest, b": : not yaml :\n - foo\n").expect("write broken yaml");
    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml.syntax]"));
}

#[test]
fn validate_rejects_yaml_larger_than_one_mib_before_parse() {
    let dir = temp_dir("validate-yaml-too-large");
    let manifest = dir.join("oversize.yaml");
    fs::write(&manifest, "[".repeat(1024 * 1024 + 1)).expect("write oversized yaml");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml.too-large]"));
    assert!(
        !stderr.contains("yaml.syntax"),
        "oversized input must fail before YAML parse: {stderr}"
    );
}

#[test]
fn validate_rejects_nested_flow_yaml_larger_than_one_mib_before_parse() {
    let dir = temp_dir("validate-nested-flow-too-large");
    let manifest = dir.join("nested-flow-oversize.yaml");
    let raw = format!(
        "{}{}",
        "[".repeat(512 * 1024 + 1),
        "]".repeat(512 * 1024 + 1)
    );
    fs::write(&manifest, raw).expect("write oversized nested flow yaml");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml.too-large]"));
    assert!(
        !stderr.contains("yaml.syntax"),
        "oversized nested-flow input must fail before YAML parse: {stderr}"
    );
}

#[test]
fn validate_rejects_yaml_anchors_and_aliases_from_parser_tokens() {
    let dir = temp_dir("validate-yaml-anchors");
    let cases = [
        (
            "anchored-scalar",
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: &title Demo
  publisher:
    name: *title
datasets: []
"#,
        ),
        (
            "anchored-sequence",
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets: &datasets []
"#,
        ),
        (
            "anchored-mapping",
            r#"
schema_version: registry-manifest/v1
catalog: &catalog
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
        ),
        (
            "flow-alias",
            r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets: [&dataset {id: demo, title: Demo, entities: []}, *dataset]
"#,
        ),
    ];

    for (name, raw) in cases {
        let manifest = dir.join(format!("{name}.yaml"));
        fs::write(&manifest, raw).expect("write manifest");
        let output = Command::new(bin())
            .args(["validate", manifest.to_str().unwrap()])
            .output()
            .expect("run cli");

        assert_eq!(output.status.code(), Some(1), "{name} must fail closed");
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            stderr.contains("error[yaml.anchor]"),
            "{name} stderr missing anchor error: {stderr}"
        );
    }
}

#[test]
fn validate_rejects_nested_anchored_mapping_quickly() {
    let dir = temp_dir("validate-nested-anchor");
    let manifest = dir.join("metadata.yaml");
    fs::write(
        &manifest,
        r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets:
  - id: demo
    title: Demo
    entities:
      - name: amplified
        fields:
          - &field
            name: a
            type: string
          - *field
          - *field
          - *field
          - *field
codelists: []
"#,
    )
    .expect("write manifest");

    let output = output_with_timeout(
        Command::new(bin()).args(["validate", manifest.to_str().unwrap()]),
        Duration::from_secs(5),
    );

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("error[yaml.anchor]") && stderr.contains("error[yaml.alias]"),
        "stderr missing anchor or alias error: {stderr}"
    );
}

#[test]
fn validate_allows_literal_ampersands_and_asterisks_in_yaml_content() {
    let dir = temp_dir("validate-yaml-literals");
    let manifest = dir.join("metadata.yaml");
    fs::write(
        &manifest,
        r#"
# A comment with &anchor-looking and *alias-looking text.
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: "https://metadata.example.test/catalog?left=a&right=*"
  title: |
    Demo title with & and * characters.
  publisher:
    name: "Publisher & Partner * Literal"
datasets: []
"#,
    )
    .expect("write manifest");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn validate_allows_anchor_like_tokens_inside_yaml_content() {
    let dir = temp_dir("validate-yaml-anchor-like-literals");
    let manifest = dir.join("metadata.yaml");
    fs::write(
        &manifest,
        r#"
# A comment with : *alias, [*alias, and { *alias } text.
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: "https://metadata.example.test/catalog?op=: *literal&next=: &literal"
  title: |
    Block scalar with : *alias, : &anchor, [*alias, and { *alias } text.
  publisher:
    name: "Publisher with : *literal and : &literal"
datasets: []
"#,
    )
    .expect("write manifest");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unknown_subcommand_returns_usage() {
    let output = Command::new(bin())
        .arg("teleport")
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("usage:"));
}

#[test]
fn validate_profiles_reports_missing_directory_and_empty_root() {
    let output = Command::new(bin())
        .args(["validate-profiles", "/no/such/profiles/dir"])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.profile.missing-directory]"));

    let empty_root = temp_dir("empty-profile-root");
    let output = Command::new(bin())
        .args(["validate-profiles", empty_root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.profile.no-descriptors]"));
}

#[test]
fn validate_profiles_rejects_descriptor_yaml_anchors() {
    let root = temp_dir("profile-descriptor-anchor");
    let profile_dir = root.join("anchored");
    fs::create_dir_all(&profile_dir).expect("profile dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile: &profile
  id: anchored
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: anchored.check
fixtures: []
"#,
    )
    .expect("write profile");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml.anchor]"));
    assert!(stderr.contains("profile.yaml:3:10 /profile"));
}

#[test]
fn validate_profiles_rejects_fixture_yaml_anchors_before_typed_or_value_parse() {
    let root = temp_dir("profile-fixture-anchor");
    let profile_dir = root.join("anchored-fixture");
    let fixtures_dir = profile_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("fixtures dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: anchored-fixture
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: anchored-fixture.check
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
  id: anchored-fixture
  base_url: https://metadata.example.test
  title: &title Anchored Fixture
  publisher:
    name: *title
profiles:
  - id: anchored-fixture
    version: "1"
datasets: []
"#,
    )
    .expect("write fixture");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml.anchor]"));
    assert!(stderr.contains("error[yaml.alias]"));
    assert!(stderr.contains("fixtures/metadata.yaml:6:10"));
}

#[test]
fn validate_profiles_reports_descriptor_and_fixture_misalignment() {
    let root = temp_dir("profile-fixture-checks");
    let profile_dir = root.join("misalign");
    let fixtures_dir = profile_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("fixtures dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: misalign
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: misalign.check
required_concepts:
  - iri: https://metadata.example.test/concepts/missing
required_identifiers:
  - entity: person
    name: missing_id
    kind: legal-id
cardinality_expectations:
  - entity: person
    field: missing_field
    min: 1
    max: 1
codelist_expectations:
  - id: missing-codelist
    required_codes: [alpha]
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
  id: misalign
  base_url: https://metadata.example.test
  title: Misalign
  publisher:
    name: Publisher
profiles:
  - id: misalign
    version: "1"
datasets:
  - id: vital-events
    title: Vital Events
    entities:
      - name: person
        fields:
          - name: person_id
            type: string
"#,
    )
    .expect("write fixture");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success(), "expected failure");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(1));
    for code in [
        "manifest.profile.required-concept-missing",
        "manifest.profile.identifier-missing",
        "manifest.profile.cardinality-mismatch",
        "manifest.profile.codelist-mismatch",
    ] {
        assert!(
            combined.contains(code),
            "expected `{code}` in output, got:\n{combined}"
        );
    }
}

#[test]
fn validate_profiles_reports_descriptor_field_errors() {
    let root = temp_dir("profile-descriptor-errors");
    let profile_dir = root.join("misnamed");
    fs::create_dir_all(&profile_dir).expect("profile dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: other-name
  version: ""
supported_input_artifacts: []
conformance_checks: []
fixtures: []
"#,
    )
    .expect("write profile");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.profile.id-mismatch]"));
    assert!(stderr.contains("/profile/id"));
    assert!(stderr.contains("error[manifest.profile.empty-value]"));
    assert!(stderr.contains("/profile/version"));
    for list in [
        "/supported_input_artifacts",
        "/conformance_checks",
        "/fixtures",
    ] {
        assert!(
            stderr.contains(&format!("{list}\n")),
            "expected an empty-list finding at {list}: {stderr}"
        );
    }
    assert_eq!(
        stderr.matches("error[manifest.profile.empty-list]").count(),
        3
    );
}

#[test]
fn validate_profiles_reports_missing_fixture_and_claim() {
    let root = temp_dir("profile-fixture-missing");
    let profile_dir = root.join("missing-fixture");
    fs::create_dir_all(&profile_dir).expect("profile dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: missing-fixture
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: missing-fixture.check
fixtures:
  - path: fixtures/nonexistent.yaml
"#,
    )
    .expect("write profile");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.profile.missing-fixture]"));
    assert!(stderr.contains("/fixtures/0/path"));
}

#[test]
fn validate_profiles_reports_unparseable_fixture() {
    let root = temp_dir("profile-fixture-unparseable");
    let profile_dir = root.join("unparseable");
    let fixtures_dir = profile_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("fixtures dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: unparseable
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: unparseable.check
fixtures:
  - path: fixtures/metadata.yaml
"#,
    )
    .expect("write profile");
    fs::write(fixtures_dir.join("metadata.yaml"), b": : nope :\n").expect("write fixture");
    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[yaml."));
    assert!(stderr.contains("fixtures/metadata.yaml:1:"));
}

#[test]
fn validate_profiles_reports_claim_missing() {
    let root = temp_dir("profile-claim-missing");
    let profile_dir = root.join("claim-missing");
    let fixtures_dir = profile_dir.join("fixtures");
    fs::create_dir_all(&fixtures_dir).expect("fixtures dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        r#"
schema_version: registry-manifest-profile/v1
profile:
  id: claim-missing
  version: "1"
supported_input_artifacts:
  - kind: metadata_manifest
conformance_checks:
  - id: claim-missing.check
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
  id: claim-missing
  base_url: https://metadata.example.test
  title: Claim Missing
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write fixture");

    let output = Command::new(bin())
        .args(["validate-profiles", root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[manifest.profile.claim-missing]"));
    assert!(stderr.contains("  note: ") && stderr.contains("fixtures/metadata.yaml the fixture"));
}

#[test]
fn publish_fails_closed_when_site_root_is_a_file() {
    let dir = temp_dir("publish-site-root-file");
    let manifest =
        manifest_product_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let site_root = dir.join("site-as-file");
    fs::write(&site_root, b"not a directory").expect("write site root file");
    let out = dir.join("out");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--site-root",
            site_root.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");
    assert!(
        !output.status.success(),
        "publish must exit non-zero when --site-root is a file"
    );
}

#[test]
fn validate_and_render_multi_vocabulary_field_concepts() {
    let manifest = manifest_product_root()
        .join("fixtures/semantic-concepts/aligned-person-concepts.metadata.yaml");
    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(bin())
        .args(["render", manifest.to_str().unwrap(), "--format", "shacl"])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        !rendered.contains("skos:exactMatch"),
        "listing several concepts on one field must not render an equivalence claim"
    );

    let shacl: serde_json::Value = serde_json::from_str(&rendered).expect("shacl json");
    let properties = shacl["@graph"]
        .as_array()
        .expect("@graph")
        .iter()
        .find(|node| node["@type"] == "sh:NodeShape")
        .expect("node shape")["sh:property"]
        .as_array()
        .expect("property shapes")
        .clone();
    let path_for = |name: &str| {
        properties
            .iter()
            .find(|property| property["sh:name"] == name)
            .unwrap_or_else(|| panic!("property shape for {name}"))["sh:path"]
            .as_str()
            .expect("sh:path")
            .to_string()
    };
    assert_eq!(
        path_for("birth_date"),
        "https://publicschema.org/date_of_birth",
        "the first concept must supply the generated property identifier"
    );
    assert_eq!(
        path_for("given_name"),
        "https://publicschema.org/given_name"
    );
    assert_eq!(
        path_for("person_id"),
        "https://person-register.example.gov/metadata/datasets/person-register/entities/person/fields/person_id",
        "a field with no concept must fall back to its deterministic manifest URI"
    );
}

fn json_report(output: &Output) -> serde_json::Value {
    assert!(
        output.stderr.is_empty(),
        "--format json writes only the report: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("a JSON report on stdout")
}

fn write_profile(root: &Path, name: &str, extra: &str, fixtures: &str) -> PathBuf {
    let profile_dir = root.join(name);
    fs::create_dir_all(profile_dir.join("fixtures")).expect("profile dir");
    fs::write(
        profile_dir.join("profile.yaml"),
        format!(
            "schema_version: registry-manifest-profile/v1\nprofile:\n  id: {name}\n  \
             version: \"1\"\nsupported_input_artifacts:\n  - kind: metadata_manifest\n\
             conformance_checks:\n  - id: {name}.check\nfixtures:\n{fixtures}{extra}"
        ),
    )
    .expect("write profile");
    profile_dir
}

#[test]
fn validate_reports_json_with_the_shared_envelope_and_exit_codes() {
    let dir = temp_dir("validate-json");
    let valid = dir.join("valid.yaml");
    write_minimal_manifest(&valid, "datasets: []\n");
    let output = Command::new(bin())
        .args(["validate", "--format", "json"])
        .arg(&valid)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(0));
    let report = json_report(&output);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "validate");
    assert_eq!(report["status"], "complete");
    assert_eq!(
        report["apiVersion"],
        "id.registrystack.org/formats/manifest/ctl-report/v1alpha1"
    );
    assert_eq!(report["kind"], "ManifestCtlReport");
    assert_eq!(report["filesChecked"], 1);
    assert_eq!(report["errors"], 0);
    assert!(report["sourceManifestDigest"]
        .as_str()
        .expect("a digest")
        .starts_with("sha256:"));

    let refused = dir.join("refused.yaml");
    write_minimal_manifest(&refused, "datasets: []\nunexpected: true\n");
    let output = Command::new(bin())
        .args(["validate", "--format=json"])
        .arg(&refused)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "domain-refusal");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "config.unknown-key");
    assert_eq!(diagnostic["path"], "/unexpected");
    assert_eq!(diagnostic["source"]["line"], 10);

    let output = Command::new(bin())
        .args(["validate", "--format", "json"])
        .arg(dir.join("absent.yaml"))
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(3));
    let report = json_report(&output);
    assert_eq!(report["status"], "operational-failure");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "manifest.metadata.missing-file"
    );

    let output = Command::new(bin())
        .args(["validate", "--format", "json"])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(2));
    let report = json_report(&output);
    assert_eq!(report["status"], "usage-error");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "manifest.usage.invalid-arguments"
    );
}

/// The registered example of the report format (CFG-SCHEMA-1) is this
/// command's own output.
#[test]
fn the_report_example_is_the_validate_output() {
    let example = manifest_product_root().join("examples/ctl-report/validate.json");
    let output = Command::new(bin())
        .current_dir(manifest_product_root())
        .args([
            "validate",
            "--format",
            "json",
            "profiles/example-benefits-sync/fixtures/metadata.yaml",
        ])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(example).expect("the report example"),
        String::from_utf8(output.stdout).expect("stdout utf8"),
        "regenerate it with `registry-manifest validate --format json \
         profiles/example-benefits-sync/fixtures/metadata.yaml` from products/manifest"
    );
}

#[test]
fn validate_refuses_null_and_substitution_without_repeating_values() {
    let dir = temp_dir("validate-null-substitution");
    let null = dir.join("null.yaml");
    write_minimal_manifest(
        &null,
        "datasets:\n  - id: people\n    title: People\n    description: null\n",
    );
    let output = Command::new(bin())
        .arg("validate")
        .arg(&null)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("error[config.null-value]"), "{stderr}");
    assert!(
        stderr.contains("null.yaml:12:18 /datasets/0/description"),
        "{stderr}"
    );

    let substituted = dir.join("substituted.yaml");
    write_minimal_manifest(
        &substituted,
        "datasets:\n  - id: people\n    title: ${DATASET_TITLE}\n",
    );
    let output = Command::new(bin())
        .arg("validate")
        .arg(&substituted)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("error[config.substitution-not-allowed]"),
        "{stderr}"
    );
    assert!(stderr.contains("/datasets/0/title"), "{stderr}");
    assert!(!stderr.contains("DATASET_TITLE"), "{stderr}");
}

#[test]
fn validate_profiles_refuses_the_retired_generator_command_key() {
    let root = temp_dir("profile-generator-command");
    write_profile(
        &root,
        "retired",
        "generator_command: null\n",
        "  - path: fixtures/metadata.yaml\n",
    );
    let output = Command::new(bin())
        .args(["validate-profiles", "--format", "json"])
        .arg(&root)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert_eq!(diagnostics.len(), 1, "{report:#}");
    assert_eq!(diagnostics[0]["code"], "config.unknown-key");
    assert_eq!(diagnostics[0]["path"], "/generator_command");
}

#[test]
fn validate_profiles_refuses_a_fixture_path_outside_its_profile() {
    let root = temp_dir("profile-fixture-escape");
    write_profile(&root, "escape", "", "  - path: ../outside.yaml\n");
    let output = Command::new(bin())
        .args(["validate-profiles"])
        .arg(&root)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("error[manifest.profile.fixture-path-escapes]"),
        "{stderr}"
    );
    assert!(stderr.contains("/fixtures/0/path"), "{stderr}");
    assert!(!stderr.contains("outside.yaml"), "{stderr}");
}

#[test]
fn validate_profiles_refuses_a_fixture_link_that_resolves_outside_its_profile() {
    use std::os::unix::fs::symlink;

    let root = temp_dir("profile-fixture-link");
    let profile_dir = write_profile(&root, "linked", "", "  - path: fixtures/metadata.yaml\n");
    let outside = temp_dir("profile-fixture-link-outside").join("metadata.yaml");
    write_minimal_manifest(
        &outside,
        "profiles:\n  - id: linked\n    version: \"1\"\ndatasets: []\n",
    );
    symlink(&outside, profile_dir.join("fixtures/metadata.yaml")).expect("fixture symlink");

    let output = Command::new(bin())
        .args(["validate-profiles", "--format", "json"])
        .arg(&root)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    let found = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| {
            (
                diagnostic["code"].as_str().expect("code"),
                diagnostic["path"].as_str().expect("path"),
                diagnostic["source"]["line"].as_u64(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [(
            "manifest.profile.fixture-path-escapes",
            "/fixtures/0/path",
            Some(10)
        )]
    );
    let text = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(!text.contains("profile-fixture-link-outside"), "{text}");
}

#[test]
fn validate_profiles_warns_on_an_unlisted_file_and_deny_warnings_refuses_it() {
    let root = temp_dir("profile-unlisted");
    let profile_dir = write_profile(&root, "unlisted", "", "  - path: fixtures/metadata.yaml\n");
    write_minimal_manifest(
        &profile_dir.join("fixtures/metadata.yaml"),
        "profiles:\n  - id: unlisted\n    version: \"1\"\ndatasets: []\n",
    );
    write_minimal_manifest(&profile_dir.join("fixtures/stray.yaml"), "datasets: []\n");

    let output = Command::new(bin())
        .arg("validate-profiles")
        .arg(&root)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("warning[manifest.profile.unlisted-file]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("0 errors, 1 warning in 2 files"),
        "{stdout}"
    );

    let output = Command::new(bin())
        .args(["validate-profiles", "--deny-warnings", "--format", "json"])
        .arg(&root)
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let report = json_report(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["warnings"], 1);
    assert_eq!(report["profiles"], 1);
}
