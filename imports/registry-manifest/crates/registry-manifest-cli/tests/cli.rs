// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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

    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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

    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
    assert!(!output.status.success(), "publish must exit non-zero");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.validation_failed"));
}

#[test]
fn publish_fails_closed_when_out_cannot_be_created() {
    let dir = temp_dir("publish-bad-out");
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");

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
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");

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
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.file_not_found"));
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.parse_failed"));
}

#[test]
fn validate_rejects_yaml_larger_than_64_kib_before_parse() {
    let dir = temp_dir("validate-yaml-too-large");
    let manifest = dir.join("oversize.yaml");
    fs::write(&manifest, "[".repeat(64 * 1024 + 1)).expect("write oversized yaml");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.too_large"));
    assert!(
        !stderr.contains("metadata.manifest.parse_failed"),
        "oversized input must fail before YAML parse: {stderr}"
    );
}

#[test]
fn validate_rejects_nested_flow_yaml_larger_than_64_kib_before_parse() {
    let dir = temp_dir("validate-nested-flow-too-large");
    let manifest = dir.join("nested-flow-oversize.yaml");
    let raw = format!("{}{}", "[".repeat(64 * 1024 + 1), "]".repeat(64 * 1024 + 1));
    fs::write(&manifest, raw).expect("write oversized nested flow yaml");

    let output = Command::new(bin())
        .args(["validate", manifest.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.too_large"));
    assert!(
        !stderr.contains("metadata.manifest.parse_failed"),
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

        assert!(!output.status.success(), "{name} must fail closed");
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            stderr.contains("metadata.manifest.aliases_unsupported"),
            "{name} stderr missing alias error: {stderr}"
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

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("metadata.manifest.aliases_unsupported"),
        "stderr missing alias error: {stderr}"
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("usage:"));
}

#[test]
fn validate_profiles_reports_missing_directory_and_empty_root() {
    let output = Command::new(bin())
        .args(["validate-profiles", "/no/such/profiles/dir"])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.directory_read_failed"));

    let empty_root = temp_dir("empty-profile-root");
    let output = Command::new(bin())
        .args(["validate-profiles", empty_root.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.descriptor_missing"));
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

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.aliases_unsupported"));
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

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.aliases_unsupported"));
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
    for code in [
        "metadata.profile.required_concept_missing",
        "metadata.profile.identifier_missing",
        "metadata.profile.cardinality_mismatch",
        "metadata.profile.codelist_mismatch",
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.id_mismatch"));
    assert!(stderr.contains("metadata.profile.version_missing"));
    assert!(stderr.contains("metadata.profile.supported_input_artifacts_missing"));
    assert!(stderr.contains("metadata.profile.conformance_checks_missing"));
    assert!(stderr.contains("metadata.profile.fixtures_missing"));
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.fixture_missing"));
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.parse_failed"));
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
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.profile.claim_missing"));
}

#[test]
fn publish_fails_closed_when_site_root_is_a_file() {
    let dir = temp_dir("publish-site-root-file");
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
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
