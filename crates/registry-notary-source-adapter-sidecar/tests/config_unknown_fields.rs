// SPDX-License-Identifier: Apache-2.0
//! Config is loaded straight from YAML via `serde_norway::from_str`
//! (`load_startup_config_with_options`, sidecar.rs). Unknown keys in any
//! sidecar config block (`server:`, `auth:`, `limits:`, `sources.<name>:` and
//! its nested `batch`/`limits`/`cache`/`smoke_lookup`/`http_json`/`http_flow`
//! blocks) must fail startup and name the offending key, instead of being
//! silently dropped (ticket #250: a typo'd auth or limits key is a
//! deployment-posture hazard, not a cosmetic one).

use registry_notary_source_adapter_sidecar::SidecarConfig;
use std::fs;
use std::path::Path;

/// Minimal, valid manifest using the `http_json` engine. Every block below is
/// mutated by exactly one test to add a single unknown key while leaving all
/// correctly-named required fields in place, so a pre-fix parse succeeds
/// (proving the key was silently dropped) and a post-fix parse must fail
/// naming that key.
fn base_manifest() -> String {
    r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: CONFIG_UNKNOWN_FIELDS_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
sources:
  http_people:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: CONFIG_UNKNOWN_FIELDS_CREDENTIAL_JSON
    allowed_base_urls:
      - https://source.example.test
    batch:
      mode: sequential_lookup
    limits:
      max_in_flight: 4
    cache:
      max_entries: 16
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: /people
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
"#
    .to_string()
}

/// Minimal, valid manifest using the `http_flow` engine, for the http_flow
/// block negative fixture.
fn base_flow_manifest() -> String {
    r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary
      hash_env: CONFIG_UNKNOWN_FIELDS_TOKEN_HASH
limits:
  max_workers: 2
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
sources:
  http_people:
    engine: http_flow
    dataset: civil_registry
    entity: civil_person
    credential_env: CONFIG_UNKNOWN_FIELDS_CREDENTIAL_JSON
    allowed_base_urls:
      - https://source.example.test
    http_flow:
      steps:
        - id: find_person
          request:
            method: GET
            base_url: https://source.example.test
            path: /people
          response:
            bind:
              person_id:
                cel: body.id
      output:
        records:
          cel: "[]"
"#
    .to_string()
}

fn assert_rejects_unknown_key(manifest: &str, offending_key: &str) {
    let error = serde_norway::from_str::<SidecarConfig>(manifest)
        .expect_err(&format!("unknown key `{offending_key}` must be rejected"));
    let message = error.to_string();
    assert!(
        message.contains(offending_key),
        "expected error to name offending key `{offending_key}`, got: {message}"
    );
}

#[test]
fn server_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "  bind: \"127.0.0.1:0\"",
        "  bind: \"127.0.0.1:0\"\n  bnid: \"typo of bind\"",
    );
    assert_rejects_unknown_key(&manifest, "bnid");
}

#[test]
fn auth_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "auth:\n  bearer_tokens:",
        "auth:\n  algorithm: hs256\n  bearer_tokens:",
    );
    assert_rejects_unknown_key(&manifest, "algorithm");
}

#[test]
fn limits_block_rejects_unknown_key() {
    let manifest =
        base_manifest().replace("  max_workers: 2", "  max_workers: 2\n  max_workerz: 2");
    assert_rejects_unknown_key(&manifest, "max_workerz");
}

#[test]
fn sources_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "    entity: civil_person",
        "    entity: civil_person\n    entiti: civil_person",
    );
    assert_rejects_unknown_key(&manifest, "entiti");
}

#[test]
fn http_json_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "      path: /people",
        "      path: /people\n      paht: /people",
    );
    assert_rejects_unknown_key(&manifest, "paht");
}

#[test]
fn http_flow_block_rejects_unknown_key() {
    let manifest = base_flow_manifest().replace("      steps:", "      stpes: []\n      steps:");
    assert_rejects_unknown_key(&manifest, "stpes");
}

#[test]
fn source_batch_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "      mode: sequential_lookup",
        "      mode: sequential_lookup\n      modee: sequential_lookup",
    );
    assert_rejects_unknown_key(&manifest, "modee");
}

#[test]
fn source_limits_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "      max_in_flight: 4",
        "      max_in_flight: 4\n      max_inflight: 4",
    );
    assert_rejects_unknown_key(&manifest, "max_inflight");
}

#[test]
fn source_cache_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "      max_entries: 16",
        "      max_entries: 16\n      max_entires: 16",
    );
    assert_rejects_unknown_key(&manifest, "max_entires");
}

#[test]
fn smoke_lookup_block_rejects_unknown_key() {
    let manifest = base_manifest().replace(
        "      value: smoke-person",
        "      value: smoke-person\n      vlaue: smoke-person",
    );
    assert_rejects_unknown_key(&manifest, "vlaue");
}

fn workspace_example(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn civil_http_json_example_loads_through_sidecar_config() {
    let manifest = workspace_example("examples/civil-http-json-sidecar.yaml");
    serde_norway::from_str::<SidecarConfig>(&manifest)
        .expect("examples/civil-http-json-sidecar.yaml parses as SidecarConfig");
}

#[test]
fn dhis2_health_example_loads_through_sidecar_config() {
    let manifest = workspace_example("examples/dhis2-health-sidecar.yaml");
    serde_norway::from_str::<SidecarConfig>(&manifest)
        .expect("examples/dhis2-health-sidecar.yaml parses as SidecarConfig");
}
